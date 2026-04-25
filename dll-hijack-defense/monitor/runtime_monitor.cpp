// =============================================================================
// monitor/runtime_monitor.cpp
// Implementation of the Runtime Monitor.
//
// Internal architecture:
//   Section 1: Internal state and types
//   Section 2: Module snapshot — EnumProcessModulesEx baseline
//   Section 3: Finding dispatch — alert emission and callback invocation
//   Section 4: ETW consumer (Layer A)
//   Section 5: Polling thread (Layer B)
//   Section 6: Public API
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <shlwapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#include "runtime_monitor.h"
#include "secure_loader.h"
#include "logging_engine.h"
#include "policy.h"
#include "constants.h"
#include "types.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <string>
#include <unordered_set>
#include <vector>

namespace dhd {

// ===========================================================================
// Section 1 — Internal State
// ===========================================================================

namespace {

// ---------------------------------------------------------------------------
// Known-module set — tracks base addresses seen so far to avoid duplicate
// alerts. Protected by s_known_lock (SRWLOCK).
// ---------------------------------------------------------------------------
struct HModuleHash {
    std::size_t operator()(HMODULE h) const noexcept {
        return std::hash<uintptr_t>{}(reinterpret_cast<uintptr_t>(h));
    }
};

using ModuleSet = std::unordered_set<HMODULE, HModuleHash>;

static ModuleSet s_known_approved;    // modules already verified as approved
static ModuleSet s_known_unapproved;  // modules already alerted on
static SRWLOCK   s_known_lock = SRWLOCK_INIT;

// ---------------------------------------------------------------------------
// Finding dispatch queue — findings are first stored here, then dispatched
// from the polling thread to avoid running callbacks on the ETW thread.
// Protected by s_findings_cs + CONDITION_VARIABLE.
// ---------------------------------------------------------------------------
static std::vector<MonitorFinding> s_finding_queue;
static CRITICAL_SECTION            s_findings_cs;
static CONDITION_VARIABLE          s_findings_cv;
static volatile LONG               s_finding_count = 0;

// ---------------------------------------------------------------------------
// User callback
// ---------------------------------------------------------------------------
static MonitorCallback s_user_callback  = nullptr;
static void*           s_user_data      = nullptr;

// ---------------------------------------------------------------------------
// Lifecycle flags and thread handles
// ---------------------------------------------------------------------------
static volatile BOOL  s_running          = FALSE;
static volatile BOOL  s_stop_requested   = FALSE;
static HANDLE         s_poll_thread      = nullptr;
static HANDLE         s_dispatch_thread  = nullptr;

// ETW session
static TRACEHANDLE    s_etw_session      = INVALID_PROCESSTRACE_HANDLE;
static TRACEHANDLE    s_etw_consumer     = INVALID_PROCESSTRACE_HANDLE;
static HANDLE         s_etw_thread       = nullptr;
static BOOL           s_etw_active       = FALSE;

// Polling control
static HANDLE         s_poll_event       = nullptr;  // auto-reset, signals forced snapshot
static volatile BOOL  s_force_snapshot   = FALSE;

// ETW session name (wide)
static constexpr wchar_t ETW_SESSION_NAME[] = L"DllHijackDefenseMonitor";

// Microsoft-Windows-Kernel-Process provider GUID
// {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
static const GUID KERNEL_PROCESS_PROVIDER = {
    0x22fb2cd6, 0x0e7b, 0x422b,
    { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 }
};

// ImageLoad event ID in Microsoft-Windows-Kernel-Process
static constexpr USHORT ETW_IMAGE_LOAD_EVENT_ID = 5;

// ===========================================================================
// Section 2 — Module Snapshot
// ===========================================================================

// ---------------------------------------------------------------------------
// TakeModuleSnapshot — enumerate all currently loaded modules via
// EnumProcessModulesEx. Returns a vector of HMODULE values.
// Uses DWORD-growing loop to handle races where the module list grows
// between the size query and the fill call.
// ---------------------------------------------------------------------------
static std::vector<HMODULE> TakeModuleSnapshot()
{
    std::vector<HMODULE> modules;
    DWORD needed = 0;

    // Initial attempt with 512 slots
    modules.resize(512);
    DWORD buf_bytes = static_cast<DWORD>(modules.size() * sizeof(HMODULE));

    if (!EnumProcessModulesEx(
            GetCurrentProcess(),
            modules.data(), buf_bytes,
            &needed, LIST_MODULES_ALL))
    {
        modules.clear();
        return modules;
    }

    // If the buffer was too small, retry with the required size + 10% headroom
    if (needed > buf_bytes) {
        modules.resize((needed / sizeof(HMODULE)) + 64);
        buf_bytes = static_cast<DWORD>(modules.size() * sizeof(HMODULE));

        if (!EnumProcessModulesEx(
                GetCurrentProcess(),
                modules.data(), buf_bytes,
                &needed, LIST_MODULES_ALL))
        {
            modules.clear();
            return modules;
        }
    }

    modules.resize(needed / sizeof(HMODULE));
    return modules;
}

// ---------------------------------------------------------------------------
// GetModuleFullPath — retrieve the full path for a module handle.
// Returns an empty string on failure.
// ---------------------------------------------------------------------------
static std::wstring GetModuleFullPath(HMODULE hmod)
{
    wchar_t buf[MAX_PATH] = {};
    DWORD   len = GetModuleFileNameExW(GetCurrentProcess(), hmod, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return {};
    return buf;
}

// ===========================================================================
// Section 3 — Finding Dispatch
// ===========================================================================

// ---------------------------------------------------------------------------
// EmitFindingAlert — emit an ALERT-level log event for an unapproved module.
// Also invokes the user callback if registered.
// Runs on the dispatch thread (NOT the ETW callback thread).
// ---------------------------------------------------------------------------
static void EmitFindingAlert(const MonitorFinding& finding)
{
    if (!IsLoggingEngineInitialized()) return;

    LogEvent ev{};
    BuildLogEvent(
        LogSeverity::Alert,
        source::RUNTIME_MONITOR,
        finding.module_path,
        0.0f,                              // trust score unknown — unapproved
        LoadAction::Blocked,
        finding.block_reasons,
        RiskLevel::Critical,
        FALSE,                             // was_prevalidated = FALSE
        &ev);

    EmitLog(ev);
}

// ---------------------------------------------------------------------------
// EnqueueFinding — thread-safe enqueue for findings detected on any thread.
// ---------------------------------------------------------------------------
static void EnqueueFinding(const MonitorFinding& finding)
{
    EnterCriticalSection(&s_findings_cs);
    s_finding_queue.push_back(finding);
    WakeConditionVariable(&s_findings_cv);
    LeaveCriticalSection(&s_findings_cs);

    InterlockedIncrement(&s_finding_count);
}

// ---------------------------------------------------------------------------
// BuildFinding — construct a MonitorFinding from a module handle and path.
// ---------------------------------------------------------------------------
static MonitorFinding BuildFinding(HMODULE hmod,
                                    const wchar_t* path,
                                    BOOL by_etw)
{
    MonitorFinding f{};
    f.module_base      = hmod;
    f.detected_by_etw  = by_etw;
    f.block_reasons    = BR_UNEXPECTED_MODULE;
    GetSystemTimeAsFileTime(&f.detected_at);

    if (path && path[0]) {
        wcscpy_s(f.module_path, _countof(f.module_path), path);
        const wchar_t* fname = PathFindFileNameW(path);
        if (fname) {
            wcscpy_s(f.module_name, _countof(f.module_name), fname);
        }
    }

    return f;
}

// ---------------------------------------------------------------------------
// CheckAndRecord — verify a module against the ApprovedModuleSet.
// Returns TRUE if the module is new AND unapproved (i.e. a finding).
// Updates s_known_approved / s_known_unapproved to avoid duplicate alerts.
// ---------------------------------------------------------------------------
static BOOL CheckAndRecord(HMODULE hmod,
                             const wchar_t* path,
                             BOOL by_etw)
{
    // Fast path: already classified?
    AcquireSRWLockShared(&s_known_lock);
    bool already_approved   = (s_known_approved.count(hmod) > 0);
    bool already_unapproved = (s_known_unapproved.count(hmod) > 0);
    ReleaseSRWLockShared(&s_known_lock);

    if (already_approved || already_unapproved) return FALSE;

    // Query the Secure Loader's ApprovedModuleSet
    BOOL approved = IsModuleApproved(hmod);

    AcquireSRWLockExclusive(&s_known_lock);
    if (approved) {
        s_known_approved.insert(hmod);
    } else {
        // Only insert if truly new (re-check under exclusive lock)
        if (s_known_unapproved.count(hmod) == 0) {
            s_known_unapproved.insert(hmod);
        } else {
            // Another thread beat us to it
            ReleaseSRWLockExclusive(&s_known_lock);
            return FALSE;
        }
    }
    ReleaseSRWLockExclusive(&s_known_lock);

    if (!approved) {
        MonitorFinding finding = BuildFinding(hmod, path, by_etw);
        EnqueueFinding(finding);
        return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// InvokeCallbackSafe — calls user callback inside SEH to swallow exceptions.
// Must be a plain function (no C++ objects) because __try is incompatible
// with C++ destructors in the same function scope.
// ---------------------------------------------------------------------------
static void InvokeCallbackSafe(MonitorCallback cb, const MonitorFinding* f, void* data)
{
    __try {
        cb(*f, data);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Swallow callback exceptions — monitor must not crash
    }
}

// ---------------------------------------------------------------------------
// DispatchThreadProc — dedicated thread for draining the finding queue
// and invoking user callbacks. Decouples callback latency from ETW thread.
// ---------------------------------------------------------------------------
static DWORD WINAPI DispatchThreadProc(LPVOID /*param*/)
{
    std::vector<MonitorFinding> local;

    while (!s_stop_requested || !s_finding_queue.empty()) {
        EnterCriticalSection(&s_findings_cs);

        while (s_finding_queue.empty() && !s_stop_requested) {
            SleepConditionVariableCS(&s_findings_cv, &s_findings_cs, 500);
        }

        local.clear();
        local.swap(s_finding_queue);
        LeaveCriticalSection(&s_findings_cs);

        for (const MonitorFinding& f : local) {
            EmitFindingAlert(f);

            if (s_user_callback) {
                InvokeCallbackSafe(s_user_callback, &f, s_user_data);
            }
        }
    }

    return 0;
}

// ===========================================================================
// Section 4 — ETW Consumer (Layer A)
// ===========================================================================

// ---------------------------------------------------------------------------
// EtwEventCallback — invoked by ProcessTrace() for each ETW event.
// Runs on a dedicated ETW processing thread (started by ProcessTrace).
// We only care about ImageLoad events (ID 5) for the current process.
// ---------------------------------------------------------------------------
static VOID WINAPI EtwEventCallback(PEVENT_RECORD record)
{
    if (!record) return;

    // Only process ImageLoad events from the kernel process provider
    if (!IsEqualGUID(record->EventHeader.ProviderId, KERNEL_PROCESS_PROVIDER))
        return;
    if (record->EventHeader.EventDescriptor.Id != ETW_IMAGE_LOAD_EVENT_ID)
        return;

    // Filter to current process only
    if (record->EventHeader.ProcessId != GetCurrentProcessId())
        return;

    // Extract ImageBase (the HMODULE) from event data.
    // For ImageLoad events the first property is ImageBase (PVOID / UInt64).
    // We use TDH to parse it correctly regardless of bitness.
    PROPERTY_DATA_DESCRIPTOR desc{};
    const wchar_t* prop_name = L"ImageBase";
    desc.PropertyName = reinterpret_cast<ULONGLONG>(prop_name);
    desc.ArrayIndex   = ULONG_MAX;

    ULONGLONG image_base = 0;
    ULONG     prop_size  = sizeof(image_base);

    ULONG status = TdhGetProperty(
        record,
        0, nullptr,
        1, &desc,
        prop_size,
        reinterpret_cast<PBYTE>(&image_base));

    if (status != ERROR_SUCCESS || image_base == 0) return;

    HMODULE hmod = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(image_base));

    // Get the module path — use GetModuleFileNameEx on the live process
    // since the ETW event's ImageName property may be a kernel path.
    std::wstring path = GetModuleFullPath(hmod);

    CheckAndRecord(hmod, path.empty() ? nullptr : path.c_str(), TRUE);
}

// ---------------------------------------------------------------------------
// EtwBufferCallback — required by ProcessTrace; return TRUE to continue.
// ---------------------------------------------------------------------------
static ULONG WINAPI EtwBufferCallback(PEVENT_TRACE_LOGFILEW /*logfile*/)
{
    if (s_stop_requested) return FALSE;   // stop ProcessTrace loop
    return TRUE;
}

// ---------------------------------------------------------------------------
// EtwThreadProc — calls ProcessTrace() which blocks until the session ends.
// ---------------------------------------------------------------------------
static DWORD WINAPI EtwThreadProc(LPVOID /*param*/)
{
    ProcessTrace(&s_etw_consumer, 1, nullptr, nullptr);
    return 0;
}

// ---------------------------------------------------------------------------
// StartEtwSession — open a real-time ETW session and subscribe to
// Microsoft-Windows-Kernel-Process. Returns TRUE on success.
//
// Requires SeSystemProfilePrivilege or elevation for kernel providers.
// If the privilege is not available, ETW is skipped and polling takes over.
// ---------------------------------------------------------------------------
static BOOL StartEtwSession()
{
    // Allocate EVENT_TRACE_PROPERTIES buffer (must include session name)
    const size_t name_sz = (wcslen(ETW_SESSION_NAME) + 1) * sizeof(wchar_t);
    const size_t props_sz = sizeof(EVENT_TRACE_PROPERTIES) + name_sz;

    PEVENT_TRACE_PROPERTIES props = static_cast<PEVENT_TRACE_PROPERTIES>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, props_sz));
    if (!props) return FALSE;

    props->Wnode.BufferSize    = static_cast<ULONG>(props_sz);
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1; // QPC clock
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

    // Copy session name into the trailing buffer
    wcscpy_s(reinterpret_cast<wchar_t*>(
                 reinterpret_cast<BYTE*>(props) + props->LoggerNameOffset),
             name_sz / sizeof(wchar_t),
             ETW_SESSION_NAME);

    // Start trace session
    ULONG err = StartTraceW(&s_etw_session, ETW_SESSION_NAME, props);
    HeapFree(GetProcessHeap(), 0, props);

    if (err == ERROR_ALREADY_EXISTS) {
        // Session lingered from a previous run — stop it and retry
        ControlTraceW(s_etw_session, ETW_SESSION_NAME, nullptr, EVENT_TRACE_CONTROL_STOP);
        PEVENT_TRACE_PROPERTIES p2 = static_cast<PEVENT_TRACE_PROPERTIES>(
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, props_sz));
        if (!p2) return FALSE;
        p2->Wnode.BufferSize  = static_cast<ULONG>(props_sz);
        p2->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES);
        err = StartTraceW(&s_etw_session, ETW_SESSION_NAME, p2);
        HeapFree(GetProcessHeap(), 0, p2);
    }

    if (err != ERROR_SUCCESS) return FALSE;

    // Enable Microsoft-Windows-Kernel-Process provider
    ENABLE_TRACE_PARAMETERS enable_params{};
    enable_params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    err = EnableTraceEx2(
        s_etw_session,
        &KERNEL_PROCESS_PROVIDER,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x10,    // ImageLoad keyword mask
        0,
        0,
        &enable_params);

    if (err != ERROR_SUCCESS) {
        ControlTraceW(s_etw_session, ETW_SESSION_NAME, nullptr,
                       EVENT_TRACE_CONTROL_STOP);
        s_etw_session = INVALID_PROCESSTRACE_HANDLE;
        return FALSE;
    }

    // Open consumer (real-time)
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName          = const_cast<LPWSTR>(ETW_SESSION_NAME);
    logfile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME |
                                  PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EtwEventCallback;
    logfile.BufferCallback      = EtwBufferCallback;

    s_etw_consumer = OpenTrace(&logfile);
    if (s_etw_consumer == INVALID_PROCESSTRACE_HANDLE) {
        ControlTraceW(s_etw_session, ETW_SESSION_NAME, nullptr,
                       EVENT_TRACE_CONTROL_STOP);
        s_etw_session = INVALID_PROCESSTRACE_HANDLE;
        return FALSE;
    }

    // Start ProcessTrace on a dedicated thread (it blocks)
    s_etw_thread = CreateThread(nullptr, 0, EtwThreadProc, nullptr, 0, nullptr);
    if (!s_etw_thread) {
        CloseTrace(s_etw_consumer);
        s_etw_consumer = INVALID_PROCESSTRACE_HANDLE;
        ControlTraceW(s_etw_session, ETW_SESSION_NAME, nullptr,
                       EVENT_TRACE_CONTROL_STOP);
        s_etw_session = INVALID_PROCESSTRACE_HANDLE;
        return FALSE;
    }

    return TRUE;
}

// ---------------------------------------------------------------------------
// StopEtwSession — stop the trace and wait for the ETW thread.
// ---------------------------------------------------------------------------
static void StopEtwSession()
{
    if (s_etw_session != INVALID_PROCESSTRACE_HANDLE) {
        ControlTraceW(s_etw_session, ETW_SESSION_NAME, nullptr,
                       EVENT_TRACE_CONTROL_STOP);
        s_etw_session = INVALID_PROCESSTRACE_HANDLE;
    }

    if (s_etw_consumer != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(s_etw_consumer);
        s_etw_consumer = INVALID_PROCESSTRACE_HANDLE;
    }

    if (s_etw_thread) {
        WaitForSingleObject(s_etw_thread, 10000);
        CloseHandle(s_etw_thread);
        s_etw_thread = nullptr;
    }
}

// ===========================================================================
// Section 5 — Polling Thread (Layer B)
// ===========================================================================

// ---------------------------------------------------------------------------
// RunPollingSnapshot — take one snapshot and compare against known sets.
// New modules not in any set → call CheckAndRecord.
// ---------------------------------------------------------------------------
static void RunPollingSnapshot()
{
    std::vector<HMODULE> modules = TakeModuleSnapshot();

    for (HMODULE hmod : modules) {
        // Fast check before acquiring locks
        AcquireSRWLockShared(&s_known_lock);
        bool seen = (s_known_approved.count(hmod) > 0) ||
                    (s_known_unapproved.count(hmod) > 0);
        ReleaseSRWLockShared(&s_known_lock);

        if (seen) continue;

        // New module: get path and verify
        std::wstring path = GetModuleFullPath(hmod);
        CheckAndRecord(hmod, path.empty() ? nullptr : path.c_str(), FALSE);
    }
}

// ---------------------------------------------------------------------------
// PollingThreadProc — periodic snapshot loop.
// Runs at the configured interval (or immediately on ForcePollingSnapshot).
// ---------------------------------------------------------------------------
static DWORD WINAPI PollingThreadProc(LPVOID /*param*/)
{
    const PolicyConfig& cfg = PolicyManager::GetConfig();
    const DWORD interval_ms = cfg.polling_interval_ms;

    // Seed the known-approved set from the current module list at startup
    // so we don't flag everything that was loaded before StartMonitor().
    {
        std::vector<HMODULE> initial = TakeModuleSnapshot();

        AcquireSRWLockExclusive(&s_known_lock);
        for (HMODULE hmod : initial) {
            if (IsModuleApproved(hmod)) {
                s_known_approved.insert(hmod);
            }
            // We do NOT pre-populate s_known_unapproved here:
            // modules present at startup but not via SecureLoadLibrary
            // (e.g. the host process's own static imports) are expected
            // at startup phase and NOT flagged.  They are simply added
            // to known_approved to suppress future duplicate checks.
            else {
                s_known_approved.insert(hmod);  // treat pre-existing as approved
            }
        }
        ReleaseSRWLockExclusive(&s_known_lock);
    }

    while (!s_stop_requested) {
        // Wait for either the poll interval or a forced snapshot signal
        (void)WaitForSingleObject(s_poll_event, interval_ms);

        if (s_stop_requested) break;

        RunPollingSnapshot();

        // If this was a forced snapshot, nothing extra to signal —
        // ForcePollingSnapshot() uses a separate event to block on completion.
    }

    return 0;
}

} // anonymous namespace

// ===========================================================================
// Section 6 — Public API
// ===========================================================================

BOOL StartMonitor(MonitorCallback callback, void* user_data)
{
    if (s_running) return TRUE;

    s_user_callback  = callback;
    s_user_data      = user_data;
    s_stop_requested = FALSE;
    s_finding_count  = 0;
    s_known_approved.clear();
    s_known_unapproved.clear();
    s_finding_queue.clear();

    // Initialize dispatch queue synchronization
    InitializeCriticalSectionAndSpinCount(&s_findings_cs, 4000);
    InitializeConditionVariable(&s_findings_cv);

    // Create polling forced-snapshot event (auto-reset)
    s_poll_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!s_poll_event) {
        DeleteCriticalSection(&s_findings_cs);
        return FALSE;
    }

    // Start dispatch thread
    s_dispatch_thread = CreateThread(nullptr, 0, DispatchThreadProc,
                                      nullptr, 0, nullptr);
    if (!s_dispatch_thread) {
        CloseHandle(s_poll_event);
        s_poll_event = nullptr;
        DeleteCriticalSection(&s_findings_cs);
        return FALSE;
    }

    // Start polling thread
    s_poll_thread = CreateThread(nullptr, 0, PollingThreadProc,
                                  nullptr, 0, nullptr);
    if (!s_poll_thread) {
        // Stop dispatch thread
        InterlockedExchange(reinterpret_cast<volatile LONG*>(&s_stop_requested), TRUE);
        EnterCriticalSection(&s_findings_cs);
        WakeConditionVariable(&s_findings_cv);
        LeaveCriticalSection(&s_findings_cs);
        WaitForSingleObject(s_dispatch_thread, 5000);
        CloseHandle(s_dispatch_thread);
        s_dispatch_thread = nullptr;
        CloseHandle(s_poll_event);
        s_poll_event = nullptr;
        DeleteCriticalSection(&s_findings_cs);
        return FALSE;
    }

    // Attempt ETW (non-fatal if unavailable)
    const PolicyConfig& cfg = PolicyManager::GetConfig();
    if (cfg.use_etw) {
        s_etw_active = StartEtwSession();
        if (!s_etw_active && !cfg.etw_fallback_to_polling) {
            // ETW required but failed — abort
            InterlockedExchange(reinterpret_cast<volatile LONG*>(&s_stop_requested), TRUE);
            SetEvent(s_poll_event);
            WaitForSingleObject(s_poll_thread, 5000);
            CloseHandle(s_poll_thread);
            s_poll_thread = nullptr;

            EnterCriticalSection(&s_findings_cs);
            WakeConditionVariable(&s_findings_cv);
            LeaveCriticalSection(&s_findings_cs);
            WaitForSingleObject(s_dispatch_thread, 5000);
            CloseHandle(s_dispatch_thread);
            s_dispatch_thread = nullptr;

            CloseHandle(s_poll_event);
            s_poll_event = nullptr;
            DeleteCriticalSection(&s_findings_cs);
            return FALSE;
        }
    }

    s_running = TRUE;
    return TRUE;
}

void StopMonitor()
{
    if (!s_running) return;

    InterlockedExchange(reinterpret_cast<volatile LONG*>(&s_stop_requested), TRUE);

    // Stop ETW
    if (s_etw_active) {
        StopEtwSession();
        s_etw_active = FALSE;
    }

    // Unblock and stop polling thread
    if (s_poll_event) SetEvent(s_poll_event);
    if (s_poll_thread) {
        WaitForSingleObject(s_poll_thread, 10000);
        CloseHandle(s_poll_thread);
        s_poll_thread = nullptr;
    }

    // Stop dispatch thread
    if (s_dispatch_thread) {
        EnterCriticalSection(&s_findings_cs);
        WakeConditionVariable(&s_findings_cv);
        LeaveCriticalSection(&s_findings_cs);

        WaitForSingleObject(s_dispatch_thread, 10000);
        CloseHandle(s_dispatch_thread);
        s_dispatch_thread = nullptr;
    }

    if (s_poll_event) {
        CloseHandle(s_poll_event);
        s_poll_event = nullptr;
    }

    DeleteCriticalSection(&s_findings_cs);

    AcquireSRWLockExclusive(&s_known_lock);
    s_known_approved.clear();
    s_known_unapproved.clear();
    ReleaseSRWLockExclusive(&s_known_lock);

    s_finding_queue.clear();
    s_running        = FALSE;
    s_stop_requested = FALSE;
}

BOOL IsMonitorRunning()
{
    return s_running;
}

void ForcePollingSnapshot()
{
    if (!s_running || !s_poll_event) return;
    SetEvent(s_poll_event);
    // Give the polling thread time to complete one cycle
    Sleep(50);
}

uint64_t GetFindingCount()
{
    return static_cast<uint64_t>(
        InterlockedCompareExchange(&s_finding_count, 0, 0));
}

} // namespace dhd
