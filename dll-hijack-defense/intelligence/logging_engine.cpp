// =============================================================================
// intelligence/logging_engine.cpp
// Implementation of the Logging Engine.
//
// Internal architecture:
//   Section 1: Internal state
//   Section 2: JSON serialization helpers (hand-written, no external library)
//   Section 3: HMAC-SHA256 per-entry signing (BCrypt)
//   Section 4: File sink — JSON Lines format, size-based rotation
//   Section 5: Windows Event Log sink
//   Section 6: Consumer background thread
//   Section 7: Public API
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <shlwapi.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#include "logging_engine.h"
#include "policy.h"
#include "constants.h"
#include "types.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

namespace dhd {

// ===========================================================================
// Section 1 — Internal State
// ===========================================================================

namespace {

// ---------------------------------------------------------------------------
// Queue configuration
// ---------------------------------------------------------------------------
static constexpr size_t QUEUE_CAPACITY    = 8192;  // max pending log events
static constexpr DWORD  FLUSH_TIMEOUT_MS  = 5000;
static constexpr DWORD  THREAD_EXIT_MS    = 10000;
static constexpr DWORD  CONSUMER_WAIT_MS  = 200;   // max idle wait per cycle

// ---------------------------------------------------------------------------
// HMAC key (session-scoped, generated at init, zeroed at shutdown)
// ---------------------------------------------------------------------------
static BYTE  s_hmac_key[HMAC_SHA256_BYTES] = {};
static BOOL  s_hmac_key_ready             = FALSE;

// ---------------------------------------------------------------------------
// Producer-consumer queue
// Uses CRITICAL_SECTION (not SRWLOCK) because CONDITION_VARIABLE requires it.
// ---------------------------------------------------------------------------
static std::vector<LogEvent> s_queue;
static CRITICAL_SECTION      s_queue_cs;
static CONDITION_VARIABLE    s_queue_cv;
static volatile LONG         s_dropped       = 0;
static volatile BOOL         s_flush_req     = FALSE;
static volatile BOOL         s_shutdown      = FALSE;
static HANDLE                s_flush_done    = nullptr;  // auto-reset event
static HANDLE                s_worker_thread = nullptr;

// ---------------------------------------------------------------------------
// File sink state
// ---------------------------------------------------------------------------
static HANDLE   s_log_file     = INVALID_HANDLE_VALUE;
static wchar_t  s_log_dir[MAX_PATH]  = {};
static wchar_t  s_log_path[MAX_PATH] = {};
static LONGLONG s_log_max_bytes      = 0;   // set from policy at init

// ---------------------------------------------------------------------------
// Windows Event Log sink
// ---------------------------------------------------------------------------
static HANDLE   s_evtlog_source = nullptr;
static BOOL     s_initialized   = FALSE;

// ---------------------------------------------------------------------------
// Drain buffer — only accessed by the consumer thread; no lock needed.
// ---------------------------------------------------------------------------
static std::vector<LogEvent> s_drain;

// ===========================================================================
// Section 2 — JSON Serialization Helpers
// ===========================================================================

// ---------------------------------------------------------------------------
// WideToUtf8 — convert a wide string to a UTF-8 std::string
// ---------------------------------------------------------------------------
static std::string WideToUtf8(const wchar_t* w)
{
    if (!w || !w[0]) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (sz <= 1) return {};
    std::string out(static_cast<size_t>(sz - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), sz, nullptr, nullptr);
    return out;
}

// ---------------------------------------------------------------------------
// JsonEscape — escape a UTF-8 string for embedding in a JSON string value.
// Returns the escaped content without surrounding quotes.
// ---------------------------------------------------------------------------
static std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 4);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    sprintf_s(buf, "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// FiletimeToIso8601 — produce "YYYY-MM-DDTHH:MM:SS.mmmZ"
// ---------------------------------------------------------------------------
static std::string FiletimeToIso8601(const FILETIME& ft)
{
    SYSTEMTIME st{};
    FileTimeToSystemTime(&ft, &st);
    char buf[32];
    sprintf_s(buf, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

// ---------------------------------------------------------------------------
// Enum → string helpers
// ---------------------------------------------------------------------------
static const char* SeverityStr(LogSeverity s)
{
    switch (s) {
        case LogSeverity::Info:    return "INFO";
        case LogSeverity::Warning: return "WARNING";
        case LogSeverity::Alert:   return "ALERT";
        default:                   return "UNKNOWN";
    }
}

static const char* ActionStr(LoadAction a)
{
    switch (a) {
        case LoadAction::Allowed:        return "Allowed";
        case LoadAction::AllowedFlagged: return "AllowedFlagged";
        case LoadAction::Blocked:        return "Blocked";
        case LoadAction::BlockedAlways:  return "BlockedAlways";
        default:                         return "Unknown";
    }
}

static const char* RiskStr(RiskLevel r)
{
    switch (r) {
        case RiskLevel::Low:      return "Low";
        case RiskLevel::Medium:   return "Medium";
        case RiskLevel::High:     return "High";
        case RiskLevel::Critical: return "Critical";
        default:                  return "Unknown";
    }
}

static std::string HexEncode(const BYTE* data, size_t len)
{
    std::string out(len * 2, '0');
    for (size_t i = 0; i < len; ++i) {
        sprintf_s(out.data() + i * 2, 3, "%02x",
                  static_cast<unsigned>(data[i]));
    }
    return out;
}

// ---------------------------------------------------------------------------
// BuildCanonicalBody — pipe-delimited string used as HMAC input.
// Does NOT include the hmac field (avoids chicken-and-egg).
// Format: "schema|ts_ticks|severity|source|host|pid|proc|dll|score|action|
//          block_reasons|risk|prevalidated"
// ---------------------------------------------------------------------------
static std::string BuildCanonicalBody(const LogEvent& e)
{
    ULONGLONG ts_ticks =
        (static_cast<ULONGLONG>(e.timestamp.dwHighDateTime) << 32) |
         static_cast<ULONGLONG>(e.timestamp.dwLowDateTime);

    char buf[4096];
    sprintf_s(buf, sizeof(buf),
        "%u|%llu|%s|%s|%s|%lu|%s|%s|%.6f|%s|0x%08X|%s|%d",
        e.schema_version,
        ts_ticks,
        SeverityStr(e.severity),
        WideToUtf8(e.source_module).c_str(),
        WideToUtf8(e.host_name).c_str(),
        e.process_id,
        WideToUtf8(e.process_name).c_str(),
        WideToUtf8(e.dll_path).c_str(),
        static_cast<double>(e.trust_score),
        ActionStr(e.action),
        e.block_reasons,
        RiskStr(e.risk_level),
        e.was_prevalidated ? 1 : 0);

    return buf;
}

// ---------------------------------------------------------------------------
// SerializeEventJson — produce a complete JSON line for |e|.
// The hmac_sha256 field is included (must be computed before calling this).
// Output does NOT have a trailing newline.
// ---------------------------------------------------------------------------
static std::string SerializeEventJson(const LogEvent& e)
{
    std::string ts  = FiletimeToIso8601(e.timestamp);
    std::string sev = SeverityStr(e.severity);
    std::string act = ActionStr(e.action);
    std::string rsk = RiskStr(e.risk_level);
    std::string hmac_hex = HexEncode(e.hmac_sha256, HMAC_SHA256_BYTES);

    std::string src  = JsonEscape(WideToUtf8(e.source_module));
    std::string host = JsonEscape(WideToUtf8(e.host_name));
    std::string proc = JsonEscape(WideToUtf8(e.process_name));
    std::string dll  = JsonEscape(WideToUtf8(e.dll_path));

    // Build JSON using std::string to avoid buffer overflow with long paths.
    std::string result;
    result.reserve(4096);  // pre-allocate to reduce reallocations
    result += "{";
    result += "\"schema_version\":" + std::to_string(e.schema_version) + ",";
    result += "\"timestamp\":\"" + ts + "\",";
    result += "\"severity\":\"" + sev + "\",";
    result += "\"source_module\":\"" + src + "\",";
    result += "\"host_name\":\"" + host + "\",";
    result += "\"process_id\":" + std::to_string(e.process_id) + ",";
    result += "\"process_name\":\"" + proc + "\",";
    result += "\"dll_path\":\"" + dll + "\",";
    result += "\"trust_score\":" + std::to_string(static_cast<double>(e.trust_score)) + ",";
    result += "\"action\":\"" + act + "\",";
    result += "\"block_reasons\":\"0x" + std::string(HexEncode(reinterpret_cast<const BYTE*>(&e.block_reasons), sizeof(e.block_reasons))) + "\",";
    result += "\"risk_level\":\"" + rsk + "\",";
    result += "\"was_prevalidated\":" + std::string(e.was_prevalidated ? "true" : "false") + ",";
    result += "\"hmac_sha256\":\"" + hmac_hex + "\"";
    result += "}";

    return result;
}
}

// ===========================================================================
// Section 3 — HMAC-SHA256 Per-Entry Signing
// ===========================================================================

// ---------------------------------------------------------------------------
// ComputeHmac — compute HMAC-SHA256 of |data| using |s_hmac_key|.
// Writes 32 bytes into |out_mac|. Returns TRUE on success.
// ---------------------------------------------------------------------------
static BOOL ComputeHmac(const char* data, size_t data_len, BYTE out_mac[HMAC_SHA256_BYTES])
{
    SecureZeroMemory(out_mac, HMAC_SHA256_BYTES);
    if (!s_hmac_key_ready) return FALSE;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    // Query hash object size
    DWORD hash_obj_size = 0, cb = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hash_obj_size), sizeof(DWORD), &cb, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return FALSE; }

    PUCHAR hash_obj = static_cast<PUCHAR>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hash_obj_size));
    if (!hash_obj) { BCryptCloseAlgorithmProvider(hAlg, 0); return FALSE; }

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash,
                               hash_obj, hash_obj_size,
                               s_hmac_key, static_cast<ULONG>(HMAC_SHA256_BYTES),
                               0);
    if (!BCRYPT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, hash_obj);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    BOOL ok = TRUE;
    status = BCryptHashData(hHash,
                             reinterpret_cast<PUCHAR>(const_cast<char*>(data)),
                             static_cast<ULONG>(data_len), 0);
    if (!BCRYPT_SUCCESS(status)) ok = FALSE;

    if (ok) {
        status = BCryptFinishHash(hHash, out_mac,
                                   static_cast<ULONG>(HMAC_SHA256_BYTES), 0);
        if (!BCRYPT_SUCCESS(status)) ok = FALSE;
    }

    BCryptDestroyHash(hHash);
    HeapFree(GetProcessHeap(), 0, hash_obj);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// ---------------------------------------------------------------------------
// SignEvent — compute HMAC over the canonical body and store in |e.hmac_sha256|.
// Modifies the event in-place.
// ---------------------------------------------------------------------------
static void SignEvent(LogEvent& e)
{
    if (!s_hmac_key_ready) return;

    std::string body = BuildCanonicalBody(e);
    ComputeHmac(body.c_str(), body.size(), e.hmac_sha256);
}

// ===========================================================================
// Section 4 — File Sink (JSON Lines, size-based rotation)
// ===========================================================================

// ---------------------------------------------------------------------------
// BuildLogFilePath — generate a timestamped log file path.
// Format: <dir>\dll_hijack_defense_YYYYMMDD_HHMMSS.log
// ---------------------------------------------------------------------------
static void BuildLogFilePath(wchar_t* out, size_t cch)
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    _snwprintf_s(out, cch, _TRUNCATE,
        L"%s\\dll_hijack_defense_%04u%02u%02u_%02u%02u%02u.log",
        s_log_dir,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
}

// ---------------------------------------------------------------------------
// OpenLogFile — open (or create) the current log file.
// Returns TRUE on success.
// ---------------------------------------------------------------------------
static BOOL OpenLogFile()
{
    if (s_log_file != INVALID_HANDLE_VALUE) {
        CloseHandle(s_log_file);
        s_log_file = INVALID_HANDLE_VALUE;
    }

    BuildLogFilePath(s_log_path, _countof(s_log_path));

    s_log_file = CreateFileW(
        s_log_path,
        GENERIC_WRITE,
        FILE_SHARE_READ,          // allow external readers (log tailing)
        nullptr,
        OPEN_ALWAYS,              // create or append
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);

    if (s_log_file == INVALID_HANDLE_VALUE) return FALSE;

    // Seek to end for append mode
    SetFilePointer(s_log_file, 0, nullptr, FILE_END);
    return TRUE;
}

// ---------------------------------------------------------------------------
// RotateLogFile — close and reopen with a new timestamp.
// Called when the current file exceeds s_log_max_bytes.
// ---------------------------------------------------------------------------
static void RotateLogFile()
{
    // Write a rotation marker
    const char marker[] = "{\"event\":\"LOG_ROTATED\"}\r\n";
    DWORD written = 0;
    WriteFile(s_log_file, marker, static_cast<DWORD>(strlen(marker)),
              &written, nullptr);
    FlushFileBuffers(s_log_file);
    OpenLogFile();
}

// ---------------------------------------------------------------------------
// WriteLineToFile — write |line| + CRLF to the log file.
// Rotates if the file has grown past the configured limit.
// ---------------------------------------------------------------------------
static void WriteLineToFile(const std::string& line)
{
    if (s_log_file == INVALID_HANDLE_VALUE) return;

    // Check if rotation is needed
    if (s_log_max_bytes > 0) {
        LARGE_INTEGER sz{};
        if (GetFileSizeEx(s_log_file, &sz) &&
            sz.QuadPart >= s_log_max_bytes)
        {
            RotateLogFile();
        }
    }

    // Write JSON line + CRLF
    std::string out = line + "\r\n";
    DWORD written = 0;
    WriteFile(s_log_file, out.c_str(),
              static_cast<DWORD>(out.size()), &written, nullptr);
}

// ===========================================================================
// Section 5 — Windows Event Log Sink
// ===========================================================================

// ---------------------------------------------------------------------------
// WriteToEventLog — emit a record to the Application event log.
// Only called for WARNING and ALERT severity to avoid noise.
// ---------------------------------------------------------------------------
static void WriteToEventLog(const LogEvent& e, const std::string& json_line)
{
    if (!s_evtlog_source) return;
    if (e.severity == LogSeverity::Info) return;

    WORD ev_type = EVENTLOG_WARNING_TYPE;
    if (e.severity == LogSeverity::Alert) ev_type = EVENTLOG_ERROR_TYPE;

    // Convert the JSON line to wide string for ReportEventW
    int wsz = MultiByteToWideChar(CP_UTF8, 0,
                                   json_line.c_str(), -1,
                                   nullptr, 0);
    if (wsz <= 1) return;

    std::wstring wmsg(static_cast<size_t>(wsz - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0,
                         json_line.c_str(), -1,
                         wmsg.data(), wsz);

    const wchar_t* strings[1] = { wmsg.c_str() };

    // Event ID: use a fixed ID per severity.
    // 1001 = INFO, 1002 = WARNING, 1003 = ALERT
    DWORD event_id = (e.severity == LogSeverity::Alert) ? 1003u : 1002u;

    ReportEventW(
        s_evtlog_source,
        ev_type,
        0,            // category
        event_id,
        nullptr,      // user SID
        1,            // num strings
        0,            // binary data size
        strings,
        nullptr);
}

// ===========================================================================
// Section 6 — Consumer Background Thread
// ===========================================================================

// ---------------------------------------------------------------------------
// ProcessEvent — sign + serialize + write a single event.
// Only called from the consumer thread.
// ---------------------------------------------------------------------------
static void ProcessEvent(LogEvent& e)
{
    const PolicyConfig& cfg = PolicyManager::GetConfig();

    // 1. Compute HMAC if enabled
    if (cfg.hmac_enabled) {
        SignEvent(e);
    }

    // 2. Serialize to JSON
    std::string line = SerializeEventJson(e);

    // 3. Write to file sink
    WriteLineToFile(line);

    // 4. Write to Event Log (WARNING/ALERT only)
    if (cfg.emit_to_event_log) {
        WriteToEventLog(e, line);
    }
}

// ---------------------------------------------------------------------------
// ConsumerThreadProc — background writer thread entry point.
// ---------------------------------------------------------------------------
static DWORD WINAPI ConsumerThreadProc(LPVOID /*param*/)
{
    const PolicyConfig& cfg = PolicyManager::GetConfig();
    const DWORD flush_interval_ms = cfg.log_flush_interval_ms;

    DWORD last_flush = GetTickCount();

    for (;;) {
        // --- Wait for work ---
        EnterCriticalSection(&s_queue_cs);

        // Sleep until signaled or timeout (for periodic flush)
        while (s_queue.empty() && !s_shutdown && !s_flush_req) {
            SleepConditionVariableCS(&s_queue_cv, &s_queue_cs,
                                     CONSUMER_WAIT_MS);
        }

        // Swap the queue under the lock to minimize hold time
        s_drain.clear();
        s_drain.swap(s_queue);
        BOOL do_flush  = s_flush_req;
        BOOL do_exit   = s_shutdown;

        LeaveCriticalSection(&s_queue_cs);

        // --- Process drained events ---
        for (LogEvent& ev : s_drain) {
            ProcessEvent(ev);
        }
        s_drain.clear();

        // --- Periodic file flush ---
        DWORD now = GetTickCount();
        if ((now - last_flush) >= flush_interval_ms) {
            if (s_log_file != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(s_log_file);
            }
            last_flush = now;
        }

        // --- Explicit flush request ---
        if (do_flush) {
            if (s_log_file != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(s_log_file);
            }
            InterlockedExchange(reinterpret_cast<volatile LONG*>(&s_flush_req),
                                 FALSE);
            SetEvent(s_flush_done);
        }

        if (do_exit) {
            // Drain any remaining events enqueued after the swap
            EnterCriticalSection(&s_queue_cs);
            s_drain.swap(s_queue);
            LeaveCriticalSection(&s_queue_cs);

            for (LogEvent& ev : s_drain) {
                ProcessEvent(ev);
            }
            s_drain.clear();

            if (s_log_file != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(s_log_file);
            }
            break;
        }
    }

    return 0;
}

} // anonymous namespace

// ===========================================================================
// Section 7 — Public API
// ===========================================================================

BOOL InitializeLoggingEngine(const wchar_t* log_directory)
{
    if (s_initialized) return TRUE;

    // --- Determine log directory ---
    if (log_directory && log_directory[0] != L'\0') {
        wcscpy_s(s_log_dir, _countof(s_log_dir), log_directory);
    } else {
        // Default: .\logs\ relative to CWD
        GetCurrentDirectoryW(_countof(s_log_dir), s_log_dir);
        PathAppendW(s_log_dir, L"logs");
    }

    // --- Create directory if absent ---
    CreateDirectoryW(s_log_dir, nullptr);   // fail silently if exists

    // --- Read policy for configuration ---
    const PolicyConfig& cfg = PolicyManager::GetConfig();
    s_log_max_bytes = static_cast<LONGLONG>(cfg.log_max_file_mb) * 1024 * 1024;

    // --- Generate session HMAC key ---
    s_hmac_key_ready = FALSE;
    if (cfg.hmac_enabled) {
        BCRYPT_ALG_HANDLE hRng = nullptr;
        NTSTATUS ns = BCryptOpenAlgorithmProvider(
            &hRng, BCRYPT_RNG_ALGORITHM, nullptr, 0);
        if (BCRYPT_SUCCESS(ns)) {
            ns = BCryptGenRandom(hRng, s_hmac_key,
                                  static_cast<ULONG>(HMAC_SHA256_BYTES), 0);
            BCryptCloseAlgorithmProvider(hRng, 0);
            s_hmac_key_ready = BCRYPT_SUCCESS(ns) ? TRUE : FALSE;
        }
    }

    // --- Open initial log file ---
    if (!OpenLogFile()) {
        SecureZeroMemory(s_hmac_key, sizeof(s_hmac_key));
        return FALSE;
    }

    // --- Write session start marker ---
    {
        SYSTEMTIME st{};
        GetSystemTime(&st);
        char marker[256];
        sprintf_s(marker, sizeof(marker),
            "{\"event\":\"SESSION_START\","
            "\"timestamp\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\","
            "\"hmac_enabled\":%s}\r\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            cfg.hmac_enabled ? "true" : "false");
        DWORD w = 0;
        WriteFile(s_log_file, marker,
                  static_cast<DWORD>(strlen(marker)), &w, nullptr);
    }

    // --- Register Windows Event Log source ---
    if (cfg.emit_to_event_log) {
        s_evtlog_source = RegisterEventSourceW(nullptr, L"DLLHijackDefense");
        // Non-fatal if this fails (e.g. missing registry entry)
    }

    // --- Initialize queue synchronization primitives ---
    InitializeCriticalSectionAndSpinCount(&s_queue_cs, 4000);
    InitializeConditionVariable(&s_queue_cv);

    s_flush_done = CreateEventW(nullptr, FALSE, FALSE, nullptr); // auto-reset
    if (!s_flush_done) {
        CloseHandle(s_log_file);
        s_log_file = INVALID_HANDLE_VALUE;
        DeleteCriticalSection(&s_queue_cs);
        SecureZeroMemory(s_hmac_key, sizeof(s_hmac_key));
        return FALSE;
    }

    s_flush_req = FALSE;
    s_shutdown  = FALSE;
    s_dropped   = 0;
    s_queue.reserve(256);
    s_drain.reserve(256);

    // --- Start consumer thread ---
    s_worker_thread = CreateThread(nullptr, 0,
                                    ConsumerThreadProc, nullptr,
                                    0, nullptr);
    if (!s_worker_thread) {
        CloseHandle(s_flush_done);
        s_flush_done = nullptr;
        CloseHandle(s_log_file);
        s_log_file = INVALID_HANDLE_VALUE;
        DeleteCriticalSection(&s_queue_cs);
        SecureZeroMemory(s_hmac_key, sizeof(s_hmac_key));
        return FALSE;
    }

    // Boost thread priority slightly so logs don't pile up under load
    SetThreadPriority(s_worker_thread, THREAD_PRIORITY_ABOVE_NORMAL);

    s_initialized = TRUE;
    return TRUE;
}

void ShutdownLoggingEngine()
{
    if (!s_initialized) return;

    // Signal background thread to exit
    InterlockedExchange(reinterpret_cast<volatile LONG*>(&s_shutdown), TRUE);

    EnterCriticalSection(&s_queue_cs);
    WakeConditionVariable(&s_queue_cv);
    LeaveCriticalSection(&s_queue_cs);

    // Wait for thread to exit
    if (s_worker_thread) {
        WaitForSingleObject(s_worker_thread, THREAD_EXIT_MS);
        CloseHandle(s_worker_thread);
        s_worker_thread = nullptr;
    }

    // Write session end marker
    if (s_log_file != INVALID_HANDLE_VALUE) {
        const char marker[] = "{\"event\":\"SESSION_END\"}\r\n";
        DWORD w = 0;
        WriteFile(s_log_file, marker,
                  static_cast<DWORD>(strlen(marker)), &w, nullptr);
        FlushFileBuffers(s_log_file);
        CloseHandle(s_log_file);
        s_log_file = INVALID_HANDLE_VALUE;
    }

    // Deregister Event Log source
    if (s_evtlog_source) {
        DeregisterEventSource(s_evtlog_source);
        s_evtlog_source = nullptr;
    }

    // Cleanup synchronization objects
    if (s_flush_done) {
        CloseHandle(s_flush_done);
        s_flush_done = nullptr;
    }
    DeleteCriticalSection(&s_queue_cs);

    // Zero HMAC key
    SecureZeroMemory(s_hmac_key, sizeof(s_hmac_key));
    s_hmac_key_ready = FALSE;

    s_queue.clear();
    s_drain.clear();
    s_initialized = FALSE;
}

BOOL IsLoggingEngineInitialized()
{
    return s_initialized;
}

void EmitLog(const LogEvent& event)
{
    if (!s_initialized) return;

    EnterCriticalSection(&s_queue_cs);

    if (s_queue.size() < QUEUE_CAPACITY) {
        s_queue.push_back(event);
        WakeConditionVariable(&s_queue_cv);
    } else {
        // Queue full — drop and count
        InterlockedIncrement(&s_dropped);
    }

    LeaveCriticalSection(&s_queue_cs);
}

void BuildLogEvent(LogSeverity    severity,
                    const wchar_t* source_module,
                    const wchar_t* dll_path,
                    float          trust_score,
                    LoadAction     action,
                    uint32_t       block_reasons,
                    RiskLevel      risk_level,
                    BOOL           was_prevalidated,
                    LogEvent*      out_event)
{
    if (!out_event) return;
    SecureZeroMemory(out_event, sizeof(LogEvent));

    out_event->schema_version  = LOG_SCHEMA_VERSION;
    out_event->severity        = severity;
    out_event->trust_score     = trust_score;
    out_event->action          = action;
    out_event->block_reasons   = block_reasons;
    out_event->risk_level      = risk_level;
    out_event->was_prevalidated = was_prevalidated;

    GetSystemTimeAsFileTime(&out_event->timestamp);
    out_event->process_id = GetCurrentProcessId();

    // Host name
    DWORD host_cch = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(out_event->host_name, &host_cch);

    // Process name (filename only)
    wchar_t exe[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, exe, MAX_PATH)) {
        const wchar_t* fname = PathFindFileNameW(exe);
        wcscpy_s(out_event->process_name, _countof(out_event->process_name),
                 fname ? fname : exe);
    }

    if (source_module) {
        wcscpy_s(out_event->source_module, _countof(out_event->source_module),
                 source_module);
    }

    if (dll_path) {
        wcscpy_s(out_event->dll_path, _countof(out_event->dll_path), dll_path);
    }

    // HMAC is zeroed — Logging Engine computes it on the consumer thread
}

void FlushLog()
{
    if (!s_initialized || !s_flush_done) return;

    // Signal flush request and wake the consumer
    InterlockedExchange(reinterpret_cast<volatile LONG*>(&s_flush_req), TRUE);

    EnterCriticalSection(&s_queue_cs);
    WakeConditionVariable(&s_queue_cv);
    LeaveCriticalSection(&s_queue_cs);

    // Wait for consumer to signal flush completion
    WaitForSingleObject(s_flush_done, FLUSH_TIMEOUT_MS);
}

uint64_t GetDroppedEventCount()
{
    return static_cast<uint64_t>(InterlockedCompareExchange(&s_dropped, 0, 0));
}

} // namespace dhd
