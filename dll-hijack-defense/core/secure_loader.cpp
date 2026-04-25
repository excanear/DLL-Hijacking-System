// =============================================================================
// core/secure_loader.cpp
// Implementation of the Secure Loader â€” the single authorized entry point
// for all DLL loads within the DLL Hijacking Defense System.
//
// Threading model:
//   - s_approved_modules and s_startup_complete are protected by s_map_lock
//     (SRWLOCK, shared for reads, exclusive for writes).
//   - s_initialized is written once during initialization and then read-only;
//     no lock required for reads after that point.
//   - All public functions are safe to call from multiple threads concurrently
//     after InitializeSecureLoader() returns TRUE.
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlwapi.h>
#include <psapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

#include "secure_loader.h"
#include "dll_validator.h"   // interface declared here; implemented in BLOCO 4
#include "logging_engine.h"  // real log sink (BLOCO 6)
#include "policy.h"
#include "constants.h"
#include "types.h"

#include <cstring>
#include <cwchar>
#include <string>
#include <unordered_map>
#include <cstdio>

namespace dhd {

// ===========================================================================
// Module-private state
// ===========================================================================

namespace {

// ---------------------------------------------------------------------------
// Custom hasher for HMODULE.
// HMODULE is HINSTANCE__* under /STRICT, not directly hashable via std::hash.
// Reinterpret to uintptr_t for a stable, well-distributed hash.
// ---------------------------------------------------------------------------
struct HModuleHash {
    std::size_t operator()(HMODULE h) const noexcept {
        return std::hash<uintptr_t>{}(reinterpret_cast<uintptr_t>(h));
    }
};

// ---------------------------------------------------------------------------
// ApprovedModuleSet â€” tracks every DLL that passed through SecureLoadLibrary.
// The Runtime Monitor (BLOCO 7) queries IsModuleApproved() to distinguish
// validated modules from injected ones.
// ---------------------------------------------------------------------------
using ApprovedModuleMap = std::unordered_map<HMODULE, ModuleRecord, HModuleHash>;

static ApprovedModuleMap s_approved_modules;
static SRWLOCK           s_map_lock        = SRWLOCK_INIT;
static BOOL              s_initialized     = FALSE;
static BOOL              s_startup_complete = FALSE;

// ---------------------------------------------------------------------------
// EmitLoaderEvent â€” emits a structured log event from the Secure Loader.
// Routes to the Logging Engine when it is initialized; falls back to
// OutputDebugStringW for diagnostics during very early startup (before
// InitializeDefenseSystem() completes).
// ---------------------------------------------------------------------------
static void EmitLoaderEvent(LogSeverity    severity,
                             const wchar_t* source,
                             const wchar_t* dll_path,
                             LoadAction     action,
                             uint32_t       block_reasons,
                             float          score)
{
    if (IsLoggingEngineInitialized()) {
        LogEvent ev{};
        BuildLogEvent(severity,
                      source,
                      dll_path ? dll_path : L"",
                      score,
                      action,
                      block_reasons,
                      RiskLevel::Low,   // Secure Loader doesn't have full risk ctx
                      FALSE,
                      &ev);
        EmitLog(ev);
        return;
    }

    // Fallback: debug output only (pre-logging-engine startup)
    const wchar_t* sev_str = L"INFO";
    const wchar_t* act_str = L"ALLOWED";
    switch (severity) {
        case LogSeverity::Warning: sev_str = L"WARNING"; break;
        case LogSeverity::Alert:   sev_str = L"ALERT";   break;
        default: break;
    }
    switch (action) {
        case LoadAction::AllowedFlagged: act_str = L"ALLOWED_FLAGGED"; break;
        case LoadAction::Blocked:        act_str = L"BLOCKED";         break;
        case LoadAction::BlockedAlways:  act_str = L"BLOCKED_ALWAYS";  break;
        default: break;
    }
    wchar_t buf[1024];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE,
        L"[DHD][%ls][%ls] source=%ls dll=%ls score=%.2f reasons=0x%08X\n",
        sev_str, act_str, source, dll_path ? dll_path : L"(null)",
        static_cast<double>(score), block_reasons);
    OutputDebugStringW(buf);
}

// ---------------------------------------------------------------------------
// IsRelativePath
// Returns TRUE if |path| is relative (no drive letter, no UNC prefix).
// PathIsRelativeW returns TRUE for relative paths.
// We additionally reject UNC paths per policy.
// ---------------------------------------------------------------------------
static BOOL IsRelativePath(const wchar_t* path)
{
    if (!path || path[0] == L'\0') return TRUE;
    return PathIsRelativeW(path);
}

// ---------------------------------------------------------------------------
// IsUNCPath
// Returns TRUE if path begins with \\ (UNC or device path).
// ---------------------------------------------------------------------------
static BOOL IsUNCPath(const wchar_t* path)
{
    return (path && path[0] == L'\\' && path[1] == L'\\');
}

// ---------------------------------------------------------------------------
// CanonicalizePath
// Produces a long, normalized absolute path from |input| into |out_buf|.
// Steps:
//   1. GetLongPathNameW  â€” expand any 8.3 short names (e.g. PROGRA~1)
//   2. PathCanonicalizeW â€” collapse . and .. components
//
// Returns TRUE on success. On failure |out_buf| is zeroed.
// ---------------------------------------------------------------------------
static BOOL CanonicalizePath(const wchar_t* input,
                              wchar_t*       out_buf,
                              DWORD          out_cch)
{
    wchar_t long_path[MAX_PATH] = {};

    // Step 1: expand short names
    DWORD len = GetLongPathNameW(input, long_path, _countof(long_path));
    if (len == 0 || len >= _countof(long_path)) {
        // GetLongPathNameW may fail if the file doesn't exist yet; fall back
        // to copying the input as-is and let PathCanonicalize handle it.
        if (wcscpy_s(long_path, _countof(long_path), input) != 0) {
            return FALSE;
        }
    }

    // Step 2: canonicalize . and .. components
    if (!PathCanonicalizeW(out_buf, long_path)) {
        SecureZeroMemory(out_buf, out_cch * sizeof(wchar_t));
        return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// ResolveSymlinks
// Resolves all symlinks and junction points in |canonical_path| by opening
// a read-only handle and calling GetFinalPathNameByHandleW.
//
// The returned handle in |out_handle| is kept open (GENERIC_READ,
// FILE_SHARE_READ, no write/delete share) to lock the file against
// replacement between validation and load â€” TOCTOU prevention.
//
// Caller is responsible for CloseHandle(*out_handle) when done.
// Returns TRUE on success; FALSE if the file does not exist or access denied.
// ---------------------------------------------------------------------------
static BOOL ResolveSymlinks(const wchar_t* canonical_path,
                             wchar_t*       out_final_path,
                             DWORD          out_cch,
                             HANDLE*        out_handle)
{
    *out_handle = INVALID_HANDLE_VALUE;
    SecureZeroMemory(out_final_path, out_cch * sizeof(wchar_t));

    // Open with FILE_SHARE_READ only.
    // Deliberately omitting FILE_SHARE_WRITE and FILE_SHARE_DELETE prevents
    // any other process from modifying or renaming/deleting the file while
    // our handle is open â€” closing the TOCTOU window.
    HANDLE h = CreateFileW(
        canonical_path,
        GENERIC_READ,
        FILE_SHARE_READ,          // no FILE_SHARE_WRITE, no FILE_SHARE_DELETE
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (h == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // FILE_NAME_NORMALIZED resolves all reparse points (symlinks, junctions)
    // and returns the canonical device path in DOS format (e.g. C:\...).
    DWORD needed = GetFinalPathNameByHandleW(
        h,
        out_final_path,
        out_cch,
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
    );

    if (needed == 0 || needed >= out_cch) {
        CloseHandle(h);
        SecureZeroMemory(out_final_path, out_cch * sizeof(wchar_t));
        return FALSE;
    }

    // GetFinalPathNameByHandleW may return an extended-length prefix \\?\
    // Strip it for consistent whitelist comparisons.
    if (wcsncmp(out_final_path, L"\\\\?\\", 4) == 0) {
        // Shift left by 4 characters in-place
        DWORD actual_len = needed - 4;
        wmemmove(out_final_path, out_final_path + 4, actual_len + 1);
    }

    *out_handle = h;
    return TRUE;
}

// ---------------------------------------------------------------------------
// PopulateModuleRecord
// Fills a ModuleRecord for a successfully loaded module.
// ---------------------------------------------------------------------------
static void PopulateModuleRecord(HMODULE           hmod,
                                 const wchar_t*    path,
                                 float             trust_score,
                                 WhitelistTier     tier,
                                 ModuleRecord*     out_rec)
{
    SecureZeroMemory(out_rec, sizeof(ModuleRecord));
    out_rec->base_address   = hmod;
    out_rec->trust_score    = trust_score;
    out_rec->whitelist_tier = tier;
    out_rec->was_validated  = TRUE;
    out_rec->load_flags_used = SECURE_LOAD_FLAGS;
    GetSystemTimeAsFileTime(&out_rec->load_timestamp);

    // Prefer the actual path reported by Windows after loading
    if (!GetModuleFileNameW(hmod, out_rec->path, _countof(out_rec->path))) {
        wcscpy_s(out_rec->path, _countof(out_rec->path), path);
    }

    // Extract just the filename for out_rec->name
    const wchar_t* fname = PathFindFileNameW(out_rec->path);
    if (fname) {
        wcscpy_s(out_rec->name, _countof(out_rec->name), fname);
    }
}

// ---------------------------------------------------------------------------
// RegisterApprovedModule â€” insert into ApprovedModuleSet (exclusive lock).
// ---------------------------------------------------------------------------
static void RegisterApprovedModule(HMODULE handle, const ModuleRecord& rec)
{
    AcquireSRWLockExclusive(&s_map_lock);
    s_approved_modules[handle] = rec;
    ReleaseSRWLockExclusive(&s_map_lock);
}

// ---------------------------------------------------------------------------
// UnregisterApprovedModule â€” remove from ApprovedModuleSet (exclusive lock).
// ---------------------------------------------------------------------------
static void UnregisterApprovedModule(HMODULE handle)
{
    AcquireSRWLockExclusive(&s_map_lock);
    s_approved_modules.erase(handle);
    ReleaseSRWLockExclusive(&s_map_lock);
}

// ---------------------------------------------------------------------------
// BuildBlockedLoadResult â€” convenience helper to populate a failed LoadResult.
// ---------------------------------------------------------------------------
static void BuildBlockedLoadResult(LoadAction action,
                                   uint32_t   reasons,
                                   float      score,
                                   RiskLevel  risk,
                                   DWORD      win32_err,
                                   LoadResult* out)
{
    if (!out) return;
    out->handle        = nullptr;
    out->action        = action;
    out->block_reasons = reasons;
    out->trust_score   = score;
    out->risk_level    = risk;
    out->win32_error   = win32_err;
}

} // anonymous namespace

// ===========================================================================
// Public implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// InitializeSecureLoader
// ---------------------------------------------------------------------------
BOOL InitializeSecureLoader(const wchar_t* policy_file_path)
{
    // Idempotency guard â€” safe to call multiple times but only acts once.
    if (s_initialized) {
        return TRUE;
    }

    // -----------------------------------------------------------------------
    // Step 1: Harden the DLL search environment for this process.
    //
    // SetDefaultDllDirectories removes the current working directory and the
    // PATH environment variable from the implicit DLL search order.
    // These two locations are responsible for the vast majority of DLL
    // Hijacking attacks in the wild.
    // -----------------------------------------------------------------------
    if (!SetDefaultDllDirectories(SAFE_DLL_SEARCH_FLAGS)) {
        // Non-fatal: log and continue. The loader will still operate but with
        // slightly reduced environmental isolation.
        OutputDebugStringW(
            L"[DHD][WARNING][SECURE_LOADER] "
            L"SetDefaultDllDirectories failed â€” search order not hardened.\n"
        );
    }

    // SetDllDirectoryW(NULL) explicitly removes any directory previously set
    // via SetDllDirectoryW (including the empty-string CWD entry).
    // Belt-and-suspenders for the above call.
    SetDllDirectoryW(nullptr);

    // -----------------------------------------------------------------------
    // Step 2: Load policy. If the file is not found or malformed, compile-time
    // defaults apply and the loader remains operational.
    // -----------------------------------------------------------------------
    BOOL policy_ok = PolicyManager::LoadPolicy(policy_file_path);

    // -----------------------------------------------------------------------
    // Step 3: Reserve capacity in the ApprovedModuleSet to avoid rehashing
    // during the hot startup path.
    // -----------------------------------------------------------------------
    {
        AcquireSRWLockExclusive(&s_map_lock);
        s_approved_modules.reserve(128);
        ReleaseSRWLockExclusive(&s_map_lock);
    }

    s_initialized = TRUE;

    EmitLoaderEvent(
        policy_ok ? LogSeverity::Info : LogSeverity::Warning,
        source::SECURE_LOADER,
        nullptr,
        LoadAction::Allowed,
        BR_NONE,
        1.0f
    );

    return policy_ok;
}

// ---------------------------------------------------------------------------
// MarkStartupComplete / IsStartupComplete
// ---------------------------------------------------------------------------
void MarkStartupComplete()
{
    AcquireSRWLockExclusive(&s_map_lock);
    s_startup_complete = TRUE;
    ReleaseSRWLockExclusive(&s_map_lock);
}

BOOL IsStartupComplete()
{
    AcquireSRWLockShared(&s_map_lock);
    BOOL v = s_startup_complete;
    ReleaseSRWLockShared(&s_map_lock);
    return v;
}

// ---------------------------------------------------------------------------
// ShutdownSecureLoader
// ---------------------------------------------------------------------------
void ShutdownSecureLoader()
{
    AcquireSRWLockExclusive(&s_map_lock);
    s_approved_modules.clear();
    s_initialized      = FALSE;
    s_startup_complete = FALSE;
    ReleaseSRWLockExclusive(&s_map_lock);
}

// ---------------------------------------------------------------------------
// SecureLoadLibrary â€” the complete secure load pipeline.
// ---------------------------------------------------------------------------
HMODULE SecureLoadLibrary(const wchar_t* requested_name,
                          LoadResult*    out_result)
{
    // -----------------------------------------------------------------------
    // Guard: loader must be initialized.
    // -----------------------------------------------------------------------
    if (!s_initialized) {
        if (out_result) {
            BuildBlockedLoadResult(
                LoadAction::BlockedAlways,
                BR_NONE,
                0.0f,
                RiskLevel::Critical,
                ERROR_NOT_READY,
                out_result
            );
        }
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Step 1: Basic input validation.
    // -----------------------------------------------------------------------
    if (!requested_name || requested_name[0] == L'\0') {
        if (out_result) {
            BuildBlockedLoadResult(
                LoadAction::BlockedAlways,
                BR_PATH_RELATIVE,
                0.0f,
                RiskLevel::Critical,
                ERROR_INVALID_PARAMETER,
                out_result
            );
        }
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Step 2: Reject relative paths immediately â€” no exception, no fallback.
    // This is the #1 DLL Hijacking vector: never allow resolution of
    // ambiguous paths via the OS search order.
    // -----------------------------------------------------------------------
    if (IsRelativePath(requested_name)) {
        EmitLoaderEvent(LogSeverity::Alert, source::SECURE_LOADER,
                     requested_name, LoadAction::BlockedAlways,
                     BR_PATH_RELATIVE, 0.0f);

        if (out_result) {
            BuildBlockedLoadResult(
                LoadAction::BlockedAlways,
                BR_PATH_RELATIVE,
                0.0f,
                RiskLevel::Critical,
                ERROR_BAD_PATHNAME,
                out_result
            );
        }
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Step 2b: Reject UNC paths if policy disallows them.
    // -----------------------------------------------------------------------
    const PolicyConfig& policy = PolicyManager::GetConfig();

    if (!policy.allow_unc_paths && IsUNCPath(requested_name)) {
        EmitLoaderEvent(LogSeverity::Alert, source::SECURE_LOADER,
                     requested_name, LoadAction::BlockedAlways,
                     BR_PATH_IS_UNC, 0.0f);

        if (out_result) {
            BuildBlockedLoadResult(
                LoadAction::BlockedAlways,
                BR_PATH_IS_UNC,
                0.0f,
                RiskLevel::Critical,
                ERROR_BAD_NETPATH,
                out_result
            );
        }
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Step 3: Canonicalize â€” expand 8.3 names, collapse . and ..
    // -----------------------------------------------------------------------
    wchar_t canonical_path[MAX_PATH] = {};
    if (!CanonicalizePath(requested_name, canonical_path,
                          _countof(canonical_path)))
    {
        DWORD err = GetLastError();
        EmitLoaderEvent(LogSeverity::Alert, source::SECURE_LOADER,
                     requested_name, LoadAction::BlockedAlways,
                     BR_PATH_NOT_IN_WHITELIST, 0.0f);

        if (out_result) {
            BuildBlockedLoadResult(
                LoadAction::BlockedAlways,
                BR_PATH_NOT_IN_WHITELIST,
                0.0f,
                RiskLevel::Critical,
                err,
                out_result
            );
        }
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Step 4: Open a shared-read, no-write, no-delete file handle.
    // This handle is held open through the entire validation + load sequence
    // to prevent TOCTOU: the file cannot be replaced, renamed, or deleted
    // while this handle is open without FILE_SHARE_WRITE/DELETE.
    // -----------------------------------------------------------------------
    wchar_t final_path[MAX_PATH] = {};
    HANDLE  validation_handle    = INVALID_HANDLE_VALUE;

    if (!ResolveSymlinks(canonical_path, final_path,
                         _countof(final_path), &validation_handle))
    {
        DWORD err = GetLastError();
        EmitLoaderEvent(LogSeverity::Alert, source::SECURE_LOADER,
                     canonical_path, LoadAction::BlockedAlways,
                     BR_SYMLINK_RESOLUTION_FAIL, 0.0f);

        if (out_result) {
            BuildBlockedLoadResult(
                LoadAction::BlockedAlways,
                BR_SYMLINK_RESOLUTION_FAIL,
                0.0f,
                RiskLevel::Critical,
                err,
                out_result
            );
        }
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Step 5: Re-check final (post-symlink) path against blocked directories.
    // An attacker might construct: whitelist_dir_symlink -> temp_dir/evil.dll
    // Without this check, the symlink would pass the initial whitelist check
    // but actually load from a blocked location.
    // -----------------------------------------------------------------------
    if (PolicyManager::IsPathBlocked(final_path)) {
        CloseHandle(validation_handle);

        EmitLoaderEvent(LogSeverity::Alert, source::SECURE_LOADER,
                     final_path, LoadAction::BlockedAlways,
                     BR_PATH_IN_BLOCKED_DIR, 0.0f);

        if (out_result) {
            BuildBlockedLoadResult(
                LoadAction::BlockedAlways,
                BR_PATH_IN_BLOCKED_DIR,
                0.0f,
                RiskLevel::Critical,
                ERROR_ACCESS_DENIED,
                out_result
            );
        }
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Step 6: Run the DLL Validator pipeline.
    // ValidateDLL() is declared in dll_validator.h and implemented in BLOCO 4.
    // It operates on |validation_handle| â€” the same handle we opened above â€”
    // so hash computation never re-opens the file.
    // -----------------------------------------------------------------------
    BOOL             is_post_startup = IsStartupComplete();
    ValidationResult vr              = {};

    BOOL validator_ok = ValidateDLL(
        validation_handle,
        final_path,
        is_post_startup,
        &vr
    );

    if (!validator_ok) {
        // Internal validator error (I/O failure, memory issue) â€” treat as
        // maximum risk; never load on validator internal failure.
        CloseHandle(validation_handle);

        EmitLoaderEvent(LogSeverity::Alert, source::SECURE_LOADER,
                     final_path, LoadAction::BlockedAlways,
                     BR_HASH_COMPUTE_FAILURE, 0.0f);

        if (out_result) {
            BuildBlockedLoadResult(
                LoadAction::BlockedAlways,
                BR_HASH_COMPUTE_FAILURE,
                0.0f,
                RiskLevel::Critical,
                GetLastError(),
                out_result
            );
        }
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Step 7: Determine load action from aggregate score + active policy mode.
    // -----------------------------------------------------------------------
    LoadAction action = PolicyManager::DetermineAction(vr.aggregate_score);

    if (action == LoadAction::Blocked ||
        action == LoadAction::BlockedAlways)
    {
        CloseHandle(validation_handle);

        LogSeverity sev = (action == LoadAction::BlockedAlways)
                        ? LogSeverity::Alert
                        : LogSeverity::Warning;

        EmitLoaderEvent(sev, source::SECURE_LOADER,
                     final_path, action,
                     vr.block_reasons, vr.aggregate_score);

        if (out_result) {
            BuildBlockedLoadResult(
                action,
                vr.block_reasons,
                vr.aggregate_score,
                vr.risk_level,
                ERROR_ACCESS_DENIED,
                out_result
            );
        }
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Step 8: Load the DLL.
    //
    // LOAD_WITH_ALTERED_SEARCH_PATH: interpret first argument as full path,
    //   bypassing the DLL search order entirely for this load.
    // LOAD_LIBRARY_SEARCH_SYSTEM32:  restrict resolution of the loaded DLL's
    //   own implicit imports to System32 only.
    //
    // The validation_handle remains open during this call â€” preventing TOCTOU.
    // -----------------------------------------------------------------------
    HMODULE hmod = LoadLibraryExW(final_path, nullptr, SECURE_LOAD_FLAGS);
    DWORD   load_err = GetLastError();

    // -----------------------------------------------------------------------
    // Step 9: Close the validation handle now that the OS has mapped the file.
    // The mapping holds its own internal reference; our handle is no longer
    // needed.
    // -----------------------------------------------------------------------
    CloseHandle(validation_handle);
    validation_handle = INVALID_HANDLE_VALUE;

    if (!hmod) {
        // LoadLibraryExW failed after successful validation.
        // This can happen if the file was replaced in the nanosecond window
        // between CloseHandle and internal OS mapping â€” highly unlikely with
        // our locking strategy but possible in adversarial conditions.
        // Flag as TOCTOU for forensic analysis.
        EmitLoaderEvent(LogSeverity::Alert, source::SECURE_LOADER,
                     final_path, LoadAction::BlockedAlways,
                     BR_TOCTOU_DETECTED, vr.aggregate_score);

        if (out_result) {
            BuildBlockedLoadResult(
                LoadAction::BlockedAlways,
                BR_TOCTOU_DETECTED,
                vr.aggregate_score,
                RiskLevel::Critical,
                load_err,
                out_result
            );
        }
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Step 10: Verify the loaded module's path matches what we validated.
    // GetModuleFileNameW returns the path Windows actually loaded â€” if it
    // differs from our final_path, something unexpected happened.
    // -----------------------------------------------------------------------
    wchar_t loaded_path[MAX_PATH] = {};
    if (GetModuleFileNameW(hmod, loaded_path, _countof(loaded_path))) {
        // Strip extended-length prefix if present
        const wchar_t* compare_loaded = loaded_path;
        if (wcsncmp(compare_loaded, L"\\\\?\\", 4) == 0) {
            compare_loaded += 4;
        }
        if (_wcsicmp(compare_loaded, final_path) != 0) {
            // Path mismatch â€” unload and treat as TOCTOU
            FreeLibrary(hmod);

            EmitLoaderEvent(LogSeverity::Alert, source::SECURE_LOADER,
                         final_path, LoadAction::BlockedAlways,
                         BR_TOCTOU_DETECTED, vr.aggregate_score);

            if (out_result) {
                BuildBlockedLoadResult(
                    LoadAction::BlockedAlways,
                    BR_TOCTOU_DETECTED,
                    vr.aggregate_score,
                    RiskLevel::Critical,
                    ERROR_INVALID_DATA,
                    out_result
                );
            }
            return nullptr;
        }
    }

    // -----------------------------------------------------------------------
    // Step 11: Register in ApprovedModuleSet.
    // -----------------------------------------------------------------------
    ModuleRecord rec = {};
    PopulateModuleRecord(hmod, final_path, vr.aggregate_score,
                         vr.whitelist_tier, &rec);
    RegisterApprovedModule(hmod, rec);

    // -----------------------------------------------------------------------
    // Step 12: Emit log event.
    // -----------------------------------------------------------------------
    LogSeverity log_sev = (action == LoadAction::AllowedFlagged)
                        ? LogSeverity::Warning
                        : LogSeverity::Info;

    EmitLoaderEvent(log_sev, source::SECURE_LOADER,
                 final_path, action,
                 vr.block_reasons, vr.aggregate_score);

    // -----------------------------------------------------------------------
    // Step 13: Populate caller's LoadResult and return handle.
    // -----------------------------------------------------------------------
    if (out_result) {
        out_result->handle        = hmod;
        out_result->action        = action;
        out_result->block_reasons = vr.block_reasons;
        out_result->trust_score   = vr.aggregate_score;
        out_result->risk_level    = vr.risk_level;
        out_result->win32_error   = ERROR_SUCCESS;
    }

    return hmod;
}

// ---------------------------------------------------------------------------
// SecureUnloadLibrary
// ---------------------------------------------------------------------------
void SecureUnloadLibrary(HMODULE handle)
{
    if (!handle) return;

    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(handle, path, _countof(path));

    UnregisterApprovedModule(handle);

    EmitLoaderEvent(LogSeverity::Info, source::SECURE_LOADER,
                 path, LoadAction::Allowed, BR_NONE, 0.0f);

    FreeLibrary(handle);
}

// ---------------------------------------------------------------------------
// IsModuleApproved
// ---------------------------------------------------------------------------
BOOL IsModuleApproved(HMODULE handle)
{
    if (!handle) return FALSE;

    AcquireSRWLockShared(&s_map_lock);
    bool found = (s_approved_modules.find(handle) != s_approved_modules.end());
    ReleaseSRWLockShared(&s_map_lock);

    return found ? TRUE : FALSE;
}

// ---------------------------------------------------------------------------
// GetApprovedModuleRecord
// ---------------------------------------------------------------------------
BOOL GetApprovedModuleRecord(HMODULE handle, ModuleRecord* out_record)
{
    if (!handle || !out_record) return FALSE;

    AcquireSRWLockShared(&s_map_lock);
    auto it = s_approved_modules.find(handle);
    if (it == s_approved_modules.end()) {
        ReleaseSRWLockShared(&s_map_lock);
        return FALSE;
    }
    *out_record = it->second;
    ReleaseSRWLockShared(&s_map_lock);
    return TRUE;
}

// ---------------------------------------------------------------------------
// GetApprovedModuleCount
// ---------------------------------------------------------------------------
size_t GetApprovedModuleCount()
{
    AcquireSRWLockShared(&s_map_lock);
    size_t count = s_approved_modules.size();
    ReleaseSRWLockShared(&s_map_lock);
    return count;
}

} // namespace dhd
