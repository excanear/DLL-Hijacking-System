#pragma once

// =============================================================================
// core/secure_loader.h
// Public interface of the Secure Loader — the single, mandatory entry point
// for every DLL load operation in the process.
//
// Design contract:
//   - No DLL may be loaded via LoadLibrary/LoadLibraryEx directly.
//     Every load MUST go through SecureLoadLibrary().
//   - InitializeSecureLoader() MUST be called before any other function,
//     and before any dynamic DLL load occurs.
//   - Thread-safe after initialization.
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "types.h"
#include "constants.h"

namespace dhd {

// ===========================================================================
// Lifecycle
// ===========================================================================

// ---------------------------------------------------------------------------
// InitializeSecureLoader
//
// Must be the FIRST call in the process, before any dynamic DLL load.
// Performs three critical setup steps:
//   1. SetDefaultDllDirectories — removes CWD and PATH from implicit search
//   2. SetDllDirectoryW(NULL)   — belt-and-suspenders removal of CWD
//   3. Loads policy from |policy_file_path| via PolicyManager
//
// |policy_file_path| may be NULL, in which case compile-time defaults apply.
//
// Returns TRUE on full success.
// Returns FALSE if policy file could not be read (safe defaults still apply
// and the loader is still operational — failure is non-fatal by design).
// ---------------------------------------------------------------------------
BOOL InitializeSecureLoader(const wchar_t* policy_file_path);

// ---------------------------------------------------------------------------
// MarkStartupComplete
//
// Call once the process has finished its initial DLL loading phase.
// After this point, any newly discovered DLL load triggers the
// post_startup_penalty modifier and raises the risk score.
// ---------------------------------------------------------------------------
void MarkStartupComplete();

// ---------------------------------------------------------------------------
// IsStartupComplete
// Returns TRUE if MarkStartupComplete() has been called.
// ---------------------------------------------------------------------------
BOOL IsStartupComplete();

// ---------------------------------------------------------------------------
// ShutdownSecureLoader
//
// Releases all internal resources (ApprovedModuleSet, locks).
// Call during process cleanup / DllMain DLL_PROCESS_DETACH if embedded.
// ---------------------------------------------------------------------------
void ShutdownSecureLoader();

// ===========================================================================
// Core Operations
// ===========================================================================

// ---------------------------------------------------------------------------
// SecureLoadLibrary
//
// The ONLY authorized way to load a DLL within the defense system.
//
// Execution pipeline:
//   1. Reject if |requested_name| is a relative path.
//   2. Canonicalize path (GetLongPathNameW + PathCanonicalize).
//   3. Open a shared-read-only, no-write, no-delete file handle.
//      This handle remains open through step 8 to prevent TOCTOU.
//   4. Resolve all symlinks/junctions via GetFinalPathNameByHandleW.
//   5. Re-validate final path against whitelist and blocked directories.
//   6. Invoke DLL Validator pipeline → ValidationResult + trust score.
//   7. Determine LoadAction via PolicyManager.
//   8. If allowed: call LoadLibraryExW with SECURE_LOAD_FLAGS.
//   9. Verify the loaded module's path matches the validated path.
//  10. Register in ApprovedModuleSet.
//  11. Close the validation file handle.
//  12. Emit structured log event.
//
// Parameters:
//   |requested_name| — absolute path to the DLL (relative paths are
//                      rejected immediately with BR_PATH_RELATIVE).
//   |out_result|     — optional; receives the full LoadResult including
//                      trust score, action taken, and block reasons.
//                      May be NULL if the caller only needs the HMODULE.
//
// Returns:
//   Valid HMODULE on success (Allowed or AllowedFlagged).
//   NULL if blocked, validation failed, or LoadLibraryExW failed.
//   When NULL, out_result.win32_error contains the relevant error code.
// ---------------------------------------------------------------------------
HMODULE SecureLoadLibrary(const wchar_t* requested_name,
                          LoadResult*    out_result);

// ---------------------------------------------------------------------------
// SecureUnloadLibrary
//
// Counterpart to SecureLoadLibrary. Removes |handle| from the
// ApprovedModuleSet and calls FreeLibrary. Emits an INFO log event.
//
// Calling FreeLibrary directly (bypassing this function) will leave a
// stale entry in the ApprovedModuleSet — the Runtime Monitor will not
// flag it as injected, but the entry will remain until process exit.
// ---------------------------------------------------------------------------
void SecureUnloadLibrary(HMODULE handle);

// ===========================================================================
// ApprovedModuleSet — Query Interface
// Used by the Runtime Monitor to distinguish validated modules from
// injected ones without coupling to the Secure Loader's internals.
// ===========================================================================

// ---------------------------------------------------------------------------
// IsModuleApproved
// Returns TRUE if |handle| is present in the ApprovedModuleSet,
// meaning it was loaded through SecureLoadLibrary and passed validation.
// ---------------------------------------------------------------------------
BOOL IsModuleApproved(HMODULE handle);

// ---------------------------------------------------------------------------
// GetApprovedModuleRecord
// Copies the ModuleRecord for |handle| into |out_record|.
// Returns TRUE if found, FALSE if |handle| is unknown or |out_record| NULL.
// ---------------------------------------------------------------------------
BOOL GetApprovedModuleRecord(HMODULE handle, ModuleRecord* out_record);

// ---------------------------------------------------------------------------
// GetApprovedModuleCount
// Returns the number of entries currently in the ApprovedModuleSet.
// Primarily for diagnostics and test assertions.
// ---------------------------------------------------------------------------
size_t GetApprovedModuleCount();

} // namespace dhd
