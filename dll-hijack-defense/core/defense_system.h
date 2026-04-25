#pragma once

// =============================================================================
// core/defense_system.h
// Unified initialization and shutdown facade for the DLL Hijacking Defense
// System.
//
// InitializeDefenseSystem() is the single entry point a host application calls
// to bring up every subsystem in the correct order:
//
//   1. LoggingEngine           — must be first so all subsequent steps can log
//   2. PolicyManager           — load policy.json before any validation
//   3. DLL Validator           — load hash_database.json; build approved set
//   4. Risk Analyzer           — initialize baseline / burst state
//   5. Secure Loader           — harden DLL search order (SetDefaultDllDirectories)
//   6. Runtime Monitor         — begin watching for unapproved module loads
//
// ShutdownDefenseSystem() tears down in reverse order:
//   1. StopMonitor             — stop receiving new load events
//   2. ShutdownLoggingEngine   — drain queue, flush log, zero HMAC key
//
// Intended to be called once per process lifetime. Calling
// InitializeDefenseSystem() more than once returns FALSE on the second call.
//
// Thread safety:
//   InitializeDefenseSystem() and ShutdownDefenseSystem() are NOT
//   thread-safe with respect to each other and must be called from a single
//   initializer thread (e.g., DllMain/PROCESS_ATTACH or main()).
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "types.h"
#include "runtime_monitor.h"  // for MonitorCallback typedef

namespace dhd {

// ===========================================================================
// Configuration
// ===========================================================================

// ---------------------------------------------------------------------------
// DefenseSystemConfig
// All fields have sensible defaults (see DefenseSystemConfig() constructor).
// Pass NULL paths to use defaults:
//   policy_file_path  — defaults to "policy\defaults.json" (relative to CWD)
//   hash_db_path      — defaults to "config\hash_database.json"
//   log_directory     — defaults to "logs\" (relative to CWD)
// ---------------------------------------------------------------------------
struct DefenseSystemConfig {
    // -----------------------------------------------------------------------
    // Paths
    // -----------------------------------------------------------------------
    wchar_t policy_file_path[MAX_PATH];  // Path to the policy JSON
    wchar_t hash_db_path    [MAX_PATH];  // Path to hash_database.json
    wchar_t log_directory   [MAX_PATH];  // Directory for .log files

    // -----------------------------------------------------------------------
    // Runtime Monitor
    // -----------------------------------------------------------------------
    DWORD           monitor_poll_interval_ms;  // Polling interval (default 5000)
    MonitorCallback monitor_callback;          // Called on unapproved DLL detection
    void*           monitor_user_data;         // Passed verbatim to callback

    // -----------------------------------------------------------------------
    // Default constructor — uses relative-path defaults, 5-second polling,
    // no callback.
    // -----------------------------------------------------------------------
    DefenseSystemConfig()
    {
        SecureZeroMemory(this, sizeof(*this));

        // Relative paths — resolved at runtime against CWD of the host process.
        wcscpy_s(policy_file_path, _countof(policy_file_path),
                 L"policy\\defaults.json");
        wcscpy_s(hash_db_path,     _countof(hash_db_path),
                 L"config\\hash_database.json");
        wcscpy_s(log_directory,    _countof(log_directory),
                 L"logs");

        monitor_poll_interval_ms = 5000;
        monitor_callback         = nullptr;
        monitor_user_data        = nullptr;
    }
};

// ===========================================================================
// Lifecycle
// ===========================================================================

// ---------------------------------------------------------------------------
// InitializeDefenseSystem
//
// Brings up all subsystems in dependency order.
//
// Returns TRUE if all critical subsystems initialized successfully.
// Returns FALSE if any critical subsystem fails (partial init is cleaned up).
//
// The Logging Engine and Policy Manager failures are non-fatal — the system
// continues with degraded logging / safe-default policy.
// The DLL Validator and Secure Loader are critical; failure returns FALSE.
//
// |config| may be NULL, in which case DefenseSystemConfig defaults apply.
// ---------------------------------------------------------------------------
BOOL InitializeDefenseSystem(const DefenseSystemConfig* config);

// ---------------------------------------------------------------------------
// ShutdownDefenseSystem
//
// Stops the Runtime Monitor and shuts down the Logging Engine.
// Safe to call even if InitializeDefenseSystem() was never called or failed.
// Blocks until all background threads have exited.
// ---------------------------------------------------------------------------
void ShutdownDefenseSystem();

// ---------------------------------------------------------------------------
// IsDefenseSystemInitialized
// Returns TRUE after a successful InitializeDefenseSystem() and before
// ShutdownDefenseSystem() is called.
// ---------------------------------------------------------------------------
BOOL IsDefenseSystemInitialized();

} // namespace dhd
