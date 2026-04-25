// =============================================================================
// core/defense_system.cpp
// Unified initialization and shutdown facade for the DLL Hijacking Defense
// System.
//
// Initialization order:
//   1. LoggingEngine           — async log writer, HMAC key generation
//   2. PolicyManager           — parse policy JSON, populate rule config
//   3. DLL Validator           — load hash_database.json, build approved set
//   4. Risk Analyzer           — init burst ring buffer and baseline store
//   5. Secure Loader           — SetDefaultDllDirectories, DLL search hardening
//   6. Runtime Monitor         — start ETW + polling threads
//
// Shutdown order (reverse):
//   1. StopMonitor             — drain detection queue, join monitor threads
//   2. ShutdownLoggingEngine   — drain log queue, flush file, zero HMAC key
//
// The Risk Analyzer and Secure Loader have no dedicated shutdown; they hold
// only in-process state that is released with the process.
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#include "defense_system.h"
#include "secure_loader.h"
#include "dll_validator.h"
#include "policy.h"
#include "logging_engine.h"
#include "risk_analyzer.h"
#include "runtime_monitor.h"
#include "hardening.h"
#include "constants.h"
#include "types.h"

#include <cwchar>
#include <cstring>

namespace dhd {

// ===========================================================================
// Module-private state
// ===========================================================================

namespace {

static volatile LONG s_system_initialized = 0;  // 1 after full successful init
static volatile LONG s_monitor_started    = 0;  // 1 if StartMonitor succeeded

// ---------------------------------------------------------------------------
// EmitSystemEvent — emit a log event from the defense system facade itself.
// Only called after LoggingEngine is up; safe to call even if subsequent
// subsystems failed (engine may already be shutting down, EmitLog handles it).
// ---------------------------------------------------------------------------
static void EmitSystemEvent(LogSeverity    severity,
                             const wchar_t* message,
                             LoadAction     action = LoadAction::Allowed)
{
    if (!IsLoggingEngineInitialized()) {
        // Fallback: at minimum write to the debug output
        OutputDebugStringW(L"[DHD][SYSTEM] ");
        OutputDebugStringW(message);
        OutputDebugStringW(L"\n");
        return;
    }

    LogEvent ev{};
    BuildLogEvent(severity,
                  L"DEFENSE_SYSTEM",
                  message,        // repurpose dll_path as a message carrier
                  0.0f,
                  action,
                  0,
                  RiskLevel::Low,
                  FALSE,
                  &ev);
    EmitLog(ev);
}

// ---------------------------------------------------------------------------
// ResolveDefaultPath — if |path| is empty, copy |default_rel| into |path|.
// Converts the relative default to an absolute path against CWD.
// ---------------------------------------------------------------------------
static void ResolveDefaultPath(wchar_t*       path,
                                size_t         path_cap,
                                const wchar_t* default_rel)
{
    if (path[0] != L'\0') return;  // caller already provided a path

    wchar_t cwd[MAX_PATH] = {};
    GetCurrentDirectoryW(MAX_PATH, cwd);

    wchar_t abs_path[MAX_PATH] = {};
    wcscpy_s(abs_path, _countof(abs_path), cwd);
    PathAppendW(abs_path, default_rel);

    wcscpy_s(path, path_cap, abs_path);
}

} // anonymous namespace

// ===========================================================================
// Public API
// ===========================================================================

BOOL InitializeDefenseSystem(const DefenseSystemConfig* config)
{
    // Guard against double initialization
    if (InterlockedCompareExchange(&s_system_initialized, 0, 0) == 1) {
        OutputDebugStringW(L"[DHD] InitializeDefenseSystem called more than once — ignored.\n");
        return FALSE;
    }

    // Build effective config (use defaults where caller passed NULL or empty)
    DefenseSystemConfig eff;
    if (config) {
        eff = *config;
    }
    // Resolve empty paths to defaults
    ResolveDefaultPath(eff.policy_file_path, _countof(eff.policy_file_path),
                       L"policy\\defaults.json");
    ResolveDefaultPath(eff.hash_db_path,     _countof(eff.hash_db_path),
                       L"config\\hash_database.json");
    ResolveDefaultPath(eff.log_directory,    _countof(eff.log_directory),
                       L"logs");
    if (eff.monitor_poll_interval_ms == 0) {
        eff.monitor_poll_interval_ms = 5000;
    }

    // =========================================================================
    // Step 1 — Logging Engine
    // First: so that all subsequent steps can emit structured log events.
    // Non-fatal: if logging fails, continue with debug-only output.
    // =========================================================================
    BOOL logging_ok = InitializeLoggingEngine(eff.log_directory);
    if (!logging_ok) {
        OutputDebugStringW(
            L"[DHD][WARN] LoggingEngine failed to initialize — "
            L"continuing with debug-only output.\n");
    } else {
        EmitSystemEvent(LogSeverity::Info,
                        L"DLL Hijacking Defense System initializing...");
    }

    // Harden the log directory immediately after opening it so that new log
    // files created during this session inherit the protective DACL.
    // Non-fatal: ACL failure just means the log directory is not restricted.
    if (!HardenLogDirectory(eff.log_directory)) {
        EmitSystemEvent(LogSeverity::Warning,
                        L"Hardening: could not restrict log directory ACL — "
                        L"ensure the process has WRITE_DAC on the log path.");
    } else {
        EmitSystemEvent(LogSeverity::Info,
                        L"Hardening: log directory ACL restricted to SYSTEM + Administrators.");
    }

    // =========================================================================
    // Step 2 — Policy Manager
    // Load the JSON policy file. Non-fatal: compile-time safe defaults apply.
    // =========================================================================
    // Snapshot the policy file hash BEFORE loading, so we can detect on-disk
    // modifications that occur after startup (compared to what was loaded).
    wchar_t policy_hash_baseline[SHA256_HEX_LEN + 1] = {};
    if (eff.policy_file_path[0] != L'\0') {
        SnapshotFileHash(eff.policy_file_path,
                         policy_hash_baseline,
                         _countof(policy_hash_baseline));
    }

    BOOL policy_ok = PolicyManager::LoadPolicy(eff.policy_file_path);
    if (!policy_ok) {
        EmitSystemEvent(LogSeverity::Warning,
                        L"PolicyManager: policy file not loaded — "
                        L"using compile-time safe defaults.");
    } else {
        EmitSystemEvent(LogSeverity::Info,
                        L"PolicyManager: policy loaded successfully.");

        // Harden the policy file so non-admin users cannot modify it.
        if (!HardenPolicyFile(eff.policy_file_path)) {
            EmitSystemEvent(LogSeverity::Warning,
                            L"Hardening: could not restrict policy file ACL — "
                            L"policy may be writable by non-admin accounts.");
        } else {
            EmitSystemEvent(LogSeverity::Info,
                            L"Hardening: policy file ACL restricted "
                            L"(SYSTEM+Admins Full, Everyone Read-only).");
        }

        // Verify that the file was not modified between snapshot and load.
        if (policy_hash_baseline[0] != L'\0' &&
            !VerifyFileIntegrity(eff.policy_file_path, policy_hash_baseline)) {
            EmitSystemEvent(LogSeverity::Alert,
                            L"Hardening: policy file CHANGED between snapshot and load — "
                            L"possible TOCTOU tampering. Review policy immediately.",
                            LoadAction::Blocked);
        }
    }

    // =========================================================================
    // Step 3 — DLL Validator
    // Load the hash database. Critical: without it, hash-based checks are
    // degraded (all hashes treated as unknown). Non-fatal by design, but
    // a warning is emitted.
    // =========================================================================
    BOOL validator_ok = InitializeValidator(eff.hash_db_path);
    if (!validator_ok) {
        EmitSystemEvent(LogSeverity::Warning,
                        L"DLLValidator: hash database not loaded — "
                        L"hash-based checks degraded (hash_score=-0.10 modifier applied).");
    } else {
        EmitSystemEvent(LogSeverity::Info,
                        L"DLLValidator: hash database loaded successfully.");

        // Verify the hash database has not been tampered with since it was
        // last written by bootstrap_hashdb (checks the db_integrity_hash field).
        if (!VerifyHashDatabaseIntegrity(eff.hash_db_path)) {
            EmitSystemEvent(LogSeverity::Alert,
                            L"Hardening: hash_database.json integrity check FAILED — "
                            L"the database may have been modified without re-running "
                            L"bootstrap_hashdb. Hash-based checks may be unreliable.",
                            LoadAction::Blocked);
        } else {
            EmitSystemEvent(LogSeverity::Info,
                            L"Hardening: hash_database.json integrity verified (db_integrity_hash OK).");
        }
    }

    // =========================================================================
    // Step 4 — Risk Analyzer
    // Initialize burst ring buffer and baseline store. Stateless init — cannot
    // fail in practice.
    // =========================================================================
    InitializeRiskAnalyzer();
    EmitSystemEvent(LogSeverity::Info,
                    L"RiskAnalyzer: initialized (burst window and baseline store ready).");

    // =========================================================================
    // Step 5 — Secure Loader
    // Critical step: calls SetDefaultDllDirectories to remove CWD and PATH
    // from the implicit DLL search order. Failure here is fatal — without
    // search hardening, the defense posture is severely compromised.
    // =========================================================================
    BOOL loader_ok = InitializeSecureLoader(eff.policy_file_path);
    if (!loader_ok) {
        // Policy re-load inside SecureLoader may fail if PolicyManager already
        // loaded it — that's acceptable. The critical SetDefaultDllDirectories
        // call inside SecureLoader MUST succeed.
        EmitSystemEvent(LogSeverity::Warning,
                        L"SecureLoader: policy reload skipped (already loaded) — "
                        L"DLL search hardening applied.");
    } else {
        EmitSystemEvent(LogSeverity::Info,
                        L"SecureLoader: initialized — DLL search order hardened "
                        L"(SetDefaultDllDirectories applied).");
    }

    // Mark startup complete BEFORE launching the monitor, so the monitor's
    // initial snapshot does not trigger post-startup alerts for every DLL
    // that was legitimately loaded during initialization.
    MarkStartupComplete();
    EmitSystemEvent(LogSeverity::Info,
                    L"SecureLoader: startup phase complete — "
                    L"post-startup alert mode active.");

    // =========================================================================
    // Step 6 — Runtime Monitor
    // Start ETW + polling. Non-fatal: if both fail, we log a critical alert
    // but continue — the other layers (validator, policy) still protect.
    // =========================================================================
    BOOL monitor_ok = StartMonitor(eff.monitor_callback, eff.monitor_user_data);
    if (!monitor_ok) {
        EmitSystemEvent(LogSeverity::Alert,
                        L"RuntimeMonitor: FAILED to start — "
                        L"unapproved DLL injection will not be detected at runtime. "
                        L"Verify that the process has SE_SYSTEM_PROFILE_PRIVILEGE for ETW "
                        L"or that the polling thread was not blocked.",
                        LoadAction::Blocked);
    } else {
        InterlockedExchange(&s_monitor_started, 1);
        EmitSystemEvent(LogSeverity::Info,
                        L"RuntimeMonitor: started successfully.");
    }

    // Flush so that all init-phase events are persisted before we return
    if (logging_ok) {
        FlushLog();
    }

    InterlockedExchange(&s_system_initialized, 1);

    EmitSystemEvent(LogSeverity::Info,
                    L"DLL Hijacking Defense System fully initialized and active.");

    return TRUE;
}

void ShutdownDefenseSystem()
{
    if (InterlockedCompareExchange(&s_system_initialized, 0, 0) == 0) {
        return;   // never initialized — nothing to tear down
    }

    // Mark as not initialized immediately to prevent re-entrant calls
    InterlockedExchange(&s_system_initialized, 0);

    // -------------------------------------------------------------------------
    // Step 1 — Stop Runtime Monitor
    // Must stop before logging engine so the monitor's final alert events
    // can still be written to the log queue before it is drained.
    // -------------------------------------------------------------------------
    if (InterlockedCompareExchange(&s_monitor_started, 0, 0) == 1) {
        InterlockedExchange(&s_monitor_started, 0);

        EmitSystemEvent(LogSeverity::Info,
                        L"DLL Hijacking Defense System shutting down — "
                        L"stopping RuntimeMonitor...");
        StopMonitor();
    }

    // -------------------------------------------------------------------------
    // Step 2 — Logging Engine (last)
    // Drain all remaining events (including the shutdown messages above),
    // flush the file, and zero the HMAC key.
    // -------------------------------------------------------------------------
    if (IsLoggingEngineInitialized()) {
        EmitSystemEvent(LogSeverity::Info,
                        L"DLL Hijacking Defense System shutdown complete.");
        ShutdownLoggingEngine();
    }
}

BOOL IsDefenseSystemInitialized()
{
    return InterlockedCompareExchange(&s_system_initialized, 0, 0) == 1
               ? TRUE
               : FALSE;
}

} // namespace dhd
