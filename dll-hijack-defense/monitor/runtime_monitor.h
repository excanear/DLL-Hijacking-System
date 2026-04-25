#pragma once

// =============================================================================
// monitor/runtime_monitor.h
// Public interface of the Runtime Monitor.
//
// The Runtime Monitor continuously observes the set of modules loaded into
// the current process and alerts when any module appears that was NOT loaded
// through the Secure Loader (i.e., not in the ApprovedModuleSet).
//
// Detection strategy (two-layer):
//   Layer A — ETW (preferred)
//     Subscribes to the Microsoft-Windows-Kernel-Process provider, ImageLoad
//     event (Event ID 5). Receives near-real-time notification of every DLL
//     mapped into the process.
//   Layer B — Polling (fallback / belt-and-suspenders)
//     If ETW initialization fails or the platform does not support the
//     provider, falls back to periodic EnumProcessModulesEx snapshots.
//     Also runs in parallel to ETW to catch modules loaded between events.
//
// On detection of an unapproved module:
//   - Block reason BR_UNEXPECTED_MODULE is set on the finding.
//   - A LogEvent with severity ALERT is emitted.
//   - The caller-registered callback (if any) is invoked on a dedicated
//     thread — never on the ETW callback thread.
//
// Threading:
//   All public functions are thread-safe after StartMonitor().
//   The callback is invoked from the monitor's internal thread — the
//   callback must be re-entrant and must not call StopMonitor().
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

#include "types.h"
#include "constants.h"

namespace dhd {

// ---------------------------------------------------------------------------
// MonitorFinding
// Produced each time an unapproved module is detected.
// ---------------------------------------------------------------------------
struct MonitorFinding {
    HMODULE   module_base;             // base address of the rogue module
    wchar_t   module_path[MAX_PATH];   // full path as reported by OS
    wchar_t   module_name[256];        // filename only
    FILETIME  detected_at;             // when detection occurred
    BOOL      detected_by_etw;         // TRUE = ETW, FALSE = polling
    uint32_t  block_reasons;           // always includes BR_UNEXPECTED_MODULE
};

// ---------------------------------------------------------------------------
// MonitorCallback
// Called (from a monitor-internal thread) when an unapproved module is
// detected. The callback MUST return quickly; do not call StopMonitor()
// from within it.
// ---------------------------------------------------------------------------
using MonitorCallback = void (*)(const MonitorFinding& finding, void* user_data);

// ===========================================================================
// Lifecycle
// ===========================================================================

// ---------------------------------------------------------------------------
// StartMonitor
// Initializes and starts the Runtime Monitor.
//
// Must be called AFTER:
//   - InitializeSecureLoader()
//   - InitializeLoggingEngine()
//   - MarkStartupComplete() (so that startup-phase loads don't alert)
//
// |callback|   — optional function called on detection. May be NULL.
// |user_data|  — passed verbatim to |callback|. May be NULL.
//
// Returns TRUE if the monitor started (ETW or polling).
// Returns FALSE only if both ETW AND polling threads could not start.
// ---------------------------------------------------------------------------
BOOL StartMonitor(MonitorCallback callback, void* user_data);

// ---------------------------------------------------------------------------
// StopMonitor
// Signals the monitor to stop and waits for all internal threads to exit.
// Safe to call even if StartMonitor() was never called.
// Timeout: 10 seconds per thread.
// ---------------------------------------------------------------------------
void StopMonitor();

// ---------------------------------------------------------------------------
// IsMonitorRunning
// Returns TRUE if the monitor was started and has not been stopped.
// ---------------------------------------------------------------------------
BOOL IsMonitorRunning();

// ===========================================================================
// Diagnostic / Test Support
// ===========================================================================

// ---------------------------------------------------------------------------
// ForcePollingSnapshot
// Triggers an immediate polling snapshot regardless of the timer interval.
// Blocks until the snapshot is complete.
// Used in tests to avoid waiting for the polling interval.
// ---------------------------------------------------------------------------
void ForcePollingSnapshot();

// ---------------------------------------------------------------------------
// GetFindingCount
// Returns the total number of unapproved-module findings since StartMonitor().
// ---------------------------------------------------------------------------
uint64_t GetFindingCount();

} // namespace dhd
