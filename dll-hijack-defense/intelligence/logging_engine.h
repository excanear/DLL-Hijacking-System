#pragma once

// =============================================================================
// intelligence/logging_engine.h
// Public interface of the Logging Engine.
//
// The Logging Engine is the central event persistence layer. It:
//   - Accepts LogEvent structs from any module via EmitLog()
//   - Queues events in a lock-free producer-consumer ring buffer
//   - Processes events asynchronously on a dedicated background thread
//   - Serializes events as JSON Lines (one JSON object per line)
//   - Computes per-entry HMAC-SHA256 for tamper detection
//   - Rotates log files when the current file exceeds the configured size
//   - Emits WARNING and ALERT events to the Windows Event Log
//
// Threading:
//   - All public functions are thread-safe after InitializeLoggingEngine().
//   - EmitLog() is non-blocking for the caller.
//   - HMAC-SHA256 is computed on the consumer thread (not the caller).
//
// HMAC key:
//   Generated with BCryptGenRandom at initialization — session-scoped.
//   The key is zeroed in memory at ShutdownLoggingEngine().
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
// InitializeLoggingEngine
// Must be called before any EmitLog(). Creates the log directory if absent,
// opens the initial log file, generates the HMAC key, registers the Windows
// Event Log source, and starts the background writer thread.
//
// |log_directory| — absolute path to the directory where .log files are
//   written. The directory is created if it does not exist. Pass NULL to
//   use ".\logs\" relative to the working directory.
// ---------------------------------------------------------------------------
BOOL InitializeLoggingEngine(const wchar_t* log_directory);

// ---------------------------------------------------------------------------
// ShutdownLoggingEngine
// Drains the queue, flushes and closes the log file, deregisters the Event
// Log source, and zeroes the HMAC key. Blocks until the background thread
// exits (10-second timeout).
// ---------------------------------------------------------------------------
void ShutdownLoggingEngine();

// ---------------------------------------------------------------------------
// IsLoggingEngineInitialized
// Returns TRUE after a successful InitializeLoggingEngine() and before
// ShutdownLoggingEngine() is called.
// ---------------------------------------------------------------------------
BOOL IsLoggingEngineInitialized();

// ===========================================================================
// Core Functions
// ===========================================================================

// ---------------------------------------------------------------------------
// EmitLog
// Thread-safe, non-blocking. Copies |event| into the internal queue.
// If the queue is at capacity, the event is dropped and the drop counter
// is incremented (see GetDroppedEventCount).
// The HMAC field in |event| does not need to be pre-filled — the engine
// computes it before writing.
// ---------------------------------------------------------------------------
void EmitLog(const LogEvent& event);

// ---------------------------------------------------------------------------
// BuildLogEvent
// Convenience helper. Fills the common fields of a LogEvent from the
// current process context (timestamp, host name, PID, process name,
// schema_version). The caller fills severity, source_module, dll_path,
// trust_score, action, block_reasons, risk_level, was_prevalidated.
// |out_event| must not be NULL.
// ---------------------------------------------------------------------------
void BuildLogEvent(LogSeverity    severity,
                   const wchar_t* source_module,
                   const wchar_t* dll_path,
                   float          trust_score,
                   LoadAction     action,
                   uint32_t       block_reasons,
                   RiskLevel      risk_level,
                   BOOL           was_prevalidated,
                   LogEvent*      out_event);

// ---------------------------------------------------------------------------
// FlushLog
// Synchronously drains the queue and calls FlushFileBuffers on the log file.
// Blocks until all pending events have been written to disk (5-second timeout).
// Use before shutdown, after critical events, or in tests.
// ---------------------------------------------------------------------------
void FlushLog();

// ---------------------------------------------------------------------------
// GetDroppedEventCount
// Returns the number of events dropped due to queue overflow since
// InitializeLoggingEngine() was last called.
// ---------------------------------------------------------------------------
uint64_t GetDroppedEventCount();

} // namespace dhd
