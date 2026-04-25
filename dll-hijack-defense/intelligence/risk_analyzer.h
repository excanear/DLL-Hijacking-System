#pragma once

// =============================================================================
// intelligence/risk_analyzer.h
// Public interface of the Risk Analyzer.
//
// The Risk Analyzer operates above the DLL Validator: it receives the raw
// ValidationResult produced by the validator and enriches it with contextual
// intelligence — process privilege level, behavioral baseline deviation,
// burst detection, and evaluation of the full rule set (R001–R007).
//
// Output is a final RiskAssessment that includes:
//   - A contextual risk score (may differ from validator aggregate score)
//   - A confirmed risk classification (LOW/MEDIUM/HIGH/CRITICAL)
//   - Triggered rule codes
//   - Anomaly flag and description
//
// Threading: All public functions are thread-safe after InitializeRiskAnalyzer().
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

// ---------------------------------------------------------------------------
// RuleCode — bitmask of triggered detection rules.
// Multiple rules may fire simultaneously.
// ---------------------------------------------------------------------------
enum RuleCode : uint32_t {
    RULE_NONE = 0x00000000,
    RULE_R001 = 0x00000001,  // System DLL name outside System32
    RULE_R002 = 0x00000002,  // DLL without valid signature
    RULE_R003 = 0x00000004,  // DLL loaded from temp/blocked directory
    RULE_R004 = 0x00000008,  // Typosquatting (Levenshtein)
    RULE_R005 = 0x00000010,  // Homoglyph Unicode characters in name
    RULE_R006 = 0x00000020,  // Unvetted DLL in privileged process context
    RULE_R007 = 0x00000040,  // Burst: N+ suspicious DLLs in time window
};

// ---------------------------------------------------------------------------
// RiskContext
// Contextual information about the load event, supplementing the static
// ValidationResult with runtime process and timing data.
// ---------------------------------------------------------------------------
struct RiskContext {
    // --- Process information ---
    DWORD    pid;
    wchar_t  process_name[MAX_PATH];  // name of the hosting process
    BOOL     is_privileged;           // TRUE if process token is SYSTEM or admin
    BOOL     is_service;              // TRUE if running in a service session

    // --- Load event timing ---
    FILETIME event_time;              // when the load was requested
    BOOL     is_post_startup;         // TRUE after MarkStartupComplete()

    // --- Behavioral context ---
    BOOL     was_seen_before;         // TRUE if this DLL was loaded by this
                                      // process in a previous session
    DWORD    load_sequence_number;    // monotonic counter for this process
};

// ---------------------------------------------------------------------------
// RiskAssessment
// Final output of the Risk Analyzer for a single DLL load event.
// ---------------------------------------------------------------------------
struct RiskAssessment {
    // Scores
    float    validator_score;    // raw aggregate from DLL Validator
    float    contextual_score;   // final score after contextual modifiers
    float    anomaly_penalty;    // deduction applied for behavioral anomaly

    // Classification
    RiskLevel    risk_level;     // final classification
    LoadAction   recommended_action;

    // Triggered rules
    uint32_t triggered_rules;   // bitfield of RuleCode values
    wchar_t  rule_summary[256]; // human-readable list of triggered rules

    // Anomaly
    BOOL     is_anomalous;
    wchar_t  anomaly_description[256];

    // Burst detection
    BOOL     burst_triggered;
    uint32_t burst_count;        // how many suspicious loads in the window
};

// ===========================================================================
// Lifecycle
// ===========================================================================

// ---------------------------------------------------------------------------
// InitializeRiskAnalyzer
// Must be called once after PolicyManager::LoadPolicy().
// Initializes internal state: behavioral baseline map, burst detection
// ring buffer, load sequence counter.
// ---------------------------------------------------------------------------
void InitializeRiskAnalyzer();

// ---------------------------------------------------------------------------
// ShutdownRiskAnalyzer
// Releases all internal resources. Call during process cleanup.
// ---------------------------------------------------------------------------
void ShutdownRiskAnalyzer();

// ===========================================================================
// Core Functions
// ===========================================================================

// ---------------------------------------------------------------------------
// AnalyzeRisk
//
// Primary entry point. Given the ValidationResult from the DLL Validator
// and the RiskContext of the current load event, produces a RiskAssessment.
//
// Steps:
//   1. Copy validator score as the baseline contextual score.
//   2. Evaluate rules R001–R007 against the combined data.
//   3. Apply contextual modifiers (privilege, burst, anomaly).
//   4. Compute final score and classify.
//   5. Update behavioral baseline for future anomaly detection.
//   6. Update burst detection ring buffer.
//
// |out_assessment| must not be NULL.
// ---------------------------------------------------------------------------
void AnalyzeRisk(const ValidationResult& validation,
                 const RiskContext&       context,
                 RiskAssessment*          out_assessment);

// ---------------------------------------------------------------------------
// BuildRiskContext
// Convenience helper: populate a RiskContext from the current process.
// Queries the process token for privilege level and fills timing fields.
// |is_post_startup| and |was_seen_before| are supplied by the caller since
// the analyzer cannot determine them without additional context.
// ---------------------------------------------------------------------------
void BuildRiskContext(BOOL   is_post_startup,
                      BOOL   was_seen_before,
                      DWORD  load_sequence_number,
                      RiskContext* out_ctx);

// ---------------------------------------------------------------------------
// RecordApprovedLoad
// Notify the Risk Analyzer that a DLL was successfully loaded and approved.
// This feeds the behavioral baseline used for anomaly detection.
// Call AFTER SecureLoadLibrary returns a valid HMODULE.
// ---------------------------------------------------------------------------
void RecordApprovedLoad(const wchar_t* dll_name,
                         const wchar_t* process_name,
                         float          trust_score);

// ---------------------------------------------------------------------------
// GetBurstCount
// Returns how many suspicious (score < BURST_SCORE_CEILING) DLL loads have
// occurred within the current burst detection window.
// Primarily for diagnostics and test assertions.
// ---------------------------------------------------------------------------
uint32_t GetBurstCount();

} // namespace dhd
