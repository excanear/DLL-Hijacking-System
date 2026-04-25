// =============================================================================
// intelligence/risk_analyzer.cpp
// Implementation of the Risk Analyzer — contextual intelligence layer
// that enriches DLL Validator results with process context, behavioral
// baseline deviation, and full R001–R007 rule evaluation.
//
// Internal structure:
//   BurstRingBuffer   — circular buffer of suspicious-load timestamps (R007)
//   BaselineStore     — per-process DLL baseline (anomaly detection)
//   Rule evaluators   — one function per rule R001–R007
//   AnalyzeRisk       — orchestrator
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <security.h>
#include <securitybaseapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

#include "risk_analyzer.h"
#include "policy.h"
#include "constants.h"
#include "types.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace dhd {

// ===========================================================================
// Internal constants — contextual modifiers applied on top of validator score
// ===========================================================================
static constexpr float CTX_PRIVILEGE_UNVETTED_PENALTY = -0.15f;  // R006
static constexpr float CTX_BURST_PENALTY              = -0.10f;  // R007
static constexpr float CTX_ANOMALY_PENALTY            = -0.05f;  // baseline

// ===========================================================================
// Section 1 — Burst Detection Ring Buffer (R007)
// Fixed-capacity circular buffer of FILETIME values.
// Each entry represents when a "suspicious" DLL load occurred.
// Entries older than rule_r007_window_seconds are considered expired.
// ===========================================================================

namespace {

static constexpr size_t BURST_RING_CAPACITY = 64;

struct BurstRingBuffer {
    FILETIME entries[BURST_RING_CAPACITY];
    size_t   head    = 0;
    size_t   count   = 0;

    void Push(FILETIME ts) {
        entries[head % BURST_RING_CAPACITY] = ts;
        head = (head + 1) % BURST_RING_CAPACITY;
        if (count < BURST_RING_CAPACITY) ++count;
    }

    // Count entries within the last |window_seconds| seconds before |now|.
    uint32_t CountWithinWindow(FILETIME now, uint32_t window_seconds) const
    {
        // Convert window to 100-ns intervals
        ULONGLONG window_ticks =
            static_cast<ULONGLONG>(window_seconds) * 10'000'000ULL;

        ULONGLONG now_val =
            (static_cast<ULONGLONG>(now.dwHighDateTime) << 32) |
             static_cast<ULONGLONG>(now.dwLowDateTime);

        uint32_t c = 0;
        for (size_t i = 0; i < count; ++i) {
            ULONGLONG entry_val =
                (static_cast<ULONGLONG>(entries[i].dwHighDateTime) << 32) |
                 static_cast<ULONGLONG>(entries[i].dwLowDateTime);

            if (now_val >= entry_val &&
                (now_val - entry_val) <= window_ticks)
            {
                ++c;
            }
        }
        return c;
    }
};

static BurstRingBuffer s_burst_buf;
static SRWLOCK         s_burst_lock = SRWLOCK_INIT;

// ===========================================================================
// Section 2 — Behavioral Baseline Store (anomaly detection)
// Maps (process_name → set<dll_name_lower>) of historically approved loads.
// Protected by s_baseline_lock.
// ===========================================================================

struct BaselineStore {
    // Maps lowercased process name → set of lowercased DLL names seen before
    std::unordered_map<std::wstring, std::unordered_set<std::wstring>> data;
};

static BaselineStore s_baseline;
static SRWLOCK       s_baseline_lock = SRWLOCK_INIT;

// ---------------------------------------------------------------------------
// Helper — lowercase wide string in-place copy
// ---------------------------------------------------------------------------
static std::wstring ToLowerW(const wchar_t* s)
{
    if (!s) return {};
    std::wstring out = s;
    for (wchar_t& c : out) c = towlower(c);
    return out;
}

// ---------------------------------------------------------------------------
// CheckBaselineAnomaly
// Returns TRUE if this (process, dll) combination has never been seen before.
// ---------------------------------------------------------------------------
static BOOL CheckBaselineAnomaly(const wchar_t* process_name,
                                  const wchar_t* dll_name)
{
    const PolicyConfig& cfg = PolicyManager::GetConfig();
    if (!cfg.anomaly_detection_enabled) return FALSE;
    if (!process_name || !dll_name) return FALSE;

    std::wstring proc_lw = ToLowerW(process_name);
    std::wstring dll_lw  = ToLowerW(dll_name);

    AcquireSRWLockShared(&s_baseline_lock);
    auto it = s_baseline.data.find(proc_lw);
    if (it == s_baseline.data.end()) {
        // Process never seen — first-time load, treat as anomalous
        ReleaseSRWLockShared(&s_baseline_lock);
        return TRUE;
    }
    bool seen = (it->second.count(dll_lw) > 0);
    ReleaseSRWLockShared(&s_baseline_lock);

    return seen ? FALSE : TRUE;   // anomaly = NOT seen before
}

// ===========================================================================
// Section 3 — Rule Evaluators (R001–R007)
// Each evaluator takes the validation + context and appends to
// |triggered_rules| if the rule fires. The function does NOT modify the
// score — score adjustment is handled by the orchestrator.
// ===========================================================================

// R001: System DLL name loaded from outside System32/SysWOW64/WinSxS
static void EvalR001(const ValidationResult& v,
                      const PolicyConfig& cfg,
                      uint32_t* triggered)
{
    if (!cfg.rule_r001_enabled) return;
    // The validator already checks this and sets BR_RULE_SYSTEM_DLL_OUTSIDE.
    // Propagate the flag to the rule set.
    if (v.block_reasons & BR_RULE_SYSTEM_DLL_OUTSIDE) {
        *triggered |= RULE_R001;
    }
}

// R002: DLL has no valid Authenticode signature (and is not Tier1)
static void EvalR002(const ValidationResult& v,
                      const PolicyConfig& cfg,
                      uint32_t* triggered)
{
    if (!cfg.rule_r002_enabled) return;

    BOOL absent  = (v.block_reasons & BR_SIGNATURE_ABSENT)  ? TRUE : FALSE;
    BOOL invalid = (v.block_reasons & BR_SIGNATURE_INVALID)  ? TRUE : FALSE;

    // Only fire outside Tier1 — Tier1 development scenarios are handled
    // by the validator's partial-credit logic.
    if ((absent || invalid) && v.whitelist_tier != WhitelistTier::Tier1) {
        *triggered |= RULE_R002;
    }
}

// R003: DLL from temp or other blocked directory
static void EvalR003(const ValidationResult& v,
                      const PolicyConfig& cfg,
                      uint32_t* triggered)
{
    if (!cfg.rule_r003_enabled) return;
    if ((v.block_reasons & BR_PATH_IN_BLOCKED_DIR) ||
        (v.block_reasons & BR_RULE_TEMP_DIRECTORY))
    {
        *triggered |= RULE_R003;
    }
}

// R004: Typosquatting (Levenshtein distance)
static void EvalR004(const ValidationResult& v,
                      const PolicyConfig& cfg,
                      uint32_t* triggered)
{
    if (cfg.rule_r004_levenshtein_max == 0) return;
    if (v.block_reasons & BR_NAME_TYPOSQUATTING) {
        *triggered |= RULE_R004;
    }
}

// R005: Homoglyph / non-ASCII characters in DLL name
static void EvalR005(const ValidationResult& v,
                      const PolicyConfig& cfg,
                      uint32_t* triggered)
{
    if (!cfg.rule_r005_enabled) return;
    if (v.block_reasons & BR_NAME_HOMOGLYPH) {
        *triggered |= RULE_R005;
    }
}

// R006: Unvetted DLL loaded into a privileged process
// "Unvetted" = not in Tier1, not hash-approved, and/or no valid signature.
static void EvalR006(const ValidationResult& v,
                      const RiskContext& ctx,
                      const PolicyConfig& cfg,
                      uint32_t* triggered)
{
    if (!cfg.rule_r006_enabled) return;
    if (!ctx.is_privileged && !ctx.is_service) return;

    // Consider a DLL "unvetted" if any of the following are true:
    BOOL unsigned_dll  = (v.block_reasons & (BR_SIGNATURE_ABSENT | BR_SIGNATURE_INVALID)) ? TRUE : FALSE;
    BOOL hash_unknown  = (v.block_reasons & BR_HASH_NOT_FOUND) ? TRUE : FALSE;
    BOOL not_whitelisted = (v.whitelist_tier == WhitelistTier::None) ? TRUE : FALSE;

    if (unsigned_dll || hash_unknown || not_whitelisted) {
        *triggered |= RULE_R006;
    }
}

// R007: Burst — N+ suspicious DLL loads within the detection window
// "Suspicious" = aggregate_score < BURST_SCORE_CEILING before context mods
static void EvalR007(const ValidationResult& v,
                      const RiskContext& ctx,
                      const PolicyConfig& cfg,
                      uint32_t* triggered,
                      uint32_t* out_burst_count)
{
    *out_burst_count = 0;
    if (!cfg.rule_r007_enabled) return;

    // If this load is suspicious, record it in the ring buffer first,
    // then count the window.
    if (v.aggregate_score < BURST_SCORE_CEILING) {
        AcquireSRWLockExclusive(&s_burst_lock);
        s_burst_buf.Push(ctx.event_time);
        uint32_t c = s_burst_buf.CountWithinWindow(
            ctx.event_time, cfg.rule_r007_window_seconds);
        ReleaseSRWLockExclusive(&s_burst_lock);

        *out_burst_count = c;
        if (c >= cfg.rule_r007_threshold) {
            *triggered |= RULE_R007;
        }
    }
}

// ===========================================================================
// Section 4 — Rule summary builder
// Produces a short human-readable string from the triggered rule bitmask.
// ===========================================================================

static void BuildRuleSummary(uint32_t triggered,
                               wchar_t* out, size_t cch)
{
    out[0] = L'\0';
    if (triggered == RULE_NONE) {
        wcscpy_s(out, cch, L"NONE");
        return;
    }

    struct RuleEntry { uint32_t mask; const wchar_t* name; };
    static const RuleEntry TABLE[] = {
        { RULE_R001, L"R001" }, { RULE_R002, L"R002" },
        { RULE_R003, L"R003" }, { RULE_R004, L"R004" },
        { RULE_R005, L"R005" }, { RULE_R006, L"R006" },
        { RULE_R007, L"R007" },
    };

    bool first = true;
    for (const auto& e : TABLE) {
        if (triggered & e.mask) {
            if (!first) {
                size_t cur = wcslen(out);
                if (cur + 2 < cch) { out[cur] = L','; out[cur+1] = L' '; out[cur+2] = L'\0'; }
            }
            size_t cur = wcslen(out);
            if (cur + wcslen(e.name) < cch) {
                wcscpy_s(out + cur, cch - cur, e.name);
            }
            first = false;
        }
    }
}

} // anonymous namespace

// ===========================================================================
// Section 5 — Public API
// ===========================================================================

void InitializeRiskAnalyzer()
{
    AcquireSRWLockExclusive(&s_burst_lock);
    SecureZeroMemory(&s_burst_buf, sizeof(s_burst_buf));
    ReleaseSRWLockExclusive(&s_burst_lock);

    AcquireSRWLockExclusive(&s_baseline_lock);
    s_baseline.data.clear();
    ReleaseSRWLockExclusive(&s_baseline_lock);
}

void ShutdownRiskAnalyzer()
{
    AcquireSRWLockExclusive(&s_burst_lock);
    SecureZeroMemory(&s_burst_buf, sizeof(s_burst_buf));
    ReleaseSRWLockExclusive(&s_burst_lock);

    AcquireSRWLockExclusive(&s_baseline_lock);
    s_baseline.data.clear();
    ReleaseSRWLockExclusive(&s_baseline_lock);
}

// ---------------------------------------------------------------------------
// AnalyzeRisk — orchestrator
// ---------------------------------------------------------------------------
void AnalyzeRisk(const ValidationResult& validation,
                  const RiskContext&       context,
                  RiskAssessment*          out_assessment)
{
    if (!out_assessment) return;
    SecureZeroMemory(out_assessment, sizeof(RiskAssessment));

    const PolicyConfig& cfg = PolicyManager::GetConfig();

    // 1. Start with the validator's aggregate score as the contextual baseline
    float ctx_score = validation.aggregate_score;
    out_assessment->validator_score = validation.aggregate_score;

    // 2. Evaluate rules R001–R007
    uint32_t triggered   = RULE_NONE;
    uint32_t burst_count = 0;

    EvalR001(validation, cfg, &triggered);
    EvalR002(validation, cfg, &triggered);
    EvalR003(validation, cfg, &triggered);
    EvalR004(validation, cfg, &triggered);
    EvalR005(validation, cfg, &triggered);
    EvalR006(validation, context, cfg, &triggered);
    EvalR007(validation, context, cfg, &triggered, &burst_count);

    out_assessment->triggered_rules = triggered;
    out_assessment->burst_count     = burst_count;
    out_assessment->burst_triggered = (triggered & RULE_R007) ? TRUE : FALSE;

    BuildRuleSummary(triggered, out_assessment->rule_summary,
                     _countof(out_assessment->rule_summary));

    // 3. Apply contextual modifiers
    float anomaly_penalty = 0.0f;

    // 3a. Privilege penalty (R006): process is privileged and DLL is unvetted
    if (triggered & RULE_R006) {
        ctx_score += CTX_PRIVILEGE_UNVETTED_PENALTY;
    }

    // 3b. Burst penalty (R007)
    if (triggered & RULE_R007) {
        ctx_score += CTX_BURST_PENALTY;
    }

    // 3c. Behavioral anomaly: DLL never seen in this process before
    out_assessment->is_anomalous = FALSE;
    out_assessment->anomaly_description[0] = L'\0';

    if (cfg.anomaly_detection_enabled) {
        // Use was_seen_before hint from caller if available,
        // otherwise query the internal baseline
        BOOL anomalous = FALSE;
        if (!context.was_seen_before) {
            const wchar_t* dll_name =
                PathFindFileNameW(validation.failure_reason[0] != L'\0'
                    ? validation.failure_reason
                    : L"unknown.dll");

            anomalous = CheckBaselineAnomaly(context.process_name,
                                              dll_name);
        }

        if (anomalous) {
            anomaly_penalty  = CTX_ANOMALY_PENALTY;
            ctx_score       += anomaly_penalty;

            out_assessment->is_anomalous = TRUE;
            _snwprintf_s(out_assessment->anomaly_description,
                          _countof(out_assessment->anomaly_description),
                          _TRUNCATE,
                          L"DLL not in baseline for process '%ls'",
                          context.process_name);
        }
    }

    out_assessment->anomaly_penalty = anomaly_penalty;

    // 3d. Clamp contextual score to [0.0, 1.0]
    if (ctx_score < 0.0f) ctx_score = 0.0f;
    if (ctx_score > 1.0f) ctx_score = 1.0f;

    out_assessment->contextual_score = ctx_score;

    // 4. Classify using contextual score via policy thresholds
    if (ctx_score >= cfg.threshold_block_always) {
        out_assessment->risk_level = RiskLevel::Critical;
    } else if (ctx_score >= cfg.threshold_block_strict) {
        out_assessment->risk_level = RiskLevel::High;
    } else if (ctx_score > cfg.threshold_allow) {
        out_assessment->risk_level = RiskLevel::Medium;
    } else {
        out_assessment->risk_level = RiskLevel::Low;
    }

    // 5. Determine recommended action
    // In Audit mode, only Critical is actually blocked.
    // In Strict mode, High and Critical are blocked.
    out_assessment->recommended_action = PolicyManager::DetermineAction(ctx_score);
}

// ---------------------------------------------------------------------------
// BuildRiskContext — populate from current process
// ---------------------------------------------------------------------------
void BuildRiskContext(BOOL   is_post_startup,
                       BOOL   was_seen_before,
                       DWORD  load_sequence_number,
                       RiskContext* out_ctx)
{
    if (!out_ctx) return;
    SecureZeroMemory(out_ctx, sizeof(RiskContext));

    // PID
    out_ctx->pid = GetCurrentProcessId();

    // Process name (executable filename only)
    wchar_t exe_path[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, exe_path, MAX_PATH)) {
        const wchar_t* fname = PathFindFileNameW(exe_path);
        if (fname) {
            wcscpy_s(out_ctx->process_name, _countof(out_ctx->process_name),
                     fname);
        }
    }

    // Timing
    GetSystemTimeAsFileTime(&out_ctx->event_time);
    out_ctx->is_post_startup        = is_post_startup;
    out_ctx->was_seen_before        = was_seen_before;
    out_ctx->load_sequence_number   = load_sequence_number;

    // Privilege: check if the current token is elevated / SYSTEM
    HANDLE hToken = nullptr;
    out_ctx->is_privileged = FALSE;
    out_ctx->is_service    = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elev{};
        DWORD cb = 0;
        if (GetTokenInformation(hToken, TokenElevation,
                                 &elev, sizeof(elev), &cb))
        {
            out_ctx->is_privileged = elev.TokenIsElevated ? TRUE : FALSE;
        }

        // Check if running as SYSTEM
        BYTE sid_buf[SECURITY_MAX_SID_SIZE];
        DWORD sid_sz = sizeof(sid_buf);
        if (CreateWellKnownSid(WinLocalSystemSid,
                                nullptr,
                                reinterpret_cast<PSID>(sid_buf),
                                &sid_sz))
        {
            BOOL is_system = FALSE;
            if (CheckTokenMembership(hToken,
                                      reinterpret_cast<PSID>(sid_buf),
                                      &is_system) && is_system)
            {
                out_ctx->is_privileged = TRUE;
                out_ctx->is_service    = TRUE;
            }
        }

        CloseHandle(hToken);
    }
}

// ---------------------------------------------------------------------------
// RecordApprovedLoad — update behavioral baseline
// ---------------------------------------------------------------------------
void RecordApprovedLoad(const wchar_t* dll_name,
                          const wchar_t* process_name,
                          float          trust_score)
{
    const PolicyConfig& cfg = PolicyManager::GetConfig();
    if (!cfg.anomaly_detection_enabled) return;
    if (!dll_name || !process_name) return;

    // Only record DLLs that are genuinely trusted (low risk)
    if (trust_score > cfg.threshold_allow) return;

    std::wstring proc_lw = ToLowerW(process_name);
    std::wstring dll_lw  = ToLowerW(PathFindFileNameW(dll_name));
    if (dll_lw.empty()) return;

    AcquireSRWLockExclusive(&s_baseline_lock);
    s_baseline.data[proc_lw].insert(dll_lw);
    ReleaseSRWLockExclusive(&s_baseline_lock);
}

// ---------------------------------------------------------------------------
// GetBurstCount — diagnostic query
// ---------------------------------------------------------------------------
uint32_t GetBurstCount()
{
    const PolicyConfig& cfg = PolicyManager::GetConfig();

    FILETIME now;
    GetSystemTimeAsFileTime(&now);

    AcquireSRWLockShared(&s_burst_lock);
    uint32_t c = s_burst_buf.CountWithinWindow(now, cfg.rule_r007_window_seconds);
    ReleaseSRWLockShared(&s_burst_lock);

    return c;
}

} // namespace dhd
