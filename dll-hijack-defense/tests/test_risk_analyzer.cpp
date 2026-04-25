// =============================================================================
// tests/test_risk_analyzer.cpp
// Unit tests for the Risk Analyzer (BLOCO 5).
//
// Coverage:
//   - R001: System DLL name resolved outside System32
//   - R002: Missing or invalid signature
//   - R003: DLL loaded from blocked directory (temp)
//   - R004: Levenshtein typosquatting
//   - R005: Homoglyph in DLL name
//   - R006: Unvetted DLL in privileged context
//   - R007: Burst detection (N+ suspicious loads in window)
//   - Score clamping: contextual_score in [0.0, 1.0]
//   - RecordApprovedLoad + anomaly detection (baseline)
//   - BuildRiskContext: populates pid, is_privileged
// =============================================================================

#include <gtest/gtest.h>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "risk_analyzer.h"
#include "dll_validator.h"
#include "policy.h"
#include "constants.h"
#include "types.h"

using namespace dhd;

// ===========================================================================
// Helpers — construct minimal ValidationResult for testing
// ===========================================================================

static ValidationResult MakeResult(float      score,
                                    uint32_t   block_reasons = 0,
                                    LoadAction action        = LoadAction::Allowed,
                                    WhitelistTier tier       = WhitelistTier::NotListed)
{
    ValidationResult r{};
    r.trust_score        = score;
    r.block_reasons      = block_reasons;
    r.recommended_action = action;
    r.whitelist_tier     = tier;
    wcscpy_s(r.dll_path, _countof(r.dll_path), L"C:\\Test\\evil.dll");
    return r;
}

static RiskContext MakeCtx(BOOL is_privileged     = FALSE,
                            BOOL is_post_startup   = FALSE,
                            BOOL was_seen_before   = FALSE)
{
    RiskContext ctx{};
    ctx.pid                  = GetCurrentProcessId();
    ctx.is_privileged        = is_privileged;
    ctx.is_service           = FALSE;
    ctx.is_post_startup      = is_post_startup;
    ctx.was_seen_before      = was_seen_before;
    ctx.load_sequence_number = 0;
    wcscpy_s(ctx.process_name, _countof(ctx.process_name), L"test_host.exe");
    GetSystemTimeAsFileTime(&ctx.event_time);
    return ctx;
}

// ===========================================================================
// Fixture
// ===========================================================================

class RiskAnalyzerTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        PolicyManager::LoadPolicy(nullptr);
        InitializeValidator(nullptr);
        InitializeRiskAnalyzer();
    }
};

// ===========================================================================
// R001 — System DLL name outside System32
// ===========================================================================

TEST_F(RiskAnalyzerTest, R001_SystemDllOutsideSystem32_RaisesScore)
{
    // BR_OUTSIDE_SYSTEM32 fires in dll_validator and is propagated by R001
    ValidationResult vr = MakeResult(0.40f, BR_OUTSIDE_SYSTEM32,
                                      LoadAction::AllowedFlagged);
    RiskContext ctx      = MakeCtx();

    RiskAssessment ra{};
    AnalyzeRisk(vr, ctx, &ra);

    EXPECT_NE(ra.triggered_rules & RULE_R001, 0u)
        << "R001 should trigger when BR_OUTSIDE_SYSTEM32 is set";
    EXPECT_GT(ra.contextual_score, vr.trust_score)
        << "Contextual score should exceed validator score for R001";
}

// ===========================================================================
// R002 — Signature absent / invalid
// ===========================================================================

TEST_F(RiskAnalyzerTest, R002_SignatureAbsent_RaisesScore)
{
    ValidationResult vr = MakeResult(0.45f, BR_SIGNATURE_ABSENT,
                                      LoadAction::AllowedFlagged);
    RiskContext ctx      = MakeCtx();

    RiskAssessment ra{};
    AnalyzeRisk(vr, ctx, &ra);

    EXPECT_NE(ra.triggered_rules & RULE_R002, 0u)
        << "R002 should trigger when BR_SIGNATURE_ABSENT is set";
}

// ===========================================================================
// R003 — Blocked directory (temp path)
// ===========================================================================

TEST_F(RiskAnalyzerTest, R003_TempDir_RaisesScore)
{
    ValidationResult vr = MakeResult(0.50f, BR_PATH_NOT_WHITELISTED,
                                      LoadAction::AllowedFlagged);
    wcscpy_s(vr.dll_path, _countof(vr.dll_path),
             L"C:\\Users\\User\\AppData\\Local\\Temp\\injected.dll");
    RiskContext ctx = MakeCtx();

    RiskAssessment ra{};
    AnalyzeRisk(vr, ctx, &ra);

    EXPECT_NE(ra.triggered_rules & RULE_R003, 0u)
        << "R003 should trigger for temp/blocked directory loads";
}

// ===========================================================================
// R004 — Levenshtein typosquatting
// ===========================================================================

TEST_F(RiskAnalyzerTest, R004_Levenshtein_RaisesScore)
{
    ValidationResult vr = MakeResult(0.55f, BR_NAME_LEVENSHTEIN,
                                      LoadAction::AllowedFlagged);
    RiskContext ctx      = MakeCtx();

    RiskAssessment ra{};
    AnalyzeRisk(vr, ctx, &ra);

    EXPECT_NE(ra.triggered_rules & RULE_R004, 0u)
        << "R004 should trigger when BR_NAME_LEVENSHTEIN is set";
}

// ===========================================================================
// R005 — Homoglyph
// ===========================================================================

TEST_F(RiskAnalyzerTest, R005_Homoglyph_RaisesScore)
{
    ValidationResult vr = MakeResult(0.60f, BR_NAME_HOMOGLYPH,
                                      LoadAction::AllowedFlagged);
    RiskContext ctx      = MakeCtx();

    RiskAssessment ra{};
    AnalyzeRisk(vr, ctx, &ra);

    EXPECT_NE(ra.triggered_rules & RULE_R005, 0u)
        << "R005 should trigger when BR_NAME_HOMOGLYPH is set";
}

// ===========================================================================
// R006 — Unvetted DLL in privileged process
// ===========================================================================

TEST_F(RiskAnalyzerTest, R006_PrivilegedProcess_UnvettedDll_RaisesScore)
{
    // Score just below THRESHOLD_BLOCK_STRICT (not auto-blocked by validator)
    ValidationResult vr = MakeResult(0.50f, BR_SIGNATURE_ABSENT,
                                      LoadAction::AllowedFlagged);
    // is_privileged = TRUE
    RiskContext ctx = MakeCtx(/*privileged=*/TRUE);

    RiskAssessment ra{};
    AnalyzeRisk(vr, ctx, &ra);

    EXPECT_NE(ra.triggered_rules & RULE_R006, 0u)
        << "R006 should trigger for unvetted DLL in privileged process";
    // Penalty should push score higher
    EXPECT_GT(ra.contextual_score, vr.trust_score);
}

// ===========================================================================
// R007 — Burst detection
// ===========================================================================

TEST_F(RiskAnalyzerTest, R007_Burst_TriggersAfterThreshold)
{
    // Simulate BURST_DLL_THRESHOLD + 1 suspicious loads in rapid succession
    // GetBurstCount reports the count — we call AnalyzeRisk multiple times
    // with a context that has is_post_startup=TRUE (burst only counts post-startup)
    ValidationResult vr = MakeResult(0.50f, BR_SIGNATURE_ABSENT,
                                      LoadAction::AllowedFlagged);
    RiskContext ctx = MakeCtx(FALSE, /*post_startup=*/TRUE);

    RiskAssessment last_ra{};
    bool burst_triggered = false;

    for (int i = 0; i <= static_cast<int>(BURST_DLL_THRESHOLD) + 1; ++i) {
        RiskAssessment ra{};
        AnalyzeRisk(vr, ctx, &ra);
        last_ra = ra;
        if (ra.burst_triggered) {
            burst_triggered = true;
            break;
        }
    }

    EXPECT_TRUE(burst_triggered)
        << "R007 burst should trigger after " << BURST_DLL_THRESHOLD
        << " suspicious loads within the burst window";
    EXPECT_NE(last_ra.triggered_rules & RULE_R007, 0u);
}

// ===========================================================================
// Score clamping
// ===========================================================================

TEST_F(RiskAnalyzerTest, ScoreClamping_NeverExceedsOne)
{
    // Stack every block reason imaginable
    uint32_t all_reasons = BR_OUTSIDE_SYSTEM32 | BR_SIGNATURE_ABSENT |
                           BR_SIGNATURE_REVOKED | BR_NAME_LEVENSHTEIN |
                           BR_NAME_HOMOGLYPH | BR_PATH_NOT_WHITELISTED |
                           BR_HASH_MISMATCH;
    ValidationResult vr = MakeResult(0.99f, all_reasons, LoadAction::BlockedAlways);
    RiskContext ctx = MakeCtx(/*privileged=*/TRUE, /*post_startup=*/TRUE);

    RiskAssessment ra{};
    AnalyzeRisk(vr, ctx, &ra);

    EXPECT_LE(ra.contextual_score, 1.0f) << "Contextual score must not exceed 1.0";
    EXPECT_GE(ra.contextual_score, 0.0f) << "Contextual score must not be negative";
}

TEST_F(RiskAnalyzerTest, ScoreClamping_NeverBelowZero)
{
    // Perfect DLL: Tier1 path, signed, known hash, no issues
    ValidationResult vr = MakeResult(0.0f, BR_NONE, LoadAction::Allowed,
                                      WhitelistTier::Tier1);
    RiskContext ctx = MakeCtx(FALSE, FALSE, /*seen_before=*/TRUE);

    RiskAssessment ra{};
    AnalyzeRisk(vr, ctx, &ra);

    EXPECT_GE(ra.contextual_score, 0.0f);
    EXPECT_EQ(ra.recommended_action, LoadAction::Allowed);
}

// ===========================================================================
// BuildRiskContext
// ===========================================================================

TEST_F(RiskAnalyzerTest, BuildRiskContext_PopulatesPidAndProcessName)
{
    RiskContext ctx{};
    BuildRiskContext(&ctx);

    EXPECT_EQ(ctx.pid, GetCurrentProcessId());
    EXPECT_NE(ctx.process_name[0], L'\0')
        << "process_name should be populated by BuildRiskContext";
}

// ===========================================================================
// RecordApprovedLoad + anomaly detection
// ===========================================================================

TEST_F(RiskAnalyzerTest, Baseline_NewDllAfterApproval_IsNotAnomaly)
{
    // Approve a DLL first
    ValidationResult vr = MakeResult(0.10f, BR_NONE, LoadAction::Allowed,
                                      WhitelistTier::Tier1);
    wcscpy_s(vr.dll_path, _countof(vr.dll_path),
             L"C:\\Windows\\System32\\kernel32.dll");
    RiskContext ctx = MakeCtx(FALSE, TRUE, FALSE);
    ctx.load_sequence_number = 1;

    RecordApprovedLoad(L"test_host.exe", vr.dll_path, vr.trust_score);

    // Same DLL, now was_seen_before = TRUE
    ctx.was_seen_before = TRUE;
    RiskAssessment ra{};
    AnalyzeRisk(vr, ctx, &ra);

    EXPECT_FALSE(ra.is_anomalous)
        << "A previously recorded DLL should not be anomalous";
}
