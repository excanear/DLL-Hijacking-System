// =============================================================================
// tests/test_policy.cpp
// Unit tests for PolicyManager and the scoring/threshold constants (BLOCO 2).
//
// Coverage:
//   - LoadPolicy with NULL (safe defaults) succeeds
//   - GetConfig returns the active config
//   - DetermineAction: correct LoadAction for each score band
//       score=0.00 → Allowed
//       score=0.31 → AllowedFlagged (warn band)
//       score=0.61 → Blocked (strict band)
//       score=0.86 → BlockedAlways (always band)
//   - IsPathInWhitelist: System32 → Tier1, SysWOW64 → Tier1
//   - IsPathBlocked: %TEMP% → TRUE, System32 → FALSE
//   - Threshold constants are self-consistent (ALLOW < WARN < STRICT < ALWAYS)
//   - LoadPolicy with nonexistent file returns FALSE but leaves safe defaults
// =============================================================================

#include <gtest/gtest.h>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlwapi.h>

#include "policy.h"
#include "constants.h"
#include "types.h"

#pragma comment(lib, "shlwapi.lib")

using namespace dhd;

// ===========================================================================
// Fixture
// ===========================================================================

class PolicyTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Always start from clean safe defaults
        PolicyManager::LoadPolicy(nullptr);
    }
};

// ===========================================================================
// Threshold self-consistency
// ===========================================================================

TEST_F(PolicyTest, Thresholds_AreStrictlyOrdered)
{
    EXPECT_LT(THRESHOLD_ALLOW,         THRESHOLD_WARN)
        << "ALLOW threshold must be less than WARN";
    EXPECT_LT(THRESHOLD_WARN,          THRESHOLD_BLOCK_STRICT)
        << "WARN threshold must be less than BLOCK_STRICT";
    EXPECT_LT(THRESHOLD_BLOCK_STRICT,  THRESHOLD_BLOCK_ALWAYS)
        << "BLOCK_STRICT threshold must be less than BLOCK_ALWAYS";
    EXPECT_LE(THRESHOLD_BLOCK_ALWAYS,  1.0f)
        << "BLOCK_ALWAYS threshold must not exceed 1.0";
    EXPECT_GE(THRESHOLD_ALLOW,         0.0f)
        << "ALLOW threshold must not be negative";
}

TEST_F(PolicyTest, ScoreWeights_SumToApproximatelyOne)
{
    float sum = WEIGHT_PATH + WEIGHT_NAME + WEIGHT_HASH + WEIGHT_SIGNATURE;
    EXPECT_NEAR(sum, 1.0f, 0.001f)
        << "Score weights must sum to 1.0";
}

// ===========================================================================
// DetermineAction — score band mapping
// ===========================================================================

TEST_F(PolicyTest, DetermineAction_Score0_ReturnsAllowed)
{
    EXPECT_EQ(PolicyManager::DetermineAction(0.00f), LoadAction::Allowed);
}

TEST_F(PolicyTest, DetermineAction_ScoreAtAllowBoundary_ReturnsAllowed)
{
    EXPECT_EQ(PolicyManager::DetermineAction(THRESHOLD_ALLOW), LoadAction::Allowed);
}

TEST_F(PolicyTest, DetermineAction_ScoreInWarnBand_ReturnsAllowedFlagged)
{
    // Just above THRESHOLD_ALLOW and at/below THRESHOLD_BLOCK_STRICT
    float warn_score = THRESHOLD_ALLOW + 0.01f;
    EXPECT_EQ(PolicyManager::DetermineAction(warn_score), LoadAction::AllowedFlagged);
}

TEST_F(PolicyTest, DetermineAction_ScoreAtWarnBoundary_ReturnsAllowedFlagged)
{
    EXPECT_EQ(PolicyManager::DetermineAction(THRESHOLD_WARN), LoadAction::AllowedFlagged);
}

TEST_F(PolicyTest, DetermineAction_ScoreInStrictBand_ReturnsBlocked)
{
    float strict_score = THRESHOLD_BLOCK_STRICT + 0.01f;
    LoadAction action  = PolicyManager::DetermineAction(strict_score);
    // May be Blocked or BlockedAlways depending on whether score also >= BLOCK_ALWAYS
    EXPECT_TRUE(action == LoadAction::Blocked || action == LoadAction::BlockedAlways);
}

TEST_F(PolicyTest, DetermineAction_ScoreAtAlwaysBoundary_ReturnsBlockedAlways)
{
    EXPECT_EQ(PolicyManager::DetermineAction(THRESHOLD_BLOCK_ALWAYS),
              LoadAction::BlockedAlways);
}

TEST_F(PolicyTest, DetermineAction_Score1_ReturnsBlockedAlways)
{
    EXPECT_EQ(PolicyManager::DetermineAction(1.0f), LoadAction::BlockedAlways);
}

// ===========================================================================
// LoadPolicy
// ===========================================================================

TEST_F(PolicyTest, LoadPolicy_Null_ReturnsTrueWithDefaults)
{
    BOOL ok = PolicyManager::LoadPolicy(nullptr);
    EXPECT_TRUE(ok) << "LoadPolicy(nullptr) must succeed with safe defaults";
}

TEST_F(PolicyTest, LoadPolicy_NonexistentFile_ReturnsFalse)
{
    BOOL ok = PolicyManager::LoadPolicy(L"C:\\nonexistent\\path\\policy.json");
    EXPECT_FALSE(ok) << "LoadPolicy with nonexistent file should return FALSE";

    // Verify safe defaults are still active after failed load
    LoadAction action = PolicyManager::DetermineAction(0.0f);
    EXPECT_EQ(action, LoadAction::Allowed)
        << "Safe defaults must remain active after failed LoadPolicy";
}

TEST_F(PolicyTest, LoadPolicy_ExistingDefaultsJson_ReturnsTrue)
{
    // Build path to policy/defaults.json relative to the binary's CWD
    // In CTest, CWD = build directory. Adjust if test is run from project root.
    wchar_t cwd[MAX_PATH] = {};
    GetCurrentDirectoryW(MAX_PATH, cwd);

    wchar_t policy_path[MAX_PATH] = {};
    wcscpy_s(policy_path, cwd);
    PathAppendW(policy_path, L"policy\\defaults.json");

    if (!PathFileExistsW(policy_path)) {
        // Try project root path (when running from solution dir)
        wcscpy_s(policy_path, cwd);
        PathAppendW(policy_path, L"..\\policy\\defaults.json");
    }

    if (PathFileExistsW(policy_path)) {
        EXPECT_TRUE(PolicyManager::LoadPolicy(policy_path))
            << "LoadPolicy should succeed with the shipped defaults.json";
    } else {
        GTEST_SKIP() << "policy/defaults.json not found relative to CWD — skipping";
    }
}

// ===========================================================================
// IsPathInWhitelist
// ===========================================================================

TEST_F(PolicyTest, IsPathInWhitelist_System32_ReturnsTier1)
{
    wchar_t sys32[MAX_PATH] = {};
    GetSystemDirectoryW(sys32, MAX_PATH);

    wchar_t dll_path[MAX_PATH] = {};
    wcscpy_s(dll_path, sys32);
    PathAppendW(dll_path, L"kernel32.dll");

    WhitelistTier tier = PolicyManager::IsPathInWhitelist(dll_path);
    EXPECT_EQ(tier, WhitelistTier::Tier1)
        << "System32 DLLs must resolve to Tier1";
}

TEST_F(PolicyTest, IsPathInWhitelist_SysWOW64_ReturnsTier1)
{
    wchar_t windir[MAX_PATH] = {};
    GetWindowsDirectoryW(windir, MAX_PATH);
    wchar_t syswow[MAX_PATH] = {};
    wcscpy_s(syswow, windir);
    PathAppendW(syswow, L"SysWOW64\\kernel32.dll");

    if (!PathFileExistsW(syswow)) {
        GTEST_SKIP() << "SysWOW64 not present on this machine — skipping";
    }

    WhitelistTier tier = PolicyManager::IsPathInWhitelist(syswow);
    EXPECT_EQ(tier, WhitelistTier::Tier1);
}

TEST_F(PolicyTest, IsPathInWhitelist_TempPath_ReturnsNotListed)
{
    wchar_t temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp);
    wchar_t dll[MAX_PATH] = {};
    wcscpy_s(dll, temp);
    PathAppendW(dll, L"evil.dll");

    WhitelistTier tier = PolicyManager::IsPathInWhitelist(dll);
    EXPECT_EQ(tier, WhitelistTier::NotListed);
}

// ===========================================================================
// IsPathBlocked
// ===========================================================================

TEST_F(PolicyTest, IsPathBlocked_TempPath_ReturnsTrue)
{
    wchar_t temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp);
    wchar_t dll[MAX_PATH] = {};
    wcscpy_s(dll, temp);
    PathAppendW(dll, L"evil.dll");

    EXPECT_TRUE(PolicyManager::IsPathBlocked(dll));
}

TEST_F(PolicyTest, IsPathBlocked_System32_ReturnsFalse)
{
    wchar_t sys32[MAX_PATH] = {};
    GetSystemDirectoryW(sys32, MAX_PATH);
    wchar_t dll[MAX_PATH] = {};
    wcscpy_s(dll, sys32);
    PathAppendW(dll, L"ntdll.dll");

    EXPECT_FALSE(PolicyManager::IsPathBlocked(dll));
}

// ===========================================================================
// GetConfig
// ===========================================================================

TEST_F(PolicyTest, GetConfig_ReturnsNonNullAfterLoad)
{
    PolicyConfig cfg = PolicyManager::GetConfig();
    EXPECT_TRUE(cfg.mode == PolicyMode::Audit || cfg.mode == PolicyMode::Enforce)
        << "GetConfig must return valid config after LoadPolicy";
}

TEST_F(PolicyTest, GetConfig_DefaultMode_IsAuditOrEnforce)
{
    PolicyConfig cfg = PolicyManager::GetConfig();
    EXPECT_TRUE(cfg.mode == PolicyMode::Audit ||
                cfg.mode == PolicyMode::Enforce)
        << "Default policy mode should be Audit or Enforce";
}
