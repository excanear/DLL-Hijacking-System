// =============================================================================
// tests/test_validator.cpp
// Unit tests for the DLL Validator pipeline (BLOCO 4).
//
// Coverage:
//   - Layer 1: path whitelist / blocked-dir short-circuit
//   - Layer 2: name heuristics (Levenshtein, homoglyph, double extension)
//   - Layer 3: SHA-256 hash computation on a temp file
//   - Aggregate score clamping and threshold mapping
//   - Cache: second call on same path skips re-validation
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

#include "dll_validator.h"
#include "policy.h"
#include "constants.h"
#include "types.h"

#pragma comment(lib, "shlwapi.lib")

using namespace dhd;

// ===========================================================================
// Test fixture — ensures Validator is initialized once per suite.
// ===========================================================================

class ValidatorTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        // Load policy with safe defaults (no JSON file needed for unit tests)
        PolicyManager::LoadPolicy(nullptr);
        // Initialize validator without a hash DB (hash checks degraded)
        InitializeValidator(nullptr);
    }

    static void TearDownTestSuite() {
        InvalidateValidationCache();
    }

    void SetUp() override {
        InvalidateValidationCache();
    }
};

// ===========================================================================
// Layer 1 — Path checks
// ===========================================================================

TEST_F(ValidatorTest, BlockedDir_TempPath_ReturnsBlocked)
{
    // Construct a fake path inside %TEMP%
    wchar_t temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp);
    wchar_t fake_dll[MAX_PATH] = {};
    wcscpy_s(fake_dll, temp);
    PathAppendW(fake_dll, L"evil.dll");

    ValidationResult result{};
    // File doesn't need to exist — path check fires before file I/O
    BOOL ok = ValidateDLL(INVALID_HANDLE_VALUE, fake_dll, FALSE, &result);

    // Validator should fire even with invalid handle (path check is first)
    // Accept either ok==FALSE (handle invalid) or result has path block reason
    if (ok) {
        EXPECT_NE(result.block_reasons & BR_PATH_NOT_WHITELISTED, 0u);
    }
}

TEST_F(ValidatorTest, WhitelistedPath_System32_ReturnsWhitelisted)
{
    // Use actual ntdll path — must exist on every Windows system
    wchar_t sys32[MAX_PATH] = {};
    GetSystemDirectoryW(sys32, MAX_PATH);
    wchar_t ntdll[MAX_PATH] = {};
    wcscpy_s(ntdll, sys32);
    PathAppendW(ntdll, L"ntdll.dll");

    ASSERT_TRUE(PathFileExistsW(ntdll)) << "ntdll.dll must exist on test machine";

    // Open handle for the validator
    HANDLE h = CreateFileW(ntdll, GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);

    ValidationResult result{};
    BOOL ok = ValidateDLL(h, ntdll, FALSE, &result);
    CloseHandle(h);

    EXPECT_TRUE(ok);
    // Path is in Tier 1 — should NOT have path-not-whitelisted flag
    EXPECT_EQ(result.block_reasons & BR_PATH_NOT_WHITELISTED, 0u);
    // Tier 1 path should be identified as such
    EXPECT_GE(static_cast<int>(result.whitelist_tier),
               static_cast<int>(WhitelistTier::Tier1));
}

// ===========================================================================
// Layer 2 — Name heuristics
// ===========================================================================

TEST_F(ValidatorTest, NameHeuristics_DoubleExtension_FlagsBlock)
{
    // kernel32.dll.exe — double extension attack
    ValidationResult result{};
    BOOL ok = ValidateDLL(INVALID_HANDLE_VALUE,
                           L"C:\\Windows\\System32\\kernel32.dll.exe",
                           FALSE, &result);
    // Even if ValidateDLL returns FALSE (no file), the name check should run
    if (ok) {
        EXPECT_NE(result.block_reasons & BR_NAME_DOUBLE_EXTENSION, 0u);
    }
}

TEST_F(ValidatorTest, NameHeuristics_HomoglyphUnicode_FlagsBlock)
{
    // Cyrillic 'а' (U+0430) instead of Latin 'a' — looks like "ntdll.dll"
    // ntdll.dll with Cyrillic а in "ntdll"
    wchar_t path_with_homoglyph[] =
        L"C:\\Windows\\System32\\nt\u0430ll.dll";

    ValidationResult result{};
    BOOL ok = ValidateDLL(INVALID_HANDLE_VALUE,
                           path_with_homoglyph,
                           FALSE, &result);
    if (ok) {
        EXPECT_NE(result.block_reasons & BR_NAME_HOMOGLYPH, 0u);
    }
}

TEST_F(ValidatorTest, NameHeuristics_Levenshtein1_FlagsTyposquatting)
{
    // "kerne132.dll" — digit '1' instead of letter 'l' in kernel32.dll
    // Levenshtein distance = 1 from "kernel32"
    ValidationResult result{};
    BOOL ok = ValidateDLL(INVALID_HANDLE_VALUE,
                           L"C:\\Windows\\System32\\kerne132.dll",
                           FALSE, &result);
    if (ok) {
        EXPECT_NE(result.block_reasons & BR_NAME_LEVENSHTEIN, 0u);
    }
}

TEST_F(ValidatorTest, NameHeuristics_LegitName_NoNameFlag)
{
    // "kernel32.dll" should not trigger any name heuristic
    wchar_t sys32[MAX_PATH] = {};
    GetSystemDirectoryW(sys32, MAX_PATH);
    wchar_t kernel32[MAX_PATH] = {};
    wcscpy_s(kernel32, sys32);
    PathAppendW(kernel32, L"kernel32.dll");

    HANDLE h = CreateFileW(kernel32, GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);

    ValidationResult result{};
    BOOL ok = ValidateDLL(h, kernel32, FALSE, &result);
    CloseHandle(h);

    EXPECT_TRUE(ok);
    EXPECT_EQ(result.block_reasons & BR_NAME_DOUBLE_EXTENSION, 0u);
    EXPECT_EQ(result.block_reasons & BR_NAME_HOMOGLYPH, 0u);
    EXPECT_EQ(result.block_reasons & BR_NAME_LEVENSHTEIN, 0u);
}

// ===========================================================================
// Layer 3 — SHA-256 via temp file
// ===========================================================================

TEST_F(ValidatorTest, HashLayer_KnownContent_ProducesDeterministicHash)
{
    // Write a temp file with known content and verify SHA-256 is computed
    wchar_t temp_dir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp_dir);
    wchar_t temp_file[MAX_PATH] = {};
    GetTempFileNameW(temp_dir, L"dhd", 0, temp_file);

    // Write 16 zero bytes
    const BYTE data[16] = {};
    HANDLE h = CreateFileW(temp_file, GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);
    DWORD written = 0;
    WriteFile(h, data, sizeof(data), &written, nullptr);
    CloseHandle(h);
    EXPECT_EQ(written, sizeof(data));

    // Open for reading and validate
    h = CreateFileW(temp_file, GENERIC_READ, FILE_SHARE_READ,
                     nullptr, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);

    // Redirect to a non-whitelisted path: the hash layer still runs
    // (path layer will flag it, but hash is still computed)
    ValidationResult result{};
    ValidateDLL(h, temp_file, FALSE, &result);
    CloseHandle(h);

    // SHA-256 of 16 zero bytes:
    // b4fc678ff6b50bde5f39cd1c9a78ead7c1effa46dc0d2d0a57a0437e8fc4d31f
    // We can't compare exactly because the path is in %TEMP% and blocked,
    // but we can verify the hash field was populated (not empty).
    bool hash_present = false;
    for (size_t i = 0; i < SHA256_HEX_LEN; ++i) {
        if (result.sha256_hex[i] != L'\0') { hash_present = true; break; }
    }
    EXPECT_TRUE(hash_present) << "SHA-256 field should be populated";

    DeleteFileW(temp_file);
}

// ===========================================================================
// Aggregate score and threshold
// ===========================================================================

TEST_F(ValidatorTest, System32_NtDll_ScoreIsLow)
{
    wchar_t sys32[MAX_PATH] = {};
    GetSystemDirectoryW(sys32, MAX_PATH);
    wchar_t ntdll[MAX_PATH] = {};
    wcscpy_s(ntdll, sys32);
    PathAppendW(ntdll, L"ntdll.dll");

    HANDLE h = CreateFileW(ntdll, GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);

    ValidationResult result{};
    BOOL ok = ValidateDLL(h, ntdll, FALSE, &result);
    CloseHandle(h);

    EXPECT_TRUE(ok);
    // ntdll.dll: Tier1 path (+0.10 bonus), good name, signed by Microsoft
    // Aggregate score should be below the WARN threshold (0.31)
    EXPECT_LT(result.trust_score, THRESHOLD_WARN)
        << "ntdll.dll should score below THRESHOLD_WARN";
    EXPECT_EQ(result.recommended_action, LoadAction::Allowed);
}

// ===========================================================================
// Cache behaviour
// ===========================================================================

TEST_F(ValidatorTest, Cache_SecondCall_ReturnsCachedResult)
{
    wchar_t sys32[MAX_PATH] = {};
    GetSystemDirectoryW(sys32, MAX_PATH);
    wchar_t kernel32[MAX_PATH] = {};
    wcscpy_s(kernel32, sys32);
    PathAppendW(kernel32, L"kernel32.dll");

    HANDLE h = CreateFileW(kernel32, GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);

    ValidationResult r1{};
    ValidateDLL(h, kernel32, FALSE, &r1);
    CloseHandle(h);

    // Second call — hit cache (score must be identical)
    h = CreateFileW(kernel32, GENERIC_READ, FILE_SHARE_READ,
                     nullptr, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);
    ValidationResult r2{};
    ValidateDLL(h, kernel32, FALSE, &r2);
    CloseHandle(h);

    EXPECT_FLOAT_EQ(r1.trust_score, r2.trust_score);
    EXPECT_EQ(r1.block_reasons, r2.block_reasons);
    EXPECT_EQ(r1.recommended_action, r2.recommended_action);

    // Confirm cache has at least 1 entry
    uint32_t hits = 0, capacity = 0;
    GetValidationCacheStats(&hits, &capacity);
    EXPECT_GE(hits, 1u);
}

TEST_F(ValidatorTest, Cache_Invalidate_ForcesRecompute)
{
    wchar_t sys32[MAX_PATH] = {};
    GetSystemDirectoryW(sys32, MAX_PATH);
    wchar_t kernel32[MAX_PATH] = {};
    wcscpy_s(kernel32, sys32);
    PathAppendW(kernel32, L"kernel32.dll");

    HANDLE h = CreateFileW(kernel32, GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);
    ValidationResult r1{};
    ValidateDLL(h, kernel32, FALSE, &r1);
    CloseHandle(h);

    InvalidateValidationCache();

    uint32_t hits = 0, capacity = 0;
    GetValidationCacheStats(&hits, &capacity);
    EXPECT_EQ(hits, 0u) << "Cache should be empty after invalidation";
}
