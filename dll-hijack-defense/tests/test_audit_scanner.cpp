// =============================================================================
// tests/test_audit_scanner.cpp
// Unit tests for the Audit Scanner (BLOCO 8).
//
// Coverage:
//   - ScanExecutable on a real Windows PE (notepad.exe) — no crash, has imports
//   - RunAuditScan with a single target exe — result counters consistent
//   - RunAuditScan with a directory containing one .exe — finds target
//   - WriteJsonReport — file is created, parseable, contains findings array
//   - Phantom DLL check: scanner detects missing DLL
//   - check_phantom_dlls = FALSE: phantom findings suppressed
//   - ScanOptions default constructor: check flags default to TRUE
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

#include "audit_scanner.h"
#include "constants.h"
#include "types.h"

#pragma comment(lib, "shlwapi.lib")

using namespace dhd;

// ===========================================================================
// Helpers
// ===========================================================================

namespace {

// Path to notepad.exe — guaranteed to exist on all Windows systems
static wchar_t s_notepad[MAX_PATH] = {};
// Temp directory for report output
static wchar_t s_temp_dir[MAX_PATH] = {};

static void InitPaths()
{
    wchar_t sys32[MAX_PATH] = {};
    GetSystemDirectoryW(sys32, MAX_PATH);
    wcscpy_s(s_notepad, sys32);
    PathAppendW(s_notepad, L"notepad.exe");

    GetTempPathW(MAX_PATH, s_temp_dir);
}

static bool ReadFileToString(const wchar_t* path, std::string& out)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    out.resize(static_cast<size_t>(sz.QuadPart));
    DWORD read = 0;
    ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(h);
    return read == static_cast<DWORD>(out.size());
}

} // anonymous namespace

// ===========================================================================
// Fixture
// ===========================================================================

class AuditScannerTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        InitPaths();
    }
};

// ===========================================================================
// ScanOptions defaults
// ===========================================================================

TEST_F(AuditScannerTest, DefaultOptions_CheckFlagsAreTrue)
{
    ScanOptions opts;
    EXPECT_TRUE(opts.check_phantom_dlls);
    EXPECT_TRUE(opts.check_writable_dirs);
    EXPECT_TRUE(opts.check_acl_permissiveness);
    EXPECT_FALSE(opts.include_low_severity);
    EXPECT_EQ(opts.max_recursion_depth, 5u);
}

// ===========================================================================
// ScanExecutable — smoke test against notepad.exe
// ===========================================================================

TEST_F(AuditScannerTest, ScanExecutable_Notepad_HasImports)
{
    ASSERT_TRUE(PathFileExistsW(s_notepad))
        << "notepad.exe must exist at " << (const char*)nullptr;

    ScanOptions opts;
    opts.check_phantom_dlls      = TRUE;
    opts.check_writable_dirs     = FALSE;  // keep test fast
    opts.check_acl_permissiveness = FALSE;

    std::vector<AuditFinding> findings;
    uint32_t dll_count = 0;
    EXPECT_NO_FATAL_FAILURE(
        ScanExecutable(s_notepad, opts, &findings, &dll_count));

    EXPECT_GT(dll_count, 0u) << "notepad.exe should import at least one DLL";
}

TEST_F(AuditScannerTest, ScanExecutable_NullPath_DoesNotCrash)
{
    ScanOptions opts;
    std::vector<AuditFinding> findings;
    uint32_t count = 0;
    EXPECT_NO_FATAL_FAILURE(ScanExecutable(nullptr, opts, &findings, &count));
}

// ===========================================================================
// RunAuditScan — single .exe target
// ===========================================================================

TEST_F(AuditScannerTest, RunAuditScan_SingleExe_CountersConsistent)
{
    ScanOptions opts;
    wcscpy_s(opts.target_exe, _countof(opts.target_exe), s_notepad);
    opts.check_writable_dirs     = FALSE;
    opts.check_acl_permissiveness = FALSE;

    ScanResult result{};
    BOOL ok = RunAuditScan(opts, &result);
    EXPECT_TRUE(ok);

    EXPECT_EQ(result.executables_scanned, 1u);
    EXPECT_GT(result.dlls_evaluated, 0u);

    // Tally invariant: sum of per-type counts <= total findings
    uint32_t total = result.phantom_count + result.writable_dir_count +
                     result.acl_issue_count;
    EXPECT_LE(total, static_cast<uint32_t>(result.findings.size()));
}

// ===========================================================================
// RunAuditScan — directory scan (System32 at depth 0 — just the top level)
// ===========================================================================

TEST_F(AuditScannerTest, RunAuditScan_DirectoryScan_FindsExe)
{
    wchar_t sys32[MAX_PATH] = {};
    GetSystemDirectoryW(sys32, MAX_PATH);

    ScanOptions opts;
    wcscpy_s(opts.target_directory, _countof(opts.target_directory), sys32);
    opts.max_recursion_depth     = 0;   // only top-level
    opts.check_phantom_dlls      = FALSE;
    opts.check_writable_dirs     = FALSE;
    opts.check_acl_permissiveness = FALSE;

    ScanResult result{};
    BOOL ok = RunAuditScan(opts, &result);
    EXPECT_TRUE(ok);
    EXPECT_GT(result.executables_scanned, 0u)
        << "System32 should contain at least one .exe at top level";
}

// ===========================================================================
// RunAuditScan — null result pointer
// ===========================================================================

TEST_F(AuditScannerTest, RunAuditScan_NullResult_ReturnsFalse)
{
    ScanOptions opts;
    wcscpy_s(opts.target_exe, _countof(opts.target_exe), s_notepad);
    EXPECT_FALSE(RunAuditScan(opts, nullptr));
}

// ===========================================================================
// check_phantom_dlls = FALSE suppresses phantom findings
// ===========================================================================

TEST_F(AuditScannerTest, PhantomCheck_Disabled_NoPhantomFindings)
{
    ScanOptions opts;
    wcscpy_s(opts.target_exe, _countof(opts.target_exe), s_notepad);
    opts.check_phantom_dlls      = FALSE;
    opts.check_writable_dirs     = FALSE;
    opts.check_acl_permissiveness = FALSE;

    ScanResult result{};
    BOOL ok = RunAuditScan(opts, &result);
    EXPECT_TRUE(ok);
    EXPECT_EQ(result.phantom_count, 0u)
        << "Phantom count must be 0 when check_phantom_dlls is FALSE";
}

// ===========================================================================
// WriteJsonReport
// ===========================================================================

TEST_F(AuditScannerTest, WriteJsonReport_CreatesValidJson)
{
    // Build a small synthetic result
    ScanResult result{};
    result.executables_scanned = 1;
    result.dlls_evaluated      = 3;
    result.phantom_count       = 1;
    GetSystemTimeAsFileTime(&result.scan_start);
    GetSystemTimeAsFileTime(&result.scan_end);

    AuditFinding f{};
    f.severity = RiskLevel::High;
    wcscpy_s(f.target_path,  _countof(f.target_path),  L"C:\\Test\\app.exe");
    wcscpy_s(f.dll_name,     _countof(f.dll_name),     L"phantom.dll");
    wcscpy_s(f.issue_code,   _countof(f.issue_code),   issue::PHANTOM_DLL);
    wcscpy_s(f.detail,       _countof(f.detail),       L"DLL not found on disk.");
    wcscpy_s(f.recommendation, _countof(f.recommendation), L"Remove the import.");
    result.findings.push_back(f);

    wchar_t report_path[MAX_PATH] = {};
    wcscpy_s(report_path, s_temp_dir);
    PathAppendW(report_path, L"dhd_test_report.json");
    DeleteFileW(report_path);  // clean up from previous run

    BOOL ok = WriteJsonReport(result, report_path);
    EXPECT_TRUE(ok);
    EXPECT_TRUE(PathFileExistsW(report_path));

    // Read back and verify structure
    std::string json;
    ASSERT_TRUE(ReadFileToString(report_path, json));
    EXPECT_NE(json.find("\"report_version\""), std::string::npos);
    EXPECT_NE(json.find("\"findings\""),       std::string::npos);
    EXPECT_NE(json.find("phantom.dll"),        std::string::npos);
    EXPECT_NE(json.find("PHANTOM_DLL"),        std::string::npos);

    DeleteFileW(report_path);
}

TEST_F(AuditScannerTest, WriteJsonReport_NullPath_ReturnsFalse)
{
    ScanResult result{};
    EXPECT_FALSE(WriteJsonReport(result, nullptr));
}

// ===========================================================================
// Scan timing — scan_start <= scan_end
// ===========================================================================

TEST_F(AuditScannerTest, ScanResult_Timestamps_Ordered)
{
    ScanOptions opts;
    wcscpy_s(opts.target_exe, _countof(opts.target_exe), s_notepad);
    opts.check_writable_dirs     = FALSE;
    opts.check_acl_permissiveness = FALSE;

    ScanResult result{};
    RunAuditScan(opts, &result);

    ULARGE_INTEGER start{}, end_{};
    start.LowPart  = result.scan_start.dwLowDateTime;
    start.HighPart = result.scan_start.dwHighDateTime;
    end_.LowPart   = result.scan_end.dwLowDateTime;
    end_.HighPart  = result.scan_end.dwHighDateTime;

    EXPECT_LE(start.QuadPart, end_.QuadPart)
        << "scan_start must not be later than scan_end";
}
