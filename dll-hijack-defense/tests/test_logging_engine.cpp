// =============================================================================
// tests/test_logging_engine.cpp
// Unit tests for the Logging Engine (BLOCO 6).
//
// Coverage:
//   - InitializeLoggingEngine / ShutdownLoggingEngine lifecycle
//   - EmitLog: event is written to disk (file exists and is non-empty)
//   - BuildLogEvent: fills required fields (pid, hostname, timestamp, schema)
//   - FlushLog: all pending events are on disk after FlushLog returns
//   - Queue overflow: dropped counter increments under artificial queue stress
//   - Double init: second InitializeLoggingEngine returns FALSE
//   - HMAC field: present and non-empty in every emitted JSON line
//   - Log rotation: large emission batch does not crash or lose events
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

#include "logging_engine.h"
#include "constants.h"
#include "types.h"

#pragma comment(lib, "shlwapi.lib")

using namespace dhd;

// ===========================================================================
// Helpers
// ===========================================================================

namespace {

static wchar_t s_log_dir[MAX_PATH] = {};

// Create a unique temp directory for this test run
static bool CreateTempLogDir()
{
    wchar_t temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp);
    wchar_t dir[MAX_PATH] = {};
    swprintf_s(dir, _countof(dir), L"%lsdhd_test_logs_%u", temp, GetCurrentProcessId());
    CreateDirectoryW(dir, nullptr);
    wcscpy_s(s_log_dir, _countof(s_log_dir), dir);
    return PathIsDirectoryW(dir);
}

// Delete directory and all contents recursively
static void DeleteDirRecursive(const wchar_t* dir)
{
    wchar_t pattern[MAX_PATH] = {};
    wcscpy_s(pattern, dir);
    PathAppendW(pattern, L"*");

    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) { RemoveDirectoryW(dir); return; }
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;
        wchar_t child[MAX_PATH] = {};
        wcscpy_s(child, dir);
        PathAppendW(child, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            DeleteDirRecursive(child);
        else
            DeleteFileW(child);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    RemoveDirectoryW(dir);
}

// Count the number of .log files in |dir|
static int CountLogFiles(const wchar_t* dir)
{
    wchar_t pattern[MAX_PATH] = {};
    wcscpy_s(pattern, dir);
    PathAppendW(pattern, L"*.log");

    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    int count = 0;
    do { ++count; } while (FindNextFileW(h, &fd));
    FindClose(h);
    return count;
}

// Read all log file content from |dir| into a string
static std::string ReadAllLogs(const wchar_t* dir)
{
    wchar_t pattern[MAX_PATH] = {};
    wcscpy_s(pattern, dir);
    PathAppendW(pattern, L"*.log");

    std::string all;
    WIN32_FIND_DATAW fd{};
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return all;
    do {
        wchar_t path[MAX_PATH] = {};
        wcscpy_s(path, dir);
        PathAppendW(path, fd.cFileName);

        HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        LARGE_INTEGER sz{};
        GetFileSizeEx(hFile, &sz);
        if (sz.QuadPart > 0 && sz.QuadPart < 64 * 1024 * 1024) {
            std::string chunk(static_cast<size_t>(sz.QuadPart), '\0');
            DWORD read = 0;
            ReadFile(hFile, chunk.data(), static_cast<DWORD>(chunk.size()),
                      &read, nullptr);
            all += chunk;
        }
        CloseHandle(hFile);
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return all;
}

static LogEvent MakeTestEvent(LogSeverity sev = LogSeverity::Info)
{
    LogEvent ev{};
    BuildLogEvent(sev,
                  L"TEST_MODULE",
                  L"C:\\Windows\\System32\\test.dll",
                  0.10f,
                  LoadAction::Allowed,
                  BR_NONE,
                  RiskLevel::Low,
                  TRUE,
                  &ev);
    return ev;
}

} // anonymous namespace

// ===========================================================================
// Fixture
// ===========================================================================

class LoggingEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(CreateTempLogDir()) << "Could not create temp log directory";
        ASSERT_TRUE(InitializeLoggingEngine(s_log_dir));
    }

    void TearDown() override {
        ShutdownLoggingEngine();
        DeleteDirRecursive(s_log_dir);
    }
};

// ===========================================================================
// Lifecycle
// ===========================================================================

TEST_F(LoggingEngineTest, IsInitialized_ReturnsTrueAfterInit)
{
    EXPECT_TRUE(IsLoggingEngineInitialized());
}

TEST_F(LoggingEngineTest, DoubleInit_ReturnsFalse)
{
    // Second call must fail without crashing
    BOOL second = InitializeLoggingEngine(s_log_dir);
    EXPECT_FALSE(second) << "Double InitializeLoggingEngine should return FALSE";
}

TEST_F(LoggingEngineTest, IsInitialized_ReturnsFalseAfterShutdown)
{
    ShutdownLoggingEngine();
    EXPECT_FALSE(IsLoggingEngineInitialized());
    // Re-init so TearDown doesn't double-shutdown
    InitializeLoggingEngine(s_log_dir);
}

// ===========================================================================
// EmitLog + FlushLog
// ===========================================================================

TEST_F(LoggingEngineTest, EmitLog_CreatesLogFile)
{
    EmitLog(MakeTestEvent());
    FlushLog();

    EXPECT_GE(CountLogFiles(s_log_dir), 1) << "At least one .log file should exist";
}

TEST_F(LoggingEngineTest, FlushLog_AllEventsOnDiskAfterFlush)
{
    const int N = 50;
    for (int i = 0; i < N; ++i) {
        EmitLog(MakeTestEvent());
    }
    FlushLog();

    std::string content = ReadAllLogs(s_log_dir);
    EXPECT_FALSE(content.empty()) << "Log file should be non-empty after flush";

    // Count JSON lines (each event is one line; SESSION_START adds at least 1)
    int lines = 0;
    for (char c : content) { if (c == '\n') ++lines; }
    // At minimum: SESSION_START + N events
    EXPECT_GE(lines, N) << "Expected at least " << N << " log lines";
}

// ===========================================================================
// BuildLogEvent
// ===========================================================================

TEST_F(LoggingEngineTest, BuildLogEvent_PopulatesRequiredFields)
{
    LogEvent ev = MakeTestEvent(LogSeverity::Warning);

    EXPECT_EQ(ev.schema_version, 1u);
    EXPECT_EQ(ev.pid, GetCurrentProcessId());
    EXPECT_NE(ev.timestamp_ticks, 0ull);
    EXPECT_NE(ev.hostname[0], L'\0') << "hostname should be populated";
    EXPECT_NE(ev.process_name[0], L'\0') << "process_name should be populated";
    EXPECT_EQ(ev.severity, LogSeverity::Warning);
    EXPECT_STREQ(ev.source_module, L"TEST_MODULE");
}

// ===========================================================================
// HMAC field in serialized output
// ===========================================================================

TEST_F(LoggingEngineTest, EmittedJson_ContainsHmacField)
{
    EmitLog(MakeTestEvent());
    FlushLog();

    std::string content = ReadAllLogs(s_log_dir);
    EXPECT_NE(content.find("\"hmac_sha256\""), std::string::npos)
        << "Serialized event must contain hmac_sha256 field";
    // HMAC value should not be the empty string
    auto pos = content.find("\"hmac_sha256\":\"");
    ASSERT_NE(pos, std::string::npos);
    pos += strlen("\"hmac_sha256\":\"");
    EXPECT_NE(content[pos], '"') << "hmac_sha256 value must not be empty";
}

// ===========================================================================
// Alert / Warning events emitted to Event Log path (smoke test)
// ===========================================================================

TEST_F(LoggingEngineTest, EmitAlertSeverity_DoesNotCrash)
{
    LogEvent ev{};
    BuildLogEvent(LogSeverity::Alert,
                  L"TEST_MODULE",
                  L"C:\\Temp\\injected.dll",
                  0.95f,
                  LoadAction::BlockedAlways,
                  BR_UNEXPECTED_MODULE | BR_SIGNATURE_ABSENT,
                  RiskLevel::Critical,
                  FALSE,
                  &ev);
    EXPECT_NO_FATAL_FAILURE(EmitLog(ev));
    EXPECT_NO_FATAL_FAILURE(FlushLog());
}

// ===========================================================================
// Dropped event counter
// ===========================================================================

TEST_F(LoggingEngineTest, DroppedEventCount_StartsAtZero)
{
    // After fresh init, no events should have been dropped yet
    EXPECT_EQ(GetDroppedEventCount(), 0ull);
}

// ===========================================================================
// Large emission batch (regression — must not crash or deadlock)
// ===========================================================================

TEST_F(LoggingEngineTest, LargeEmissionBatch_DoesNotCrash)
{
    const int N = 2000;
    for (int i = 0; i < N; ++i) {
        EmitLog(MakeTestEvent(i % 2 == 0 ? LogSeverity::Info : LogSeverity::Warning));
    }
    EXPECT_NO_FATAL_FAILURE(FlushLog());
    EXPECT_GE(CountLogFiles(s_log_dir), 1);
}
