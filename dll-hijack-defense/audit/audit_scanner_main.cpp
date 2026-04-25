// =============================================================================
// audit/audit_scanner_main.cpp
// Standalone CLI entry point for the Audit Scanner.
//
// Usage:
//   audit_scanner_cli.exe --exe <path>      [options]
//   audit_scanner_cli.exe --dir <path>      [options]
//
// Options:
//   --report <path>        Write JSON report to <path>
//   --depth  <n>           Max recursion depth for --dir (default: 5)
//   --no-phantom           Skip phantom DLL check
//   --no-writable          Skip writable directory check
//   --no-acl               Skip ACL permissiveness check
//   --include-low          Include Low-severity findings in output
//
// Exit codes:
//   0  — no findings (or only low-severity if --include-low is not set)
//   1  — one or more findings of Medium severity or higher
//   2  — usage error or fatal scan failure
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cwchar>

#include "audit_scanner.h"
#include "policy.h"
#include "constants.h"
#include "types.h"

using namespace dhd;

static void PrintUsage()
{
    wprintf(
        L"Usage:\n"
        L"  audit_scanner_cli.exe --exe <path>   [options]\n"
        L"  audit_scanner_cli.exe --dir <path>   [options]\n"
        L"\n"
        L"Options:\n"
        L"  --report <path>    Write JSON report to <path>\n"
        L"  --depth  <n>       Max recursion depth for --dir (default: 5)\n"
        L"  --no-phantom       Skip phantom DLL check\n"
        L"  --no-writable      Skip writable directory check\n"
        L"  --no-acl           Skip ACL permissiveness check\n"
        L"  --include-low      Include Low-severity findings\n"
        L"\n"
        L"Exit codes: 0=clean, 1=findings, 2=error\n");
}

static const wchar_t* SeverityW(RiskLevel r)
{
    switch (r) {
        case RiskLevel::Low:      return L"LOW";
        case RiskLevel::Medium:   return L"MEDIUM";
        case RiskLevel::High:     return L"HIGH";
        case RiskLevel::Critical: return L"CRITICAL";
        default:                  return L"UNKNOWN";
    }
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 3) { PrintUsage(); return 2; }

    ScanOptions options;

    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--exe") == 0 && i + 1 < argc) {
            wcscpy_s(options.target_exe, _countof(options.target_exe),
                     argv[++i]);
        } else if (_wcsicmp(argv[i], L"--dir") == 0 && i + 1 < argc) {
            wcscpy_s(options.target_directory,
                     _countof(options.target_directory), argv[++i]);
        } else if (_wcsicmp(argv[i], L"--report") == 0 && i + 1 < argc) {
            wcscpy_s(options.report_output_path,
                     _countof(options.report_output_path), argv[++i]);
        } else if (_wcsicmp(argv[i], L"--depth") == 0 && i + 1 < argc) {
            options.max_recursion_depth = static_cast<uint32_t>(
                _wtoi(argv[++i]));
        } else if (_wcsicmp(argv[i], L"--no-phantom") == 0) {
            options.check_phantom_dlls = FALSE;
        } else if (_wcsicmp(argv[i], L"--no-writable") == 0) {
            options.check_writable_dirs = FALSE;
        } else if (_wcsicmp(argv[i], L"--no-acl") == 0) {
            options.check_acl_permissiveness = FALSE;
        } else if (_wcsicmp(argv[i], L"--include-low") == 0) {
            options.include_low_severity = TRUE;
        } else {
            wprintf(L"[ERROR] Unknown option: %ls\n", argv[i]);
            PrintUsage();
            return 2;
        }
    }

    if (options.target_exe[0] == L'\0' &&
        options.target_directory[0] == L'\0')
    {
        wprintf(L"[ERROR] Must specify --exe or --dir.\n");
        PrintUsage();
        return 2;
    }

    wprintf(L"[*] DLL Hijacking Defense — Audit Scanner\n");
    if (options.target_exe[0])
        wprintf(L"[*] Target: %ls\n", options.target_exe);
    else
        wprintf(L"[*] Directory: %ls (depth %u)\n",
                options.target_directory, options.max_recursion_depth);

    ScanResult result;
    if (!RunAuditScan(options, &result)) {
        wprintf(L"[ERROR] Scan failed (invalid target or I/O error).\n");
        return 2;
    }

    // --- Print findings to console ---
    BOOL has_significant = FALSE;

    for (const AuditFinding& f : result.findings) {
        if (!options.include_low_severity && f.severity == RiskLevel::Low)
            continue;

        if (f.severity >= RiskLevel::Medium) has_significant = TRUE;

        wprintf(L"\n[%ls] %ls\n  DLL     : %ls\n  Detail  : %ls\n  Fix     : %ls\n",
                SeverityW(f.severity),
                f.target_path,
                f.dll_name,
                f.detail,
                f.recommendation);
    }

    // --- Summary ---
    wprintf(L"\n--- Summary ---\n"
            L"  Executables scanned : %u\n"
            L"  DLLs evaluated      : %u\n"
            L"  Phantom DLLs        : %u\n"
            L"  Writable dir risks  : %u\n"
            L"  ACL issues          : %u\n"
            L"  Total findings      : %u\n",
            result.executables_scanned,
            result.dlls_evaluated,
            result.phantom_count,
            result.writable_dir_count,
            result.acl_issue_count,
            static_cast<uint32_t>(result.findings.size()));

    if (options.report_output_path[0]) {
        wprintf(L"\n[*] JSON report written to: %ls\n", options.report_output_path);
    }

    return has_significant ? 1 : 0;
}
