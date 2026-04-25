#pragma once

// =============================================================================
// audit/audit_scanner.h
// Public interface of the Audit Scanner.
//
// The Audit Scanner is an OFFLINE, non-real-time analysis tool. It does NOT
// intercept live DLL loads. Instead, it:
//
//   1. Parses PE import tables (IMAGE_IMPORT_DESCRIPTOR) of target executables
//      to enumerate all DLL dependencies.
//   2. Simulates the Windows DLL search order for each imported DLL to
//      identify potentially hijackable resolution paths.
//   3. Checks directory ACLs along each search path for write-permissive
//      entries (world-writable or user-writable by non-admin principals).
//   4. Flags phantom DLL imports (DLLs that do not exist anywhere on disk).
//   5. Produces a structured list of AuditFinding records and optionally
//      serializes them as a JSON report.
//
// Threading: NOT thread-safe. The scanner is designed for single-threaded
// use (CLI tool or scheduled task). Run one scan at a time per process.
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <vector>
#include <string>

#include "types.h"
#include "constants.h"

namespace dhd {

// ---------------------------------------------------------------------------
// ScanOptions
// Controls which checks the scanner performs and how it reports results.
// ---------------------------------------------------------------------------
struct ScanOptions {
    // --- Scope ---
    // Scan a single executable
    wchar_t  target_exe[MAX_PATH];

    // If non-empty, scan all .exe files found recursively in this directory
    wchar_t  target_directory[MAX_PATH];

    // Max recursion depth for directory scanning (0 = top-level only)
    uint32_t max_recursion_depth;

    // --- Check flags ---
    BOOL check_phantom_dlls;         // flag DLLs that don't exist on disk
    BOOL check_writable_dirs;        // flag hijackable search-order dirs
    BOOL check_acl_permissiveness;   // flag world/user-writable directories
    BOOL check_search_order;         // simulate Windows DLL search order

    // --- Report ---
    wchar_t  report_output_path[MAX_PATH];  // where to write the JSON report
                                            // leave empty to skip file output
    BOOL     include_low_severity;   // include Low-severity findings in report

    // --- Defaults ---
    ScanOptions()
    {
        SecureZeroMemory(this, sizeof(*this));
        max_recursion_depth    = 5;
        check_phantom_dlls     = TRUE;
        check_writable_dirs    = TRUE;
        check_acl_permissiveness = TRUE;
        check_search_order     = TRUE;
        include_low_severity   = FALSE;
    }
};

// ---------------------------------------------------------------------------
// ScanResult
// Output of a full audit scan.
// ---------------------------------------------------------------------------
struct ScanResult {
    std::vector<AuditFinding> findings;

    uint32_t executables_scanned;
    uint32_t dlls_evaluated;
    uint32_t phantom_count;
    uint32_t writable_dir_count;
    uint32_t acl_issue_count;

    FILETIME scan_start;
    FILETIME scan_end;
};

// ===========================================================================
// Core Functions
// ===========================================================================

// ---------------------------------------------------------------------------
// RunAuditScan
// Execute a full audit scan according to |options|.
// Populates |out_result| with all findings.
// If |options.report_output_path| is non-empty, also writes a JSON report.
// Returns TRUE if the scan completed (even with zero findings).
// Returns FALSE on fatal error (e.g. target path does not exist).
// ---------------------------------------------------------------------------
BOOL RunAuditScan(const ScanOptions& options, ScanResult* out_result);

// ---------------------------------------------------------------------------
// ScanExecutable
// Scan a single PE executable. Appends findings to |out_findings|.
// Used internally by RunAuditScan; exposed for testing.
// ---------------------------------------------------------------------------
void ScanExecutable(const wchar_t*          exe_path,
                    const ScanOptions&      options,
                    std::vector<AuditFinding>* out_findings,
                    uint32_t*               out_dll_count);

// ---------------------------------------------------------------------------
// WriteJsonReport
// Serialize |result| to a JSON file at |output_path|.
// The report format is a single JSON object with a "findings" array.
// Returns TRUE on success.
// ---------------------------------------------------------------------------
BOOL WriteJsonReport(const ScanResult& result, const wchar_t* output_path);

} // namespace dhd
