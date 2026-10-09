// =============================================================================
// audit/audit_scanner.cpp
// Implementation of the Audit Scanner.
//
// Internal structure:
//   Section 1: PE Import Table parser (IMAGE_IMPORT_DESCRIPTOR)
//   Section 2: DLL search order simulation
//   Section 3: ACL permissiveness checker (GetNamedSecurityInfoW)
//   Section 4: Per-executable scan orchestrator
//   Section 5: JSON report writer (hand-written serialization)
//   Section 6: Public API
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <imagehlp.h>
#include <aclapi.h>
#include <shlwapi.h>

#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#include "audit_scanner.h"
#include "constants.h"
#include "types.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <deque>
#include <string>
#include <vector>

namespace dhd {

// ===========================================================================
// Section 1 — PE Import Table Parser
// Maps the PE header in read-only memory using MapAndLoad, iterates
// IMAGE_IMPORT_DESCRIPTOR chain, and collects all imported DLL names.
// ===========================================================================

namespace {

// ---------------------------------------------------------------------------
// ParseImports — open |exe_path| via MapAndLoad, walk the import table, and
// append each imported DLL name (lowercase) to |out_imports|.
// Returns TRUE if the file is a valid PE with at least one import.
// ---------------------------------------------------------------------------
static BOOL ParseImports(const wchar_t*          exe_path,
                          std::vector<std::wstring>* out_imports)
{
    // MapAndLoad works on narrow paths
    char narrow[MAX_PATH] = {};
    WideCharToMultiByte(CP_ACP, 0, exe_path, -1,
                         narrow, static_cast<int>(_countof(narrow)),
                         nullptr, nullptr);

    LOADED_IMAGE loaded_image{};
    if (!MapAndLoad(narrow, nullptr, &loaded_image, TRUE, TRUE)) {
        return FALSE;   // not a PE or file not found
    }

    BOOL found_any = FALSE;

    __try {
        // Locate the import directory
        ULONG import_dir_size = 0;
        PIMAGE_IMPORT_DESCRIPTOR import_desc =
            static_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                ImageDirectoryEntryToData(
                    loaded_image.MappedAddress,
                    FALSE,  // mapped as file, not as image
                    IMAGE_DIRECTORY_ENTRY_IMPORT,
                    &import_dir_size));

        if (!import_desc || import_dir_size == 0) {
            __leave;
        }

        // Walk the descriptor chain (terminated by an all-zero entry)
        while (import_desc->Name != 0) {
            // Translate the RVA to a file offset
            DWORD rva = import_desc->Name;
            DWORD raw_offset = 0;

            // Find the section that contains this RVA
            PIMAGE_SECTION_HEADER section = loaded_image.Sections;
            for (WORD i = 0; i < loaded_image.NumberOfSections; ++i, ++section) {
                DWORD sec_start = section->VirtualAddress;
                DWORD sec_end   = sec_start + section->SizeOfRawData;
                if (rva >= sec_start && rva < sec_end) {
                    raw_offset = rva - sec_start + section->PointerToRawData;
                    break;
                }
            }

            if (raw_offset != 0 &&
                raw_offset < loaded_image.SizeOfImage)
            {
                const char* dll_name_a =
                    reinterpret_cast<const char*>(
                        loaded_image.MappedAddress + raw_offset);

                // Sanity: name must be a non-empty, printable ASCII string
                size_t name_len = strnlen(dll_name_a, MAX_DLL_NAME_LEN);
                if (name_len > 0 && name_len < MAX_DLL_NAME_LEN) {
                    // Convert to wide and lowercase
                    wchar_t wide_name[MAX_DLL_NAME_LEN] = {};
                    MultiByteToWideChar(CP_ACP, 0, dll_name_a, -1,
                                         wide_name, static_cast<int>(_countof(wide_name)));
                    _wcslwr_s(wide_name, _countof(wide_name));
                    out_imports->emplace_back(wide_name);
                    found_any = TRUE;
                }
            }

            ++import_desc;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Malformed PE — ignore and return what we have
    }

    UnMapAndLoad(&loaded_image);
    return found_any;
}

// ===========================================================================
// Section 2 — DLL Search Order Simulation
// Implements the standard Windows DLL search order (SafeDllSearchMode on):
//   1. Directories listed in the application's manifest KnownDLLs
//   2. The directory from which the application loaded
//   3. The system directory (System32 / SysWOW64)
//   4. The 16-bit system directory (System)
//   5. The Windows directory
//   6. The current working directory (when SafeDllSearchMode is ON, this
//      comes after system dirs — we simulate that safe mode is enabled)
//   7. Directories in the PATH environment variable
//
// For each DLL name we check each directory in order and return the first
// path where the file physically exists. We also flag any directory in the
// chain that is write-permissive before the legitimate DLL is found.
// ===========================================================================

// Candidate directory struct used during search simulation
struct SearchDir {
    std::wstring path;
    bool         is_system;    // TRUE for System32/SysWOW64/Windows dirs
};

// ---------------------------------------------------------------------------
// ExpandPathEnv — collect directories from the PATH environment variable.
// ---------------------------------------------------------------------------
static std::vector<std::wstring> GetPathDirectories()
{
    std::vector<std::wstring> dirs;

    DWORD needed = GetEnvironmentVariableW(L"PATH", nullptr, 0);
    if (needed == 0) return dirs;

    std::wstring path_val(static_cast<size_t>(needed), L'\0');
    if (!GetEnvironmentVariableW(L"PATH", path_val.data(),
                                  static_cast<DWORD>(path_val.size())))
    {
        return dirs;
    }

    // Tokenize on semicolons
    wchar_t* ctx = nullptr;
    wchar_t* token = wcstok_s(path_val.data(), L";", &ctx);
    while (token) {
        if (token[0] != L'\0') dirs.emplace_back(token);
        token = wcstok_s(nullptr, L";", &ctx);
    }
    return dirs;
}

// ---------------------------------------------------------------------------
// BuildSearchOrder — construct the ordered directory list for |exe_path|.
// ---------------------------------------------------------------------------
static std::vector<SearchDir> BuildSearchOrder(const wchar_t* exe_path)
{
    std::vector<SearchDir> order;

    // 1. Application directory
    {
        wchar_t app_dir[MAX_PATH] = {};
        wcscpy_s(app_dir, _countof(app_dir), exe_path);
        PathRemoveFileSpecW(app_dir);
        if (app_dir[0] != L'\0') {
            order.push_back({ app_dir, false });
        }
    }

    // 2. System32
    {
        wchar_t sys32[MAX_PATH] = {};
        GetSystemDirectoryW(sys32, MAX_PATH);
        order.push_back({ sys32, true });
    }

    // 3. System (16-bit) — usually C:\Windows\System
    {
        wchar_t sys16[MAX_PATH] = {};
        GetSystemDirectoryW(sys16, MAX_PATH);
        PathRemoveFileSpecW(sys16);
        PathAppendW(sys16, L"System");
        order.push_back({ sys16, true });
    }

    // 4. Windows directory
    {
        wchar_t windir[MAX_PATH] = {};
        GetWindowsDirectoryW(windir, MAX_PATH);
        order.push_back({ windir, true });
    }

    // 5. Current working directory (safe search mode: AFTER system dirs)
    {
        wchar_t cwd[MAX_PATH] = {};
        GetCurrentDirectoryW(MAX_PATH, cwd);
        order.push_back({ cwd, false });
    }

    // 6. PATH directories
    for (auto& d : GetPathDirectories()) {
        order.push_back({ d, false });
    }

    return order;
}

// ---------------------------------------------------------------------------
// FindDllOnDisk — search for |dll_name_lower| in each directory of
// |search_order| and return the first path where the file exists.
// Returns empty string if not found on disk (phantom DLL).
// ---------------------------------------------------------------------------
static std::wstring FindDllOnDisk(const std::wstring&            dll_name,
                                   const std::vector<SearchDir>& search_order)
{
    for (const SearchDir& dir : search_order) {
        wchar_t candidate[MAX_PATH] = {};
        wcscpy_s(candidate, _countof(candidate), dir.path.c_str());
        PathAppendW(candidate, dll_name.c_str());

        if (PathFileExistsW(candidate)) {
            return candidate;
        }
    }
    return {};
}

// ===========================================================================
// Section 3 — ACL Permissiveness Checker
// Determines if a directory allows write access to non-admin principals.
//
// Strategy:
//   Call GetNamedSecurityInfoW to get the DACL.
//   Walk each ACE. Flag if any of the following are present:
//     - Everyone (S-1-1-0) with write/modify/full access
//     - BUILTIN\Users (S-1-5-32-545) with write/modify/full access
//     - Authenticated Users (S-1-5-11) with write/modify/full access
//
// This is a best-effort check; it does not evaluate token impersonation,
// deny ACEs, or object inheritance beyond what is directly on the directory.
// ===========================================================================

// Write-relevant access rights
static constexpr DWORD WRITE_ACCESS_MASK =
    FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
    FILE_WRITE_EA   | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER |
    GENERIC_WRITE   | GENERIC_ALL;

// ---------------------------------------------------------------------------
// SidMatchesKnownNonAdmin — returns TRUE if |sid| is one of the three
// common non-admin principals we flag: Everyone, Users, Authenticated Users.
// ---------------------------------------------------------------------------
static BOOL SidMatchesKnownNonAdmin(PSID sid)
{
    static const WELL_KNOWN_SID_TYPE NON_ADMIN_SIDS[] = {
        WinWorldSid,               // Everyone (S-1-1-0)
        WinBuiltinUsersSid,        // BUILTIN\Users (S-1-5-32-545)
        WinAuthenticatedUserSid,   // Authenticated Users (S-1-5-11)
    };

    for (WELL_KNOWN_SID_TYPE wkt : NON_ADMIN_SIDS) {
        BYTE known_buf[SECURITY_MAX_SID_SIZE];
        DWORD known_sz = sizeof(known_buf);
        if (CreateWellKnownSid(wkt, nullptr,
                                reinterpret_cast<PSID>(known_buf),
                                &known_sz))
        {
            if (EqualSid(sid, reinterpret_cast<PSID>(known_buf))) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// IsDirectoryWritableByNonAdmin — returns TRUE if |dir_path| has a DACL
// that grants write access to a known non-admin principal.
// ---------------------------------------------------------------------------
static BOOL IsDirectoryWritableByNonAdmin(const wchar_t* dir_path)
{
    PSECURITY_DESCRIPTOR psd = nullptr;
    PACL                 dacl = nullptr;

    DWORD err = GetNamedSecurityInfoW(
        dir_path,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr,
        &dacl, nullptr,
        &psd);

    if (err != ERROR_SUCCESS || !dacl) {
        if (psd) LocalFree(psd);
        return FALSE;
    }

    BOOL flagged = FALSE;

    ACL_SIZE_INFORMATION acl_info{};
    if (!GetAclInformation(dacl, &acl_info,
                            sizeof(acl_info), AclSizeInformation))
    {
        LocalFree(psd);
        return FALSE;
    }

    for (DWORD i = 0; i < acl_info.AceCount && !flagged; ++i) {
        LPVOID ace = nullptr;
        if (!GetAce(dacl, i, &ace)) continue;

        ACE_HEADER* hdr = static_cast<ACE_HEADER*>(ace);

        // Only care about allow ACEs
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;

        ACCESS_ALLOWED_ACE* allow_ace = static_cast<ACCESS_ALLOWED_ACE*>(ace);
        PSID ace_sid = &allow_ace->SidStart;
        DWORD ace_mask = allow_ace->Mask;

        if ((ace_mask & WRITE_ACCESS_MASK) &&
            SidMatchesKnownNonAdmin(ace_sid))
        {
            flagged = TRUE;
        }
    }

    LocalFree(psd);
    return flagged;
}

// ===========================================================================
// Section 4 — Per-Executable Scan Orchestrator
// ===========================================================================

// ---------------------------------------------------------------------------
// MakeFinding — fill an AuditFinding with common fields.
// ---------------------------------------------------------------------------
static AuditFinding MakeFinding(RiskLevel      severity,
                                 const wchar_t* target_exe,
                                 const wchar_t* dll_name,
                                 const wchar_t* issue_code,
                                 const wchar_t* detail_fmt,
                                 ...)
{
    AuditFinding f{};
    f.severity = severity;
    wcscpy_s(f.target_path, _countof(f.target_path), target_exe);
    wcscpy_s(f.dll_name,    _countof(f.dll_name),    dll_name);
    wcscpy_s(f.issue_code,  _countof(f.issue_code),  issue_code);

    va_list args;
    va_start(args, detail_fmt);
    _vsnwprintf_s(f.detail, _countof(f.detail), _TRUNCATE, detail_fmt, args);
    va_end(args);

    return f;
}

// ---------------------------------------------------------------------------
// CheckImportedDll — run all enabled checks for a single imported DLL name.
// Appends any findings to |out_findings|.
// ---------------------------------------------------------------------------
static void CheckImportedDll(const wchar_t*             exe_path,
                               const std::wstring&        dll_name,
                               const std::vector<SearchDir>& search_order,
                               const ScanOptions&         options,
                               std::vector<AuditFinding>* out_findings)
{
    // --- Phantom DLL check ---
    std::wstring resolved_path;
    if (options.check_phantom_dlls || options.check_writable_dirs) {
        resolved_path = FindDllOnDisk(dll_name, search_order);
    }

    if (options.check_phantom_dlls && resolved_path.empty()) {
        AuditFinding f = MakeFinding(
            RiskLevel::High,
            exe_path,
            dll_name.c_str(),
            issue::PHANTOM_DLL,
            L"DLL '%ls' is imported by '%ls' but does not exist anywhere in the "
            L"simulated search order. An attacker can plant a malicious DLL to "
            L"satisfy this import.",
            dll_name.c_str(),
            PathFindFileNameW(exe_path));
        wcscpy_s(f.recommendation, _countof(f.recommendation),
                 L"Remove this import or add the DLL to a write-protected system directory.");
        out_findings->push_back(std::move(f));
        return;  // no path to check further
    }

    // --- Search order hijack check ---
    // Walk every directory that appears BEFORE the resolved path in the search
    // order. If any of those directories is writable by non-admin principals,
    // an attacker could plant a DLL that gets loaded first.
    if (options.check_writable_dirs && !resolved_path.empty()) {
        for (const SearchDir& dir : search_order) {
            // Build the candidate path in this directory
            wchar_t candidate[MAX_PATH] = {};
            wcscpy_s(candidate, _countof(candidate), dir.path.c_str());
            PathAppendW(candidate, dll_name.c_str());

            // Have we reached the actual resolved location?
            if (_wcsicmp(candidate, resolved_path.c_str()) == 0) break;

            // This directory precedes the real DLL and could shadow it.
            // Check if it is writable by non-admin principals.
            BOOL dir_writable = FALSE;
            if (options.check_acl_permissiveness && PathIsDirectoryW(dir.path.c_str())) {
                dir_writable = IsDirectoryWritableByNonAdmin(dir.path.c_str());
            }

            if (dir_writable) {
                AuditFinding f = MakeFinding(
                    dir.is_system ? RiskLevel::Critical : RiskLevel::High,
                    exe_path,
                    dll_name.c_str(),
                    issue::WRITABLE_DIR_HIJACKABLE,
                    L"Directory '%ls' precedes the legitimate '%ls' in the DLL search "
                    L"order and is writable by non-admin principals. A DLL named '%ls' "
                    L"placed there would be loaded instead.",
                    dir.path.c_str(),
                    resolved_path.c_str(),
                    dll_name.c_str());
                wcscpy_s(f.recommendation, _countof(f.recommendation),
                         L"Restrict write access on this directory to SYSTEM and "
                         L"Administrators only, or use SetDefaultDllDirectories() "
                         L"to harden the DLL search order.");
                out_findings->push_back(std::move(f));
                // Report all such directories, not just the first
            }
        }
    }

    // --- ACL check on the resolved path's directory ---
    if (options.check_acl_permissiveness && !resolved_path.empty()) {
        wchar_t resolved_dir[MAX_PATH] = {};
        wcscpy_s(resolved_dir, _countof(resolved_dir), resolved_path.c_str());
        PathRemoveFileSpecW(resolved_dir);

        if (!PathIsDirectoryW(resolved_dir)) return;

        // Skip system-owned directories (System32, Windows) — expected behaviour
        bool is_sys = (_wcsnicmp(resolved_dir,
                                  tier1_paths::SYSTEM32,
                                  wcslen(tier1_paths::SYSTEM32)) == 0) ||
                      (_wcsnicmp(resolved_dir,
                                  tier1_paths::SYSWOW64,
                                  wcslen(tier1_paths::SYSWOW64)) == 0) ||
                      (_wcsnicmp(resolved_dir,
                                  tier1_paths::WINSXS,
                                  wcslen(tier1_paths::WINSXS)) == 0);
        if (is_sys) return;

        if (IsDirectoryWritableByNonAdmin(resolved_dir)) {
            AuditFinding f = MakeFinding(
                RiskLevel::Medium,
                exe_path,
                dll_name.c_str(),
                issue::ACL_OVERLY_PERMISSIVE,
                L"The directory '%ls' containing '%ls' grants write access to "
                L"non-admin principals. An in-place replacement attack is possible.",
                resolved_dir,
                dll_name.c_str());
            wcscpy_s(f.recommendation, _countof(f.recommendation),
                     L"Restrict write access on this directory to SYSTEM and "
                     L"Administrators only.");
            out_findings->push_back(std::move(f));
        }
    }
}

} // anonymous namespace

// ===========================================================================
// Section 5 — JSON Report Writer
// ===========================================================================

namespace {

static const char* RiskLevelStr(RiskLevel r)
{
    switch (r) {
        case RiskLevel::Low:      return "Low";
        case RiskLevel::Medium:   return "Medium";
        case RiskLevel::High:     return "High";
        case RiskLevel::Critical: return "Critical";
        default:                  return "Unknown";
    }
}

static std::string WideToUtf8(const wchar_t* w)
{
    if (!w || !w[0]) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (sz <= 1) return {};
    std::string out(static_cast<size_t>(sz - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), sz, nullptr, nullptr);
    return out;
}

static std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 4);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    sprintf_s(buf, "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

static std::string FiletimeToIso(const FILETIME& ft)
{
    SYSTEMTIME st{};
    FileTimeToSystemTime(&ft, &st);
    char buf[32];
    sprintf_s(buf, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

} // anonymous namespace

// ===========================================================================
// Section 6 — Public API
// ===========================================================================

void ScanExecutable(const wchar_t*          exe_path,
                    const ScanOptions&      options,
                    std::vector<AuditFinding>* out_findings,
                    uint32_t*               out_dll_count)
{
    if (!exe_path || !out_findings) return;

    // Parse imports from PE
    std::vector<std::wstring> imports;
    if (!ParseImports(exe_path, &imports)) return;

    if (out_dll_count) *out_dll_count += static_cast<uint32_t>(imports.size());

    // Deduplicate (same DLL may appear in multiple import descriptors)
    std::sort(imports.begin(), imports.end());
    imports.erase(std::unique(imports.begin(), imports.end()), imports.end());

    // Build search order for this executable
    std::vector<SearchDir> search_order;
    if (options.check_writable_dirs || options.check_phantom_dlls) {
        search_order = BuildSearchOrder(exe_path);
    }

    // Evaluate each imported DLL
    for (const std::wstring& dll : imports) {
        CheckImportedDll(exe_path, dll, search_order, options, out_findings);
    }
}

BOOL RunAuditScan(const ScanOptions& options, ScanResult* out_result)
{
    if (!out_result) return FALSE;
    SecureZeroMemory(out_result, sizeof(ScanResult));
    GetSystemTimeAsFileTime(&out_result->scan_start);

    // --- Collect target executables ---
    std::vector<std::wstring> targets;

    if (options.target_exe[0] != L'\0') {
        if (!PathFileExistsW(options.target_exe)) return FALSE;
        targets.emplace_back(options.target_exe);
    }

    if (options.target_directory[0] != L'\0') {
        if (!PathIsDirectoryW(options.target_directory)) return FALSE;

        // BFS directory enumeration up to max_recursion_depth
        struct DirEntry { std::wstring path; uint32_t depth; };
        std::deque<DirEntry> dir_queue = { { options.target_directory, 0 } };

        while (!dir_queue.empty()) {
            DirEntry entry = dir_queue.front();
            dir_queue.pop_front();  // O(1) instead of vector::erase(begin()) O(n)

            wchar_t pattern[MAX_PATH] = {};
            wcscpy_s(pattern, _countof(pattern), entry.path.c_str());
            PathAppendW(pattern, L"*");

            WIN32_FIND_DATAW fd{};
            HANDLE hFind = FindFirstFileW(pattern, &fd);
            if (hFind == INVALID_HANDLE_VALUE) continue;

            do {
                if (wcscmp(fd.cFileName, L".") == 0 ||
                    wcscmp(fd.cFileName, L"..") == 0) continue;

                wchar_t child[MAX_PATH] = {};
                wcscpy_s(child, _countof(child), entry.path.c_str());
                PathAppendW(child, fd.cFileName);

                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (entry.depth < options.max_recursion_depth) {
                        dir_queue.push_back({ child, entry.depth + 1 });
                    }
                } else {
                    // Only scan .exe files
                    const wchar_t* ext = PathFindExtensionW(fd.cFileName);
                    if (ext && _wcsicmp(ext, L".exe") == 0) {
                        targets.emplace_back(child);
                    }
                }
            } while (FindNextFileW(hFind, &fd));

            FindClose(hFind);
        }
    }

    if (targets.empty()) return FALSE;

    // --- Scan each executable ---
    for (const std::wstring& exe : targets) {
        uint32_t dll_count = 0;
        ScanExecutable(exe.c_str(), options, &out_result->findings, &dll_count);
        out_result->executables_scanned++;
        out_result->dlls_evaluated += dll_count;
    }

    // --- Tally findings by type ---
    for (const AuditFinding& f : out_result->findings) {
        if (wcscmp(f.issue_code, issue::PHANTOM_DLL) == 0)
            out_result->phantom_count++;
        else if (wcscmp(f.issue_code, issue::WRITABLE_DIR_HIJACKABLE) == 0)
            out_result->writable_dir_count++;
        else if (wcscmp(f.issue_code, issue::ACL_OVERLY_PERMISSIVE) == 0)
            out_result->acl_issue_count++;
    }

    GetSystemTimeAsFileTime(&out_result->scan_end);

    // --- Write JSON report if requested ---
    if (options.report_output_path[0] != L'\0') {
        WriteJsonReport(*out_result, options.report_output_path);
    }

    return TRUE;
}

BOOL WriteJsonReport(const ScanResult& result, const wchar_t* output_path)
{
    if (!output_path || output_path[0] == L'\0') return FALSE;

    // Ensure the output directory exists
    wchar_t out_dir[MAX_PATH] = {};
    wcscpy_s(out_dir, _countof(out_dir), output_path);
    PathRemoveFileSpecW(out_dir);
    if (out_dir[0] != L'\0') {
        CreateDirectoryW(out_dir, nullptr);  // fails silently if exists
    }

    HANDLE hFile = CreateFileW(output_path,
                                GENERIC_WRITE, 0,
                                nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    std::string json;
    json.reserve(4096);

    json += "{\r\n";
    json += "  \"report_version\": 1,\r\n";
    json += "  \"scan_start\": \"";
    json += FiletimeToIso(result.scan_start);
    json += "\",\r\n";
    json += "  \"scan_end\": \"";
    json += FiletimeToIso(result.scan_end);
    json += "\",\r\n";

    char summary[256];
    sprintf_s(summary, sizeof(summary),
        "  \"executables_scanned\": %u,\r\n"
        "  \"dlls_evaluated\": %u,\r\n"
        "  \"phantom_count\": %u,\r\n"
        "  \"writable_dir_count\": %u,\r\n"
        "  \"acl_issue_count\": %u,\r\n"
        "  \"total_findings\": %u,\r\n",
        result.executables_scanned,
        result.dlls_evaluated,
        result.phantom_count,
        result.writable_dir_count,
        result.acl_issue_count,
        static_cast<uint32_t>(result.findings.size()));
    json += summary;

    json += "  \"findings\": [\r\n";

    for (size_t i = 0; i < result.findings.size(); ++i) {
        const AuditFinding& f = result.findings[i];
        const bool last = (i + 1 == result.findings.size());

        // Build entry as std::string to avoid buffer overflow on long paths/details.
        std::string entry;
        entry += "    {\r\n";
        entry += "      \"severity\": \"" + std::string(RiskLevelStr(f.severity)) + "\",\r\n";
        entry += "      \"target_path\": \"" + JsonEscape(WideToUtf8(f.target_path)) + "\",\r\n";
        entry += "      \"dll_name\": \"" + JsonEscape(WideToUtf8(f.dll_name)) + "\",\r\n";
        entry += "      \"issue_code\": \"" + JsonEscape(WideToUtf8(f.issue_code)) + "\",\r\n";
        entry += "      \"detail\": \"" + JsonEscape(WideToUtf8(f.detail)) + "\",\r\n";
        entry += "      \"recommendation\": \"" + JsonEscape(WideToUtf8(f.recommendation)) + "\"\r\n";
        entry += last ? "    }\r\n" : "    },\r\n";
        json += entry;
    }

    json += "  ]\r\n";
    json += "}\r\n";

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, json.c_str(),
                         static_cast<DWORD>(json.size()),
                         &written, nullptr);
    FlushFileBuffers(hFile);
    CloseHandle(hFile);

    return ok && (written == static_cast<DWORD>(json.size()));
}

} // namespace dhd
