// =============================================================================
// core/hardening.cpp
// ACL hardening and integrity verification for the DLL Hijacking Defense System.
//
// Sections
// --------
//   §1  Internal helpers — SHA-256 via BCrypt (64 KB chunk streaming)
//   §2  Internal helper — SetHardenedAcl (DACL builder via WINAPI)
//   §3  HardenLogDirectory — restrict log dir to SYSTEM + Admins
//   §4  HardenPolicyFile   — policy file: SYSTEM/Admins Full + Everyone Read
//   §5  SnapshotFileHash   — compute SHA-256 baseline of any file
//   §6  VerifyFileIntegrity — recompute and compare against baseline
//   §7  VerifyHashDatabaseIntegrity — parse db_integrity_hash and verify
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <bcrypt.h>
#include <shlwapi.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#include "hardening.h"
#include "constants.h"

#include <cstring>
#include <cwchar>
#include <cstdio>
#include <string>

namespace dhd {

// =============================================================================
// §1 — Internal SHA-256 helpers (BCrypt)
// =============================================================================

namespace {

// Chunk size for streaming file reads (64 KB)
static constexpr DWORD k_chunk_bytes = 64u * 1024u;

// ---------------------------------------------------------------------------
// Sha256Context — RAII wrapper around a BCrypt hash handle.
// ---------------------------------------------------------------------------
struct Sha256Context
{
    BCRYPT_ALG_HANDLE  alg    = nullptr;
    BCRYPT_HASH_HANDLE hash   = nullptr;
    DWORD              hash_len = 0;
    bool               ok     = false;

    Sha256Context()
    {
        NTSTATUS st = BCryptOpenAlgorithmProvider(&alg,
                                                   BCRYPT_SHA256_ALGORITHM,
                                                   nullptr, 0);
        if (!BCRYPT_SUCCESS(st)) return;

        DWORD result_len = 0, bytes = 0;
        st = BCryptGetProperty(alg,
                               BCRYPT_HASH_LENGTH,
                               reinterpret_cast<PUCHAR>(&hash_len),
                               sizeof(hash_len), &bytes, 0);
        if (!BCRYPT_SUCCESS(st)) return;
        (void)result_len;

        st = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(st)) return;

        ok = true;
    }

    ~Sha256Context()
    {
        if (hash) BCryptDestroyHash(hash);
        if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
    }

    BOOL Feed(const void* data, DWORD len) const
    {
        NTSTATUS st = BCryptHashData(hash,
                                     const_cast<PUCHAR>(
                                         reinterpret_cast<const UCHAR*>(data)),
                                     len, 0);
        return BCRYPT_SUCCESS(st) ? TRUE : FALSE;
    }

    // Finalise and write raw bytes into |out| (caller must provide hash_len bytes)
    BOOL Finalise(PUCHAR out) const
    {
        NTSTATUS st = BCryptFinishHash(hash, out, hash_len, 0);
        return BCRYPT_SUCCESS(st) ? TRUE : FALSE;
    }

    // Convenience: finalise and write lowercase hex into |out_hex|
    // |out_hex| must be at least (hash_len * 2 + 1) chars
    BOOL FinaliseHex(wchar_t* out_hex, size_t out_cap) const
    {
        if (out_cap < static_cast<size_t>(hash_len) * 2 + 1) return FALSE;

        UCHAR raw[32] = {};  // SHA-256 is always 32 bytes
        if (!BCRYPT_SUCCESS(BCryptFinishHash(hash, raw, hash_len, 0))) return FALSE;

        for (DWORD i = 0; i < hash_len; ++i) {
            swprintf_s(out_hex + i * 2, 3, L"%02x",
                       static_cast<unsigned>(raw[i]));
        }
        return TRUE;
    }

    Sha256Context(const Sha256Context&)            = delete;
    Sha256Context& operator=(const Sha256Context&) = delete;
};

// ---------------------------------------------------------------------------
// ComputeFileSha256Hex — open a file and stream its content through SHA-256.
// Writes lowercase hex into out_hex (must be >= SHA256_HEX_LEN+1 wchars).
// ---------------------------------------------------------------------------
static BOOL ComputeFileSha256Hex(const wchar_t* file_path,
                                  wchar_t*       out_hex,
                                  size_t         out_cap)
{
    if (!file_path || !out_hex || out_cap < SHA256_HEX_LEN + 1) return FALSE;

    HANDLE hf = CreateFileW(file_path,
                             GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING,
                             FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return FALSE;

    Sha256Context ctx;
    if (!ctx.ok) { CloseHandle(hf); return FALSE; }

    BYTE* buf = new(std::nothrow) BYTE[k_chunk_bytes];
    if (!buf) { CloseHandle(hf); return FALSE; }

    BOOL success = TRUE;
    DWORD read   = 0;
    while (ReadFile(hf, buf, k_chunk_bytes, &read, nullptr) && read > 0) {
        if (!ctx.Feed(buf, read)) { success = FALSE; break; }
    }

    delete[] buf;
    CloseHandle(hf);

    if (!success) return FALSE;
    return ctx.FinaliseHex(out_hex, out_cap);
}

// ---------------------------------------------------------------------------
// ComputeBufferSha256Hex — compute SHA-256 over an in-memory buffer.
// Writes lowercase hex into out_hex.
// ---------------------------------------------------------------------------
static BOOL ComputeBufferSha256Hex(const char* data,
                                    size_t      len,
                                    wchar_t*    out_hex,
                                    size_t      out_cap)
{
    if (!data || !out_hex || out_cap < SHA256_HEX_LEN + 1) return FALSE;

    Sha256Context ctx;
    if (!ctx.ok) return FALSE;

    // Feed in 64 KB slices to avoid DWORD overflow
    size_t remaining = len;
    const char* ptr  = data;
    while (remaining > 0) {
        DWORD chunk = (remaining > k_chunk_bytes)
                      ? k_chunk_bytes
                      : static_cast<DWORD>(remaining);
        if (!ctx.Feed(ptr, chunk)) return FALSE;
        ptr       += chunk;
        remaining -= chunk;
    }

    return ctx.FinaliseHex(out_hex, out_cap);
}

// =============================================================================
// §2 — Internal DACL builder
// =============================================================================

// ACE inheritance flags for directories vs. plain files
static constexpr BYTE k_dir_inherit  = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
static constexpr BYTE k_file_inherit = 0;   // no inheritance — file-level only

// ---------------------------------------------------------------------------
// SetHardenedAcl
// ---------------------------------------------------------------------------
// Builds a new DACL with the specified ACEs and applies it to |path| via
// SetNamedSecurityInfoW with PROTECTED_DACL_SECURITY_INFORMATION (breaks
// inherited permissions from parent containers).
//
// |obj_type|          — SE_FILE_OBJECT for both files and directories
// |ace_inherit_flags| — k_dir_inherit or k_file_inherit
// |include_everyone_read| — if TRUE, add Everyone: FILE_GENERIC_READ ACE
// ---------------------------------------------------------------------------
static BOOL SetHardenedAcl(const wchar_t*  path,
                             SE_OBJECT_TYPE  obj_type,
                             BYTE            ace_inherit_flags,
                             BOOL            include_everyone_read)
{
    // ---- Build SIDs --------------------------------------------------------
    BYTE sys_buf[SECURITY_MAX_SID_SIZE] = {};
    BYTE adm_buf[SECURITY_MAX_SID_SIZE] = {};
    BYTE evr_buf[SECURITY_MAX_SID_SIZE] = {};

    DWORD sys_sz = sizeof(sys_buf);
    DWORD adm_sz = sizeof(adm_buf);
    DWORD evr_sz = sizeof(evr_buf);

    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr,
                             reinterpret_cast<PSID>(sys_buf), &sys_sz))
        return FALSE;

    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
                             reinterpret_cast<PSID>(adm_buf), &adm_sz))
        return FALSE;

    if (include_everyone_read) {
        if (!CreateWellKnownSid(WinWorldSid, nullptr,
                                 reinterpret_cast<PSID>(evr_buf), &evr_sz))
            return FALSE;
    }

    // ---- Build DACL --------------------------------------------------------
    // 4 KB ACL buffer is more than sufficient for 3 ACEs with well-known SIDs
    // (max SID size is 68 bytes; each ACE header is 8 bytes → well within 4 KB)
    static constexpr DWORD k_acl_buf_size = 4096;
    BYTE acl_buf[k_acl_buf_size] = {};
    PACL dacl = reinterpret_cast<PACL>(acl_buf);

    if (!InitializeAcl(dacl, k_acl_buf_size, ACL_REVISION)) return FALSE;

    // SYSTEM: Full Control
    if (!AddAccessAllowedAceEx(dacl, ACL_REVISION,
                                ace_inherit_flags,
                                FILE_ALL_ACCESS,
                                reinterpret_cast<PSID>(sys_buf)))
        return FALSE;

    // Administrators: Full Control
    if (!AddAccessAllowedAceEx(dacl, ACL_REVISION,
                                ace_inherit_flags,
                                FILE_ALL_ACCESS,
                                reinterpret_cast<PSID>(adm_buf)))
        return FALSE;

    // Everyone: Read (optional — for policy file)
    if (include_everyone_read) {
        // FILE_GENERIC_READ includes Read Data + Read Attributes + Read Extended
        // Attributes + Synchronize — sufficient for opening and reading the file
        if (!AddAccessAllowedAceEx(dacl, ACL_REVISION,
                                    ace_inherit_flags,
                                    FILE_GENERIC_READ,
                                    reinterpret_cast<PSID>(evr_buf)))
            return FALSE;
    }

    // ---- Apply DACL — break inheritance via PROTECTED_DACL_SECURITY_INFORMATION
    DWORD err = SetNamedSecurityInfoW(
        const_cast<wchar_t*>(path),
        obj_type,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,    // owner — unchanged
        nullptr,    // group — unchanged
        dacl,
        nullptr);   // sacl  — unchanged

    return (err == ERROR_SUCCESS) ? TRUE : FALSE;
}

}  // anonymous namespace

// =============================================================================
// §3 — HardenLogDirectory
// =============================================================================

BOOL HardenLogDirectory(const wchar_t* log_dir_path)
{
    if (!log_dir_path || log_dir_path[0] == L'\0') return FALSE;

    // Create the directory if it does not exist yet
    if (!PathFileExistsW(log_dir_path)) {
        if (!CreateDirectoryW(log_dir_path, nullptr)) {
            DWORD err = GetLastError();
            if (err != ERROR_ALREADY_EXISTS) return FALSE;
        }
    }

    // Verify it is actually a directory
    DWORD attr = GetFileAttributesW(log_dir_path);
    if (attr == INVALID_FILE_ATTRIBUTES) return FALSE;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) return FALSE;

    // Apply hardened DACL:
    //   SYSTEM        → FILE_ALL_ACCESS (inheritable)
    //   Administrators → FILE_ALL_ACCESS (inheritable)
    //   No Everyone / Users write access — inheritance is broken
    return SetHardenedAcl(log_dir_path,
                           SE_FILE_OBJECT,
                           k_dir_inherit,
                           /*include_everyone_read=*/ FALSE);
}

// =============================================================================
// §4 — HardenPolicyFile
// =============================================================================

BOOL HardenPolicyFile(const wchar_t* policy_file_path)
{
    if (!policy_file_path || policy_file_path[0] == L'\0') return FALSE;

    if (!PathFileExistsW(policy_file_path)) return FALSE;

    DWORD attr = GetFileAttributesW(policy_file_path);
    if (attr == INVALID_FILE_ATTRIBUTES) return FALSE;
    if (attr & FILE_ATTRIBUTE_DIRECTORY) return FALSE;  // must be a file

    // Apply hardened DACL:
    //   SYSTEM         → FILE_ALL_ACCESS (no inheritance — file only)
    //   Administrators → FILE_ALL_ACCESS (no inheritance — file only)
    //   Everyone       → FILE_GENERIC_READ (read-only for non-admins)
    return SetHardenedAcl(policy_file_path,
                           SE_FILE_OBJECT,
                           k_file_inherit,
                           /*include_everyone_read=*/ TRUE);
}

// =============================================================================
// §5 — SnapshotFileHash
// =============================================================================

BOOL SnapshotFileHash(const wchar_t* file_path,
                      wchar_t*       out_hex_64,
                      size_t         out_cap_wchars)
{
    return ComputeFileSha256Hex(file_path, out_hex_64, out_cap_wchars);
}

// =============================================================================
// §6 — VerifyFileIntegrity
// =============================================================================

BOOL VerifyFileIntegrity(const wchar_t* file_path,
                         const wchar_t* expected_hex_64)
{
    if (!file_path || !expected_hex_64) return FALSE;
    if (wcslen(expected_hex_64) != SHA256_HEX_LEN) return FALSE;

    wchar_t computed[SHA256_HEX_LEN + 1] = {};
    if (!ComputeFileSha256Hex(file_path, computed, _countof(computed))) return FALSE;

    return (_wcsicmp(computed, expected_hex_64) == 0) ? TRUE : FALSE;
}

// =============================================================================
// §7 — VerifyHashDatabaseIntegrity
// =============================================================================
//
// The bootstrap tool (bootstrap_hashdb.cpp) writes the db_integrity_hash field
// as SHA-256(canonical_json), where canonical_json is the rebuilt JSON with
// db_integrity_hash set to the empty string "".
//
// To verify:
//   1. Read the raw file content
//   2. Locate "db_integrity_hash": "<hex>" in the raw bytes
//   3. Extract the stored hex value (64 chars)
//   4. Erase those 64 chars → produces canonical zero-hash content
//   5. SHA-256(canonical) must equal the extracted hex
//
// This approach is robust as long as bootstrap_hashdb uses a consistent format,
// which it does (RebuildJson always writes the same structure).
// =============================================================================

BOOL VerifyHashDatabaseIntegrity(const wchar_t* db_path)
{
    if (!db_path || db_path[0] == L'\0') return FALSE;
    if (!PathFileExistsW(db_path)) return FALSE;

    // ---- Read the entire file into a std::string ---------------------------
    HANDLE hf = CreateFileW(db_path, GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING,
                             FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return FALSE;

    LARGE_INTEGER file_size = {};
    if (!GetFileSizeEx(hf, &file_size)) { CloseHandle(hf); return FALSE; }

    // Reject unreasonably large files (>= 16 MB is not a valid hash DB)
    if (file_size.QuadPart >= 16LL * 1024 * 1024) {
        CloseHandle(hf);
        return FALSE;
    }

    DWORD sz = static_cast<DWORD>(file_size.QuadPart);
    std::string content;
    content.resize(sz);

    DWORD read_bytes = 0;
    BOOL read_ok = ReadFile(hf, &content[0], sz, &read_bytes, nullptr);
    CloseHandle(hf);

    if (!read_ok || read_bytes != sz) return FALSE;

    // ---- Locate the db_integrity_hash field --------------------------------
    // The bootstrap tool always writes:  "db_integrity_hash": "<hex64>",
    static const char k_key[] = "\"db_integrity_hash\": \"";
    size_t key_pos = content.find(k_key);
    if (key_pos == std::string::npos) {
        // Field is absent — file was never bootstrapped
        OutputDebugStringW(
            L"[DHD][HARDENING] VerifyHashDatabaseIntegrity: "
            L"db_integrity_hash field not found.\n");
        return FALSE;
    }

    size_t val_start = key_pos + (sizeof(k_key) - 1);  // sizeof includes '\0'
    size_t val_end   = content.find('"', val_start);
    if (val_end == std::string::npos) return FALSE;

    size_t val_len = val_end - val_start;

    // Empty hash means the DB was never bootstrapped (no DLL paths resolved yet)
    if (val_len == 0) {
        OutputDebugStringW(
            L"[DHD][HARDENING] VerifyHashDatabaseIntegrity: "
            L"db_integrity_hash is empty — run bootstrap_hashdb first.\n");
        return FALSE;
    }

    // Must be exactly 64 hex characters
    if (val_len != SHA256_HEX_LEN) return FALSE;

    // Extract stored hash as narrow string (it is always ASCII hex)
    std::string stored_narrow = content.substr(val_start, val_len);

    // Convert to wide for comparison
    wchar_t stored_hex[SHA256_HEX_LEN + 1] = {};
    for (size_t i = 0; i < SHA256_HEX_LEN; ++i) {
        stored_hex[i] = static_cast<wchar_t>(stored_narrow[i]);
    }

    // ---- Build canonical content (erase the 64 hash chars) -----------------
    // canonical = content with the hex value replaced by ""
    // i.e.:  "db_integrity_hash": ""
    std::string canonical = content;
    canonical.erase(val_start, val_len);

    // ---- Compute SHA-256 of the canonical content --------------------------
    wchar_t computed_hex[SHA256_HEX_LEN + 1] = {};
    if (!ComputeBufferSha256Hex(canonical.data(), canonical.size(),
                                 computed_hex, _countof(computed_hex)))
        return FALSE;

    // ---- Compare (case-insensitive) ----------------------------------------
    BOOL match = (_wcsicmp(computed_hex, stored_hex) == 0) ? TRUE : FALSE;

    if (!match) {
        OutputDebugStringW(
            L"[DHD][HARDENING] VerifyHashDatabaseIntegrity: "
            L"HASH MISMATCH — hash_database.json may have been tampered with.\n");
    }

    return match;
}

}  // namespace dhd
