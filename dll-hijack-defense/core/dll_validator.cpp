// =============================================================================
// core/dll_validator.cpp
// Implementation of the DLL Validator — four-layer validation pipeline.
//
// Internal structure:
//   HashDatabaseLoader — loads config/hash_database.json; in-memory lookup
//   ValidationCache    — thread-safe, keyed by (canonical_path, file_mtime)
//   Layer functions    — CheckPathWhitelist, CheckNameHeuristics,
//                        ComputeFileHashSHA256, LookupHashDatabase,
//                        VerifyAuthenticode
//   ValidateDLL        — orchestrator
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include <wincrypt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

#include "dll_validator.h"
#include "policy.h"
#include "constants.h"
#include "types.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace dhd {

// ===========================================================================
// Section 1 — Hash Database Loader
// Parses config/hash_database.json once at initialization and exposes
// O(1) lookup by SHA-256 hex string.
// ===========================================================================

namespace {

// ---------------------------------------------------------------------------
// Minimal JSON helpers (same approach as policy.cpp — no external library).
// ---------------------------------------------------------------------------
static std::string ReadFileToStr(const wchar_t* path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart == 0 ||
        sz.QuadPart > 8 * 1024 * 1024)   // 8 MB cap
    {
        CloseHandle(h); return {};
    }

    std::string buf(static_cast<size_t>(sz.QuadPart), '\0');
    DWORD nread = 0;
    BOOL ok = ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()),
                       &nread, nullptr);
    CloseHandle(h);
    if (!ok || nread != static_cast<DWORD>(buf.size())) return {};
    return buf;
}

// Extract all string values for a repeated key inside JSON array objects.
// E.g. ExtractAllValuesForKey(json, "sha256") → {"abc...", "def...", ...}
static std::vector<std::string> ExtractAllValuesForKey(
    const std::string& json, const char* key)
{
    std::vector<std::string> result;
    size_t pos = 0;
    std::string search = std::string("\"") + key + "\"";

    while ((pos = json.find(search, pos)) != std::string::npos) {
        size_t colon = json.find(':', pos + search.size());
        if (colon == std::string::npos) break;
        size_t q1 = json.find('"', colon + 1);
        if (q1 == std::string::npos) break;
        size_t q2 = json.find('"', q1 + 1);
        if (q2 == std::string::npos) break;

        std::string val = json.substr(q1 + 1, q2 - q1 - 1);
        if (!val.empty()) result.push_back(std::move(val));
        pos = q2 + 1;
    }
    return result;
}

// Extract string array under a top-level key  "key": ["v1", "v2", ...]
static std::vector<std::string> ExtractTopLevelArray(
    const std::string& json, const char* key)
{
    std::vector<std::string> result;
    std::string search = std::string("\"") + key + "\"";
    size_t kpos = json.find(search);
    if (kpos == std::string::npos) return result;

    size_t bracket = json.find('[', kpos + search.size());
    size_t end_bracket = json.find(']', bracket);
    if (bracket == std::string::npos || end_bracket == std::string::npos)
        return result;

    std::string section = json.substr(bracket, end_bracket - bracket + 1);
    size_t pos = 0;
    while ((pos = section.find('"', pos)) != std::string::npos) {
        size_t q2 = section.find('"', pos + 1);
        if (q2 == std::string::npos) break;
        result.push_back(section.substr(pos + 1, q2 - pos - 1));
        pos = q2 + 1;
    }
    return result;
}

// Collect the "sha256" values from the "revoked" array block.
static std::vector<std::string> ExtractRevokedHashes(const std::string& json)
{
    std::vector<std::string> result;
    size_t revoked_pos = json.find("\"revoked\"");
    if (revoked_pos == std::string::npos) return result;

    size_t bracket = json.find('[', revoked_pos);
    size_t end_bracket = json.find(']', bracket);
    if (bracket == std::string::npos || end_bracket == std::string::npos)
        return result;

    std::string section = json.substr(bracket, end_bracket - bracket + 1);
    size_t pos = 0;
    std::string search = "\"sha256\"";
    while ((pos = section.find(search, pos)) != std::string::npos) {
        size_t colon = section.find(':', pos + search.size());
        if (colon == std::string::npos) break;
        size_t q1 = section.find('"', colon + 1);
        if (q1 == std::string::npos) break;
        size_t q2 = section.find('"', q1 + 1);
        if (q2 == std::string::npos) break;
        std::string val = section.substr(q1 + 1, q2 - q1 - 1);
        if (!val.empty()) result.push_back(std::move(val));
        pos = q2 + 1;
    }
    return result;
}

// ---------------------------------------------------------------------------
// HashDatabase — in-memory hash lookup store.
// ---------------------------------------------------------------------------
struct HashDatabase {
    // lowercase hex SHA-256 → approved
    std::unordered_set<std::string> approved;
    // lowercase hex SHA-256 → revoked
    std::unordered_set<std::string> revoked;
    // lowercase DLL names known to be system DLLs
    std::unordered_set<std::string> known_system_dlls;
    bool loaded = false;
};

static HashDatabase    s_hash_db;
static SRWLOCK         s_db_lock = SRWLOCK_INIT;

static std::string ToLower(const std::string& s)
{
    std::string out = s;
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

static BOOL LoadHashDatabase(const wchar_t* path)
{
    std::string json = ReadFileToStr(path);
    if (json.empty()) return FALSE;

    AcquireSRWLockExclusive(&s_db_lock);

    s_hash_db.approved.clear();
    s_hash_db.revoked.clear();
    s_hash_db.known_system_dlls.clear();

    // Parse approved hashes from "entries" objects
    // We look for all "sha256" values that appear before any "revoked" block.
    // Simplification: collect ALL sha256 values in "entries", then subtract
    // those in "revoked".
    auto all_hashes = ExtractAllValuesForKey(json, "sha256");
    for (auto& h : all_hashes) {
        if (!h.empty()) s_hash_db.approved.insert(ToLower(h));
    }

    // Revoked hashes
    auto revoked = ExtractRevokedHashes(json);
    for (auto& h : revoked) {
        std::string lh = ToLower(h);
        s_hash_db.revoked.insert(lh);
        s_hash_db.approved.erase(lh);   // cannot be both approved and revoked
    }

    // Known system DLL names (lowercase)
    auto sys_dlls = ExtractTopLevelArray(json, "known_system_dlls");
    for (auto& name : sys_dlls) {
        s_hash_db.known_system_dlls.insert(ToLower(name));
    }

    s_hash_db.loaded = true;
    ReleaseSRWLockExclusive(&s_db_lock);
    return TRUE;
}

static HashLookupResult QueryHashDatabase(const char* sha256_lower)
{
    AcquireSRWLockShared(&s_db_lock);

    if (!s_hash_db.loaded) {
        ReleaseSRWLockShared(&s_db_lock);
        return HashLookupResult::DbError;
    }

    bool is_revoked  = (s_hash_db.revoked.count(sha256_lower) > 0);
    bool is_approved = (s_hash_db.approved.count(sha256_lower) > 0);

    ReleaseSRWLockShared(&s_db_lock);

    if (is_revoked)  return HashLookupResult::Revoked;
    if (is_approved) return HashLookupResult::Found;
    return HashLookupResult::NotFound;
}

static bool IsKnownSystemDll(const wchar_t* dll_name_lower_w)
{
    // Convert wide to narrow for set lookup
    char narrow[MAX_DLL_NAME_LEN] = {};
    WideCharToMultiByte(CP_ACP, 0, dll_name_lower_w, -1,
                        narrow, static_cast<int>(_countof(narrow)), nullptr, nullptr);

    AcquireSRWLockShared(&s_db_lock);
    bool found = (s_hash_db.known_system_dlls.count(narrow) > 0);
    ReleaseSRWLockShared(&s_db_lock);
    return found;
}

// ===========================================================================
// Section 2 — Validation Cache
// Keyed by (canonical_path, file_mtime). Evicted when mtime changes.
// Thread-safe via SRWLOCK.
// ===========================================================================

struct CacheKey {
    std::wstring  path;
    FILETIME      mtime;    // last write time at validation time
};

struct CacheKeyEqual {
    bool operator()(const CacheKey& a, const CacheKey& b) const noexcept {
        return (CompareFileTime(&a.mtime, &b.mtime) == 0) &&
               (_wcsicmp(a.path.c_str(), b.path.c_str()) == 0);
    }
};

struct CacheKeyHash {
    std::size_t operator()(const CacheKey& k) const noexcept {
        std::size_t h1 = std::hash<std::wstring>{}(k.path);
        std::size_t h2 = std::hash<uint64_t>{}(
            (static_cast<uint64_t>(k.mtime.dwHighDateTime) << 32) |
             static_cast<uint64_t>(k.mtime.dwLowDateTime));
        return h1 ^ (h2 << 1);
    }
};

using CacheMap = std::unordered_map<CacheKey, ValidationResult,
                                    CacheKeyHash, CacheKeyEqual>;

static CacheMap  s_cache;
static SRWLOCK   s_cache_lock = SRWLOCK_INIT;
static size_t    s_cache_hits   = 0;
static size_t    s_cache_misses = 0;

static BOOL GetFileMtime(HANDLE h, FILETIME* out_mtime)
{
    FILETIME creation, access, write;
    if (!GetFileTime(h, &creation, &access, &write)) return FALSE;
    *out_mtime = write;
    return TRUE;
}

static BOOL CacheLookup(const wchar_t* path, HANDLE file_handle,
                         ValidationResult* out)
{
    FILETIME mtime{};
    if (!GetFileMtime(file_handle, &mtime)) return FALSE;

    CacheKey key{ path, mtime };

    AcquireSRWLockShared(&s_cache_lock);
    auto it = s_cache.find(key);
    if (it == s_cache.end()) {
        // Upgrade to exclusive to increment miss counter
        ReleaseSRWLockShared(&s_cache_lock);
        AcquireSRWLockExclusive(&s_cache_lock);
        ++s_cache_misses;
        ReleaseSRWLockExclusive(&s_cache_lock);
        return FALSE;
    }

    *out = it->second;
    out->served_from_cache = TRUE;
    
    // Increment cache hits under exclusive lock to avoid data race (A-09)
    ReleaseSRWLockShared(&s_cache_lock);
    AcquireSRWLockExclusive(&s_cache_lock);
    ++s_cache_hits;
    ReleaseSRWLockExclusive(&s_cache_lock);
    
    return TRUE;
}

static void CacheInsert(const wchar_t* path, HANDLE file_handle,
                         const ValidationResult& result)
{
    const PolicyConfig& cfg = PolicyManager::GetConfig();
    if (!cfg.cache_enabled) return;

    FILETIME mtime{};
    if (!GetFileMtime(file_handle, &mtime)) return;

    AcquireSRWLockExclusive(&s_cache_lock);

    // Evict oldest entry if at capacity (simple LRU-less eviction)
    if (s_cache.size() >= cfg.cache_max_entries && cfg.cache_max_entries > 0) {
        s_cache.erase(s_cache.begin());
    }

    CacheKey key{ path, mtime };
    ValidationResult stored = result;
    stored.served_from_cache = FALSE;   // mark as fresh when stored
    s_cache[key] = stored;

    ReleaseSRWLockExclusive(&s_cache_lock);
}

// ===========================================================================
// Section 3 — Layer 1: Path Whitelist
// ===========================================================================

static void CheckPathWhitelist(const wchar_t*     canonical_path,
                                float*             out_score,
                                WhitelistTier*     out_tier,
                                uint32_t*          out_reasons)
{
    *out_score   = 0.0f;
    *out_tier    = WhitelistTier::None;

    // Blocked directory check — hard zero regardless of tier
    if (PolicyManager::IsPathBlocked(canonical_path)) {
        *out_reasons |= BR_PATH_IN_BLOCKED_DIR;
        return;
    }

    WhitelistTier tier = PolicyManager::IsPathInWhitelist(canonical_path);
    *out_tier = tier;

    switch (tier) {
        case WhitelistTier::Tier1: *out_score = 1.0f; break;
        case WhitelistTier::Tier2: *out_score = 1.0f; break;
        case WhitelistTier::Tier3: *out_score = 1.0f; break;
        case WhitelistTier::None:
            *out_score = 0.0f;
            *out_reasons |= BR_PATH_NOT_IN_WHITELIST;
            break;
    }
}

// ===========================================================================
// Section 4 — Layer 2: Name Heuristics
// ===========================================================================

// Compute Levenshtein distance between two wide strings (bounded by max).
// Returns min(actual_distance, max+1) for early exit performance.
static uint32_t LevenshteinW(const wchar_t* s1, size_t n1,
                              const wchar_t* s2, size_t n2,
                              uint32_t max_dist)
{
    if (n1 == 0) return static_cast<uint32_t>(n2);
    if (n2 == 0) return static_cast<uint32_t>(n1);

    // Allocate two rows on the stack — DLL names are short
    // Maximum safe stack allocation: 2 * (256+1) * 4 bytes = ~2 KB
    const size_t MAX_LEN = 257;
    if (n1 >= MAX_LEN || n2 >= MAX_LEN) return max_dist + 1;

    uint32_t prev[MAX_LEN];
    uint32_t curr[MAX_LEN];

    for (size_t j = 0; j <= n2; ++j)
        prev[j] = static_cast<uint32_t>(j);

    for (size_t i = 1; i <= n1; ++i) {
        curr[0] = static_cast<uint32_t>(i);
        uint32_t row_min = curr[0];

        for (size_t j = 1; j <= n2; ++j) {
            uint32_t cost = (towlower(s1[i-1]) == towlower(s2[j-1])) ? 0u : 1u;
            curr[j] = (std::min)({
                prev[j]   + 1u,
                curr[j-1] + 1u,
                prev[j-1] + cost
            });
            if (curr[j] < row_min) row_min = curr[j];
        }

        // Early exit: entire row exceeds max — cannot improve
        if (row_min > max_dist) return max_dist + 1;

        memcpy(prev, curr, (n2 + 1) * sizeof(uint32_t));
    }
    return prev[n2];
}

static void CheckNameHeuristics(const wchar_t* dll_name,
                                  float*         out_score,
                                  uint32_t*      out_reasons)
{
    *out_score = 1.0f;  // assume clean; deductions applied below

    const PolicyConfig& cfg = PolicyManager::GetConfig();
    size_t name_len = wcslen(dll_name);

    // ------------------------------------------------------------------
    // Check 1: Non-ASCII / homoglyph characters
    // All legitimate system DLL names use only printable ASCII [0x20–0x7E].
    // Any character outside this range is a red flag for homoglyph attacks.
    // ------------------------------------------------------------------
    if (cfg.rule_r005_enabled) {
        for (size_t i = 0; i < name_len; ++i) {
            wchar_t c = dll_name[i];
            if (c < 0x20 || c > 0x7E) {
                *out_score    = 0.0f;
                *out_reasons |= BR_NAME_HOMOGLYPH;
                return;   // definitive failure — no need to check further
            }
        }
    }

    // ------------------------------------------------------------------
    // Check 2: Double extension  (e.g. document.pdf.dll, payload.txt.dll)
    // ------------------------------------------------------------------
    {
        // Find the last dot that produces the .dll extension
        const wchar_t* last_dot = wcsrchr(dll_name, L'.');
        if (last_dot && _wcsicmp(last_dot, L".dll") == 0) {
            // Check if there's another dot before it
            size_t prefix_len = static_cast<size_t>(last_dot - dll_name);
            // Scan the prefix for a dot (after position 0 to skip drive-less names)
            for (size_t i = 0; i < prefix_len; ++i) {
                if (dll_name[i] == L'.') {
                    *out_score    = 0.0f;
                    *out_reasons |= BR_NAME_SUSPICIOUS_PATTERN;
                    return;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Check 3: Typosquatting — Levenshtein distance vs known system DLLs
    // Applies only to DLL names that are NOT exact matches (those would be
    // caught by path + hash layers if legitimate, or by R001 if imposters).
    // ------------------------------------------------------------------
    if (cfg.rule_r004_levenshtein_max > 0) {
        uint32_t max_d = cfg.rule_r004_levenshtein_max;

        // Build a lowercase version of the candidate name (without .dll)
        wchar_t candidate[MAX_DLL_NAME_LEN] = {};
        wcscpy_s(candidate, _countof(candidate), dll_name);
        // Strip .dll suffix for comparison
        wchar_t* dot = wcsrchr(candidate, L'.');
        if (dot && _wcsicmp(dot, L".dll") == 0) *dot = L'\0';
        _wcslwr_s(candidate, _countof(candidate));
        size_t cand_len = wcslen(candidate);

        // Representative set of critical system DLL base names.
        // The full list comes from known_system_dlls in the hash database;
        // this inline set covers the most commonly spoofed names and
        // acts as a fast hard-coded fallback even if the DB is not loaded.
        static const wchar_t* const CRITICAL_BASES[] = {
            L"ntdll",       L"kernel32",   L"kernelbase", L"user32",
            L"advapi32",    L"ole32",      L"oleaut32",   L"shell32",
            L"shlwapi",     L"wininet",    L"winhttp",    L"ws2_32",
            L"msvcrt",      L"wintrust",   L"crypt32",    L"bcrypt",
            L"secur32",     L"version",    L"setupapi",   L"rpcrt4",
            L"combase",     L"gdi32",      L"dbghelp",    L"imagehlp",
            L"psapi",       L"iphlpapi",   L"dnsapi",     L"netapi32",
            nullptr
        };

        for (size_t i = 0; CRITICAL_BASES[i]; ++i) {
            const wchar_t* base = CRITICAL_BASES[i];
            size_t base_len = wcslen(base);

            // Exact match → NOT typosquatting (legitimate name for this layer)
            if (_wcsicmp(candidate, base) == 0) continue;

            uint32_t dist = LevenshteinW(candidate, cand_len,
                                          base, base_len, max_d);
            if (dist <= max_d && dist > 0) {
                // Deduct proportionally: dist=1 → 0.5, dist=2 → 0.0
                float deduction = 1.0f - ((float)dist / ((float)max_d + 1.0f));
                *out_score    = (std::max)(0.0f, *out_score - deduction);
                *out_reasons |= BR_NAME_TYPOSQUATTING;
                break;   // worst-case already applied
            }
        }
    }
}

// ===========================================================================
// Section 5 — Layer 3: SHA-256 Hash
// Computed using BCrypt over the already-open file handle.
// The file pointer is seeked to position 0 before reading.
// ===========================================================================

static BOOL ComputeFileHashSHA256(HANDLE file_handle,
                                    char   out_hex[SHA256_HEX_LEN + 1])
{
    out_hex[0] = '\0';

    // Seek to beginning — handle may have been positioned by caller
    if (SetFilePointer(file_handle, 0, nullptr, FILE_BEGIN) ==
        INVALID_SET_FILE_POINTER)
    {
        if (GetLastError() != NO_ERROR) return FALSE;
    }

    // Open BCrypt SHA-256 algorithm provider
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    // Query hash object size and hash length
    DWORD hash_obj_size = 0, hash_len = 0, cb = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hash_obj_size), sizeof(DWORD), &cb, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return FALSE; }

    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hash_len), sizeof(DWORD), &cb, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return FALSE; }

    // hash_len must be 32 for SHA-256 — sanity check
    if (hash_len != HMAC_SHA256_BYTES) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Allocate hash object buffer on the heap (avoid VLAs — not standard C++)
    PUCHAR hash_obj = static_cast<PUCHAR>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hash_obj_size));
    PUCHAR hash_buf = static_cast<PUCHAR>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hash_len));

    if (!hash_obj || !hash_buf) {
        HeapFree(GetProcessHeap(), 0, hash_obj);
        HeapFree(GetProcessHeap(), 0, hash_buf);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Create hash object
    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, hash_obj, hash_obj_size,
                               nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, hash_obj);
        HeapFree(GetProcessHeap(), 0, hash_buf);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Hash file content in 64 KB chunks
    static const DWORD CHUNK = 65536;
    PUCHAR chunk_buf = static_cast<PUCHAR>(
        HeapAlloc(GetProcessHeap(), 0, CHUNK));
    if (!chunk_buf) {
        BCryptDestroyHash(hHash);
        HeapFree(GetProcessHeap(), 0, hash_obj);
        HeapFree(GetProcessHeap(), 0, hash_buf);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    BOOL io_ok = TRUE;
    DWORD bytes_read = 0;
    while (TRUE) {
        if (!ReadFile(file_handle, chunk_buf, CHUNK, &bytes_read, nullptr)) {
            io_ok = FALSE; break;
        }
        if (bytes_read == 0) break;   // EOF

        status = BCryptHashData(hHash, chunk_buf, bytes_read, 0);
        if (!BCRYPT_SUCCESS(status)) { io_ok = FALSE; break; }
    }

    HeapFree(GetProcessHeap(), 0, chunk_buf);

    if (io_ok) {
        status = BCryptFinishHash(hHash, hash_buf, hash_len, 0);
        io_ok = BCRYPT_SUCCESS(status) ? TRUE : FALSE;
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    HeapFree(GetProcessHeap(), 0, hash_obj);

    if (io_ok) {
        // Encode to lowercase hex string
        for (DWORD i = 0; i < hash_len; ++i) {
            sprintf_s(out_hex + i * 2, 3, "%02x",
                      static_cast<unsigned>(hash_buf[i]));
        }
        out_hex[hash_len * 2] = '\0';
    }

    HeapFree(GetProcessHeap(), 0, hash_buf);
    return io_ok;
}

// ===========================================================================
// Section 6 — Layer 4: Authenticode Signature (WinVerifyTrust)
// ===========================================================================

// Extract Subject and Issuer CN from the signer certificate.
// On failure the out buffers receive empty strings — non-fatal.
static void ExtractCertInfo(const wchar_t* path,
                              wchar_t* out_subject, size_t subj_cch,
                              wchar_t* out_issuer,  size_t iss_cch)
{
    out_subject[0] = L'\0';
    out_issuer[0]  = L'\0';

    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg   = nullptr;
    DWORD      enc    = 0, ct = 0, ft = 0;

    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0, &enc, &ct, &ft,
            &hStore, &hMsg, nullptr))
    {
        return;
    }

    // Get the signer info to find the cert
    DWORD si_size = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &si_size);
    if (si_size == 0) {
        CryptMsgClose(hMsg);
        CertCloseStore(hStore, 0);
        return;
    }

    PCMSG_SIGNER_INFO pSignerInfo = static_cast<PCMSG_SIGNER_INFO>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, si_size));
    if (!pSignerInfo) {
        CryptMsgClose(hMsg);
        CertCloseStore(hStore, 0);
        return;
    }

    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &si_size)) {
        CERT_INFO ci{};
        ci.Issuer       = pSignerInfo->Issuer;
        ci.SerialNumber = pSignerInfo->SerialNumber;

        PCCERT_CONTEXT pCert = CertFindCertificateInStore(
            hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, CERT_FIND_SUBJECT_CERT, &ci, nullptr);

        if (pCert) {
            CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                nullptr, out_subject,
                                static_cast<DWORD>(subj_cch));
            CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                CERT_NAME_ISSUER_FLAG, nullptr,
                                out_issuer, static_cast<DWORD>(iss_cch));
            CertFreeCertificateContext(pCert);
        }
    }

    HeapFree(GetProcessHeap(), 0, pSignerInfo);
    CryptMsgClose(hMsg);
    CertCloseStore(hStore, 0);
}

static void VerifyAuthenticode(const wchar_t* canonical_path,
                                const PolicyConfig& cfg,
                                float*    out_score,
                                BOOL*     out_present,
                                BOOL*     out_valid,
                                BOOL*     out_revoked,
                                wchar_t*  out_subject,
                                wchar_t*  out_issuer,
                                uint32_t* out_reasons)
{
    *out_score   = 0.0f;
    *out_present = FALSE;
    *out_valid   = FALSE;
    *out_revoked = FALSE;
    out_subject[0] = L'\0';
    out_issuer[0]  = L'\0';

    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct       = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath  = canonical_path;
    file_info.hFile          = nullptr;
    file_info.pgKnownSubject = nullptr;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wd{};
    wd.cbStruct            = sizeof(WINTRUST_DATA);
    wd.dwUIChoice          = WTD_UI_NONE;             // never show UI
    wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;   // check entire chain
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &file_info;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;

    // Exclude root CA from revocation check (standard practice)
    wd.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;

    if (cfg.check_revocation_ocsp) {
        // Online OCSP check — do NOT restrict to cached CRL only.
        // WinVerifyTrust will contact the OCSP/CRL endpoint.
    } else {
        // Offline only — use locally cached CRL, no network round-trip.
        wd.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
    }

    LONG result = WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &action, &wd);

    // Always close the state — required by WinVerifyTrust documentation
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &action, &wd);

    switch (result) {
        case ERROR_SUCCESS:
            // Signature is valid and the trust chain is intact
            *out_present = TRUE;
            *out_valid   = TRUE;
            *out_score   = 1.0f;
            ExtractCertInfo(canonical_path,
                             out_subject, MAX_CERT_FIELD,
                             out_issuer,  MAX_CERT_FIELD);
            break;

        case TRUST_E_NOSIGNATURE:
        case TRUST_E_SUBJECT_FORM_UNKNOWN:
        case TRUST_E_PROVIDER_UNKNOWN:
            // File is unsigned
            *out_present  = FALSE;
            *out_reasons |= BR_SIGNATURE_ABSENT;
            break;

        case CERT_E_REVOKED:
        case CRYPT_E_REVOKED:
            // Valid chain but certificate was explicitly revoked
            *out_present  = TRUE;
            *out_valid    = FALSE;
            *out_revoked  = TRUE;
            *out_reasons |= BR_SIGNATURE_REVOKED;
            ExtractCertInfo(canonical_path,
                             out_subject, MAX_CERT_FIELD,
                             out_issuer,  MAX_CERT_FIELD);
            break;

        default:
            // Signature present but verification failed
            *out_present  = TRUE;
            *out_valid    = FALSE;
            *out_reasons |= BR_SIGNATURE_INVALID;
            break;
    }
}

// ===========================================================================
// Section 7 — Aggregate Score Calculation
// ===========================================================================

static float ComputeAggregateScore(const PolicyConfig& cfg,
                                    float path_score,
                                    float name_score,
                                    float hash_score,
                                    float sig_score,
                                    WhitelistTier tier,
                                    BOOL  is_post_startup,
                                    HashLookupResult hash_lookup)
{
    float score = path_score * cfg.weight_path
                + name_score * cfg.weight_name
                + hash_score * cfg.weight_hash
                + sig_score  * cfg.weight_signature;

    // Tier 1 bonus
    if (tier == WhitelistTier::Tier1) {
        score += cfg.modifier_tier1_bonus;
    }

    // Post-startup penalty
    if (is_post_startup) {
        score += cfg.modifier_post_startup_penalty;   // negative value
    }

    // Hash unknown (not in DB, not revoked — just not registered)
    if (hash_lookup == HashLookupResult::NotFound) {
        score += cfg.modifier_hash_unknown_penalty;   // negative value
    }

    // Clamp to [0.0, 1.0]
    if (score < 0.0f) score = 0.0f;
    if (score > 1.0f) score = 1.0f;
    return score;
}

static RiskLevel ScoreToRiskLevel(float score)
{
    PolicyConfig cfg = PolicyManager::GetConfig();
    // score is a TRUST score: LOW = suspicious/risky, HIGH = trusted/safe.
    // Invert thresholds for comparison: critical when trust is critically low.
    if (score < (1.0f - cfg.threshold_block_always)) return RiskLevel::Critical;  // < 0.14
    if (score < (1.0f - cfg.threshold_block_strict))  return RiskLevel::High;     // < 0.39
    if (score < (1.0f - cfg.threshold_allow))         return RiskLevel::Medium;   // < 0.70
    return RiskLevel::Low;
}

} // anonymous namespace

// ===========================================================================
// Section 8 — Public API
// ===========================================================================

BOOL InitializeValidator(const wchar_t* hash_db_path)
{
    if (hash_db_path && *hash_db_path) {
        return LoadHashDatabase(hash_db_path);
    }
    // No path provided — start with empty DB, non-fatal
    AcquireSRWLockExclusive(&s_db_lock);
    s_hash_db.loaded = true;
    ReleaseSRWLockExclusive(&s_db_lock);
    return FALSE;
}

// ---------------------------------------------------------------------------
// ValidateDLL — the main orchestrator.
// ---------------------------------------------------------------------------
BOOL ValidateDLL(HANDLE            file_handle,
                 const wchar_t*    canonical_path,
                 BOOL              is_post_startup,
                 ValidationResult* out_result)
{
    if (!file_handle || file_handle == INVALID_HANDLE_VALUE ||
        !canonical_path || !out_result)
    {
        return FALSE;
    }

    SecureZeroMemory(out_result, sizeof(ValidationResult));

    const PolicyConfig& cfg = PolicyManager::GetConfig();

    // ------------------------------------------------------------------
    // Cache check — only on the final resolved path + current mtime
    // ------------------------------------------------------------------
    if (cfg.cache_enabled) {
        if (CacheLookup(canonical_path, file_handle, out_result)) {
            // Cache hit — return the stored result directly
            return TRUE;
        }
    }

    uint32_t reasons = BR_NONE;

    // ------------------------------------------------------------------
    // Layer 1: Path Whitelist
    // ------------------------------------------------------------------
    float         path_score = 0.0f;
    WhitelistTier tier       = WhitelistTier::None;
    CheckPathWhitelist(canonical_path, &path_score, &tier, &reasons);

    // Short-circuit: if path is in a blocked directory, no need to continue.
    if (reasons & BR_PATH_IN_BLOCKED_DIR) {
        reasons |= BR_SCORE_TOO_LOW;

        out_result->path_score       = 0.0f;
        out_result->name_score       = 0.0f;
        out_result->hash_score       = 0.0f;
        out_result->signature_score  = 0.0f;
        out_result->aggregate_score  = 0.0f;
        out_result->risk_level       = RiskLevel::Critical;
        out_result->block_reasons    = reasons;
        out_result->whitelist_tier   = WhitelistTier::None;

        wcscpy_s(out_result->failure_reason, _countof(out_result->failure_reason),
                 L"PATH_IN_BLOCKED_DIR");
        return TRUE;
    }

    // ------------------------------------------------------------------
    // Layer 2: Name Heuristics
    // ------------------------------------------------------------------
    float name_score = 1.0f;

    // Extract just the filename from canonical path for name checks
    const wchar_t* dll_name = PathFindFileNameW(canonical_path);
    if (!dll_name || dll_name[0] == L'\0') dll_name = canonical_path;

    CheckNameHeuristics(dll_name, &name_score, &reasons);

    // ------------------------------------------------------------------
    // Layer 3: SHA-256 Hash
    // ------------------------------------------------------------------
    float          hash_score   = 0.0f;
    HashLookupResult hash_result = HashLookupResult::DbError;
    char sha256_hex[SHA256_HEX_LEN + 1] = {};

    if (!ComputeFileHashSHA256(file_handle, sha256_hex)) {
        // I/O error during hash computation — treat as critical
        reasons |= BR_HASH_COMPUTE_FAILURE;
        // Do NOT short-circuit; continue to record partial result
    } else {
        hash_result = QueryHashDatabase(sha256_hex);

        switch (hash_result) {
            case HashLookupResult::Found:
                hash_score = 1.0f;
                break;
            case HashLookupResult::Revoked:
                hash_score = 0.0f;
                reasons   |= BR_HASH_REVOKED;
                break;
            case HashLookupResult::NotFound:
                hash_score = 0.0f;
                reasons   |= BR_HASH_NOT_FOUND;
                break;
            case HashLookupResult::DbError:
                hash_score = 0.0f;
                reasons   |= BR_HASH_COMPUTE_FAILURE;
                break;
        }

        // Copy SHA-256 hex into result (wide string)
        MultiByteToWideChar(CP_ACP, 0, sha256_hex, -1,
                             out_result->sha256_hex,
                             static_cast<int>(_countof(out_result->sha256_hex)));
    }

    out_result->hash_lookup = hash_result;

    // ------------------------------------------------------------------
    // Layer 4: Authenticode Signature
    // Skip if hash is revoked — revoked signature compounds the block.
    // Tier 1 paths: still verify but non-fatal for missing sig.
    // ------------------------------------------------------------------
    float sig_score  = 0.0f;
    BOOL  sig_present = FALSE, sig_valid = FALSE, sig_revoked_cert = FALSE;

    VerifyAuthenticode(canonical_path, cfg,
                        &sig_score, &sig_present, &sig_valid, &sig_revoked_cert,
                        out_result->cert_subject, out_result->cert_issuer,
                        &reasons);

    out_result->signature_present = sig_present;
    out_result->signature_valid   = sig_valid;
    out_result->signature_revoked = sig_revoked_cert;

    // Tier 1 policy: signature absence is not fatal (System32 DLLs in
    // development builds may lack counter-signatures, but they are in Tier 1
    // and their hash is registered). Allow with reduced score.
    if (tier == WhitelistTier::Tier1 && !sig_present) {
        sig_score = 0.5f;  // partial credit — path + hash coverage is strong
        reasons &= ~BR_SIGNATURE_ABSENT;  // clear the flag for Tier 1
    }

    // ------------------------------------------------------------------
    // Apply Rule R001: known system DLL name outside System32
    // ------------------------------------------------------------------
    if (cfg.rule_r001_enabled) {
        wchar_t name_lower[MAX_DLL_NAME_LEN] = {};
        wcscpy_s(name_lower, _countof(name_lower), dll_name);
        _wcslwr_s(name_lower, _countof(name_lower));

        bool is_sys_dll = IsKnownSystemDll(name_lower);
        bool in_tier1   = (tier == WhitelistTier::Tier1);

        if (is_sys_dll && !in_tier1) {
            // System DLL name found outside System32/SysWOW64/WinSxS
            reasons    |= BR_RULE_SYSTEM_DLL_OUTSIDE;
            name_score  = 0.0f;   // override name score — definitive risk
        }
    }

    // ------------------------------------------------------------------
    // Apply Rule R003: DLL from temp directory (already caught by blocked
    // paths, but apply here as well for belt-and-suspenders)
    // ------------------------------------------------------------------
    if (cfg.rule_r003_enabled && (reasons & BR_PATH_IN_BLOCKED_DIR)) {
        reasons |= BR_RULE_TEMP_DIRECTORY;
    }

    // ------------------------------------------------------------------
    // Compute aggregate score
    // ------------------------------------------------------------------
    float agg = ComputeAggregateScore(cfg,
                                       path_score, name_score,
                                       hash_score, sig_score,
                                       tier, is_post_startup, hash_result);

    // ------------------------------------------------------------------
    // Populate output
    // ------------------------------------------------------------------
    out_result->path_score      = path_score;
    out_result->name_score      = name_score;
    out_result->hash_score      = hash_score;
    out_result->signature_score = sig_score;
    out_result->aggregate_score = agg;
    out_result->risk_level      = ScoreToRiskLevel(agg);
    out_result->block_reasons   = reasons;
    out_result->whitelist_tier  = tier;

    if (reasons != BR_NONE) {
        // Populate human-readable failure summary (first dominant reason)
        const wchar_t* summary = L"VALIDATION_FAILED";
        if (reasons & BR_HASH_REVOKED)              summary = L"HASH_REVOKED";
        else if (reasons & BR_SIGNATURE_REVOKED)    summary = L"CERT_REVOKED";
        else if (reasons & BR_RULE_SYSTEM_DLL_OUTSIDE) summary = L"SYSTEM_DLL_OUTSIDE_SYSTEM32";
        else if (reasons & BR_NAME_HOMOGLYPH)       summary = L"HOMOGLYPH_DETECTED";
        else if (reasons & BR_NAME_TYPOSQUATTING)   summary = L"TYPOSQUATTING_DETECTED";
        else if (reasons & BR_PATH_NOT_IN_WHITELIST) summary = L"PATH_NOT_IN_WHITELIST";
        else if (reasons & BR_HASH_NOT_FOUND)       summary = L"HASH_UNKNOWN";
        else if (reasons & BR_SIGNATURE_ABSENT)     summary = L"UNSIGNED_DLL";
        else if (reasons & BR_SIGNATURE_INVALID)    summary = L"SIGNATURE_INVALID";

        wcscpy_s(out_result->failure_reason,
                 _countof(out_result->failure_reason), summary);
    }

    // ------------------------------------------------------------------
    // Store in cache (only if we have a clean, complete result)
    // ------------------------------------------------------------------
    if (cfg.cache_enabled && !(reasons & BR_HASH_COMPUTE_FAILURE)) {
        CacheInsert(canonical_path, file_handle, *out_result);
    }

    return TRUE;
}

// ---------------------------------------------------------------------------
// InvalidateValidationCache
// ---------------------------------------------------------------------------
void InvalidateValidationCache(const wchar_t* canonical_path)
{
    if (!canonical_path) return;

    AcquireSRWLockExclusive(&s_cache_lock);
    for (auto it = s_cache.begin(); it != s_cache.end(); ) {
        if (_wcsicmp(it->first.path.c_str(), canonical_path) == 0) {
            it = s_cache.erase(it);
        } else {
            ++it;
        }
    }
    ReleaseSRWLockExclusive(&s_cache_lock);
}

// ---------------------------------------------------------------------------
// GetValidationCacheStats
// ---------------------------------------------------------------------------
void GetValidationCacheStats(size_t* out_hits, size_t* out_misses)
{
    AcquireSRWLockShared(&s_cache_lock);
    if (out_hits)   *out_hits   = s_cache_hits;
    if (out_misses) *out_misses = s_cache_misses;
    ReleaseSRWLockShared(&s_cache_lock);
}

} // namespace dhd
