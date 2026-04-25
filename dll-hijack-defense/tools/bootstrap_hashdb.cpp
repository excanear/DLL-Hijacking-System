// =============================================================================
// tools/bootstrap_hashdb.cpp
// Standalone bootstrap tool: computes SHA-256 hashes for all DLL entries in
// hash_database.json that have an empty "sha256" field, then writes a final
// db_integrity_hash over the canonical JSON body.
//
// Run this tool once after building the project on a trusted reference machine
// (the hashes produced are machine-specific to the Windows version installed).
//
// Usage:
//   bootstrap_hashdb.exe [<path_to_hash_database.json>]
//
//   Default path: config\hash_database.json (relative to CWD)
//
// Exit codes:
//   0 — success (all entries hashed)
//   1 — one or more DLLs not found (partial update, skipped DLLs noted)
//   2 — fatal I/O or parse error
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include <shlobj.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")

#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <algorithm>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static constexpr size_t SHA256_HEX_LEN  = 64;
static constexpr size_t HASH_CHUNK_SIZE = 65536;   // 64 KB I/O buffer

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------
struct DbEntry {
    std::string dll_name;       // e.g. "ntdll.dll"
    std::string friendly_name;
    std::string version;
    std::string trusted_path;
    std::string sha256;         // filled by bootstrap
    int         tier;
    std::string approved_by;
    std::string approved_date;
    std::string notes;
};

struct HashDb {
    int                      schema_version   = 1;
    std::string              description;
    std::string              created_at;
    std::string              db_integrity_hash;
    std::vector<DbEntry>     entries;
    std::vector<std::string> known_system_dlls;
    std::vector<std::string> revoked_hashes;   // raw sha256 strings
};

// ===========================================================================
// Section 1 — File I/O helpers
// ===========================================================================

static bool ReadWholeFile(const wchar_t* path, std::string& out)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart > 16 * 1024 * 1024) {
        CloseHandle(h);
        return false;   // sanity: refuse files >16 MB
    }

    out.resize(static_cast<size_t>(sz.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()),
                        &read, nullptr);
    CloseHandle(h);
    return ok && read == static_cast<DWORD>(out.size());
}

static bool WriteWholeFile(const wchar_t* path, const std::string& content)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    BOOL ok = WriteFile(h, content.c_str(),
                         static_cast<DWORD>(content.size()),
                         &written, nullptr);
    FlushFileBuffers(h);
    CloseHandle(h);
    return ok && written == static_cast<DWORD>(content.size());
}

// ===========================================================================
// Section 2 — Minimal JSON parser
// Handles the known schema of hash_database.json; not a general-purpose parser.
// ===========================================================================

static std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
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

// ---------------------------------------------------------------------------
// Advance past whitespace
// ---------------------------------------------------------------------------
static size_t SkipWs(const std::string& s, size_t pos)
{
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' ||
                               s[pos] == '\r' || s[pos] == '\n'))
        ++pos;
    return pos;
}

// ---------------------------------------------------------------------------
// Extract a JSON string value starting at the opening '"'.
// Advances |pos| past the closing '"'.
// ---------------------------------------------------------------------------
static std::string ParseString(const std::string& s, size_t& pos)
{
    if (pos >= s.size() || s[pos] != '"') return {};
    ++pos; // skip opening '"'
    std::string result;
    while (pos < s.size()) {
        if (s[pos] == '\\' && pos + 1 < s.size()) {
            switch (s[++pos]) {
                case '"':  result += '"';  ++pos; break;
                case '\\': result += '\\'; ++pos; break;
                case '/':  result += '/';  ++pos; break;
                case 'n':  result += '\n'; ++pos; break;
                case 'r':  result += '\r'; ++pos; break;
                case 't':  result += '\t'; ++pos; break;
                default:   result += s[pos]; ++pos; break;
            }
        } else if (s[pos] == '"') {
            ++pos; // skip closing '"'
            return result;
        } else {
            result += s[pos++];
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Parse a JSON integer (digits only, no sign for our schema).
// Advances |pos| past the integer.
// ---------------------------------------------------------------------------
static int ParseInt(const std::string& s, size_t& pos)
{
    int val = 0;
    while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9')
        val = val * 10 + (s[pos++] - '0');
    return val;
}

// ---------------------------------------------------------------------------
// Find the position of the first occurrence of |key| (as a JSON key) in |s|
// starting at |from|. Returns the position of the ':' character, or npos.
// ---------------------------------------------------------------------------
static size_t FindKey(const std::string& s, size_t from, const char* key)
{
    std::string needle = "\"";
    needle += key;
    needle += '"';
    size_t p = s.find(needle, from);
    if (p == std::string::npos) return std::string::npos;
    p += needle.size();
    p = SkipWs(s, p);
    if (p >= s.size() || s[p] != ':') return std::string::npos;
    return p; // points at ':'
}

// ---------------------------------------------------------------------------
// Extract the string value of a top-level key.
// ---------------------------------------------------------------------------
static std::string ExtractTopLevelString(const std::string& json, const char* key)
{
    size_t p = FindKey(json, 0, key);
    if (p == std::string::npos) return {};
    ++p; // skip ':'
    p = SkipWs(json, p);
    return ParseString(json, p);
}

// ---------------------------------------------------------------------------
// Extract an integer value of a top-level key.
// ---------------------------------------------------------------------------
static int ExtractTopLevelInt(const std::string& json, const char* key)
{
    size_t p = FindKey(json, 0, key);
    if (p == std::string::npos) return 0;
    ++p;
    p = SkipWs(json, p);
    return ParseInt(json, p);
}

// ---------------------------------------------------------------------------
// Parse the "entries" array.
// ---------------------------------------------------------------------------
static std::vector<DbEntry> ParseEntries(const std::string& json)
{
    std::vector<DbEntry> entries;

    size_t arr_start = json.find("\"entries\"");
    if (arr_start == std::string::npos) return entries;
    arr_start = json.find('[', arr_start);
    if (arr_start == std::string::npos) return entries;
    ++arr_start;

    // Walk until the closing ']'
    size_t pos = arr_start;
    while (pos < json.size()) {
        pos = SkipWs(json, pos);
        if (pos >= json.size()) break;
        if (json[pos] == ']') break;
        if (json[pos] == ',') { ++pos; continue; }
        if (json[pos] != '{') { ++pos; continue; }

        // Parse one entry object
        DbEntry entry;
        size_t obj_end = json.find('}', pos);
        if (obj_end == std::string::npos) break;
        std::string obj_str = json.substr(pos, obj_end - pos + 1);

        // Extract each field from the object substring
        size_t local_p;
        auto FieldStr = [&](const char* k) -> std::string {
            size_t kp = FindKey(obj_str, 0, k);
            if (kp == std::string::npos) return {};
            ++kp; local_p = SkipWs(obj_str, kp);
            return ParseString(obj_str, local_p);
        };
        auto FieldInt = [&](const char* k) -> int {
            size_t kp = FindKey(obj_str, 0, k);
            if (kp == std::string::npos) return 0;
            ++kp; local_p = SkipWs(obj_str, kp);
            return ParseInt(obj_str, local_p);
        };

        entry.dll_name      = FieldStr("dll_name");
        entry.friendly_name = FieldStr("friendly_name");
        entry.version       = FieldStr("version");
        entry.trusted_path  = FieldStr("trusted_path");
        entry.sha256        = FieldStr("sha256");
        entry.tier          = FieldInt("tier");
        entry.approved_by   = FieldStr("approved_by");
        entry.approved_date = FieldStr("approved_date");
        entry.notes         = FieldStr("notes");

        if (!entry.dll_name.empty()) {
            entries.push_back(std::move(entry));
        }

        pos = obj_end + 1;
    }
    return entries;
}

// ---------------------------------------------------------------------------
// Parse a simple string array (e.g. "known_system_dlls", "revoked").
// ---------------------------------------------------------------------------
static std::vector<std::string> ParseStringArray(const std::string& json,
                                                   const char*        key)
{
    std::vector<std::string> result;
    std::string needle = "\"";
    needle += key;
    needle += '"';
    size_t arr_start = json.find(needle);
    if (arr_start == std::string::npos) return result;
    arr_start = json.find('[', arr_start);
    if (arr_start == std::string::npos) return result;
    ++arr_start;

    size_t pos = arr_start;
    while (pos < json.size()) {
        pos = SkipWs(json, pos);
        if (pos >= json.size()) break;
        if (json[pos] == ']') break;
        if (json[pos] == ',') { ++pos; continue; }
        if (json[pos] == '"') {
            std::string val = ParseString(json, pos);
            if (!val.empty()) result.push_back(std::move(val));
        } else {
            ++pos;
        }
    }
    return result;
}

// ===========================================================================
// Section 3 — SHA-256 computation (BCrypt)
// ===========================================================================

static bool BytesToHex(const BYTE* data, size_t len, char* out_hex, size_t hex_cap)
{
    if (hex_cap < len * 2 + 1) return false;
    static const char HEX[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out_hex[i * 2]     = HEX[data[i] >> 4];
        out_hex[i * 2 + 1] = HEX[data[i] & 0x0F];
    }
    out_hex[len * 2] = '\0';
    return true;
}

// ---------------------------------------------------------------------------
// ComputeSHA256Bytes — hash raw bytes, return 64-char lowercase hex string.
// ---------------------------------------------------------------------------
static bool ComputeSHA256Bytes(const BYTE* data, size_t len, std::string& out_hex)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                     nullptr, 0) != 0)
        return false;

    DWORD hash_obj_size = 0, cb_result = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                       reinterpret_cast<PUCHAR>(&hash_obj_size),
                       sizeof(hash_obj_size), &cb_result, 0);

    DWORD hash_size = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                       reinterpret_cast<PUCHAR>(&hash_size),
                       sizeof(hash_size), &cb_result, 0);

    std::vector<BYTE> hash_obj(hash_obj_size);
    std::vector<BYTE> hash_buf(hash_size);

    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;

    if (BCryptCreateHash(hAlg, &hHash, hash_obj.data(), hash_obj_size,
                          nullptr, 0, 0) == 0)
    {
        if (BCryptHashData(hHash,
                            const_cast<PUCHAR>(data),
                            static_cast<ULONG>(len), 0) == 0 &&
            BCryptFinishHash(hHash, hash_buf.data(), hash_size, 0) == 0)
        {
            char hex[SHA256_HEX_LEN + 1];
            if (BytesToHex(hash_buf.data(), hash_size, hex, sizeof(hex))) {
                out_hex = hex;
                ok = true;
            }
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// ---------------------------------------------------------------------------
// ComputeSHA256File — open path and hash in HASH_CHUNK_SIZE chunks.
// ---------------------------------------------------------------------------
static bool ComputeSHA256File(const wchar_t* path, std::string& out_hex)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                     nullptr, 0) != 0) {
        CloseHandle(h);
        return false;
    }

    DWORD hash_obj_size = 0, hash_size = 0, cb_result = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                       reinterpret_cast<PUCHAR>(&hash_obj_size),
                       sizeof(hash_obj_size), &cb_result, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                       reinterpret_cast<PUCHAR>(&hash_size),
                       sizeof(hash_size), &cb_result, 0);

    std::vector<BYTE> hash_obj(hash_obj_size);
    std::vector<BYTE> hash_buf(hash_size);
    std::vector<BYTE> io_buf(HASH_CHUNK_SIZE);

    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;

    if (BCryptCreateHash(hAlg, &hHash, hash_obj.data(), hash_obj_size,
                          nullptr, 0, 0) == 0)
    {
        DWORD bytes_read = 0;
        bool io_ok = true;
        while (ReadFile(h, io_buf.data(), static_cast<DWORD>(io_buf.size()),
                         &bytes_read, nullptr) && bytes_read > 0)
        {
            if (BCryptHashData(hHash, io_buf.data(), bytes_read, 0) != 0) {
                io_ok = false;
                break;
            }
        }

        if (io_ok &&
            BCryptFinishHash(hHash, hash_buf.data(), hash_size, 0) == 0)
        {
            char hex[SHA256_HEX_LEN + 1];
            if (BytesToHex(hash_buf.data(), hash_size, hex, sizeof(hex))) {
                out_hex = hex;
                ok = true;
            }
        }
        BCryptDestroyHash(hHash);
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(h);
    return ok;
}

// ===========================================================================
// Section 4 — DLL Locator
// Searches the trusted_path, then System32, then SysWOW64.
// ===========================================================================

static bool FindDllPath(const DbEntry& entry, std::wstring& out_path)
{
    // 1. Use the trusted_path stored in the entry (most precise)
    if (!entry.trusted_path.empty()) {
        wchar_t wide[MAX_PATH] = {};
        MultiByteToWideChar(CP_UTF8, 0, entry.trusted_path.c_str(), -1,
                             wide, MAX_PATH);
        if (PathFileExistsW(wide)) {
            out_path = wide;
            return true;
        }
    }

    // 2. System32
    {
        wchar_t sys32[MAX_PATH] = {};
        GetSystemDirectoryW(sys32, MAX_PATH);
        wchar_t wide_name[MAX_PATH] = {};
        MultiByteToWideChar(CP_UTF8, 0, entry.dll_name.c_str(), -1,
                             wide_name, MAX_PATH);
        wchar_t candidate[MAX_PATH] = {};
        wcscpy_s(candidate, _countof(candidate), sys32);
        PathAppendW(candidate, wide_name);
        if (PathFileExistsW(candidate)) {
            out_path = candidate;
            return true;
        }
    }

    // 3. SysWOW64 (32-bit DLLs on 64-bit systems)
    {
        wchar_t syswow[MAX_PATH] = {};
        GetWindowsDirectoryW(syswow, MAX_PATH);
        PathAppendW(syswow, L"SysWOW64");
        wchar_t wide_name[MAX_PATH] = {};
        MultiByteToWideChar(CP_UTF8, 0, entry.dll_name.c_str(), -1,
                             wide_name, MAX_PATH);
        wchar_t candidate[MAX_PATH] = {};
        wcscpy_s(candidate, _countof(candidate), syswow);
        PathAppendW(candidate, wide_name);
        if (PathFileExistsW(candidate)) {
            out_path = candidate;
            return true;
        }
    }

    return false;
}

// ===========================================================================
// Section 5 — JSON Reconstruction
// Builds the full hash_database.json content from the parsed + updated data.
// Pass an empty string for |integrity_hash| on the first pass (to compute it),
// then pass the computed hash on the second pass for the final file.
// ===========================================================================

static std::string IsoTimestamp()
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buf[32];
    sprintf_s(buf, "%04u-%02u-%02uT%02u:%02u:%02uZ",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::string RebuildJson(const HashDb& db, const std::string& integrity_hash)
{
    std::string j;
    j.reserve(8192);

    auto qs = [](const std::string& s) -> std::string {
        return "\"" + JsonEscape(s) + "\"";
    };

    j += "{\n";
    j += "  \"schema_version\": ";
    j += std::to_string(db.schema_version);
    j += ",\n";
    j += "  \"description\": " + qs(db.description) + ",\n";
    j += "  \"created_at\": " + qs(db.created_at) + ",\n";
    j += "  \"last_updated\": " + qs(IsoTimestamp()) + ",\n";
    j += "  \"db_integrity_hash\": " + qs(integrity_hash) + ",\n";
    j += "\n";
    j += "  \"entries\": [\n";

    for (size_t i = 0; i < db.entries.size(); ++i) {
        const DbEntry& e = db.entries[i];
        const bool last = (i + 1 == db.entries.size());

        j += "    {\n";
        j += "      \"sha256\": "        + qs(e.sha256)        + ",\n";
        j += "      \"dll_name\": "      + qs(e.dll_name)      + ",\n";
        j += "      \"friendly_name\": " + qs(e.friendly_name) + ",\n";
        j += "      \"version\": "       + qs(e.version)       + ",\n";
        j += "      \"trusted_path\": "  + qs(e.trusted_path)  + ",\n";
        j += "      \"tier\": "          + std::to_string(e.tier) + ",\n";
        j += "      \"approved_by\": "   + qs(e.approved_by)   + ",\n";
        j += "      \"approved_date\": " + qs(e.approved_date) + ",\n";
        j += "      \"notes\": "         + qs(e.notes)         + "\n";
        j += last ? "    }\n" : "    },\n";
    }

    j += "  ],\n";
    j += "\n";
    j += "  \"revoked\": [";

    for (size_t i = 0; i < db.revoked_hashes.size(); ++i) {
        j += (i == 0 ? "\n    " : ",\n    ");
        j += "\"" + db.revoked_hashes[i] + "\"";
    }
    if (!db.revoked_hashes.empty()) j += "\n  ";
    j += "],\n";

    j += "\n";
    j += "  \"known_system_dlls\": [\n";
    for (size_t i = 0; i < db.known_system_dlls.size(); ++i) {
        const bool last = (i + 1 == db.known_system_dlls.size());
        j += "    " + qs(db.known_system_dlls[i]);
        j += last ? "\n" : ",\n";
    }
    j += "  ]\n";
    j += "}\n";

    return j;
}

// ===========================================================================
// Section 6 — Entry Point
// ===========================================================================

int wmain(int argc, wchar_t* argv[])
{
    wprintf(L"[*] DLL Hijacking Defense — Hash Database Bootstrap\n");
    wprintf(L"[*] Build: " __DATE__ "\n\n");

    // Determine the path to hash_database.json
    wchar_t db_path[MAX_PATH] = {};
    if (argc >= 2) {
        wcscpy_s(db_path, _countof(db_path), argv[1]);
    } else {
        // Default: config\hash_database.json relative to CWD
        GetCurrentDirectoryW(MAX_PATH, db_path);
        PathAppendW(db_path, L"config\\hash_database.json");
    }

    wprintf(L"[*] Database path: %ls\n\n", db_path);

    if (!PathFileExistsW(db_path)) {
        wprintf(L"[ERROR] File not found: %ls\n", db_path);
        return 2;
    }

    // --- Read & parse ---
    std::string raw_json;
    if (!ReadWholeFile(db_path, raw_json)) {
        wprintf(L"[ERROR] Failed to read %ls\n", db_path);
        return 2;
    }

    HashDb db;
    db.schema_version    = ExtractTopLevelInt(raw_json, "schema_version");
    db.description       = ExtractTopLevelString(raw_json, "description");
    db.created_at        = ExtractTopLevelString(raw_json, "created_at");
    db.entries           = ParseEntries(raw_json);
    db.known_system_dlls = ParseStringArray(raw_json, "known_system_dlls");
    db.revoked_hashes    = ParseStringArray(raw_json, "revoked");

    if (db.entries.empty()) {
        wprintf(L"[ERROR] No entries found in database. Check file format.\n");
        return 2;
    }

    wprintf(L"[*] Parsed %u entries, %u known_system_dlls, %u revoked hashes.\n\n",
            static_cast<uint32_t>(db.entries.size()),
            static_cast<uint32_t>(db.known_system_dlls.size()),
            static_cast<uint32_t>(db.revoked_hashes.size()));

    // --- Hash each entry ---
    int skipped = 0;
    for (DbEntry& entry : db.entries) {
        wchar_t wide_name[MAX_PATH] = {};
        MultiByteToWideChar(CP_UTF8, 0, entry.dll_name.c_str(), -1,
                             wide_name, MAX_PATH);
        wprintf(L"  [~] %ls ... ", wide_name);

        std::wstring dll_path;
        if (!FindDllPath(entry, dll_path)) {
            wprintf(L"NOT FOUND (skipped)\n");
            ++skipped;
            continue;
        }

        // Compute SHA-256 even if we already have a hash (--force behaviour)
        std::string new_hash;
        if (!ComputeSHA256File(dll_path.c_str(), new_hash)) {
            wprintf(L"HASH ERROR (skipped)\n");
            ++skipped;
            continue;
        }

        if (entry.sha256 == new_hash) {
            wprintf(L"unchanged  [%hs...]\n", new_hash.substr(0, 16).c_str());
        } else {
            if (!entry.sha256.empty()) {
                wprintf(L"UPDATED  (was %hs...)\n",
                        entry.sha256.substr(0, 16).c_str());
            } else {
                wprintf(L"ok  [%hs...]\n", new_hash.substr(0, 16).c_str());
            }
            entry.sha256 = new_hash;
        }

        // Update trusted_path with the canonical path used
        wchar_t final_path[MAX_PATH] = {};
        DWORD fp_len = GetFinalPathNameByHandleW(
            CreateFileW(dll_path.c_str(), 0,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS, nullptr),
            final_path, MAX_PATH, VOLUME_NAME_DOS);
        if (fp_len > 0 && fp_len < MAX_PATH) {
            // Strip \\?\ prefix if present
            const wchar_t* p = final_path;
            if (wcsncmp(p, L"\\\\?\\", 4) == 0) p += 4;
            char narrow[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, p, -1, narrow, MAX_PATH,
                                 nullptr, nullptr);
            entry.trusted_path = narrow;
        }
    }

    wprintf(L"\n");

    // --- Rebuild JSON (with empty integrity hash) ---
    std::string canonical = RebuildJson(db, "");

    // --- Compute integrity hash over the canonical content ---
    std::string integrity_hash;
    if (!ComputeSHA256Bytes(
            reinterpret_cast<const BYTE*>(canonical.c_str()),
            canonical.size(),
            integrity_hash))
    {
        wprintf(L"[ERROR] Failed to compute integrity hash.\n");
        return 2;
    }

    // --- Rebuild JSON again, this time with the integrity hash ---
    std::string final_json = RebuildJson(db, integrity_hash);

    // --- Write to disk ---
    if (!WriteWholeFile(db_path, final_json)) {
        wprintf(L"[ERROR] Failed to write updated database to %ls\n", db_path);
        return 2;
    }

    // --- Summary ---
    wprintf(L"[+] Database updated successfully.\n");
    wprintf(L"    Entries hashed   : %u\n",
            static_cast<uint32_t>(db.entries.size()) - static_cast<uint32_t>(skipped));
    wprintf(L"    Skipped (missing): %u\n", static_cast<uint32_t>(skipped));
    wprintf(L"    Integrity hash   : %hs...%hs\n",
            integrity_hash.substr(0, 8).c_str(),
            integrity_hash.substr(56, 8).c_str());
    wprintf(L"    Output           : %ls\n", db_path);

    return skipped > 0 ? 1 : 0;
}
