// =============================================================================
// shared/policy.cpp
// Implementation of PolicyManager — loads policy/defaults.json, exposes
// thread-safe query interface to all modules.
//
// JSON parsing is done with a minimal hand-written parser to avoid external
// dependencies at this layer. nlohmann/json will be introduced in the
// intelligence module (BLOCO 6) for full log serialization.
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#include "policy.h"
#include "constants.h"
#include "types.h"

#include <cstdio>
#include <cstring>
#include <cwctype>
#include <string>
#include <vector>
#include <algorithm>

namespace dhd {

// ---------------------------------------------------------------------------
// Static member definitions
// ---------------------------------------------------------------------------
PolicyConfig PolicyManager::s_config    = {};
BOOL         PolicyManager::s_initialized = FALSE;
SRWLOCK      PolicyManager::s_lock      = SRWLOCK_INIT;

// ===========================================================================
// Internal — minimal JSON helpers
// These parse only the specific fields we need from defaults.json.
// A proper JSON library (nlohmann) is added in BLOCO 6 for the Logging Engine.
// ===========================================================================
namespace {

// Read entire file into a std::string. Returns empty string on failure.
std::string ReadFileToString(const wchar_t* path)
{
    HANDLE hFile = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        return {};
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(hFile, &size) || size.QuadPart == 0 ||
        size.QuadPart > 4 * 1024 * 1024) // 4 MB sanity cap
    {
        CloseHandle(hFile);
        return {};
    }

    std::string buf(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    BOOL  ok   = ReadFile(hFile, buf.data(), static_cast<DWORD>(buf.size()),
                          &read, nullptr);
    CloseHandle(hFile);

    if (!ok || read != static_cast<DWORD>(buf.size())) {
        return {};
    }
    return buf;
}

// Case-insensitive ASCII string search (needle in haystack).
const char* IStrStr(const char* haystack, const char* needle)
{
    if (!haystack || !needle) return nullptr;
    size_t n = strlen(needle);
    for (; *haystack; ++haystack) {
        if (_strnicmp(haystack, needle, n) == 0) {
            return haystack;
        }
    }
    return nullptr;
}

// Extract a string value after "key": "value" pattern. Returns "" on miss.
std::string ExtractStringValue(const std::string& json, const char* key)
{
    std::string search = std::string("\"") + key + "\"";
    const char* pos = IStrStr(json.c_str(), search.c_str());
    if (!pos) return {};

    pos = strchr(pos + search.size(), ':');
    if (!pos) return {};

    while (*pos && (*pos == ':' || *pos == ' ' || *pos == '\t')) ++pos;
    if (*pos != '"') return {};
    ++pos;

    const char* end = strchr(pos, '"');
    if (!end) return {};

    return std::string(pos, end);
}

// Extract a float value after "key": <float>.
float ExtractFloatValue(const std::string& json, const char* key, float def)
{
    std::string search = std::string("\"") + key + "\"";
    const char* pos = IStrStr(json.c_str(), search.c_str());
    if (!pos) return def;

    pos = strchr(pos + search.size(), ':');
    if (!pos) return def;

    while (*pos && (*pos == ':' || *pos == ' ' || *pos == '\t')) ++pos;
    char* endptr = nullptr;
    float v = std::strtof(pos, &endptr);
    return (endptr != pos) ? v : def;
}

// Extract a uint32 value after "key": <uint>.
uint32_t ExtractUintValue(const std::string& json, const char* key,
                          uint32_t def)
{
    std::string search = std::string("\"") + key + "\"";
    const char* pos = IStrStr(json.c_str(), search.c_str());
    if (!pos) return def;

    pos = strchr(pos + search.size(), ':');
    if (!pos) return def;

    while (*pos && (*pos == ':' || *pos == ' ' || *pos == '\t')) ++pos;
    char* endptr = nullptr;
    unsigned long v = std::strtoul(pos, &endptr, 10);
    return (endptr != pos) ? static_cast<uint32_t>(v) : def;
}

// Extract a bool value after "key": true|false.
bool ExtractBoolValue(const std::string& json, const char* key, bool def)
{
    std::string search = std::string("\"") + key + "\"";
    const char* pos = IStrStr(json.c_str(), search.c_str());
    if (!pos) return def;

    pos = strchr(pos + search.size(), ':');
    if (!pos) return def;

    while (*pos && (*pos == ':' || *pos == ' ' || *pos == '\t')) ++pos;

    if (_strnicmp(pos, "true", 4) == 0)  return true;
    if (_strnicmp(pos, "false", 5) == 0) return false;
    return def;
}

// Extract a JSON array of strings after "key": ["v1","v2",...].
// Returns list of wstring (UTF-8 -> wide conversion).
std::vector<std::wstring> ExtractStringArray(const std::string& json,
                                             const char* key)
{
    std::vector<std::wstring> result;

    std::string search = std::string("\"") + key + "\"";
    const char* pos = IStrStr(json.c_str(), search.c_str());
    if (!pos) return result;

    pos = strchr(pos + search.size(), '[');
    if (!pos) return result;
    ++pos;

    const char* end_bracket = strchr(pos, ']');
    if (!end_bracket) return result;

    while (pos < end_bracket) {
        const char* q1 = strchr(pos, '"');
        if (!q1 || q1 >= end_bracket) break;
        const char* q2 = strchr(q1 + 1, '"');
        if (!q2 || q2 >= end_bracket) break;

        std::string entry(q1 + 1, q2);
        // Convert UTF-8 to wide string
        int wlen = MultiByteToWideChar(CP_UTF8, 0,
                                       entry.c_str(), -1,
                                       nullptr, 0);
        if (wlen > 1) {
            std::wstring wentry(static_cast<size_t>(wlen - 1), L'\0');
            MultiByteToWideChar(CP_UTF8, 0,
                                entry.c_str(), -1,
                                wentry.data(), wlen);
            result.push_back(std::move(wentry));
        }
        pos = q2 + 1;
    }
    return result;
}

// Expand %ENV_VAR% sequences in a wide string using ExpandEnvironmentStringsW.
std::wstring ExpandEnvVars(const std::wstring& s)
{
    DWORD needed = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
    if (needed == 0) return s;
    std::wstring out(static_cast<size_t>(needed), L'\0');
    ExpandEnvironmentStringsW(s.c_str(), out.data(), needed);
    // ExpandEnvironmentStrings includes the NUL in 'needed' — trim it
    while (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

} // anonymous namespace

// ===========================================================================
// PolicyManager implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// ApplyHardcodedDefaults — populate |cfg| with compile-time constants.
// Called before JSON parsing so any missing JSON key retains a safe default.
// ---------------------------------------------------------------------------
void PolicyManager::ApplyHardcodedDefaults(PolicyConfig& cfg)
{
    cfg.mode = PolicyMode::Audit;

    cfg.threshold_allow        = THRESHOLD_ALLOW;
    cfg.threshold_warn         = THRESHOLD_WARN;
    cfg.threshold_block_strict = THRESHOLD_BLOCK_STRICT;
    cfg.threshold_block_always = THRESHOLD_BLOCK_ALWAYS;

    cfg.weight_path      = WEIGHT_PATH;
    cfg.weight_name      = WEIGHT_NAME;
    cfg.weight_hash      = WEIGHT_HASH;
    cfg.weight_signature = WEIGHT_SIGNATURE;

    cfg.modifier_tier1_bonus          = MODIFIER_TIER1_BONUS;
    cfg.modifier_post_startup_penalty = MODIFIER_POST_STARTUP_PENALTY;
    cfg.modifier_hash_unknown_penalty = MODIFIER_HASH_UNKNOWN_PENALTY;
    cfg.modifier_ocsp_unavail_penalty = MODIFIER_OCSP_UNAVAIL_PENALTY;

    // Hard-coded Tier 1 fallback paths
    cfg.tier1_paths = {
        tier1_paths::SYSTEM32,
        tier1_paths::SYSWOW64,
        tier1_paths::WINSXS
    };
    cfg.tier2_paths.clear();
    cfg.tier3_paths.clear();

    cfg.blocked_paths = {
        blocked_dirs::WINDOWS_TEMP,
        blocked_dirs::USERS_PUBLIC
    };

    cfg.allow_unc_paths       = false;
    cfg.resolve_symlinks      = true;
    cfg.reject_relative_paths = true;
    cfg.reject_short_paths    = true;

    cfg.require_valid_sig_tier2   = true;
    cfg.require_valid_sig_tier3   = true;
    cfg.allow_expired_countersign = false;
    cfg.check_revocation_ocsp     = true;
    cfg.ocsp_timeout_ms           = OCSP_TIMEOUT_MS;

    cfg.polling_interval_ms     = MONITOR_POLLING_INTERVAL_MS;
    cfg.use_etw                 = true;
    cfg.etw_fallback_to_polling = true;
    cfg.alert_on_post_startup   = true;

    cfg.log_file_path          = L"logs\\dll_hijack_defense.log";
    cfg.log_max_file_mb        = LOG_MAX_FILE_SIZE_MB;
    cfg.log_retention_days     = LOG_RETENTION_DAYS;
    cfg.emit_to_event_log      = true;
    cfg.log_flush_interval_ms  = LOG_FLUSH_INTERVAL_MS;
    cfg.hmac_enabled           = true;

    cfg.cache_enabled               = true;
    cfg.cache_max_entries           = CACHE_MAX_ENTRIES;
    cfg.cache_invalidate_on_mtime   = true;
    cfg.cache_ttl_fallback_secs     = CACHE_TTL_FALLBACK_SECS;

    cfg.anomaly_detection_enabled    = true;
    cfg.anomaly_baseline_window_days = 30;
    cfg.anomaly_threshold_multiplier = 2.0f;

    cfg.rule_r001_enabled          = true;
    cfg.rule_r002_enabled          = true;
    cfg.rule_r003_enabled          = true;
    cfg.rule_r004_levenshtein_max  = TYPOSQUATTING_LEVENSHTEIN_MAX;
    cfg.rule_r005_enabled          = true;
    cfg.rule_r006_enabled          = true;
    cfg.rule_r007_enabled          = true;
    cfg.rule_r007_window_seconds   = BURST_WINDOW_SECONDS;
    cfg.rule_r007_threshold        = BURST_DLL_THRESHOLD;
}

// ---------------------------------------------------------------------------
// ExpandEnvironmentStringsInList — resolve %VAR% sequences in all entries.
// ---------------------------------------------------------------------------
void PolicyManager::ExpandEnvironmentStringsInList(
    std::vector<std::wstring>& paths)
{
    for (auto& p : paths) {
        p = ExpandEnvVars(p);
    }
}

// ---------------------------------------------------------------------------
// ParseJsonFile — populate |cfg| fields from the JSON policy file.
// Any field not present in the file retains the default already set by
// ApplyHardcodedDefaults. Parsing errors are non-fatal: the field is skipped.
// ---------------------------------------------------------------------------
BOOL PolicyManager::ParseJsonFile(const wchar_t* path, PolicyConfig& cfg)
{
    std::string json = ReadFileToString(path);
    if (json.empty()) {
        return FALSE;
    }

    // Mode
    std::string mode = ExtractStringValue(json, "mode");
    if (_stricmp(mode.c_str(), "STRICT") == 0) {
        cfg.mode = PolicyMode::Strict;
    }

    // Thresholds
    cfg.threshold_allow        = ExtractFloatValue(json, "allow",        cfg.threshold_allow);
    cfg.threshold_warn         = ExtractFloatValue(json, "warn",         cfg.threshold_warn);
    cfg.threshold_block_strict = ExtractFloatValue(json, "block_strict", cfg.threshold_block_strict);
    cfg.threshold_block_always = ExtractFloatValue(json, "block_always", cfg.threshold_block_always);

    // Weights
    cfg.weight_path      = ExtractFloatValue(json, "path",      cfg.weight_path);
    cfg.weight_name      = ExtractFloatValue(json, "name",      cfg.weight_name);
    cfg.weight_hash      = ExtractFloatValue(json, "hash",      cfg.weight_hash);
    cfg.weight_signature = ExtractFloatValue(json, "signature", cfg.weight_signature);

    // Path lists (overwrite hard-coded defaults only if present in JSON)
    auto tier1 = ExtractStringArray(json, "tier1");
    if (!tier1.empty()) cfg.tier1_paths = std::move(tier1);

    auto tier2 = ExtractStringArray(json, "tier2");
    if (!tier2.empty()) cfg.tier2_paths = std::move(tier2);

    auto tier3 = ExtractStringArray(json, "tier3");
    if (!tier3.empty()) cfg.tier3_paths = std::move(tier3);

    auto blocked = ExtractStringArray(json, "blocked_paths");
    if (!blocked.empty()) cfg.blocked_paths = std::move(blocked);

    // Path rules
    cfg.allow_unc_paths       = ExtractBoolValue(json, "allow_unc_paths",      cfg.allow_unc_paths);
    cfg.resolve_symlinks      = ExtractBoolValue(json, "resolve_symlinks",     cfg.resolve_symlinks);
    cfg.reject_relative_paths = ExtractBoolValue(json, "reject_relative_paths",cfg.reject_relative_paths);
    cfg.reject_short_paths    = ExtractBoolValue(json, "reject_short_paths",   cfg.reject_short_paths);

    // Signature policy
    cfg.require_valid_sig_tier2   = ExtractBoolValue(json, "require_valid_signature_tier2", cfg.require_valid_sig_tier2);
    cfg.require_valid_sig_tier3   = ExtractBoolValue(json, "require_valid_signature_tier3", cfg.require_valid_sig_tier3);
    cfg.allow_expired_countersign = ExtractBoolValue(json, "allow_expired_countersign",     cfg.allow_expired_countersign);
    cfg.check_revocation_ocsp     = ExtractBoolValue(json, "check_revocation_ocsp",         cfg.check_revocation_ocsp);
    cfg.ocsp_timeout_ms           = ExtractUintValue(json, "ocsp_timeout_ms",               cfg.ocsp_timeout_ms);

    // Monitor
    cfg.polling_interval_ms     = ExtractUintValue(json, "polling_interval_ms",     cfg.polling_interval_ms);
    cfg.use_etw                 = ExtractBoolValue(json, "use_etw",                 cfg.use_etw);
    cfg.etw_fallback_to_polling = ExtractBoolValue(json, "etw_fallback_to_polling", cfg.etw_fallback_to_polling);
    cfg.alert_on_post_startup   = ExtractBoolValue(json, "alert_on_post_startup_load", cfg.alert_on_post_startup);

    // Logging
    cfg.log_max_file_mb       = ExtractUintValue(json, "max_file_size_mb",        static_cast<uint32_t>(cfg.log_max_file_mb));
    cfg.log_retention_days    = ExtractUintValue(json, "retention_days",          cfg.log_retention_days);
    cfg.emit_to_event_log     = ExtractBoolValue(json, "emit_to_windows_event_log", cfg.emit_to_event_log);
    cfg.log_flush_interval_ms = ExtractUintValue(json, "flush_interval_ms",       cfg.log_flush_interval_ms);
    cfg.hmac_enabled          = ExtractBoolValue(json, "hmac_enabled",            cfg.hmac_enabled);

    // Cache
    cfg.cache_enabled             = ExtractBoolValue(json, "enabled",                    cfg.cache_enabled);
    cfg.cache_max_entries         = ExtractUintValue(json, "max_entries",                static_cast<uint32_t>(cfg.cache_max_entries));
    cfg.cache_invalidate_on_mtime = ExtractBoolValue(json, "invalidate_on_mtime_change", cfg.cache_invalidate_on_mtime);
    cfg.cache_ttl_fallback_secs   = ExtractUintValue(json, "ttl_seconds_fallback",       cfg.cache_ttl_fallback_secs);

    // Anomaly
    cfg.anomaly_detection_enabled    = ExtractBoolValue(json, "enabled",                    cfg.anomaly_detection_enabled);
    cfg.anomaly_baseline_window_days = ExtractUintValue(json, "baseline_window_days",       cfg.anomaly_baseline_window_days);
    cfg.anomaly_threshold_multiplier = ExtractFloatValue(json, "anomaly_threshold_multiplier", cfg.anomaly_threshold_multiplier);

    // Rules
    cfg.rule_r001_enabled         = ExtractBoolValue(json, "R001_system_dll_outside_system32",       cfg.rule_r001_enabled);
    cfg.rule_r002_enabled         = ExtractBoolValue(json, "R002_dll_without_valid_signature",       cfg.rule_r002_enabled);
    cfg.rule_r003_enabled         = ExtractBoolValue(json, "R003_dll_from_temp_directory",           cfg.rule_r003_enabled);
    cfg.rule_r004_levenshtein_max = ExtractUintValue(json, "R004_typosquatting_levenshtein_threshold", cfg.rule_r004_levenshtein_max);
    cfg.rule_r005_enabled         = ExtractBoolValue(json, "R005_homoglyph_unicode_detection",       cfg.rule_r005_enabled);
    cfg.rule_r006_enabled         = ExtractBoolValue(json, "R006_privileged_process_unvetted_dll",   cfg.rule_r006_enabled);
    cfg.rule_r007_enabled         = ExtractBoolValue(json, "R007_burst_detection_enabled",           cfg.rule_r007_enabled);
    cfg.rule_r007_window_seconds  = ExtractUintValue(json, "R007_burst_window_seconds",              cfg.rule_r007_window_seconds);
    cfg.rule_r007_threshold       = ExtractUintValue(json, "R007_burst_threshold",                   cfg.rule_r007_threshold);

    return TRUE;
}

// ---------------------------------------------------------------------------
// LoadPolicy — public entry point. Call once at system initialization.
// ---------------------------------------------------------------------------
BOOL PolicyManager::LoadPolicy(const wchar_t* policy_file_path)
{
    AcquireSRWLockExclusive(&s_lock);

    PolicyConfig fresh{};
    ApplyHardcodedDefaults(fresh);

    BOOL json_ok = FALSE;
    if (policy_file_path && *policy_file_path) {
        json_ok = ParseJsonFile(policy_file_path, fresh);
    }

    // Expand environment variable references in path lists
    ExpandEnvironmentStringsInList(fresh.tier1_paths);
    ExpandEnvironmentStringsInList(fresh.tier2_paths);
    ExpandEnvironmentStringsInList(fresh.tier3_paths);
    ExpandEnvironmentStringsInList(fresh.blocked_paths);

    s_config      = std::move(fresh);
    s_initialized = TRUE;

    ReleaseSRWLockExclusive(&s_lock);
    return json_ok;  // FALSE = file not found/parse error, but defaults loaded
}

// ---------------------------------------------------------------------------
// GetConfig — thread-safe copy of the active policy.
// ---------------------------------------------------------------------------
PolicyConfig PolicyManager::GetConfig()
{
    AcquireSRWLockShared(&s_lock);
    PolicyConfig copy = s_config;  // copy under lock
    ReleaseSRWLockShared(&s_lock);
    return copy;
}

// ---------------------------------------------------------------------------
// IsInitialized
// ---------------------------------------------------------------------------
BOOL PolicyManager::IsInitialized()
{
    AcquireSRWLockShared(&s_lock);
    BOOL v = s_initialized;
    ReleaseSRWLockShared(&s_lock);
    return v;
}

// ---------------------------------------------------------------------------
// IsPathInWhitelist
// Performs a case-insensitive prefix match against each tier.
// Tier 1 is checked first (fastest return for System32 paths).
// ---------------------------------------------------------------------------
WhitelistTier PolicyManager::IsPathInWhitelist(const wchar_t* canonical_path)
{
    if (!canonical_path) return WhitelistTier::None;

    AcquireSRWLockShared(&s_lock);
    const PolicyConfig& cfg = s_config;

    auto prefixMatch = [&](const std::vector<std::wstring>& list) -> bool {
        for (const auto& prefix : list) {
            if (PathIsPrefix(prefix.c_str(), canonical_path)) {
                return true;
            }
        }
        return false;
    };

    WhitelistTier result = WhitelistTier::None;

    if      (prefixMatch(cfg.tier1_paths)) result = WhitelistTier::Tier1;
    else if (prefixMatch(cfg.tier2_paths)) result = WhitelistTier::Tier2;
    else if (prefixMatch(cfg.tier3_paths)) result = WhitelistTier::Tier3;

    ReleaseSRWLockShared(&s_lock);
    return result;
}

// ---------------------------------------------------------------------------
// IsPathBlocked
// ---------------------------------------------------------------------------
BOOL PolicyManager::IsPathBlocked(const wchar_t* canonical_path)
{
    if (!canonical_path) return FALSE;

    AcquireSRWLockShared(&s_lock);
    const PolicyConfig& cfg = s_config;

    BOOL blocked = FALSE;
    for (const auto& prefix : cfg.blocked_paths) {
        if (PathIsPrefix(prefix.c_str(), canonical_path)) {
            blocked = TRUE;
            break;
        }
    }

    ReleaseSRWLockShared(&s_lock);
    return blocked;
}

// ---------------------------------------------------------------------------
// DetermineAction
// Maps a score to the appropriate LoadAction given the active policy mode.
// ---------------------------------------------------------------------------
LoadAction PolicyManager::DetermineAction(float score)
{
    AcquireSRWLockShared(&s_lock);
    const PolicyMode mode = s_config.mode;
    float ta  = s_config.threshold_allow;
    float tbs = s_config.threshold_block_strict;
    float tba = s_config.threshold_block_always;
    ReleaseSRWLockShared(&s_lock);

    // score is a TRUST score: 1.0 = fully trusted, 0.0 = fully untrusted.
    // A DLL is blocked when its trust score is too LOW (suspicious).
    // Thresholds are inverted: block_always=0.86 → block when score < 0.14.

    // Critically low trust → block in any mode
    if (score < (1.0f - tba)) {
        return LoadAction::BlockedAlways;
    }

    // Low trust → block only in Strict mode
    if (score < (1.0f - tbs) && mode == PolicyMode::Strict) {
        return LoadAction::Blocked;
    }

    // Medium trust → allow with warning flag
    if (score < (1.0f - ta)) {
        return LoadAction::AllowedFlagged;
    }

    // High trust → clean allow
    return LoadAction::Allowed;
}

} // namespace dhd
