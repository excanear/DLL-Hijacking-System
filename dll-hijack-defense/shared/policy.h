#pragma once

// =============================================================================
// shared/policy.h
// Interface for loading, querying, and caching the runtime security policy.
// Policy is read from policy/defaults.json at initialization and cached in
// memory. All modules query policy through this interface — never read the
// JSON file directly.
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "types.h"
#include "constants.h"

namespace dhd {

// ---------------------------------------------------------------------------
// PolicyConfig
// In-memory representation of the parsed policy file.
// Populated once by LoadPolicy() and read-only thereafter.
// ---------------------------------------------------------------------------
struct PolicyConfig {
    // Mode
    PolicyMode mode = PolicyMode::Audit;

    // Score thresholds (loaded from JSON, fall back to constants.h defaults)
    float threshold_allow        = THRESHOLD_ALLOW;
    float threshold_warn         = THRESHOLD_WARN;
    float threshold_block_strict = THRESHOLD_BLOCK_STRICT;
    float threshold_block_always = THRESHOLD_BLOCK_ALWAYS;

    // Score weights
    float weight_path      = WEIGHT_PATH;
    float weight_name      = WEIGHT_NAME;
    float weight_hash      = WEIGHT_HASH;
    float weight_signature = WEIGHT_SIGNATURE;

    // Score modifiers
    float modifier_tier1_bonus          = MODIFIER_TIER1_BONUS;
    float modifier_post_startup_penalty = MODIFIER_POST_STARTUP_PENALTY;
    float modifier_hash_unknown_penalty = MODIFIER_HASH_UNKNOWN_PENALTY;
    float modifier_ocsp_unavail_penalty = MODIFIER_OCSP_UNAVAIL_PENALTY;

    // Path whitelist — grouped by tier
    std::vector<std::wstring> tier1_paths;
    std::vector<std::wstring> tier2_paths;
    std::vector<std::wstring> tier3_paths;

    // Blocked path prefixes (e.g. %TEMP% resolved at load time)
    std::vector<std::wstring> blocked_paths;

    // Path rules
    bool allow_unc_paths        = false;
    bool resolve_symlinks       = true;
    bool reject_relative_paths  = true;
    bool reject_short_paths     = true;

    // Signature policy
    bool     require_valid_sig_tier2  = true;
    bool     require_valid_sig_tier3  = true;
    bool     allow_expired_countersign = false;
    bool     check_revocation_ocsp    = true;
    uint32_t ocsp_timeout_ms          = OCSP_TIMEOUT_MS;

    // Monitor
    uint32_t polling_interval_ms      = MONITOR_POLLING_INTERVAL_MS;
    bool     use_etw                  = true;
    bool     etw_fallback_to_polling  = true;
    bool     alert_on_post_startup    = true;

    // Logging
    std::wstring log_file_path        = L"logs\\dll_hijack_defense.log";
    size_t       log_max_file_mb      = LOG_MAX_FILE_SIZE_MB;
    uint32_t     log_retention_days   = LOG_RETENTION_DAYS;
    bool         emit_to_event_log    = true;
    uint32_t     log_flush_interval_ms = LOG_FLUSH_INTERVAL_MS;
    bool         hmac_enabled         = true;

    // Cache
    bool     cache_enabled            = true;
    size_t   cache_max_entries        = CACHE_MAX_ENTRIES;
    bool     cache_invalidate_on_mtime = true;
    uint32_t cache_ttl_fallback_secs  = CACHE_TTL_FALLBACK_SECS;

    // Anomaly detection
    bool     anomaly_detection_enabled      = true;
    uint32_t anomaly_baseline_window_days   = 30;
    float    anomaly_threshold_multiplier   = 2.0f;

    // Detection rules (R001–R007)
    bool     rule_r001_enabled = true;   // system DLL outside System32
    bool     rule_r002_enabled = true;   // no valid signature
    bool     rule_r003_enabled = true;   // DLL from temp directory
    uint32_t rule_r004_levenshtein_max = TYPOSQUATTING_LEVENSHTEIN_MAX;
    bool     rule_r005_enabled = true;   // homoglyph Unicode
    bool     rule_r006_enabled = true;   // privileged process unvetted DLL
    bool     rule_r007_enabled = true;   // burst detection
    uint32_t rule_r007_window_seconds  = BURST_WINDOW_SECONDS;
    uint32_t rule_r007_threshold       = BURST_DLL_THRESHOLD;
};

// ===========================================================================
// PolicyManager
// Singleton-style manager for the active policy configuration.
// Thread-safe after initialization — uses SRWLOCK for reads.
// ===========================================================================
class PolicyManager {
public:
    // -----------------------------------------------------------------------
    // LoadPolicy
    // Parse the JSON policy file at |policy_file_path| and populate the
    // internal PolicyConfig. Must be called once before any other method.
    // Expands environment variables in blocked_paths (e.g. %TEMP%).
    //
    // Returns TRUE on success. On failure, the internal config retains
    // compile-time defaults so the system can continue in a safe state.
    // -----------------------------------------------------------------------
    static BOOL LoadPolicy(const wchar_t* policy_file_path);

    // -----------------------------------------------------------------------
    // GetConfig
    // Returns a copy of the active policy config, taken atomically under the
    // shared lock. Safe to call concurrently with LoadPolicy().
    // -----------------------------------------------------------------------
    static PolicyConfig GetConfig();

    // -----------------------------------------------------------------------
    // IsPathInWhitelist
    // Case-insensitive prefix check against all whitelist tiers.
    // Returns the matching tier (None if not found).
    // -----------------------------------------------------------------------
    static WhitelistTier IsPathInWhitelist(const wchar_t* canonical_path);

    // -----------------------------------------------------------------------
    // IsPathBlocked
    // Returns TRUE if |canonical_path| starts with any blocked directory
    // prefix defined in the policy (e.g. TEMP, Public).
    // -----------------------------------------------------------------------
    static BOOL IsPathBlocked(const wchar_t* canonical_path);

    // -----------------------------------------------------------------------
    // DetermineAction
    // Given a final aggregate score and the active mode, returns the
    // LoadAction that should be taken.
    // -----------------------------------------------------------------------
    static LoadAction DetermineAction(float aggregate_score);

    // -----------------------------------------------------------------------
    // IsInitialized
    // Returns TRUE if LoadPolicy() has been called successfully.
    // -----------------------------------------------------------------------
    static BOOL IsInitialized();

private:
    PolicyManager() = delete;  // static-only interface

    static PolicyConfig  s_config;
    static BOOL          s_initialized;
    static SRWLOCK       s_lock;

    // Internal helpers
    static void ApplyHardcodedDefaults(PolicyConfig& cfg);
    static BOOL ParseJsonFile(const wchar_t* path, PolicyConfig& cfg);
    static void ExpandEnvironmentStringsInList(std::vector<std::wstring>& paths);
};

} // namespace dhd
