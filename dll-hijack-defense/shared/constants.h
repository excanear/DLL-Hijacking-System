#pragma once

// =============================================================================
// shared/constants.h
// Compile-time constants, default thresholds, and named values used across
// all modules of the DLL Hijacking Defense System.
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <cstddef>

namespace dhd {

// ===========================================================================
// Schema versions
// ===========================================================================
inline constexpr uint32_t LOG_SCHEMA_VERSION      = 2;
inline constexpr uint32_t HASH_DB_SCHEMA_VERSION  = 1;
inline constexpr uint32_t POLICY_SCHEMA_VERSION   = 1;

// ===========================================================================
// Score thresholds (matches policy/defaults.json — runtime policy overrides)
//
// Trust score semantics: 1.0 = fully trusted / clean, 0.0 = fully untrusted / malicious.
// DetermineAction and ScoreToRiskLevel use (1.0 - threshold) to invert these
// values for comparison against the trust score.
// ===========================================================================

// Trust score BELOW (1.0 - THRESHOLD_BLOCK_ALWAYS) → BlockedAlways [score < 0.14]
inline constexpr float THRESHOLD_BLOCK_ALWAYS = 0.86f;

// Trust score BELOW (1.0 - THRESHOLD_BLOCK_STRICT) → Blocked in Strict [score < 0.39]
inline constexpr float THRESHOLD_BLOCK_STRICT = 0.61f;

// Trust score BELOW (1.0 - THRESHOLD_ALLOW) → AllowedFlagged [score < 0.70]
inline constexpr float THRESHOLD_ALLOW        = 0.30f;

// (Unused in DetermineAction — kept for risk_analyzer burst band)
inline constexpr float THRESHOLD_WARN         = 0.60f;

// ===========================================================================
// Score weights (must sum to 1.0)
// ===========================================================================
inline constexpr float WEIGHT_PATH      = 0.40f;
inline constexpr float WEIGHT_NAME      = 0.15f;
inline constexpr float WEIGHT_HASH      = 0.25f;
inline constexpr float WEIGHT_SIGNATURE = 0.20f;

static_assert(
    (WEIGHT_PATH + WEIGHT_NAME + WEIGHT_HASH + WEIGHT_SIGNATURE) == 1.0f,
    "Score weights must sum to 1.0"
);

// ===========================================================================
// Score modifiers (applied after weighted sum)
// ===========================================================================
inline constexpr float MODIFIER_TIER1_BONUS            =  0.10f;
inline constexpr float MODIFIER_POST_STARTUP_PENALTY   = -0.15f;
inline constexpr float MODIFIER_HASH_UNKNOWN_PENALTY   = -0.10f;
inline constexpr float MODIFIER_OCSP_UNAVAIL_PENALTY   = -0.05f;

// ===========================================================================
// Levenshtein distance threshold for typosquatting detection (Rule R004)
// DLL names within this distance from a known system DLL are flagged.
// ===========================================================================
inline constexpr uint32_t TYPOSQUATTING_LEVENSHTEIN_MAX = 2;

// ===========================================================================
// Runtime Monitor — polling
// ===========================================================================
inline constexpr uint32_t MONITOR_POLLING_INTERVAL_MS = 500;

// ===========================================================================
// Burst detection (Rule R007)
// Flag if N+ low-scoring DLLs are loaded within a time window.
// ===========================================================================
inline constexpr uint32_t BURST_WINDOW_SECONDS  = 5;
inline constexpr uint32_t BURST_DLL_THRESHOLD   = 3;
inline constexpr float    BURST_SCORE_CEILING   = 0.50f;  // "low-scoring" = below this

// ===========================================================================
// Validation cache
// ===========================================================================
inline constexpr size_t   CACHE_MAX_ENTRIES       = 1024;
inline constexpr uint32_t CACHE_TTL_FALLBACK_SECS = 3600;  // 1 hour

// ===========================================================================
// Logging Engine
// ===========================================================================
inline constexpr size_t   LOG_MAX_FILE_SIZE_MB  = 100;
inline constexpr uint32_t LOG_RETENTION_DAYS    = 30;
inline constexpr uint32_t LOG_FLUSH_INTERVAL_MS = 1000;

// ===========================================================================
// OCSP / signature verification
// ===========================================================================
inline constexpr uint32_t OCSP_TIMEOUT_MS = 3000;

// ===========================================================================
// Buffer sizes (for wchar_t arrays not using MAX_PATH)
// ===========================================================================
inline constexpr size_t SHA256_HEX_LEN    = 64;   // chars, excluding NUL
inline constexpr size_t HMAC_SHA256_BYTES = 32;
inline constexpr size_t MAX_DLL_NAME_LEN  = 256;
inline constexpr size_t MAX_SOURCE_LEN    = 64;
inline constexpr size_t MAX_CERT_FIELD    = 256;
inline constexpr size_t MAX_ISSUE_CODE    = 64;
inline constexpr size_t MAX_DETAIL_LEN    = 512;

// ===========================================================================
// Known blocked directory prefixes
// These are matched as case-insensitive prefix checks at runtime.
// The runtime policy loader also populates a list from defaults.json.
// These constants serve as a hard-coded last-resort fallback.
// ===========================================================================
namespace blocked_dirs {
    inline constexpr const wchar_t* WINDOWS_TEMP = L"C:\\Windows\\Temp";
    inline constexpr const wchar_t* USERS_PUBLIC  = L"C:\\Users\\Public";
} // namespace blocked_dirs

// ===========================================================================
// Tier 1 whitelist — hard-coded fallback (policy file may extend or override)
// ===========================================================================
namespace tier1_paths {
    inline constexpr const wchar_t* SYSTEM32  = L"C:\\Windows\\System32";
    inline constexpr const wchar_t* SYSWOW64  = L"C:\\Windows\\SysWOW64";
    inline constexpr const wchar_t* WINSXS    = L"C:\\Windows\\WinSxS";
} // namespace tier1_paths

// ===========================================================================
// LoadLibraryExW flags used by the Secure Loader
// LOAD_WITH_ALTERED_SEARCH_PATH: interpret first param as full path,
//   disabling relative DLL lookup from that location.
// LOAD_LIBRARY_SEARCH_SYSTEM32:  restrict implicit dependency resolution
//   to System32 only when loading a module.
// ===========================================================================
inline constexpr DWORD SECURE_LOAD_FLAGS =
    LOAD_WITH_ALTERED_SEARCH_PATH |
    LOAD_LIBRARY_SEARCH_SYSTEM32;

// ===========================================================================
// SetDefaultDllDirectories flags applied during initialization
// Restricts implicit DLL search to:
//   - Directories explicitly added via AddDllDirectory()
//   - System32
//   - Application directory
// Removes: CWD, PATH — the two most common hijacking vectors.
// ===========================================================================
inline constexpr DWORD SAFE_DLL_SEARCH_FLAGS =
    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
    LOAD_LIBRARY_SEARCH_SYSTEM32     |
    LOAD_LIBRARY_SEARCH_APPLICATION_DIR;

// ===========================================================================
// Source module names — used in LogEvent.source_module
// ===========================================================================
namespace source {
    inline constexpr const wchar_t* SECURE_LOADER    = L"SECURE_LOADER";
    inline constexpr const wchar_t* DLL_VALIDATOR    = L"DLL_VALIDATOR";
    inline constexpr const wchar_t* RUNTIME_MONITOR  = L"RUNTIME_MONITOR";
    inline constexpr const wchar_t* RISK_ANALYZER    = L"RISK_ANALYZER";
    inline constexpr const wchar_t* LOGGING_ENGINE   = L"LOGGING_ENGINE";
    inline constexpr const wchar_t* AUDIT_SCANNER    = L"AUDIT_SCANNER";
} // namespace source

// ===========================================================================
// Issue codes — used in AuditFinding.issue_code
// ===========================================================================
namespace issue {
    inline constexpr const wchar_t* PHANTOM_DLL              = L"PHANTOM_DLL_IMPORT";
    inline constexpr const wchar_t* WRITABLE_DIR_HIJACKABLE  = L"WRITABLE_DIR_HIJACKABLE_IMPORT";
    inline constexpr const wchar_t* SEARCH_ORDER_RISK        = L"UNSAFE_SEARCH_ORDER";
    inline constexpr const wchar_t* NO_SAFE_SEARCH_MODE      = L"SAFE_SEARCH_MODE_DISABLED";
    inline constexpr const wchar_t* ACL_OVERLY_PERMISSIVE    = L"ACL_OVERLY_PERMISSIVE";
} // namespace issue

} // namespace dhd
