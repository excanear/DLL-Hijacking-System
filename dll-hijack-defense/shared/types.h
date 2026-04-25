#pragma once

// =============================================================================
// shared/types.h
// Central data contracts for the DLL Hijacking Defense System.
// All modules include this header — keep it dependency-free (no WinAPI types
// that require including <windows.h> in unexpected translation units).
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wintrust.h>

#include <cstdint>
#include <string>

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
namespace dhd { // dll hijack defense

// ---------------------------------------------------------------------------
// RiskLevel — classification output of the Risk Analyzer
// Ordered so that higher value == higher risk (allows simple comparisons).
// ---------------------------------------------------------------------------
enum class RiskLevel : uint32_t {
    Low      = 0,
    Medium   = 1,
    High     = 2,
    Critical = 3
};

// ---------------------------------------------------------------------------
// PolicyMode — operational mode of the system
// ---------------------------------------------------------------------------
enum class PolicyMode : uint32_t {
    Audit  = 0,  // observe + log, never block
    Strict = 1   // observe + log + block on threshold breach
};

// ---------------------------------------------------------------------------
// LoadAction — final decision on a load request
// ---------------------------------------------------------------------------
enum class LoadAction : uint32_t {
    Allowed        = 0,  // score >= allow threshold, loaded normally
    AllowedFlagged = 1,  // score in warn band, loaded with WARNING log
    Blocked        = 2,  // score >= block threshold (strict mode)
    BlockedAlways  = 3   // score >= block_always threshold regardless of mode
};

// ---------------------------------------------------------------------------
// BlockReason — bitfield of reasons a load was denied or flagged
// Multiple reasons may apply simultaneously.
// ---------------------------------------------------------------------------
enum BlockReason : uint32_t {
    BR_NONE                    = 0x00000000,
    BR_PATH_RELATIVE           = 0x00000001,  // requested path was relative
    BR_PATH_NOT_IN_WHITELIST   = 0x00000002,  // resolved path not in any tier
    BR_PATH_IN_BLOCKED_DIR     = 0x00000004,  // path inside a blocked directory
    BR_PATH_IS_UNC             = 0x00000008,  // UNC path rejected by policy
    BR_SYMLINK_RESOLUTION_FAIL = 0x00000010,  // GetFinalPathNameByHandle failed
    BR_NAME_HOMOGLYPH          = 0x00000020,  // non-ASCII characters in DLL name
    BR_NAME_TYPOSQUATTING      = 0x00000040,  // Levenshtein distance <= threshold
    BR_NAME_SUSPICIOUS_PATTERN = 0x00000080,  // double extension, suspect suffix
    BR_HASH_NOT_FOUND          = 0x00000100,  // SHA-256 not in approved database
    BR_HASH_REVOKED            = 0x00000200,  // SHA-256 explicitly revoked
    BR_HASH_COMPUTE_FAILURE    = 0x00000400,  // could not compute hash (I/O error)
    BR_SIGNATURE_INVALID       = 0x00000800,  // WinVerifyTrust returned failure
    BR_SIGNATURE_ABSENT        = 0x00001000,  // file is unsigned
    BR_SIGNATURE_REVOKED       = 0x00002000,  // certificate revoked via OCSP/CRL
    BR_SCORE_TOO_LOW           = 0x00004000,  // aggregate score below threshold
    BR_RULE_SYSTEM_DLL_OUTSIDE = 0x00008000,  // R001: system DLL outside System32
    BR_RULE_TEMP_DIRECTORY     = 0x00010000,  // R003: DLL from temp directory
    BR_RULE_PRIVILEGED_PROCESS = 0x00020000,  // R006: unvetted DLL in SYSTEM process
    BR_TOCTOU_DETECTED         = 0x00040000,  // file changed between validate+load
    BR_UNEXPECTED_MODULE       = 0x00080000   // module appeared without Secure Loader
};

// ---------------------------------------------------------------------------
// WhitelistTier — tier of the matching whitelist entry
// ---------------------------------------------------------------------------
enum class WhitelistTier : uint32_t {
    None  = 0,  // path not in any whitelist
    Tier1 = 1,  // always trusted (System32, SysWOW64, WinSxS)
    Tier2 = 2,  // trusted with valid hash (Program Files)
    Tier3 = 3   // trusted with hash + valid signature
};

// ---------------------------------------------------------------------------
// HashLookupResult — result of querying the hash database
// ---------------------------------------------------------------------------
enum class HashLookupResult : uint32_t {
    Found    = 0,  // SHA-256 is in the approved database
    NotFound = 1,  // SHA-256 is not known (not approved, not revoked)
    Revoked  = 2,  // SHA-256 has been explicitly revoked
    DbError  = 3   // database could not be read/parsed
};

// ---------------------------------------------------------------------------
// LogSeverity — severity levels for the Logging Engine
// ---------------------------------------------------------------------------
enum class LogSeverity : uint32_t {
    Info    = 0,
    Warning = 1,
    Alert   = 2
};

// ===========================================================================
// Structs
// ===========================================================================

// ---------------------------------------------------------------------------
// LoadRequest
// Populated by the caller of SecureLoadLibrary before validation begins.
// ---------------------------------------------------------------------------
struct LoadRequest {
    wchar_t  requested_name[MAX_PATH];   // as passed by caller (may be relative)
    wchar_t  canonical_path[MAX_PATH];   // resolved absolute path (filled by loader)
    wchar_t  final_path[MAX_PATH];       // after symlink resolution
    DWORD    caller_pid;
    DWORD    caller_tid;
    FILETIME timestamp;
    DWORD    load_flags;                 // original flags passed by caller
    BOOL     is_post_startup;            // TRUE if process startup phase is over
};

// ---------------------------------------------------------------------------
// ValidationResult
// Output of the DLL Validator pipeline for a single DLL.
// ---------------------------------------------------------------------------
struct ValidationResult {
    // Per-layer scores (0.0 = failed, 1.0 = fully passed)
    float    path_score;
    float    name_score;
    float    hash_score;
    float    signature_score;

    // Computed aggregate score (weighted sum, 0.0 – 1.0)
    float    aggregate_score;

    // Classification
    RiskLevel    risk_level;
    uint32_t     block_reasons;      // bitfield of BlockReason values

    // Whitelist context
    WhitelistTier whitelist_tier;

    // Hash details
    wchar_t  sha256_hex[65];         // null-terminated 64-char hex + NUL
    HashLookupResult hash_lookup;

    // Signature details
    BOOL     signature_present;
    BOOL     signature_valid;
    BOOL     signature_revoked;
    wchar_t  cert_subject[256];
    wchar_t  cert_issuer[256];

    // Cache metadata
    BOOL     served_from_cache;

    // Human-readable failure summary (for logging)
    wchar_t  failure_reason[512];
};

// ---------------------------------------------------------------------------
// LoadResult
// Returned by SecureLoadLibrary to the caller.
// ---------------------------------------------------------------------------
struct LoadResult {
    HMODULE      handle;             // NULL if blocked or load failed
    LoadAction   action;
    uint32_t     block_reasons;      // bitfield of BlockReason (if blocked)
    float        trust_score;        // final aggregate score
    RiskLevel    risk_level;
    DWORD        win32_error;        // GetLastError() value if WinAPI call failed
};

// ---------------------------------------------------------------------------
// ModuleRecord
// Stored in the ApprovedModuleSet by the Runtime Monitor.
// One record per successfully loaded (validated) DLL.
// ---------------------------------------------------------------------------
struct ModuleRecord {
    HMODULE  base_address;
    wchar_t  path[MAX_PATH];
    wchar_t  name[256];
    FILETIME load_timestamp;
    BOOL     was_validated;          // passed through SecureLoadLibrary
    float    trust_score;
    DWORD    load_flags_used;        // flags passed to LoadLibraryExW
    WhitelistTier whitelist_tier;
};

// ---------------------------------------------------------------------------
// CacheEntry
// Used by the DLL Validator's validation cache.
// Keyed by (canonical_path, file_mtime) — invalidated on mtime change.
// ---------------------------------------------------------------------------
struct CacheEntry {
    wchar_t          canonical_path[MAX_PATH];
    FILETIME         file_mtime;         // last write time at validation time
    ValidationResult result;
    FILETIME         cached_at;
    uint32_t         ttl_seconds;
    BOOL             valid;              // FALSE = entry is stale/unused slot
};

// ---------------------------------------------------------------------------
// LogEvent
// Produced by any module, consumed and persisted by the Logging Engine.
// ---------------------------------------------------------------------------
struct LogEvent {
    uint32_t     schema_version;         // always 2 (current schema)
    FILETIME     timestamp;
    LogSeverity  severity;
    wchar_t      source_module[64];      // e.g. L"SECURE_LOADER"
    wchar_t      host_name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD        process_id;
    wchar_t      process_name[MAX_PATH];
    wchar_t      dll_path[MAX_PATH];
    float        trust_score;
    LoadAction   action;
    uint32_t     block_reasons;          // bitfield of BlockReason
    RiskLevel    risk_level;
    BOOL         was_prevalidated;
    BYTE         hmac_sha256[32];        // HMAC-SHA256 over serialized JSON body
};

// ---------------------------------------------------------------------------
// AuditFinding
// Single finding produced by the Audit Scanner for one executable/directory.
// ---------------------------------------------------------------------------
struct AuditFinding {
    RiskLevel    severity;
    wchar_t      target_path[MAX_PATH];   // the executable being analyzed
    wchar_t      dll_name[256];           // the problematic imported DLL
    wchar_t      issue_code[64];          // e.g. L"WRITABLE_DIR_HIJACKABLE_IMPORT"
    wchar_t      detail[512];
    wchar_t      recommendation[512];
};

} // namespace dhd
