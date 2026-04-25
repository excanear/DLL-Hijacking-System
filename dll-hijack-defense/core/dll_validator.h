#pragma once

// =============================================================================
// core/dll_validator.h
// Public interface of the DLL Validator pipeline.
// Called exclusively by SecureLoadLibrary (Secure Loader, BLOCO 3).
//
// Pipeline layers (cheapest → most expensive, short-circuit on hard failure):
//   Layer 1 — Path whitelist      O(n) prefix match
//   Layer 2 — Name heuristics     Levenshtein + Unicode check
//   Layer 3 — SHA-256 hash        O(file_size) via BCrypt over open handle
//   Layer 4 — Authenticode sig    WinVerifyTrust + OCSP
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "types.h"

namespace dhd {

// ---------------------------------------------------------------------------
// InitializeValidator
//
// Load the hash database from |hash_db_path| into memory and prepare the
// validation cache. Must be called once before ValidateDLL().
// If |hash_db_path| is NULL the database starts empty — all hash lookups
// will return HashLookupResult::NotFound (score penalty applied).
//
// Returns TRUE on success. FALSE means the DB file was missing or malformed;
// validation continues with an empty database (non-fatal, penalised in score).
// ---------------------------------------------------------------------------
BOOL InitializeValidator(const wchar_t* hash_db_path);

// ---------------------------------------------------------------------------
// ValidateDLL
//
// Orchestrates the four-layer validation pipeline.
//
// |file_handle|    — GENERIC_READ handle, FILE_SHARE_READ only (no write/delete).
//                   BCrypt reads through this handle; it is NEVER re-opened.
//                   The caller keeps it open until after LoadLibraryExW to
//                   close the TOCTOU window.
// |canonical_path| — fully resolved path after GetFinalPathNameByHandleW.
// |is_post_startup|— TRUE triggers the post_startup_penalty score modifier.
// |out_result|     — mandatory output; must not be NULL.
//
// Returns TRUE even when the aggregate score is low — blocking is the
// caller's responsibility via PolicyManager::DetermineAction().
// Returns FALSE only on unrecoverable internal error (e.g. BCrypt init fail).
// ---------------------------------------------------------------------------
BOOL ValidateDLL(HANDLE            file_handle,
                 const wchar_t*    canonical_path,
                 BOOL              is_post_startup,
                 ValidationResult* out_result);

// ---------------------------------------------------------------------------
// InvalidateValidationCache
// Evict a specific path from the cache (e.g. after a known file update).
// ---------------------------------------------------------------------------
void InvalidateValidationCache(const wchar_t* canonical_path);

// ---------------------------------------------------------------------------
// GetValidationCacheStats
// Diagnostic counters. Either pointer may be NULL.
// ---------------------------------------------------------------------------
void GetValidationCacheStats(size_t* out_hits, size_t* out_misses);

} // namespace dhd
