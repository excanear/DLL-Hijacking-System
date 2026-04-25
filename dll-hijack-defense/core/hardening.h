// =============================================================================
// core/hardening.h
// Defense-in-depth hardening: ACL restriction and file integrity verification.
//
// Overview
// --------
// This module provides two complementary hardening layers:
//
//   1. ACL Hardening — restrict write access on sensitive paths to SYSTEM
//      and Administrators only, breaking inherited permissive permissions.
//
//   2. Integrity Verification — compute and verify SHA-256 hashes of policy
//      and configuration files to detect off-band tampering.
//
// All functions are non-fatal by design. If hardening fails (e.g., the
// process lacks WRITE_DAC permission), the function returns FALSE and the
// caller emits a warning. The core validation pipeline continues regardless.
//
// Requirements
// ------------
// - HardenLogDirectory / HardenPolicyFile require WRITE_DAC on the target.
//   This typically means the process must run as Administrator or SYSTEM.
// - VerifyHashDatabaseIntegrity requires read access to the DB file and
//   that the file was written by bootstrap_hashdb (which computes
//   db_integrity_hash using the canonical JSON format).
//
// Thread Safety
// -------------
// All functions are stateless (no shared mutable state) and are safe to
// call from any thread. SnapshotFileHash / VerifyFileIntegrity operate on
// the file system and are subject to normal file-locking constraints.
// =============================================================================

#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "constants.h"  // SHA256_HEX_LEN

namespace dhd {

// ---------------------------------------------------------------------------
// HardenLogDirectory
// ---------------------------------------------------------------------------
// Sets a protected DACL on |log_dir_path| that grants:
//   - SYSTEM        : FILE_ALL_ACCESS  (container + object inherit)
//   - Administrators: FILE_ALL_ACCESS  (container + object inherit)
//   - All others    : no access        (inheritance is broken)
//
// The directory is created if it does not already exist.
// Returns TRUE on success, FALSE if the path cannot be secured (caller should
// emit a warning — logging degrades gracefully to OutputDebugStringW).
// ---------------------------------------------------------------------------
BOOL HardenLogDirectory(const wchar_t* log_dir_path);

// ---------------------------------------------------------------------------
// HardenPolicyFile
// ---------------------------------------------------------------------------
// Sets a protected DACL on |policy_file_path| that grants:
//   - SYSTEM        : FILE_ALL_ACCESS  (no inheritance — file only)
//   - Administrators: FILE_ALL_ACCESS  (no inheritance — file only)
//   - Everyone      : FILE_GENERIC_READ (read-only; no modification)
//
// Policy files must be readable by the host process (which may run as a
// non-admin user), but must not be writable by unprivileged accounts.
// Returns TRUE on success, FALSE otherwise.
// ---------------------------------------------------------------------------
BOOL HardenPolicyFile(const wchar_t* policy_file_path);

// ---------------------------------------------------------------------------
// SnapshotFileHash
// ---------------------------------------------------------------------------
// Computes the SHA-256 hash of the file at |file_path| (in 64 KB chunks,
// using BCrypt) and writes the lowercase hex representation into
// |out_hex_64|, which must be at least (SHA256_HEX_LEN + 1) wide chars.
//
// Intended use: call once at startup to baseline the policy or hash-DB file.
// Store the returned hex; later pass it to VerifyFileIntegrity.
//
// Returns TRUE on success, FALSE if the file cannot be read or BCrypt fails.
// ---------------------------------------------------------------------------
BOOL SnapshotFileHash(const wchar_t* file_path,
                      wchar_t*       out_hex_64,
                      size_t         out_cap_wchars);

// ---------------------------------------------------------------------------
// VerifyFileIntegrity
// ---------------------------------------------------------------------------
// Recomputes the SHA-256 of |file_path| and compares it (case-insensitive)
// against |expected_hex_64| (the value previously returned by SnapshotFileHash).
//
// Returns TRUE if the hash matches (file unmodified).
// Returns FALSE if:
//   - the file cannot be read
//   - BCrypt computation fails
//   - the computed hash differs from expected (tamper detected)
// ---------------------------------------------------------------------------
BOOL VerifyFileIntegrity(const wchar_t* file_path,
                         const wchar_t* expected_hex_64);

// ---------------------------------------------------------------------------
// VerifyHashDatabaseIntegrity
// ---------------------------------------------------------------------------
// Reads the JSON file at |db_path|, extracts the "db_integrity_hash" field,
// reconstructs the canonical zero-hash version (replacing the hash value
// with an empty string), and verifies that SHA-256(canonical) equals the
// stored hash value.
//
// This detects manual or malicious edits to hash_database.json that were
// made without re-running bootstrap_hashdb or Update-HashDatabase.ps1.
//
// Returns TRUE if the integrity hash matches.
// Returns FALSE if:
//   - the file cannot be read
//   - the "db_integrity_hash" field is absent or malformed
//   - the computed hash differs from the stored value (tamper detected)
//   - the stored hash is empty (file was never bootstrapped — FALSE + warning)
// ---------------------------------------------------------------------------
BOOL VerifyHashDatabaseIntegrity(const wchar_t* db_path);

}  // namespace dhd
