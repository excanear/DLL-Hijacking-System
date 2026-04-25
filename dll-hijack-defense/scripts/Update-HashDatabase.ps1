#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Populates SHA-256 hashes in hash_database.json for all entries that have an
    empty "sha256" field, then writes a db_integrity_hash over the final content.

.DESCRIPTION
    This PowerShell alternative to bootstrap_hashdb.exe uses Get-FileHash (built-in)
    to compute SHA-256 values for each DLL listed in the database. Run this script
    once on the reference machine before deploying the DLL Hijacking Defense System.

    The script:
      1. Reads config\hash_database.json (or a custom path via -DatabasePath)
      2. For each entry, resolves the DLL from trusted_path → System32 → SysWOW64
      3. Computes SHA-256 and updates the entry
      4. Computes a SHA-256 integrity hash over the final JSON and stores it in
         db_integrity_hash
      5. Writes the updated JSON in-place

.PARAMETER DatabasePath
    Path to hash_database.json.
    Defaults to: <script_dir>\..\config\hash_database.json

.PARAMETER Force
    Re-compute and overwrite hashes even if they are already populated.

.EXAMPLE
    .\Update-HashDatabase.ps1

.EXAMPLE
    .\Update-HashDatabase.ps1 -DatabasePath "C:\MyApp\config\hash_database.json" -Force

.NOTES
    Requires -RunAsAdministrator to ensure accurate ACL/file reads from System32.
    Tested on Windows 10/11 with PowerShell 5.1+.
#>

[CmdletBinding()]
param(
    [string]$DatabasePath = "",
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Resolve default database path
# ---------------------------------------------------------------------------
if ([string]::IsNullOrEmpty($DatabasePath)) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $DatabasePath = Join-Path $ScriptDir "..\config\hash_database.json"
}
$DatabasePath = [System.IO.Path]::GetFullPath($DatabasePath)

Write-Host "[*] DLL Hijacking Defense -- Hash Database Bootstrap (PowerShell)"
Write-Host "[*] Database: $DatabasePath"
Write-Host ""

if (-not (Test-Path $DatabasePath)) {
    Write-Error "Database file not found: $DatabasePath"
    exit 2
}

# ---------------------------------------------------------------------------
# Read and parse the JSON
# ---------------------------------------------------------------------------
$raw = Get-Content -Path $DatabasePath -Encoding UTF8 -Raw
try {
    $db = $raw | ConvertFrom-Json
} catch {
    Write-Error "Failed to parse JSON: $_"
    exit 2
}

Write-Host "[*] Parsed $($db.entries.Count) entries, " `
           "$($db.known_system_dlls.Count) known_system_dlls, " `
           "$($db.revoked.Count) revoked hashes."
Write-Host ""

# ---------------------------------------------------------------------------
# Helper: locate a DLL on disk
# ---------------------------------------------------------------------------
function Find-DllPath {
    param([string]$DllName, [string]$TrustedPath)

    # 1. trusted_path from the entry
    if (-not [string]::IsNullOrEmpty($TrustedPath) -and (Test-Path $TrustedPath)) {
        return $TrustedPath
    }

    # 2. System32
    $sys32 = [System.Environment]::GetFolderPath('System')
    $candidate = Join-Path $sys32 $DllName
    if (Test-Path $candidate) { return $candidate }

    # 3. SysWOW64
    $windir = [System.Environment]::GetFolderPath('Windows')
    $candidate = Join-Path $windir "SysWOW64\$DllName"
    if (Test-Path $candidate) { return $candidate }

    return $null
}

# ---------------------------------------------------------------------------
# Helper: compute SHA-256 hex string from a file
# ---------------------------------------------------------------------------
function Get-SHA256File {
    param([string]$FilePath)
    $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
    return $hash.Hash.ToLower()
}

# ---------------------------------------------------------------------------
# Helper: compute SHA-256 hex string from a string's UTF-8 bytes
# ---------------------------------------------------------------------------
function Get-SHA256String {
    param([string]$Content)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes  = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $hash   = $sha256.ComputeHash($bytes)
    $sha256.Dispose()
    return ([System.BitConverter]::ToString($hash) -replace '-','').ToLower()
}

# ---------------------------------------------------------------------------
# Process entries
# ---------------------------------------------------------------------------
$skipped = 0
$updated = 0
$unchanged = 0

foreach ($entry in $db.entries) {
    $name = $entry.dll_name
    Write-Host -NoNewline "  [~] $($name.PadRight(25)) ... "

    # Skip if hash already present and --Force not set
    if (-not $Force -and -not [string]::IsNullOrEmpty($entry.sha256)) {
        Write-Host "already hashed (use -Force to re-compute)"
        $unchanged++
        continue
    }

    $dllPath = Find-DllPath -DllName $name -TrustedPath $entry.trusted_path
    if ($null -eq $dllPath) {
        Write-Host "NOT FOUND (skipped)"
        $skipped++
        continue
    }

    try {
        $newHash = Get-SHA256File -FilePath $dllPath
    } catch {
        Write-Host "HASH ERROR: $_  (skipped)"
        $skipped++
        continue
    }

    $oldHash = $entry.sha256
    $entry.sha256       = $newHash
    $entry.trusted_path = $dllPath       # update to resolved path
    $entry.version      = (Get-Item $dllPath).VersionInfo.FileVersion

    if ([string]::IsNullOrEmpty($oldHash)) {
        Write-Host "ok  [$($newHash.Substring(0,16))...]"
    } elseif ($oldHash -eq $newHash) {
        Write-Host "verified  [$($newHash.Substring(0,16))...]"
    } else {
        Write-Host "UPDATED  (was $($oldHash.Substring(0,16))...)"
    }
    $updated++
}

Write-Host ""

# ---------------------------------------------------------------------------
# Update last_updated timestamp
# ---------------------------------------------------------------------------
$db.last_updated = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

# ---------------------------------------------------------------------------
# Compute integrity hash
# First serialize with db_integrity_hash = "" to get canonical content.
# ---------------------------------------------------------------------------
$db.db_integrity_hash = ""

# Use Depth=10 to ensure nested objects are fully serialized
$canonicalJson = $db | ConvertTo-Json -Depth 10

$integrityHash = Get-SHA256String -Content $canonicalJson

$db.db_integrity_hash = $integrityHash
$finalJson = $db | ConvertTo-Json -Depth 10

# ---------------------------------------------------------------------------
# Write updated file (UTF-8 without BOM)
# ---------------------------------------------------------------------------
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($DatabasePath, $finalJson, $utf8NoBom)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host "[+] Database updated successfully."
Write-Host "    Entries hashed   : $updated"
Write-Host "    Already present  : $unchanged"
Write-Host "    Skipped (missing): $skipped"
Write-Host "    Integrity hash   : $($integrityHash.Substring(0,8))...$($integrityHash.Substring(56,8))"
Write-Host "    Output           : $DatabasePath"

exit $(if ($skipped -gt 0) { 1 } else { 0 })
