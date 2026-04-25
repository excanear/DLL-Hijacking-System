#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets hardened ACLs on sensitive directories and files used by the
    DLL Hijacking Defense System.

.DESCRIPTION
    This deployment script restricts access to the log directory, policy
    file, and hash database to SYSTEM and Administrators only (with
    read-only access to Everyone for configuration files).

    It mirrors what core/hardening.cpp does at runtime, but is intended
    to be run once during initial deployment or after a directory reset.

    Requires Administrator rights (enforced by #Requires -RunAsAdministrator).

.PARAMETER InstallRoot
    The root folder of the deployed dll-hijack-defense installation.
    Defaults to the directory containing this script.

.PARAMETER LogDir
    Path to the log directory. Defaults to <InstallRoot>\logs.

.PARAMETER PolicyFile
    Path to the policy JSON file. Defaults to <InstallRoot>\policy\defaults.json.

.PARAMETER HashDb
    Path to the hash database JSON file. Defaults to <InstallRoot>\config\hash_database.json.

.PARAMETER WhatIf
    Show what changes would be made without applying them.

.EXAMPLE
    .\Set-Acls.ps1 -InstallRoot "C:\Program Files\DllHijackDefense"

.EXAMPLE
    .\Set-Acls.ps1 -WhatIf

.NOTES
    Exit codes:
        0 — All ACLs applied successfully
        1 — One or more ACL operations failed (partial hardening applied)
        2 — Fatal error (e.g., InstallRoot not found)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallRoot = $PSScriptRoot,
    [string] $LogDir      = '',
    [string] $PolicyFile  = '',
    [string] $HashDb      = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Resolve default paths
# ---------------------------------------------------------------------------
if (-not $LogDir)    { $LogDir    = Join-Path $InstallRoot 'logs' }
if (-not $PolicyFile){ $PolicyFile = Join-Path $InstallRoot 'policy\defaults.json' }
if (-not $HashDb)    { $HashDb     = Join-Path $InstallRoot 'config\hash_database.json' }

Write-Host ''
Write-Host '=== DLL Hijack Defense — ACL Hardening ===' -ForegroundColor Cyan
Write-Host "  Install root : $InstallRoot"
Write-Host "  Log dir      : $LogDir"
Write-Host "  Policy file  : $PolicyFile"
Write-Host "  Hash DB      : $HashDb"
Write-Host ''

if (-not (Test-Path $InstallRoot -PathType Container)) {
    Write-Error "InstallRoot does not exist: $InstallRoot"
    exit 2
}

$failCount = 0

# ---------------------------------------------------------------------------
# Helper: Get well-known SID objects
# ---------------------------------------------------------------------------
$sidSystem = [System.Security.Principal.SecurityIdentifier]'S-1-5-18'   # SYSTEM
$sidAdmins = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544' # Administrators
$sidEveryone = [System.Security.Principal.SecurityIdentifier]'S-1-1-0'  # Everyone

# ---------------------------------------------------------------------------
# Helper: Build a protected (non-inherited) DirectorySecurity object with
# SYSTEM + Admins = FullControl, no other access.
# ---------------------------------------------------------------------------
function New-LogDirectorySecurity {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity

    # Disable inheritance and remove all inherited ACEs
    $acl.SetAccessRuleProtection($true, $false)

    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit `
             -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $prop    = [System.Security.AccessControl.PropagationFlags]::None
    $allow   = [System.Security.AccessControl.AccessControlType]::Allow
    $full    = [System.Security.AccessControl.FileSystemRights]::FullControl

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sidSystem, $full, $inherit, $prop, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sidAdmins, $full, $inherit, $prop, $allow)))

    return $acl
}

# ---------------------------------------------------------------------------
# Helper: Build a protected FileSecurity for config/policy files.
# SYSTEM + Admins = FullControl, Everyone = Read.
# ---------------------------------------------------------------------------
function New-ConfigFileSecurity {
    $acl = New-Object System.Security.AccessControl.FileSecurity

    # Disable inheritance and remove all inherited ACEs
    $acl.SetAccessRuleProtection($true, $false)

    $no_inherit = [System.Security.AccessControl.InheritanceFlags]::None
    $prop       = [System.Security.AccessControl.PropagationFlags]::None
    $allow      = [System.Security.AccessControl.AccessControlType]::Allow
    $full       = [System.Security.AccessControl.FileSystemRights]::FullControl
    $read       = [System.Security.AccessControl.FileSystemRights]::Read

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sidSystem,   $full, $no_inherit, $prop, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sidAdmins,   $full, $no_inherit, $prop, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sidEveryone, $read, $no_inherit, $prop, $allow)))

    return $acl
}

# ---------------------------------------------------------------------------
# §1 — Log directory
# ---------------------------------------------------------------------------
Write-Host '[1/3] Hardening log directory...' -ForegroundColor Yellow

if (-not (Test-Path $LogDir -PathType Container)) {
    Write-Host "  Creating directory: $LogDir"
    if ($PSCmdlet.ShouldProcess($LogDir, 'Create directory')) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
}

try {
    $logAcl = New-LogDirectorySecurity
    if ($PSCmdlet.ShouldProcess($LogDir, 'Set hardened DACL (SYSTEM+Admins Full, no others)')) {
        Set-Acl -Path $LogDir -AclObject $logAcl
        Write-Host "  OK  $LogDir" -ForegroundColor Green
    } else {
        Write-Host "  WhatIf: would set DACL on $LogDir"
    }
} catch {
    Write-Warning "  FAILED to harden log directory: $_"
    $failCount++
}

# ---------------------------------------------------------------------------
# §2 — Policy file
# ---------------------------------------------------------------------------
Write-Host '[2/3] Hardening policy file...' -ForegroundColor Yellow

if (-not (Test-Path $PolicyFile -PathType Leaf)) {
    Write-Warning "  Policy file not found — skipping: $PolicyFile"
    $failCount++
} else {
    try {
        $policyAcl = New-ConfigFileSecurity
        if ($PSCmdlet.ShouldProcess($PolicyFile, 'Set hardened DACL (SYSTEM+Admins Full, Everyone Read)')) {
            Set-Acl -Path $PolicyFile -AclObject $policyAcl
            Write-Host "  OK  $PolicyFile" -ForegroundColor Green
        } else {
            Write-Host "  WhatIf: would set DACL on $PolicyFile"
        }
    } catch {
        Write-Warning "  FAILED to harden policy file: $_"
        $failCount++
    }
}

# ---------------------------------------------------------------------------
# §3 — Hash database
# ---------------------------------------------------------------------------
Write-Host '[3/3] Hardening hash database...' -ForegroundColor Yellow

if (-not (Test-Path $HashDb -PathType Leaf)) {
    Write-Warning "  Hash database not found — skipping: $HashDb"
    $failCount++
} else {
    try {
        $dbAcl = New-ConfigFileSecurity
        if ($PSCmdlet.ShouldProcess($HashDb, 'Set hardened DACL (SYSTEM+Admins Full, Everyone Read)')) {
            Set-Acl -Path $HashDb -AclObject $dbAcl
            Write-Host "  OK  $HashDb" -ForegroundColor Green
        } else {
            Write-Host "  WhatIf: would set DACL on $HashDb"
        }
    } catch {
        Write-Warning "  FAILED to harden hash database: $_"
        $failCount++
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ''
if ($failCount -eq 0) {
    Write-Host 'All ACLs applied successfully.' -ForegroundColor Green
    exit 0
} else {
    Write-Warning "$failCount ACL operation(s) failed — review warnings above."
    exit 1
}
