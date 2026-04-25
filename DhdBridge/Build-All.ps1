# =============================================================================
# Build-All.ps1
# Builds the native C++ static libs (cmake/MSBuild) then the C++/CLI bridge.
#
# Usage (from repo root or from the DhdBridge folder):
#   .\Build-All.ps1
#
# Prerequisites (installed by winget):
#   - VS 2022 Build Tools with workloads:
#       Microsoft.VisualStudio.Workload.VCTools
#       Microsoft.VisualStudio.Component.VC.CLI.Support
#       Microsoft.VisualStudio.Component.Windows11SDK.22621
#       Microsoft.VisualStudio.Component.VC.CMake.Project
# =============================================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 0. Locate vswhere
# ---------------------------------------------------------------------------
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vsWhere)) {
    Write-Error "vswhere.exe not found. Is VS 2022 Build Tools installed?"
}

$vsInstallPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstallPath) {
    Write-Error "No VS installation with VC++ tools found."
}

Write-Host "[BUILD] VS install path: $vsInstallPath" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Set up MSVC environment (x64 native)
# ---------------------------------------------------------------------------
$vcvarsall = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path $vcvarsall)) {
    Write-Error "vcvarsall.bat not found at: $vcvarsall"
}

# Import MSVC environment into this PowerShell session
Write-Host "[BUILD] Importing MSVC x64 environment..." -ForegroundColor Cyan
$envBlock = cmd /c "`"$vcvarsall`" x64 > nul 2>&1 && set"
foreach ($line in $envBlock) {
    if ($line -match '^([^=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}

# Verify cmake and msbuild are now on PATH
$cmake   = Get-Command cmake   -ErrorAction Stop
$msbuild = Get-Command msbuild -ErrorAction Stop
Write-Host "[BUILD] cmake   : $($cmake.Source)"   -ForegroundColor Green
Write-Host "[BUILD] msbuild : $($msbuild.Source)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Build native C++ static libs via cmake
# ---------------------------------------------------------------------------
$repoRoot     = Split-Path -Parent $PSScriptRoot
$nativeDir    = Join-Path $repoRoot "dll-hijack-defense"
$nativeBuild  = Join-Path $nativeDir "build"

Write-Host "`n[BUILD] === Step 1: CMake configure ===" -ForegroundColor Yellow
Push-Location $nativeDir
    cmake -S . -B build `
          -G "Visual Studio 17 2022" `
          -A x64 `
          -DCMAKE_BUILD_TYPE=Release
    if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Error "CMake configure failed (exit $LASTEXITCODE)" }
Pop-Location

Write-Host "`n[BUILD] === Step 2: CMake build (Release) ===" -ForegroundColor Yellow
cmake --build $nativeBuild --config Release --parallel
if ($LASTEXITCODE -ne 0) { Write-Error "CMake build failed (exit $LASTEXITCODE)" }

# Confirm libs exist
$libDir = Join-Path $nativeBuild "lib\Release"
$expectedLibs = @("core.lib","intelligence.lib","monitor.lib","audit.lib","shared.lib")
foreach ($lib in $expectedLibs) {
    $libPath = Join-Path $libDir $lib
    if (-not (Test-Path $libPath)) {
        Write-Error "Expected lib not found after build: $libPath"
    }
    Write-Host "[BUILD]   Found: $libPath" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 3. Build C++/CLI Bridge (DhdBridge.dll) via msbuild
# ---------------------------------------------------------------------------
Write-Host "`n[BUILD] === Step 3: DhdBridge.dll (C++/CLI) ===" -ForegroundColor Yellow
$bridgeProj = Join-Path $PSScriptRoot "DhdBridge.vcxproj"
if (-not (Test-Path $bridgeProj)) {
    Write-Error "DhdBridge.vcxproj not found at: $bridgeProj"
}

msbuild $bridgeProj `
    /p:Configuration=Release `
    /p:Platform=x64 `
    /p:SolutionDir="$repoRoot\" `
    /m `
    /nologo `
    /verbosity:minimal

if ($LASTEXITCODE -ne 0) { Write-Error "DhdBridge build failed (exit $LASTEXITCODE)" }

$bridgeOut = Join-Path $repoRoot "build\DhdBridge\Release\DhdBridge.dll"
if (Test-Path $bridgeOut) {
    Write-Host "`n[BUILD] SUCCESS: $bridgeOut" -ForegroundColor Green
} else {
    Write-Error "DhdBridge.dll not found at expected location: $bridgeOut"
}

Write-Host "`n[BUILD] All done." -ForegroundColor Cyan
Write-Host "  Native libs : $libDir"
Write-Host "  Bridge DLL  : $bridgeOut"
