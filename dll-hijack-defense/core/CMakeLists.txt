# =============================================================================
# Module: core
# Contains: SecureLoader (BLOCO 3), DLLValidator (BLOCO 4),
#           DefenseSystem integration facade (BLOCO 10)
# =============================================================================
cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# Source files
# secure_loader.cpp — implemented in BLOCO 3
# dll_validator.cpp — implemented in BLOCO 4 (add to list when ready)
# ---------------------------------------------------------------------------
set(CORE_SOURCES
    secure_loader.cpp
    dll_validator.cpp
    defense_system.cpp
    hardening.cpp       # BLOCO 12 — ACL hardening + integrity verification
)

# ---------------------------------------------------------------------------
# Static library
# ---------------------------------------------------------------------------
add_library(core STATIC ${CORE_SOURCES})

# ---------------------------------------------------------------------------
# Include paths
# PUBLIC: consumers of 'core' also get the shared/ and core/ headers
# ---------------------------------------------------------------------------
target_include_directories(core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/shared
)

# ---------------------------------------------------------------------------
# Link against the shared module (PolicyManager) and Windows system libs
# ---------------------------------------------------------------------------
# wintrust    — WinVerifyTrust (Authenticode)     [used by dll_validator]
# crypt32     — Certificate chain / CRL / OCSP   [used by dll_validator]
# bcrypt      — SHA-256 hash computation          [used by dll_validator, hardening]
# advapi32    — Registry, ACL queries             [used by dll_validator]
# aclapi      — SetNamedSecurityInfoW, GetNamedSecurityInfoW [used by hardening]
# shlwapi     — Path helpers (PathIsRelativeW, PathCanonicalizeW, etc.)
# psapi       — GetModuleFileNameW for loaded module path verification
# ---------------------------------------------------------------------------
target_link_libraries(core
    PUBLIC
        shared
        intelligence   # LoggingEngine + RiskAnalyzer (used by defense_system)
        monitor        # RuntimeMonitor (used by defense_system)
        wintrust
        crypt32
        bcrypt
        advapi32
        shlwapi
        psapi
)
