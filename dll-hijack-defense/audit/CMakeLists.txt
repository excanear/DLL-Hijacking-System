# =============================================================================
# Module: audit
# Contains: AuditScanner (offline PE parser, ACL checker, report generator)
# =============================================================================
cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# Source files — populated in BLOCO 8
# ---------------------------------------------------------------------------
set(AUDIT_SOURCES
    audit_scanner.cpp
)

# ---------------------------------------------------------------------------
# Static library target — INTERFACE placeholder until sources are added
# ---------------------------------------------------------------------------
if(AUDIT_SOURCES)
    add_library(audit STATIC ${AUDIT_SOURCES})
else()
    add_library(audit INTERFACE)
    message(STATUS "[audit] No source files yet — INTERFACE placeholder active")
endif()

# ---------------------------------------------------------------------------
# Executable: standalone audit scanner (runs as scheduled task / CLI tool)
# Uncomment once source files are available in BLOCO 8
# ---------------------------------------------------------------------------
add_executable(audit_scanner_cli audit_scanner_main.cpp)
target_link_libraries(audit_scanner_cli PRIVATE audit shared imagehlp advapi32 shlwapi)
target_include_directories(audit_scanner_cli PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/shared
)

# ---------------------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------------------
if(TARGET audit AND NOT audit MATCHES INTERFACE)
    target_include_directories(audit
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/shared
    )
else()
    target_include_directories(audit INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/shared
    )
endif()

# ---------------------------------------------------------------------------
# Windows system libraries required by this module
# ---------------------------------------------------------------------------
# imagehlp    — MapAndLoad, UnMapAndLoad for PE parsing
# advapi32    — GetNamedSecurityInfoW, ACL traversal
# shlwapi     — Path helpers
# ---------------------------------------------------------------------------
set(AUDIT_SYSTEM_LIBS
    imagehlp
    advapi32
    shlwapi
)

if(TARGET audit AND NOT audit MATCHES INTERFACE)
    target_link_libraries(audit
        PUBLIC  ${AUDIT_SYSTEM_LIBS}
        PRIVATE core intelligence
    )
else()
    target_link_libraries(audit INTERFACE
        ${AUDIT_SYSTEM_LIBS}
        core
        intelligence
    )
endif()
