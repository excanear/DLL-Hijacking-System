# =============================================================================
# Module: intelligence
# Contains: RiskAnalyzer, LoggingEngine
# =============================================================================
cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# Source files — populated in BLOCO 5 (RiskAnalyzer) and BLOCO 6 (Logging)
# ---------------------------------------------------------------------------
set(INTELLIGENCE_SOURCES
    risk_analyzer.cpp
    logging_engine.cpp
)

# ---------------------------------------------------------------------------
# Static library target — INTERFACE placeholder until sources are added
# ---------------------------------------------------------------------------
if(INTELLIGENCE_SOURCES)
    add_library(intelligence STATIC ${INTELLIGENCE_SOURCES})
else()
    add_library(intelligence INTERFACE)
    message(STATUS "[intelligence] No source files yet — INTERFACE placeholder active")
endif()

# ---------------------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------------------
if(TARGET intelligence AND NOT intelligence MATCHES INTERFACE)
    target_include_directories(intelligence
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/shared
    )
else()
    target_include_directories(intelligence INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/shared
    )
endif()

# ---------------------------------------------------------------------------
# Windows system libraries required by this module
# ---------------------------------------------------------------------------
# bcrypt      — HMAC-SHA256 for log entry signing
# advapi32    — ReportEventW (Windows Event Log sink)
# shlwapi     — Path utility functions
# ---------------------------------------------------------------------------
set(INTELLIGENCE_SYSTEM_LIBS
    bcrypt
    advapi32
    shlwapi
    psapi
)

if(TARGET intelligence AND NOT intelligence MATCHES INTERFACE)
    target_link_libraries(intelligence
        PUBLIC  ${INTELLIGENCE_SYSTEM_LIBS}
        PRIVATE core
    )
else()
    target_link_libraries(intelligence INTERFACE
        ${INTELLIGENCE_SYSTEM_LIBS}
        core
    )
endif()

# ---------------------------------------------------------------------------
# JSON serialization — header-only nlohmann/json (vendored in BLOCO 6)
# Uncomment once vendored under third_party/json/
# ---------------------------------------------------------------------------
# target_include_directories(intelligence INTERFACE
#     ${CMAKE_SOURCE_DIR}/third_party/json/include
# )
