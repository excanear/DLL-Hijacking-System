# =============================================================================
# Module: monitor
# Contains: RuntimeMonitor (ETW + polling, ApprovedModuleSet)
# =============================================================================
cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# Source files — populated in BLOCO 7
# ---------------------------------------------------------------------------
set(MONITOR_SOURCES
    runtime_monitor.cpp
)

# ---------------------------------------------------------------------------
# Static library target — INTERFACE placeholder until sources are added
# ---------------------------------------------------------------------------
if(MONITOR_SOURCES)
    add_library(monitor STATIC ${MONITOR_SOURCES})
else()
    add_library(monitor INTERFACE)
    message(STATUS "[monitor] No source files yet — INTERFACE placeholder active")
endif()

# ---------------------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------------------
if(TARGET monitor AND NOT monitor MATCHES INTERFACE)
    target_include_directories(monitor
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/shared
    )
else()
    target_include_directories(monitor INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/shared
    )
endif()

# ---------------------------------------------------------------------------
# Windows system libraries required by this module
# ---------------------------------------------------------------------------
# psapi       — EnumProcessModules, GetModuleFileNameEx, GetModuleInformation
# tdh         — TDH (Trace Data Helper) for ETW consumer
# eventing    — ETW API (StartTrace, OpenTrace, ProcessTrace)
# advapi32    — OpenProcessToken, privilege manipulation for ETW
# ---------------------------------------------------------------------------
set(MONITOR_SYSTEM_LIBS
    psapi
    tdh
    advapi32
    shlwapi
)

if(TARGET monitor AND NOT monitor MATCHES INTERFACE)
    target_link_libraries(monitor
        PUBLIC  ${MONITOR_SYSTEM_LIBS}
        PRIVATE core
        PRIVATE intelligence
    )
else()
    target_link_libraries(monitor INTERFACE
        ${MONITOR_SYSTEM_LIBS}
        core
    )
endif()
