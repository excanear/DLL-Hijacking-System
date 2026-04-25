# =============================================================================
# DLL Hijacking Defense System
# Root CMakeLists.txt
# =============================================================================
cmake_minimum_required(VERSION 3.20)

project(DLLHijackDefense
    VERSION 1.0.0
    DESCRIPTION "DLL Hijacking Prevention, Detection and Audit System"
    LANGUAGES CXX
)

# ---------------------------------------------------------------------------
# Guard: Windows-only project
# ---------------------------------------------------------------------------
if(NOT WIN32)
    message(FATAL_ERROR "DLLHijackDefense targets Windows only.")
endif()

# ---------------------------------------------------------------------------
# C++17 — no compiler extensions
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Output directories
# ---------------------------------------------------------------------------
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ---------------------------------------------------------------------------
# Windows target: Windows 10+ (0x0A00)
# ---------------------------------------------------------------------------
add_compile_definitions(
    WINVER=0x0A00
    _WIN32_WINNT=0x0A00
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    STRICT                  # Enforce strict type checking for Win32 handles
)

# ---------------------------------------------------------------------------
# MSVC security flags
# ---------------------------------------------------------------------------
if(MSVC)
    # Compiler security flags
    add_compile_options(
        /GS             # Buffer Security Check (stack canary)
        /guard:cf       # Control Flow Guard — forward-edge protection
        /sdl            # Additional SDL security checks (superset of /GS)
        /W4             # High warning level
        /WX             # Treat warnings as errors
        /permissive-    # ISO C++ conformance mode
        /Gy             # Function-level linking (required for /GUARD:CF)
        /Zi             # Debug information (PDB) — even in Release for forensics
    )

    # Linker security flags
    add_link_options(
        /DYNAMICBASE    # ASLR — randomize base address at load time
        /NXCOMPAT       # DEP — mark stack/heap as non-executable
        /GUARD:CF       # Control Flow Guard enforcement at link time
        /HIGHENTROPYVA  # 64-bit ASLR with high-entropy addresses
        /LTCG           # Link-Time Code Generation (also enables WPO)
    )

    # Disable insecure CRT functions — force use of _s variants
    add_compile_definitions(
        _CRT_SECURE_NO_WARNINGS=0
        _SCL_SECURE_NO_WARNINGS=0
    )

    # Release: full optimization + whole-program optimization
    string(REPLACE "/O2" "/O2 /GL" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
endif()

# ---------------------------------------------------------------------------
# Shared include path (types, constants, contracts between modules)
# ---------------------------------------------------------------------------
include_directories(${CMAKE_SOURCE_DIR}/shared)

# ---------------------------------------------------------------------------
# Testing support
# ---------------------------------------------------------------------------
if(BUILD_TESTING)
    enable_testing()
endif()

# ---------------------------------------------------------------------------
# Submodules
# ---------------------------------------------------------------------------
add_subdirectory(shared)
add_subdirectory(core)
add_subdirectory(monitor)
add_subdirectory(intelligence)
add_subdirectory(audit)
add_subdirectory(tools)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install rules (optional — for deployment packaging)
# ---------------------------------------------------------------------------
install(DIRECTORY ${CMAKE_BINARY_DIR}/bin/ DESTINATION bin)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/config/ DESTINATION config)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/policy/ DESTINATION policy)
