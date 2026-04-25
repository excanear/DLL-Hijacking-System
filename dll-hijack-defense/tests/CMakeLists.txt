# =============================================================================
# Module: tests
# Google Test via CMake FetchContent (no external install required).
# Run with: ctest --test-dir build -C Debug --output-on-failure
# =============================================================================
cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# GoogleTest — downloaded at configure time via FetchContent
# ---------------------------------------------------------------------------
include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
    GIT_SHALLOW    TRUE
)

# Prevent GoogleTest from overriding our compiler/linker settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Disable GoogleTest's own install rules to avoid polluting the install tree
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

include(GoogleTest)

# ---------------------------------------------------------------------------
# Shared include directories used by all test targets
# ---------------------------------------------------------------------------
set(DHD_TEST_INCLUDES
    ${CMAKE_SOURCE_DIR}/shared
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/intelligence
    ${CMAKE_SOURCE_DIR}/monitor
    ${CMAKE_SOURCE_DIR}/audit
)

# ===========================================================================
# test_policy — PolicyManager, scoring constants, threshold mapping
# ===========================================================================
add_executable(test_policy
    test_policy.cpp
)
target_include_directories(test_policy PRIVATE ${DHD_TEST_INCLUDES})
target_link_libraries(test_policy PRIVATE
    GTest::gtest_main
    shared
    shlwapi
)
gtest_discover_tests(test_policy)

# ===========================================================================
# test_validator — DLL Validator four-layer pipeline
# ===========================================================================
add_executable(test_validator
    test_validator.cpp
)
target_include_directories(test_validator PRIVATE ${DHD_TEST_INCLUDES})
target_link_libraries(test_validator PRIVATE
    GTest::gtest_main
    core        # SecureLoader + DLLValidator + DefenseSystem
    shared
    shlwapi
)
gtest_discover_tests(test_validator)

# ===========================================================================
# test_risk_analyzer — contextual risk rules R001-R007
# ===========================================================================
add_executable(test_risk_analyzer
    test_risk_analyzer.cpp
)
target_include_directories(test_risk_analyzer PRIVATE ${DHD_TEST_INCLUDES})
target_link_libraries(test_risk_analyzer PRIVATE
    GTest::gtest_main
    intelligence    # RiskAnalyzer + LoggingEngine
    core
    shared
)
gtest_discover_tests(test_risk_analyzer)

# ===========================================================================
# test_logging_engine — async queue, HMAC, flush, rotation
# ===========================================================================
add_executable(test_logging_engine
    test_logging_engine.cpp
)
target_include_directories(test_logging_engine PRIVATE ${DHD_TEST_INCLUDES})
target_link_libraries(test_logging_engine PRIVATE
    GTest::gtest_main
    intelligence
    shared
    shlwapi
)
gtest_discover_tests(test_logging_engine)

# ===========================================================================
# test_audit_scanner — PE import parsing, phantom DLL, report writing
# ===========================================================================
add_executable(test_audit_scanner
    test_audit_scanner.cpp
)
target_include_directories(test_audit_scanner PRIVATE ${DHD_TEST_INCLUDES})
target_link_libraries(test_audit_scanner PRIVATE
    GTest::gtest_main
    audit
    shared
    shlwapi
)
gtest_discover_tests(test_audit_scanner)

message(STATUS "[tests] Google Test targets configured (FetchContent v1.14.0)")
