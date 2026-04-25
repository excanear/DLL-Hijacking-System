# =============================================================================
# Module: shared
# Contains: types.h (header-only), constants.h (header-only), policy.h/.cpp
# All other modules link against this as a static library for policy.cpp.
# =============================================================================
cmake_minimum_required(VERSION 3.20)

add_library(shared STATIC
    policy.cpp
)

target_include_directories(shared
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# shlwapi — PathIsPrefix used in PolicyManager::IsPathInWhitelist / IsPathBlocked
target_link_libraries(shared PUBLIC shlwapi)
