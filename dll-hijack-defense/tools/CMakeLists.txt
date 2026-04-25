# =============================================================================
# Module: tools
# Contains: bootstrap_hashdb — offline tool to populate SHA-256 hashes in
#           config/hash_database.json on the reference deployment machine.
# =============================================================================
cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# bootstrap_hashdb — standalone executable (developer / deployment tool)
# Not linked into the defense system runtime; built separately.
# ---------------------------------------------------------------------------
add_executable(bootstrap_hashdb
    bootstrap_hashdb.cpp
)

target_include_directories(bootstrap_hashdb
    PRIVATE
        ${CMAKE_SOURCE_DIR}/shared
)

target_link_libraries(bootstrap_hashdb
    PRIVATE
        shared          # PolicyManager, types, constants (for tier1_paths, etc.)
        bcrypt
        shlwapi
)

# Inherit the global security compile/link flags from the root CMakeLists.
# No extra flags needed — bootstrap_hashdb follows the same hardening profile.

set_target_properties(bootstrap_hashdb PROPERTIES
    OUTPUT_NAME  "bootstrap_hashdb"
    FOLDER       "tools"
)
