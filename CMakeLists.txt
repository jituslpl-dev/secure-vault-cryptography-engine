# ============================================================================
# SecureVault — CMake Build Configuration
# ============================================================================
# Supports both standalone C++ builds (library + tests + benchmarks)
# and Node.js N-API addon builds via node-gyp.
# ============================================================================

cmake_minimum_required(VERSION 3.16)
project(SecureVault VERSION 1.0.0 LANGUAGES CXX)

# ─── C++ Standard ───────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Build Options ─────────────────────────────────────────────────
option(SECUREVAULT_BUILD_TESTS     "Build unit and integration tests" ON)
option(SECUREVAULT_BUILD_BENCHMARKS "Build benchmark suite" ON)
option(SECUREVAULT_BUILD_FUZZER    "Build fuzz tests" ON)
option(SECUREVAULT_BUILD_ADDON     "Build Node.js N-API addon" OFF)
option(SECUREVAULT_ENABLE_ASAN     "Enable AddressSanitizer" OFF)
option(SECUREVAULT_ENABLE_UBSAN    "Enable UndefinedBehaviorSanitizer" OFF)

# ─── Sanitizer Flags ───────────────────────────────────────────────
if(SECUREVAULT_ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address)
    message(STATUS "AddressSanitizer enabled")
endif()

if(SECUREVAULT_ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=undefined)
    message(STATUS "UndefinedBehaviorSanitizer enabled")
endif()

# ─── Optimization ──────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3)
    if(MSVC)
        add_compile_options(/O2 /favor:INTEL64)
    else()
        add_compile_options(-march=native)
    endif()
endif()

# ─── Core Library ──────────────────────────────────────────────────
set(SECUREVAULT_SOURCES
    src/sha256.cpp
    src/aes256.cpp
    src/encryption_engine.cpp
    src/time_lock.cpp
    src/streaming_engine.cpp
    src/logger.cpp
)

set(SECUREVAULT_HEADERS
    src/sha256.h
    src/aes256.h
    src/encryption_engine.h
    src/time_lock.h
    src/streaming_engine.h
    src/logger.h
)

add_library(securevault_core STATIC ${SECUREVAULT_SOURCES} ${SECUREVAULT_HEADERS})
target_include_directories(securevault_core PUBLIC src)

# ─── N-API Addon (optional) ────────────────────────────────────────
if(SECUREVAULT_BUILD_ADDON)
    # Find node-addon-api headers
    execute_process(
        COMMAND node -p "require('path').dirname(require.resolve('node-addon-api'))"
        OUTPUT_VARIABLE NODE_ADDON_API_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    add_library(secure_vault SHARED
        ${SECUREVAULT_SOURCES}
        src/addon.cpp
    )
    target_include_directories(secure_vault PRIVATE ${NODE_ADDON_API_DIR})
    target_compile_definitions(secure_vault PRIVATE NAPI_DISABLE_CPP_EXCEPTIONS)
    set_target_properties(secure_vault PROPERTIES
        PREFIX ""
        SUFFIX ".node"
    )
endif()

# ─── Tests ─────────────────────────────────────────────────────────
if(SECUREVAULT_BUILD_TESTS)
    enable_testing()

    # Unit tests (C++)
    add_executable(securevault_tests
        tests/test_sha256.cpp
        tests/test_aes256.cpp
        tests/test_encryption_engine.cpp
        tests/test_time_lock.cpp
        tests/test_streaming.cpp
        tests/test_fuzz.cpp
        tests/test_main.cpp
    )
    target_link_libraries(securevault_tests PRIVATE securevault_core)

    # Integration tests (C++)
    add_executable(securevault_integration
        tests/test_integration.cpp
    )
    target_link_libraries(securevault_integration PRIVATE securevault_core)

    add_test(NAME SecureVaultUnitTests COMMAND securevault_tests)
    add_test(NAME SecureVaultIntegration COMMAND securevault_integration)
endif()

# ─── Benchmarks ────────────────────────────────────────────────────
if(SECUREVAULT_BUILD_BENCHMARKS)
    add_executable(securevault_bench
        tests/benchmark.cpp
    )
    target_link_libraries(securevault_bench PRIVATE securevault_core)
endif()

# ─── Fuzz Tests ────────────────────────────────────────────────────
if(SECUREVAULT_BUILD_FUZZER)
    add_executable(securevault_fuzz
        tests/fuzz_main.cpp
    )
    target_link_libraries(securevault_fuzz PRIVATE securevault_core)
    if(NOT MSVC)
        target_compile_options(securevault_fuzz PRIVATE -fsanitize=fuzzer)
        target_link_options(securevault_fuzz PRIVATE -fsanitize=fuzzer)
    endif()
endif()

# ─── Install ───────────────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS securevault_core
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES ${SECUREVAULT_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/securevault
)

# ─── pkg-config ────────────────────────────────────────────────────
configure_file(
    cmake/securevault.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/securevault.pc
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/securevault.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)



