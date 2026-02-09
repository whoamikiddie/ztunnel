cmake_minimum_required(VERSION 3.16)
project(zcrypto VERSION 0.1.0 LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Detect architecture
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(ARCH_X64 TRUE)
    message(STATUS "Building for x86-64 with SIMD optimizations")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
    set(ARCH_ARM64 TRUE)
    message(STATUS "Building for ARM64")
else()
    message(STATUS "Building generic (no ASM optimizations)")
endif()

# Source files
set(SOURCES
    src/chacha20.cpp
    src/poly1305.cpp
    src/x25519.cpp
    src/hkdf.cpp
    src/ffi.cpp
)

# Add ASM files for x86-64
if(ARCH_X64)
    enable_language(ASM)
    list(APPEND SOURCES
        src/chacha20_x64.S
    )
    add_compile_definitions(ZCRYPTO_USE_ASM)
endif()

# Library
add_library(zcrypto STATIC ${SOURCES})
target_include_directories(zcrypto PUBLIC include)

# Compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(zcrypto PRIVATE
        -Wall -Wextra -Wpedantic
        -fno-exceptions
        -fno-rtti
    )
    if(ARCH_X64)
        target_compile_options(zcrypto PRIVATE -mavx2)
    endif()
endif()

# Tests
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_executable(test_crypto tests/test_crypto.cpp)
    target_link_libraries(test_crypto zcrypto)
    add_test(NAME crypto_tests COMMAND test_crypto)
endif()

# Install
install(TARGETS zcrypto
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)
install(FILES include/zcrypto.hpp DESTINATION include)
