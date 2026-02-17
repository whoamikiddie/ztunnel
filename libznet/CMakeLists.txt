cmake_minimum_required(VERSION 3.16)
project(znet C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Detect architecture for ASM support
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    set(ZNET_HAS_ASM ON)
    enable_language(ASM)
    message(STATUS "x86-64 ASM support enabled for znet")
else()
    set(ZNET_HAS_ASM OFF)
    message(STATUS "ASM not available for ${CMAKE_SYSTEM_PROCESSOR}, using C fallback")
endif()

# Source files
set(ZNET_SOURCES
    src/udp_engine.c
    src/throttle.c
    src/connpool.c
)

if(ZNET_HAS_ASM)
    list(APPEND ZNET_SOURCES src/throttle_x64.S)
endif()

# Build static library
add_library(znet STATIC ${ZNET_SOURCES})
target_include_directories(znet PUBLIC include)

# Compiler flags
target_compile_options(znet PRIVATE
    -Wall -Wextra -Werror -O2
    -fPIC
)

# Define _GNU_SOURCE for Linux features (mmsghdr, recvmmsg, sendmmsg)
target_compile_definitions(znet PRIVATE _GNU_SOURCE)

if(ZNET_HAS_ASM)
    target_compile_definitions(znet PRIVATE ZNET_HAS_ASM=1)
endif()

# Tests
option(ZNET_BUILD_TESTS "Build znet tests" ON)
if(ZNET_BUILD_TESTS)
    enable_testing()
    add_executable(znet_test tests/test_all.c)
    target_link_libraries(znet_test PRIVATE znet)
    add_test(NAME znet_tests COMMAND znet_test)
endif()
