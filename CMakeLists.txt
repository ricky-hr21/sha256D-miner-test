cmake_minimum_required(VERSION 3.10.0)
project(sha256-miner VERSION 0.1.0 LANGUAGES C CXX)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBTC QUIET libbtc)

# Cari library OpenSSL di sistem
find_package(OpenSSL REQUIRED)

include_directories(${LIBBTC_INCLUDE_DIRS})
link_directories(${LIBBTC_LIBRARY_DIRS})
add_definitions(${LIBBTC_CFLAGS_OTHER})

add_executable(sha256-miner main.cpp
                            hash_openssl.cpp)

target_link_libraries(sha256-miner PRIVATE OpenSSL::Crypto ${LIBBTC_LIBRARIES})

# (Opsional) Tambahkan optimasi dan akselerasi CPU
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    message(STATUS "Targeting ARM64: enabling crypto extensions")
    target_compile_options(sha256-miner PRIVATE -O3 -march=armv8-a+crypto)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    message(STATUS "Targeting x86_64: enabling SHA-NI")
    target_compile_options(sha256-miner PRIVATE -O3 -march=native)
else()
    target_compile_options(sha256-miner PRIVATE -O3)
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
