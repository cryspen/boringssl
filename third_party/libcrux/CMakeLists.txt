# cmake -B build -G "Ninja Multi-Config"
# cmake --build build
# # For release (benchmarks)
# cmake --build build --config Release

cmake_minimum_required(VERSION 3.10)

project(libcrux-ml-kem
    VERSION 0.1.0
    LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

if(NOT MSVC)
    add_compile_options(
        -Wall

        # -Wextra
        # -pedantic
        # -Wconversion
        # -Wsign-conversion
        $<$<CONFIG:DEBUG>:-g>
        $<$<CONFIG:DEBUG>:-Og>
        $<$<CONFIG:RELEASE>:-g>
        $<$<CONFIG:RELEASE>:-O3>
    )
endif(NOT MSVC)

set(CMAKE_COLOR_DIAGNOSTICS "ON")
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/internal
    ${PROJECT_SOURCE_DIR}/karamel/include

    # # The external API
    # ${PROJECT_SOURCE_DIR}/api

    # # BoringSSL
    # ${PROJECT_SOURCE_DIR}/../..
    # ${PROJECT_SOURCE_DIR}/../../include
)
file(GLOB SOURCES
    ${PROJECT_SOURCE_DIR}/src/libcrux_core.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_platform.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_mlkem512.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_mlkem768.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_mlkem1024.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_mlkem_portable.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_mlkem512_portable.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_mlkem768_portable.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_mlkem1024_portable.c

    # # The external API
    # ${PROJECT_SOURCE_DIR}/api/Libcrux_Kem_ML_KEM768.c
)
file(GLOB SOURCES_vec256
    ${PROJECT_SOURCE_DIR}/src/libcrux_mlkem_avx2.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_mlkem512_avx2.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_mlkem768_avx2.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_mlkem1024_avx2.c
    ${PROJECT_SOURCE_DIR}/src/libcrux_sha3_avx2.c
)

if(${CMAKE_SYSTEM_NAME} MATCHES Linux)
    add_compile_options(
        -fPIC
        -flto
    )
    add_link_options(-flto)
endif(${CMAKE_SYSTEM_NAME} MATCHES Linux)

add_library(ml_kem SHARED ${SOURCES})
add_library(ml_kem_static STATIC ${SOURCES})

# This is only for local testing and we assume avx2 on x64.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    message(STATUS "Detected an x64 architecture")
    add_compile_definitions(LIBCRUX_X64 OPENSSL_X86_64)

    add_library(ml_kem_vec256 OBJECT ${SOURCES_vec256})
    target_sources(ml_kem_static PRIVATE $<TARGET_OBJECTS:ml_kem_vec256>)
    target_sources(ml_kem PRIVATE $<TARGET_OBJECTS:ml_kem_vec256>)

    if(NOT MSVC)
        target_compile_options(ml_kem_vec256 PRIVATE
            -mavx
            -mavx2
        )
    endif(NOT MSVC)
endif()

# --- Tests

# # For Windows: Prevent overriding the parent project's compiler/linker settings
# set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# # Get gtests
# include(FetchContent)
# FetchContent_Declare(googletest
#     DOWNLOAD_EXTRACT_TIMESTAMP TRUE
#     URL https://github.com/google/googletest/archive/refs/tags/release-1.11.0.zip
# )

# FetchContent_MakeAvailable(googletest)

# # Get nlohmann json
# FetchContent_Declare(json
#     DOWNLOAD_EXTRACT_TIMESTAMP TRUE
#     URL https://github.com/nlohmann/json/archive/refs/tags/v3.10.3.zip
# )
# FetchContent_MakeAvailable(json)

# add_executable(ml_kem_test
#     ${PROJECT_SOURCE_DIR}/tests/mlkem768.cc
# )
# target_link_libraries(ml_kem_test PRIVATE
#     ml_kem_static
#     gtest_main
#     nlohmann_json::nlohmann_json
# )

# --- Benchmarks
# FetchContent_Declare(benchmark
# GIT_REPOSITORY https://github.com/google/benchmark.git
# GIT_TAG v1.8.4
# )
# FetchContent_MakeAvailable(benchmark)

# add_executable(ml_kem_bench
# ${PROJECT_SOURCE_DIR}/benches/mlkem768.cc
# )
# target_link_libraries(ml_kem_bench PRIVATE
# ml_kem_static
# benchmark::benchmark
# )
