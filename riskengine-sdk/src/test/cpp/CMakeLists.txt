cmake_minimum_required(VERSION 3.16)
project(riskengine_cpp_host_tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CheckIncludeFileCXX)
enable_testing()

option(RISKENGINE_USE_SYSTEM_GTEST "Use system GTest when installed offline (never FetchContent)" ON)

set(RISKENGINE_USE_GTEST 0)
set(RISKENGINE_GTEST_TARGETS "")
if(RISKENGINE_USE_SYSTEM_GTEST)
    find_package(GTest QUIET)
    if(GTest_FOUND AND TARGET GTest::gtest_main)
        set(RISKENGINE_USE_GTEST 1)
        set(RISKENGINE_GTEST_TARGETS GTest::gtest_main)
        message(STATUS "RiskEngine L2 C++ tests: using system GTest (GTest::gtest_main)")
    elseif(GTest_FOUND AND TARGET GTest::GTest AND TARGET GTest::Main)
        set(RISKENGINE_USE_GTEST 1)
        set(RISKENGINE_GTEST_TARGETS GTest::GTest GTest::Main)
        message(STATUS "RiskEngine L2 C++ tests: using system GTest (GTest::GTest + GTest::Main)")
    else()
        message(STATUS "RiskEngine L2 C++ tests: system GTest not found; using offline mini_gtest.h")
    endif()
endif()

set(MAIN_CPP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../main/cpp")
set(HOST_SHIMS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/host_shims")

check_include_file_cxx("elf.h" HAVE_SYSTEM_ELF_H)
check_include_file_cxx("link.h" HAVE_SYSTEM_LINK_H)
check_include_file_cxx("sys/vfs.h" HAVE_SYSTEM_SYS_VFS_H)

function(configure_riskengine_host_test target_name)
    # Unconditionally prepend Android-ABI-compatible JNI shim (`struct JNINativeInterface`
    # without trailing underscore, matching Android NDK <jni.h> rather than OpenJDK <jni.h>).
    target_include_directories(${target_name} BEFORE PRIVATE "${HOST_SHIMS_DIR}/jni")
    target_include_directories(${target_name} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${MAIN_CPP_DIR}"
    )
    if(NOT (HAVE_SYSTEM_ELF_H AND HAVE_SYSTEM_LINK_H AND HAVE_SYSTEM_SYS_VFS_H))
        target_include_directories(${target_name} PRIVATE "${HOST_SHIMS_DIR}/linux")
    endif()
    target_compile_definitions(${target_name} PRIVATE
        RISKENGINE_HOST_TEST=1
        RISKENGINE_USING_SYSTEM_GTEST=${RISKENGINE_USE_GTEST}
    )
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_definitions(${target_name} PRIVATE _GNU_SOURCE)
    endif()
    target_compile_options(${target_name} PRIVATE
        -Wall -Wextra -Wno-unused-function -Wno-unused-parameter
    )
    target_link_libraries(${target_name} PRIVATE ${CMAKE_DL_LIBS})
    if(RISKENGINE_USE_GTEST)
        target_link_libraries(${target_name} PRIVATE ${RISKENGINE_GTEST_TARGETS})
    endif()
    add_test(NAME ${target_name} COMMAND ${target_name})
endfunction()

# Suite 1: maps_parser (>4 MiB streaming), raw_dir fuzz vectors, payload_codec round-trip
add_executable(test_parsers_and_codec
    test_parsers_and_codec.cpp
    "${MAIN_CPP_DIR}/util/maps_parser.cpp"
    "${MAIN_CPP_DIR}/util/raw_dir.cpp"
    "${MAIN_CPP_DIR}/util/payload_codec.cpp"
)
configure_riskengine_host_test(test_parsers_and_codec)

# Suite 2: crypto_mini (SHA-256, ct_memcmp, secure_zero) + 4-ABI looks_like_trampoline
add_executable(test_integrity_and_crypto
    test_integrity_and_crypto.cpp
    "${MAIN_CPP_DIR}/util/maps_parser.cpp"
    "${MAIN_CPP_DIR}/util/payload_codec.cpp"
)
configure_riskengine_host_test(test_integrity_and_crypto)

# Suite 3: bionic_prop_area (HoleRun, dirty serial, NUL tail, API-30 dirty_backup) + DiskElf 16KB/SHF_EXECINSTR/PT_LOAD
add_executable(test_prop_area_and_elf
    test_prop_area_and_elf.cpp
    "${MAIN_CPP_DIR}/detector/bionic_prop_area.cpp"
    "${MAIN_CPP_DIR}/util/maps_parser.cpp"
    "${MAIN_CPP_DIR}/util/payload_codec.cpp"
)
configure_riskengine_host_test(test_prop_area_and_elf)
