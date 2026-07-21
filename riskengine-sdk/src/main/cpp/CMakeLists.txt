cmake_minimum_required(VERSION 3.22.1)
project("riskengine")

add_library(riskengine SHARED
    riskengine_jni.cpp
    util/syscall_wrapper.cpp
    collector/drm_collector.cpp
    collector/system_property_collector.cpp
    collector/boot_id_collector.cpp
    collector/cpu_info_collector.cpp
    collector/disk_size_collector.cpp
    collector/kernel_info_collector.cpp
    detector/native_root_detector.cpp
    detector/native_hook_detector.cpp
    detector/native_emulator_detector.cpp
    detector/native_debug_detector.cpp
    detector/runtime_arch_checker.cpp
    util/custom_jni_register.cpp
)

target_include_directories(riskengine PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Support 4 KiB/16 KiB pages and minimize the exported native attack surface.
target_link_options(riskengine PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,relro,-z,now"
    "-Wl,--exclude-libs,ALL"
)
