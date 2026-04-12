cmake_minimum_required(VERSION 3.22.1)
project("riskengine")

add_library(riskengine SHARED
    riskengine_jni.cpp
    util/syscall_wrapper.cpp
    util/elf_parser.cpp
    collector/drm_collector.cpp
    collector/system_property_collector.cpp
    collector/boot_id_collector.cpp
    collector/cpu_info_collector.cpp
    collector/disk_size_collector.cpp
    collector/mac_netlink_collector.cpp
    collector/kernel_info_collector.cpp
    detector/native_root_detector.cpp
    detector/native_hook_detector.cpp
    detector/native_emulator_detector.cpp
    detector/native_debug_detector.cpp
    detector/native_signature_checker.cpp
    detector/seccomp_arch_checker.cpp
    antitamper/memory_crc_checker.cpp
    antitamper/maps_monitor.cpp
    antitamper/custom_jni_register.cpp
)

target_include_directories(riskengine PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

find_library(log-lib log)

target_link_libraries(riskengine
    ${log-lib}
    mediandk
    android
)
