cmake_minimum_required(VERSION 3.22.1)
project("riskengine")

add_library(riskengine SHARED
    riskengine_jni.cpp
    util/syscall_wrapper.cpp
    util/raw_dir.cpp
    util/maps_parser.cpp
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
    detector/native_integrity.cpp
    detector/runtime_arch_checker.cpp
    detector/mount_namespace_diff.cpp
    detector/kernel_su_probe.cpp
    detector/sealed_verdict.cpp
    detector/art_hook_detector.cpp
    detector/periodic_monitor.cpp
    util/custom_jni_register.cpp
)

target_include_directories(riskengine PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(riskengine PRIVATE
    -Wall
    -Wextra
    -Wformat
    -Wformat-security
    -fstack-protector-strong
    "$<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:-D_FORTIFY_SOURCE=2>"
    # Release hardening: drop the frame pointer and unwind tables an analyst
    # would otherwise use to reconstruct call graphs, and enable LTO so the
    # detector call graph is inlined across translation units.
    "$<$<CONFIG:Release>:-flto=thin>"
    "$<$<CONFIG:Release>:-fno-unwind-tables>"
    "$<$<CONFIG:Release>:-fno-asynchronous-unwind-tables>"
    "$<$<CONFIG:Release>:-fomit-frame-pointer>"
    "$<$<CONFIG:Release>:-fmerge-all-constants>"
)

find_library(android_log_lib log)
find_library(android_dl_lib dl)
target_link_libraries(riskengine PRIVATE ${android_log_lib} ${android_dl_lib})

target_link_options(riskengine PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,relro,-z,now"
    "-Wl,-z,noexecstack"
    "-Wl,--exclude-libs,ALL"
    # Only JNI_OnLoad needs to be externally visible. Everything else is
    # resolved through RegisterNatives, so the symbol table can go.
    "$<$<CONFIG:Release>:-flto=thin>"
    "$<$<CONFIG:Release>:-Wl,--gc-sections>"
    "$<$<CONFIG:Release>:-Wl,--strip-all>"
    "$<$<CONFIG:Release>:-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map>"
)
