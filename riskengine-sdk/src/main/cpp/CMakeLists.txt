cmake_minimum_required(VERSION 3.22.1)
project("riskengine")

add_library(riskengine SHARED
    riskengine_jni.cpp
    util/syscall_wrapper.cpp
    util/raw_dir.cpp
    util/maps_parser.cpp
    util/safe_mem_read.cpp
    util/payload_codec.cpp
    util/disposable_child.cpp
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
    detector/kernel_su_probe.cpp
    detector/art_hook_detector.cpp
    detector/periodic_monitor.cpp
    detector/apk_sig_native.cpp
    detector/bionic_prop_area.cpp
    detector/hardware_cpu_identity.cpp
    detector/custom_rom_probe.cpp
    detector/kernel_sidechannel.cpp
    detector/selinux_audit_probe.cpp
    detector/mount_forensics.cpp
    detector/zygisk_atexit_probe.cpp
    detector/virtualization_traps.cpp
    detector/widevine_ndk_probe.cpp
    detector/tee_binder_probe.cpp
    detector/hma_uid_probe.cpp
    util/custom_jni_register.cpp
)

target_include_directories(riskengine PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

set(IS_RELEASE_LIKE "$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>")

target_compile_options(riskengine PRIVATE
    -Wall
    -Wextra
    -Wformat
    -Wformat-security
    -fstack-protector-strong
    -fno-exceptions
    -fno-rtti
    "$<${IS_RELEASE_LIKE}:-Os>"
    "$<${IS_RELEASE_LIKE}:-D_FORTIFY_SOURCE=2>"
    # Release hardening: AGP passes RelWithDebInfo for release AAR builds, so
    # apply hardening flags to both Release and RelWithDebInfo.
    "$<${IS_RELEASE_LIKE}:-ffunction-sections>"
    "$<${IS_RELEASE_LIKE}:-fdata-sections>"
    "$<${IS_RELEASE_LIKE}:-flto=thin>"
    "$<${IS_RELEASE_LIKE}:-fno-unwind-tables>"
    "$<${IS_RELEASE_LIKE}:-fno-asynchronous-unwind-tables>"
    "$<${IS_RELEASE_LIKE}:-fomit-frame-pointer>"
    "$<${IS_RELEASE_LIKE}:-fmerge-all-constants>"
)

find_library(android_log_lib log)
find_library(android_dl_lib dl)
target_link_libraries(riskengine PRIVATE ${android_log_lib} ${android_dl_lib})

target_link_options(riskengine PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,relro,-z,now"
    "-Wl,-z,noexecstack"
    "-Wl,--exclude-libs,ALL"
    # Only JNI_OnLoad and JNI_OnUnload need to be externally visible.
    "$<${IS_RELEASE_LIKE}:-flto=thin>"
    "$<${IS_RELEASE_LIKE}:-Wl,--gc-sections>"
    "$<${IS_RELEASE_LIKE}:-Wl,--icf=safe>"
    "$<${IS_RELEASE_LIKE}:-Wl,--wrap=__cxa_demangle>"
    "$<${IS_RELEASE_LIKE}:-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map>"
    "$<${IS_RELEASE_LIKE}:-Wl,--strip-all>"
)

# Strip remaining compiler metadata (.comment) on Release and RelWithDebInfo builds.
set(RISKENGINE_STRIP_TOOL "${CMAKE_STRIP}")
if(NOT RISKENGINE_STRIP_TOOL)
    find_program(RISKENGINE_STRIP_TOOL NAMES llvm-strip strip)
endif()

if(CMAKE_CONFIGURATION_TYPES)
    if(NOT RISKENGINE_STRIP_TOOL)
        message(FATAL_ERROR "llvm-strip/strip not found for release-like ELF hardening")
    endif()
    add_custom_command(TARGET riskengine POST_BUILD
        COMMAND "$<${IS_RELEASE_LIKE}:${RISKENGINE_STRIP_TOOL}>"
                "$<${IS_RELEASE_LIKE}:--strip-all>"
                "$<${IS_RELEASE_LIKE}:-R>"
                "$<${IS_RELEASE_LIKE}:.comment>"
                "$<${IS_RELEASE_LIKE}:$<TARGET_FILE:riskengine>>"
        COMMAND_EXPAND_LISTS
        COMMENT "Stripping symbols and .comment from libriskengine.so"
    )
elseif(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    if(NOT RISKENGINE_STRIP_TOOL)
        message(FATAL_ERROR "llvm-strip/strip not found for release-like ELF hardening")
    endif()
    add_custom_command(TARGET riskengine POST_BUILD
        COMMAND "${RISKENGINE_STRIP_TOOL}" --strip-all -R .comment "$<TARGET_FILE:riskengine>"
        COMMENT "Stripping symbols and .comment from libriskengine.so"
    )
endif()
