#ifndef RISKENGINE_NATIVE_INTEGRITY_H
#define RISKENGINE_NATIVE_INTEGRITY_H

#include <cstddef>
#include <jni.h>
#include <string>

std::string native_get_integrity_evidence(JNIEnv *env);
std::string native_get_so_integrity_evidence();
std::string native_scan_process_tokens();

/**
 * Verifies that this library's own registered JNI entry points still resolve
 * inside this library. Guards the bridge that every other check reports
 * through, which was previously unprotected.
 */
std::string native_get_jni_self_table_evidence(JNIEnv *env,
                                               const void *const *registered,
                                               size_t count);

#endif
