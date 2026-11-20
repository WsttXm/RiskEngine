#ifndef RISKENGINE_NATIVE_INTEGRITY_H
#define RISKENGINE_NATIVE_INTEGRITY_H

#include "../util/maps_parser.h"
#include <cstddef>
#include <cstdint>
#include <jni.h>
#include <string>
#include <vector>

std::string native_get_integrity_evidence(JNIEnv *env);
std::string native_get_integrity_evidence(JNIEnv *env, const std::vector<MapEntry> &maps);
std::string native_get_so_integrity_evidence();
std::string native_get_so_integrity_evidence(const std::vector<MapEntry> &maps);
std::string native_scan_process_tokens();

/** Computes a 16-byte entry prologue FNV-1a snapshot for inline-hook checks. */
uint64_t native_hash_fn_prologue(const void *fn_ptr);

/**
 * Verifies that this library's own registered JNI entry points still resolve
 * inside this library and have intact entry prologues.
 */
std::string native_get_jni_self_table_evidence(JNIEnv *env,
                                               const void *const *registered,
                                               const uint64_t *expected_prologues,
                                               size_t count,
                                               const std::vector<MapEntry> &maps);

std::string native_get_jni_self_table_evidence(JNIEnv *env,
                                               const void *const *registered,
                                               size_t count);

#endif
