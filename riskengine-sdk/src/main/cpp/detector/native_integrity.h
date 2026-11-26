#ifndef RISKENGINE_NATIVE_INTEGRITY_H
#define RISKENGINE_NATIVE_INTEGRITY_H

#include "../util/maps_parser.h"
#include <jni.h>
#include <string>
#include <vector>

struct IntegrityFinding {
    std::string token;
    std::string code;
    std::string location;
    std::string value;
};

/**
 * Records libriskengine.so's registered JNI methods (XOR-masked pointers +
 * SHA-256 of each entry's 16-byte prologue) during JNI_OnLoad.
 */
void native_integrity_record_jni_table(const JNINativeMethod *methods, int count);

/**
 * Records a core internal C++ detection function entry point (XOR-masked pointer +
 * SHA-256 of its 16-byte prologue) during JNI_OnLoad for runtime prologue verification.
 */
void native_integrity_record_core_fn(const char *tag, const void *fn_ptr);

std::vector<IntegrityFinding> native_collect_integrity_findings(
        JNIEnv *env, const std::vector<MapEntry> &maps);

std::string native_get_integrity_evidence(JNIEnv *env);
std::string native_get_integrity_evidence(JNIEnv *env, const std::vector<MapEntry> &maps);

#endif
