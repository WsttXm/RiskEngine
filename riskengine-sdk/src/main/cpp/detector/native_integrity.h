#ifndef RISKENGINE_NATIVE_INTEGRITY_H
#define RISKENGINE_NATIVE_INTEGRITY_H

#include <jni.h>
#include <string>

std::string native_get_integrity_evidence(JNIEnv *env);
std::string native_get_so_integrity_evidence();
std::string native_scan_process_tokens();

#endif
