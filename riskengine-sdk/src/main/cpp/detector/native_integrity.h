#ifndef RISKENGINE_NATIVE_INTEGRITY_H
#define RISKENGINE_NATIVE_INTEGRITY_H

#include "../util/maps_parser.h"
#include <jni.h>
#include <string>
#include <vector>

std::string native_get_integrity_evidence(JNIEnv *env);
std::string native_get_integrity_evidence(JNIEnv *env, const std::vector<MapEntry> &maps);

#endif
