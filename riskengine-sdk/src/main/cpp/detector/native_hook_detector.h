#ifndef RISKENGINE_NATIVE_HOOK_DETECTOR_H
#define RISKENGINE_NATIVE_HOOK_DETECTOR_H

#include "../util/maps_parser.h"
#include <jni.h>
#include <string>
#include <vector>

std::string native_get_hook_evidence(JNIEnv *env);
std::string native_get_hook_evidence(JNIEnv *env, const std::vector<MapEntry> &maps);
std::vector<std::string> native_scan_memfd_private_elfs(const std::vector<MapEntry> &maps);

#endif
