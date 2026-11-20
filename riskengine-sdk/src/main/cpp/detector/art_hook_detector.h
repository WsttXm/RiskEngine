#ifndef RISKENGINE_ART_HOOK_DETECTOR_H
#define RISKENGINE_ART_HOOK_DETECTOR_H

#include "../util/maps_parser.h"
#include <jni.h>
#include <string>
#include <vector>

/**
 * Detects Java-method hooking at the ART level.
 */
std::string native_get_art_hook_evidence(JNIEnv *env);
std::string native_get_art_hook_evidence(JNIEnv *env, const std::vector<MapEntry> &maps);

#endif
