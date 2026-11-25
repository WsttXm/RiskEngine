#ifndef RISKENGINE_NATIVE_DEBUG_DETECTOR_H
#define RISKENGINE_NATIVE_DEBUG_DETECTOR_H

#include <string>

int get_tracer_pid();
std::string native_get_debug_evidence();
bool native_set_anti_dumpable(bool enable);
std::string native_get_adb_protocol_evidence();

#endif
