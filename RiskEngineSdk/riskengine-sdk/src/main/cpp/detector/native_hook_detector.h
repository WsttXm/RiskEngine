#ifndef RISKENGINE_NATIVE_HOOK_DETECTOR_H
#define RISKENGINE_NATIVE_HOOK_DETECTOR_H

#include <string>

bool native_check_hooks();
std::string native_get_hook_evidence();
std::string native_inspect_method_entry_point(void *method_id);

#endif
