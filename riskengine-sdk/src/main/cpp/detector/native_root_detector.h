#ifndef RISKENGINE_NATIVE_ROOT_DETECTOR_H
#define RISKENGINE_NATIVE_ROOT_DETECTOR_H

#include <string>

bool native_check_root();
std::string native_get_root_evidence();
int native_get_selinux_enforce();
std::string native_get_build_prop_fingerprint();

#endif
