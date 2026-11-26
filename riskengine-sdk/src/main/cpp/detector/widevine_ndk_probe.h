#ifndef RISKENGINE_WIDEVINE_NDK_PROBE_H
#define RISKENGINE_WIDEVINE_NDK_PROBE_H

#include <string>

/**
 * Dynamically loads libmediandk.so via dlopen/dlsym (zero link-time dependency)
 * and reads Widevine non-PII properties ("securityLevel" and "systemId") into
 * a NativePayloadCodec frame for Java-vs-NDK dual-source parity verification.
 */
std::string native_get_widevine_ndk_probe();

#endif  // RISKENGINE_WIDEVINE_NDK_PROBE_H
