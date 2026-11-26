#ifndef RISKENGINE_CUSTOM_ROM_PROBE_H
#define RISKENGINE_CUSTOM_ROM_PROBE_H

#include <string>

/**
 * Probes custom-ROM native indicators:
 * 1. Inspects libstagefright.so (both on-disk ELF symbol tables and in-memory
 *    linker via RTLD_NOLOAD) for _ZN7android15ANetworkSession10threadLoopEv.
 * 2. Counts distinct non-zero block devices mapping framework-res.apk in
 *    /proc/self/maps.
 *
 * Returns a NativePayloadCodec frame.
 */
std::string native_get_custom_rom_probe();

#endif  // RISKENGINE_CUSTOM_ROM_PROBE_H
