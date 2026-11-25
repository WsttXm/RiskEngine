#ifndef RISKENGINE_TEE_BINDER_PROBE_H
#define RISKENGINE_TEE_BINDER_PROBE_H

#include <cstddef>
#include <cstdint>
#include <string>

/**
 * Native 5-vector TrickyStore / Keystore2 Binder interceptor probe:
 *  1) /proc/self/maps scan for tricky/keystore_interceptor artifacts
 *  2) libbinder.so ioctl GOT inspection (strictly via PipeMemoryReader)
 *  3) ioctl 16-byte disk-vs-memory inline hook inspection (strictly via PipeMemoryReader)
 *  4) BINDER_VERSION 3-way backend parity (Libc ioctl vs syscall vs inline-asm)
 *  5) 3-round rotating-order Binder Honeypot timing with median/MAD analysis (POSTPONED only)
 *
 * Returns a NativePayloadCodec frame.
 */
std::string native_get_tee_binder_probe(bool include_honeypot_timing);

/**
 * Native X.509 leaf certificate DER structural validation cross-verifiable with Java DerReader:
 * detects 32-char pure-hex placeholder templates (HEX_TEMPLATE_32), non-minimal BER length
 * encodings (NON_MINIMAL_LENGTH), and malformed TLV trees.
 */
std::string native_inspect_leaf_der(const uint8_t *bytes, size_t len);

#endif  // RISKENGINE_TEE_BINDER_PROBE_H
