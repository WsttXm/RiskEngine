#ifndef RISKENGINE_SEALED_VERDICT_H
#define RISKENGINE_SEALED_VERDICT_H

#include <cstdint>
#include <string>

/**
 * Native-computed verdict, sealed so the Java layer cannot forge it.
 *
 * Motivation: every native check previously returned a plain evidence string
 * that Java then ranked and scored. One Java-level hook returning "" made the
 * whole report read SAFE. Here native does the ranking itself and returns an
 * opaque blob authenticated with a process-local key that never crosses JNI.
 *
 * Threat model and its limit, stated honestly: an attacker with native code
 * execution in this process can read the key out of memory and mint blobs.
 * This does not stop that. What it stops is the cheap and overwhelmingly common
 * attack, a Java/Xposed hook on the bridge that fabricates a clean result,
 * because forging a blob now requires native access rather than a one-line
 * method replacement. Verification happens in native; Java only forwards the
 * blob back and receives a boolean.
 */
struct VerdictBits {
    // Bit flags, native-assigned. Kept numeric so no human-readable token
    // ordering leaks the ranking logic into the Java layer.
    static constexpr uint32_t kRootStrong = 1u << 0;
    static constexpr uint32_t kRootHidden = 1u << 1;
    static constexpr uint32_t kHookInline = 1u << 2;
    static constexpr uint32_t kHookFramework = 1u << 3;
    static constexpr uint32_t kTextMismatch = 1u << 4;
    static constexpr uint32_t kEmulator = 1u << 5;
    static constexpr uint32_t kDebugger = 1u << 6;
    static constexpr uint32_t kKernelRoot = 1u << 7;
    static constexpr uint32_t kJniSelfHook = 1u << 8;
    static constexpr uint32_t kCoverageLoss = 1u << 9;
};

/**
 * Computes the native verdict and returns it as a hex-encoded sealed blob:
 * nonce | flags | score | timestamp | MAC. Empty string on failure.
 */
std::string native_build_sealed_verdict(JNIEnv *env);

/**
 * Verifies a blob produced by this process and returns its score, or -1 when
 * the MAC fails, the nonce is unknown, or the blob is malformed. A failed
 * verification is itself a tamper signal.
 */
int native_verify_sealed_verdict(const std::string &blob);

#endif
