#ifndef RISKENGINE_SEALED_VERDICT_H
#define RISKENGINE_SEALED_VERDICT_H

#include <cstddef>
#include <cstdint>
#include <string>

struct VerdictBits {
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
 * Computes the native verdict and returns a hex-encoded HMAC-SHA256 sealed blob:
 * nonce (8B) | challenge (8B) | flags (4B) | score (4B) | timestamp (8B) | HMAC-SHA256[0..15] (16B).
 */
std::string native_build_sealed_verdict(JNIEnv *env,
                                        const void *const *registered_methods,
                                        const uint64_t *expected_prologues,
                                        size_t registered_method_count,
                                        uint64_t challenge = 0);

/**
 * Verifies a blob in a single JNI call. Checks HMAC-SHA256 in constant time,
 * caller challenge binding, 10s monotonic freshness window, and optional
 * one-time nonce replay protection.
 *
 * Returns ((int64_t)flags << 32) | (score & 0xFFFFFFFFLL), or -1 on failure.
 */
int64_t native_verify_sealed_verdict_packed(const std::string &blob,
                                            uint64_t expected_challenge,
                                            bool consume_nonce = true);

/** Legacy score-only verifier (challenge=0, non-consuming). */
int native_verify_sealed_verdict(const std::string &blob);

/** Legacy flags-only verifier (challenge=0, non-consuming). */
int native_verify_sealed_verdict_flags(const std::string &blob);

#endif
