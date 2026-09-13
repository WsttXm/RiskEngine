#include <jni.h>

#include "sealed_verdict.h"

#include "kernel_su_probe.h"
#include "mount_namespace_diff.h"
#include "native_debug_detector.h"
#include "native_emulator_detector.h"
#include "native_hook_detector.h"
#include "native_integrity.h"
#include "native_root_detector.h"
#include "../util/obf_str.h"
#include "../util/syscall_wrapper.h"

#include <atomic>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <sys/auxv.h>
#include <vector>

namespace {

constexpr size_t kKeyBytes = 32;
constexpr size_t kNonceBytes = 8;
constexpr uint64_t kVerdictMaxAgeMs = 10'000;

struct SealState {
    uint8_t key[kKeyBytes];
    bool initialized;
};

SealState g_state = {};
std::atomic<bool> g_key_ready{false};
std::mutex g_key_mutex;

/** Seeds the per-process MAC key from the kernel. Never leaves native. */
void ensure_key() {
    if (g_key_ready.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lock(g_key_mutex);
    if (g_key_ready.load(std::memory_order_acquire)) return;

    uint8_t key[kKeyBytes] = {0};
    bool filled = false;

    int fd = static_cast<int>(my_openat(AT_FDCWD, OBF("/dev/urandom").c_str(),
                                        O_RDONLY | O_CLOEXEC, 0));
    if (fd >= 0) {
        size_t got = 0;
        while (got < kKeyBytes) {
            long n = my_read(fd, key + got, kKeyBytes - got);
            if (n <= 0) break;
            got += static_cast<size_t>(n);
        }
        my_close(fd);
        filled = got == kKeyBytes;
    }
    if (!filled) {
        // AT_RANDOM is 16 kernel-supplied bytes present in every process.
        auto at_random = reinterpret_cast<const uint8_t *>(getauxval(AT_RANDOM));
        if (at_random != nullptr) {
            for (size_t i = 0; i < kKeyBytes; ++i) {
                key[i] = static_cast<uint8_t>(at_random[i % 16] ^ (i * 31u));
            }
            filled = true;
        }
    }
    if (!filled) {
        // Last resort: still process-local, just weaker.
        auto seed = static_cast<uint64_t>(
                reinterpret_cast<uintptr_t>(&g_state) ^ my_gettid());
        for (size_t i = 0; i < kKeyBytes; ++i) {
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            key[i] = static_cast<uint8_t>(seed >> 33);
        }
    }

    memcpy(g_state.key, key, kKeyBytes);
    g_state.initialized = true;
    g_key_ready.store(true, std::memory_order_release);
}

uint64_t random_nonce() {
    uint64_t value = 0;
    int fd = static_cast<int>(my_openat(AT_FDCWD, OBF("/dev/urandom").c_str(),
                                       O_RDONLY | O_CLOEXEC, 0));
    if (fd >= 0) {
        my_read(fd, &value, sizeof(value));
        my_close(fd);
    }
    if (value == 0) {
        struct timespec ts = {};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        value = static_cast<uint64_t>(ts.tv_nsec) * 2654435761u
                ^ static_cast<uint64_t>(my_gettid());
    }
    return value;
}

/** FNV-1a keyed MAC. Not HMAC-SHA256, but no crypto dependency is linked. */
uint64_t mac(const uint8_t *key, const uint8_t *data, size_t len) {
    uint64_t hash = 0xCBF29CE484222325ull;
    for (size_t i = 0; i < kKeyBytes; ++i) {
        hash ^= key[i];
        hash *= 0x100000001B3ull;
    }
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 0x100000001B3ull;
    }
    for (size_t i = 0; i < kKeyBytes; ++i) {
        hash ^= key[kKeyBytes - 1 - i];
        hash *= 0x100000001B3ull;
    }
    return hash;
}

bool contains(const std::string &haystack, const std::string &needle) {
    return !needle.empty() && haystack.find(needle) != std::string::npos;
}

bool has_csv_token(const std::string &value, const std::string &wanted) {
    size_t start = 0;
    while (start <= value.size()) {
        size_t comma = value.find(',', start);
        if (comma == std::string::npos) comma = value.size();
        if (value.compare(start, comma - start, wanted) == 0) return true;
        if (comma == value.size()) break;
        start = comma + 1;
    }
    return false;
}

std::string to_hex(const uint8_t *data, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0x0F]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

bool from_hex(const std::string &hex, std::vector<uint8_t> &out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = -1, lo = -1;
        for (int d = 0; d < 16; ++d) {
            const char c = "0123456789abcdef"[d];
            if (hex[i] == c) hi = d;
            if (hex[i + 1] == c) lo = d;
        }
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

/** Native-side ranking. Replaces what the Java classifiers used to decide. */
uint32_t compute_flags(JNIEnv *env,
                       const void *const *registered_methods,
                       size_t registered_method_count,
                       int &score_out) {
    uint32_t flags = 0;

    const std::string root = native_get_root_evidence();
    if (!root.empty()) {
        if (contains(root, OBF("su:")) || contains(root, OBF("magisk:"))
            || contains(root, OBF("ksu:")) || contains(root, OBF("apatch:"))
            || contains(root, OBF("mount:magisk"))
            || contains(root, OBF("mount:ksu"))
            || contains(root, OBF("mount:debug_ramdisk"))) {
            flags |= VerdictBits::kRootStrong;
        }
        if (contains(root, OBF("mount_hidden")) || contains(root, OBF("ns_differs"))
            || contains(root, OBF("listing_mismatch"))
            || contains(root, OBF("syscall_mismatch"))) {
            flags |= VerdictBits::kRootHidden;
        }
        if (contains(root, OBF("ksu_prctl"))) {
            flags |= VerdictBits::kKernelRoot;
        }
        if (contains(root, OBF("ns_unreadable"))) {
            flags |= VerdictBits::kCoverageLoss;
        }
    }

    const std::string hook = native_get_hook_evidence(env);
    if (!hook.empty()) {
        if (contains(hook, OBF("inline_hook:")) || contains(hook, OBF("got_hook:"))
            || contains(hook, OBF("jni_table_hook:"))
            || contains(hook, OBF("wx_segment:self"))) {
            flags |= VerdictBits::kHookInline;
        }
        if (contains(hook, OBF("frida")) || contains(hook, OBF("xposed"))
            || contains(hook, OBF("lsposed")) || contains(hook, OBF("substrate"))
            || contains(hook, OBF("unix_socket:"))) {
            flags |= VerdictBits::kHookFramework;
        }
    }

    const std::string self_integrity = native_get_so_integrity_evidence();
    if (has_csv_token(self_integrity, OBF("text_mismatch"))) {
        flags |= VerdictBits::kTextMismatch;
    }

    const std::string jni_self = native_get_jni_self_table_evidence(
            env, registered_methods, registered_method_count);
    if (contains(jni_self, OBF("jni_self_hook:"))) {
        flags |= VerdictBits::kJniSelfHook;
    }
    if (contains(jni_self, OBF("jni_self:no_range"))) {
        flags |= VerdictBits::kCoverageLoss;
    }

    if (!check_emulator_files().empty() || get_thermal_zone_count() == 0) {
        flags |= VerdictBits::kEmulator;
    }

    if (get_tracer_pid() > 0) {
        flags |= VerdictBits::kDebugger;
    }

    // Weighted score, native-side so thresholds are not patchable from Java.
    int score = 0;
    if (flags & VerdictBits::kTextMismatch) score += 10;
    if (flags & VerdictBits::kHookInline) score += 9;
    if (flags & VerdictBits::kJniSelfHook) score += 10;
    if (flags & VerdictBits::kRootHidden) score += 8;
    if (flags & VerdictBits::kKernelRoot) score += 8;
    if (flags & VerdictBits::kRootStrong) score += 7;
    if (flags & VerdictBits::kHookFramework) score += 6;
    if (flags & VerdictBits::kDebugger) score += 6;
    if (flags & VerdictBits::kEmulator) score += 4;
    // Coverage loss must affect completeness, not risk. Treating an expected
    // permission failure as a positive signal made stock devices score risk.
    score_out = score > 100 ? 100 : score;

    return flags;
}

}  // namespace

std::string native_build_sealed_verdict(JNIEnv *env,
                                        const void *const *registered_methods,
                                        size_t registered_method_count) {
    ensure_key();
    if (!g_state.initialized) return std::string();

    int score = 0;
    const uint32_t flags = compute_flags(
            env, registered_methods, registered_method_count, score);
    const uint64_t nonce = random_nonce();

    struct timespec ts = {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    const uint64_t uptime_ms = static_cast<uint64_t>(ts.tv_sec) * 1000ull
                               + static_cast<uint64_t>(ts.tv_nsec) / 1000000ull;

    uint8_t payload[kNonceBytes + 4 + 4 + 8];
    size_t off = 0;
    memcpy(payload + off, &nonce, kNonceBytes);            off += kNonceBytes;
    memcpy(payload + off, &flags, sizeof(flags));          off += sizeof(flags);
    const uint32_t score32 = static_cast<uint32_t>(score);
    memcpy(payload + off, &score32, sizeof(score32));      off += sizeof(score32);
    memcpy(payload + off, &uptime_ms, sizeof(uptime_ms));  off += sizeof(uptime_ms);

    const uint64_t tag = mac(g_state.key, payload, off);

    std::string blob = to_hex(payload, off);
    blob += to_hex(reinterpret_cast<const uint8_t *>(&tag), sizeof(tag));
    return blob;
}

namespace {

bool verify_sealed_verdict(const std::string &blob, uint32_t &flags, uint32_t &score) {
    ensure_key();
    if (!g_state.initialized || blob.empty()) return false;

    std::vector<uint8_t> raw;
    if (!from_hex(blob, raw)) return false;
    constexpr size_t kPayload = kNonceBytes + 4 + 4 + 8;
    if (raw.size() != kPayload + sizeof(uint64_t)) return false;

    uint64_t tag = 0;
    memcpy(&tag, raw.data() + kPayload, sizeof(tag));
    if (mac(g_state.key, raw.data(), kPayload) != tag) return false;

    uint64_t issued_at_ms = 0;
    memcpy(&issued_at_ms, raw.data() + kNonceBytes + 4 + 4, sizeof(issued_at_ms));
    struct timespec now = {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return false;
    const uint64_t now_ms = static_cast<uint64_t>(now.tv_sec) * 1000ull
                            + static_cast<uint64_t>(now.tv_nsec) / 1000000ull;
    // A freshness window avoids the global "last nonce" race: concurrent
    // callers can issue independent verdicts without invalidating each other,
    // while stale blobs still cannot be replayed indefinitely.
    if (issued_at_ms > now_ms || now_ms - issued_at_ms > kVerdictMaxAgeMs) return false;

    memcpy(&flags, raw.data() + kNonceBytes, sizeof(flags));
    memcpy(&score, raw.data() + kNonceBytes + 4, sizeof(score));
    return true;
}

}  // namespace

int native_verify_sealed_verdict(const std::string &blob) {
    uint32_t flags = 0;
    uint32_t score = 0;
    if (!verify_sealed_verdict(blob, flags, score)) return -1;
    return static_cast<int>(score);
}

int native_verify_sealed_verdict_flags(const std::string &blob) {
    uint32_t flags = 0;
    uint32_t score = 0;
    if (!verify_sealed_verdict(blob, flags, score)) return -1;
    return static_cast<int>(flags);
}
