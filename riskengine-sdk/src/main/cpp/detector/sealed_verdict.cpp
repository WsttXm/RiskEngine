#include <jni.h>

#include "sealed_verdict.h"

#include "kernel_su_probe.h"
#include "mount_namespace_diff.h"
#include "native_debug_detector.h"
#include "native_emulator_detector.h"
#include "native_hook_detector.h"
#include "native_integrity.h"
#include "native_root_detector.h"
#include "periodic_monitor.h"
#include "../util/crypto_mini.h"
#include "../util/maps_parser.h"
#include "../util/obf_str.h"
#include "../util/syscall_wrapper.h"

#include <array>
#include <atomic>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <sys/auxv.h>
#include <time.h>
#include <vector>

namespace {

constexpr size_t kKeyBytes = 32;
constexpr size_t kNonceBytes = 8;
constexpr size_t kChallengeBytes = 8;
constexpr size_t kTagBytes = 16;  // 128-bit truncated HMAC-SHA256
constexpr size_t kPayloadBytes = kNonceBytes + kChallengeBytes + 4 + 4 + 8;
constexpr uint64_t kVerdictMaxAgeMs = 10'000;
constexpr size_t kReplayRingSize = 64;

struct SealState {
    uint8_t key[kKeyBytes];
    bool initialized;
};

SealState g_state = {};
std::atomic<bool> g_key_ready{false};
std::mutex g_key_mutex;

std::mutex g_replay_mutex;
std::array<uint64_t, kReplayRingSize> g_consumed_nonces = {};
size_t g_consumed_cursor = 0;

uint64_t monotonic_ms() {
    struct timespec ts = {};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return static_cast<uint64_t>(ts.tv_sec) * 1000ull
           + static_cast<uint64_t>(ts.tv_nsec) / 1000000ull;
}

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
        auto at_random = reinterpret_cast<const uint8_t *>(getauxval(AT_RANDOM));
        if (at_random != nullptr) {
            for (size_t i = 0; i < kKeyBytes; ++i) {
                key[i] = static_cast<uint8_t>(at_random[i % 16] ^ (i * 31u));
            }
            filled = true;
        }
    }
    if (!filled) {
        auto seed = static_cast<uint64_t>(
                reinterpret_cast<uintptr_t>(&g_state) ^ my_gettid());
        for (size_t i = 0; i < kKeyBytes; ++i) {
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            key[i] = static_cast<uint8_t>(seed >> 33);
        }
    }

    std::memcpy(g_state.key, key, kKeyBytes);
    crypto_mini::secure_zero(key, sizeof(key));
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
        if (value == 0) value = 1;
    }
    return value;
}

bool consume_nonce_once(uint64_t nonce) {
    if (nonce == 0) return false;
    std::lock_guard<std::mutex> lock(g_replay_mutex);
    for (uint64_t seen : g_consumed_nonces) {
        if (seen == nonce) return false;
    }
    g_consumed_nonces[g_consumed_cursor] = nonce;
    g_consumed_cursor = (g_consumed_cursor + 1) % kReplayRingSize;
    return true;
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

uint32_t compute_flags(JNIEnv *env,
                       const void *const *registered_methods,
                       const uint64_t *expected_prologues,
                       size_t registered_method_count,
                       int &score_out) {
    uint32_t flags = 0;
    // Read /proc/self/maps once and share it across hook, integrity, and jni_self checks.
    auto maps = read_self_maps();

    const std::string root = native_get_root_evidence();
    if (!root.empty()) {
        if (contains(root, OBF("su:")) || contains(root, OBF("magisk:"))
            || contains(root, OBF("ksu:")) || contains(root, OBF("apatch:"))
            || contains(root, OBF("modules:")) || contains(root, OBF("path_su:"))
            || contains(root, OBF("tamper_tool:")) || contains(root, OBF("selinux_context:"))
            || contains(root, OBF("mount:magisk"))
            || contains(root, OBF("mount:ksu"))
            || contains(root, OBF("mount:module"))
            || contains(root, OBF("mount:system_tmpfs:"))
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
        // Only treat unreadable self mountinfo as true coverage loss; PID 1's
        // mountinfo is expected to be EACCES (ns_restricted:init) on Android 10+.
        if (contains(root, OBF("ns_unreadable:self"))) {
            flags |= VerdictBits::kCoverageLoss;
        }
    }

    const std::string hook = native_get_hook_evidence(env, maps);
    if (!hook.empty()) {
        if (contains(hook, OBF("inline_hook:")) || contains(hook, OBF("got_hook:"))
            || contains(hook, OBF("jni_table_hook:"))
            || contains(hook, OBF("jni_slot_hook:"))
            || contains(hook, OBF("art_native_flag:"))
            || contains(hook, OBF("art_native_cleared:"))
            || contains(hook, OBF("memfd_private_elf:"))
            || contains(hook, OBF("wx_segment:self"))) {
            flags |= VerdictBits::kHookInline;
        }
        if (contains(hook, OBF("frida")) || contains(hook, OBF("xposed"))
            || contains(hook, OBF("lsposed")) || contains(hook, OBF("substrate"))
            || contains(hook, OBF("unix_socket:"))) {
            flags |= VerdictBits::kHookFramework;
        }
    }

    // Fold periodic background monitor findings into the sealed verdict so
    // post-init injection cannot be hidden by hooking HookFrameworkDetector.
    const std::string monitor = native_monitor_findings();
    if (!monitor.empty()) {
        if (contains(monitor, OBF("late_text_mismatch"))) {
            flags |= VerdictBits::kTextMismatch;
        }
        if (contains(monitor, OBF("late_wx_self"))
            || contains(monitor, OBF("late_memfd_elf"))) {
            flags |= VerdictBits::kHookInline;
        }
        if (contains(monitor, OBF("late_module:"))) {
            flags |= VerdictBits::kHookFramework;
        }
        if (contains(monitor, OBF("late_tracer_attached"))) {
            flags |= VerdictBits::kDebugger;
        }
    }

    const std::string self_integrity = native_get_so_integrity_evidence(maps);
    if (has_csv_token(self_integrity, OBF("text_mismatch"))
        || has_csv_token(self_integrity, OBF("text_mismatch:anonymous_map"))) {
        flags |= VerdictBits::kTextMismatch;
    }

    const std::string jni_self = native_get_jni_self_table_evidence(
            env, registered_methods, expected_prologues, registered_method_count, maps);
    if (contains(jni_self, OBF("jni_self_hook:"))) {
        flags |= VerdictBits::kJniSelfHook;
    }
    if (contains(jni_self, OBF("jni_self:no_range"))) {
        flags |= VerdictBits::kCoverageLoss;
    }

    if (!check_emulator_files().empty()
        || get_thermal_zone_count() == 0
        || native_has_emulator_props()) {
        flags |= VerdictBits::kEmulator;
    }

    if (get_tracer_pid() > 0) {
        flags |= VerdictBits::kDebugger;
    }

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
    score_out = score > 100 ? 100 : score;

    return flags;
}

bool verify_sealed_verdict(const std::string &blob,
                           uint64_t expected_challenge,
                           bool consume_nonce,
                           uint32_t &flags,
                           uint32_t &score) {
    ensure_key();
    if (!g_state.initialized || blob.empty()) return false;

    std::vector<uint8_t> raw;
    if (!from_hex(blob, raw)) return false;
    if (raw.size() != kPayloadBytes + kTagBytes) return false;

    uint8_t computed_hmac[crypto_mini::kSha256DigestSize];
    crypto_mini::hmac_sha256(g_state.key, kKeyBytes, raw.data(), kPayloadBytes, computed_hmac);
    const bool mac_ok = crypto_mini::ct_memcmp(computed_hmac, raw.data() + kPayloadBytes, kTagBytes);
    crypto_mini::secure_zero(computed_hmac, sizeof(computed_hmac));
    if (!mac_ok) return false;

    uint64_t nonce = 0;
    uint64_t blob_challenge = 0;
    uint32_t blob_flags = 0;
    uint32_t blob_score = 0;
    uint64_t issued_at_ms = 0;

    size_t off = 0;
    std::memcpy(&nonce, raw.data() + off, sizeof(nonce));                   off += sizeof(nonce);
    std::memcpy(&blob_challenge, raw.data() + off, sizeof(blob_challenge)); off += sizeof(blob_challenge);
    std::memcpy(&blob_flags, raw.data() + off, sizeof(blob_flags));         off += sizeof(blob_flags);
    std::memcpy(&blob_score, raw.data() + off, sizeof(blob_score));         off += sizeof(blob_score);
    std::memcpy(&issued_at_ms, raw.data() + off, sizeof(issued_at_ms));

    if (blob_challenge != expected_challenge) return false;

    const uint64_t now_ms = monotonic_ms();
    if (now_ms == 0 || issued_at_ms > now_ms || now_ms - issued_at_ms > kVerdictMaxAgeMs) {
        return false;
    }

    if (consume_nonce && !consume_nonce_once(nonce)) {
        return false;
    }

    flags = blob_flags;
    score = blob_score;
    return true;
}

}  // namespace

std::string native_build_sealed_verdict(JNIEnv *env,
                                        const void *const *registered_methods,
                                        const uint64_t *expected_prologues,
                                        size_t registered_method_count,
                                        uint64_t challenge) {
    ensure_key();
    if (!g_state.initialized) return std::string();

    int score = 0;
    const uint32_t flags = compute_flags(
            env, registered_methods, expected_prologues, registered_method_count, score);
    const uint64_t nonce = random_nonce();
    const uint64_t uptime_ms = monotonic_ms();

    uint8_t payload[kPayloadBytes];
    size_t off = 0;
    std::memcpy(payload + off, &nonce, sizeof(nonce));             off += sizeof(nonce);
    std::memcpy(payload + off, &challenge, sizeof(challenge));     off += sizeof(challenge);
    std::memcpy(payload + off, &flags, sizeof(flags));             off += sizeof(flags);
    const uint32_t score32 = static_cast<uint32_t>(score);
    std::memcpy(payload + off, &score32, sizeof(score32));         off += sizeof(score32);
    std::memcpy(payload + off, &uptime_ms, sizeof(uptime_ms));     off += sizeof(uptime_ms);

    uint8_t full_hmac[crypto_mini::kSha256DigestSize];
    crypto_mini::hmac_sha256(g_state.key, kKeyBytes, payload, off, full_hmac);

    std::string blob = to_hex(payload, off);
    blob += to_hex(full_hmac, kTagBytes);
    crypto_mini::secure_zero(full_hmac, sizeof(full_hmac));
    return blob;
}

int64_t native_verify_sealed_verdict_packed(const std::string &blob,
                                            uint64_t expected_challenge,
                                            bool consume_nonce) {
    uint32_t flags = 0;
    uint32_t score = 0;
    if (!verify_sealed_verdict(blob, expected_challenge, consume_nonce, flags, score)) {
        return -1;
    }
    return (static_cast<int64_t>(flags) << 32) | static_cast<int64_t>(score & 0x7FFFFFFFu);
}

int native_verify_sealed_verdict(const std::string &blob) {
    uint32_t flags = 0;
    uint32_t score = 0;
    if (!verify_sealed_verdict(blob, 0, false, flags, score)) return -1;
    return static_cast<int>(score);
}

int native_verify_sealed_verdict_flags(const std::string &blob) {
    uint32_t flags = 0;
    uint32_t score = 0;
    if (!verify_sealed_verdict(blob, 0, false, flags, score)) return -1;
    return static_cast<int>(flags);
}
