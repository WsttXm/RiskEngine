#ifndef RISKENGINE_OBF_STR_H
#define RISKENGINE_OBF_STR_H

#include <cstddef>
#include <cstdint>
#include <string>

/**
 * Compile-time string obfuscation with runtime optimization barriers.
 *
 * Each literal gets its own key stream seeded from a per-site compile-time
 * value (__LINE__ mixed with __COUNTER__ and the literal length), then a
 * rolling xorshift keystream. The runtime decoder uses volatile reads and an
 * inline asm barrier so Clang -O2 / ThinLTO cannot constant-fold the decoded
 * plaintext back into .rodata.
 */
namespace obf_detail {

constexpr uint32_t mix(uint32_t value) {
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    return value ? value : 0x9E3779B9u;
}

__attribute__((noinline))
inline std::string decode_runtime(const uint8_t *enc, size_t n, uint32_t seed) {
    const size_t len = n > 0 ? n - 1 : 0;
    std::string out(len, '\0');
    uint32_t state = seed;
    asm volatile("" : "+r"(enc), "+r"(state) : : "memory");
    for (size_t i = 0; i < len; ++i) {
        state = mix(state);
        uint8_t b = enc[i];
        asm volatile("" : "+r"(b) : : "memory");
        out[i] = static_cast<char>(b ^ static_cast<uint8_t>(state & 0xFFu));
    }
    return out;
}

}  // namespace obf_detail

template<size_t N>
struct ObfLit {
    uint8_t data[N];
    uint32_t seed;

    constexpr explicit ObfLit(const char (&s)[N], uint32_t site)
            : data{},
              seed(obf_detail::mix(site * 0x01000193u ^ static_cast<uint32_t>(N) * 2654435761u)) {
        uint32_t state = seed;
        for (size_t i = 0; i < N; ++i) {
            state = obf_detail::mix(state);
            data[i] = static_cast<uint8_t>(
                    static_cast<uint8_t>(s[i]) ^ static_cast<uint8_t>(state & 0xFFu));
        }
    }

    std::string dec() const {
        return obf_detail::decode_runtime(data, N, seed);
    }
};

#define OBF_SITE_ (static_cast<uint32_t>(__LINE__) * 0x9E3779B9u ^ static_cast<uint32_t>(__COUNTER__))
#define OBF(s) ([] { static constexpr ObfLit<sizeof(s)> enc(s, OBF_SITE_); return enc.dec(); }())

#endif
