#ifndef RISKENGINE_OBF_STR_H
#define RISKENGINE_OBF_STR_H

#include <cstddef>
#include <cstdint>
#include <string>

/**
 * Compile-time string obfuscation.
 *
 * Each literal gets its own key stream seeded from a per-site compile-time
 * value (__LINE__ mixed with __COUNTER__ and the literal length), then a
 * rolling xorshift keystream. A single fixed key is recoverable by frequency
 * analysis across the whole .so; a per-site rolling stream is not.
 */
template<size_t N>
struct ObfLit {
    char data[N];
    uint32_t seed;

    static constexpr uint32_t mix(uint32_t value) {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        return value ? value : 0x9E3779B9u;
    }

    constexpr explicit ObfLit(const char (&s)[N], uint32_t site)
            : data{}, seed(mix(site * 0x01000193u ^ static_cast<uint32_t>(N) * 2654435761u)) {
        uint32_t state = seed;
        for (size_t i = 0; i < N; ++i) {
            state = mix(state);
            data[i] = static_cast<char>(
                    static_cast<uint8_t>(s[i]) ^ static_cast<uint8_t>(state & 0xFFu));
        }
    }

    std::string dec() const {
        std::string out(N > 0 ? N - 1 : 0, '\0');
        uint32_t state = seed;
        for (size_t i = 0; i + 1 < N; ++i) {
            state = mix(state);
            out[i] = static_cast<char>(
                    static_cast<uint8_t>(data[i]) ^ static_cast<uint8_t>(state & 0xFFu));
        }
        return out;
    }
};

#define OBF_SITE_ (static_cast<uint32_t>(__LINE__) * 0x9E3779B9u ^ static_cast<uint32_t>(__COUNTER__))
#define OBF(s) ([] { constexpr ObfLit<sizeof(s)> enc(s, OBF_SITE_); return enc.dec(); }())

#endif
