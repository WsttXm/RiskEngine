#ifndef RISKENGINE_OBF_STR_H
#define RISKENGINE_OBF_STR_H

#include "crypto_mini.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

/**
 * Polymorphic compile-time string obfuscation with RAII stack wiping.
 *
 * Each call site derives a unique compile-time seed from __FILE__, __LINE__,
 * __COUNTER__, and literal length, then instantiates a per-<N, Seed> inline
 * decoder with one of four polymorphic byte-transform variants and local
 * inline-asm barriers to block Clang -O2/-Os/ThinLTO constant folding back
 * into .rodata.
 *
 * There is no shared noinline decode_runtime() choke point to hook. Decoded
 * plaintext lives in a fixed stack buffer inside ScopedObfString<N> and is
 * wiped with crypto_mini::secure_zero() on scope exit.
 */
namespace obf_detail {

constexpr uint32_t fnv1a_32_cstr(const char *s) noexcept {
    uint32_t hash = 0x811c9dc5u;
    if (s != nullptr) {
        while (*s != '\0') {
            hash ^= static_cast<uint8_t>(*s++);
            hash *= 0x01000193u;
        }
    }
    return hash;
}

constexpr uint32_t mix(uint32_t value) noexcept {
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    return value ? value : 0x9E3779B9u;
}

constexpr uint8_t rotl8(uint8_t v, unsigned r) noexcept {
    return static_cast<uint8_t>((v << r) | (v >> (8u - r)));
}

constexpr uint8_t rotr8(uint8_t v, unsigned r) noexcept {
    return static_cast<uint8_t>((v >> r) | (v << (8u - r)));
}

template<uint32_t Seed>
constexpr uint8_t encode_byte(uint8_t plain, uint8_t key) noexcept {
    constexpr unsigned kMode = Seed & 3u;
    constexpr unsigned kRot = ((Seed >> 2) % 7u) + 1u;
    constexpr uint8_t kSaltA = static_cast<uint8_t>((Seed >> 8) & 0xFFu);
    constexpr uint8_t kSaltB = static_cast<uint8_t>((Seed >> 16) & 0xFFu);
    if constexpr (kMode == 0u) {
        return static_cast<uint8_t>(plain ^ key);
    } else if constexpr (kMode == 1u) {
        return static_cast<uint8_t>(static_cast<uint8_t>(plain + key) ^ kSaltA);
    } else if constexpr (kMode == 2u) {
        return rotl8(static_cast<uint8_t>(plain ^ key), kRot);
    } else {
        return static_cast<uint8_t>(static_cast<uint8_t>(~(plain ^ key)) + kSaltB);
    }
}

template<uint32_t Seed>
__attribute__((always_inline))
inline uint8_t decode_byte(uint8_t enc, uint8_t key) noexcept {
    constexpr unsigned kMode = Seed & 3u;
    constexpr unsigned kRot = ((Seed >> 2) % 7u) + 1u;
    constexpr uint8_t kSaltA = static_cast<uint8_t>((Seed >> 8) & 0xFFu);
    constexpr uint8_t kSaltB = static_cast<uint8_t>((Seed >> 16) & 0xFFu);
    if constexpr (kMode == 0u) {
        return static_cast<uint8_t>(enc ^ key);
    } else if constexpr (kMode == 1u) {
        return static_cast<uint8_t>(static_cast<uint8_t>(enc ^ kSaltA) - key);
    } else if constexpr (kMode == 2u) {
        return static_cast<uint8_t>(rotr8(enc, kRot) ^ key);
    } else {
        return static_cast<uint8_t>(
                static_cast<uint8_t>(~static_cast<uint8_t>(enc - kSaltB)) ^ key);
    }
}

}  // namespace obf_detail

template<size_t N>
class ScopedObfString {
public:
    static_assert(N >= 1, "ScopedObfString requires a NUL-terminated string literal");

    template<uint32_t Seed>
    __attribute__((always_inline))
    static ScopedObfString<N> decode(const uint8_t (&enc)[N]) noexcept {
        ScopedObfString<N> out;
        if constexpr (N > 1) {
            const uint8_t *ptr = enc;
            uint32_t state = Seed;
            asm volatile("" : "+r"(ptr), "+r"(state) : : "memory");
            for (size_t i = 0; i < N - 1; ++i) {
                state = obf_detail::mix(state);
                uint32_t bv = ptr[i];
                asm volatile("" : "+r"(bv) : : "memory");
                out.buf_[i] = static_cast<char>(
                        obf_detail::decode_byte<Seed>(
                                static_cast<uint8_t>(bv),
                                static_cast<uint8_t>(state & 0xFFu)));
            }
        }
        out.buf_[N - 1] = '\0';
        return out;
    }

    ScopedObfString(const ScopedObfString &) = delete;
    ScopedObfString &operator=(const ScopedObfString &) = delete;

    ScopedObfString(ScopedObfString &&other) noexcept {
        for (size_t i = 0; i < N; ++i) {
            buf_[i] = other.buf_[i];
        }
        crypto_mini::secure_zero(other.buf_, sizeof(other.buf_));
    }

    ScopedObfString &operator=(ScopedObfString &&other) noexcept {
        if (this != &other) {
            for (size_t i = 0; i < N; ++i) {
                buf_[i] = other.buf_[i];
            }
            crypto_mini::secure_zero(other.buf_, sizeof(other.buf_));
        }
        return *this;
    }

    ~ScopedObfString() noexcept {
        crypto_mini::secure_zero(buf_, sizeof(buf_));
    }

    const char *c_str() const noexcept { return buf_; }
    const char *data() const noexcept { return buf_; }
    constexpr size_t size() const noexcept { return N - 1; }
    constexpr size_t length() const noexcept { return N - 1; }
    constexpr bool empty() const noexcept { return N <= 1; }
    std::string_view view() const noexcept { return std::string_view(buf_, N - 1); }
    std::string str() const { return std::string(buf_, N - 1); }

    operator std::string() const { return std::string(buf_, N - 1); }

private:
    ScopedObfString() noexcept : buf_{} {}

    char buf_[N];
};

template<size_t N>
inline std::string operator+(const ScopedObfString<N> &lhs, const std::string &rhs) {
    std::string out;
    out.reserve(lhs.size() + rhs.size());
    out.append(lhs.data(), lhs.size());
    out.append(rhs);
    return out;
}

template<size_t N>
inline std::string operator+(const std::string &lhs, const ScopedObfString<N> &rhs) {
    std::string out;
    out.reserve(lhs.size() + rhs.size());
    out.append(lhs);
    out.append(rhs.data(), rhs.size());
    return out;
}

template<size_t N>
inline std::string operator+(const ScopedObfString<N> &lhs, const char *rhs) {
    std::string out;
    const std::string_view rv = rhs != nullptr ? std::string_view(rhs) : std::string_view();
    out.reserve(lhs.size() + rv.size());
    out.append(lhs.data(), lhs.size());
    out.append(rv.data(), rv.size());
    return out;
}

template<size_t N>
inline std::string operator+(const char *lhs, const ScopedObfString<N> &rhs) {
    std::string out;
    const std::string_view lv = lhs != nullptr ? std::string_view(lhs) : std::string_view();
    out.reserve(lv.size() + rhs.size());
    out.append(lv.data(), lv.size());
    out.append(rhs.data(), rhs.size());
    return out;
}

template<size_t N1, size_t N2>
inline std::string operator+(const ScopedObfString<N1> &lhs, const ScopedObfString<N2> &rhs) {
    std::string out;
    out.reserve(lhs.size() + rhs.size());
    out.append(lhs.data(), lhs.size());
    out.append(rhs.data(), rhs.size());
    return out;
}

template<size_t N>
inline bool operator==(const ScopedObfString<N> &lhs, const std::string &rhs) noexcept {
    return lhs.view() == rhs;
}

template<size_t N>
inline bool operator==(const std::string &lhs, const ScopedObfString<N> &rhs) noexcept {
    return lhs == rhs.view();
}

template<size_t N>
inline bool operator!=(const ScopedObfString<N> &lhs, const std::string &rhs) noexcept {
    return lhs.view() != rhs;
}

template<size_t N>
inline bool operator!=(const std::string &lhs, const ScopedObfString<N> &rhs) noexcept {
    return lhs != rhs.view();
}

template<size_t N>
inline bool operator==(const ScopedObfString<N> &lhs, const char *rhs) noexcept {
    return rhs != nullptr && lhs.view() == rhs;
}

template<size_t N>
inline bool operator==(const char *lhs, const ScopedObfString<N> &rhs) noexcept {
    return lhs != nullptr && rhs.view() == lhs;
}

template<size_t N>
inline bool operator!=(const ScopedObfString<N> &lhs, const char *rhs) noexcept {
    return !(lhs == rhs);
}

template<size_t N>
inline bool operator!=(const char *lhs, const ScopedObfString<N> &rhs) noexcept {
    return !(lhs == rhs);
}

template<size_t N, uint32_t Seed>
struct ObfLit {
    static_assert(N >= 1, "ObfLit requires a NUL-terminated string literal");
    static constexpr uint32_t kSeed =
            obf_detail::mix(Seed ^ (static_cast<uint32_t>(N) * 2654435761u));

    uint8_t data[N];

    constexpr explicit ObfLit(const char (&s)[N]) noexcept : data{} {
        uint32_t state = kSeed;
        for (size_t i = 0; i < N; ++i) {
            state = obf_detail::mix(state);
            data[i] = obf_detail::encode_byte<kSeed>(
                    static_cast<uint8_t>(s[i]),
                    static_cast<uint8_t>(state & 0xFFu));
        }
    }

    __attribute__((always_inline))
    ScopedObfString<N> dec() const noexcept {
        return ScopedObfString<N>::template decode<kSeed>(data);
    }
};

#define OBF_SEED_ \
    (obf_detail::fnv1a_32_cstr(__FILE__) ^ \
     (static_cast<uint32_t>(__LINE__) * 0x9E3779B9u) ^ \
     ((static_cast<uint32_t>(__COUNTER__) + 1u) * 0x85EBCA6Bu))

#define OBF(s) \
    ([]() noexcept { \
        constexpr uint32_t kSiteSeed = OBF_SEED_; \
        static constexpr ObfLit<sizeof(s), kSiteSeed> kEnc(s); \
        return kEnc.dec(); \
    }())

#endif
