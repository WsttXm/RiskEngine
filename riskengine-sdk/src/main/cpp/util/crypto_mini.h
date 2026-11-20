#ifndef RISKENGINE_CRYPTO_MINI_H
#define RISKENGINE_CRYPTO_MINI_H

#include <cstddef>
#include <cstdint>
#include <cstring>

/**
 * Self-contained SHA-256 and HMAC-SHA256 (FIPS 180-4 / RFC 2104) with no
 * external library dependency, plus constant-time comparison and secure zeroing.
 */
namespace crypto_mini {

constexpr size_t kSha256DigestSize = 32;
constexpr size_t kSha256BlockSize = 64;

inline void secure_zero(void *ptr, size_t len) {
    if (ptr == nullptr || len == 0) return;
    volatile uint8_t *p = reinterpret_cast<volatile uint8_t *>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

inline bool ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

class Sha256 {
public:
    Sha256() { reset(); }

    void reset() {
        state_[0] = 0x6a09e667u;
        state_[1] = 0xbb67ae85u;
        state_[2] = 0x3c6ef372u;
        state_[3] = 0xa54ff53au;
        state_[4] = 0x510e527fu;
        state_[5] = 0x9b05688cu;
        state_[6] = 0x1f83d9abu;
        state_[7] = 0x5be0cd19u;
        bit_count_ = 0;
        buf_len_ = 0;
    }

    void update(const uint8_t *data, size_t len) {
        if (data == nullptr || len == 0) return;
        size_t i = 0;
        if (buf_len_ > 0) {
            while (i < len && buf_len_ < kSha256BlockSize) {
                buf_[buf_len_++] = data[i++];
            }
            if (buf_len_ == kSha256BlockSize) {
                transform(buf_);
                bit_count_ += 512;
                buf_len_ = 0;
            }
        }
        while (i + kSha256BlockSize <= len) {
            transform(data + i);
            bit_count_ += 512;
            i += kSha256BlockSize;
        }
        while (i < len) {
            buf_[buf_len_++] = data[i++];
        }
    }

    void final(uint8_t out[kSha256DigestSize]) {
        const uint64_t total_bits = bit_count_ + static_cast<uint64_t>(buf_len_) * 8ull;
        buf_[buf_len_++] = 0x80u;
        if (buf_len_ > 56) {
            std::memset(buf_ + buf_len_, 0, kSha256BlockSize - buf_len_);
            transform(buf_);
            buf_len_ = 0;
        }
        std::memset(buf_ + buf_len_, 0, 56 - buf_len_);
        for (int i = 0; i < 8; ++i) {
            buf_[56 + i] = static_cast<uint8_t>((total_bits >> ((7 - i) * 8)) & 0xFFu);
        }
        transform(buf_);

        for (int i = 0; i < 8; ++i) {
            out[i * 4 + 0] = static_cast<uint8_t>((state_[i] >> 24) & 0xFFu);
            out[i * 4 + 1] = static_cast<uint8_t>((state_[i] >> 16) & 0xFFu);
            out[i * 4 + 2] = static_cast<uint8_t>((state_[i] >> 8) & 0xFFu);
            out[i * 4 + 3] = static_cast<uint8_t>(state_[i] & 0xFFu);
        }
        secure_zero(buf_, sizeof(buf_));
        secure_zero(state_, sizeof(state_));
    }

private:
    static inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32u - n));
    }

    void transform(const uint8_t block[kSha256BlockSize]) {
        static constexpr uint32_t kRound[64] = {
                0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
                0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
                0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
                0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
                0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
                0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
                0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
                0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
                0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
                0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
                0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
                0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
                0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
                0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
                0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
                0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
        };

        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4 + 0]) << 24)
                 | (static_cast<uint32_t>(block[i * 4 + 1]) << 16)
                 | (static_cast<uint32_t>(block[i * 4 + 2]) << 8)
                 |  static_cast<uint32_t>(block[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + kRound[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
        secure_zero(w, sizeof(w));
    }

    uint32_t state_[8] = {};
    uint8_t buf_[kSha256BlockSize] = {};
    uint64_t bit_count_ = 0;
    size_t buf_len_ = 0;
};

inline void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[kSha256DigestSize]) {
    uint8_t key_block[kSha256BlockSize] = {0};
    if (key_len > kSha256BlockSize) {
        Sha256 kh;
        kh.update(key, key_len);
        kh.final(key_block);
    } else if (key != nullptr && key_len > 0) {
        std::memcpy(key_block, key, key_len);
    }

    uint8_t ipad[kSha256BlockSize];
    uint8_t opad[kSha256BlockSize];
    for (size_t i = 0; i < kSha256BlockSize; ++i) {
        ipad[i] = static_cast<uint8_t>(key_block[i] ^ 0x36u);
        opad[i] = static_cast<uint8_t>(key_block[i] ^ 0x5cu);
    }

    uint8_t inner[kSha256DigestSize];
    Sha256 inner_hash;
    inner_hash.update(ipad, sizeof(ipad));
    inner_hash.update(data, data_len);
    inner_hash.final(inner);

    Sha256 outer_hash;
    outer_hash.update(opad, sizeof(opad));
    outer_hash.update(inner, sizeof(inner));
    outer_hash.final(out);

    secure_zero(key_block, sizeof(key_block));
    secure_zero(ipad, sizeof(ipad));
    secure_zero(opad, sizeof(opad));
    secure_zero(inner, sizeof(inner));
}

}  // namespace crypto_mini

#endif
