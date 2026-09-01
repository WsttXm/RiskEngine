#ifndef RISKENGINE_OBF_STR_H
#define RISKENGINE_OBF_STR_H

#include <cstddef>
#include <string>

template<size_t N>
struct ObfLit {
    char data[N];
    static constexpr char k = 0x5A;

    constexpr ObfLit(const char (&s)[N]) : data{} {
        for (size_t i = 0; i < N; ++i) {
            data[i] = static_cast<char>(s[i] ^ k);
        }
    }

    std::string dec() const {
        std::string out(N > 0 ? N - 1 : 0, '\0');
        for (size_t i = 0; i + 1 < N; ++i) {
            out[i] = static_cast<char>(data[i] ^ k);
        }
        return out;
    }
};

#define OBF(s) ([] { constexpr ObfLit<sizeof(s)> enc(s); return enc.dec(); }())

#endif
