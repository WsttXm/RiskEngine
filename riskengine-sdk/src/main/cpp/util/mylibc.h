#ifndef RISKENGINE_MYLIBC_H
#define RISKENGINE_MYLIBC_H

#include <stddef.h>
#include <stdint.h>
#ifndef __cplusplus
#include <stdbool.h>
#endif

/*
 * Always-inline, zero-libc-dependency string, memory, and numeric helpers.
 * Compiler barriers prevent LoopIdiomRecognize from lowering loops back into
 * PLT calls to hookable libc symbols (memset/memcpy/memcmp/strlen/etc.).
 */
#if defined(__GNUC__) || defined(__clang__)
#define RISKENGINE_ALWAYS_INLINE __attribute__((always_inline)) static inline
#else
#define RISKENGINE_ALWAYS_INLINE static inline
#endif

RISKENGINE_ALWAYS_INLINE int my_is_space(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

RISKENGINE_ALWAYS_INLINE int my_is_digit(unsigned char c) {
    return c >= '0' && c <= '9';
}

RISKENGINE_ALWAYS_INLINE int my_hex_digit_value(unsigned char c) {
    if (c >= '0' && c <= '9') {
        return (int) (c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return (int) (c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return (int) (c - 'A' + 10);
    }
    return -1;
}

RISKENGINE_ALWAYS_INLINE size_t my_strlen(const char *s) {
    if (!s) {
        return 0;
    }
    size_t len = 0;
    while (s[len] != '\0') {
        len++;
        __asm__ volatile("" : "+r"(len) : : "memory");
    }
    return len;
}

RISKENGINE_ALWAYS_INLINE int my_strcmp(const char *s1, const char *s2) {
    if (s1 == s2) {
        return 0;
    }
    if (!s1) {
        return -1;
    }
    if (!s2) {
        return 1;
    }
    const unsigned char *p1 = (const unsigned char *) s1;
    const unsigned char *p2 = (const unsigned char *) s2;
    while (*p1 != '\0' && *p1 == *p2) {
        p1++;
        p2++;
        __asm__ volatile("" : : : "memory");
    }
    return (int) (*p1) - (int) (*p2);
}

RISKENGINE_ALWAYS_INLINE int my_strncmp(const char *s1, const char *s2, size_t n) {
    if (n == 0) {
        return 0;
    }
    if (s1 == s2) {
        return 0;
    }
    if (!s1) {
        return -1;
    }
    if (!s2) {
        return 1;
    }
    const unsigned char *p1 = (const unsigned char *) s1;
    const unsigned char *p2 = (const unsigned char *) s2;
    while (n > 0) {
        unsigned char c1 = *p1++;
        unsigned char c2 = *p2++;
        if (c1 != c2) {
            return (int) c1 - (int) c2;
        }
        if (c1 == '\0') {
            return 0;
        }
        n--;
        __asm__ volatile("" : : : "memory");
    }
    return 0;
}

RISKENGINE_ALWAYS_INLINE const char *my_strstr(const char *haystack, const char *needle) {
    if (!haystack || !needle) {
        return NULL;
    }
    if (needle[0] == '\0') {
        return haystack;
    }
    size_t needle_len = my_strlen(needle);
    char first = needle[0];
    for (const char *p = haystack; *p != '\0'; p++) {
        if (*p == first && my_strncmp(p, needle, needle_len) == 0) {
            return p;
        }
    }
    return NULL;
}

RISKENGINE_ALWAYS_INLINE int my_memcmp(const void *s1, const void *s2, size_t n) {
    if (n == 0 || s1 == s2) {
        return 0;
    }
    if (!s1) {
        return -1;
    }
    if (!s2) {
        return 1;
    }
    const unsigned char *p1 = (const unsigned char *) s1;
    const unsigned char *p2 = (const unsigned char *) s2;
    for (size_t i = 0; i < n; i++) {
        unsigned char a = p1[i];
        unsigned char b = p2[i];
        if (a != b) {
            return (int) a - (int) b;
        }
        __asm__ volatile("" : : : "memory");
    }
    return 0;
}

RISKENGINE_ALWAYS_INLINE void *my_memset(void *dst, int c, size_t n) {
    if (!dst || n == 0) {
        return dst;
    }
    unsigned char *d = (unsigned char *) dst;
    unsigned char val = (unsigned char) c;
    for (size_t i = 0; i < n; i++) {
        d[i] = val;
        __asm__ volatile("" : "+r"(d) : : "memory");
    }
    return dst;
}

RISKENGINE_ALWAYS_INLINE void *my_memcpy(void *dst, const void *src, size_t n) {
    if (!dst || !src || n == 0 || dst == src) {
        return dst;
    }
    unsigned char *d = (unsigned char *) dst;
    const unsigned char *s = (const unsigned char *) src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
        __asm__ volatile("" : "+r"(d) : : "memory");
    }
    return dst;
}

RISKENGINE_ALWAYS_INLINE size_t my_strlcpy(char *dst, const char *src, size_t siz) {
    if (!src) {
        if (dst && siz > 0) {
            dst[0] = '\0';
        }
        return 0;
    }
    size_t src_len = my_strlen(src);
    if (dst && siz > 0) {
        size_t copy_len = (src_len >= siz) ? (siz - 1) : src_len;
        my_memcpy(dst, src, copy_len);
        dst[copy_len] = '\0';
    }
    return src_len;
}

RISKENGINE_ALWAYS_INLINE int my_atoi(const char *s) {
    if (!s) {
        return 0;
    }
    while (my_is_space((unsigned char) *s)) {
        s++;
    }
    int neg = 0;
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }
    uint64_t acc = 0;
    const uint64_t limit = neg ? ((uint64_t) INT32_MAX + 1ULL) : (uint64_t) INT32_MAX;
    while (my_is_digit((unsigned char) *s)) {
        uint64_t digit = (uint64_t) (*s - '0');
        if (acc > (limit - digit) / 10ULL) {
            return neg ? INT32_MIN : INT32_MAX;
        }
        acc = acc * 10ULL + digit;
        s++;
    }
    if (neg) {
        if (acc == (uint64_t) INT32_MAX + 1ULL) {
            return INT32_MIN;
        }
        return -(int) acc;
    }
    return (int) acc;
}

RISKENGINE_ALWAYS_INLINE bool my_hex_parse_prefix(const char *s,
                                                  uint64_t *out,
                                                  const char **end_out) {
    if (!s || !out) {
        return false;
    }
    const char *p = s;
    while (my_is_space((unsigned char) *p)) {
        p++;
    }
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }
    uint64_t acc = 0;
    size_t digits = 0;
    while (*p != '\0') {
        int d = my_hex_digit_value((unsigned char) *p);
        if (d < 0) {
            break;
        }
        if (acc > (UINT64_MAX >> 4)) {
            return false;
        }
        acc = (acc << 4) | (uint64_t) d;
        digits++;
        p++;
    }
    if (digits == 0) {
        return false;
    }
    *out = acc;
    if (end_out) {
        *end_out = p;
    }
    return true;
}

RISKENGINE_ALWAYS_INLINE bool my_hex_parse(const char *s, uint64_t *out) {
    const char *end = NULL;
    if (!my_hex_parse_prefix(s, out, &end)) {
        return false;
    }
    while (*end != '\0' && my_is_space((unsigned char) *end)) {
        end++;
    }
    return *end == '\0';
}

#endif  // RISKENGINE_MYLIBC_H
