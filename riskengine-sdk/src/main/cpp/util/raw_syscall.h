#ifndef RISKENGINE_RAW_SYSCALL_H
#define RISKENGINE_RAW_SYSCALL_H

#include <sys/syscall.h>

// Direct SVC/syscall instructions. Do not call libc syscall().
#if defined(__aarch64__)
static inline long raw_syscall6(long n, long a0, long a1, long a2,
                                long a3, long a4, long a5) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}
#elif defined(__arm__)
static inline long raw_syscall6(long n, long a0, long a1, long a2,
                                long a3, long a4, long a5) {
    register long r0 __asm__("r0") = a0;
    register long r1 __asm__("r1") = a1;
    register long r2 __asm__("r2") = a2;
    register long r3 __asm__("r3") = a3;
    register long r4 __asm__("r4") = a4;
    register long r5 __asm__("r5") = a5;
    register long nr __asm__("r6") = n;
    __asm__ volatile(
            "push {r7}\n\t"
            "mov r7, r6\n\t"
            "svc #0\n\t"
            "pop {r7}\n\t"
            : "+r"(r0)
            : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(nr)
            : "memory", "cc");
    return r0;
}
#elif defined(__x86_64__)
static inline long raw_syscall6(long n, long a0, long a1, long a2,
                                long a3, long a4, long a5) {
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a0;
    register long rsi __asm__("rsi") = a1;
    register long rdx __asm__("rdx") = a2;
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    __asm__ volatile("syscall"
                     : "+r"(rax)
                     : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory", "cc");
    return rax;
}
#elif defined(__i386__)
static inline long raw_syscall6(long n, long a0, long a1, long a2,
                                long a3, long a4, long a5) {
    (void) a5;
    long ret;
    __asm__ volatile(
            "push %%ebx\n\t"
            "movl %[a0], %%ebx\n\t"
            "int $0x80\n\t"
            "pop %%ebx"
            : "=a"(ret)
            : "a"(n), [a0] "r"(a0), "c"(a1), "d"(a2), "S"(a3), "D"(a4)
            : "memory", "cc");
    return ret;
}
#else
#error "unsupported ABI for raw_syscall"
#endif

static inline long raw_syscall0(long n) {
    return raw_syscall6(n, 0, 0, 0, 0, 0, 0);
}
static inline long raw_syscall1(long n, long a0) {
    return raw_syscall6(n, a0, 0, 0, 0, 0, 0);
}
static inline long raw_syscall2(long n, long a0, long a1) {
    return raw_syscall6(n, a0, a1, 0, 0, 0, 0);
}
static inline long raw_syscall3(long n, long a0, long a1, long a2) {
    return raw_syscall6(n, a0, a1, a2, 0, 0, 0);
}
static inline long raw_syscall4(long n, long a0, long a1, long a2, long a3) {
    return raw_syscall6(n, a0, a1, a2, a3, 0, 0);
}
static inline long raw_syscall5(long n, long a0, long a1, long a2, long a3, long a4) {
    return raw_syscall6(n, a0, a1, a2, a3, a4, 0);
}

#endif
