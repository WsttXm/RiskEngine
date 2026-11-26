#include "runtime_arch_checker.h"

#include <string>

std::string get_runtime_arch() {
#if defined(__x86_64__)
    return "X86_64";
#elif defined(__aarch64__)
    return "AARCH64";
#else
    return "UNKNOWN";
#endif
}
