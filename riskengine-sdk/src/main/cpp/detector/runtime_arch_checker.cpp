#include "runtime_arch_checker.h"

#include <string>

std::string get_runtime_arch() {
#if defined(__x86_64__)
    return "X86_64";
#elif defined(__i386__)
    return "I386";
#elif defined(__aarch64__)
    return "AARCH64";
#elif defined(__arm__)
    return "ARM";
#else
    return "UNKNOWN";
#endif
}
