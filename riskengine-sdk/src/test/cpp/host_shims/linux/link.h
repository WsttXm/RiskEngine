#ifndef RISKENGINE_HOST_SHIM_LINK_H
#define RISKENGINE_HOST_SHIM_LINK_H

#include <cstddef>
#include <elf.h>

#if defined(__LP64__)
#define ElfW(type) Elf64_##type
#else
#define ElfW(type) Elf32_##type
#endif

struct dl_phdr_info {
    ElfW(Addr) dlpi_addr;
    const char *dlpi_name;
    const ElfW(Phdr) *dlpi_phdr;
    ElfW(Half) dlpi_phnum;
};

inline int dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *), void *) {
    return 0;
}

#endif  // RISKENGINE_HOST_SHIM_LINK_H
