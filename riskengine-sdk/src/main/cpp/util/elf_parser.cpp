#include "elf_parser.h"
#include "syscall_wrapper.h"

#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>

#define LOG_TAG "RiskEngine:ELF"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91b, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d09, 0x90bf1d17, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4db, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c58, 0xdd0d7822, 0x3a6c5767, 0x4d6b6731,
    0xd4624a0a, 0xa365399c, 0x0a0e6133, 0x7d079eb1, 0xf00f9344, 0x8708a3d2,
    0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9,
    0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
    0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
    0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703,
    0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
    0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226,
    0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d,
    0x7cdcefb9, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242, 0x68ddb3f6, 0x1fda836e,
    0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 0x88085ae6, 0xff0f6b70,
    0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
    0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
    0xa9bcae53, 0xdede86c5, 0x5765b0d6, 0x2062a040, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b0, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5
};

uint32_t compute_crc32(const void *data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t *p = (const uint8_t *) data;
    for (size_t i = 0; i < length; i++) {
        crc = crc32_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

uint32_t get_section_crc_from_disk(const char *so_path, const char *section_name) {
    int fd = (int) my_openat(AT_FDCWD, so_path, O_RDONLY, 0);
    if (fd < 0) return 0;

    // Read ELF header
    Elf64_Ehdr ehdr;
    if (my_read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        my_close(fd);
        return 0;
    }

    // Read section header string table
    Elf64_Shdr shstrtab_hdr;
    my_lseek(fd, ehdr.e_shoff + ehdr.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
    my_read(fd, &shstrtab_hdr, sizeof(shstrtab_hdr));

    char *shstrtab = (char *) malloc(shstrtab_hdr.sh_size);
    my_lseek(fd, shstrtab_hdr.sh_offset, SEEK_SET);
    my_read(fd, shstrtab, shstrtab_hdr.sh_size);

    // Find target section
    uint32_t crc = 0;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        my_lseek(fd, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
        my_read(fd, &shdr, sizeof(shdr));

        if (strcmp(shstrtab + shdr.sh_name, section_name) == 0) {
            void *section_data = malloc(shdr.sh_size);
            my_lseek(fd, shdr.sh_offset, SEEK_SET);
            my_read(fd, section_data, shdr.sh_size);
            crc = compute_crc32(section_data, shdr.sh_size);
            free(section_data);
            break;
        }
    }

    free(shstrtab);
    my_close(fd);
    return crc;
}

uint32_t get_section_crc_from_memory(const char *so_path, const char *section_name) {
    void *handle = dlopen(so_path, RTLD_NOLOAD);
    if (!handle) return 0;

    // Get base address from /proc/self/maps
    // This is a simplified version; production code should parse maps more carefully
    char maps_line[512];
    char buf[8192];
    int fd = (int) my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) {
        dlclose(handle);
        return 0;
    }

    uintptr_t base_addr = 0;
    ssize_t n = my_read(fd, buf, sizeof(buf) - 1);
    my_close(fd);

    if (n > 0) {
        buf[n] = '\0';
        char *line = strtok(buf, "\n");
        while (line) {
            if (strstr(line, so_path) && strstr(line, "r-xp")) {
                sscanf(line, "%lx-", &base_addr);
                break;
            }
            line = strtok(NULL, "\n");
        }
    }

    dlclose(handle);
    if (base_addr == 0) return 0;

    // Parse ELF in memory
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) base_addr;
    Elf64_Shdr *shdrs = (Elf64_Shdr *) (base_addr + ehdr->e_shoff);
    char *shstrtab_mem = (char *) (base_addr + shdrs[ehdr->e_shstrndx].sh_offset);

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (strcmp(shstrtab_mem + shdrs[i].sh_name, section_name) == 0) {
            void *section_mem = (void *) (base_addr + shdrs[i].sh_offset);
            return compute_crc32(section_mem, shdrs[i].sh_size);
        }
    }

    return 0;
}
