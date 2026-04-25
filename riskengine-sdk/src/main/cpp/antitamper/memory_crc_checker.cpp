#include "memory_crc_checker.h"
#include "../util/elf_parser.h"
#include <string>
#include <android/log.h>

#define LOG_TAG "RiskEngine:CRC"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static uint32_t saved_text_crc = 0;
static uint32_t saved_plt_crc = 0;
static const char *saved_so_path = nullptr;

bool init_memory_crc(const char *so_path) {
    saved_so_path = so_path;
    saved_text_crc = get_section_crc_from_disk(so_path, ".text");
    saved_plt_crc = get_section_crc_from_disk(so_path, ".plt");

    if (saved_text_crc == 0 && saved_plt_crc == 0) {
        LOGD("Failed to compute initial CRC for %s", so_path);
        return false;
    }

    LOGD("CRC initialized: text=0x%08x, plt=0x%08x", saved_text_crc, saved_plt_crc);
    return true;
}

bool check_memory_crc() {
    if (!saved_so_path || (saved_text_crc == 0 && saved_plt_crc == 0)) {
        return true; // Not initialized, skip
    }

    bool intact = true;

    if (saved_text_crc != 0) {
        uint32_t current = get_section_crc_from_memory(saved_so_path, ".text");
        if (current != 0 && current != saved_text_crc) {
            LOGD("TEXT section CRC mismatch: disk=0x%08x, mem=0x%08x",
                 saved_text_crc, current);
            intact = false;
        }
    }

    if (saved_plt_crc != 0) {
        uint32_t current = get_section_crc_from_memory(saved_so_path, ".plt");
        if (current != 0 && current != saved_plt_crc) {
            LOGD("PLT section CRC mismatch: disk=0x%08x, mem=0x%08x",
                 saved_plt_crc, current);
            intact = false;
        }
    }

    return intact;
}
