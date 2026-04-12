#ifndef RISKENGINE_ELF_PARSER_H
#define RISKENGINE_ELF_PARSER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compute CRC32 checksum of a memory region
uint32_t compute_crc32(const void *data, size_t length);

// Get CRC32 of a specific ELF section from disk
uint32_t get_section_crc_from_disk(const char *so_path, const char *section_name);

// Get CRC32 of a specific ELF section from memory
uint32_t get_section_crc_from_memory(const char *so_path, const char *section_name);

#ifdef __cplusplus
}
#endif

#endif // RISKENGINE_ELF_PARSER_H
