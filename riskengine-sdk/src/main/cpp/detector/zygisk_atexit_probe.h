#ifndef RISKENGINE_ZYGISK_ATEXIT_PROBE_H
#define RISKENGINE_ZYGISK_ATEXIT_PROBE_H

#include "util/maps_parser.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/**
 * Native Zygisk Bionic atexit array forensics returning a payload_codec frame.
 *
 * Locates _ZL7g_array (including LLVM SRA splits _ZL7g_array.0..4) and
 * _ZL13g_atexit_lock in disk libc.so local SHT_SYMTAB, acquires the lock
 * strictly via non-blocking pthread_mutex_trylock, copies entries exclusively
 * via safe_mem::PipeMemoryReader (zero direct dereference), and detects
 * anonymous-executable callbacks and >= 3 contiguous unloaded-module holes.
 */
std::string native_get_zygisk_atexit_probe();

namespace zygisk_atexit {

enum class ObjectState : uint8_t {
    kUnsupported = 0,
    kMalformed = 1,
    kFound = 2,
};

struct LibcObjects {
    ObjectState state = ObjectState::kUnsupported;
    uintptr_t mutex = 0;
    size_t mutex_size = 0;
    // [0]=array_, [1]=size_, [2]=extracted_count_, [3]=capacity_, [4]=total_appends_
    std::array<uintptr_t, 5> fields{};
};

struct AtexitEntry {
    uintptr_t fn = 0;
    uintptr_t arg = 0;
    uintptr_t dso = 0;

    bool empty() const noexcept {
        return fn == 0 && arg == 0 && dso == 0;
    }
};

struct AnonCallbackHit {
    size_t index = 0;
    std::string owner;
};

struct HoleRunHit {
    size_t start = 0;
    size_t end = 0;
    size_t count = 0;
};

struct TableAnalysis {
    bool bounded = false;
    bool dense_clearing = false;
    size_t null_entries = 0;
    size_t unresolved_callbacks = 0;
    std::vector<AnonCallbackHit> anon_callbacks;
    std::vector<HoleRunHit> anchored_holes;
};

/** Pure ELF SHT_SYMTAB parser exposed for host C++ fixture testing. */
LibcObjects locate_libc_objects(const uint8_t *image, size_t image_size, uintptr_t bias) noexcept;

/** Pure atexit table analyzer exposed for host C++ fixture testing. */
TableAnalysis interpret_atexit_table(const std::vector<AtexitEntry> &entries,
                                     const std::vector<MapEntry> &stable_maps);

}  // namespace zygisk_atexit

#endif  // RISKENGINE_ZYGISK_ATEXIT_PROBE_H
