#include "disk_size_collector.h"
#include "../util/syscall_wrapper.h"

#include <cstring>
#include <limits>

long long get_disk_total_size(const char *path) {
    if (path == nullptr) return -1;
    struct statfs sf;
    memset(&sf, 0, sizeof(sf));
    if (my_statfs(path, &sf) == 0) {
        if (sf.f_blocks == 0 || sf.f_bsize == 0) return 0;
        const auto blocks = static_cast<unsigned long long>(sf.f_blocks);
        const auto block_size = static_cast<unsigned long long>(sf.f_bsize);
        const auto max = static_cast<unsigned long long>(
                std::numeric_limits<long long>::max());
        if (blocks > max / block_size) return -1;
        return static_cast<long long>(blocks * block_size);
    }
    return -1;
}
