#include "disk_size_collector.h"
#include "../util/syscall_wrapper.h"

#include <cstring>

long long get_disk_total_size(const char *path) {
    if (path == nullptr) return -1;
    struct statfs sf;
    memset(&sf, 0, sizeof(sf));
    if (my_statfs(path, &sf) == 0) {
        return (long long) sf.f_blocks * sf.f_bsize;
    }
    return -1;
}
