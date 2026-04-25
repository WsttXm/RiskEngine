#include "disk_size_collector.h"
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <unistd.h>

long long get_disk_total_size(const char *path) {
    struct statfs sf;
    if (syscall(__NR_statfs, path, &sf) == 0) {
        return (long long) sf.f_blocks * sf.f_bsize;
    }
    return -1;
}
