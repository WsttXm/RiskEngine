#include "native_debug_detector.h"
#include "../collector/system_property_collector.h"
#include "../util/mylibc.h"
#include "../util/obf_str.h"
#include "../util/payload_codec.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

bool is_all_digits(const std::string &s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

size_t find_line_prefix(const std::string &text, const char *key, size_t key_len) {
    size_t pos = 0;
    while (pos < text.size()) {
        if (text.size() - pos >= key_len
                && std::memcmp(text.data() + pos, key, key_len) == 0) {
            return pos;
        }
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return std::string::npos;
}

int parse_tracer_pid_from_status(const std::string &status) {
    const auto key = OBF("TracerPid:");
    const size_t pos = find_line_prefix(status, key.c_str(), key.size());
    if (pos == std::string::npos) return -1;
    const char *p = status.c_str() + pos + key.size();
    while (*p == ' ' || *p == '\t') ++p;
    if (*p < '0' || *p > '9') return -1;
    char *end = nullptr;
    long val = std::strtol(p, &end, 10);
    if (end == p || val < 0 || val > 2147483647L) return -1;
    return static_cast<int>(val);
}

std::string parse_name_from_status(const std::string &status) {
    const auto key = OBF("Name:");
    const size_t pos = find_line_prefix(status, key.c_str(), key.size());
    if (pos == std::string::npos) return {};
    size_t start = pos + key.size();
    while (start < status.size() && (status[start] == ' ' || status[start] == '\t')) {
        ++start;
    }
    size_t end = status.find('\n', start);
    if (end == std::string::npos) end = status.size();
    while (end > start && (status[end - 1] == '\r' || status[end - 1] == ' ' || status[end - 1] == '\t')) {
        --end;
    }
    return status.substr(start, end - start);
}

// Parses field 3 (process/thread state) from /proc/<pid>/task/<tid>/stat.
// Format: "<pid> (<comm>) <state> ..." where <comm> may contain spaces and ')'.
// Always locates the LAST ')' before reading the state character.
char parse_stat_state(std::string_view stat_content) {
    const size_t rparen = stat_content.rfind(')');
    if (rparen == std::string_view::npos) {
        return '\0';
    }
    size_t pos = rparen + 1;
    while (pos < stat_content.size()
            && (stat_content[pos] == ' ' || stat_content[pos] == '\t')) {
        ++pos;
    }
    if (pos >= stat_content.size()) {
        return '\0';
    }
    return stat_content[pos];
}

std::string trim_whitespace(std::string_view raw) {
    size_t start = 0;
    while (start < raw.size()
            && (raw[start] == ' ' || raw[start] == '\t'
                || raw[start] == '\r' || raw[start] == '\n')) {
        ++start;
    }
    size_t end = raw.size();
    while (end > start
            && (raw[end - 1] == ' ' || raw[end - 1] == '\t'
                || raw[end - 1] == '\r' || raw[end - 1] == '\n')) {
        --end;
    }
    return std::string(raw.substr(start, end - start));
}

bool is_jdwp_thread_name(std::string_view comm) {
    if (comm.empty()) return false;
    const auto jdwp = OBF("JDWP");
    if (comm.find(jdwp.c_str()) != std::string_view::npos) {
        return true;
    }
    const auto adb_conn = OBF("ADB connection");
    if (comm.find(adb_conn.c_str()) != std::string_view::npos) {
        return true;
    }
    return false;
}

bool detect_jdwp_abstract_socket() {
    const auto unix_path = OBF("/proc/net/unix");
    std::string content = read_file_string(unix_path.c_str(), 256 * 1024);
    if (content.empty()) {
        return false;
    }
    const auto jdwp_ctrl = OBF("@jdwp-control");
    return content.find(jdwp_ctrl.c_str()) != std::string::npos;
}

}  // namespace

int get_tracer_pid() {
    const auto self_status_path = OBF("/proc/self/status");
    std::string self_status = read_file_string(self_status_path.c_str(), 8192);
    int main_tracer = self_status.empty() ? -1 : parse_tracer_pid_from_status(self_status);
    if (main_tracer > 0) {
        return main_tracer;
    }

    // Dual-path check: /proc/<pid>/task/<pid>/status resists hooks on /proc/self/status only.
    const pid_t pid = getpid();
    if (pid > 0) {
        char pid_task_path[96] = {};
        const auto fmt = OBF("/proc/%d/task/%d/status");
        std::snprintf(pid_task_path, sizeof(pid_task_path), fmt.c_str(),
                      static_cast<int>(pid), static_cast<int>(pid));
        std::string alt_status = read_file_string(pid_task_path, 8192);
        if (!alt_status.empty()) {
            int alt_tracer = parse_tracer_pid_from_status(alt_status);
            if (alt_tracer > 0) {
                return alt_tracer;
            }
            if (main_tracer < 0 && alt_tracer == 0) {
                main_tracer = 0;
            }
        }
    }

    // Per-thread status scan in case a debugger attaches to a non-main thread.
    const auto task_dir = OBF("/proc/self/task");
    RawDirResult tasks = raw_list_dir(task_dir.c_str());
    if (tasks.ok()) {
        const auto prefix = OBF("/proc/self/task/");
        const auto suffix = OBF("/status");
        for (const auto &tid : tasks.names) {
            if (!is_all_digits(tid)) continue;
            std::string path = std::string(prefix.c_str()) + tid + suffix.c_str();
            std::string status = read_file_string(path.c_str(), 4096);
            if (status.empty()) continue;
            int tracer = parse_tracer_pid_from_status(status);
            if (tracer > 0) {
                return tracer;
            }
        }
    }
    return main_tracer;
}

std::string native_get_debug_evidence() {
    payload_codec::PayloadBuilder builder(payload_codec::Status::OK, 0);

    bool any_status_read = false;
    int status_err = 0;
    int self_tracer = -1;
    int alt_tracer = -1;
    int first_nonzero_tracer = 0;
    std::string first_nonzero_loc;

    // 1. Path A: /proc/self/status
    const auto self_status_path = OBF("/proc/self/status");
    std::string self_status = read_file_string(self_status_path.c_str(), 8192);
    if (!self_status.empty()) {
        self_tracer = parse_tracer_pid_from_status(self_status);
        if (self_tracer >= 0) {
            any_status_read = true;
            if (self_tracer > 0) {
                first_nonzero_tracer = self_tracer;
                first_nonzero_loc = self_status_path.c_str();
            }
        }
    } else if (status_err == 0) {
        status_err = raw_last_error();
    }

    // 2. Path B: /proc/<pid>/task/<pid>/status
    const pid_t pid = getpid();
    std::string pid_task_path_str;
    if (pid > 0) {
        char buf[96] = {};
        const auto fmt = OBF("/proc/%d/task/%d/status");
        std::snprintf(buf, sizeof(buf), fmt.c_str(),
                      static_cast<int>(pid), static_cast<int>(pid));
        pid_task_path_str = buf;
        std::string alt_status = read_file_string(pid_task_path_str.c_str(), 8192);
        if (!alt_status.empty()) {
            alt_tracer = parse_tracer_pid_from_status(alt_status);
            if (alt_tracer >= 0) {
                any_status_read = true;
                if (alt_tracer > 0 && first_nonzero_tracer == 0) {
                    first_nonzero_tracer = alt_tracer;
                    first_nonzero_loc = pid_task_path_str;
                }
            }
        } else if (status_err == 0) {
            status_err = raw_last_error();
        }
    }

    // 3. Path C: /proc/self/task/*/status, stat ('t'), wchan ('ptrace_stop'), comm (JDWP)
    const auto task_dir = OBF("/proc/self/task");
    RawDirResult tasks = raw_list_dir(task_dir.c_str());
    bool reported_stat_traced = false;
    bool reported_wchan_ptrace = false;
    bool reported_jdwp_thread = false;
    int task_tracer_hit = 0;
    std::string task_tracer_loc;

    if (tasks.ok()) {
        const auto prefix = OBF("/proc/self/task/");
        const auto status_suf = OBF("/status");
        const auto stat_suf = OBF("/stat");
        const auto wchan_suf = OBF("/wchan");
        const auto comm_suf = OBF("/comm");
        const auto ptrace_stop = OBF("ptrace_stop");

        for (const auto &tid : tasks.names) {
            if (!is_all_digits(tid)) continue;
            const std::string base = std::string(prefix.c_str()) + tid;

            // Per-thread status: TracerPid + Name
            std::string t_status_path = base + status_suf.c_str();
            std::string t_status = read_file_string(t_status_path.c_str(), 4096);
            std::string t_name;
            if (!t_status.empty()) {
                int t_tracer = parse_tracer_pid_from_status(t_status);
                if (t_tracer >= 0) {
                    any_status_read = true;
                    if (t_tracer > 0 && task_tracer_hit == 0) {
                        task_tracer_hit = t_tracer;
                        task_tracer_loc = t_status_path;
                    }
                }
                if (!reported_jdwp_thread) {
                    t_name = parse_name_from_status(t_status);
                    if (is_jdwp_thread_name(t_name)) {
                        reported_jdwp_thread = true;
                        payload_codec::RecordBuilder rec;
                        rec.add("code", OBF("jdwp_thread").c_str())
                           .add("value", t_name)
                           .add("loc", base + comm_suf.c_str());
                        builder.add_record(rec);
                    }
                }
            } else if (status_err == 0) {
                status_err = raw_last_error();
            }

            // Fallback comm read ONLY when status did not yield a thread Name
            if (!reported_jdwp_thread && t_name.empty()) {
                std::string t_comm_path = base + comm_suf.c_str();
                std::string t_comm = trim_whitespace(read_file_string(t_comm_path.c_str(), 128));
                if (is_jdwp_thread_name(t_comm)) {
                    reported_jdwp_thread = true;
                    payload_codec::RecordBuilder rec;
                    rec.add("code", OBF("jdwp_thread").c_str())
                       .add("value", t_comm)
                       .add("loc", t_comm_path);
                    builder.add_record(rec);
                }
            }

            // Per-thread stat field 3: 't' (TASK_TRACED / tracing stop)
            if (!reported_stat_traced) {
                std::string t_stat_path = base + stat_suf.c_str();
                std::string t_stat = read_file_string(t_stat_path.c_str(), 1024);
                if (!t_stat.empty() && parse_stat_state(t_stat) == 't') {
                    reported_stat_traced = true;
                    payload_codec::RecordBuilder rec;
                    rec.add("code", OBF("stat_tracing_stop").c_str())
                       .add("value", tid)
                       .add("loc", t_stat_path);
                    builder.add_record(rec);
                }
            }

            // Per-thread wchan: ptrace_stop
            if (!reported_wchan_ptrace) {
                std::string t_wchan_path = base + wchan_suf.c_str();
                std::string t_wchan = trim_whitespace(read_file_string(t_wchan_path.c_str(), 256));
                if (!t_wchan.empty() && t_wchan.find(ptrace_stop.c_str()) != std::string::npos) {
                    reported_wchan_ptrace = true;
                    payload_codec::RecordBuilder rec;
                    rec.add("code", OBF("wchan_ptrace_stop").c_str())
                       .add("value", tid)
                       .add("loc", t_wchan_path);
                    builder.add_record(rec);
                }
            }
        }
    }

    if (first_nonzero_tracer == 0 && task_tracer_hit > 0) {
        first_nonzero_tracer = task_tracer_hit;
        first_nonzero_loc = task_tracer_loc;
    }

    const auto tracer_pid_key = OBF("tracer_pid");
    if (first_nonzero_tracer > 0) {
        payload_codec::RecordBuilder rec;
        rec.add("code", tracer_pid_key.c_str())
           .add_int("value", first_nonzero_tracer)
           .add("loc", first_nonzero_loc);
        builder.add_record(rec);
    }

    // Dual-path contradiction: /proc/self/status reports 0 while alt/task status reports > 0.
    int alt_hit = alt_tracer > 0 ? alt_tracer : task_tracer_hit;
    if (self_tracer == 0 && alt_hit > 0) {
        payload_codec::RecordBuilder rec;
        rec.add("code", OBF("tracer_pid_mismatch").c_str())
           .add("value", std::string(OBF("self=0,alt=").c_str()) + std::to_string(alt_hit))
           .add("loc", alt_tracer > 0 ? pid_task_path_str : task_tracer_loc);
        builder.add_record(rec);
    }

    // 4. Abstract socket @jdwp-control in /proc/net/unix (SELinux-safe: empty/denied != threat)
    if (detect_jdwp_abstract_socket()) {
        payload_codec::RecordBuilder rec;
        rec.add("code", OBF("jdwp_socket").c_str())
           .add("value", OBF("@jdwp-control").c_str())
           .add("loc", OBF("/proc/net/unix").c_str());
        builder.add_record(rec);
    }

    builder.add_header_int(tracer_pid_key.c_str(), first_nonzero_tracer);
    if (!any_status_read) {
        builder.set_status(payload_codec::Status::RESTRICTED, status_err);
    }
    return builder.build();
}

bool native_set_anti_dumpable(bool enable) {
    // PR_SET_DUMPABLE(0) blocks non-root ptrace attach & core dumps; (1) restores dumpable.
    const unsigned long dumpable = enable ? 0UL : 1UL;
    long ret = my_prctl(PR_SET_DUMPABLE, dumpable, 0, 0, 0);
    return ret >= 0;
}

namespace {

int raw_stat_errno(const char *path) noexcept {
    struct stat st {};
    const long rc = my_fstatat(AT_FDCWD, path, &st, 0);
    if (rc == 0) {
        return 0;
    }
    int err = raw_last_error();
    return err > 0 ? err : EIO;
}

const char *classify_init_socket(int dir_err, int target_err, int ctrl_err,
                                 bool dir_listed, bool listed_has_adbd) noexcept {
    enum class Obs { PRESENT, PRESENT_DENIED, ABSENT, DIR_DENIED, UNKNOWN };
    Obs obs = Obs::UNKNOWN;
    if (dir_err != 0) {
        obs = (dir_err == EACCES || dir_err == EPERM) ? Obs::DIR_DENIED : Obs::UNKNOWN;
    } else if (target_err == 0) {
        obs = Obs::PRESENT;
    } else if (ctrl_err != ENOENT) {
        obs = (ctrl_err == EACCES || ctrl_err == EPERM) ? Obs::DIR_DENIED : Obs::UNKNOWN;
    } else if (target_err == ENOENT) {
        obs = Obs::ABSENT;
    } else if (target_err == EACCES || target_err == EPERM) {
        obs = Obs::PRESENT_DENIED;
    } else {
        obs = Obs::UNKNOWN;
    }

    if (dir_listed) {
        if (listed_has_adbd) {
            if (obs != Obs::PRESENT && obs != Obs::PRESENT_DENIED) {
                obs = Obs::UNKNOWN;
            }
        } else {
            if (obs != Obs::ABSENT) {
                obs = Obs::UNKNOWN;
            }
        }
    }

    switch (obs) {
        case Obs::PRESENT: return "present";
        case Obs::PRESENT_DENIED: return "present_denied";
        case Obs::ABSENT: return "absent";
        case Obs::DIR_DENIED: return "directory_denied";
        case Obs::UNKNOWN:
        default: return "unknown";
    }
}

int probe_abstract_seqpacket_errno(const char *name, size_t len) noexcept {
    if (name == nullptr || len == 0) {
        return EINVAL;
    }
    struct sockaddr_un addr {};
    if (len > sizeof(addr.sun_path) - 1) {
        return EINVAL;
    }
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    my_memcpy(addr.sun_path + 1, name, len);
    const socklen_t addr_len =
            static_cast<socklen_t>(offsetof(struct sockaddr_un, sun_path) + 1 + len);

    const long fd_ret = my_socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd_ret < 0) {
        int err = raw_last_error();
        return err > 0 ? err : EIO;
    }
    const int fd = static_cast<int>(fd_ret);
    // Zero-byte non-blocking connect + immediate close: no JDWP handshake is started,
    // and EINTR is intentionally not retried.
    const int rc = ::connect(fd, reinterpret_cast<const struct sockaddr *>(&addr), addr_len);
    const int err = (rc == 0) ? 0 : errno;
    my_close(fd);
    return err;
}

const char *classify_jdwp_connect(int err) noexcept {
    if (err == 0 || err == EACCES || err == EPERM) {
        return "observed";
    }
    if (err == ECONNREFUSED || err == ENOENT) {
        return "not_observed";
    }
    return "unavailable";
}

}  // namespace

std::string native_get_adb_protocol_evidence() {
    const auto sock_dir = OBF("/dev/socket");
    const auto adbd_path = OBF("/dev/socket/adbd");
    const auto ctrl_prefix = OBF("/dev/socket/re_absent_ctrl_");
    const auto adbd_name = OBF("adbd");
    const auto jdwp_name = OBF("jdwp-control");
    const auto init_svc_prop = OBF("init.svc.adbd");

    const std::string ctrl_path = std::string(ctrl_prefix.c_str())
            + std::to_string(static_cast<long long>(my_gettid()))
            + "_" + std::to_string(static_cast<long long>(getpid()));

    bool dir_listed = false;
    bool listed_has_adbd = false;
    RawDirResult listing = raw_list_dir(sock_dir.c_str());
    if (listing.ok()) {
        dir_listed = true;
        for (const auto &entry : listing.names) {
            if (my_strcmp(entry.c_str(), adbd_name.c_str()) == 0) {
                listed_has_adbd = true;
                break;
            }
        }
    }

    const int dir_err = raw_stat_errno(sock_dir.c_str());
    const int target_err = raw_stat_errno(adbd_path.c_str());
    const int ctrl_err = raw_stat_errno(ctrl_path.c_str());
    const char *socket_state = classify_init_socket(
            dir_err, target_err, ctrl_err, dir_listed, listed_has_adbd);

    const int jdwp_err = probe_abstract_seqpacket_errno(jdwp_name.c_str(), jdwp_name.size());
    const char *jdwp_state = classify_jdwp_connect(jdwp_err);

    const std::string init_svc_adbd = get_system_property(init_svc_prop.c_str());

    payload_codec::PayloadBuilder pb(payload_codec::Status::OK, 0);
    pb.add_header("adbd_socket", socket_state);
    pb.add_header("jdwp_control", jdwp_state);
    pb.add_header("init_svc_adbd", init_svc_adbd);
    pb.add_header_int("dir_errno", dir_err);
    pb.add_header_int("adbd_errno", target_err);
    pb.add_header_int("ctrl_errno", ctrl_err);
    pb.add_header_int("jdwp_errno", jdwp_err);
    return pb.build();
}
