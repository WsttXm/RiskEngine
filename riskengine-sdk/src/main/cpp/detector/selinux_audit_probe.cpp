#include "detector/selinux_audit_probe.h"

#include "util/crypto_mini.h"
#include "util/disposable_child.h"
#include "util/mylibc.h"
#include "util/obf_str.h"
#include "util/payload_codec.h"
#include "util/syscall_wrapper.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef NDA_RTA
#define NDA_RTA(r) ((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct ndmsg))
#endif

namespace riskengine {
namespace selinux_audit {

namespace {

constexpr int kMaxNetlinkPackets = 64;

enum class InterfaceKind : uint8_t {
    kNone = 0,
    kWifi = 1,
    kEthernet = 2,
};

InterfaceKind classify_physical_interface(const char *ifname) noexcept {
    if (ifname == nullptr || ifname[0] == '\0') {
        return InterfaceKind::kNone;
    }
    if (my_strncmp(ifname, "wlan", 4) == 0 || my_strncmp(ifname, "swlan", 5) == 0) {
        return InterfaceKind::kWifi;
    }
    if (my_strncmp(ifname, "eth", 3) == 0) {
        return InterfaceKind::kEthernet;
    }
    return InterfaceKind::kNone;
}

int create_netlink_route_socket() {
    const long fd_ret = my_socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd_ret < 0) {
        return -1;
    }
    const int fd = static_cast<int>(fd_ret);

    struct timeval tv = {};
    tv.tv_sec = 0;
    tv.tv_usec = 250000;  // 250ms bounded receive timeout
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0
            || setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        my_close(fd);
        return -1;
    }

    struct sockaddr_nl addr = {};
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;
    addr.nl_groups = 0;
    if (my_bind(fd, reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        my_close(fd);
        return -1;
    }
    return fd;
}

struct NetlinkProbeOutcome {
    bool link_applicable = false;
    bool link_evaluated = false;
    bool link_enforced = false;
    InterfaceKind link_leak_kind = InterfaceKind::kNone;

    bool neigh_applicable = false;
    bool neigh_evaluated = false;
    bool neigh_enforced = false;
    bool neigh_leaked = false;
};

void probe_netlink_link(int api_level, int target_sdk, NetlinkProbeOutcome &out) {
    out.link_applicable = is_netlink_getlink_restricted(api_level, target_sdk);
    if (!out.link_applicable) {
        return;
    }
    const int sock = create_netlink_route_socket();
    if (sock < 0) {
        return;
    }

    struct {
        struct nlmsghdr hdr;
        struct rtgenmsg gen;
    } req = {};
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.gen.rtgen_family = AF_UNSPEC;

    const long sent = my_sendto(sock, &req, req.hdr.nlmsg_len, 0, nullptr, 0);
    if (sent != static_cast<long>(req.hdr.nlmsg_len)) {
        if (raw_last_error() == EACCES) {
            out.link_evaluated = true;
            out.link_enforced = true;
        }
        my_close(sock);
        return;
    }
    out.link_evaluated = true;

    alignas(4) char buffer[8192] = {};
    for (int pkt = 0; pkt < kMaxNetlinkPackets && out.link_leak_kind == InterfaceKind::kNone; ++pkt) {
        const long len = my_recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (len <= 0) {
            break;
        }
        int remaining = static_cast<int>(len);
        const auto *nlh = reinterpret_cast<const struct nlmsghdr *>(buffer);
        bool done = false;
        for (; remaining >= static_cast<int>(sizeof(struct nlmsghdr))
                && NLMSG_OK(nlh, static_cast<unsigned int>(remaining));
             nlh = NLMSG_NEXT(nlh, remaining)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type != RTM_NEWLINK) {
                continue;
            }
            if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
                continue;
            }
            const auto *ifi = static_cast<const struct ifinfomsg *>(NLMSG_DATA(nlh));
            if ((ifi->ifi_flags & IFF_LOOPBACK) != 0 || (ifi->ifi_flags & IFF_UP) == 0) {
                continue;
            }

            const auto *rta = IFLA_RTA(ifi);
            int rta_len = static_cast<int>(IFLA_PAYLOAD(nlh));
            InterfaceKind kind = InterfaceKind::kNone;
            uint8_t mac_bytes[6] = {};
            bool has_mac = false;

            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                if (rta->rta_type == IFLA_IFNAME && RTA_PAYLOAD(rta) > 0) {
                    char ifname[IFNAMSIZ + 1] = {};
                    std::size_t copy_len = RTA_PAYLOAD(rta);
                    if (copy_len > IFNAMSIZ) {
                        copy_len = IFNAMSIZ;
                    }
                    my_memcpy(ifname, RTA_DATA(rta), copy_len);
                    ifname[copy_len] = '\0';
                    kind = classify_physical_interface(ifname);
                    crypto_mini::secure_zero(ifname, sizeof(ifname));
                } else if (rta->rta_type == IFLA_ADDRESS && RTA_PAYLOAD(rta) == 6) {
                    my_memcpy(mac_bytes, RTA_DATA(rta), 6);
                    has_mac = true;
                }
            }

            const bool physical_mac = has_mac && is_valid_physical_mac(mac_bytes);
            // Zero raw MAC bytes immediately; never store, log, or serialize PII.
            crypto_mini::secure_zero(mac_bytes, sizeof(mac_bytes));

            if (kind != InterfaceKind::kNone && physical_mac) {
                out.link_leak_kind = kind;
                done = true;
                break;
            }
        }
        if (done) {
            break;
        }
    }

    crypto_mini::secure_zero(buffer, sizeof(buffer));
    my_close(sock);
}

void probe_netlink_neigh(int api_level, int target_sdk, NetlinkProbeOutcome &out) {
    out.neigh_applicable = is_netlink_getneigh_restricted(api_level, target_sdk);
    if (!out.neigh_applicable) {
        return;
    }
    const int sock = create_netlink_route_socket();
    if (sock < 0) {
        return;
    }

    struct {
        struct nlmsghdr hdr;
        struct ndmsg msg;
    } req = {};
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.hdr.nlmsg_type = RTM_GETNEIGH;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 2;
    req.msg.ndm_family = AF_INET;

    const long sent = my_sendto(sock, &req, req.hdr.nlmsg_len, 0, nullptr, 0);
    if (sent != static_cast<long>(req.hdr.nlmsg_len)) {
        if (raw_last_error() == EACCES) {
            out.neigh_evaluated = true;
            out.neigh_enforced = true;
        }
        my_close(sock);
        return;
    }
    out.neigh_evaluated = true;

    alignas(4) char buffer[8192] = {};
    for (int pkt = 0; pkt < kMaxNetlinkPackets && !out.neigh_leaked; ++pkt) {
        const long len = my_recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (len <= 0) {
            break;
        }
        int remaining = static_cast<int>(len);
        const auto *nlh = reinterpret_cast<const struct nlmsghdr *>(buffer);
        bool done = false;
        for (; remaining >= static_cast<int>(sizeof(struct nlmsghdr))
                && NLMSG_OK(nlh, static_cast<unsigned int>(remaining));
             nlh = NLMSG_NEXT(nlh, remaining)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type != RTM_NEWNEIGH) {
                continue;
            }
            if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ndmsg))) {
                continue;
            }
            const auto *ndm = static_cast<const struct ndmsg *>(NLMSG_DATA(nlh));
            if ((ndm->ndm_state & (NUD_NOARP | NUD_FAILED | NUD_INCOMPLETE)) != 0) {
                continue;
            }

            const auto *rta = NDA_RTA(ndm);
            int rta_len = static_cast<int>(NDA_PAYLOAD(nlh));
            uint32_t addr_be = 0;
            bool has_unicast_ip = false;
            uint8_t mac_bytes[6] = {};
            bool has_mac = false;

            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                if (rta->rta_type == NDA_DST && RTA_PAYLOAD(rta) == sizeof(uint32_t)) {
                    my_memcpy(&addr_be, RTA_DATA(rta), sizeof(uint32_t));
                    has_unicast_ip = is_valid_unicast_ipv4_be(addr_be);
                } else if (rta->rta_type == NDA_LLADDR && RTA_PAYLOAD(rta) == 6) {
                    my_memcpy(mac_bytes, RTA_DATA(rta), 6);
                    has_mac = true;
                }
            }

            const bool physical_mac = has_mac && is_valid_physical_mac(mac_bytes);
            // Zero raw IP/MAC bytes immediately; never format, log, or emit PII.
            crypto_mini::secure_zero(&addr_be, sizeof(addr_be));
            crypto_mini::secure_zero(mac_bytes, sizeof(mac_bytes));

            if (has_unicast_ip && physical_mac) {
                out.neigh_leaked = true;
                done = true;
                break;
            }
        }
        if (done) {
            break;
        }
    }

    crypto_mini::secure_zero(buffer, sizeof(buffer));
    my_close(sock);
}

// ==================== Probe 2: /sys/fs/selinux/status ABI ====================

constexpr uint8_t kStatusReqTwoPage = 0;
constexpr uint8_t kStatusReqOffset = 1;
constexpr uint8_t kStatusReqWritable = 2;
constexpr uint8_t kStatusReqMprotect = 3;
constexpr int kStatusReqCount = 4;

struct SelinuxStatusHeader {
    uint32_t version;
    uint32_t sequence;
    uint32_t enforcing;
    uint32_t policyload;
    uint32_t deny_unknown;
};

struct StatusAbiChildInput {
    const char *status_path = nullptr;
    std::size_t page_size = 4096;
};

struct StatusAbiChildReport {
    uint8_t opened = 0;
    uint8_t baseline_mapped = 0;
    uint8_t done = 0;
    uint8_t header_anomaly = 0;
    uint8_t granted[kStatusReqCount] = {};
    int32_t req_errno[kStatusReqCount] = {};
    uint32_t header_version = 0;
    uint32_t header_enforcing = 0;
    int32_t open_errno = 0;
};

int selinux_status_abi_child_body(const void *ctx, int report_fd) {
    const auto *in = static_cast<const StatusAbiChildInput *>(ctx);
    StatusAbiChildReport rep = {};
    if (in == nullptr || in->status_path == nullptr || in->page_size < 4096) {
        return 1;
    }
    const std::size_t page = in->page_size;

    const long fd_ret = my_openat(AT_FDCWD, in->status_path, O_RDONLY | O_CLOEXEC, 0);
    if (fd_ret < 0) {
        rep.open_errno = raw_last_error();
        riskengine::util::write_child_report(report_fd, &rep, sizeof(rep));
        return 0;
    }
    const int fd = static_cast<int>(fd_ret);
    rep.opened = 1;

    const long base_ret = my_mmap(nullptr, page, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base_ret == -1) {
        rep.open_errno = raw_last_error();
        my_close(fd);
        riskengine::util::write_child_report(report_fd, &rep, sizeof(rep));
        return 0;
    }
    void *baseline = reinterpret_cast<void *>(static_cast<uintptr_t>(base_ret));
    rep.baseline_mapped = 1;

    // Validate baseline selinux_status_t header invariants inside the isolated child.
    SelinuxStatusHeader hdr = {};
    my_memcpy(&hdr, baseline, sizeof(hdr));
    rep.header_version = hdr.version;
    rep.header_enforcing = hdr.enforcing;
    if (hdr.version != 1U || hdr.enforcing > 1U) {
        rep.header_anomaly = 1;
    }

    // Request 0: two-page MAP_SHARED (stock rejects with EIO).
    {
        const long m = my_mmap(nullptr, 2 * page, PROT_READ, MAP_SHARED, fd, 0);
        if (m != -1) {
            rep.granted[kStatusReqTwoPage] = 1;
            my_munmap(reinterpret_cast<void *>(static_cast<uintptr_t>(m)), 2 * page);
        } else {
            rep.req_errno[kStatusReqTwoPage] = raw_last_error();
        }
    }

    // Request 1: non-zero page offset MAP_SHARED (stock rejects non-zero vm_pgoff).
    {
        const long m = my_mmap(nullptr, page, PROT_READ, MAP_SHARED, fd, static_cast<long>(page));
        if (m != -1) {
            rep.granted[kStatusReqOffset] = 1;
            my_munmap(reinterpret_cast<void *>(static_cast<uintptr_t>(m)), page);
        } else {
            rep.req_errno[kStatusReqOffset] = raw_last_error();
        }
    }

    // Request 2: writable MAP_PRIVATE (stock rejects VM_WRITE with EPERM).
    {
        const long m = my_mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (m != -1) {
            rep.granted[kStatusReqWritable] = 1;
            my_munmap(reinterpret_cast<void *>(static_cast<uintptr_t>(m)), page);
        } else {
            rep.req_errno[kStatusReqWritable] = raw_last_error();
        }
    }

    // Request 3: mprotect(PROT_READ | PROT_WRITE) on baseline (stock cleared VM_MAYWRITE -> EACCES).
    {
        errno = 0;
        const int pr = mprotect(baseline, page, PROT_READ | PROT_WRITE);
        if (pr == 0) {
            rep.granted[kStatusReqMprotect] = 1;
        } else {
            rep.req_errno[kStatusReqMprotect] = errno;
        }
    }

    my_munmap(baseline, page);
    my_close(fd);
    rep.done = 1;
    if (!riskengine::util::write_child_report(report_fd, &rep, sizeof(rep))) {
        return 2;
    }
    return 0;
}

const char *status_req_name(int idx) noexcept {
    switch (idx) {
        case kStatusReqTwoPage:
            return "TWO_PAGE_SHARED";
        case kStatusReqOffset:
            return "OFFSET_SHARED";
        case kStatusReqWritable:
            return "WRITABLE_PRIVATE";
        case kStatusReqMprotect:
            return "MPROTECT_WRITE";
        default:
            return "UNKNOWN";
    }
}

// ==================== Probe 3: Controlled /proc/thread-self/attr/current ====================

constexpr int kContextTargetCount = 6;
constexpr int kContextRounds = 2;

struct ContextChildInput {
    const char *attr_path = nullptr;
    const char *neg_ctrl = nullptr;
    const char *pos_ctrl = nullptr;
    const char *oem_ctrl = nullptr;
    const char *targets[kContextTargetCount] = {};
};

struct ContextWriteOutcome {
    int32_t open_err = 0;
    int32_t write_err = 0;
    int32_t bytes = -2;
};

struct ContextChildReport {
    uint8_t controls_valid = 0;
    uint8_t identity_changed = 0;
    uint8_t completed_rounds = 0;
    uint8_t reserved = 0;
    uint8_t target_present_rounds[kContextTargetCount] = {};
};

bool read_thread_context(const char *path, char *out, std::size_t cap) noexcept {
    if (path == nullptr || out == nullptr || cap < 2) {
        return false;
    }
    const long fd_ret = my_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd_ret < 0) {
        return false;
    }
    const int fd = static_cast<int>(fd_ret);
    const long n = my_read(fd, out, cap - 1);
    my_close(fd);
    if (n <= 0) {
        return false;
    }
    out[n] = '\0';
    return true;
}

ContextWriteOutcome write_thread_context(const char *path, const char *ctx_str) noexcept {
    ContextWriteOutcome out = {};
    if (path == nullptr || ctx_str == nullptr) {
        out.open_err = EINVAL;
        return out;
    }
    const long fd_ret = my_openat(AT_FDCWD, path, O_WRONLY | O_CLOEXEC, 0);
    if (fd_ret < 0) {
        out.open_err = raw_last_error();
        return out;
    }
    const int fd = static_cast<int>(fd_ret);
    const std::size_t len = my_strlen(ctx_str) + 1;
    errno = 0;
    ssize_t w = -1;
    do {
        w = write(fd, ctx_str, len);
    } while (w < 0 && errno == EINTR);
    out.bytes = static_cast<int32_t>(w);
    if (w < 0) {
        out.write_err = errno;
    }
    my_close(fd);
    return out;
}

bool denied_with(const ContextWriteOutcome &o, int expected_err) noexcept {
    return o.open_err == 0 && o.bytes == -1 && o.write_err == expected_err;
}

bool denied_with_access(const ContextWriteOutcome &o) noexcept {
    return o.open_err == 0 && o.bytes == -1
            && (o.write_err == EACCES || o.write_err == EPERM);
}

bool verify_context_controls(const ContextChildInput &in,
                             uid_t initial_uid,
                             const char *initial_ctx,
                             uint8_t &identity_changed) noexcept {
    // 1. Negative control (non-existent / malformed type) MUST fail with EINVAL.
    const ContextWriteOutcome neg = write_thread_context(in.attr_path, in.neg_ctrl);
    if (!denied_with(neg, EINVAL)) {
        return false;
    }

    // 2. Positive control (stock AOSP domain) MUST fail with EACCES/EPERM (NOT EINVAL).
    const ContextWriteOutcome pos = write_thread_context(in.attr_path, in.pos_ctrl);
    if (!denied_with_access(pos)) {
        return false;
    }

    // 3. OEM / universal unlabeled control MUST fail with EACCES/EPERM (NOT EINVAL).
    const ContextWriteOutcome oem = write_thread_context(in.attr_path, in.oem_ctrl);
    if (!denied_with_access(oem)) {
        return false;
    }

    // 4. Thread UID and SELinux context must remain completely unchanged.
    char current_ctx[128] = {};
    if (getuid() != initial_uid
            || !read_thread_context(in.attr_path, current_ctx, sizeof(current_ctx))
            || my_strcmp(current_ctx, initial_ctx) != 0) {
        identity_changed = 1;
        return false;
    }
    return true;
}

int controlled_context_child_body(const void *ctx, int report_fd) {
    const auto *in = static_cast<const ContextChildInput *>(ctx);
    ContextChildReport rep = {};
    if (in == nullptr || in->attr_path == nullptr) {
        return 1;
    }

    const uid_t uid = getuid();
    char initial_ctx[128] = {};
    if (uid < 10000 || !read_thread_context(in->attr_path, initial_ctx, sizeof(initial_ctx))) {
        riskengine::util::write_child_report(report_fd, &rep, sizeof(rep));
        return 0;
    }

    bool all_rounds_ok = true;
    for (int round = 0; round < kContextRounds; ++round) {
        if (!verify_context_controls(*in, uid, initial_ctx, rep.identity_changed)) {
            all_rounds_ok = false;
            break;
        }

        for (int i = 0; i < kContextTargetCount; ++i) {
            const ContextWriteOutcome w = write_thread_context(in->attr_path, in->targets[i]);
            // Any successful write invalidates the refusal model immediately.
            if (w.bytes >= 0) {
                rep.identity_changed = 1;
                all_rounds_ok = false;
                break;
            }
            if (denied_with_access(w)) {
                rep.target_present_rounds[i]++;
            } else if (!denied_with(w, EINVAL)) {
                // Unexpected error invalidates this round.
                all_rounds_ok = false;
                break;
            }
        }
        if (!all_rounds_ok) {
            break;
        }

        if (!verify_context_controls(*in, uid, initial_ctx, rep.identity_changed)) {
            all_rounds_ok = false;
            break;
        }
        rep.completed_rounds++;
    }

    if (all_rounds_ok && rep.completed_rounds == kContextRounds && rep.identity_changed == 0) {
        rep.controls_valid = 1;
    } else {
        // Controls failed -> clear all target counts so parent emits ZERO findings.
        rep.controls_valid = 0;
        my_memset(rep.target_present_rounds, 0, sizeof(rep.target_present_rounds));
    }

    if (!riskengine::util::write_child_report(report_fd, &rep, sizeof(rep))) {
        return 2;
    }
    return 0;
}

}  // namespace

bool is_valid_physical_mac(const uint8_t mac[6]) noexcept {
    if (mac == nullptr) {
        return false;
    }
    // Multicast bit (LSB of first octet) must be 0 for a unicast hardware MAC.
    if ((mac[0] & 0x01U) != 0U) {
        return false;
    }
    // Reject all-zero 00:00:00:00:00:00.
    uint8_t or_all = 0;
    for (int i = 0; i < 6; ++i) {
        or_all |= mac[i];
    }
    if (or_all == 0U) {
        return false;
    }
    // Reject AOSP privacy dummy 02:00:00:00:00:00.
    if (mac[0] == 0x02U && mac[1] == 0x00U && mac[2] == 0x00U
            && mac[3] == 0x00U && mac[4] == 0x00U && mac[5] == 0x00U) {
        return false;
    }
    return true;
}

bool is_valid_unicast_ipv4_be(uint32_t addr_be) noexcept {
    const uint32_t ip = ntohl(addr_be);
    if (ip == 0U) return false;
    if ((ip & 0xff000000U) == 0x7f000000U) return false;  // 127.0.0.0/8 loopback
    if (ip >= 0xe0000000U && ip <= 0xefffffffU) return false;  // 224.0.0.0/4 multicast
    if (ip == 0xffffffffU) return false;  // broadcast
    return true;
}

}  // namespace selinux_audit
}  // namespace riskengine

std::string native_get_selinux_audit(int api_level, int target_sdk) {
    using namespace riskengine::selinux_audit;

    payload_codec::PayloadBuilder payload(payload_codec::Status::OK, 0);
    riskengine::util::ChildDeadlines deadlines;
    deadlines.run = std::chrono::milliseconds(1000);
    deadlines.reap = std::chrono::milliseconds(250);

    int probes_evaluated = 0;

    // 1. Netlink RTM_GETLINK & RTM_GETNEIGH policy-reload leak audit (zero PII).
    NetlinkProbeOutcome nl = {};
    probe_netlink_link(api_level, target_sdk, nl);
    probe_netlink_neigh(api_level, target_sdk, nl);

    if (nl.link_evaluated) {
        probes_evaluated++;
    }
    if (nl.neigh_evaluated) {
        probes_evaluated++;
    }
    if (nl.link_leak_kind != InterfaceKind::kNone) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", "netlink_link_leak")
           .add("if_kind", nl.link_leak_kind == InterfaceKind::kWifi ? "wifi" : "ethernet");
        payload.add_record(rec);
    }
    if (nl.neigh_leaked) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", "netlink_neigh_leak")
           .add("leaked", "1");
        payload.add_record(rec);
    }

    // 2. /sys/fs/selinux/status mmap ABI & header invariant check (disposable child).
    bool status_abi_evaluated = false;
    {
        const auto status_path = OBF("/sys/fs/selinux/status");
        const long ps = sysconf(_SC_PAGESIZE);
        StatusAbiChildInput in = {};
        in.status_path = status_path.c_str();
        in.page_size = (ps >= 4096) ? static_cast<std::size_t>(ps) : 4096U;

        StatusAbiChildReport rep = {};
        riskengine::util::ChildOutcome child = riskengine::util::run_disposable_child(
                reinterpret_cast<uint8_t *>(&rep),
                sizeof(rep),
                deadlines,
                &selinux_status_abi_child_body,
                &in);

        if (child.end == riskengine::util::ChildEnd::kExited
                && child.exit_status == 0
                && child.report_length == sizeof(rep)
                && rep.done != 0
                && rep.baseline_mapped != 0) {
            status_abi_evaluated = true;
            probes_evaluated++;

            for (int i = 0; i < kStatusReqCount; ++i) {
                if (rep.granted[i] != 0) {
                    payload_codec::RecordBuilder rec;
                    rec.add("kind", "selinux_status_abi_violation")
                       .add("request", status_req_name(i));
                    payload.add_record(rec);
                }
            }
            if (rep.header_anomaly != 0) {
                payload_codec::RecordBuilder rec;
                rec.add("kind", "selinux_status_header_anomaly")
                   .add_uint("version", rep.header_version)
                   .add_uint("enforcing", rep.header_enforcing);
                payload.add_record(rec);
            }
        }
    }

    // 3. Controlled /proc/thread-self/attr/current context probe (disposable child).
    bool ctx_probe_valid = false;
    {
        const auto attr_path = OBF("/proc/thread-self/attr/current");
        const auto neg_ctrl = OBF("u:object_r:riskengine_nonexistent_ctrl:s0");
        const auto pos_ctrl = OBF("u:r:init:s0");
        const auto oem_ctrl = OBF("u:object_r:unlabeled:s0");

        const auto t0 = OBF("u:r:magisk:s0");
        const auto t1 = OBF("u:object_r:magisk_file:s0");
        const auto t2 = OBF("u:r:ksu:s0");
        const auto t3 = OBF("u:object_r:ksu_file:s0");
        const auto t4 = OBF("u:object_r:lsposed_file:s0");
        const auto t5 = OBF("u:object_r:xposed_file:s0");
        const auto l0 = OBF("magisk");
        const auto l1 = OBF("magisk_file");
        const auto l2 = OBF("ksu");
        const auto l3 = OBF("ksu_file");
        const auto l4 = OBF("lsposed_file");
        const auto l5 = OBF("xposed_file");
        const char *target_labels[kContextTargetCount] = {
                l0.c_str(), l1.c_str(), l2.c_str(), l3.c_str(), l4.c_str(), l5.c_str()
        };

        ContextChildInput in = {};
        in.attr_path = attr_path.c_str();
        in.neg_ctrl = neg_ctrl.c_str();
        in.pos_ctrl = pos_ctrl.c_str();
        in.oem_ctrl = oem_ctrl.c_str();
        in.targets[0] = t0.c_str();
        in.targets[1] = t1.c_str();
        in.targets[2] = t2.c_str();
        in.targets[3] = t3.c_str();
        in.targets[4] = t4.c_str();
        in.targets[5] = t5.c_str();

        ContextChildReport rep = {};
        riskengine::util::ChildOutcome child = riskengine::util::run_disposable_child(
                reinterpret_cast<uint8_t *>(&rep),
                sizeof(rep),
                deadlines,
                &controlled_context_child_body,
                &in);

        if (child.end == riskengine::util::ChildEnd::kExited
                && child.exit_status == 0
                && child.report_length == sizeof(rep)
                && rep.controls_valid != 0
                && rep.identity_changed == 0
                && rep.completed_rounds == kContextRounds) {
            ctx_probe_valid = true;
            probes_evaluated++;
            for (int i = 0; i < kContextTargetCount; ++i) {
                if (rep.target_present_rounds[i] == kContextRounds) {
                    payload_codec::RecordBuilder rec;
                    rec.add("kind", "selinux_context_type_present")
                       .add("type", target_labels[i]);
                    payload.add_record(rec);
                }
            }
        }
    }

    if (probes_evaluated == 0) {
        payload.set_status(payload_codec::Status::RESTRICTED, raw_last_error());
    }
    payload.add_header_int("probes_evaluated", probes_evaluated);
    payload.add_header("link_applicable", nl.link_applicable ? "1" : "0");
    payload.add_header("link_enforced", nl.link_enforced ? "1" : "0");
    payload.add_header("neigh_applicable", nl.neigh_applicable ? "1" : "0");
    payload.add_header("neigh_enforced", nl.neigh_enforced ? "1" : "0");
    payload.add_header("status_abi_evaluated", status_abi_evaluated ? "1" : "0");
    payload.add_header("ctx_probe_state", ctx_probe_valid ? "COMPLETE" : "UNAVAILABLE");
    return payload.build();
}

std::string native_get_active_net_interfaces() {
    using namespace riskengine::selinux_audit;

    // Use unbound SOCK_DGRAM NETLINK_ROUTE socket (same pattern as Bionic getifaddrs).
    // Android 11+ untrusted_app SELinux policy omits netlink_route_socket:bind (dontaudit),
    // but allows create + nlmsg_read; sending directly to kernel pid=0 triggers kernel autobind
    // without requiring INTERNET or ACCESS_NETWORK_STATE permissions.
    const long fd_ret = my_socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd_ret < 0) {
        return {};
    }
    const int sock = static_cast<int>(fd_ret);

    struct timeval tv = {};
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0
            || setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        my_close(sock);
        return {};
    }

    struct {
        struct nlmsghdr hdr;
        struct rtgenmsg gen;
    } req = {};
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 3;
    req.gen.rtgen_family = AF_UNSPEC;

    struct sockaddr_nl dst = {};
    dst.nl_family = AF_NETLINK;
    dst.nl_pid = 0;
    dst.nl_groups = 0;

    const long sent = my_sendto(sock, &req, req.hdr.nlmsg_len, 0,
                                reinterpret_cast<const struct sockaddr *>(&dst), sizeof(dst));
    if (sent != static_cast<long>(req.hdr.nlmsg_len)) {
        my_close(sock);
        return {};
    }

    std::string result;
    int iface_count = 0;
    constexpr int kMaxIfaces = 64;
    alignas(4) char buffer[8192] = {};

    for (int pkt = 0; pkt < kMaxNetlinkPackets && iface_count < kMaxIfaces; ++pkt) {
        const long len = my_recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (len <= 0) {
            break;
        }
        int remaining = static_cast<int>(len);
        const auto *nlh = reinterpret_cast<const struct nlmsghdr *>(buffer);
        bool done = false;
        for (; remaining >= static_cast<int>(sizeof(struct nlmsghdr))
                && NLMSG_OK(nlh, static_cast<unsigned int>(remaining));
             nlh = NLMSG_NEXT(nlh, remaining)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type != RTM_NEWLINK) {
                continue;
            }
            if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
                continue;
            }
            const auto *ifi = static_cast<const struct ifinfomsg *>(NLMSG_DATA(nlh));
            // Only collect active (IFF_UP) interfaces; filters stock DOWN tunl0 / rmnet* noise.
            if ((ifi->ifi_flags & IFF_UP) == 0) {
                continue;
            }

            const auto *rta = IFLA_RTA(ifi);
            int rta_len = static_cast<int>(IFLA_PAYLOAD(nlh));
            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                // Strictly inspect IFLA_IFNAME only; NEVER read IFLA_ADDRESS (MAC PII).
                if (rta->rta_type != IFLA_IFNAME || RTA_PAYLOAD(rta) == 0) {
                    continue;
                }
                char ifname[IFNAMSIZ + 1] = {};
                std::size_t copy_len = RTA_PAYLOAD(rta);
                if (copy_len > IFNAMSIZ) {
                    copy_len = IFNAMSIZ;
                }
                my_memcpy(ifname, RTA_DATA(rta), copy_len);
                ifname[copy_len] = '\0';

                std::size_t clean_len = my_strlen(ifname);
                bool valid = clean_len > 0;
                for (std::size_t i = 0; i < clean_len; ++i) {
                    const unsigned char ch = static_cast<unsigned char>(ifname[i]);
                    if (ch <= 0x20U || ch >= 0x7fU || ch == ',') {
                        valid = false;
                        break;
                    }
                }
                if (valid && iface_count < kMaxIfaces) {
                    if (!result.empty()) {
                        result.push_back(',');
                    }
                    result.append(ifname, clean_len);
                    iface_count++;
                }
                crypto_mini::secure_zero(ifname, sizeof(ifname));
                break;
            }
        }
        if (done) {
            break;
        }
    }

    crypto_mini::secure_zero(buffer, sizeof(buffer));
    my_close(sock);
    return result;
}
