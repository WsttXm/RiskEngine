#include "mac_netlink_collector.h"
#include <string>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <net/if.h>

std::string get_mac_via_netlink() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) return "";

    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifm;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.ifm.ifi_family = AF_UNSPEC;

    if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
        close(sock);
        return "";
    }

    char buf[8192];
    ssize_t len = recv(sock, buf, sizeof(buf), 0);
    close(sock);

    if (len < 0) return "";

    std::string result;
    struct nlmsghdr *nlh;
    for (nlh = (struct nlmsghdr *) buf; NLMSG_OK(nlh, (size_t)len); nlh = NLMSG_NEXT(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type != RTM_NEWLINK) continue;

        struct ifinfomsg *ifi = (struct ifinfomsg *) NLMSG_DATA(nlh);
        struct rtattr *rta = IFLA_RTA(ifi);
        int rta_len = IFLA_PAYLOAD(nlh);

        char ifname[IF_NAMESIZE] = {0};
        unsigned char *mac = nullptr;
        int mac_len = 0;

        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == IFLA_IFNAME) {
                strncpy(ifname, (char *) RTA_DATA(rta), IF_NAMESIZE - 1);
            } else if (rta->rta_type == IFLA_ADDRESS) {
                mac = (unsigned char *) RTA_DATA(rta);
                mac_len = RTA_PAYLOAD(rta);
            }
        }

        // Skip loopback and virtual interfaces
        if (strcmp(ifname, "lo") == 0) continue;
        if (mac && mac_len == 6) {
            char mac_str[32];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            // Skip all-zero MACs
            if (strcmp(mac_str, "00:00:00:00:00:00") != 0) {
                if (!result.empty()) result += ",";
                result += std::string(ifname) + "=" + mac_str;
            }
        }
    }
    return result;
}
