#ifndef RISKENGINE_SELINUX_AUDIT_PROBE_H
#define RISKENGINE_SELINUX_AUDIT_PROBE_H

#include <cstdint>
#include <string>

namespace riskengine {
namespace selinux_audit {

/**
 * Policy gating for Netlink RTM_GETLINK MAC-leak audit (Android 11+ / API 30+).
 * Enforced iff ((api_level >= 30 && target_sdk >= 30) || api_level >= 33).
 */
inline bool is_netlink_getlink_restricted(int api_level, int target_sdk) noexcept {
    return (api_level >= 30 && target_sdk >= 30) || api_level >= 33;
}

/**
 * Policy gating for Netlink RTM_GETNEIGH ARP/neighbor-leak audit (Android 13+ / API 33+).
 * Enforced iff (api_level >= 33 && target_sdk >= 32).
 */
inline bool is_netlink_getneigh_restricted(int api_level, int target_sdk) noexcept {
    return api_level >= 33 && target_sdk >= 32;
}

/**
 * Validates that a 6-byte MAC address is a real physical unicast hardware address
 * (non-multicast, non-all-zero, non-AOSP 02:00:00:00:00:00 privacy dummy).
 * Never logs or formats raw MAC bytes.
 */
bool is_valid_physical_mac(const uint8_t mac[6]) noexcept;

/**
 * Validates an IPv4 address in network byte order is a non-loopback, non-multicast,
 * non-broadcast, non-zero unicast host address. Never logs or formats raw IP bytes.
 */
bool is_valid_unicast_ipv4_be(uint32_t addr_be) noexcept;

}  // namespace selinux_audit
}  // namespace riskengine

/**
 * Executes SELinux deep audit probes:
 * 1. Zero-PII Netlink policy-reload leak audit (RTM_GETLINK & RTM_GETNEIGH),
 *    strictly gated on (api_level, target_sdk).
 * 2. /sys/fs/selinux/status mmap ABI & header invariant check inside disposable_child.
 * 3. Controlled /proc/thread-self/attr/current context probe inside disposable_child
 *    with mandatory positive/negative/OEM control groups before & after target checks.
 *
 * Returns a NativePayloadCodec frame. NEVER emits raw MAC or IP PII.
 */
std::string native_get_selinux_audit(int api_level, int target_sdk);

/**
 * Zero-permission, zero-PII enumeration of active (IFF_UP) network interface names
 * via NETLINK_ROUTE RTM_GETLINK (does not require INTERNET or ACCESS_NETWORK_STATE,
 * bypasses Android 11+ /sys/class/net SELinux restrictions, and never inspects IFLA_ADDRESS/MAC).
 * Returns a comma-separated list of interface names, or empty string if unavailable.
 */
std::string native_get_active_net_interfaces();

#endif  // RISKENGINE_SELINUX_AUDIT_PROBE_H
