# Evidence Contract Record — `network_risk`

- **Detector**: `network_risk` (`NetworkRiskDetector`)
- **ScanTier**: `FAST`
- **EvidenceFamily**: `network_mitm`
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Java KeyStore / Cert Dir | `user_ca_cert` | `network_mitm` | `STRONG` | User-installed root CA certificates in `AndroidCAStore` (`user:*`) or `/data/misc/user/<uid>/cacerts-added` (TLS MitM interception vector) |
| Java + Native VPN Detection | `vpn_active` | `network_mitm` | `WEAK` | `ConnectivityManager` `TRANSPORT_VPN` (when host holds `ACCESS_NETWORK_STATE`) or active (`IFF_UP`) tunnel interfaces (`tun*`, `ppp*`, `wg*`, `utun*`, `tap*`, `ipsec*`, excluding stock `tunl*`) via unbound `AF_NETLINK` `RTM_GETLINK` / `/sys/class/net` |
| Java Proxy Inspection | `http_proxy` | `network_mitm` | `WEAK` | Active HTTP/HTTPS proxy detected via `ConnectivityManager.getDefaultProxy()`, JVM `http.proxyHost`/`https.proxyHost`, or `Settings.Global.HTTP_PROXY` (emits source tag only — zero credentials/host PII) |
| Proxy Tool Signing Certs & Modules | `proxy_tool_cert`, `proxy_module` | `network_mitm` | `WEAK` | Official release signing cert SHA-256 verification on curated `<queries>` proxy tools (ClashMeta, Clash, Clash FOSS, v2rayNG, sing-box, Surfboard, NekoBox, Reqable) plus read-only existence check on `/data/adb/modules/{box4,box_for_root}` |

## Producing Subsystem

- Android `KeyStore("AndroidCAStore")` and `/data/misc/user/<uid>/cacerts-added`.
- Android `ConnectivityManager` (runtime-guarded behind `ACCESS_NETWORK_STATE`), JVM proxy properties, and `Settings.Global.HTTP_PROXY`.
- Native unbound `SOCK_DGRAM` `AF_NETLINK` `NETLINK_ROUTE` `RTM_GETLINK` (`native_get_active_net_interfaces`, `IFLA_IFNAME` only, zero `bind()`, zero permissions, zero MAC PII).
- Android `PackageManager` (`GET_SIGNING_CERTIFICATES` strictly over curated `<queries>` proxy packages).

## Mechanism (AOSP/Linux/ACK)

- **Zero-Permission VPN Enumeration (`D48`)**: Android 11+ `untrusted_app` SELinux blocks `/sys/class/net` and omits `netlink_route_socket:bind`. `native_get_active_net_interfaces()` sends `RTM_GETLINK` over an **unbound** `AF_NETLINK` `SOCK_DGRAM` socket reading ONLY `IFLA_IFNAME` of `IFF_UP` interfaces (requiring zero `INTERNET`/`ACCESS_NETWORK_STATE` and zero MAC/IP PII), enabling real-device VPN detection even in zero-permission SDK hosts.
- **Tri-State `DevicePosture.systemVpn` (`D24`, `D48`)**: `DataAggregator` sets `systemVpn = Boolean.TRUE` on `vpn_active`, `Boolean.FALSE` only when `checksSucceeded >= 4` and no `vpn_check_*` failure occurred, and `null` when VPN visibility is absent.
- **Zero-PII Proxy Reporting (`D19`)**: Records only the configuration source tag (`default_proxy`, `jvm_property`, `settings_global`) — never proxy URLs, usernames, passwords, SSID, BSSID, or MAC addresses.

## Applicable API Range

- Android 11–17 (API 30–37), both 64-bit ABIs (`arm64-v8a`, `x86_64`).

## Visibility Boundaries

- Zero `<uses-permission>` is declared in `riskengine-sdk/src/main/AndroidManifest.xml`; if the host lacks `ACCESS_NETWORK_STATE`, `ConnectivityManager` is skipped cleanly and the unbound `AF_NETLINK` / JVM / `Settings.Global` fallback path runs without error.
- Transparent router/gateway-level proxies and root-injected system CA stores (modifying `/apex/com.android.conscrypt/cacerts` via overlay, caught by `mount_analysis`) are outside `AndroidCAStore` `user:*` visibility.
- Package checks are limited strictly to curated proxy packages declared in `<queries>` (zero `QUERY_ALL_PACKAGES`).

## False-Positive Defenses

- **Stock `tunl*` IPIP interface filter (`D48`)**: Filters out stock kernel IP-in-IP `tunl0` interfaces (verified on Pixel 6) so inactive VPN never triggers `vpn_active`.
- **Actionable vs informational split (`D19`)**: `user_ca_cert` is actionable `MEDIUM/5` in all scenes; VPN, HTTP proxy, proxy-tool certs, and `box4` modules stay `LOW/2` informational in `STANDARD`/`LOGIN` and elevate to actionable `MEDIUM/4` only in `PAYMENT` (via `CorrelationEngine.applyScene`).
- **Read-only module probe (`D19`)**: `EACCES`/`ENOENT` on `/data/adb/modules/box4` is never treated as a positive threat.
- **Official cert SHA-256 matching**: Proxy tool package checks require verified official signing cert SHA-256 match rather than raw package name alone.

## Result State Mapping

- **User CA installed (`user_ca_cert`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 5`, `informational = false` (actionable in all 4 scenes).
- **Soft network risk only (`vpn_active`, `http_proxy`, `proxy_tool_cert`, `proxy_module`)**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 2`, `informational = true` in `STANDARD`/`LOGIN` (elevates to actionable `MEDIUM/4` in `PAYMENT`).
- **Clean**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
