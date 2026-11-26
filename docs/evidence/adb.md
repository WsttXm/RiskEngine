# Evidence Contract Record — `adb`

- **Detector**: `adb` (`AdbDetector`, backed by `AdbInspector` and `native_debug_detector.cpp:native_get_adb_protocol_evidence`)
- **ScanTier**: `FAST` (with conditional 1.5s 2-sample debounce triggered ONLY on initial hidden-`adbd` contradiction — zero sleep on clean consistent devices)
- **EvidenceFamily**: `adb`
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Native ADB Protocol Contradiction (`native_get_adb_protocol_evidence` + `AdbInspector` debounce) | `adbd_contradiction`, `adbd_hidden_socket`, `adbd_hidden_jdwp_control` | `adb` | `STRONG` | Persistent contradiction (confirmed across 2 samples 1.5s apart) where `init.svc.adbd=stopped` or `adb_enabled=0` while `/dev/socket/adbd` exists or `@jdwp-control` is actively listening |
| Java Wi-Fi ADB signals | `settings_adb_wifi_enabled`, `adb_tcp_port`, `adbd_pid_port` | `adb` | `MEDIUM` | `Settings.Global.adb_wifi_enabled == 1`, `service.adb.tcp.port` / `persist.adb.tcp.port > 0`, or listening `adbd` TCP port (informational in `STANDARD`/`LOGIN`) |
| Java / Native USB ADB signals | `settings_adb_enabled`, `sys_usb_state_adb`, `init_svc_adbd_running`, `adbd_socket`, `jdwp_control_socket` | `adb` | `WEAK` | Standard USB debugging enabled (`adb_enabled=1`, `sys.usb.state` containing `adb`, `init.svc.adbd=running`, `/dev/socket/adbd` / `@jdwp-control` consistent with enabled ADB) |

## Producing Subsystem

- Android `Settings.Global` (`adb_enabled`, `adb_wifi_enabled`) and `init` properties (`init.svc.adbd`, `sys.usb.state`, `service.adb.tcp.port`, `persist.adb.tcp.port`).
- Linux filesystem `/dev/socket/adbd` (3-way `fstatat` + sibling `ENOENT` sentinel + `raw_list_dir` cross-check).
- Linux abstract Unix domain socket `@jdwp-control` (non-blocking zero-byte `SOCK_SEQPACKET` connect probe).

## Mechanism (AOSP/Linux/ACK)

- **Native `/dev/socket/adbd` & `@jdwp-control` Probing (`D38`)**: `native_get_adb_protocol_evidence()` probes `/dev/socket/adbd` via raw Linux `fstatat` alongside a non-existent sibling sentinel under `/dev/socket/` (distinguishing real socket existence/`EACCES` from directory search denial) and `raw_list_dir` cross-check, performs a non-blocking zero-byte `SOCK_SEQPACKET` `connect()` probe on abstract socket `\0jdwp-control`, and reads `init.svc.adbd` natively (all string literals `OBF`-protected).
- **Conditional 2-Sample 1.5s Debounce (`D38`)**: On clean or consistent devices (ADB genuinely off or genuinely on), `AdbInspector.collect()` completes in a single fast pass with **0ms sleep**. Only when Sample 1 observes an apparent hidden-`adbd` contradiction (`init.svc.adbd=stopped` / `adb_enabled=0` while `/dev/socket/adbd` or `@jdwp-control` is live) does `AdbInspector` wait 1.5s and take Sample 2 to rule out transient USB-toggle teardown races before emitting `adbd_contradiction` / `adbd_hidden_socket` / `adbd_hidden_jdwp_control`.

## Applicable API Range

- Android 11–17 (API 30–37), all 4 ABIs (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`).

## Visibility Boundaries

- On devices where SELinux denies unprivileged `search` on `/dev/socket` AND `connectto` on `@jdwp-control`, native socket probes return unobserved (`UNAVAILABLE`), and `AdbInspector` relies cleanly on `Settings.Global` and `init.svc.adbd` without raising false contradictions.
- Wireless ADB on Android 11+ uses dynamic ephemeral TLS ports managed by `adbd`; `settings_adb_wifi_enabled` captures it without requiring `/proc/net/tcp` visibility.

## False-Positive Defenses

- **1.5s 2-sample debounce (`D38`)**: Eliminates false hidden-`adbd` alerts during the brief transition window when a user toggles USB debugging off while `adbd` is shutting down its socket, with zero latency impact on clean devices.
- **Sibling `ENOENT` sentinel on `/dev/socket`**: Ensures SELinux denial on `/dev/socket` is never mistaken for an existing `adbd` socket.
- **Normal USB/Wi-Fi ADB informational semantics**: Legitimate developer USB debugging (`LOW/2`) and Wi-Fi ADB (`MEDIUM/4`) remain `informational = true` in `STANDARD`/`LOGIN` (elevating to actionable in `PAYMENT`/`DIAGNOSTIC` via `CorrelationEngine.applyScene`), whereas spoofed/hidden `adbd` contradictions are immediately actionable `HIGH/7` in all 4 scenes.

## Result State Mapping

- **Persistent hidden-`adbd` contradiction (`adbd_contradiction`, `adbd_hidden_socket`, `adbd_hidden_jdwp_control`)**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 7`, `informational = false` (actionable in all 4 `CollectScene`s).
- **Wi-Fi ADB enabled (consistent)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 4`, `informational = true` (`PAYMENT`/`DIAGNOSTIC` actionable).
- **USB ADB enabled (consistent)**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 2`, `informational = true` (`PAYMENT`/`DIAGNOSTIC` actionable).
- **ADB disabled and no contradiction**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
