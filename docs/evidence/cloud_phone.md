# Evidence Contract Record — `cloud_phone`

- **Detector**: `cloud_phone` (`CloudPhoneDetector`)
- **ScanTier**: `FAST` (cloud packages, cloud vendor properties, `virtual_gpu`, wired `ethN`, battery anomaly, camera count, physical sensor count, `zero_hw_codec`) + `POSTPONED` (`SensorNoiseProbe` static zero-variance corroboration)
- **EvidenceFamily**: `emulator` (shared with `emulator` so `CorrelationEngine` deduplicates overlapping virtualization hits)
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Cloud vendor packages & properties | `cloud_pkg`, `cloud_prop` | `emulator` | `STRONG` | Installed cloud-phone management packages (`DetectionLists.CLOUD_PACKAGES`, synced with `<queries>`) and vendor system properties (`DetectionLists.CLOUD_PHONE_PROPERTIES`) |
| GPU renderer | `virtual_gpu` | `emulator` | `STRONG` | Virtualized GLES renderer (`virgl`/`virtio`/`SwiftShader`/`llvmpipe`) classified by `GpuClassifier` |
| MediaCodec hardware ratio | `zero_hw_codec` | `emulator` | `WEAK` | `MediaCodecCollector.CodecSummary` showing software-only Android/Google codecs (`c2.android.*`/`OMX.google.*`) and zero SoC hardware codecs |
| Hardware & network environment | `wired_interface`, `battery_zero`, `battery_anomaly`, `low_camera_count`, `very_low_sensor_count` | `emulator` | `WEAK` | Wired `ethN` interface, zero battery voltage/temperature or 100% charging with `plugged == 0`, zero cameras, or minimal physical sensors |
| `POSTPONED` `SensorNoiseProbe` | `sensor_static_zero_var` | `emulator` | `WEAK` | 8–10 frame MEMS static `stddev == 0.0` emitted ONLY when `base.getDetails()` already contains a battery/camera/hardware/cloud anomaly |

## Producing Subsystem

- Android `PackageManager`, `SystemProperties`, EGL/GLES renderer query, `MediaCodecList`, `BatteryManager` sticky broadcast, `CameraManager`, and `SensorManager`.
- Network interface enumeration via unbound `AF_NETLINK` `RTM_GETLINK` (`native_get_active_net_interfaces`, zero permissions, zero MAC PII) or Java `NetworkInterface`.

## Mechanism (AOSP/Linux/ACK)

- **Multi-Dimension Hosted-Instance Fingerprinting**: Commercial cloud-phone farms either run virtualized Android containers (exposing `virgl`/`SwiftShader`, `zero_hw_codec`, vendor props/packages, and `eth0`) or rack-mounted headless ARM boards (exposing missing cameras, `voltage == 0` / `temperature == 0` or `100%` charging without plug, minimal physical MEMS sensors, and zero-variance synthetic sensor streams).
- **Zero-Permission Network Enumeration (`D48`)**: Uses unbound `SOCK_DGRAM` `AF_NETLINK` `NETLINK_ROUTE` `RTM_GETLINK` reading `IFLA_IFNAME` only (zero `INTERNET`/`ACCESS_NETWORK_STATE`, zero MAC PII); cleanly marks network check succeeded when host lacks enumeration visibility.
- **Corroborated MEMS Micro-Noise (`D43`)**: Real physical MEMS sensors exhibit thermal micro-noise even when stationary on a desk (`stddev > 0`). `CloudPhoneDetector.detectPostponed()` skips `SensorNoiseProbe` completely when `base.getDetails().isEmpty()` so a static synthetic sensor reading never fires standalone.

## Applicable API Range

- Android 11–17 (API 30–37), all 4 ABIs.

## Visibility Boundaries

- Bare-metal physical phone farms (real retail handsets connected via USB hubs without cloud vendor packages/props) retain real SoC GPUs, hardware codecs, cameras, and physical MEMS sensors, so they are outside single-device cloud-phone detection visibility.
- Package visibility on Android 11+ covers only the curated `CLOUD_PACKAGES` declared in `<queries>` (zero `QUERY_ALL_PACKAGES`).
- Headless tablets or ChromeOS devices legitimately lacking cameras or using USB-C Ethernet docks are protected by weak-signal gating (`weak.size() >= 2` required for `MEDIUM/4`).

## False-Positive Defenses

- **Wired `ethN` downgraded to weak corroborator**: USB-C docks, tablets, and ChromeOS legitimately expose `eth0`; `wired_interface` NEVER triggers standalone `HIGH` danger.
- **Solo `sensor_static_zero_var` prohibited (`D43`)**: `detectPostponed()` short-circuits immediately when `base.getDetails().isEmpty()`, guaranteeing zero false positives on stationary physical devices with quantized low-precision sensors.
- **ANGLE-on-Vulkan exemption (`GpuClassifier`)**: Prevents false `virtual_gpu` on physical Android 14–16 devices using ANGLE over Vulkan.
- **Zero-permission graceful skip**: Missing `INTERNET` permission for `NetworkInterface` enumeration never marks `cloud_phone` failed or `PARTIAL`.
- **Single-family deduplication**: Shares `emulator` family with `EmulatorDetector` to prevent double-scoring.

## Result State Mapping

- **`strong >= 1` (`cloud_pkg`, `cloud_prop`, `virtual_gpu`)**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 7`, `informational = false` (actionable in all 4 scenes).
- **`weak >= 2` (`wired_interface`, `battery_zero`/`battery_anomaly`, `low_camera_count`, `very_low_sensor_count`, `zero_hw_codec`, corroborated `sensor_static_zero_var`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 4`, `informational = false` (actionable in `LOGIN`/`PAYMENT`; `STANDARD` follows detector risk level).
- **`weak == 1` only**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 1`, `informational = true` in `STANDARD` (elevates in `LOGIN`/`PAYMENT`).
- **Zero signals**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
