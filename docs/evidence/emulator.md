# Evidence Contract Record — `emulator`

- **Detector**: `emulator` (`EmulatorDetector`)
- **ScanTier**: `FAST` (Build/QEMU/modern-emulator properties, files, packages, thermal/CPU/disk/screen/sensors/IP, `virtual_gpu`, AVF joint markers, Native Bridge fast path, `zero_hw_codec`) + `POSTPONED` (`disposable_child` `virtualization_traps`: `sched_yield_low_cv` + `arm64_clock_drift`, and `SensorNoiseProbe`)
- **EvidenceFamily**: `emulator` (deduplicated with `cloud_phone`)
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Java Build / QEMU / Modern Virtualization | `fingerprint`, `model`, `manufacturer`, `product`, `hardware`, `board`, `qemu_prop`, `emulator_file`, `emulator_pkg`, `modern_virt_prop` | `emulator` | `STRONG` / `WEAK` | Ranchu/Goldfish/Genymotion/Nox/Waydroid/Cuttlefish/WSA/Corellium/LDPlayer 9/MuMu 12 artifacts synced via `artifact_paths.ini` & `<queries>` |
| Native Bridge (`virtualization_traps.cpp` fast path) | `native_bridge_prop`, `native_bridge_maps`, `native_bridge_cmdline`, `native_bridge_binary` | `emulator` | `STRONG` | Detects ARM translation on x86 hosts via `ro.dalvik.vm.native.bridge`, `/proc/self/maps`, `-Xnative-bridge`, and `/system/{bin,lib,lib64}/{houdini*,libnb.so,libndk_translation.so}` |
| GPU & MediaCodec | `virtual_gpu`, `zero_hw_codec` | `emulator` | `STRONG` / `WEAK` | EGL/GLES virtual renderers (`virgl`/`virtio`/`SwiftShader`/`llvmpipe`/`Android Emulator`) via `GpuClassifier`, plus `MediaCodecCollector.CodecSummary` zero-SoC-hardware (`c2.android.*`/`OMX.google.*` only) |
| AVF / Microdroid Joint Check | `avf_joint_markers` | `emulator` | `STRONG` | Requires `>= 2` joint AVF markers (`authfs` + `virtiofs`/`crosvm`) simultaneously |
| Hardware / Runtime heuristics | `thermal_zones_empty`, `runtime_arch_x86`, `cpu_hypervisor`, `emulator_ip`, `container_signal`, `build_characteristics` | `emulator` | `WEAK` | Supporting hardware/network/environment heuristics classified by `EmulatorEvidenceClassifier` |
| `POSTPONED` `virtualization_traps.cpp` | `arm64_clock_drift`, `sched_yield_low_cv` | `emulator` | `STRONG` / `INFO` | Disposable-child overflow-safe `sec/rem` ARM64 `cntfrq_el0`/`cntvct_el0` vs `CLOCK_MONOTONIC` drift (`STRONG`), and `sched_yield()` timing CV `< 0.03` & `<= 2` us buckets & `mean < 250us` (soft corroborator `INFO` only) |
| `POSTPONED` `SensorNoiseProbe` | `sensor_static_zero_var` | `emulator` | `INFO` / `WEAK` | Short-window (`<= 200ms`, 8–10 frames) MEMS accelerometer/gyroscope `stddev == 0.0`, emitted ONLY when corroborated by battery/camera/hardware/virtualization anomalies |

## Producing Subsystem

- Android `Build` / system properties, `PackageManager`, `MediaCodecList`, `SensorManager`, and EGL/OpenGL ES renderer query.
- Linux `/proc/self/{maps,cmdline}`, `/proc/cpuinfo`, `/sys/class/thermal`, and network interfaces.
- ARM64 virtual timer (`cntfrq_el0`/`cntvct_el0`) vs `CLOCK_MONOTONIC` and Linux `sched_yield()` inside `util/disposable_child`.

## Mechanism (AOSP/Linux/ACK)

- **Native Bridge Binary Translation (`D42`)**: Catches x86 emulators spoofing ARM ABIs by probing `OBF`-protected `ro.dalvik.vm.native.bridge`, loaded translation shared objects in `/proc/self/maps`, process cmdline `-Xnative-bridge`, and `/system/{bin,lib,lib64}` Houdini/NDK-translation binaries.
- **Overflow-Safe ARM64 Clock Drift (`D42`)**: Computes counter elapsed nanoseconds using `sec = delta / freq; rem = delta % freq; ns = sec * 1e9 + (rem * 1e9) / freq` inside `disposable_child` to prevent 64-bit multiplication overflow, comparing against `CLOCK_MONOTONIC`.
- **EGL Safety Invariant (`RED_LINES`)**: GPU inspection uses `eglReleaseThread()` and NEVER calls `eglTerminate(EGL_DEFAULT_DISPLAY)`, preventing destruction of host `hwui` `RenderThread`.
- **Separate `FAST`/`POSTPONED` Snapshot Cache (`D42`)**: `SignalSnapshot.getVirtualizationTraps(false)` vs `(true)` use isolated cache slots so fast scans never alias postponed trap results.

## Applicable API Range

- **Core Build/QEMU/Files/Packages/GPU/MediaCodec/Native Bridge/AVF/SensorNoise**: Android 11–17 (API 30–37), both 64-bit ABIs (`arm64-v8a`, `x86_64`).
- **`ro.hardware.virtual`**: Gated to `SDK_INT < 33` (denied by `default_prop` SELinux on API 33+).
- **`arm64_clock_drift`**: `arm64-v8a` only; `sched_yield_low_cv` runs on both 64-bit ABIs inside `disposable_child`.

## Visibility Boundaries

- Package visibility on Android 11+ restricts `PackageManager.getPackageInfo` to packages declared in `AndroidManifest.xml` `<queries>` (single-source synced with `artifact_paths.ini`, zero `QUERY_ALL_PACKAGES`).
- Hardware-accelerated ARM cloud instances running real SoC GPUs and native ARM64 kernels without QEMU/translation artifacts may appear clean to `emulator` and are corroborated by `cloud_phone`.
- Devices without accelerometers/gyroscopes (e.g. TV boxes or minimal tablets) cleanly skip `SensorNoiseProbe` without penalty.

## False-Positive Defenses

- **ANGLE-on-Vulkan physical GPU exemption (`GpuClassifier`)**: Physical handsets running ANGLE over Adreno/Mali/Xclipse Vulkan are explicitly exempted from `virtual_gpu`.
- **AVF/Microdroid `>= 2` joint-marker gate (`D43`)**: Prevents false positives on stock Pixel/Android 14+ devices that ship Android Virtualization Framework (`pVM`) support without running inside Microdroid.
- **Solo soft-corroborator suppression (`D42`, `D43`)**: Solo `sched_yield_low_cv` or solo `sensor_static_zero_var` NEVER produces actionable risk (not even under `LOGIN`/`PAYMENT` scene elevation — returns `SAFE/0` informational if no other signal is present); `sensor_static_zero_var` requires an existing hardware/battery/camera/virtualization anomaly.
- **Hardware noise exclusion (`D04`)**: `EmulatorEvidenceClassifier.isHardwareNoise()` excludes tablet/non-cellular noise (e.g. missing telephony/GPS) from weak-signal correlation escalation (`C1` requires `usefulWeak >= 3`).
- **Family deduplication**: Shares `emulator` family with `cloud_phone` so overlapping virtualization hits never double-score.

## Result State Mapping

- **`strong >= 2` or (`strong >= 1 && usefulWeak >= 1`)**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 8`, `informational = false` (actionable in all 4 scenes).
- **`strong == 1` only**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 4`, `informational = false` (actionable in all 4 scenes).
- **Non-soft `weak >= 1` only**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 1`, `informational = true` in `STANDARD` (elevates to actionable in `LOGIN`/`PAYMENT`).
- **Solo soft corroborators only (`sched_yield_low_cv` / `sensor_static_zero_var`)**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`, `informational = true`.
- **Zero signals**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
