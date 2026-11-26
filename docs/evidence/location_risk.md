# Evidence Contract Record — `location_risk`

- **Detector**: `location_risk` (`LocationRiskDetector`)
- **ScanTier**: `FAST`
- **EvidenceFamily**: `location_spoof`
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Zero-Permission `Location` Contract Canary | `location_canary_tamper` (`lat_lon_roundtrip_a`, `altitude_mask_a`, `accuracy_mask_a`, `time_roundtrip_a`, `lat_lon_roundtrip_b`, `reset_fields_mask`, `set_mock_roundtrip`) | `location_spoof` | `STRONG` | In-memory synthetic `android.location.Location` contract round-trip verifying setter/getter fidelity across two distinct synthetic values, `reset()` field-mask clearing, and API 31+ `setMock(true/false)`/`isMock()` parity |
| Optional Cached `Location.isMock()` | `cached_location_mock` | `location_spoof` | `MEDIUM` | Cached `LocationManager.getLastKnownLocation().isMock()` flag (ONLY executed if the host already holds `ACCESS_FINE_LOCATION` or `ACCESS_COARSE_LOCATION`; logs sanitized provider tag only — zero coordinates!) |
| `AppOpsManager` Mock-Location Op | `mock_location_appop_allowed` | `location_spoof` | `MEDIUM` | `AppOpsManager.OPSTR_MOCK_LOCATION` observed in `MODE_ALLOWED` for the host UID |

## Producing Subsystem

- Android framework `android.location.Location` in-memory object (exercised purely with fixed synthetic test constants — never real GPS data).
- Android `LocationManager` (strictly runtime-permission gated) and `AppOpsManager`.

## Mechanism (AOSP/Linux/ACK)

- **Zero-Permission Location Contract Canary (`D20`)**: Coarse Xposed/LSPosed GPS spoofing modules hook `Location.getLatitude()`, `getLongitude()`, `getAltitude()`, `getAccuracy()`, `getTime()`, or `isMock()` globally to return constant spoofed coordinates or always return `isMock() == false`. By instantiating a fresh synthetic `Location`, writing synthetic coordinates A and B, verifying `hasAltitude()`/`hasAccuracy()` before and after `reset()`, and testing `setMock(true/false)` on API 31+, `LocationRiskDetector` exposes active hooks with **zero location permissions** and **zero coordinate PII**.
- **Strict Zero-PII Guarantee (`RED_LINES`)**: Even when the host holds location permissions and `cached_location_mock` runs, only the boolean `isMock()` result and a sanitized provider tag (e.g. `gps`, `fused`) are inspected; latitude, longitude, altitude, and addresses are NEVER read, logged, or serialized.

## Applicable API Range

- **Contract canary (`lat`/`lon`/`alt`/`acc`/`time`/`reset`) & `AppOpsManager` / cached `isMock()`**: Android 11–17 (API 30–37), both 64-bit ABIs (`arm64-v8a`, `x86_64`).
- **`setMock(true/false)` <-> `isMock()` canary round-trip**: Android 12–17 (API 31–37; `Location.setMock` introduced in API 31).

## Visibility Boundaries

- Zero `<uses-permission>` is declared in `riskengine-sdk/src/main/AndroidManifest.xml`; without host location permissions, `cached_location_mock` is skipped cleanly while the zero-permission contract canary continues to run.
- Hardware/external Bluetooth GPS spoofers or kernel/HAL-level GNSS injection that produce structurally valid `Location` objects without hooking `android.location.Location` Java methods or setting `isMock` are outside user-space location canary visibility.

## False-Positive Defenses

- **Pure-JVM `android.jar` stub guard (`D20`)**: `LocationCanaryAdapter.isFunctionalRuntime()` verifies `getProvider() != null` on a constructed `Location("riskengine_canary")` so unmocked JVM unit-test stubs cleanly skip the canary instead of producing false positives.
- **No-error visibility neutrality**: If no location sub-check can run on a restricted environment, `LocationRiskDetector` stays `SAFE` (never degrades to `UNKNOWN`).
- **Scene-tiered `isMock()` scoring (`D20`)**: Contract-canary hook tamper (`HIGH/7`) is actionable in all 4 scenes, while `cached_location_mock` / `mock_location_appop_allowed` (`MEDIUM/4`) remain informational in `STANDARD` and elevate to actionable in `LOGIN`/`PAYMENT`.

## Result State Mapping

- **Contract canary tampered (`location_canary_tamper`)**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 7`, `informational = false` (actionable in all 4 scenes).
- **Mock flag / AppOp only (`cached_location_mock`, `mock_location_appop_allowed`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 4`, `informational = true` in `STANDARD` (actionable in `LOGIN`/`PAYMENT`).
- **Clean**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
