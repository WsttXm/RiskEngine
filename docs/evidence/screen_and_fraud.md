# Evidence Contract Record — `screen_and_fraud`

- **Detector**: `screen_and_fraud` (`ScreenAndFraudDetector`, paired with lifecycle hooks in `AppLifecycleObserver` and optional `RiskWindowGuard`)
- **ScanTier**: `FAST` + event-driven API 34/35 capture & recording callbacks
- **EvidenceFamily**: `screen_control`, `fraud_context`
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| `DisplayManager` | `virtual_display` | `screen_control` | `STRONG` | Active virtual or presentation display matching remote-viewing/projection keywords (`scrcpy`, `virtual`, `projection`, `mirror`, `screenrecord`, `anydesk`, `teamviewer`, `airdroid`, `cast`, `vysor`) |
| `AccessibilityManager` | `third_party_a11y` | `screen_control` | `STRONG` | Enabled non-system third-party accessibility service (excluding `FLAG_SYSTEM` / `FLAG_UPDATED_SYSTEM_APP`) capable of remote UI automation or overlay theft |
| `InputManager` | `virtual_input` | `screen_control` | `MEDIUM` | Active virtual or remote-control input device (`scrcpy`, `anydesk`, `teamviewer`, `appium`, `droidvnc`, `uiautomator`, `vtouch`, `todesk`, `sunlogin`, `rustdesk`, etc., or UI-pointer/touch/keyboard `uinput`) |
| `AppLifecycleObserver` API 34/35 callbacks | `screen_recording_active`, `screen_capture_observed` | `screen_control` | `STRONG` / `WEAK` | Active API 35+ `WindowManager.addScreenRecordingCallback` (`STRONG`) or recent (`<= 60s`) API 34+ `Activity.ScreenCaptureCallback` (`WEAK`) |
| `AudioManager` | `ongoing_call` | `fraud_context` | `WEAK` | Active voice/VoIP call mode (`AudioManager.getMode()` in `MODE_IN_CALL` / `MODE_IN_COMMUNICATION`, zero `READ_PHONE_STATE`) |
| Wall-clock vs Monotonic Anchor | `time_spoofing` (`clock_rollback`, `clock_jump`, `auto_time_disabled`) | `fraud_context` | `MEDIUM` | Monotonic `SystemClock.elapsedRealtime()` vs `System.currentTimeMillis()` rollback (`> 60s`) or large forward jump (`> 300s`) between checks |

## Producing Subsystem

- Android `DisplayManager`, `AccessibilityManager`, `InputManager`, `AudioManager`, `Settings.Global` (`AUTO_TIME`), and `SystemClock.elapsedRealtime()`.
- Android 14 (API 34) `Activity.registerScreenCaptureCallback` and Android 15 (API 35) `WindowManager.addScreenRecordingCallback` registered by zero-dependency `AppLifecycleObserver` (guarded by runtime permission & exception checks).
- Optional host UI hardening helper `RiskWindowGuard` (`FLAG_SECURE`, API 31+ `setHideOverlayWindows`, `setFilterTouchesWhenObscured`).

## Mechanism (AOSP/Linux/ACK)

- **Vishing / Financial Fraud Combo (`C10:vishing_fraud_combo`, `D21`)**: During `PAYMENT` scene correlation, combining `ongoing_call` (`fraud_context`) with active screen sharing, screen recording, or third-party accessibility remote control (`screen_control`) triggers `CorrelationEngine` `C10:vishing_fraud_combo` (`HIGH/8` actionable), directly mitigating telecom-fraud guided transfers.
- **Zero-Permission Call & Capture Awareness (`D21`, `D23`)**: Uses `AudioManager.getMode()` (zero `READ_PHONE_STATE`) for ongoing-call context and runtime-checks `DETECT_SCREEN_CAPTURE` / `DETECT_SCREEN_RECORDING` before subscribing API 34/35 callbacks (zero `<uses-permission>` in SDK Manifest).
- **Monotonic Clock Anchor**: Stores a process-wide `ClockAnchor(wallMs, elapsedMs)` and compares wall-clock delta against monotonic `elapsedRealtime()` delta to detect manual clock rollback (`> 60s`) or forward tampering (`> 300s`).

## Applicable API Range

- **Displays, Accessibility, InputDevices, AudioManager call mode, Clock anchor**: Android 11–17 (API 30–37), all 4 ABIs.
- **Screen capture callback**: Android 14+ (API 34+) when host declares `DETECT_SCREEN_CAPTURE`.
- **Screen recording callback**: Android 15+ (API 35+) when host declares `DETECT_SCREEN_RECORDING`.

## Visibility Boundaries

- Without `DETECT_SCREEN_CAPTURE` / `DETECT_SCREEN_RECORDING` declared in the host app, API 34/35 callbacks are skipped cleanly without errors while `DisplayManager` virtual-display detection still covers standard `MediaProjection` / `scrcpy` sessions.
- Hardware HDMI capture cards or external cameras filming the screen are outside OS-level software visibility.

## False-Positive Defenses

- **System Accessibility & Built-In Keyboard exemptions (`D21`)**: Strictly excludes accessibility services carrying `FLAG_SYSTEM` or `FLAG_UPDATED_SYSTEM_APP` (e.g. TalkBack, Switch Access, OEM assistants) and excludes built-in `VIRTUAL_KEYBOARD` (`deviceId <= 0`).
- **Stock OEM `uinput-*` Hardware Driver exemption (`D46`)**: Explicitly exempts built-in OEM kernel `uinput` hardware drivers (`uinput-goodix`, `uinput-fpc`, `uinput-silead`, `uinput-focal`, `uinput-egis`, `uinput-elan`, `uinput-novatek`, `uinput-synaptics`, `uinput-qbt`, `uinput-haptics`, `uinput-pen`, `uinput-stylus`, `uinput-hall`, `uinput-ir`, `uinput-nfc`, `xiaomi_touch`, etc.), removes overly broad `uhid` matching, and gates generic `uinput`/`isVirtual` strictly on UI pointer/touch/alphabetic-keyboard sources (validated on Xiaomi 15 HyperOS 2).
- **Informational context separation (`D21`)**: Standalone `ongoing_call` or recent `screen_capture_observed` remains `LOW/1` informational (`fraud_context`), never blocking legitimate phone calls unless paired with active remote-control/screen-sharing in `PAYMENT` (`C10`).

## Result State Mapping

- **Active screen control (`virtual_display`, `third_party_a11y`, `virtual_input`, `screen_recording_active`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 5`, `informational = false` (elevates to `HIGH/7` in `PAYMENT`; combines with `ongoing_call` via `C10:vishing_fraud_combo` `HIGH/8`).
- **Time spoofing (`time_spoofing`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 4`, `informational = false` (actionable in all 4 scenes).
- **Soft context only (`ongoing_call`, `screen_capture_observed`)**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 1`, `informational = true`.
- **Clean**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
