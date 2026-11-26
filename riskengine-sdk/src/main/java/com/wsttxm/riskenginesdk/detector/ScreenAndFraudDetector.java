package com.wsttxm.riskenginesdk.detector;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.ResolveInfo;
import android.hardware.display.DisplayManager;
import android.hardware.input.InputManager;
import android.media.AudioManager;
import android.os.Build;
import android.os.SystemClock;
import android.provider.Settings;
import android.view.Display;
import android.view.InputDevice;
import android.view.accessibility.AccessibilityManager;

import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * FAST-tier screen sharing, remote-control automation, vishing call-state & time-spoofing
 * detector ({@code screen_and_fraud}).
 *
 * <p>Requires zero {@code <uses-permission>} in the SDK manifest and exposes lightweight static
 * hooks for API 34/35 screen capture/recording callbacks integrated by {@code AppLifecycleObserver}.
 */
public class ScreenAndFraudDetector extends BaseDetector {
    private static final String FAMILY_SCREEN_CONTROL = "screen_control";
    private static final String FAMILY_FRAUD_CONTEXT = "fraud_context";

    private static final long RECENT_CAPTURE_WINDOW_MS = 60_000L;
    private static final long CLOCK_ROLLBACK_THRESHOLD_MS = 60_000L;
    private static final long CLOCK_JUMP_THRESHOLD_MS = 300_000L;

    private static final List<String> VIRTUAL_DISPLAY_KEYWORDS = Arrays.asList(
            "scrcpy", "virtual", "projection", "mirror", "screenrecord",
            "anydesk", "teamviewer", "airdroid", "cast", "vysor"
    );

    private static final List<String> REMOTE_CONTROL_INPUT_KEYWORDS = Arrays.asList(
            "scrcpy", "anydesk", "teamviewer", "appium", "droidvnc",
            "uiautomator", "vtouch", "airdroid", "vysor", "todesk",
            "sunlogin", "rustdesk", "quickassist"
    );

    /**
     * Built-in OEM hardware drivers exposed via kernel uinput (under-display fingerprint
     * sensors, haptics, stylus, hall/IR/NFC keys) on stock Xiaomi/Qualcomm/OPPO/vivo phones.
     */
    private static final List<String> STOCK_OEM_UINPUT_HARDWARE_KEYWORDS = Arrays.asList(
            "uinput-goodix", "uinput_goodix",
            "uinput-fpc", "uinput_fpc",
            "uinput-silead", "uinput_silead",
            "uinput-focal", "uinput_focal",
            "uinput-egis", "uinput_egis",
            "uinput-elan", "uinput_elan",
            "uinput-novatek", "uinput_novatek",
            "uinput-synaptics", "uinput_synaptics",
            "uinput-qbt", "uinput_qbt",
            "uinput-haptics", "uinput_haptics",
            "uinput-folio", "uinput_folio",
            "uinput-pen", "uinput_pen",
            "uinput-stylus", "uinput_stylus",
            "uinput-hall", "uinput_hall",
            "uinput-ir", "uinput_ir",
            "uinput-nfc", "uinput_nfc",
            "uinput-sensor", "uinput_sensor",
            "uinput-nav", "uinput_nav",
            "goodix_fingerprint", "fpc_fingerprint", "fingerprint",
            "xiaomi_touch", "mi_pen"
    );

    // Lightweight process-wide runtime state hooks populated by AppLifecycleObserver (P1-12).
    private static final AtomicBoolean SCREEN_RECORDING_ACTIVE = new AtomicBoolean(false);
    private static final AtomicLong LAST_SCREEN_CAPTURE_WALL_MS = new AtomicLong(0L);
    private static final AtomicReference<ClockAnchor> LAST_CLOCK_ANCHOR = new AtomicReference<>(null);

    private final ScreenAndFraudEnvironment env;

    public ScreenAndFraudDetector(Context context) {
        this(context, null);
    }

    /** Internal test seam for deterministic pure-JVM unit tests (not part of public SDK contract). */
    public static ScreenAndFraudDetector createForTest(Context context,
                                                       ScreenAndFraudEnvironment env) {
        return new ScreenAndFraudDetector(context, env);
    }

    ScreenAndFraudDetector(Context context, ScreenAndFraudEnvironment env) {
        super(context);
        this.env = env != null ? env : new AndroidScreenAndFraudEnvironment(this.context);
    }

    /** Records an API 34+ screen capture callback event from {@code AppLifecycleObserver}. */
    public static void notifyScreenCaptureObserved() {
        notifyScreenCaptureObservedAt(System.currentTimeMillis());
    }

    /** Internal/test hook specifying the exact observation timestamp. */
    public static void notifyScreenCaptureObservedAt(long wallTimeMs) {
        LAST_SCREEN_CAPTURE_WALL_MS.set(wallTimeMs);
    }

    /** Updates the API 35+ active screen recording state from {@code AppLifecycleObserver}. */
    public static void setScreenRecordingActive(boolean active) {
        SCREEN_RECORDING_ACTIVE.set(active);
    }

    public static boolean isScreenRecordingActive() {
        return SCREEN_RECORDING_ACTIVE.get();
    }

    public static long getLastScreenCaptureWallMs() {
        return LAST_SCREEN_CAPTURE_WALL_MS.get();
    }

    /** Internal test helper to clear static runtime hooks & clock anchor between tests. */
    public static void resetRuntimeStateForTest() {
        SCREEN_RECORDING_ACTIVE.set(false);
        LAST_SCREEN_CAPTURE_WALL_MS.set(0L);
        LAST_CLOCK_ANCHOR.set(null);
    }

    @Override
    public String getName() {
        return "screen_and_fraud";
    }

    @Override
    public ScanTier getScanTier() {
        return ScanTier.FAST;
    }

    @Override
    protected DetectionResult detect() {
        CheckCoverage coverage = new CheckCoverage();
        List<String> details = new ArrayList<>();
        Map<String, EvidenceItem> evidenceByKey = new LinkedHashMap<>();

        boolean hasScreenControl = false;
        boolean hasTimeSpoofing = false;
        boolean hasSoftFraudContext = false;

        // 1. Virtual / Presentation displays (scrcpy, MediaProjection, AnyDesk, TeamViewer)
        try {
            List<String> virtualDisplays = env.findVirtualOrPresentationDisplays();
            if (virtualDisplays != null) {
                coverage.success();
                for (String name : virtualDisplays) {
                    if (name == null || name.isBlank()) continue;
                    hasScreenControl = true;
                    String safe = sanitizeTag(name);
                    addFinding(details, evidenceByKey, "virtual_display:" + safe,
                            "virtual_display", EvidenceItem.SourceLayer.JAVA,
                            "DisplayManager", safe, FAMILY_SCREEN_CONTROL,
                            EvidenceItem.Rank.STRONG);
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("display_check_error:" + e.getClass().getSimpleName());
        }

        // 2. Non-system 3rd-party accessibility services (remote control / auto-clicker / bankers)
        try {
            List<String> thirdPartyA11y = env.findThirdPartyAccessibilityServices();
            if (thirdPartyA11y != null) {
                coverage.success();
                for (String pkg : thirdPartyA11y) {
                    if (pkg == null || pkg.isBlank()) continue;
                    hasScreenControl = true;
                    String safe = sanitizeTag(pkg);
                    addFinding(details, evidenceByKey, "third_party_a11y:" + safe,
                            "third_party_a11y", EvidenceItem.SourceLayer.JAVA,
                            "AccessibilityManager", safe, FAMILY_SCREEN_CONTROL,
                            EvidenceItem.Rank.STRONG);
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("a11y_check_error:" + e.getClass().getSimpleName());
        }

        // 3. Virtual input devices (uinput / scrcpy / remote touch injection)
        try {
            List<String> virtualInputs = env.findVirtualInputDevices();
            if (virtualInputs != null) {
                coverage.success();
                for (String dev : virtualInputs) {
                    if (dev == null || dev.isBlank()) continue;
                    hasScreenControl = true;
                    String safe = sanitizeTag(dev);
                    addFinding(details, evidenceByKey, "virtual_input:" + safe,
                            "virtual_input", EvidenceItem.SourceLayer.JAVA,
                            "InputManager", safe, FAMILY_SCREEN_CONTROL,
                            EvidenceItem.Rank.MEDIUM);
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("input_check_error:" + e.getClass().getSimpleName());
        }

        // 4. Lifecycle-bound screen recording / recent capture hook state
        coverage.success();
        long nowWall = env.currentTimeMillis();
        if (env.isScreenRecordingActive()) {
            hasScreenControl = true;
            addFinding(details, evidenceByKey, "screen_recording_active",
                    "screen_recording_active", EvidenceItem.SourceLayer.JAVA,
                    "WindowManager", "recording=true", FAMILY_SCREEN_CONTROL,
                    EvidenceItem.Rank.STRONG);
        }
        long lastCaptureMs = env.getLastScreenCaptureWallMs();
        if (lastCaptureMs > 0 && nowWall >= lastCaptureMs
                && (nowWall - lastCaptureMs) <= RECENT_CAPTURE_WINDOW_MS) {
            hasSoftFraudContext = true;
            addFinding(details, evidenceByKey, "screen_capture_observed",
                    "screen_capture_observed", EvidenceItem.SourceLayer.JAVA,
                    "Activity.ScreenCaptureCallback", "recent_capture",
                    FAMILY_SCREEN_CONTROL, EvidenceItem.Rank.WEAK);
        }

        // 5. Ongoing call state (zero READ_PHONE_STATE; AudioManager.getMode() only)
        try {
            String callMode = env.getOngoingCallMode();
            coverage.success();
            if (callMode != null && !callMode.isBlank()) {
                hasSoftFraudContext = true;
                String safe = sanitizeTag(callMode);
                addFinding(details, evidenceByKey, "ongoing_call:" + safe,
                        "ongoing_call", EvidenceItem.SourceLayer.JAVA,
                        "AudioManager", safe, FAMILY_FRAUD_CONTEXT,
                        EvidenceItem.Rank.WEAK);
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("audio_mode_error:" + e.getClass().getSimpleName());
        }

        // 6. Time spoofing (currentTimeMillis < Build.TIME, AUTO_TIME==0, wall vs monotonic drift)
        try {
            coverage.success();
            long buildTime = env.getBuildTimeMillis();
            if (buildTime > 0 && nowWall > 0 && nowWall < buildTime) {
                hasTimeSpoofing = true;
                addFinding(details, evidenceByKey, "time_spoofing:before_build_time",
                        "time_spoofing", EvidenceItem.SourceLayer.JAVA,
                        "clock:build_time", "wall_before_build_time",
                        FAMILY_FRAUD_CONTEXT, EvidenceItem.Rank.MEDIUM);
            }
            Integer autoTime = env.getAutoTimeSetting();
            if (autoTime != null && autoTime == 0) {
                hasTimeSpoofing = true;
                addFinding(details, evidenceByKey, "time_spoofing:auto_time_disabled",
                        "time_spoofing", EvidenceItem.SourceLayer.JAVA,
                        "Settings.Global.AUTO_TIME", "auto_time=0",
                        FAMILY_FRAUD_CONTEXT, EvidenceItem.Rank.MEDIUM);
            }
            long nowMono = env.elapsedRealtimeMillis();
            if (nowWall > 0 && nowMono > 0) {
                ClockAnchor prev = env.getAndUpdateClockAnchor(new ClockAnchor(nowWall, nowMono));
                if (prev != null) {
                    long wallDelta = nowWall - prev.wallMs;
                    long monoDelta = nowMono - prev.monoMs;
                    if (wallDelta < -CLOCK_ROLLBACK_THRESHOLD_MS) {
                        hasTimeSpoofing = true;
                        addFinding(details, evidenceByKey, "time_spoofing:clock_rollback",
                                "time_spoofing", EvidenceItem.SourceLayer.JAVA,
                                "clock:monotonic_compare",
                                "wall_delta_ms=" + wallDelta,
                                FAMILY_FRAUD_CONTEXT, EvidenceItem.Rank.MEDIUM);
                    } else if (monoDelta >= 0
                            && Math.abs(wallDelta - monoDelta) > CLOCK_JUMP_THRESHOLD_MS) {
                        hasTimeSpoofing = true;
                        addFinding(details, evidenceByKey, "time_spoofing:clock_jump",
                                "time_spoofing", EvidenceItem.SourceLayer.JAVA,
                                "clock:monotonic_compare",
                                "drift_ms=" + (wallDelta - monoDelta),
                                FAMILY_FRAUD_CONTEXT, EvidenceItem.Rank.MEDIUM);
                    }
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("time_check_error:" + e.getClass().getSimpleName());
        }

        RiskLevel level;
        DetectionStatus status;
        int score;
        boolean informational;
        if (hasScreenControl) {
            level = RiskLevel.MEDIUM;
            status = DetectionStatus.WARNING;
            score = 5;
            informational = false;
        } else if (hasTimeSpoofing) {
            level = RiskLevel.MEDIUM;
            status = DetectionStatus.WARNING;
            score = 4;
            informational = false;
        } else if (hasSoftFraudContext) {
            level = RiskLevel.LOW;
            status = DetectionStatus.WARNING;
            score = 1;
            informational = true;
        } else {
            level = RiskLevel.SAFE;
            status = DetectionStatus.NORMAL;
            score = 0;
            informational = false;
        }

        String evidence = details.isEmpty() ? "clean" : String.join("; ", details);
        DetectionResult result = result(
                level,
                status,
                score,
                10,
                informational,
                details,
                evidence,
                coverage
        );
        if (!evidenceByKey.isEmpty()) {
            result = result.withEvidenceItems(new ArrayList<>(evidenceByKey.values()));
        }
        return result;
    }

    static boolean isVirtualDisplayCandidate(int displayId, int flags, String name) {
        if (displayId == Display.DEFAULT_DISPLAY) {
            return false;
        }
        if ((flags & Display.FLAG_PRESENTATION) != 0) {
            return true;
        }
        if (name != null && !name.isBlank()) {
            String lower = name.toLowerCase(Locale.ROOT);
            for (String kw : VIRTUAL_DISPLAY_KEYWORDS) {
                if (lower.contains(kw)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean isVirtualInputCandidate(int deviceId, boolean isVirtualFlag, String name) {
        return isVirtualInputCandidate(deviceId, isVirtualFlag, name,
                InputDevice.SOURCE_TOUCHSCREEN, InputDevice.KEYBOARD_TYPE_NONE);
    }

    public static boolean isVirtualInputCandidate(int deviceId,
                                                  boolean isVirtualFlag,
                                                  String name,
                                                  int sources,
                                                  int keyboardType) {
        // Android devices always expose built-in system VIRTUAL_KEYBOARD (id == -1, name "Virtual").
        if (deviceId <= 0) {
            return false;
        }
        String lower = name == null ? "" : name.trim().toLowerCase(Locale.ROOT);
        if ("virtual".equals(lower)) {
            return false;
        }
        // Explicit remote-control / automation tool input devices always trigger.
        if (!lower.isEmpty()) {
            for (String kw : REMOTE_CONTROL_INPUT_KEYWORDS) {
                if (lower.contains(kw)) {
                    return true;
                }
            }
            // Exempt known stock OEM hardware uinput drivers (e.g. Xiaomi 15 uinput-goodix/fpc).
            for (String hw : STOCK_OEM_UINPUT_HARDWARE_KEYWORDS) {
                if (lower.contains(hw)) {
                    return false;
                }
            }
        }

        // Generic uinput or virtual devices must have UI pointer/touch/alphabetic-keyboard
        // injection capability (filtering out kernel sensor/fingerprint/key-only drivers).
        boolean hasUiControlSource =
                (sources & InputDevice.SOURCE_TOUCHSCREEN) == InputDevice.SOURCE_TOUCHSCREEN
                || (sources & InputDevice.SOURCE_MOUSE) == InputDevice.SOURCE_MOUSE
                || (sources & InputDevice.SOURCE_TOUCHPAD) == InputDevice.SOURCE_TOUCHPAD
                || (sources & InputDevice.SOURCE_STYLUS) == InputDevice.SOURCE_STYLUS
                || (sources & InputDevice.SOURCE_DPAD) == InputDevice.SOURCE_DPAD
                || keyboardType == InputDevice.KEYBOARD_TYPE_ALPHABETIC;

        if (!hasUiControlSource) {
            return false;
        }
        return isVirtualFlag || lower.contains("uinput");
    }

    private static String sanitizeTag(String raw) {
        StringBuilder sb = new StringBuilder(Math.min(raw.length(), 48));
        for (int i = 0; i < raw.length() && sb.length() < 48; i++) {
            char c = raw.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
                sb.append(c);
            } else if (c == ' ') {
                sb.append('_');
            }
        }
        return sb.length() == 0 ? "unknown" : sb.toString();
    }

    private static void addFinding(List<String> details,
                                   Map<String, EvidenceItem> evidenceByKey,
                                   String detailToken,
                                   String code,
                                   EvidenceItem.SourceLayer source,
                                   String location,
                                   String rawValue,
                                   String family,
                                   EvidenceItem.Rank rank) {
        if (!details.contains(detailToken)) {
            details.add(detailToken);
        }
        String key = code + "|" + (location == null ? "" : location) + "|" + rawValue;
        EvidenceItem item = new EvidenceItem(code, source, location, rawValue, family, rank);
        EvidenceItem existing = evidenceByKey.get(key);
        evidenceByKey.put(key, existing == null ? item : existing.mergeWith(item));
    }

    public static final class ClockAnchor {
        public final long wallMs;
        public final long monoMs;

        public ClockAnchor(long wallMs, long monoMs) {
            this.wallMs = wallMs;
            this.monoMs = monoMs;
        }
    }

    /** Environment abstraction for deterministic pure-JVM unit testing. */
    public interface ScreenAndFraudEnvironment {
        List<String> findVirtualOrPresentationDisplays();
        List<String> findThirdPartyAccessibilityServices();
        List<String> findVirtualInputDevices();
        boolean isScreenRecordingActive();
        long getLastScreenCaptureWallMs();
        String getOngoingCallMode();
        long currentTimeMillis();
        long elapsedRealtimeMillis();
        long getBuildTimeMillis();
        Integer getAutoTimeSetting();
        ClockAnchor getAndUpdateClockAnchor(ClockAnchor next);
    }

    private static final class AndroidScreenAndFraudEnvironment implements ScreenAndFraudEnvironment {
        private final Context context;

        AndroidScreenAndFraudEnvironment(Context context) {
            this.context = context;
        }

        @Override
        public List<String> findVirtualOrPresentationDisplays() {
            if (context == null) return null;
            try {
                DisplayManager dm = (DisplayManager) context.getSystemService(
                        Context.DISPLAY_SERVICE);
                if (dm == null) return null;
                Display[] displays = dm.getDisplays();
                if (displays == null) return Collections.emptyList();
                List<String> hits = new ArrayList<>();
                for (Display display : displays) {
                    if (display == null) continue;
                    String name = display.getName();
                    if (isVirtualDisplayCandidate(display.getDisplayId(), display.getFlags(), name)) {
                        hits.add(name != null && !name.isBlank()
                                ? name : ("display_" + display.getDisplayId()));
                    }
                }
                return hits;
            } catch (Exception | LinkageError e) {
                return null;
            }
        }

        @Override
        public List<String> findThirdPartyAccessibilityServices() {
            if (context == null) return null;
            try {
                AccessibilityManager am = (AccessibilityManager) context.getSystemService(
                        Context.ACCESSIBILITY_SERVICE);
                if (am == null) return null;
                List<AccessibilityServiceInfo> list = am.getEnabledAccessibilityServiceList(
                        AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
                if (list == null) return Collections.emptyList();
                List<String> thirdParty = new ArrayList<>();
                for (AccessibilityServiceInfo info : list) {
                    if (info == null) continue;
                    ResolveInfo ri = info.getResolveInfo();
                    if (ri == null || ri.serviceInfo == null) continue;
                    ApplicationInfo ai = ri.serviceInfo.applicationInfo;
                    if (ai != null) {
                        int sysMask = ApplicationInfo.FLAG_SYSTEM
                                | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP;
                        if ((ai.flags & sysMask) != 0) {
                            continue; // Exclude system accessibility services (e.g., TalkBack)
                        }
                    }
                    String pkg = ri.serviceInfo.packageName;
                    if (pkg != null && !pkg.isBlank() && !thirdParty.contains(pkg)) {
                        thirdParty.add(pkg);
                    }
                }
                return thirdParty;
            } catch (Exception | LinkageError e) {
                return null;
            }
        }

        @Override
        public List<String> findVirtualInputDevices() {
            if (context == null) return null;
            try {
                InputManager im = (InputManager) context.getSystemService(Context.INPUT_SERVICE);
                if (im == null) return null;
                int[] ids = im.getInputDeviceIds();
                if (ids == null) return Collections.emptyList();
                List<String> hits = new ArrayList<>();
                for (int id : ids) {
                    InputDevice device = im.getInputDevice(id);
                    if (device == null) continue;
                    String name = device.getName();
                    if (isVirtualInputCandidate(
                            id, device.isVirtual(), name,
                            device.getSources(), device.getKeyboardType())) {
                        hits.add(name != null && !name.isBlank() ? name : ("input_" + id));
                    }
                }
                return hits;
            } catch (Exception | LinkageError e) {
                return null;
            }
        }

        @Override
        public boolean isScreenRecordingActive() {
            return SCREEN_RECORDING_ACTIVE.get();
        }

        @Override
        public long getLastScreenCaptureWallMs() {
            return LAST_SCREEN_CAPTURE_WALL_MS.get();
        }

        @Override
        public String getOngoingCallMode() {
            if (context == null) return null;
            try {
                AudioManager audio = (AudioManager) context.getSystemService(Context.AUDIO_SERVICE);
                if (audio == null) return null;
                int mode = audio.getMode();
                if (mode == AudioManager.MODE_IN_CALL) {
                    return "in_call";
                }
                if (mode == AudioManager.MODE_IN_COMMUNICATION) {
                    return "in_communication";
                }
                if (mode == AudioManager.MODE_CALL_SCREENING) {
                    return "call_screening";
                }
                return null;
            } catch (Exception | LinkageError e) {
                return null;
            }
        }

        @Override
        public long currentTimeMillis() {
            return System.currentTimeMillis();
        }

        @Override
        public long elapsedRealtimeMillis() {
            try {
                return SystemClock.elapsedRealtime();
            } catch (Exception | LinkageError e) {
                return 0L;
            }
        }

        @Override
        public long getBuildTimeMillis() {
            return Build.TIME;
        }

        @Override
        public Integer getAutoTimeSetting() {
            if (context == null) return null;
            try {
                return Settings.Global.getInt(
                        context.getContentResolver(), Settings.Global.AUTO_TIME);
            } catch (Exception | LinkageError e) {
                return null;
            }
        }

        @Override
        public ClockAnchor getAndUpdateClockAnchor(ClockAnchor next) {
            return LAST_CLOCK_ANCHOR.getAndSet(next);
        }
    }
}
