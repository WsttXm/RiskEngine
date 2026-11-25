package com.wsttxm.riskenginesdk.detector;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.AppOpsManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.os.Build;
import android.os.Process;

import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * FAST-tier zero-location-permission mock/spoof location detector ({@code location_risk}).
 *
 * <p>Core checks run with ZERO location permissions in the SDK manifest and NEVER collect,
 * log, or serialize raw coordinates (latitude, longitude, altitude, or address):
 * <ol>
 *   <li>Zero-permission {@link Location} contract canary: verifies getter/setter round-trip,
 *       field-mask ({@code has*}) semantics across {@code reset()}, and API 31+
 *       {@code setMock(true/false)}/{@code isMock()} parity to defeat coarse Xposed/LSPosed
 *       location hooks ({@code HIGH/7} actionable in all scenes).</li>
 *   <li>Optional cached {@code Location.isMock()} inspection (only if the host already holds
 *       location permission) and {@code AppOpsManager.OPSTR_MOCK_LOCATION} check
 *       ({@code MEDIUM/4}, informational in {@code STANDARD}, actionable in
 *       {@code LOGIN}/{@code PAYMENT}).</li>
 * </ol>
 */
public class LocationRiskDetector extends BaseDetector {
    private static final String FAMILY_LOCATION_SPOOF = "location_spoof";

    private final LocationEnvironment env;

    public LocationRiskDetector(Context context) {
        this(context, null);
    }

    /** Internal test seam for deterministic pure-JVM unit tests (not part of public SDK contract). */
    public static LocationRiskDetector createForTest(Context context, LocationEnvironment env) {
        return new LocationRiskDetector(context, env);
    }

    LocationRiskDetector(Context context, LocationEnvironment env) {
        super(context);
        this.env = env != null ? env : new AndroidLocationEnvironment(this.context);
    }

    @Override
    public String getName() {
        return "location_risk";
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

        boolean hasCanaryTamper = false;
        boolean hasMockLocation = false;
        boolean anyCheckExecuted = false;

        // 1. Zero-permission Location contract canary (decoupled via adapter for JVM stub safety)
        try {
            LocationCanaryAdapter canary = env.createCanaryAdapter();
            if (canary != null && canary.isFunctionalRuntime()) {
                coverage.success();
                anyCheckExecuted = true;
                List<String> violations = runLocationContractCanary(canary);
                for (String violation : violations) {
                    hasCanaryTamper = true;
                    String token = "location_canary_tamper:" + violation;
                    addFinding(details, evidenceByKey, token, "location_canary_tamper",
                            EvidenceItem.SourceLayer.JAVA, "android.location.Location",
                            violation, EvidenceItem.Rank.STRONG);
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("location_canary_error:" + e.getClass().getSimpleName());
            anyCheckExecuted = true;
        }

        // 2. Optional cached Location.isMock() (ONLY when host already holds permission; zero PII)
        try {
            List<String> mockProviders = env.findMockCachedLocationProviders();
            if (mockProviders != null) {
                coverage.success();
                anyCheckExecuted = true;
                for (String provider : mockProviders) {
                    if (provider == null || provider.isBlank()) continue;
                    hasMockLocation = true;
                    String safeProvider = sanitizeProviderTag(provider);
                    String token = "cached_location_mock:" + safeProvider;
                    addFinding(details, evidenceByKey, token, "cached_location_mock",
                            EvidenceItem.SourceLayer.JAVA, "LocationManager:" + safeProvider,
                            "isMock=true", EvidenceItem.Rank.MEDIUM);
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("cached_location_error:" + e.getClass().getSimpleName());
            anyCheckExecuted = true;
        }

        // 3. AppOpsManager mock-location status (visibility loss is never a threat)
        try {
            Boolean mockAppOpAllowed = env.isMockLocationAppOpAllowed();
            if (mockAppOpAllowed != null) {
                coverage.success();
                anyCheckExecuted = true;
                if (Boolean.TRUE.equals(mockAppOpAllowed)) {
                    hasMockLocation = true;
                    addFinding(details, evidenceByKey, "mock_location_appop_allowed",
                            "mock_location_appop_allowed",
                            EvidenceItem.SourceLayer.JAVA, "AppOpsManager",
                            "OPSTR_MOCK_LOCATION=MODE_ALLOWED", EvidenceItem.Rank.MEDIUM);
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("appops_mock_error:" + e.getClass().getSimpleName());
            anyCheckExecuted = true;
        }

        // If running on pure-JVM stub where canary/location services are absent and no errors occurred,
        // keep visibility loss neutral (SAFE) rather than degrading clean hosts.
        if (!anyCheckExecuted) {
            coverage.success();
        }

        RiskLevel level;
        DetectionStatus status;
        int score;
        boolean informational;
        if (hasCanaryTamper) {
            level = RiskLevel.HIGH;
            status = DetectionStatus.DANGER;
            score = 7;
            informational = false;
        } else if (hasMockLocation) {
            level = RiskLevel.MEDIUM;
            status = DetectionStatus.WARNING;
            score = 4;
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

    /**
     * Executes the zero-permission Location contract canary against an adapter.
     * Uses fixed synthetic in-memory test numbers (never real device coordinates).
     */
    static List<String> runLocationContractCanary(LocationCanaryAdapter canary) {
        List<String> violations = new ArrayList<>();
        final double eps = 1e-6;

        // Round 1: set synthetic values A and verify getters + field-mask flags
        canary.setLatitude(12.345678);
        canary.setLongitude(-45.678901);
        canary.setAltitude(123.5);
        canary.setAccuracy(7.25f);
        canary.setTime(1_700_000_000_123L);

        if (Math.abs(canary.getLatitude() - 12.345678) > eps
                || Math.abs(canary.getLongitude() - (-45.678901)) > eps) {
            violations.add("lat_lon_roundtrip_a");
        }
        if (!canary.hasAltitude() || Math.abs(canary.getAltitude() - 123.5) > eps) {
            violations.add("altitude_mask_a");
        }
        if (!canary.hasAccuracy() || Math.abs(canary.getAccuracy() - 7.25f) > 1e-4f) {
            violations.add("accuracy_mask_a");
        }
        if (canary.getTime() != 1_700_000_000_123L) {
            violations.add("time_roundtrip_a");
        }

        // Round 2: mutate to distinct synthetic values B to defeat constant-return hooks
        canary.setLatitude(-33.112233);
        canary.setLongitude(118.445566);
        if (Math.abs(canary.getLatitude() - (-33.112233)) > eps
                || Math.abs(canary.getLongitude() - 118.445566) > eps) {
            violations.add("lat_lon_roundtrip_b");
        }

        // Round 3: reset() must clear mFieldsMask bits and zero core coordinates/time
        canary.reset();
        if (canary.hasAltitude() || canary.hasAccuracy()
                || Math.abs(canary.getLatitude()) > eps
                || Math.abs(canary.getLongitude()) > eps
                || canary.getTime() != 0L) {
            violations.add("reset_fields_mask");
        }

        // Round 4: API 31+ setMock(true/false) <-> isMock() round-trip
        if (canary.supportsSetMock()) {
            canary.setMock(true);
            boolean mockTrue = canary.isMock();
            canary.setMock(false);
            boolean mockFalse = canary.isMock();
            if (!mockTrue || mockFalse) {
                violations.add("set_mock_roundtrip");
            }
        }
        return violations;
    }

    private static String sanitizeProviderTag(String provider) {
        StringBuilder sb = new StringBuilder(provider.length());
        for (int i = 0; i < provider.length() && sb.length() < 32; i++) {
            char c = provider.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_' || c == '-') {
                sb.append(c);
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
                                   EvidenceItem.Rank rank) {
        if (!details.contains(detailToken)) {
            details.add(detailToken);
        }
        String key = code + "|" + (location == null ? "" : location);
        EvidenceItem item = new EvidenceItem(
                code, source, location, rawValue, FAMILY_LOCATION_SPOOF, rank);
        EvidenceItem existing = evidenceByKey.get(key);
        evidenceByKey.put(key, existing == null ? item : existing.mergeWith(item));
    }

    /** Adapter over {@link Location} so JVM android.jar default stubs never false-positive. */
    public interface LocationCanaryAdapter {
        boolean isFunctionalRuntime();
        void setLatitude(double lat);
        double getLatitude();
        void setLongitude(double lon);
        double getLongitude();
        void setAltitude(double alt);
        double getAltitude();
        boolean hasAltitude();
        void setAccuracy(float acc);
        float getAccuracy();
        boolean hasAccuracy();
        void setTime(long timeMs);
        long getTime();
        void reset();
        boolean supportsSetMock();
        void setMock(boolean mock);
        boolean isMock();
    }

    /** Environment abstraction for deterministic zero-permission pure-JVM unit tests. */
    public interface LocationEnvironment {
        LocationCanaryAdapter createCanaryAdapter();
        /** Returns provider names whose cached Location reports isMock()==true, or null if skipped. */
        List<String> findMockCachedLocationProviders();
        /** Returns true/false if AppOps mock check succeeded, or null if unavailable. */
        Boolean isMockLocationAppOpAllowed();
    }

    private static final class AndroidLocationCanaryAdapter implements LocationCanaryAdapter {
        private static final String CANARY_PROVIDER = "riskengine_canary";
        private final Location loc;
        private final boolean functional;

        AndroidLocationCanaryAdapter() {
            this.loc = new Location(CANARY_PROVIDER);
            // Under android.jar pure-JVM default-value stubs, Location(provider) does not store
            // the provider string, so getProvider() returns null.
            this.functional = CANARY_PROVIDER.equals(loc.getProvider());
        }

        @Override public boolean isFunctionalRuntime() { return functional; }
        @Override public void setLatitude(double lat) { loc.setLatitude(lat); }
        @Override public double getLatitude() { return loc.getLatitude(); }
        @Override public void setLongitude(double lon) { loc.setLongitude(lon); }
        @Override public double getLongitude() { return loc.getLongitude(); }
        @Override public void setAltitude(double alt) { loc.setAltitude(alt); }
        @Override public double getAltitude() { return loc.getAltitude(); }
        @Override public boolean hasAltitude() { return loc.hasAltitude(); }
        @Override public void setAccuracy(float acc) { loc.setAccuracy(acc); }
        @Override public float getAccuracy() { return loc.getAccuracy(); }
        @Override public boolean hasAccuracy() { return loc.hasAccuracy(); }
        @Override public void setTime(long timeMs) { loc.setTime(timeMs); }
        @Override public long getTime() { return loc.getTime(); }
        @Override public void reset() { loc.reset(); }
        @Override public boolean supportsSetMock() {
            return Build.VERSION.SDK_INT >= Build.VERSION_CODES.S;
        }

        @Override
        public void setMock(boolean mock) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                loc.setMock(mock);
            }
        }

        @Override
        public boolean isMock() {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                return loc.isMock();
            }
            @SuppressWarnings("deprecation")
            boolean legacyMock = loc.isFromMockProvider();
            return legacyMock;
        }
    }

    private static final class AndroidLocationEnvironment implements LocationEnvironment {
        private final Context context;

        AndroidLocationEnvironment(Context context) {
            this.context = context;
        }

        @Override
        public LocationCanaryAdapter createCanaryAdapter() {
            try {
                return new AndroidLocationCanaryAdapter();
            } catch (Exception | LinkageError e) {
                return null;
            }
        }

        @SuppressLint("MissingPermission")
        @Override
        public List<String> findMockCachedLocationProviders() {
            if (context == null) {
                return null;
            }
            try {
                boolean hasFine = context.checkSelfPermission(
                        Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
                boolean hasCoarse = context.checkSelfPermission(
                        Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;
                if (!hasFine && !hasCoarse) {
                    return null;
                }
                LocationManager lm = (LocationManager) context.getSystemService(
                        Context.LOCATION_SERVICE);
                if (lm == null) {
                    return null;
                }
                List<String> providers = lm.getProviders(true);
                if (providers == null || providers.isEmpty()) {
                    return Collections.emptyList();
                }
                List<String> mockProviders = new ArrayList<>();
                for (String provider : providers) {
                    if (provider == null || provider.isBlank()) continue;
                    try {
                        Location last = lm.getLastKnownLocation(provider);
                        if (last == null) continue;
                        boolean isMock;
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                            isMock = last.isMock();
                        } else {
                            @SuppressWarnings("deprecation")
                            boolean legacy = last.isFromMockProvider();
                            isMock = legacy;
                        }
                        if (isMock) {
                            // Never read or record latitude/longitude/altitude PII.
                            mockProviders.add(provider);
                        }
                    } catch (SecurityException ignored) {
                        // Individual provider denied; skip cleanly.
                    }
                }
                return mockProviders;
            } catch (SecurityException | LinkageError e) {
                return null;
            } catch (Exception e) {
                return null;
            }
        }

        @Override
        public Boolean isMockLocationAppOpAllowed() {
            if (context == null) {
                return null;
            }
            try {
                AppOpsManager appOps = (AppOpsManager) context.getSystemService(
                        Context.APP_OPS_SERVICE);
                String pkg = context.getPackageName();
                if (appOps == null || pkg == null || pkg.isBlank()) {
                    return null;
                }
                int mode = appOps.unsafeCheckOpNoThrow(
                        AppOpsManager.OPSTR_MOCK_LOCATION, Process.myUid(), pkg);
                return mode == AppOpsManager.MODE_ALLOWED;
            } catch (SecurityException | LinkageError e) {
                return null;
            } catch (Exception e) {
                return null;
            }
        }
    }
}
