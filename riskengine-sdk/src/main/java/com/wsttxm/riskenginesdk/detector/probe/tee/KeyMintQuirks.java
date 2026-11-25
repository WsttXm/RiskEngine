package com.wsttxm.riskenginesdk.detector.probe.tee;

import android.os.Build;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * OEM KeyMint / Keystore2 hardware quirks and AOSP KeyMint VTS vendor-API-level resolution.
 *
 * <p>Models documented vendor deviations so stock OEM devices never trigger false positives:
 * <ul>
 *   <li>Samsung devices and Xiaomi-family (Xiaomi/Redmi/POCO) MediaTek ({@code mt*}) devices
 *       legitimately accept {@code IKeyMintOperation.updateAad()} on non-AEAD signing operations,
 *       whereas AOSP's reference KeyMint TA rejects it.</li>
 *   <li>AOSP KeyMint VTS {@code get_vendor_api_level()} resolution order:
 *       {@code ro.vendor.api_level} &rarr; {@code min(productApi, boardApi)} using
 *       {@code ro.board.api_level}/{@code ro.board.first_api_level} and
 *       {@code ro.product.first_api_level}/{@code ro.build.version.sdk}.</li>
 * </ul></p>
 */
public final class KeyMintQuirks {

    public static final int STRICT_KEYMINT_VENDOR_API_THRESHOLD = 202504;

    private static final String SAMSUNG = "samsung";
    private static final String MEDIATEK_PREFIX = "mt";
    private static final Set<String> XIAOMI_BRANDS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("xiaomi", "redmi", "poco")));

    /** Injectable system property reader for deterministic pure-JVM unit testing. */
    public interface PropertyReader {
        String getProperty(String key);
    }

    /** Immutable snapshot of build fields identifying a vendor KeyMint implementation. */
    public static final class VendorIdentity {
        private final String manufacturer;
        private final String brand;
        private final String hardware;
        private final String roHardware;

        public VendorIdentity(
                String manufacturer,
                String brand,
                String hardware,
                String roHardware) {
            this.manufacturer = normalize(manufacturer);
            this.brand = normalize(brand);
            this.hardware = normalize(hardware);
            this.roHardware = normalize(roHardware);
        }

        public String getManufacturer() {
            return manufacturer;
        }

        public String getBrand() {
            return brand;
        }

        public String getHardware() {
            return hardware;
        }

        public String getRoHardware() {
            return roHardware;
        }

        public static VendorIdentity current() {
            return from(DEFAULT_PROPERTY_READER);
        }

        public static VendorIdentity from(PropertyReader reader) {
            PropertyReader effective = reader == null ? DEFAULT_PROPERTY_READER : reader;
            String manufacturer = safeBuildString(Build.MANUFACTURER);
            if (manufacturer.isEmpty()) {
                manufacturer = normalize(safeReadProperty(effective, "ro.product.manufacturer"));
            }
            String brand = safeBuildString(Build.BRAND);
            if (brand.isEmpty()) {
                brand = normalize(safeReadProperty(effective, "ro.product.brand"));
            }
            String hardware = safeBuildString(Build.HARDWARE);
            String roHw = safeReadProperty(effective, "ro.hardware");
            return new VendorIdentity(manufacturer, brand, hardware, roHw);
        }

        private static String normalize(String value) {
            return value == null ? "" : value.trim();
        }

        private static String safeBuildString(String raw) {
            return raw == null ? "" : raw.trim();
        }
    }

    /** Result of AOSP KeyMint VTS vendor API level resolution. */
    public static final class VendorApiLevelResult {
        private final Integer level;
        private final String detail;

        public VendorApiLevelResult(Integer level, String detail) {
            this.level = level;
            this.detail = detail == null ? "" : detail;
        }

        public Integer getLevel() {
            return level;
        }

        public String getDetail() {
            return detail;
        }

        public boolean isAvailable() {
            return level != null;
        }

        public static VendorApiLevelResult unused() {
            return new VendorApiLevelResult(null, "vendor_api_not_required");
        }
    }

    public static final PropertyReader DEFAULT_PROPERTY_READER = new PropertyReader() {
        @Override
        public String getProperty(String key) {
            if (key == null || key.isEmpty()) {
                return null;
            }
            try {
                Class<?> sp = Class.forName("android.os.SystemProperties");
                Method get = sp.getMethod("get", String.class, String.class);
                Object val = get.invoke(null, key, "");
                if (val instanceof String) {
                    String s = ((String) val).trim();
                    return s.isEmpty() ? null : s;
                }
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                // Fall back cleanly to null
            }
            return null;
        }
    };

    private KeyMintQuirks() {
    }

    /**
     * Returns {@code true} if the given vendor's KeyMint TA is known to accept
     * {@code updateAad()} on non-AEAD operations (Samsung devices and Xiaomi/Redmi/POCO
     * MediaTek devices).
     */
    public static boolean isUpdateAadAcceptanceExpected(VendorIdentity identity) {
        if (identity == null) {
            return false;
        }
        String manufacturer = identity.getManufacturer().toLowerCase(Locale.ROOT);
        String brand = identity.getBrand().toLowerCase(Locale.ROOT);
        if (SAMSUNG.equals(manufacturer) || SAMSUNG.equals(brand)) {
            return true;
        }
        if (!XIAOMI_BRANDS.contains(manufacturer) && !XIAOMI_BRANDS.contains(brand)) {
            return false;
        }
        String roHw = identity.getRoHardware().toLowerCase(Locale.ROOT);
        String hw = identity.getHardware().toLowerCase(Locale.ROOT);
        return roHw.startsWith(MEDIATEK_PREFIX) || hw.startsWith(MEDIATEK_PREFIX);
    }

    /**
     * Resolves the KeyMint VTS vendor API level following
     * {@code KeyMintAidlTestBase::get_vendor_api_level()}.
     */
    public static VendorApiLevelResult resolveVendorApiLevel(PropertyReader reader) {
        PropertyReader effective = reader == null ? DEFAULT_PROPERTY_READER : reader;
        Integer vendorApi = parseNonNegativeInt(safeReadProperty(effective, "ro.vendor.api_level"));
        if (vendorApi != null) {
            return new VendorApiLevelResult(vendorApi, "source=ro.vendor.api_level");
        }

        Integer boardApi = parseNonNegativeInt(safeReadProperty(effective, "ro.board.api_level"));
        if (boardApi == null) {
            boardApi = parseNonNegativeInt(safeReadProperty(effective, "ro.board.first_api_level"));
        }

        Integer productApi = parseNonNegativeInt(
                safeReadProperty(effective, "ro.product.first_api_level"));
        if (productApi == null) {
            productApi = parseNonNegativeInt(safeReadProperty(effective, "ro.build.version.sdk"));
        }
        if (productApi == null) {
            return new VendorApiLevelResult(
                    null, "missing_ro.product.first_api_level_and_ro.build.version.sdk");
        }

        if (boardApi == null) {
            return new VendorApiLevelResult(productApi, "source=productApi,boardApi=absent");
        }
        int resolved = Math.min(productApi, boardApi);
        return new VendorApiLevelResult(
                resolved, "source=min(productApi=" + productApi + ",boardApi=" + boardApi + ")");
    }

    private static String safeReadProperty(PropertyReader reader, String key) {
        try {
            return reader.getProperty(key);
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            return null;
        }
    }

    private static Integer parseNonNegativeInt(String raw) {
        if (raw == null) {
            return null;
        }
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        try {
            int parsed = Integer.parseInt(trimmed);
            return parsed >= 0 ? parsed : null;
        } catch (NumberFormatException ignored) {
            return null;
        }
    }
}
