package com.wsttxm.riskenginesdk.detector.probe.tee;

import android.os.Build;
import android.os.IBinder;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.wsttxm.riskenginesdk.attestation.AttestationCapability;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.process.Keystore2ParcelClient;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

/**
 * VINTF KeyMint/Keymaster HAL version parity &amp; Keystore2 {@code OperationErrorPath} probe.
 *
 * <p>Combines two hardware/daemon consistency checks:
 * <ol>
 *   <li><b>VINTF Manifest Parity</b>: parses {@code /{vendor,odm,system,system_ext,product}/etc/vintf/manifest*}
 *       for declared {@code android.hardware.security.keymint} (AIDL) and
 *       {@code android.hardware.keymaster} (HIDL) HAL versions and verifies them against the
 *       runtime attested {@code keymasterVersion}, {@code attestationVersion}, and security tier
 *       following AOSP KeyMint VTS {@code check_attestation_version()} rules.</li>
 *   <li><b>Keystore2 {@code OperationErrorPath}</b>: verifies daemon-enforced rejection of
 *       {@code >0x8000}-byte {@code update()} payloads ({@code MAX_RECEIVE_DATA}), post-{@code abort()}
 *       handle invalidation ({@code INVALID_OPERATION_HANDLE = -28}), and non-AEAD
 *       {@code updateAad()} behavior honoring {@link KeyMintQuirks} Samsung &amp; Xiaomi MediaTek
 *       exemptions.</li>
 * </ol></p>
 */
public final class VintfHalAndErrorPathProbe {

    public static final String FAMILY_TEE_TAMPER = TeeNativeProbe.FAMILY_TEE_TAMPER;

    public static final String CODE_VINTF_HAL_MISMATCH = "tee_vintf_hal_mismatch";
    public static final String CODE_ERROR_PATH_DIVERGED = "tee_keystore2_error_path_diverged";
    public static final String CODE_UPDATE_AAD_ACCEPTED = "tee_keymint_update_aad_accepted";

    public static final int OVERSIZED_UPDATE_BYTES = 0x8001;
    public static final int ERROR_INVALID_OPERATION_HANDLE = -28;

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String CLASS_SERVICE_SPECIFIC_EXCEPTION =
            "android.os.ServiceSpecificException";

    private static final String KEYMINT_HAL_NAME = "android.hardware.security.keymint";
    private static final String KEYMASTER_HAL_NAME = "android.hardware.keymaster";
    private static final String KEYMINT_INTERFACE_NAME = "IKeyMintDevice";
    private static final String KEYMASTER_INTERFACE_NAME = "IKeymasterDevice";
    private static final String INSTANCE_DEFAULT = "default";
    private static final String INSTANCE_STRONGBOX = "strongbox";

    private static final int MAX_MANIFEST_BYTES = 512 * 1024;

    private static final List<String> DEFAULT_MANIFEST_DIRS = Collections.unmodifiableList(
            Arrays.asList(
                    "/vendor/etc/vintf/manifest",
                    "/odm/etc/vintf/manifest",
                    "/system/etc/vintf/manifest",
                    "/system_ext/etc/vintf/manifest",
                    "/product/etc/vintf/manifest"));

    private static final List<String> DEFAULT_MANIFEST_FILES = Collections.unmodifiableList(
            Arrays.asList(
                    "/vendor/etc/vintf/manifest.xml",
                    "/odm/etc/vintf/manifest.xml",
                    "/system/etc/vintf/manifest.xml",
                    "/system_ext/etc/vintf/manifest.xml",
                    "/product/etc/vintf/manifest.xml"));

    private static final Pattern HIDL_FQNAME_PATTERN =
            Pattern.compile("^@([0-9]+(?:\\.[0-9]+)?)::([^/]+)/(.+)$");
    private static final Pattern HIDL_RANGE_PATTERN =
            Pattern.compile("^([0-9]+)\\.([0-9]+)-([0-9]+)$");

    public enum HalFamily {
        KEYMINT_AIDL,
        KEYMASTER_HIDL
    }

    public enum VintfAnomalyKind {
        NONE,
        UNREADABLE,
        NO_DECLARATION,
        NO_ATTESTED_VERSION,
        MISMATCH
    }

    /** Single parsed VINTF KeyMint or Keymaster HAL declaration. */
    public static final class VintfHalDeclaration {
        private final HalFamily family;
        private final String sourcePath;
        private final String halName;
        private final String interfaceName;
        private final String instance;
        private final String vintfVersion;
        private final int expectedKeymasterVersion;
        private final int expectedAttestationVersion;

        public VintfHalDeclaration(
                HalFamily family,
                String sourcePath,
                String halName,
                String interfaceName,
                String instance,
                String vintfVersion,
                int expectedKeymasterVersion,
                int expectedAttestationVersion) {
            this.family = family;
            this.sourcePath = sourcePath == null ? "" : sourcePath;
            this.halName = halName == null ? "" : halName;
            this.interfaceName = interfaceName == null ? "" : interfaceName;
            this.instance = instance == null ? "" : instance;
            this.vintfVersion = vintfVersion == null ? "" : vintfVersion;
            this.expectedKeymasterVersion = expectedKeymasterVersion;
            this.expectedAttestationVersion = expectedAttestationVersion;
        }

        public HalFamily getFamily() {
            return family;
        }

        public String getSourcePath() {
            return sourcePath;
        }

        public String getHalName() {
            return halName;
        }

        public String getInterfaceName() {
            return interfaceName;
        }

        public String getInstance() {
            return instance;
        }

        public String getVintfVersion() {
            return vintfVersion;
        }

        public int getExpectedKeymasterVersion() {
            return expectedKeymasterVersion;
        }

        public int getExpectedAttestationVersion() {
            return expectedAttestationVersion;
        }

        public String getSummary() {
            return halName + "/" + interfaceName + "/" + instance + "@" + vintfVersion
                    + "->km=" + expectedKeymasterVersion + ",att=" + expectedAttestationVersion;
        }

        public boolean matches(
                Integer keymasterVersion, Integer attestationVersion, Integer vendorApiLevel) {
            if (family == HalFamily.KEYMINT_AIDL) {
                if (vendorApiLevel == null || keymasterVersion == null || attestationVersion == null) {
                    return false;
                }
                if (vendorApiLevel > KeyMintQuirks.STRICT_KEYMINT_VENDOR_API_THRESHOLD) {
                    return keymasterVersion == expectedKeymasterVersion
                            && attestationVersion == expectedKeymasterVersion;
                }
                return isValidRelaxedKeyMintVersion(keymasterVersion, expectedKeymasterVersion)
                        && isValidRelaxedKeyMintVersion(attestationVersion, expectedKeymasterVersion);
            }
            boolean kmMatch = keymasterVersion == null
                    || keymasterVersion == expectedKeymasterVersion;
            boolean attMatch = attestationVersion == null
                    || attestationVersion == expectedAttestationVersion;
            return kmMatch && attMatch;
        }

        private static boolean isValidRelaxedKeyMintVersion(int actual, int expectedMax) {
            return actual >= 100 && (actual % 100 == 0) && actual <= expectedMax;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof VintfHalDeclaration)) {
                return false;
            }
            VintfHalDeclaration that = (VintfHalDeclaration) o;
            return expectedKeymasterVersion == that.expectedKeymasterVersion
                    && expectedAttestationVersion == that.expectedAttestationVersion
                    && family == that.family
                    && Objects.equals(halName, that.halName)
                    && Objects.equals(interfaceName, that.interfaceName)
                    && Objects.equals(instance, that.instance)
                    && Objects.equals(vintfVersion, that.vintfVersion);
        }

        @Override
        public int hashCode() {
            return Objects.hash(
                    family,
                    halName,
                    interfaceName,
                    instance,
                    vintfVersion,
                    expectedKeymasterVersion,
                    expectedAttestationVersion);
        }
    }

    /** Manifest entry supplied by {@link VintfManifestSource}. */
    public static final class ManifestEntry {
        private final String path;
        private final String xmlContent;
        private final String readError;

        private ManifestEntry(String path, String xmlContent, String readError) {
            this.path = path == null ? "" : path;
            this.xmlContent = xmlContent;
            this.readError = readError;
        }

        public static ManifestEntry readable(String path, String xmlContent) {
            return new ManifestEntry(path, xmlContent == null ? "" : xmlContent, null);
        }

        public static ManifestEntry unreadable(String path, String error) {
            return new ManifestEntry(path, null, error == null ? "unreadable" : error);
        }

        public String getPath() {
            return path;
        }

        public String getXmlContent() {
            return xmlContent;
        }

        public String getReadError() {
            return readError;
        }

        public boolean isReadable() {
            return readError == null && xmlContent != null;
        }
    }

    /** Injectable source of VINTF XML files for deterministic pure-JVM unit testing. */
    public interface VintfManifestSource {
        List<ManifestEntry> loadManifestEntries();
    }

    /** Evaluated result of VINTF KeyMint/Keymaster HAL version inspection. */
    public static final class VintfVersionResult {
        private final boolean readable;
        private final VintfAnomalyKind anomalyKind;
        private final List<VintfHalDeclaration> declarations;
        private final List<VintfHalDeclaration> comparedDeclarations;
        private final List<String> unreadablePaths;
        private final Integer vendorApiLevel;
        private final String detail;

        VintfVersionResult(
                boolean readable,
                VintfAnomalyKind anomalyKind,
                List<VintfHalDeclaration> declarations,
                List<VintfHalDeclaration> comparedDeclarations,
                List<String> unreadablePaths,
                Integer vendorApiLevel,
                String detail) {
            this.readable = readable;
            this.anomalyKind = anomalyKind == null ? VintfAnomalyKind.UNREADABLE : anomalyKind;
            this.declarations = declarations == null
                    ? Collections.<VintfHalDeclaration>emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(declarations));
            this.comparedDeclarations = comparedDeclarations == null
                    ? Collections.<VintfHalDeclaration>emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(comparedDeclarations));
            this.unreadablePaths = unreadablePaths == null
                    ? Collections.<String>emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(unreadablePaths));
            this.vendorApiLevel = vendorApiLevel;
            this.detail = detail == null ? "" : detail;
        }

        public boolean isReadable() {
            return readable;
        }

        public VintfAnomalyKind getAnomalyKind() {
            return anomalyKind;
        }

        public List<VintfHalDeclaration> getDeclarations() {
            return declarations;
        }

        public List<VintfHalDeclaration> getComparedDeclarations() {
            return comparedDeclarations;
        }

        public List<String> getUnreadablePaths() {
            return unreadablePaths;
        }

        public Integer getVendorApiLevel() {
            return vendorApiLevel;
        }

        public String getDetail() {
            return detail;
        }
    }

    /** Evaluated result of Keystore2 {@code OperationErrorPath} constraints. */
    public static final class OperationErrorPathResult {
        private final boolean executed;
        private final Boolean updateAadRejected;
        private final boolean updateAadAcceptanceExpected;
        private final Boolean oversizedUpdateRejected;
        private final Boolean abortInvalidatedHandle;
        private final boolean fallbackCompatParamsUsed;
        private final String detail;

        public OperationErrorPathResult(
                boolean executed,
                Boolean updateAadRejected,
                boolean updateAadAcceptanceExpected,
                Boolean oversizedUpdateRejected,
                Boolean abortInvalidatedHandle,
                boolean fallbackCompatParamsUsed,
                String detail) {
            this.executed = executed;
            this.updateAadRejected = updateAadRejected;
            this.updateAadAcceptanceExpected = updateAadAcceptanceExpected;
            this.oversizedUpdateRejected = oversizedUpdateRejected;
            this.abortInvalidatedHandle = abortInvalidatedHandle;
            this.fallbackCompatParamsUsed = fallbackCompatParamsUsed;
            this.detail = detail == null ? "" : detail;
        }

        public static OperationErrorPathResult notCompleted(String reason) {
            return new OperationErrorPathResult(false, null, false, null, null, false, reason);
        }

        public boolean isExecuted() {
            return executed;
        }

        public Boolean getUpdateAadRejected() {
            return updateAadRejected;
        }

        public boolean isUpdateAadAcceptanceExpected() {
            return updateAadAcceptanceExpected;
        }

        public Boolean getOversizedUpdateRejected() {
            return oversizedUpdateRejected;
        }

        public Boolean getAbortInvalidatedHandle() {
            return abortInvalidatedHandle;
        }

        public boolean isFallbackCompatParamsUsed() {
            return fallbackCompatParamsUsed;
        }

        public String getDetail() {
            return detail;
        }

        public boolean isKeystore2SemanticsDiverged() {
            return Boolean.FALSE.equals(oversizedUpdateRejected)
                    || Boolean.FALSE.equals(abortInvalidatedHandle);
        }

        public boolean isUpdateAadUnexpectedlyAccepted() {
            return Boolean.FALSE.equals(updateAadRejected) && !updateAadAcceptanceExpected;
        }

        public boolean hasCompletedSubCheck() {
            return updateAadRejected != null
                    || oversizedUpdateRejected != null
                    || abortInvalidatedHandle != null;
        }
    }

    /** Injectable seam for {@code OperationErrorPath} execution in pure-JVM unit tests. */
    public interface OperationErrorPathAdapter {
        int getSdkInt();

        KeyMintQuirks.VendorIdentity getVendorIdentity();

        OperationErrorPathResult executeErrorPathProbe(String alias) throws Exception;

        void deleteAlias(String alias);
    }

    /** Combined probe result consumed by {@code TeeIntegrityDetector}. */
    public static final class ProbeResult {
        private final boolean usable;
        private final String failureReason;
        private final Set<String> strongTokens;
        private final Set<String> mediumTokens;
        private final List<EvidenceItem> evidenceItems;
        private final VintfVersionResult vintfResult;
        private final OperationErrorPathResult errorPathResult;

        ProbeResult(
                boolean usable,
                String failureReason,
                Set<String> strongTokens,
                Set<String> mediumTokens,
                List<EvidenceItem> evidenceItems,
                VintfVersionResult vintfResult,
                OperationErrorPathResult errorPathResult) {
            this.usable = usable;
            this.failureReason = failureReason;
            this.strongTokens = Collections.unmodifiableSet(strongTokens);
            this.mediumTokens = Collections.unmodifiableSet(mediumTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
            this.vintfResult = vintfResult;
            this.errorPathResult = errorPathResult;
        }

        public boolean isUsable() {
            return usable;
        }

        public String getFailureReason() {
            return failureReason;
        }

        public Set<String> getStrongTokens() {
            return strongTokens;
        }

        public Set<String> getMediumTokens() {
            return mediumTokens;
        }

        public List<EvidenceItem> getEvidenceItems() {
            return evidenceItems;
        }

        public VintfVersionResult getVintfResult() {
            return vintfResult;
        }

        public OperationErrorPathResult getErrorPathResult() {
            return errorPathResult;
        }

        public boolean hasFindings() {
            return !strongTokens.isEmpty() || !mediumTokens.isEmpty() || !evidenceItems.isEmpty();
        }
    }

    private VintfHalAndErrorPathProbe() {
    }

    public static ProbeResult run(AttestationCapability.AttestationSnapshot attestationSnapshot) {
        AttestationRecord record = attestationSnapshot != null && attestationSnapshot.isAvailable()
                ? attestationSnapshot.getRecord()
                : null;
        return run(
                record,
                new FileSystemManifestSource(DEFAULT_MANIFEST_DIRS, DEFAULT_MANIFEST_FILES),
                KeyMintQuirks.DEFAULT_PROPERTY_READER,
                new AndroidOperationErrorPathAdapter());
    }

    public static ProbeResult run(
            AttestationRecord record,
            VintfManifestSource manifestSource,
            KeyMintQuirks.PropertyReader propertyReader,
            OperationErrorPathAdapter errorPathAdapter) {
        Set<String> strong = new LinkedHashSet<>();
        Set<String> medium = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();
        boolean anyUsable = false;
        String lastFailure = null;

        // 1. VINTF KeyMint / Keymaster HAL parity check
        VintfVersionResult vintfResult =
                inspectVintfHalVersion(record, manifestSource, propertyReader);
        if (vintfResult.getAnomalyKind() == VintfAnomalyKind.NONE
                || vintfResult.getAnomalyKind() == VintfAnomalyKind.MISMATCH) {
            anyUsable = true;
            if (vintfResult.getAnomalyKind() == VintfAnomalyKind.MISMATCH) {
                strong.add(CODE_VINTF_HAL_MISMATCH);
                items.add(new EvidenceItem(
                        CODE_VINTF_HAL_MISMATCH,
                        EvidenceItem.SourceLayer.HARDWARE,
                        EnumSet.of(EvidenceItem.SourceLayer.HARDWARE, EvidenceItem.SourceLayer.JAVA),
                        "vintf:KeyMint_vs_Attestation",
                        vintfResult.getDetail(),
                        FAMILY_TEE_TAMPER,
                        EvidenceItem.Rank.STRONG));
            }
        } else {
            lastFailure = vintfResult.getDetail();
        }

        // 2. Keystore2 OperationErrorPath check (API 31+)
        OperationErrorPathResult errResult = null;
        if (errorPathAdapter != null && errorPathAdapter.getSdkInt() >= 31) {
            String alias = "riskengine_op_err_"
                    + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
            try {
                OperationErrorPathResult raw = errorPathAdapter.executeErrorPathProbe(alias);
                if (raw != null) {
                    boolean expectedQuirk = KeyMintQuirks.isUpdateAadAcceptanceExpected(
                            errorPathAdapter.getVendorIdentity());
                    errResult = new OperationErrorPathResult(
                            raw.isExecuted(),
                            raw.getUpdateAadRejected(),
                            expectedQuirk || raw.isUpdateAadAcceptanceExpected(),
                            raw.getOversizedUpdateRejected(),
                            raw.getAbortInvalidatedHandle(),
                            raw.isFallbackCompatParamsUsed(),
                            raw.getDetail());
                    if (errResult.isExecuted() && errResult.hasCompletedSubCheck()) {
                        anyUsable = true;
                        if (errResult.isKeystore2SemanticsDiverged()) {
                            List<String> reasons = new ArrayList<>();
                            if (Boolean.FALSE.equals(errResult.getOversizedUpdateRejected())) {
                                reasons.add("oversized_0x8001_accepted");
                            }
                            if (Boolean.FALSE.equals(errResult.getAbortInvalidatedHandle())) {
                                reasons.add("post_abort_update_accepted");
                            }
                            strong.add(CODE_ERROR_PATH_DIVERGED);
                            items.add(new EvidenceItem(
                                    CODE_ERROR_PATH_DIVERGED,
                                    EvidenceItem.SourceLayer.HARDWARE,
                                    EnumSet.of(
                                            EvidenceItem.SourceLayer.HARDWARE,
                                            EvidenceItem.SourceLayer.JAVA),
                                    "keystore2:IKeystoreOperation",
                                    join(reasons, ";"),
                                    FAMILY_TEE_TAMPER,
                                    EvidenceItem.Rank.STRONG));
                        }
                        // Note: IKeyMintOperation.aidl defines no mandatory error for updateAad() on
                        // non-AEAD operations, and stock Google Pixel (Trusty KeyMint v2), Samsung,
                        // and Xiaomi MTK TAs accept it; record only on OperationErrorPathResult
                        // diagnostics without escalating standalone acceptance to actionable MEDIUM.
                    } else if (lastFailure == null) {
                        lastFailure = errResult.getDetail();
                    }
                }
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                if (lastFailure == null) {
                    lastFailure = "operation_error_path_err:" + e.getClass().getSimpleName();
                }
            } finally {
                try {
                    errorPathAdapter.deleteAlias(alias);
                } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                    // Best-effort cleanup
                }
            }
        }

        return new ProbeResult(
                anyUsable,
                anyUsable ? null : (lastFailure == null ? "vintf_error_path_unavailable" : lastFailure),
                strong,
                medium,
                items,
                vintfResult,
                errResult);
    }

    /** Evaluates VINTF KeyMint/Keymaster declarations against an {@link AttestationRecord}. */
    public static VintfVersionResult inspectVintfHalVersion(
            AttestationRecord record,
            VintfManifestSource manifestSource,
            KeyMintQuirks.PropertyReader propertyReader) {
        List<VintfHalDeclaration> allDeclarations = new ArrayList<>();
        List<String> unreadablePaths = new ArrayList<>();

        if (manifestSource != null) {
            List<ManifestEntry> entries;
            try {
                entries = manifestSource.loadManifestEntries();
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                entries = Collections.singletonList(
                        ManifestEntry.unreadable("vintf_source", e.getClass().getSimpleName()));
            }
            if (entries != null) {
                for (ManifestEntry entry : entries) {
                    if (entry == null) {
                        continue;
                    }
                    if (!entry.isReadable()) {
                        if (isPotentialKeyMintManifestPath(entry.getPath(), true)) {
                            unreadablePaths.add(entry.getPath() + ":" + entry.getReadError());
                        }
                        continue;
                    }
                    String xml = entry.getXmlContent();
                    if (!isPotentialKeyMintManifest(entry.getPath(), xml)) {
                        continue;
                    }
                    try {
                        allDeclarations.addAll(parseVintfManifestXml(entry.getPath(), xml));
                    } catch (Exception | LinkageError | OutOfMemoryError e) {
                        unreadablePaths.add(entry.getPath() + ":" + e.getClass().getSimpleName());
                    }
                }
            }
        }

        List<VintfHalDeclaration> deduped = new ArrayList<>(new LinkedHashSet<>(allDeclarations));
        List<String> dedupedUnreadable = new ArrayList<>(new LinkedHashSet<>(unreadablePaths));

        if (record == null || !record.isValid()) {
            VintfAnomalyKind kind = dedupedUnreadable.isEmpty()
                    ? VintfAnomalyKind.NO_ATTESTED_VERSION
                    : VintfAnomalyKind.UNREADABLE;
            return new VintfVersionResult(
                    dedupedUnreadable.isEmpty(),
                    kind,
                    deduped,
                    Collections.<VintfHalDeclaration>emptyList(),
                    dedupedUnreadable,
                    null,
                    "no_attested_record");
        }

        int kmVer = record.getKeymasterVersion();
        int attVer = record.getAttestationVersion();
        Integer actualKm = kmVer >= 0 ? kmVer : null;
        Integer actualAtt = attVer >= 0 ? attVer : null;

        AttestationRecord.SecurityLevel attTier = record.getAttestationSecurityLevel();
        AttestationRecord.SecurityLevel kmTier = record.getKeymasterSecurityLevel();

        boolean tierMismatch = attTier != AttestationRecord.SecurityLevel.UNKNOWN
                && kmTier != AttestationRecord.SecurityLevel.UNKNOWN
                && attTier != kmTier;
        boolean versionFamilyMismatch = actualKm != null
                && actualAtt != null
                && ((actualKm >= 100) != (actualAtt >= 100));
        boolean invalidKeyMintMultiple = actualKm != null
                && actualAtt != null
                && actualKm >= 100
                && actualAtt >= 100
                && ((actualKm % 100 != 0) || (actualAtt % 100 != 0));

        AttestationRecord.SecurityLevel selectedTier =
                kmTier != AttestationRecord.SecurityLevel.UNKNOWN ? kmTier : attTier;

        // SoftwareKeyMintDevice lives in /system rather than /vendor VINTF; never compare
        // SOFTWARE/UNKNOWN tiers against hardware /vendor IKeyMintDevice declarations.
        if (!tierMismatch && !versionFamilyMismatch && !invalidKeyMintMultiple
                && !selectedTier.isHardwareBacked()) {
            VintfAnomalyKind nonHwKind = dedupedUnreadable.isEmpty()
                    ? VintfAnomalyKind.NO_ATTESTED_VERSION
                    : VintfAnomalyKind.UNREADABLE;
            return new VintfVersionResult(
                    dedupedUnreadable.isEmpty(),
                    nonHwKind,
                    deduped,
                    Collections.<VintfHalDeclaration>emptyList(),
                    dedupedUnreadable,
                    null,
                    "non_hardware_attestation_tier:" + selectedTier.name());
        }

        boolean keyMintAttestation = Math.max(actualKm == null ? 0 : actualKm,
                actualAtt == null ? 0 : actualAtt) >= 100;
        String expectedInstance = selectedTier == AttestationRecord.SecurityLevel.STRONGBOX
                ? INSTANCE_STRONGBOX
                : INSTANCE_DEFAULT;

        List<VintfHalDeclaration> compared = new ArrayList<>();
        if (!tierMismatch) {
            HalFamily targetFamily = keyMintAttestation
                    ? HalFamily.KEYMINT_AIDL
                    : HalFamily.KEYMASTER_HIDL;
            for (VintfHalDeclaration decl : deduped) {
                if (decl.getFamily() == targetFamily
                        && expectedInstance.equals(decl.getInstance())) {
                    compared.add(decl);
                }
            }
        }

        boolean hasActualVersion = actualKm != null || actualAtt != null;
        boolean requiresVendorApi = hasActualVersion
                && (keyMintAttestation || containsKeyMintAidl(compared));
        KeyMintQuirks.VendorApiLevelResult vendorApi = requiresVendorApi
                ? KeyMintQuirks.resolveVendorApiLevel(propertyReader)
                : KeyMintQuirks.VendorApiLevelResult.unused();
        boolean vendorApiUnavailable = !compared.isEmpty()
                && containsKeyMintAidl(compared)
                && hasActualVersion
                && !vendorApi.isAvailable();

        // KeyMint VTS check_attestation_version() allows attestationVersion and keymasterVersion
        // to lag independently on vendor API <= 202504 (provided both are multiples of 100 and <= aidl*100);
        // strict equality between the two only applies when vendorApiLevel > 202504.
        boolean runtimeIdentityMismatch = invalidKeyMintMultiple
                || (actualKm != null
                        && actualAtt != null
                        && actualKm >= 100
                        && actualAtt >= 100
                        && vendorApi.isAvailable()
                        && vendorApi.getLevel() > KeyMintQuirks.STRICT_KEYMINT_VENDOR_API_THRESHOLD
                        && !actualKm.equals(actualAtt));

        boolean declarationMismatch = !vendorApiUnavailable
                && !compared.isEmpty()
                && hasActualVersion
                && !anyMatches(compared, actualKm, actualAtt, vendorApi.getLevel());

        VintfAnomalyKind kind;
        String detail;
        if (tierMismatch) {
            kind = VintfAnomalyKind.MISMATCH;
            detail = "tier_mismatch:att=" + attTier.name() + ",km=" + kmTier.name();
        } else if (versionFamilyMismatch) {
            kind = VintfAnomalyKind.MISMATCH;
            detail = "family_mismatch:att=" + actualAtt + ",km=" + actualKm;
        } else if (runtimeIdentityMismatch) {
            kind = VintfAnomalyKind.MISMATCH;
            detail = "keymint_identity_mismatch:att=" + actualAtt + ",km=" + actualKm;
        } else if (declarationMismatch) {
            kind = VintfAnomalyKind.MISMATCH;
            detail = "vintf_mismatch:att=" + actualAtt + ",km=" + actualKm
                    + ",vendorApi=" + vendorApi.getLevel()
                    + ",vintf=" + summarizeDeclarations(compared);
        } else if (!dedupedUnreadable.isEmpty() || vendorApiUnavailable) {
            kind = VintfAnomalyKind.UNREADABLE;
            detail = vendorApiUnavailable
                    ? "vendor_api_unavailable:" + vendorApi.getDetail()
                    : "unreadable_vintf:" + join(dedupedUnreadable, ",");
        } else if (compared.isEmpty()) {
            kind = VintfAnomalyKind.NO_DECLARATION;
            detail = "no_vintf_declaration_for_" + expectedInstance;
        } else if (!hasActualVersion) {
            kind = VintfAnomalyKind.NO_ATTESTED_VERSION;
            detail = "no_attested_version";
        } else {
            kind = VintfAnomalyKind.NONE;
            detail = "matched:" + summarizeDeclarations(compared);
        }

        return new VintfVersionResult(
                dedupedUnreadable.isEmpty() && !vendorApiUnavailable,
                kind,
                deduped,
                compared,
                dedupedUnreadable,
                vendorApi.getLevel(),
                detail);
    }

    /** Parses VINTF XML content into normalized KeyMint AIDL / Keymaster HIDL declarations. */
    public static List<VintfHalDeclaration> parseVintfManifestXml(String sourcePath, String xml)
            throws Exception {
        DocumentBuilder builder = createSecureDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xml)));
        Element root = doc.getDocumentElement();
        if (root == null) {
            return Collections.emptyList();
        }

        List<VintfHalDeclaration> out = new ArrayList<>();
        for (Element halEl : directChildElements(root, "hal")) {
            String halName = firstDirectChildText(halEl, "name");
            if (!KEYMINT_HAL_NAME.equals(halName) && !KEYMASTER_HAL_NAME.equals(halName)) {
                continue;
            }
            List<String> versions = directChildTexts(halEl, "version");
            List<String> fqnames = directChildTexts(halEl, "fqname");
            Map<String, Set<String>> interfaces = new LinkedHashMap<>();
            for (Element ifaceEl : directChildElements(halEl, "interface")) {
                String ifaceName = firstDirectChildText(ifaceEl, "name");
                if (!ifaceName.isEmpty()) {
                    Set<String> insts = interfaces.get(ifaceName);
                    if (insts == null) {
                        insts = new LinkedHashSet<>();
                        interfaces.put(ifaceName, insts);
                    }
                    insts.addAll(directChildTexts(ifaceEl, "instance"));
                }
            }
            if (KEYMINT_HAL_NAME.equals(halName)) {
                out.addAll(buildKeyMintDeclarations(sourcePath, versions, interfaces, fqnames));
            } else {
                out.addAll(buildKeymasterDeclarations(sourcePath, versions, interfaces, fqnames));
            }
        }
        return out;
    }

    private static List<VintfHalDeclaration> buildKeyMintDeclarations(
            String sourcePath,
            List<String> versions,
            Map<String, Set<String>> interfaces,
            List<String> fqnames) {
        Set<String> instances = new LinkedHashSet<>();
        Set<String> ifaceInst = interfaces.get(KEYMINT_INTERFACE_NAME);
        if (ifaceInst != null) {
            instances.addAll(ifaceInst);
        }
        for (String fq : fqnames) {
            int sep = fq.indexOf("::");
            String after = sep >= 0 ? fq.substring(sep + 2) : fq;
            int slash = after.indexOf('/');
            if (slash > 0) {
                String name = after.substring(0, slash);
                String inst = after.substring(slash + 1);
                if (KEYMINT_INTERFACE_NAME.equals(name) && !inst.isEmpty()) {
                    instances.add(inst);
                }
            }
        }

        List<String> filteredInstances = new ArrayList<>();
        for (String inst : instances) {
            if (INSTANCE_DEFAULT.equals(inst) || INSTANCE_STRONGBOX.equals(inst)) {
                filteredInstances.add(inst);
            }
        }
        if (filteredInstances.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> aidlVersions = versions.isEmpty()
                ? Collections.singletonList("1")
                : versions;
        List<VintfHalDeclaration> result = new ArrayList<>();
        for (String inst : filteredInstances) {
            for (String verStr : aidlVersions) {
                try {
                    int aidlVer = Integer.parseInt(verStr.trim());
                    if (aidlVer > 0) {
                        result.add(new VintfHalDeclaration(
                                HalFamily.KEYMINT_AIDL,
                                sourcePath,
                                KEYMINT_HAL_NAME,
                                KEYMINT_INTERFACE_NAME,
                                inst,
                                verStr.trim(),
                                aidlVer * 100,
                                aidlVer * 100));
                    }
                } catch (NumberFormatException ignored) {
                    // Ignore malformed version token
                }
            }
        }
        return result;
    }

    private static List<VintfHalDeclaration> buildKeymasterDeclarations(
            String sourcePath,
            List<String> versions,
            Map<String, Set<String>> interfaces,
            List<String> fqnames) {
        Set<VintfHalDeclaration> result = new LinkedHashSet<>();

        Set<String> ifaceInstances = interfaces.get(KEYMASTER_INTERFACE_NAME);
        if (ifaceInstances != null) {
            List<String> expandedVersions = new ArrayList<>();
            for (String v : versions) {
                expandedVersions.addAll(expandHidlVersions(v));
            }
            for (String inst : ifaceInstances) {
                if (!INSTANCE_DEFAULT.equals(inst) && !INSTANCE_STRONGBOX.equals(inst)) {
                    continue;
                }
                for (String ver : expandedVersions) {
                    int[] expected = expectedLegacyVersions(ver);
                    if (expected != null) {
                        result.add(new VintfHalDeclaration(
                                HalFamily.KEYMASTER_HIDL,
                                sourcePath,
                                KEYMASTER_HAL_NAME,
                                KEYMASTER_INTERFACE_NAME,
                                inst,
                                ver,
                                expected[0],
                                expected[1]));
                    }
                }
            }
        }

        // Preserve exact (version, instance) binding from <fqname>@4.0::IKeymasterDevice/default</fqname>
        for (String fq : fqnames) {
            Matcher m = HIDL_FQNAME_PATTERN.matcher(fq.trim());
            if (!m.matches()) {
                continue;
            }
            String ver = m.group(1);
            String iface = m.group(2);
            String inst = m.group(3);
            if (!KEYMASTER_INTERFACE_NAME.equals(iface)) {
                continue;
            }
            if (!INSTANCE_DEFAULT.equals(inst) && !INSTANCE_STRONGBOX.equals(inst)) {
                continue;
            }
            int[] expected = expectedLegacyVersions(ver);
            if (expected != null) {
                result.add(new VintfHalDeclaration(
                        HalFamily.KEYMASTER_HIDL,
                        sourcePath,
                        KEYMASTER_HAL_NAME,
                        KEYMASTER_INTERFACE_NAME,
                        inst,
                        ver,
                        expected[0],
                        expected[1]));
            }
        }
        return new ArrayList<>(result);
    }

    private static List<String> expandHidlVersions(String raw) {
        String trimmed = raw.trim();
        Matcher m = HIDL_RANGE_PATTERN.matcher(trimmed);
        if (!m.matches()) {
            return Collections.singletonList(trimmed);
        }
        String major = m.group(1);
        int firstMinor = Integer.parseInt(m.group(2));
        int lastMinor = Integer.parseInt(m.group(3));
        if (lastMinor < firstMinor || (lastMinor - firstMinor) > 16) {
            return Collections.singletonList(trimmed);
        }
        List<String> out = new ArrayList<>();
        for (int minor = firstMinor; minor <= lastMinor; minor++) {
            out.add(major + "." + minor);
        }
        return out;
    }

    private static int[] expectedLegacyVersions(String version) {
        if ("3.0".equals(version)) {
            return new int[]{3, 2};
        }
        if ("4.0".equals(version)) {
            return new int[]{4, 3};
        }
        if ("4.1".equals(version)) {
            return new int[]{41, 4};
        }
        return null;
    }

    private static DocumentBuilder createSecureDocumentBuilder() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setExpandEntityReferences(false);
        try {
            factory.setXIncludeAware(false);
        } catch (Exception | LinkageError ignored) {
        }
        trySetXmlFeature(factory, XMLConstants.FEATURE_SECURE_PROCESSING, true);
        trySetXmlFeature(factory, "http://apache.org/xml/features/disallow-doctype-decl", true);
        trySetXmlFeature(factory, "http://xml.org/sax/features/external-general-entities", false);
        trySetXmlFeature(factory, "http://xml.org/sax/features/external-parameter-entities", false);
        trySetXmlFeature(
                factory, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setEntityResolver(new EntityResolver() {
            @Override
            public InputSource resolveEntity(String publicId, String systemId) {
                return new InputSource(new StringReader(""));
            }
        });
        return builder;
    }

    private static void trySetXmlFeature(
            DocumentBuilderFactory factory, String feature, boolean value) {
        try {
            factory.setFeature(feature, value);
        } catch (Exception | LinkageError ignored) {
            // Android Expat DOM ignores unsupported desktop Xerces feature URIs
        }
    }

    private static List<Element> directChildElements(Element parent, String tagName) {
        List<Element> out = new ArrayList<>();
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child instanceof Element && tagName.equals(((Element) child).getTagName())) {
                out.add((Element) child);
            }
        }
        return out;
    }

    private static List<String> directChildTexts(Element parent, String tagName) {
        List<String> out = new ArrayList<>();
        for (Element el : directChildElements(parent, tagName)) {
            String txt = el.getTextContent();
            if (txt != null) {
                String trimmed = txt.trim();
                if (!trimmed.isEmpty()) {
                    out.add(trimmed);
                }
            }
        }
        return out;
    }

    private static String firstDirectChildText(Element parent, String tagName) {
        List<String> list = directChildTexts(parent, tagName);
        return list.isEmpty() ? "" : list.get(0);
    }

    private static boolean containsKeyMintAidl(List<VintfHalDeclaration> list) {
        for (VintfHalDeclaration d : list) {
            if (d.getFamily() == HalFamily.KEYMINT_AIDL) {
                return true;
            }
        }
        return false;
    }

    private static boolean anyMatches(
            List<VintfHalDeclaration> list,
            Integer kmVer,
            Integer attVer,
            Integer vendorApiLevel) {
        for (VintfHalDeclaration d : list) {
            if (d.matches(kmVer, attVer, vendorApiLevel)) {
                return true;
            }
        }
        return false;
    }

    private static String summarizeDeclarations(List<VintfHalDeclaration> list) {
        List<String> summaries = new ArrayList<>(list.size());
        for (VintfHalDeclaration d : list) {
            summaries.add(d.getSummary());
        }
        return join(summaries, "|");
    }

    private static boolean isPotentialKeyMintManifest(String path, String xml) {
        if (isPotentialKeyMintManifestPath(path, false)) {
            return true;
        }
        if (xml == null) {
            return false;
        }
        String lower = xml.toLowerCase(Locale.ROOT);
        return lower.contains("android.hardware.security.keymint")
                || lower.contains("android.hardware.keymaster")
                || lower.contains("ikeymintdevice")
                || lower.contains("ikeymasterdevice");
    }

    private static boolean isPotentialKeyMintManifestPath(
            String path, boolean includeAggregateManifest) {
        if (path == null) {
            return false;
        }
        String name = new File(path).getName().toLowerCase(Locale.ROOT);
        return name.contains("keymint")
                || name.contains("keymaster")
                || (includeAggregateManifest
                        && ("manifest.xml".equals(name) || "manifest".equals(name)));
    }

    private static String join(List<String> items, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(sep);
            }
            sb.append(items.get(i));
        }
        return sb.toString();
    }

    /** Default filesystem-backed VINTF manifest reader. */
    private static final class FileSystemManifestSource implements VintfManifestSource {
        private final List<String> dirs;
        private final List<String> files;

        FileSystemManifestSource(List<String> dirs, List<String> files) {
            this.dirs = dirs;
            this.files = files;
        }

        @Override
        public List<ManifestEntry> loadManifestEntries() {
            Map<String, File> discovered = new LinkedHashMap<>();
            List<ManifestEntry> entries = new ArrayList<>();

            for (String dirPath : dirs) {
                File dir = new File(dirPath);
                if (!dir.exists()) {
                    continue;
                }
                File[] listed = null;
                try {
                    listed = dir.listFiles();
                } catch (SecurityException e) {
                    entries.add(ManifestEntry.unreadable(dirPath, "SecurityException"));
                    continue;
                }
                if (listed == null) {
                    entries.add(ManifestEntry.unreadable(dirPath, "listFiles_null"));
                    continue;
                }
                Arrays.sort(listed);
                for (File f : listed) {
                    if (f.isFile() && f.getName().toLowerCase(Locale.ROOT).endsWith(".xml")) {
                        discovered.put(f.getAbsolutePath(), f);
                    }
                }
            }
            for (String filePath : files) {
                File f = new File(filePath);
                if (f.exists() && f.isFile()) {
                    discovered.put(f.getAbsolutePath(), f);
                }
            }

            for (File f : discovered.values()) {
                try {
                    String content = readBoundedUtf8(f);
                    entries.add(ManifestEntry.readable(f.getAbsolutePath(), content));
                } catch (IOException | SecurityException e) {
                    entries.add(ManifestEntry.unreadable(
                            f.getAbsolutePath(), e.getClass().getSimpleName()));
                }
            }
            return entries;
        }

        private static String readBoundedUtf8(File file) throws IOException {
            try (FileInputStream fis = new FileInputStream(file);
                 ByteArrayOutputStream out = new ByteArrayOutputStream(4096)) {
                byte[] buf = new byte[4096];
                int total = 0;
                int n;
                while ((n = fis.read(buf)) != -1) {
                    total += n;
                    if (total > MAX_MANIFEST_BYTES) {
                        throw new IOException("manifest_exceeds_512k");
                    }
                    out.write(buf, 0, n);
                }
                return new String(out.toByteArray(), StandardCharsets.UTF_8);
            }
        }
    }

    /** Production Keystore2 {@code OperationErrorPath} adapter on Android 12+ (API 31+). */
    private static final class AndroidOperationErrorPathAdapter implements OperationErrorPathAdapter {
        @Override
        public int getSdkInt() {
            return Build.VERSION.SDK_INT;
        }

        @Override
        public KeyMintQuirks.VendorIdentity getVendorIdentity() {
            return KeyMintQuirks.VendorIdentity.current();
        }

        @Override
        public OperationErrorPathResult executeErrorPathProbe(String alias) throws Exception {
            if (Build.VERSION.SDK_INT < 31) {
                return OperationErrorPathResult.notCompleted("requires_api_31");
            }
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                        alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .build();
                kpg.initialize(spec);
                kpg.generateKeyPair();

                IBinder binder = Keystore2ParcelClient.lookupServiceBinder();
                if (binder == null) {
                    return OperationErrorPathResult.notCompleted("keystore2_binder_unavailable");
                }
                Keystore2ParcelClient.KeyDescriptor appDesc =
                        Keystore2ParcelClient.KeyDescriptor.app(alias);
                Keystore2ParcelClient.KeyEntryResponse response =
                        Keystore2ParcelClient.getKeyEntry(binder, appDesc);
                if (response == null) {
                    return OperationErrorPathResult.notCompleted("getKeyEntry_null");
                }

                Keystore2ParcelClient.KeyDescriptor retDesc =
                        response.metadata != null ? response.metadata.key : null;
                Keystore2ParcelClient.KeyDescriptor opDescriptor =
                        resolveOperationDescriptor(alias, retDesc, appDesc);

                IBinder secLevelBinder = response.securityLevelBinder;
                if (secLevelBinder == null) {
                    secLevelBinder = Keystore2ParcelClient.getSecurityLevel(
                            binder, Keystore2DeepProbe.SECURITY_LEVEL_TRUSTED_ENVIRONMENT);
                }
                if (secLevelBinder == null) {
                    return OperationErrorPathResult.notCompleted("security_level_unavailable");
                }

                List<Keystore2ParcelClient.KeyParam> minimalParams = buildMinimalSigningOperationParams();
                IBinder testOp = tryCreateOperationHandle(secLevelBinder, opDescriptor, minimalParams);
                List<Keystore2ParcelClient.KeyParam> activeParams = minimalParams;
                boolean usedCompat = false;
                if (testOp != null) {
                    safeAbort(testOp);
                } else {
                    List<Keystore2ParcelClient.KeyParam> compatParams =
                            buildCompatSigningOperationParams();
                    IBinder compatOp = tryCreateOperationHandle(
                            secLevelBinder, opDescriptor, compatParams);
                    if (compatOp == null) {
                        return OperationErrorPathResult.notCompleted("createOperation_unavailable");
                    }
                    safeAbort(compatOp);
                    activeParams = compatParams;
                    usedCompat = true;
                }

                Boolean updateAadRejected = probeUpdateAad(secLevelBinder, opDescriptor, activeParams);
                Boolean oversizedRejected = probeOversizedUpdate(secLevelBinder, opDescriptor, activeParams);
                Boolean abortInvalidated = probeAbortInvalidates(secLevelBinder, opDescriptor, activeParams);

                boolean expectedAadAcceptance = KeyMintQuirks.isUpdateAadAcceptanceExpected(
                        getVendorIdentity());
                String detail = "updateAadRejected=" + updateAadRejected
                        + ",oversizedRejected=" + oversizedRejected
                        + ",abortInvalidated=" + abortInvalidated
                        + ",compat=" + usedCompat;
                return new OperationErrorPathResult(
                        true,
                        updateAadRejected,
                        expectedAadAcceptance,
                        oversizedRejected,
                        abortInvalidated,
                        usedCompat,
                        detail);
            } catch (Exception | LinkageError | OutOfMemoryError t) {
                return OperationErrorPathResult.notCompleted(
                        t.getClass().getSimpleName()
                                + (t.getMessage() != null ? ":" + t.getMessage() : ""));
            } finally {
                deleteAlias(alias);
            }
        }

        @Override
        public void deleteAlias(String alias) {
            Keystore2DeepProbe.deleteAliasFromJavaKeyStore(alias);
        }

        private Keystore2ParcelClient.KeyDescriptor resolveOperationDescriptor(
                String alias,
                Keystore2ParcelClient.KeyDescriptor retDesc,
                Keystore2ParcelClient.KeyDescriptor fallback) {
            if (retDesc == null) {
                return fallback;
            }
            if (retDesc.domain == Keystore2ParcelClient.DOMAIN_KEY_ID) {
                return retDesc;
            }
            return Keystore2ParcelClient.KeyDescriptor.keyId(retDesc.nspace, alias);
        }

        private List<Keystore2ParcelClient.KeyParam> buildMinimalSigningOperationParams() {
            List<Keystore2ParcelClient.KeyParam> params = new ArrayList<>(2);
            params.add(Keystore2ParcelClient.KeyParam.ofInt(
                    0x20000001, Keystore2ParcelClient.VAL_KEY_PURPOSE, 2));
            params.add(Keystore2ParcelClient.KeyParam.ofInt(
                    0x20000005, Keystore2ParcelClient.VAL_DIGEST, 4));
            return params;
        }

        private List<Keystore2ParcelClient.KeyParam> buildCompatSigningOperationParams() {
            List<Keystore2ParcelClient.KeyParam> params = new ArrayList<>(3);
            params.addAll(buildMinimalSigningOperationParams());
            params.add(Keystore2ParcelClient.KeyParam.ofInt(
                    0x10000002, Keystore2ParcelClient.VAL_ALGORITHM, 3));
            return params;
        }

        private IBinder tryCreateOperationHandle(
                IBinder secLevelBinder,
                Keystore2ParcelClient.KeyDescriptor descriptor,
                List<Keystore2ParcelClient.KeyParam> params) {
            try {
                return Keystore2ParcelClient.createOperation(secLevelBinder, descriptor, params, false);
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                return null;
            }
        }

        private Boolean probeUpdateAad(
                IBinder secLevelBinder,
                Keystore2ParcelClient.KeyDescriptor descriptor,
                List<Keystore2ParcelClient.KeyParam> params) {
            IBinder op = tryCreateOperationHandle(secLevelBinder, descriptor, params);
            if (op == null) {
                return null;
            }
            try {
                if (!Keystore2ParcelClient.updateAad(op, "aad".getBytes(StandardCharsets.UTF_8))) {
                    return null;
                }
                return Boolean.FALSE;
            } catch (Exception | LinkageError | OutOfMemoryError t) {
                return isServiceSpecificException(t) ? Boolean.TRUE : null;
            } finally {
                safeAbort(op);
            }
        }

        private Boolean probeOversizedUpdate(
                IBinder secLevelBinder,
                Keystore2ParcelClient.KeyDescriptor descriptor,
                List<Keystore2ParcelClient.KeyParam> params) {
            IBinder op = tryCreateOperationHandle(secLevelBinder, descriptor, params);
            if (op == null) {
                return null;
            }
            try {
                Keystore2ParcelClient.update(op, new byte[OVERSIZED_UPDATE_BYTES]);
                return Boolean.FALSE;
            } catch (Exception | LinkageError | OutOfMemoryError t) {
                return isServiceSpecificException(t) ? Boolean.TRUE : null;
            } finally {
                safeAbort(op);
            }
        }

        private Boolean probeAbortInvalidates(
                IBinder secLevelBinder,
                Keystore2ParcelClient.KeyDescriptor descriptor,
                List<Keystore2ParcelClient.KeyParam> params) {
            IBinder op = tryCreateOperationHandle(secLevelBinder, descriptor, params);
            if (op == null) {
                return null;
            }
            try {
                if (!Keystore2ParcelClient.abort(op)) {
                    return null;
                }
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                return null;
            }
            try {
                Keystore2ParcelClient.update(op, "after_abort".getBytes(StandardCharsets.UTF_8));
                return Boolean.FALSE;
            } catch (Exception | LinkageError | OutOfMemoryError t) {
                if (!isServiceSpecificException(t)) {
                    return null;
                }
                Integer errCode = extractServiceSpecificErrorCode(t);
                return errCode == null ? null : (errCode == ERROR_INVALID_OPERATION_HANDLE);
            }
        }

        private void safeAbort(IBinder op) {
            if (op == null) {
                return;
            }
            try {
                Keystore2ParcelClient.abort(op);
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                // Best-effort abort
            }
        }

        private static boolean isServiceSpecificException(Throwable t) {
            return t instanceof Keystore2ParcelClient.ServiceErrorException
                    || (t != null && CLASS_SERVICE_SPECIFIC_EXCEPTION.equals(t.getClass().getName()));
        }

        private static Integer extractServiceSpecificErrorCode(Throwable t) {
            if (t instanceof Keystore2ParcelClient.ServiceErrorException) {
                return ((Keystore2ParcelClient.ServiceErrorException) t).getErrorCode();
            }
            if (t == null || !CLASS_SERVICE_SPECIFIC_EXCEPTION.equals(t.getClass().getName())) {
                return null;
            }
            try {
                Field f = t.getClass().getField("errorCode");
                f.setAccessible(true);
                return f.getInt(t);
            } catch (Exception | LinkageError ignored) {
                return null;
            }
        }
    }
}
