package com.wsttxm.riskenginesdk.process;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Pure-Java canonicalizer and cross-process diff engine for Linux {@code /proc/<pid>/mountinfo}.
 *
 * <p>Canonicalization sorts entries by {@code (peerGroup, mountPoint, mountId)} and strips
 * dynamic shmem capacity options ({@code size=}, {@code nr_inodes=}, {@code nr_blocks=}) on
 * {@code tmpfs}/{@code devtmpfs}/{@code rootfs} so memory hotplug/balloon changes produce
 * zero false positives while Shamiko/Magisk/KernelSU selective main-process unmounts produce
 * deterministic diff entries.
 */
public final class MountViewNormalizer {

    private static final Set<String> SHMEM_FS_TYPES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("tmpfs", "devtmpfs", "rootfs")));

    private static final List<String> DYNAMIC_SHMEM_OPTION_PREFIXES = Collections.unmodifiableList(
            Arrays.asList("size=", "nr_inodes=", "nr_blocks="));

    private static final List<String> ROOT_MOUNT_TOKENS = Collections.unmodifiableList(
            Arrays.asList(
                    "magisk", "kernelsu", "apatch", "susfs",
                    "shamiko", "zygisk", "debug_ramdisk", "/data/adb"));

    // Boundary-delimited match for short "ksu" token so benign substrings like "worksuite" or
    // "banksu" never false-positive while "KSU", "/data/adb/ksu", or "ksu_overlay" still match.
    private static final Pattern KSU_TOKEN_BOUNDARY =
            Pattern.compile("(?i)(^|[^a-z0-9])ksu($|[^a-z0-9])");

    /**
     * Mount point base paths that legitimately differ between an app's main process and an
     * {@code android:isolatedProcess="true"} sandbox due to Android storage/profile isolation
     * (including exact mount points without trailing slashes such as {@code /storage} or
     * {@code /data/data} mounted by Zygote on Android 11+).
     */
    private static final List<String> EXPECTED_ISOLATED_SANDBOX_BASES =
            Collections.unmodifiableList(Arrays.asList(
                    "/storage", "/mnt/user", "/mnt/pass_through", "/mnt/installer",
                    "/mnt/androidwritable", "/mnt/runtime", "/data/media",
                    "/data/user", "/data/user_de", "/data/data",
                    "/data/misc/profiles", "/data_mirror"));

    private static final Comparator<ParsedMountEntry> CANONICAL_ORDER = (a, b) -> {
        int cmp = Integer.compareUnsigned(a.peerGroup, b.peerGroup);
        if (cmp != 0) return cmp;
        cmp = a.mountPoint.compareTo(b.mountPoint);
        if (cmp != 0) return cmp;
        return Integer.compareUnsigned(a.mountId, b.mountId);
    };

    private MountViewNormalizer() {}

    /** Single parsed {@code /proc/<pid>/mountinfo} line. */
    public static final class ParsedMountEntry {
        public final String rawLine;
        public final int mountId;
        public final int parentId;
        public final String root;
        public final String mountPoint;
        public final String mountOptions;
        public final String optionalFields;
        public final int peerGroup;
        public final String fsType;
        public final String mountSource;
        public final String superOptions;
        private final String canonicalSignature;

        private ParsedMountEntry(String rawLine,
                                 int mountId,
                                 int parentId,
                                 String root,
                                 String mountPoint,
                                 String mountOptions,
                                 String optionalFields,
                                 int peerGroup,
                                 String fsType,
                                 String mountSource,
                                 String superOptions) {
            this.rawLine = rawLine;
            this.mountId = mountId;
            this.parentId = parentId;
            this.root = root;
            this.mountPoint = mountPoint;
            this.mountOptions = mountOptions;
            this.optionalFields = optionalFields;
            this.peerGroup = peerGroup;
            this.fsType = fsType;
            this.mountSource = mountSource;
            this.superOptions = superOptions;
            this.canonicalSignature = buildCanonicalSignature(
                    mountSource, root, mountPoint, fsType, mountOptions, superOptions);
        }

        public String getCanonicalSignature() {
            return canonicalSignature;
        }
    }

    /** Result of comparing main-process vs isolated-process mount views. */
    public static final class MountDiffResult {
        private final int mainEntryCount;
        private final int isolatedEntryCount;
        private final boolean identicalAfterNormalization;
        private final List<String> isolatedOnlyEntries;
        private final List<String> mainOnlyEntries;
        private final List<String> suspiciousHiddenMounts;
        private final List<String> directRootTokens;

        public MountDiffResult(int mainEntryCount,
                               int isolatedEntryCount,
                               boolean identicalAfterNormalization,
                               List<String> isolatedOnlyEntries,
                               List<String> mainOnlyEntries,
                               List<String> suspiciousHiddenMounts,
                               List<String> directRootTokens) {
            this.mainEntryCount = mainEntryCount;
            this.isolatedEntryCount = isolatedEntryCount;
            this.identicalAfterNormalization = identicalAfterNormalization;
            this.isolatedOnlyEntries = Collections.unmodifiableList(
                    new ArrayList<>(isolatedOnlyEntries));
            this.mainOnlyEntries = Collections.unmodifiableList(
                    new ArrayList<>(mainOnlyEntries));
            this.suspiciousHiddenMounts = Collections.unmodifiableList(
                    new ArrayList<>(suspiciousHiddenMounts));
            this.directRootTokens = Collections.unmodifiableList(
                    new ArrayList<>(directRootTokens));
        }

        public int getMainEntryCount() { return mainEntryCount; }
        public int getIsolatedEntryCount() { return isolatedEntryCount; }
        public boolean isIdenticalAfterNormalization() { return identicalAfterNormalization; }
        public List<String> getIsolatedOnlyEntries() { return isolatedOnlyEntries; }
        public List<String> getMainOnlyEntries() { return mainOnlyEntries; }
        public List<String> getSuspiciousHiddenMounts() { return suspiciousHiddenMounts; }
        public List<String> getDirectRootTokens() { return directRootTokens; }

        public boolean hasSelectiveUnmountEvidence() {
            return !suspiciousHiddenMounts.isEmpty() || !directRootTokens.isEmpty();
        }
    }

    /** Parses a single {@code mountinfo} line according to Linux procfs specification. */
    public static ParsedMountEntry parseLine(String line) {
        if (line == null || line.isBlank()) {
            return null;
        }
        int sep = line.indexOf(" - ");
        if (sep < 0) {
            return null;
        }
        String left = line.substring(0, sep).trim();
        String right = line.substring(sep + 3).trim();
        if (left.isEmpty() || right.isEmpty()) {
            return null;
        }
        String[] leftParts = left.split("\\s+");
        String[] rightParts = right.split("\\s+");
        if (leftParts.length < 6 || rightParts.length < 2) {
            return null;
        }
        int mountId;
        int parentId;
        try {
            mountId = Integer.parseUnsignedInt(leftParts[0]);
            parentId = Integer.parseUnsignedInt(leftParts[1]);
        } catch (NumberFormatException e) {
            return null;
        }
        String root = leftParts[3];
        String mountPoint = leftParts[4];
        String mountOptions = leftParts[5];
        StringBuilder optionalBuilder = new StringBuilder();
        for (int i = 6; i < leftParts.length; i++) {
            if (i > 6) optionalBuilder.append(' ');
            optionalBuilder.append(leftParts[i]);
        }
        String optionalFields = optionalBuilder.toString();
        int peerGroup = parsePeerGroup(optionalFields);

        String fsType = rightParts[0];
        String mountSource = rightParts[1];
        StringBuilder superBuilder = new StringBuilder();
        for (int i = 2; i < rightParts.length; i++) {
            if (i > 2) superBuilder.append(' ');
            superBuilder.append(rightParts[i]);
        }
        return new ParsedMountEntry(
                line, mountId, parentId, root, mountPoint, mountOptions,
                optionalFields, peerGroup, fsType, mountSource, superBuilder.toString());
    }

    /** Parses and canonically sorts all valid {@code mountinfo} lines by (peerGroup, mountPoint, mountId). */
    public static List<ParsedMountEntry> normalize(List<String> rawLines) {
        if (rawLines == null || rawLines.isEmpty()) {
            return Collections.emptyList();
        }
        List<ParsedMountEntry> entries = new ArrayList<>(rawLines.size());
        for (String line : rawLines) {
            ParsedMountEntry parsed = parseLine(line);
            if (parsed != null) {
                entries.add(parsed);
            }
        }
        entries.sort(CANONICAL_ORDER);
        return Collections.unmodifiableList(entries);
    }

    /** Produces the ordered canonical signature lines for deterministic cross-process comparison. */
    public static List<String> toCanonicalSignatures(List<String> rawLines) {
        List<ParsedMountEntry> normalized = normalize(rawLines);
        List<String> signatures = new ArrayList<>(normalized.size());
        for (ParsedMountEntry entry : normalized) {
            signatures.add(entry.getCanonicalSignature());
        }
        return Collections.unmodifiableList(signatures);
    }

    /**
     * Compares main-process and isolated-process {@code mountinfo} tables after canonical sorting
     * and dynamic shmem option stripping.
     */
    public static MountDiffResult diffViews(List<String> mainRawLines,
                                            List<String> isolatedRawLines) {
        List<ParsedMountEntry> mainEntries = normalize(mainRawLines);
        List<ParsedMountEntry> isolatedEntries = normalize(isolatedRawLines);

        Map<String, ParsedMountEntry> mainBySig = new LinkedHashMap<>();
        for (ParsedMountEntry e : mainEntries) {
            mainBySig.putIfAbsent(e.getCanonicalSignature(), e);
        }
        Map<String, ParsedMountEntry> isolatedBySig = new LinkedHashMap<>();
        for (ParsedMountEntry e : isolatedEntries) {
            isolatedBySig.putIfAbsent(e.getCanonicalSignature(), e);
        }

        List<String> isolatedOnly = new ArrayList<>();
        List<String> suspiciousHidden = new ArrayList<>();
        Set<String> directRootTokens = new LinkedHashSet<>();

        for (Map.Entry<String, ParsedMountEntry> item : isolatedBySig.entrySet()) {
            String sig = item.getKey();
            ParsedMountEntry entry = item.getValue();
            if (!mainBySig.containsKey(sig)) {
                isolatedOnly.add(sig);
                String token = matchRootMountToken(entry);
                if (token != null) {
                    directRootTokens.add(token + ":" + entry.mountPoint);
                }
                if (!isExpectedSandboxMountPoint(entry.mountPoint)
                        || token != null
                        || isOverlayOnSystemPartition(entry)) {
                    suspiciousHidden.add(entry.mountPoint + " (" + entry.fsType + ":" + entry.mountSource + ")");
                }
            }
        }

        List<String> mainOnly = new ArrayList<>();
        for (String sig : mainBySig.keySet()) {
            if (!isolatedBySig.containsKey(sig)) {
                mainOnly.add(sig);
            }
        }

        boolean identical = isolatedOnly.isEmpty() && mainOnly.isEmpty();
        return new MountDiffResult(
                mainEntries.size(),
                isolatedEntries.size(),
                identical,
                isolatedOnly,
                mainOnly,
                suspiciousHidden,
                new ArrayList<>(directRootTokens));
    }

    /** Strips dynamic {@code size=}, {@code nr_inodes=}, and {@code nr_blocks=} on shmem filesystems. */
    static String stripDynamicOptionsIfShmem(String fsType, String options) {
        if (options == null || options.isEmpty()) {
            return "";
        }
        if (fsType == null || !SHMEM_FS_TYPES.contains(fsType.toLowerCase(Locale.ROOT))) {
            return options;
        }
        String[] parts = options.split(",");
        StringBuilder out = new StringBuilder(options.length());
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) continue;
            if (isDynamicShmemOption(trimmed)) continue;
            if (out.length() > 0) out.append(',');
            out.append(trimmed);
        }
        return out.toString();
    }

    private static boolean isDynamicShmemOption(String option) {
        String lower = option.toLowerCase(Locale.ROOT);
        for (String prefix : DYNAMIC_SHMEM_OPTION_PREFIXES) {
            if (lower.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static String buildCanonicalSignature(String mountSource,
                                                  String root,
                                                  String mountPoint,
                                                  String fsType,
                                                  String mountOptions,
                                                  String superOptions) {
        String cleanMountOpts = stripDynamicOptionsIfShmem(fsType, mountOptions);
        String cleanSuperOpts = stripDynamicOptionsIfShmem(fsType, superOptions);
        return mountSource + " " + root + " " + mountPoint + " " + fsType
                + " " + cleanMountOpts + " " + cleanSuperOpts;
    }

    private static int parsePeerGroup(String optionalFields) {
        if (optionalFields == null || optionalFields.isEmpty()) {
            return 0;
        }
        int colon = optionalFields.indexOf(':');
        if (colon < 0 || colon + 1 >= optionalFields.length()) {
            return 0;
        }
        int space = optionalFields.indexOf(' ', colon + 1);
        String groupStr = space < 0
                ? optionalFields.substring(colon + 1)
                : optionalFields.substring(colon + 1, space);
        try {
            return Integer.parseUnsignedInt(groupStr);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static boolean isExpectedSandboxMountPoint(String mountPoint) {
        if (mountPoint == null || mountPoint.isEmpty()) {
            return false;
        }
        for (String base : EXPECTED_ISOLATED_SANDBOX_BASES) {
            if (mountPoint.equals(base) || mountPoint.startsWith(base + "/")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isOverlayOnSystemPartition(ParsedMountEntry entry) {
        if (entry == null) return false;
        String fs = entry.fsType.toLowerCase(Locale.ROOT);
        if (!"overlay".equals(fs) && !"overlayfs".equals(fs)) {
            return false;
        }
        String mp = entry.mountPoint;
        return mp.startsWith("/system")
                || mp.startsWith("/vendor")
                || mp.startsWith("/product")
                || mp.startsWith("/odm")
                || mp.startsWith("/apex");
    }

    private static String matchRootMountToken(ParsedMountEntry entry) {
        if (entry == null) return null;
        String combined = entry.mountSource + " " + entry.root + " " + entry.mountPoint
                + " " + entry.superOptions;
        if ("KSU".equals(entry.mountSource)
                || KSU_TOKEN_BOUNDARY.matcher(combined).find()) {
            return "ksu";
        }
        String hay = combined.toLowerCase(Locale.ROOT);
        for (String token : ROOT_MOUNT_TOKENS) {
            if (hay.contains(token)) {
                return token;
            }
        }
        return null;
    }
}
