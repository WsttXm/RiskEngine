package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;

import com.wsttxm.riskenginesdk.FingerprintHasher;
import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.core.SafeExecutor;
import com.wsttxm.riskenginesdk.model.CollectorResult;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * Zero-permission collector capturing the device's MediaCodec hardware/software matrix.
 *
 * <p>Physical SoCs expose characteristic vendor hardware codec prefixes (e.g. {@code c2.qti.*},
 * {@code c2.mtk.*}, {@code c2.exynos.*}), whereas emulators and cloud phones lean heavily on
 * {@code c2.android.*} software codecs.
 */
public class MediaCodecCollector extends BaseCollector {

    public static final class CodecSummary {
        public final int totalCount;
        public final int hwCount;
        public final int swAndroidGoogleCount;
        public final int nonGoogleCodecCount;

        public CodecSummary(int totalCount,
                            int hwCount,
                            int swAndroidGoogleCount,
                            int nonGoogleCodecCount) {
            this.totalCount = totalCount;
            this.hwCount = hwCount;
            this.swAndroidGoogleCount = swAndroidGoogleCount;
            this.nonGoogleCodecCount = nonGoogleCodecCount;
        }

        /**
         * Returns true when the device exposes only {@code c2.android.*} / {@code OMX.google.*}
         * software codecs and zero SoC hardware codecs.
         */
        public boolean isZeroHardwareOnly() {
            return totalCount > 0
                    && hwCount == 0
                    && nonGoogleCodecCount == 0
                    && swAndroidGoogleCount > 0;
        }
    }

    /** Computes a hardware/software codec summary from parsed codec entries. */
    public static CodecSummary summarize(List<CodecEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return new CodecSummary(0, 0, 0, 0);
        }
        int total = 0;
        int hw = 0;
        int swGoogle = 0;
        int nonGoogle = 0;
        for (CodecEntry entry : entries) {
            if (entry == null || entry.name.isEmpty()) {
                continue;
            }
            total++;
            String lower = entry.name.toLowerCase(Locale.ROOT);
            boolean isAndroidGoogle = lower.startsWith("c2.android.")
                    || lower.startsWith("omx.google.");
            if (entry.hardwareAccelerated) {
                hw++;
            }
            if (isAndroidGoogle) {
                swGoogle++;
            } else {
                nonGoogle++;
                if (!entry.softwareOnly && !entry.hardwareAccelerated) {
                    hw++;
                }
            }
        }
        return new CodecSummary(total, hw, swGoogle, nonGoogle);
    }

    /** Safely reads and summarizes system MediaCodecs, returning null if unavailable. */
    public static CodecSummary readSystemCodecsSummary() {
        SafeExecutor.SafeResult<List<CodecEntry>> safe = SafeExecutor.safeWithTimeoutOrInline(
                SafeExecutor.TIMEOUT_SHORT_MS, MediaCodecCollector::readSystemCodecs);
        if (!safe.isSuccess() || safe.getOrNull() == null || safe.getOrNull().isEmpty()) {
            return null;
        }
        CodecSummary summary = summarize(safe.getOrNull());
        return summary.totalCount > 0 ? summary : null;
    }

    public static final class CodecEntry {
        public final String name;
        public final boolean hardwareAccelerated;
        public final boolean softwareOnly;
        public final boolean encoder;
        public final List<String> supportedTypes;

        public CodecEntry(String name,
                          boolean hardwareAccelerated,
                          boolean softwareOnly,
                          boolean encoder,
                          List<String> supportedTypes) {
            this.name = name == null ? "" : name.trim();
            this.hardwareAccelerated = hardwareAccelerated;
            this.softwareOnly = softwareOnly;
            this.encoder = encoder;
            this.supportedTypes = supportedTypes == null
                    ? Collections.emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(supportedTypes));
        }
    }

    public MediaCodecCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "codec_info";
    }

    @Override
    protected void collect(CollectorResult result) {
        SafeExecutor.SafeResult<List<CodecEntry>> safe = SafeExecutor.safeWithTimeoutOrInline(
                SafeExecutor.TIMEOUT_SHORT_MS, MediaCodecCollector::readSystemCodecs);
        if (!safe.isSuccess() || safe.getOrNull() == null || safe.getOrNull().isEmpty()) {
            result.markUnsupported("media_codec_unavailable");
            return;
        }
        populateFromEntries(safe.getOrNull(), result);
    }

    /** Deterministic pure-Java population helper shared by runtime collection and JVM tests. */
    public static void populateFromEntries(List<CodecEntry> entries, CollectorResult result) {
        if (entries == null || entries.isEmpty()) {
            result.markUnsupported("media_codec_empty");
            return;
        }

        List<String> canonical = new ArrayList<>(entries.size());
        Set<String> hwPrefixes = new TreeSet<>();
        int hwCount = 0;
        int swCount = 0;

        for (CodecEntry entry : entries) {
            if (entry == null || entry.name.isEmpty()) {
                continue;
            }
            if (entry.hardwareAccelerated) {
                hwCount++;
                String prefix = extractVendorPrefix(entry.name);
                if (!prefix.isEmpty()) {
                    hwPrefixes.add(prefix);
                }
            }
            if (entry.softwareOnly) {
                swCount++;
            }
            List<String> types = new ArrayList<>();
            for (String type : entry.supportedTypes) {
                if (type != null && !type.isBlank()) {
                    types.add(type.trim().toLowerCase(Locale.ROOT));
                }
            }
            Collections.sort(types);
            canonical.add(entry.name.toLowerCase(Locale.ROOT)
                    + "|hw=" + (entry.hardwareAccelerated ? 1 : 0)
                    + "|sw=" + (entry.softwareOnly ? 1 : 0)
                    + "|enc=" + (entry.encoder ? 1 : 0)
                    + "|types=" + String.join(",", types));
        }

        if (canonical.isEmpty()) {
            result.markUnsupported("media_codec_empty");
            return;
        }

        Collections.sort(canonical);
        String matrixHash = FingerprintHasher.sha256Utf8(String.join("\n", canonical));
        result.addValue("codec_matrix_hash", matrixHash);
        result.addValue("total_count", String.valueOf(canonical.size()));
        result.addValue("hw_count", String.valueOf(hwCount));
        result.addValue("sw_count", String.valueOf(swCount));
        if (!hwPrefixes.isEmpty()) {
            result.addValue("hw_vendor_prefixes", String.join(",", hwPrefixes));
        }
    }

    private static List<CodecEntry> readSystemCodecs() {
        MediaCodecList list = new MediaCodecList(MediaCodecList.ALL_CODECS);
        MediaCodecInfo[] infos = list.getCodecInfos();
        if (infos == null || infos.length == 0) {
            return Collections.emptyList();
        }
        List<CodecEntry> entries = new ArrayList<>(infos.length);
        for (MediaCodecInfo info : infos) {
            if (info == null) {
                continue;
            }
            String name = info.getName();
            String[] rawTypes = info.getSupportedTypes();
            List<String> types = rawTypes == null
                    ? Collections.emptyList()
                    : Arrays.asList(rawTypes);
            entries.add(new CodecEntry(
                    name,
                    info.isHardwareAccelerated(),
                    info.isSoftwareOnly(),
                    info.isEncoder(),
                    types));
        }
        return entries;
    }

    private static String extractVendorPrefix(String codecName) {
        String lower = codecName.toLowerCase(Locale.ROOT);
        String[] parts = lower.split("\\.");
        if (parts.length >= 2) {
            return parts[0] + "." + parts[1];
        }
        return "";
    }
}
