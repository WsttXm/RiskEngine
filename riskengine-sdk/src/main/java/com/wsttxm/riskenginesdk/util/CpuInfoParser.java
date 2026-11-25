package com.wsttxm.riskenginesdk.util;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Structured parser for Linux {@code /proc/cpuinfo}.
 *
 * <p>Splits content into global {@code commonInfo} and per-core {@code perCoreInfo} sections,
 * preserving {@code flags}/{@code Features} and {@code model name}/{@code Hardware}, while
 * stripping frequency-scaling volatile fields ({@code BogoMIPS}, {@code cpu MHz}) before
 * producing a stable fingerprint string.
 */
public final class CpuInfoParser {

    private static final String SINGLE_PROCESSOR_KEY = "processor";

    private CpuInfoParser() {}

    public static ParsedCpuInfo parse(String contents) {
        if (contents == null || contents.isBlank()) {
            return ParsedCpuInfo.EMPTY;
        }

        String[] rawLines = contents.split("\\r?\\n", -1);
        List<List<Map.Entry<String, String>>> sections = new ArrayList<>();
        List<Map.Entry<String, String>> currentSection = new ArrayList<>();

        for (String line : rawLines) {
            if (line.trim().isEmpty()) {
                if (!currentSection.isEmpty()) {
                    sections.add(currentSection);
                    currentSection = new ArrayList<>();
                }
                continue;
            }
            Map.Entry<String, String> pair = parseLine(line);
            if (pair != null) {
                currentSection.add(pair);
            }
        }
        if (!currentSection.isEmpty()) {
            sections.add(currentSection);
        }

        List<Map.Entry<String, String>> commonInfo = new ArrayList<>();
        List<List<Map.Entry<String, String>>> perCoreInfo = new ArrayList<>();

        for (List<Map.Entry<String, String>> section : sections) {
            int firstProcIdx = -1;
            for (int i = 0; i < section.size(); i++) {
                if (isSingleProcessorPair(section.get(i))) {
                    firstProcIdx = i;
                    break;
                }
            }
            if (firstProcIdx < 0) {
                commonInfo.addAll(section);
            } else {
                for (int i = 0; i < firstProcIdx; i++) {
                    commonInfo.add(section.get(i));
                }
                List<Map.Entry<String, String>> corePairs = new ArrayList<>();
                for (int i = firstProcIdx + 1; i < section.size(); i++) {
                    Map.Entry<String, String> pair = section.get(i);
                    if (!isSingleProcessorPair(pair)) {
                        corePairs.add(pair);
                    }
                }
                perCoreInfo.add(Collections.unmodifiableList(corePairs));
            }
        }

        return new ParsedCpuInfo(commonInfo, perCoreInfo);
    }

    public static boolean isVolatileField(String key) {
        if (key == null) {
            return false;
        }
        String normalized = key.trim().toLowerCase(Locale.ROOT);
        return "bogomips".equals(normalized) || "cpu mhz".equals(normalized);
    }

    private static Map.Entry<String, String> parseLine(String line) {
        int colonIdx = line.indexOf(':');
        if (colonIdx <= 0) {
            return null;
        }
        String key = line.substring(0, colonIdx).trim();
        if (key.isEmpty()) {
            return null;
        }
        String value = line.substring(colonIdx + 1).trim();
        return new AbstractMap.SimpleImmutableEntry<>(key, value);
    }

    private static boolean isSingleProcessorPair(Map.Entry<String, String> pair) {
        if (!SINGLE_PROCESSOR_KEY.equals(pair.getKey())) {
            return false;
        }
        String val = pair.getValue();
        if (val.isEmpty()) {
            return false;
        }
        for (int i = 0; i < val.length(); i++) {
            if (!Character.isDigit(val.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    public static final class ParsedCpuInfo {
        public static final ParsedCpuInfo EMPTY =
                new ParsedCpuInfo(Collections.emptyList(), Collections.emptyList());

        private final List<Map.Entry<String, String>> commonInfo;
        private final List<List<Map.Entry<String, String>>> perCoreInfo;

        public ParsedCpuInfo(List<Map.Entry<String, String>> commonInfo,
                             List<List<Map.Entry<String, String>>> perCoreInfo) {
            this.commonInfo = commonInfo == null || commonInfo.isEmpty()
                    ? Collections.emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(commonInfo));
            if (perCoreInfo == null || perCoreInfo.isEmpty()) {
                this.perCoreInfo = Collections.emptyList();
            } else {
                List<List<Map.Entry<String, String>>> copy = new ArrayList<>(perCoreInfo.size());
                for (List<Map.Entry<String, String>> core : perCoreInfo) {
                    copy.add(core == null || core.isEmpty()
                            ? Collections.emptyList()
                            : Collections.unmodifiableList(new ArrayList<>(core)));
                }
                this.perCoreInfo = Collections.unmodifiableList(copy);
            }
        }

        public List<Map.Entry<String, String>> getCommonInfo() {
            return commonInfo;
        }

        public List<List<Map.Entry<String, String>>> getPerCoreInfo() {
            return perCoreInfo;
        }

        public int getCoreCount() {
            return perCoreInfo.size();
        }

        public String getModelName() {
            String v = findFirstValue("model name");
            return v != null ? v : findFirstValue("Processor");
        }

        public String getHardware() {
            return findFirstValue("Hardware");
        }

        public String getFlags() {
            String v = findFirstValue("flags");
            return v != null ? v : findFirstValue("Features");
        }

        /** Returns a new {@link ParsedCpuInfo} with volatile fields ({@code BogoMIPS}, {@code cpu MHz}) removed. */
        public ParsedCpuInfo withoutVolatileFields() {
            List<Map.Entry<String, String>> filteredCommon = filterVolatile(commonInfo);
            List<List<Map.Entry<String, String>>> filteredCores = new ArrayList<>(perCoreInfo.size());
            for (List<Map.Entry<String, String>> core : perCoreInfo) {
                filteredCores.add(filterVolatile(core));
            }
            return new ParsedCpuInfo(filteredCommon, filteredCores);
        }

        /**
         * Canonical deterministic string excluding volatile frequency fields ({@code BogoMIPS},
         * {@code cpu MHz}), suitable for v2 device fingerprinting.
         */
        public String toStableFingerprintString() {
            ParsedCpuInfo stable = withoutVolatileFields();
            if (stable.commonInfo.isEmpty() && stable.perCoreInfo.isEmpty()) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            if (!stable.commonInfo.isEmpty()) {
                List<String> commonParts = new ArrayList<>(stable.commonInfo.size());
                for (Map.Entry<String, String> entry : stable.commonInfo) {
                    commonParts.add(entry.getKey().toLowerCase(Locale.ROOT) + "=" + entry.getValue());
                }
                Collections.sort(commonParts);
                sb.append("common:").append(String.join(";", commonParts));
            }
            if (!stable.perCoreInfo.isEmpty()) {
                if (sb.length() > 0) sb.append('|');
                sb.append("cores=").append(stable.perCoreInfo.size()).append(':');
                List<String> coreProfiles = new ArrayList<>(stable.perCoreInfo.size());
                for (List<Map.Entry<String, String>> core : stable.perCoreInfo) {
                    List<String> fields = new ArrayList<>(core.size());
                    for (Map.Entry<String, String> entry : core) {
                        fields.add(entry.getKey().toLowerCase(Locale.ROOT) + "=" + entry.getValue());
                    }
                    Collections.sort(fields);
                    coreProfiles.add(String.join(";", fields));
                }
                Collections.sort(coreProfiles);
                sb.append(String.join("/", coreProfiles));
            }
            return sb.toString();
        }

        private String findFirstValue(String targetKey) {
            for (Map.Entry<String, String> entry : commonInfo) {
                if (entry.getKey().equalsIgnoreCase(targetKey) && !entry.getValue().isEmpty()) {
                    return entry.getValue();
                }
            }
            for (List<Map.Entry<String, String>> core : perCoreInfo) {
                for (Map.Entry<String, String> entry : core) {
                    if (entry.getKey().equalsIgnoreCase(targetKey) && !entry.getValue().isEmpty()) {
                        return entry.getValue();
                    }
                }
            }
            return null;
        }

        private static List<Map.Entry<String, String>> filterVolatile(
                List<Map.Entry<String, String>> input) {
            if (input.isEmpty()) {
                return Collections.emptyList();
            }
            List<Map.Entry<String, String>> out = new ArrayList<>(input.size());
            for (Map.Entry<String, String> entry : input) {
                if (!isVolatileField(entry.getKey())) {
                    out.add(entry);
                }
            }
            return out;
        }
    }
}
