package com.wsttxm.riskenginesdk.collector.native_layer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unambiguous escaped wire protocol codec shared between C++ ({@code util/payload_codec.cpp})
 * and Java.
 *
 * <p>Wire format:
 * <ul>
 *   <li>Line 0 (header): {@code status=<OK|RESTRICTED|UNSUPPORTED|ERROR>\terrno=<int>[\tKEY=val...]}</li>
 *   <li>Lines 1..N (records): {@code KEY=escaped_val[\tKEY=escaped_val...]}</li>
 * </ul>
 *
 * <p>Value escaping table:
 * {@code '\' -> "\\"}, {@code '\t' -> "\t"}, {@code '\n' -> "\n"}, {@code '\r' -> "\r"},
 * {@code '=' -> "\="}.
 */
public final class NativePayloadCodec {
    private NativePayloadCodec() {}

    public enum Status {
        OK,
        RESTRICTED,
        UNSUPPORTED,
        ERROR;

        public static Status fromWire(String raw) {
            if (raw == null) return null;
            switch (raw) {
                case "OK":
                    return OK;
                case "RESTRICTED":
                    return RESTRICTED;
                case "UNSUPPORTED":
                    return UNSUPPORTED;
                case "ERROR":
                    return ERROR;
                default:
                    return null;
            }
        }
    }

    public static final class DecodedPayload {
        private final Status status;
        private final int errno;
        private final boolean malformed;
        private final Map<String, String> headerFields;
        private final List<Map<String, String>> records;

        DecodedPayload(Status status,
                       int errno,
                       boolean malformed,
                       Map<String, String> headerFields,
                       List<Map<String, String>> records) {
            this.status = status == null ? Status.ERROR : status;
            this.errno = errno;
            this.malformed = malformed;
            this.headerFields = Collections.unmodifiableMap(new LinkedHashMap<>(headerFields));
            List<Map<String, String>> frozen = new ArrayList<>(records.size());
            for (Map<String, String> record : records) {
                frozen.add(Collections.unmodifiableMap(new LinkedHashMap<>(record)));
            }
            this.records = Collections.unmodifiableList(frozen);
        }

        public Status getStatus() {
            return status;
        }

        public int getErrno() {
            return errno;
        }

        public boolean isMalformed() {
            return malformed;
        }

        public boolean isOk() {
            return status == Status.OK && !malformed;
        }

        public Map<String, String> getHeaderFields() {
            return headerFields;
        }

        public String getHeaderField(String key) {
            return headerFields.get(key);
        }

        public List<Map<String, String>> getRecords() {
            return records;
        }
    }

    public static boolean isValidKey(String key) {
        if (key == null || key.isEmpty()) {
            return false;
        }
        for (int i = 0; i < key.length(); i++) {
            char ch = key.charAt(i);
            if (ch == '\t' || ch == '\n' || ch == '\r' || ch == '=' || ch == '\\' || ch == '\0') {
                return false;
            }
        }
        return true;
    }

    public static String escapeValue(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        boolean needsEscape = false;
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '\\' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '=') {
                needsEscape = true;
                break;
            }
        }
        if (!needsEscape) {
            return value;
        }
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '=':
                    sb.append("\\=");
                    break;
                default:
                    sb.append(ch);
                    break;
            }
        }
        return sb.toString();
    }

    public static String unescapeValue(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return "";
        }
        if (encoded.indexOf('\\') < 0) {
            return encoded;
        }
        StringBuilder sb = new StringBuilder(encoded.length());
        int i = 0;
        final int len = encoded.length();
        while (i < len) {
            char ch = encoded.charAt(i);
            if (ch != '\\' || i + 1 >= len) {
                sb.append(ch);
                i++;
                continue;
            }
            char next = encoded.charAt(i + 1);
            switch (next) {
                case '\\':
                    sb.append('\\');
                    break;
                case 't':
                    sb.append('\t');
                    break;
                case 'n':
                    sb.append('\n');
                    break;
                case 'r':
                    sb.append('\r');
                    break;
                case '=':
                    sb.append('=');
                    break;
                default:
                    // Forward compatibility: preserve unrecognized escape verbatim.
                    sb.append(ch).append(next);
                    break;
            }
            i += 2;
        }
        return sb.toString();
    }

    public static String encodeRecord(Map<String, String> fields) {
        if (fields == null || fields.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            String key = entry.getKey();
            if (!isValidKey(key)) {
                throw new IllegalArgumentException("Invalid payload key: " + key);
            }
            if (sb.length() > 0) {
                sb.append('\t');
            }
            sb.append(key).append('=').append(escapeValue(entry.getValue()));
        }
        return sb.toString();
    }

    public static Map<String, String> decodeRecord(String line) {
        boolean[] malformed = new boolean[1];
        return Collections.unmodifiableMap(parseRecordLine(line, malformed));
    }

    public static String encodePayload(Status status,
                                       int errno,
                                       Map<String, String> headerFields,
                                       List<Map<String, String>> records) {
        Status effectiveStatus = status == null ? Status.ERROR : status;
        Map<String, String> header = new LinkedHashMap<>();
        header.put("status", effectiveStatus.name());
        header.put("errno", Integer.toString(errno));
        if (headerFields != null) {
            for (Map.Entry<String, String> entry : headerFields.entrySet()) {
                String key = entry.getKey();
                if ("status".equals(key) || "errno".equals(key)) {
                    continue;
                }
                header.put(key, entry.getValue());
            }
        }
        StringBuilder sb = new StringBuilder(encodeRecord(header));
        if (records != null) {
            for (Map<String, String> record : records) {
                if (record == null || record.isEmpty()) {
                    continue;
                }
                sb.append('\n').append(encodeRecord(record));
            }
        }
        return sb.toString();
    }

    public static DecodedPayload decodePayload(String raw) {
        if (raw == null || raw.isEmpty()) {
            return new DecodedPayload(Status.ERROR, 0, true,
                    Collections.emptyMap(), Collections.emptyList());
        }

        boolean[] malformedFlag = new boolean[1];
        int firstNl = raw.indexOf('\n');
        String headerLine = firstNl >= 0 ? raw.substring(0, firstNl) : raw;
        Map<String, String> rawHeader = parseRecordLine(headerLine, malformedFlag);

        Status status = Status.fromWire(rawHeader.get("status"));
        if (status == null) {
            status = Status.ERROR;
            malformedFlag[0] = true;
        }

        int errno = 0;
        String rawErrno = rawHeader.get("errno");
        if (rawErrno != null) {
            try {
                errno = Integer.parseInt(rawErrno);
            } catch (NumberFormatException e) {
                malformedFlag[0] = true;
            }
        }

        Map<String, String> extraHeaders = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : rawHeader.entrySet()) {
            if (!"status".equals(entry.getKey()) && !"errno".equals(entry.getKey())) {
                extraHeaders.put(entry.getKey(), entry.getValue());
            }
        }

        List<Map<String, String>> records = new ArrayList<>();
        if (firstNl >= 0) {
            int pos = firstNl + 1;
            final int len = raw.length();
            while (pos <= len) {
                int nextNl = raw.indexOf('\n', pos);
                String line = nextNl >= 0 ? raw.substring(pos, nextNl) : raw.substring(pos);
                if (line.isEmpty()) {
                    malformedFlag[0] = true;
                } else {
                    Map<String, String> record = parseRecordLine(line, malformedFlag);
                    if (!record.isEmpty()) {
                        records.add(record);
                    }
                }
                if (nextNl < 0) {
                    break;
                }
                pos = nextNl + 1;
            }
        }

        return new DecodedPayload(status, errno, malformedFlag[0], extraHeaders, records);
    }

    public static boolean decodeFlag(String value) {
        return "1".equals(value) || "true".equalsIgnoreCase(value);
    }

    private static Map<String, String> parseRecordLine(String line, boolean[] malformedFlag) {
        Map<String, String> fields = new LinkedHashMap<>();
        if (line == null || line.isEmpty()) {
            malformedFlag[0] = true;
            return fields;
        }
        int pos = 0;
        final int len = line.length();
        while (pos <= len) {
            int tab = line.indexOf('\t', pos);
            String segment = tab >= 0 ? line.substring(pos, tab) : line.substring(pos);
            if (segment.isEmpty()) {
                malformedFlag[0] = true;
            } else {
                int eq = segment.indexOf('=');
                if (eq <= 0) {
                    malformedFlag[0] = true;
                } else {
                    String key = segment.substring(0, eq);
                    if (!isValidKey(key)) {
                        malformedFlag[0] = true;
                    } else {
                        String rawVal = segment.substring(eq + 1);
                        fields.put(key, unescapeValue(rawVal));
                    }
                }
            }
            if (tab < 0) {
                break;
            }
            pos = tab + 1;
        }
        return fields;
    }
}
