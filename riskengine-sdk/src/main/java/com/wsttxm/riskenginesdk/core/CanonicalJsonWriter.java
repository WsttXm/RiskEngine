package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.attestation.AttestationRecord;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Deterministic UTF-8 canonical JSON serializer (RFC 8785 / Python
 * {@code json.dumps(..., sort_keys=True, separators=(',', ':'), ensure_ascii=False)} compatible).
 *
 * <p>Guarantees:
 * <ul>
 *   <li>All object/map keys are sorted recursively by Unicode code-point order.</li>
 *   <li>Zero insignificant whitespace ({@code ','} and {@code ':'} separators only).</li>
 *   <li>Strict RFC 8259 string escaping without escaping {@code '/'} so output bytes match
 *       Python/Node/Go canonical serializers bit-for-bit.</li>
 *   <li>Rejects non-finite floating-point numbers ({@code NaN} / {@code Infinity}).</li>
 * </ul></p>
 */
public final class CanonicalJsonWriter {

    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    private static final Comparator<String> CODE_POINT_KEY_COMPARATOR = new Comparator<String>() {
        @Override
        public int compare(String a, String b) {
            int i = 0;
            int lenA = a.length();
            int lenB = b.length();
            while (i < lenA && i < lenB) {
                int cpA = a.codePointAt(i);
                int cpB = b.codePointAt(i);
                if (cpA != cpB) {
                    return Integer.compare(cpA, cpB);
                }
                i += Character.charCount(cpA);
            }
            return Integer.compare(lenA, lenB);
        }
    };

    private CanonicalJsonWriter() {
    }

    /** Serializes {@code value} into a deterministic canonical JSON string. */
    public static String toCanonicalJson(Object value) {
        StringBuilder sb = new StringBuilder(256);
        writeValue(sb, value);
        return sb.toString();
    }

    /** Serializes {@code value} into deterministic canonical UTF-8 bytes. */
    public static byte[] toCanonicalUtf8Bytes(Object value) {
        return toCanonicalJson(value).getBytes(StandardCharsets.UTF_8);
    }

    /** Returns the 64-char lowercase hex SHA-256 digest of {@code value}'s canonical UTF-8 JSON. */
    public static String sha256HexOfCanonicalJson(Object value) {
        byte[] utf8 = toCanonicalUtf8Bytes(value);
        return sha256Hex(utf8);
    }

    public static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return AttestationRecord.toLowerHex(md.digest(data == null ? new byte[0] : data));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static void writeValue(StringBuilder sb, Object value) {
        if (value == null || value == JSONObject.NULL) {
            sb.append("null");
            return;
        }
        if (value instanceof Boolean) {
            sb.append(((Boolean) value) ? "true" : "false");
            return;
        }
        if (value instanceof String) {
            writeEscapedString(sb, (String) value);
            return;
        }
        if (value instanceof Integer
                || value instanceof Long
                || value instanceof Short
                || value instanceof Byte
                || value instanceof AtomicInteger
                || value instanceof AtomicLong) {
            sb.append(((Number) value).longValue());
            return;
        }
        if (value instanceof BigInteger) {
            sb.append(value.toString());
            return;
        }
        if (value instanceof Number) {
            double d = ((Number) value).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("Non-finite JSON number: " + value);
            }
            if (d == Math.rint(d)
                    && d >= -9223372036854775808.0
                    && d < 9223372036854775808.0) {
                sb.append((long) d);
            } else {
                sb.append(value.toString());
            }
            return;
        }
        if (value instanceof JSONObject) {
            writeJsonObject(sb, (JSONObject) value);
            return;
        }
        if (value instanceof Map<?, ?>) {
            writeMap(sb, (Map<?, ?>) value);
            return;
        }
        if (value instanceof JSONArray) {
            writeJsonArray(sb, (JSONArray) value);
            return;
        }
        if (value instanceof Collection<?>) {
            writeCollection(sb, (Collection<?>) value);
            return;
        }
        if (value.getClass().isArray()) {
            writePrimitiveOrObjectArray(sb, value);
            return;
        }
        if (value instanceof Enum<?>) {
            writeEscapedString(sb, ((Enum<?>) value).name());
            return;
        }
        throw new IllegalArgumentException(
                "Unsupported canonical JSON value type: " + value.getClass().getName());
    }

    private static void writeJsonObject(StringBuilder sb, JSONObject obj) {
        List<String> keys = new ArrayList<>();
        Iterator<String> it = obj.keys();
        while (it.hasNext()) {
            String k = it.next();
            if (k != null) {
                keys.add(k);
            }
        }
        Collections.sort(keys, CODE_POINT_KEY_COMPARATOR);
        sb.append('{');
        for (int i = 0; i < keys.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            String k = keys.get(i);
            writeEscapedString(sb, k);
            sb.append(':');
            try {
                Object v = obj.isNull(k) ? JSONObject.NULL : obj.get(k);
                writeValue(sb, v);
            } catch (JSONException e) {
                throw new IllegalStateException("Failed reading JSONObject key: " + k, e);
            }
        }
        sb.append('}');
    }

    private static void writeMap(StringBuilder sb, Map<?, ?> map) {
        List<String> keys = new ArrayList<>(map.size());
        for (Object rawKey : map.keySet()) {
            if (rawKey == null) {
                throw new IllegalArgumentException("Canonical JSON map key must not be null");
            }
            if (!(rawKey instanceof String)) {
                throw new IllegalArgumentException(
                        "Canonical JSON map key must be String: " + rawKey.getClass().getName());
            }
            keys.add((String) rawKey);
        }
        Collections.sort(keys, CODE_POINT_KEY_COMPARATOR);
        sb.append('{');
        for (int i = 0; i < keys.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            String k = keys.get(i);
            writeEscapedString(sb, k);
            sb.append(':');
            writeValue(sb, map.get(k));
        }
        sb.append('}');
    }

    private static void writeJsonArray(StringBuilder sb, JSONArray arr) {
        sb.append('[');
        int len = arr.length();
        for (int i = 0; i < len; i++) {
            if (i > 0) {
                sb.append(',');
            }
            try {
                Object v = arr.isNull(i) ? JSONObject.NULL : arr.get(i);
                writeValue(sb, v);
            } catch (JSONException e) {
                throw new IllegalStateException("Failed reading JSONArray index: " + i, e);
            }
        }
        sb.append(']');
    }

    private static void writeCollection(StringBuilder sb, Collection<?> col) {
        sb.append('[');
        int i = 0;
        for (Object item : col) {
            if (i++ > 0) {
                sb.append(',');
            }
            writeValue(sb, item);
        }
        sb.append(']');
    }

    private static void writePrimitiveOrObjectArray(StringBuilder sb, Object arrayObj) {
        sb.append('[');
        int len = Array.getLength(arrayObj);
        for (int i = 0; i < len; i++) {
            if (i > 0) {
                sb.append(',');
            }
            writeValue(sb, Array.get(arrayObj, i));
        }
        sb.append(']');
    }

    private static void writeEscapedString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append("\\u00");
                        sb.append(HEX_DIGITS[(c >>> 4) & 0x0F]);
                        sb.append(HEX_DIGITS[c & 0x0F]);
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        sb.append('"');
    }
}
