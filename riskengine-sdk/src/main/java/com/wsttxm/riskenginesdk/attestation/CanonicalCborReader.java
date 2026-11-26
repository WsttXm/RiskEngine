package com.wsttxm.riskenginesdk.attestation;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Zero-dependency strict canonical CBOR (RFC 8949 deterministic encoding) decoder.
 *
 * <p>Designed for RKP provisioning-info extension decoding (OID {@code 1.3.6.1.4.1.11129.2.1.30}).
 * Strictly rejects indefinite-length items, non-canonical integer/length encodings, duplicate map
 * keys, invalid UTF-8 text strings, excessive nesting, and trailing bytes.</p>
 */
public final class CanonicalCborReader {

    public static final int MAX_DEPTH = 32;
    public static final int MAX_ITEMS = 4096;

    private CanonicalCborReader() {
    }

    public enum ErrorCode {
        EMPTY_INPUT,
        TRUNCATED,
        INDEFINITE_LENGTH,
        RESERVED_ADDITIONAL_INFO,
        NON_CANONICAL_INT,
        INTEGER_OVERFLOW,
        INVALID_UTF8,
        DUPLICATE_MAP_KEY,
        TRAILING_BYTES,
        MAX_DEPTH_EXCEEDED,
        MAX_ITEMS_EXCEEDED,
        UNSUPPORTED_SIMPLE
    }

    public static final class CborException extends Exception {
        private static final long serialVersionUID = 1L;
        private final ErrorCode errorCode;

        public CborException(ErrorCode errorCode, String message) {
            super(message);
            this.errorCode = errorCode;
        }

        public ErrorCode getErrorCode() {
            return errorCode;
        }
    }

    public enum ValueType {
        INTEGER,
        BYTE_STRING,
        TEXT_STRING,
        ARRAY,
        MAP,
        BOOLEAN,
        NULL,
        FLOAT
    }

    public static final class CborValue {
        private final ValueType type;
        private final boolean tagged;
        private final long tagNumber;
        private final long intValue;
        private final byte[] bytesValue;
        private final String textValue;
        private final List<CborValue> arrayValue;
        private final Map<CborValue, CborValue> mapValue;
        private final boolean boolValue;
        private final double floatValue;

        private CborValue(
                ValueType type,
                boolean tagged,
                long tagNumber,
                long intValue,
                byte[] bytesValue,
                String textValue,
                List<CborValue> arrayValue,
                Map<CborValue, CborValue> mapValue,
                boolean boolValue,
                double floatValue) {
            this.type = type;
            this.tagged = tagged;
            this.tagNumber = tagNumber;
            this.intValue = intValue;
            this.bytesValue = bytesValue;
            this.textValue = textValue;
            this.arrayValue = arrayValue;
            this.mapValue = mapValue;
            this.boolValue = boolValue;
            this.floatValue = floatValue;
        }

        public static CborValue ofInt(long value) {
            return new CborValue(ValueType.INTEGER, false, -1L, value, null, null, null, null, false, 0.0);
        }

        static CborValue ofBytes(byte[] value) {
            return new CborValue(ValueType.BYTE_STRING, false, -1L, 0L, value, null, null, null, false, 0.0);
        }

        public static CborValue ofText(String value) {
            return new CborValue(ValueType.TEXT_STRING, false, -1L, 0L, null, value, null, null, false, 0.0);
        }

        static CborValue ofArray(List<CborValue> items) {
            return new CborValue(
                    ValueType.ARRAY, false, -1L, 0L, null, null, Collections.unmodifiableList(items), null, false, 0.0);
        }

        static CborValue ofMap(Map<CborValue, CborValue> entries) {
            return new CborValue(
                    ValueType.MAP, false, -1L, 0L, null, null, null, Collections.unmodifiableMap(entries), false, 0.0);
        }

        static CborValue ofBoolean(boolean value) {
            return new CborValue(ValueType.BOOLEAN, false, -1L, 0L, null, null, null, null, value, 0.0);
        }

        static CborValue ofNull() {
            return new CborValue(ValueType.NULL, false, -1L, 0L, null, null, null, null, false, 0.0);
        }

        static CborValue ofFloat(double value) {
            return new CborValue(ValueType.FLOAT, false, -1L, 0L, null, null, null, null, false, value);
        }

        CborValue withTag(long tag) {
            return new CborValue(
                    type, true, tag, intValue, bytesValue, textValue, arrayValue, mapValue, boolValue, floatValue);
        }

        public ValueType getType() {
            return type;
        }

        public boolean isTagged() {
            return tagged;
        }

        public long getTagNumber() {
            return tagNumber;
        }

        public long asLong() {
            return intValue;
        }

        public byte[] asBytes() {
            return bytesValue == null ? null : Arrays.copyOf(bytesValue, bytesValue.length);
        }

        public String asText() {
            return textValue;
        }

        public List<CborValue> asArray() {
            return arrayValue;
        }

        public Map<CborValue, CborValue> asMap() {
            return mapValue;
        }

        public boolean asBoolean() {
            return boolValue;
        }

        public double asDouble() {
            return floatValue;
        }

        public CborValue getMapValue(long intKey) {
            if (type != ValueType.MAP || mapValue == null) {
                return null;
            }
            return mapValue.get(ofInt(intKey));
        }

        public String toDiagnosticString(int maxChars) {
            StringBuilder sb = new StringBuilder();
            appendDiagnostic(sb, 0, maxChars);
            return sb.toString();
        }

        private void appendDiagnostic(StringBuilder sb, int depth, int maxChars) {
            if (sb.length() >= maxChars) {
                return;
            }
            if (depth > MAX_DEPTH) {
                sb.append("...");
                return;
            }
            if (tagged) {
                sb.append(tagNumber).append('(');
            }
            switch (type) {
                case INTEGER:
                    sb.append(intValue);
                    break;
                case BYTE_STRING:
                    sb.append("h'");
                    if (bytesValue != null) {
                        for (byte b : bytesValue) {
                            if (sb.length() >= maxChars) {
                                break;
                            }
                            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
                            sb.append(Character.forDigit(b & 0xF, 16));
                        }
                    }
                    sb.append('\'');
                    break;
                case TEXT_STRING: {
                    sb.append('"');
                    if (textValue != null) {
                        int remaining = maxChars - sb.length();
                        if (remaining > 0) {
                            if (textValue.length() > remaining) {
                                sb.append(textValue, 0, remaining);
                            } else {
                                sb.append(textValue);
                            }
                        }
                    }
                    if (sb.length() < maxChars) {
                        sb.append('"');
                    }
                    break;
                }
                case ARRAY:
                    sb.append('[');
                    if (arrayValue != null) {
                        for (int i = 0; i < arrayValue.size() && sb.length() < maxChars; i++) {
                            if (i > 0) {
                                sb.append(", ");
                            }
                            arrayValue.get(i).appendDiagnostic(sb, depth + 1, maxChars);
                        }
                    }
                    sb.append(']');
                    break;
                case MAP:
                    sb.append('{');
                    if (mapValue != null) {
                        boolean first = true;
                        for (Map.Entry<CborValue, CborValue> e : mapValue.entrySet()) {
                            if (sb.length() >= maxChars) {
                                break;
                            }
                            if (!first) {
                                sb.append(", ");
                            }
                            first = false;
                            e.getKey().appendDiagnostic(sb, depth + 1, maxChars);
                            sb.append(": ");
                            e.getValue().appendDiagnostic(sb, depth + 1, maxChars);
                        }
                    }
                    sb.append('}');
                    break;
                case BOOLEAN:
                    sb.append(boolValue);
                    break;
                case NULL:
                    sb.append("null");
                    break;
                case FLOAT:
                    sb.append(floatValue);
                    break;
                default:
                    sb.append("?");
            }
            if (tagged) {
                sb.append(')');
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof CborValue)) {
                return false;
            }
            CborValue other = (CborValue) o;
            if (type != other.type || tagged != other.tagged || tagNumber != other.tagNumber) {
                return false;
            }
            switch (type) {
                case INTEGER:
                    return intValue == other.intValue;
                case BYTE_STRING:
                    return Arrays.equals(bytesValue, other.bytesValue);
                case TEXT_STRING:
                    return Objects.equals(textValue, other.textValue);
                case ARRAY:
                    return Objects.equals(arrayValue, other.arrayValue);
                case MAP:
                    return Objects.equals(mapValue, other.mapValue);
                case BOOLEAN:
                    return boolValue == other.boolValue;
                case NULL:
                    return true;
                case FLOAT:
                    return Double.doubleToLongBits(floatValue) == Double.doubleToLongBits(other.floatValue);
                default:
                    return false;
            }
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(type, tagged, tagNumber);
            switch (type) {
                case INTEGER:
                    return 31 * result + Long.hashCode(intValue);
                case BYTE_STRING:
                    return 31 * result + Arrays.hashCode(bytesValue);
                case TEXT_STRING:
                    return 31 * result + Objects.hashCode(textValue);
                case ARRAY:
                    return 31 * result + Objects.hashCode(arrayValue);
                case MAP:
                    return 31 * result + Objects.hashCode(mapValue);
                case BOOLEAN:
                    return 31 * result + Boolean.hashCode(boolValue);
                case NULL:
                    return result;
                case FLOAT:
                    return 31 * result + Long.hashCode(Double.doubleToLongBits(floatValue));
                default:
                    return result;
            }
        }
    }

    /**
     * Strictly parses a single canonical CBOR value from {@code bytes}, rejecting trailing data.
     */
    public static CborValue parse(byte[] bytes) throws CborException {
        if (bytes == null || bytes.length == 0) {
            throw new CborException(ErrorCode.EMPTY_INPUT, "CBOR input is null or empty");
        }
        Cursor cursor = new Cursor(bytes);
        CborValue value = readItem(cursor, 0);
        if (cursor.offset != bytes.length) {
            throw new CborException(
                    ErrorCode.TRAILING_BYTES,
                    "Trailing CBOR bytes: " + (bytes.length - cursor.offset));
        }
        return value;
    }

    private static final class Cursor {
        final byte[] data;
        int offset;
        int itemCount;

        Cursor(byte[] data) {
            this.data = data;
        }

        int readByte() throws CborException {
            if (offset >= data.length) {
                throw new CborException(ErrorCode.TRUNCATED, "Unexpected end of CBOR input");
            }
            return data[offset++] & 0xFF;
        }

        byte[] readSlice(int length) throws CborException {
            if (length < 0 || length > data.length - offset) {
                throw new CborException(
                        ErrorCode.TRUNCATED,
                        "CBOR slice exceeds buffer: need " + length + ", remain " + (data.length - offset));
            }
            byte[] out = Arrays.copyOfRange(data, offset, offset + length);
            offset += length;
            return out;
        }

        void countItem() throws CborException {
            itemCount++;
            if (itemCount > MAX_ITEMS) {
                throw new CborException(ErrorCode.MAX_ITEMS_EXCEEDED, "CBOR item count limit exceeded");
            }
        }
    }

    private static CborValue readItem(Cursor cursor, int depth) throws CborException {
        if (depth > MAX_DEPTH) {
            throw new CborException(ErrorCode.MAX_DEPTH_EXCEEDED, "CBOR nesting depth exceeded");
        }
        cursor.countItem();

        int initial = cursor.readByte();
        int major = (initial >>> 5) & 0x07;
        int ai = initial & 0x1F;

        switch (major) {
            case 0: {
                long uval = readCanonicalUint(cursor, ai);
                if (uval < 0) {
                    throw new CborException(
                            ErrorCode.INTEGER_OVERFLOW, "Unsigned CBOR integer exceeds signed 64-bit");
                }
                return CborValue.ofInt(uval);
            }
            case 1: {
                long uval = readCanonicalUint(cursor, ai);
                if (uval < 0) {
                    throw new CborException(
                            ErrorCode.INTEGER_OVERFLOW, "Negative CBOR integer underflows signed 64-bit");
                }
                return CborValue.ofInt(-1L - uval);
            }
            case 2: {
                int len = readCanonicalLength(cursor, ai);
                return CborValue.ofBytes(cursor.readSlice(len));
            }
            case 3: {
                int len = readCanonicalLength(cursor, ai);
                byte[] utf8 = cursor.readSlice(len);
                return CborValue.ofText(decodeStrictUtf8(utf8));
            }
            case 4: {
                int count = readCanonicalLength(cursor, ai);
                if (count > MAX_ITEMS) {
                    throw new CborException(ErrorCode.MAX_ITEMS_EXCEEDED, "CBOR array too large");
                }
                List<CborValue> list = new ArrayList<>(Math.min(count, 64));
                for (int i = 0; i < count; i++) {
                    list.add(readItem(cursor, depth + 1));
                }
                return CborValue.ofArray(list);
            }
            case 5: {
                int count = readCanonicalLength(cursor, ai);
                if (count > MAX_ITEMS) {
                    throw new CborException(ErrorCode.MAX_ITEMS_EXCEEDED, "CBOR map too large");
                }
                Map<CborValue, CborValue> map = new LinkedHashMap<>(Math.min(count, 64));
                for (int i = 0; i < count; i++) {
                    CborValue key = readItem(cursor, depth + 1);
                    CborValue val = readItem(cursor, depth + 1);
                    if (map.containsKey(key)) {
                        throw new CborException(
                                ErrorCode.DUPLICATE_MAP_KEY,
                                "Duplicate CBOR map key: " + key.toDiagnosticString(64));
                    }
                    map.put(key, val);
                }
                return CborValue.ofMap(map);
            }
            case 6: {
                long tag = readCanonicalUint(cursor, ai);
                CborValue inner = readItem(cursor, depth + 1);
                return inner.withTag(tag);
            }
            case 7: {
                return readSimpleOrFloat(cursor, ai);
            }
            default:
                throw new CborException(ErrorCode.UNSUPPORTED_SIMPLE, "Unknown CBOR major type");
        }
    }

    private static long readCanonicalUint(Cursor cursor, int ai) throws CborException {
        if (ai < 24) {
            return ai;
        }
        if (ai == 24) {
            long val = cursor.readByte();
            if (val < 24L) {
                throw new CborException(
                        ErrorCode.NON_CANONICAL_INT,
                        "Non-canonical 1-byte CBOR integer: " + val);
            }
            return val;
        }
        if (ai == 25) {
            long val = ((long) cursor.readByte() << 8) | cursor.readByte();
            if (val <= 0xFFL) {
                throw new CborException(
                        ErrorCode.NON_CANONICAL_INT,
                        "Non-canonical 2-byte CBOR integer: " + val);
            }
            return val;
        }
        if (ai == 26) {
            long val = ((long) cursor.readByte() << 24)
                    | ((long) cursor.readByte() << 16)
                    | ((long) cursor.readByte() << 8)
                    | cursor.readByte();
            if (val <= 0xFFFFL) {
                throw new CborException(
                        ErrorCode.NON_CANONICAL_INT,
                        "Non-canonical 4-byte CBOR integer: " + val);
            }
            return val;
        }
        if (ai == 27) {
            long val = 0L;
            for (int i = 0; i < 8; i++) {
                val = (val << 8) | cursor.readByte();
            }
            if (Long.compareUnsigned(val, 0xFFFFFFFFL) <= 0) {
                throw new CborException(
                        ErrorCode.NON_CANONICAL_INT,
                        "Non-canonical 8-byte CBOR integer: " + val);
            }
            return val;
        }
        if (ai == 31) {
            throw new CborException(
                    ErrorCode.INDEFINITE_LENGTH, "Indefinite-length CBOR item is not allowed");
        }
        throw new CborException(
                ErrorCode.RESERVED_ADDITIONAL_INFO, "Reserved CBOR additional info: " + ai);
    }

    private static int readCanonicalLength(Cursor cursor, int ai) throws CborException {
        long len = readCanonicalUint(cursor, ai);
        if (len < 0 || len > Integer.MAX_VALUE) {
            throw new CborException(ErrorCode.INTEGER_OVERFLOW, "CBOR length out of int range");
        }
        return (int) len;
    }

    private static CborValue readSimpleOrFloat(Cursor cursor, int ai) throws CborException {
        if (ai == 20) {
            return CborValue.ofBoolean(false);
        }
        if (ai == 21) {
            return CborValue.ofBoolean(true);
        }
        if (ai == 22 || ai == 23) {
            return CborValue.ofNull();
        }
        if (ai == 25) {
            int half = (cursor.readByte() << 8) | cursor.readByte();
            return CborValue.ofFloat(decodeHalfFloat(half));
        }
        if (ai == 26) {
            int bits = (cursor.readByte() << 24)
                    | (cursor.readByte() << 16)
                    | (cursor.readByte() << 8)
                    | cursor.readByte();
            return CborValue.ofFloat(Float.intBitsToFloat(bits));
        }
        if (ai == 27) {
            long bits = 0L;
            for (int i = 0; i < 8; i++) {
                bits = (bits << 8) | cursor.readByte();
            }
            return CborValue.ofFloat(Double.longBitsToDouble(bits));
        }
        if (ai == 31) {
            throw new CborException(ErrorCode.INDEFINITE_LENGTH, "Unexpected CBOR break code");
        }
        throw new CborException(
                ErrorCode.UNSUPPORTED_SIMPLE, "Unsupported CBOR simple value ai=" + ai);
    }

    private static double decodeHalfFloat(int half) {
        int exp = (half >>> 10) & 0x1F;
        int mant = half & 0x03FF;
        double val;
        if (exp == 0) {
            val = Math.scalb((double) mant, -24);
        } else if (exp != 31) {
            val = Math.scalb((double) (mant + 1024), exp - 25);
        } else {
            val = (mant == 0) ? Double.POSITIVE_INFINITY : Double.NaN;
        }
        return (half & 0x8000) != 0 ? -val : val;
    }

    private static String decodeStrictUtf8(byte[] bytes) throws CborException {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new CborException(ErrorCode.INVALID_UTF8, "Invalid UTF-8 in CBOR text string");
        }
    }
}
