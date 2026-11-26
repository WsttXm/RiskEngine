package com.wsttxm.riskenginesdk.attestation;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Zero-dependency strict ASN.1 DER reader and leaf certificate DER structural inspector.
 *
 * <p>Enforces minimal DER length/tag encoding and bounded TLV traversal so forged BER-encoded
 * attestation extensions or synthetic leaf certificates with 32-char pure-hex placeholder templates
 * are rejected deterministically without BouncyCastle or any third-party library.</p>
 */
public final class DerReader {

    public static final int CLASS_UNIVERSAL = 0;
    public static final int CLASS_APPLICATION = 1;
    public static final int CLASS_CONTEXT_SPECIFIC = 2;
    public static final int CLASS_PRIVATE = 3;

    public static final int TAG_BOOLEAN = 0x01;
    public static final int TAG_INTEGER = 0x02;
    public static final int TAG_BIT_STRING = 0x03;
    public static final int TAG_OCTET_STRING = 0x04;
    public static final int TAG_NULL = 0x05;
    public static final int TAG_OBJECT_IDENTIFIER = 0x06;
    public static final int TAG_ENUMERATED = 0x0A;
    public static final int TAG_UTF8_STRING = 0x0C;
    public static final int TAG_SEQUENCE = 0x10;
    public static final int TAG_SET = 0x11;

    private static final int MAX_DER_DEPTH = 40;
    private static final int MAX_TAG_BYTES = 5;

    private DerReader() {
    }

    public enum ErrorCode {
        EMPTY_INPUT,
        TRUNCATED,
        INVALID_TAG,
        NON_MINIMAL_TAG,
        INDEFINITE_LENGTH,
        LENGTH_TOO_LARGE,
        NON_MINIMAL_LENGTH,
        TRAILING_BYTES,
        MAX_DEPTH_EXCEEDED,
        TYPE_MISMATCH,
        INVALID_VALUE
    }

    public static final class DerException extends Exception {
        private static final long serialVersionUID = 1L;
        private final ErrorCode errorCode;

        public DerException(ErrorCode errorCode, String message) {
            super(message);
            this.errorCode = errorCode;
        }

        public ErrorCode getErrorCode() {
            return errorCode;
        }
    }

    public static final class DerElement {
        private final byte[] buffer;
        private final int tagClass;
        private final boolean constructed;
        private final int tagNumber;
        private final int firstTagByte;
        private final int encodedOffset;
        private final int encodedLength;
        private final int valueOffset;
        private final int valueLength;
        private final int depth;

        DerElement(
                byte[] buffer,
                int tagClass,
                boolean constructed,
                int tagNumber,
                int firstTagByte,
                int encodedOffset,
                int encodedLength,
                int valueOffset,
                int valueLength,
                int depth) {
            this.buffer = buffer;
            this.tagClass = tagClass;
            this.constructed = constructed;
            this.tagNumber = tagNumber;
            this.firstTagByte = firstTagByte;
            this.encodedOffset = encodedOffset;
            this.encodedLength = encodedLength;
            this.valueOffset = valueOffset;
            this.valueLength = valueLength;
            this.depth = depth;
        }

        public int getTagClass() {
            return tagClass;
        }

        public boolean isConstructed() {
            return constructed;
        }

        public int getTagNumber() {
            return tagNumber;
        }

        public int getFirstTagByte() {
            return firstTagByte;
        }

        public int getEncodedOffset() {
            return encodedOffset;
        }

        public int getEncodedLength() {
            return encodedLength;
        }

        public int getValueOffset() {
            return valueOffset;
        }

        public int getValueLength() {
            return valueLength;
        }

        public int getNextOffset() {
            return encodedOffset + encodedLength;
        }

        public boolean isUniversal(int expectedTagNumber) {
            return tagClass == CLASS_UNIVERSAL && tagNumber == expectedTagNumber;
        }

        public boolean isContextSpecific() {
            return tagClass == CLASS_CONTEXT_SPECIFIC;
        }

        public byte[] copyValueBytes() {
            return Arrays.copyOfRange(buffer, valueOffset, valueOffset + valueLength);
        }

        public byte[] copyEncodedBytes() {
            return Arrays.copyOfRange(buffer, encodedOffset, encodedOffset + encodedLength);
        }

        public BigInteger asBigInteger() throws DerException {
            if (tagClass != CLASS_UNIVERSAL
                    || (tagNumber != TAG_INTEGER && tagNumber != TAG_ENUMERATED)
                    || constructed) {
                throw new DerException(ErrorCode.TYPE_MISMATCH, "Expected INTEGER or ENUMERATED");
            }
            if (valueLength <= 0) {
                throw new DerException(ErrorCode.INVALID_VALUE, "Empty INTEGER/ENUMERATED value");
            }
            // DER minimal two's complement check: no redundant leading 0x00 or 0xFF
            if (valueLength > 1) {
                int b0 = buffer[valueOffset] & 0xFF;
                int b1 = buffer[valueOffset + 1] & 0xFF;
                if ((b0 == 0x00 && (b1 & 0x80) == 0) || (b0 == 0xFF && (b1 & 0x80) != 0)) {
                    throw new DerException(
                            ErrorCode.INVALID_VALUE, "Non-minimal DER INTEGER encoding");
                }
            }
            return new BigInteger(copyValueBytes());
        }

        private static final BigInteger MIN_INT = BigInteger.valueOf(Integer.MIN_VALUE);
        private static final BigInteger MAX_INT = BigInteger.valueOf(Integer.MAX_VALUE);
        private static final BigInteger MIN_LONG = BigInteger.valueOf(Long.MIN_VALUE);
        private static final BigInteger MAX_LONG = BigInteger.valueOf(Long.MAX_VALUE);

        public int asInt() throws DerException {
            BigInteger v = asBigInteger();
            if (v.compareTo(MIN_INT) < 0 || v.compareTo(MAX_INT) > 0) {
                throw new DerException(ErrorCode.INVALID_VALUE, "INTEGER out of 32-bit int range");
            }
            return v.intValue();
        }

        public long asLong() throws DerException {
            BigInteger v = asBigInteger();
            if (v.compareTo(MIN_LONG) < 0 || v.compareTo(MAX_LONG) > 0) {
                throw new DerException(ErrorCode.INVALID_VALUE, "INTEGER out of 64-bit long range");
            }
            return v.longValue();
        }

        public boolean asBoolean() throws DerException {
            if (!isUniversal(TAG_BOOLEAN) || constructed) {
                throw new DerException(ErrorCode.TYPE_MISMATCH, "Expected BOOLEAN");
            }
            if (valueLength != 1) {
                throw new DerException(ErrorCode.INVALID_VALUE, "BOOLEAN length must be 1");
            }
            int v = buffer[valueOffset] & 0xFF;
            if (v == 0x00) {
                return false;
            }
            if (v == 0xFF) {
                return true;
            }
            throw new DerException(
                    ErrorCode.INVALID_VALUE, "Non-canonical DER BOOLEAN byte: 0x" + Integer.toHexString(v));
        }

        public byte[] asOctetString() throws DerException {
            if (!isUniversal(TAG_OCTET_STRING) || constructed) {
                throw new DerException(ErrorCode.TYPE_MISMATCH, "Expected primitive OCTET STRING");
            }
            return copyValueBytes();
        }

        public String asOctetUtf8String() throws DerException {
            return new String(asOctetString(), StandardCharsets.UTF_8);
        }

        public List<DerElement> readChildren() throws DerException {
            if (!constructed) {
                throw new DerException(ErrorCode.TYPE_MISMATCH, "Expected constructed DER element");
            }
            if (depth >= MAX_DER_DEPTH) {
                throw new DerException(ErrorCode.MAX_DEPTH_EXCEEDED, "DER nesting limit exceeded");
            }
            List<DerElement> children = new ArrayList<>();
            int cursor = valueOffset;
            int end = valueOffset + valueLength;
            while (cursor < end) {
                DerElement child = parseElement(buffer, cursor, end, depth + 1, true);
                children.add(child);
                cursor = child.getNextOffset();
            }
            return children;
        }

        public DerElement readSingleChild() throws DerException {
            List<DerElement> children = readChildren();
            if (children.size() != 1) {
                throw new DerException(
                        ErrorCode.INVALID_VALUE,
                        "Expected single child inside tagged wrapper, got " + children.size());
            }
            return children.get(0);
        }
    }

    public static final class LeafDerInspection {
        private final boolean hexTemplate32Detected;
        private final boolean nonMinimalLengthDetected;
        private final boolean structureInvalid;
        private final List<String> findings;

        public LeafDerInspection(
                boolean hexTemplate32Detected,
                boolean nonMinimalLengthDetected,
                boolean structureInvalid,
                List<String> findings) {
            this.hexTemplate32Detected = hexTemplate32Detected;
            this.nonMinimalLengthDetected = nonMinimalLengthDetected;
            this.structureInvalid = structureInvalid;
            this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
        }

        public boolean isHexTemplate32Detected() {
            return hexTemplate32Detected;
        }

        public boolean isNonMinimalLengthDetected() {
            return nonMinimalLengthDetected;
        }

        public boolean isStructureInvalid() {
            return structureInvalid;
        }

        public boolean hasAnomaly() {
            return hexTemplate32Detected || nonMinimalLengthDetected || structureInvalid;
        }

        public List<String> getFindings() {
            return findings;
        }
    }

    /**
     * Parses exactly one strict DER TLV element from {@code data}; rejects trailing bytes.
     */
    public static DerElement parseSingle(byte[] data) throws DerException {
        if (data == null || data.length == 0) {
            throw new DerException(ErrorCode.EMPTY_INPUT, "DER input is null or empty");
        }
        DerElement element = parseElement(data, 0, data.length, 0, true);
        if (element.getNextOffset() != data.length) {
            throw new DerException(
                    ErrorCode.TRAILING_BYTES,
                    "Trailing bytes after DER element: " + (data.length - element.getNextOffset()));
        }
        return element;
    }

    /**
     * Unwraps a strict DER-encoded X.509 extension value (outer OCTET STRING) into its inner bytes.
     */
    public static byte[] unwrapOctetString(byte[] derExtensionValue) throws DerException {
        DerElement outer = parseSingle(derExtensionValue);
        return outer.asOctetString();
    }

    /**
     * Inspects raw X.509 leaf certificate DER bytes for structural anomalies:
     * <ul>
     *   <li>32-character pure-hex ASCII placeholder templates ({@code HEX_TEMPLATE_32})</li>
     *   <li>Non-minimal BER length encodings ({@code NON_MINIMAL_LENGTH})</li>
     *   <li>Invalid top-level SEQUENCE or truncated/overflowing TLV tree</li>
     * </ul>
     */
    public static LeafDerInspection inspectLeafDer(byte[] certDer) {
        List<String> findings = new ArrayList<>();
        if (certDer == null || certDer.length < 8) {
            findings.add("DER_MISSING");
            return new LeafDerInspection(false, false, true, findings);
        }

        // [0]=nonMinimalLength, [1]=structureInvalid, [2]=hexTemplate32
        boolean[] flags = new boolean[3];
        // Exclude X.509 TBSCertificate.issuer byte range [start, end) from HEX_TEMPLATE_32 matching
        // because genuine Google KeyMint/StrongBox Batch CAs use 32-hex Issuer serialNumber RDNs.
        int[] issuerRange = findX509IssuerRange(certDer);
        try {
            DerElement top = parseElement(certDer, 0, certDer.length, 0, false, flags);
            if (!top.isUniversal(TAG_SEQUENCE) || !top.isConstructed() || top.getNextOffset() != certDer.length) {
                flags[1] = true;
                findings.add("TOP_LEVEL_SEQUENCE_INVALID");
            } else {
                boolean treeOk = walkTreeForInspection(
                        certDer, top.getValueOffset(), top.getNextOffset(), 1, flags, issuerRange);
                if (!treeOk) {
                    flags[1] = true;
                    findings.add("DER_TREE_PARSE_FAILURE");
                }
            }
        } catch (DerException e) {
            if (e.getErrorCode() == ErrorCode.NON_MINIMAL_LENGTH
                    || e.getErrorCode() == ErrorCode.NON_MINIMAL_TAG) {
                flags[0] = true;
            } else {
                flags[1] = true;
                findings.add("TOP_LEVEL_SEQUENCE_INVALID");
            }
        }

        if (!flags[2] && scanAsciiHexTemplate32(certDer, issuerRange)) {
            flags[2] = true;
        }
        if (flags[2]) {
            findings.add("HEX_TEMPLATE_32");
        }
        if (flags[0] && !findings.contains("NON_MINIMAL_LENGTH")) {
            findings.add("NON_MINIMAL_LENGTH");
        }
        return new LeafDerInspection(flags[2], flags[0], flags[1], findings);
    }

    /**
     * Locates the byte range {@code [encodedOffset, nextOffset)} of {@code TBSCertificate.issuer}
     * inside an X.509 Certificate ({@code SEQUENCE { tbsCertificate SEQUENCE, sigAlg SEQUENCE,
     * sigValue BIT STRING }}). Returns {@code null} for non-X.509 synthetic DER inputs.
     */
    private static int[] findX509IssuerRange(byte[] certDer) {
        try {
            DerElement cert = parseElement(certDer, 0, certDer.length, 0, false, null);
            if (!cert.isUniversal(TAG_SEQUENCE) || !cert.isConstructed()
                    || cert.getNextOffset() != certDer.length) {
                return null;
            }
            // Verify 3-element X.509 Certificate shape: tbs (SEQ), sigAlg (SEQ), sigVal (BIT STRING)
            int cur = cert.getValueOffset();
            int end = cert.getNextOffset();
            DerElement tbs = parseElement(certDer, cur, end, 1, false, null);
            if (!tbs.isUniversal(TAG_SEQUENCE) || !tbs.isConstructed()) {
                return null;
            }
            cur = tbs.getNextOffset();
            if (cur >= end) {
                return null;
            }
            DerElement sigAlg = parseElement(certDer, cur, end, 1, false, null);
            if (!sigAlg.isUniversal(TAG_SEQUENCE) || !sigAlg.isConstructed()) {
                return null;
            }
            cur = sigAlg.getNextOffset();
            if (cur >= end) {
                return null;
            }
            DerElement sigVal = parseElement(certDer, cur, end, 1, false, null);
            if (!sigVal.isUniversal(TAG_BIT_STRING) || sigVal.isConstructed()
                    || sigVal.getNextOffset() != end) {
                return null;
            }

            // Inside TBSCertificate (RFC 5280 §4.1.2):
            //   version [0] EXPLICIT Version (INTEGER) OPTIONAL,
            //   serialNumber INTEGER, signature SEQUENCE, issuer SEQUENCE,
            //   validity SEQUENCE, subject SEQUENCE, subjectPublicKeyInfo SEQUENCE, ...
            int tbsCur = tbs.getValueOffset();
            int tbsEnd = tbs.getNextOffset();
            if (tbsCur >= tbsEnd) {
                return null;
            }
            DerElement field = parseElement(certDer, tbsCur, tbsEnd, 2, false, null);
            if (field.isContextSpecific() && field.isConstructed() && field.getTagNumber() == 0) {
                if (field.getValueLength() <= 0) {
                    return null;
                }
                DerElement verInt = parseElement(
                        certDer, field.getValueOffset(), field.getNextOffset(), 3, false, null);
                if (!verInt.isUniversal(TAG_INTEGER) || verInt.isConstructed()
                        || verInt.getNextOffset() != field.getNextOffset()) {
                    return null;
                }
                tbsCur = field.getNextOffset();
                if (tbsCur >= tbsEnd) {
                    return null;
                }
                field = parseElement(certDer, tbsCur, tbsEnd, 2, false, null);
            }
            // serialNumber: primitive INTEGER
            if (!field.isUniversal(TAG_INTEGER) || field.isConstructed()) {
                return null;
            }
            tbsCur = field.getNextOffset();
            if (tbsCur >= tbsEnd) {
                return null;
            }
            // signature: constructed SEQUENCE
            DerElement tbsSig = parseElement(certDer, tbsCur, tbsEnd, 2, false, null);
            if (!tbsSig.isUniversal(TAG_SEQUENCE) || !tbsSig.isConstructed()) {
                return null;
            }
            tbsCur = tbsSig.getNextOffset();
            if (tbsCur >= tbsEnd) {
                return null;
            }
            // issuer: constructed SEQUENCE
            DerElement issuer = parseElement(certDer, tbsCur, tbsEnd, 2, false, null);
            if (!issuer.isUniversal(TAG_SEQUENCE) || !issuer.isConstructed()) {
                return null;
            }
            int issuerStart = issuer.getEncodedOffset();
            int issuerEnd = issuer.getNextOffset();
            tbsCur = issuerEnd;
            if (tbsCur >= tbsEnd) {
                return null;
            }
            // validity: constructed SEQUENCE
            DerElement validity = parseElement(certDer, tbsCur, tbsEnd, 2, false, null);
            if (!validity.isUniversal(TAG_SEQUENCE) || !validity.isConstructed()) {
                return null;
            }
            tbsCur = validity.getNextOffset();
            if (tbsCur >= tbsEnd) {
                return null;
            }
            // subject: constructed SEQUENCE
            DerElement subject = parseElement(certDer, tbsCur, tbsEnd, 2, false, null);
            if (!subject.isUniversal(TAG_SEQUENCE) || !subject.isConstructed()) {
                return null;
            }
            tbsCur = subject.getNextOffset();
            if (tbsCur >= tbsEnd) {
                return null;
            }
            // subjectPublicKeyInfo: constructed SEQUENCE
            DerElement spki = parseElement(certDer, tbsCur, tbsEnd, 2, false, null);
            if (!spki.isUniversal(TAG_SEQUENCE) || !spki.isConstructed()) {
                return null;
            }
            return new int[]{issuerStart, issuerEnd};
        } catch (DerException ignored) {
            return null;
        }
    }

    private static boolean isInsideRange(int offset, int endOffset, int[] excludedRange) {
        return excludedRange != null
                && offset >= excludedRange[0]
                && endOffset <= excludedRange[1];
    }

    private static boolean walkTreeForInspection(
            byte[] data, int start, int end, int depth, boolean[] flags, int[] excludedRange) {
        if (depth > MAX_DER_DEPTH || start > end || end > data.length) {
            return false;
        }
        int cursor = start;
        while (cursor < end) {
            DerElement elem;
            try {
                elem = parseElement(data, cursor, end, depth, false, flags);
            } catch (DerException e) {
                return false;
            }
            if (elem.getNextOffset() > end || elem.getNextOffset() <= cursor) {
                return false;
            }
            if (!elem.isConstructed() && isHexTemplateCandidateTag(elem)
                    && elem.getValueLength() == 32
                    && !isInsideRange(elem.getEncodedOffset(), elem.getNextOffset(), excludedRange)
                    && isAllAsciiHex(data, elem.getValueOffset(), 32)) {
                flags[2] = true;
            }
            if (elem.isConstructed() && elem.getValueLength() > 0) {
                if (!walkTreeForInspection(
                        data, elem.getValueOffset(), elem.getNextOffset(),
                        depth + 1, flags, excludedRange)) {
                    return false;
                }
            }
            cursor = elem.getNextOffset();
        }
        return cursor == end;
    }

    private static boolean isHexTemplateCandidateTag(DerElement elem) {
        if (elem.getTagClass() != CLASS_UNIVERSAL) {
            return false;
        }
        int tag = elem.getTagNumber();
        return tag == TAG_OCTET_STRING
                || tag == TAG_UTF8_STRING
                || tag == 0x13 // PrintableString
                || tag == 0x14 // T61String
                || tag == 0x16 // IA5String
                || tag == 0x1A; // VisibleString
    }

    private static boolean isAllAsciiHex(byte[] data, int offset, int length) {
        for (int i = 0; i < length; i++) {
            if (!isHexDigit(data[offset + i] & 0xFF)) {
                return false;
            }
        }
        return true;
    }

    private static boolean scanAsciiHexTemplate32(byte[] bytes, int[] excludedRange) {
        int runLength = 0;
        boolean allHex = true;
        for (int i = 0; i < bytes.length; i++) {
            if (excludedRange != null && i >= excludedRange[0] && i < excludedRange[1]) {
                if (runLength == 32 && allHex) {
                    return true;
                }
                runLength = 0;
                allHex = true;
                continue;
            }
            int c = bytes[i] & 0xFF;
            // Exclude 0x20 (space) because DER length 32 encodes as 0x20 immediately before a
            // 32-byte ASCII hex placeholder value.
            if (c >= 0x21 && c <= 0x7E) {
                runLength++;
                if (!isHexDigit(c)) {
                    allHex = false;
                }
            } else {
                if (runLength == 32 && allHex) {
                    return true;
                }
                runLength = 0;
                allHex = true;
            }
        }
        return runLength == 32 && allHex;
    }

    private static boolean isHexDigit(int c) {
        return (c >= '0' && c <= '9')
                || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F');
    }

    private static DerElement parseElement(
            byte[] data, int offset, int end, int depth, boolean strict) throws DerException {
        return parseElement(data, offset, end, depth, strict, null);
    }

    private static DerElement parseElement(
            byte[] data,
            int offset,
            int end,
            int depth,
            boolean strict,
            boolean[] nonMinimalFlags) throws DerException {
        if (depth > MAX_DER_DEPTH) {
            throw new DerException(ErrorCode.MAX_DEPTH_EXCEEDED, "DER depth exceeded");
        }
        if (offset >= end) {
            throw new DerException(ErrorCode.TRUNCATED, "Unexpected end of DER input at tag");
        }

        int cursor = offset;
        int firstTag = data[cursor++] & 0xFF;
        int tagClass = (firstTag >>> 6) & 0x03;
        boolean constructed = (firstTag & 0x20) != 0;
        int tagNumber = firstTag & 0x1F;

        if (tagNumber == 0x1F) {
            tagNumber = 0;
            int tagBytes = 0;
            while (true) {
                if (cursor >= end) {
                    throw new DerException(ErrorCode.TRUNCATED, "Truncated high-tag-number");
                }
                int b = data[cursor++] & 0xFF;
                if (tagBytes == 0 && (b & 0x7F) == 0) {
                    if (strict) {
                        throw new DerException(
                                ErrorCode.NON_MINIMAL_TAG, "Non-minimal high-tag-number encoding");
                    }
                    if (nonMinimalFlags != null) {
                        nonMinimalFlags[0] = true;
                    }
                }
                tagBytes++;
                if (tagBytes > MAX_TAG_BYTES) {
                    throw new DerException(ErrorCode.INVALID_TAG, "ASN.1 tag number too large");
                }
                if (tagNumber > (Integer.MAX_VALUE >>> 7)) {
                    throw new DerException(ErrorCode.INVALID_TAG, "ASN.1 tag number overflow");
                }
                tagNumber = (tagNumber << 7) | (b & 0x7F);
                if ((b & 0x80) == 0) {
                    break;
                }
            }
            if (tagNumber < 31) {
                if (strict) {
                    throw new DerException(
                            ErrorCode.NON_MINIMAL_TAG, "High-tag form used for tag < 31");
                }
                if (nonMinimalFlags != null) {
                    nonMinimalFlags[0] = true;
                }
            }
        }

        if (cursor >= end) {
            throw new DerException(ErrorCode.TRUNCATED, "Truncated DER length byte");
        }

        int lenByte = data[cursor++] & 0xFF;
        int valueLength;
        if ((lenByte & 0x80) == 0) {
            valueLength = lenByte;
        } else {
            int lenOctets = lenByte & 0x7F;
            if (lenOctets == 0) {
                throw new DerException(ErrorCode.INDEFINITE_LENGTH, "Indefinite BER length rejected");
            }
            if (lenOctets > 4) {
                throw new DerException(
                        ErrorCode.LENGTH_TOO_LARGE, "DER length exceeds 4 octets: " + lenOctets);
            }
            if (end - cursor < lenOctets) {
                throw new DerException(ErrorCode.TRUNCATED, "Truncated long-form DER length");
            }
            int firstLenOctet = data[cursor] & 0xFF;
            long acc = 0;
            for (int i = 0; i < lenOctets; i++) {
                acc = (acc << 8) | (data[cursor++] & 0xFF);
            }
            if (acc > Integer.MAX_VALUE) {
                throw new DerException(ErrorCode.LENGTH_TOO_LARGE, "DER length exceeds 31-bit int");
            }
            valueLength = (int) acc;
            if (firstLenOctet == 0x00 || valueLength <= 0x7F) {
                if (strict) {
                    throw new DerException(
                            ErrorCode.NON_MINIMAL_LENGTH,
                            "Non-minimal BER length encoding (valueLength=" + valueLength + ")");
                }
                if (nonMinimalFlags != null) {
                    nonMinimalFlags[0] = true;
                }
            }
        }

        int valueOffset = cursor;
        if (valueLength < 0 || valueLength > end - valueOffset) {
            throw new DerException(
                    ErrorCode.TRUNCATED,
                    "DER TLV value overflows buffer: need " + valueLength + ", remain " + (end - valueOffset));
        }

        int encodedLength = (valueOffset - offset) + valueLength;
        return new DerElement(
                data,
                tagClass,
                constructed,
                tagNumber,
                firstTag,
                offset,
                encodedLength,
                valueOffset,
                valueLength,
                depth);
    }
}
