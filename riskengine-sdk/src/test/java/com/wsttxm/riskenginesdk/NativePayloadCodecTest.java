package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class NativePayloadCodecTest {

    @Test
    public void escapeAndUnescapeRoundTripAllSpecialCharacters() {
        String[] samples = {
                "",
                "plain_ascii_123",
                "/data/app/~~abc==/com.foo,bar-1/lib/arm64/libtest.so",
                "a,b,c\td\ne\rf=g\\h",
                "\\\\n\\t\\r\\=already_escaped_looking",
                "===\t\t\t\n\n\r\r\\\\\\",
                "key=val=1,2\tcol2=3\nline2",
                "中文路径/带,逗号=和\\反斜杠"
        };
        for (String sample : samples) {
            String encoded = NativePayloadCodec.escapeValue(sample);
            assertFalse("Encoded value must not contain raw tab: " + encoded,
                    encoded.contains("\t"));
            assertFalse("Encoded value must not contain raw LF: " + encoded,
                    encoded.contains("\n"));
            assertFalse("Encoded value must not contain raw CR: " + encoded,
                    encoded.contains("\r"));
            // Every '=' in encoded output must be immediately preceded by an odd number of '\'.
            for (int i = 0; i < encoded.length(); i++) {
                if (encoded.charAt(i) == '=') {
                    int slashes = 0;
                    for (int j = i - 1; j >= 0 && encoded.charAt(j) == '\\'; j--) {
                        slashes++;
                    }
                    assertEquals("Unescaped '=' found in: " + encoded, 1, slashes % 2);
                }
            }
            assertEquals("Round-trip mismatch for sample: " + sample,
                    sample, NativePayloadCodec.unescapeValue(encoded));
        }
    }

    @Test
    public void singlePassUnescapeDoesNotDoubleDecodeBackslashN() {
        // Raw string "\n" (two chars: backslash + 'n') encodes to "\\n" (three chars).
        String literalBackslashN = "\\n";
        String encoded = NativePayloadCodec.escapeValue(literalBackslashN);
        assertEquals("\\\\n", encoded);
        assertEquals(literalBackslashN, NativePayloadCodec.unescapeValue(encoded));
    }

    @Test
    public void payloadRoundTripWithStatusErrnoHeadersAndStructuredRecords() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("probe", "self_integrity");
        headers.put("empty_hdr", "");
        headers.put("maps_path", "/data/app/~~x==/com.example,app/base.apk!/lib/arm64-v8a/libriskengine.so");

        Map<String, String> rec1 = new LinkedHashMap<>();
        rec1.put("code", "text_tampered");
        rec1.put("location", "/system/lib64/libc.so");
        rec1.put("value", "sha256=deadbeef\texpected=cafebabe\nline2\r\nend\\tail");

        Map<String, String> rec2 = new LinkedHashMap<>();
        rec2.put("code", "empty_val_case");
        rec2.put("value", "");
        rec2.put("commas", "a,b,c");

        String wire = NativePayloadCodec.encodePayload(
                NativePayloadCodec.Status.OK, 0, headers, Arrays.asList(rec1, rec2));

        NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(wire);
        assertTrue(decoded.isOk());
        assertFalse(decoded.isMalformed());
        assertEquals(NativePayloadCodec.Status.OK, decoded.getStatus());
        assertEquals(0, decoded.getErrno());
        assertEquals("self_integrity", decoded.getHeaderField("probe"));
        assertEquals("", decoded.getHeaderField("empty_hdr"));
        assertEquals(headers.get("maps_path"), decoded.getHeaderField("maps_path"));
        assertEquals(2, decoded.getRecords().size());
        assertEquals(rec1, decoded.getRecords().get(0));
        assertEquals(rec2, decoded.getRecords().get(1));
    }

    @Test
    public void payloadSupportsAllStatusCodesAndErrno() {
        for (NativePayloadCodec.Status status : NativePayloadCodec.Status.values()) {
            String wire = NativePayloadCodec.encodePayload(
                    status, 13, Collections.singletonMap("reason", "selinux=denied"), null);
            NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(wire);
            assertEquals(status, decoded.getStatus());
            assertEquals(13, decoded.getErrno());
            assertFalse(decoded.isMalformed());
            assertEquals("selinux=denied", decoded.getHeaderField("reason"));
            assertTrue(decoded.getRecords().isEmpty());
        }
    }

    @Test
    public void malformedInputsNeverThrowAndReportMalformedFlag() {
        NativePayloadCodec.DecodedPayload nullPayload = NativePayloadCodec.decodePayload(null);
        assertEquals(NativePayloadCodec.Status.ERROR, nullPayload.getStatus());
        assertTrue(nullPayload.isMalformed());
        assertFalse(nullPayload.isOk());

        NativePayloadCodec.DecodedPayload emptyPayload = NativePayloadCodec.decodePayload("");
        assertEquals(NativePayloadCodec.Status.ERROR, emptyPayload.getStatus());
        assertTrue(emptyPayload.isMalformed());

        NativePayloadCodec.DecodedPayload garbage = NativePayloadCodec.decodePayload("no_equals_at_all");
        assertEquals(NativePayloadCodec.Status.ERROR, garbage.getStatus());
        assertTrue(garbage.isMalformed());

        NativePayloadCodec.DecodedPayload badStatus =
                NativePayloadCodec.decodePayload("status=BOGUS\terrno=notanint\tfoo=bar");
        assertEquals(NativePayloadCodec.Status.ERROR, badStatus.getStatus());
        assertEquals(0, badStatus.getErrno());
        assertTrue(badStatus.isMalformed());
        assertEquals("bar", badStatus.getHeaderField("foo"));

        // Trailing lone backslash and unknown escape sequence preserved verbatim without throwing.
        assertEquals("abc\\", NativePayloadCodec.unescapeValue("abc\\"));
        assertEquals("a\\xb", NativePayloadCodec.unescapeValue("a\\xb"));

        // Malformed record segment & trailing empty line do not crash and still parse valid fields.
        NativePayloadCodec.DecodedPayload partial = NativePayloadCodec.decodePayload(
                "status=OK\terrno=0\nvalid=1\tbadsegment\t=emptykey\tok=yes\n");
        assertEquals(NativePayloadCodec.Status.OK, partial.getStatus());
        assertTrue(partial.isMalformed());
        assertFalse(partial.isOk());
        assertEquals(1, partial.getRecords().size());
        assertEquals("1", partial.getRecords().get(0).get("valid"));
        assertEquals("yes", partial.getRecords().get(0).get("ok"));
    }

    @Test
    public void invalidKeyRejectedOnEncodeAndDecodeFlagSemantics() {
        Map<String, String> badKey = Collections.singletonMap("bad=key", "val");
        assertThrows(IllegalArgumentException.class, () -> NativePayloadCodec.encodeRecord(badKey));

        assertTrue(NativePayloadCodec.decodeFlag("1"));
        assertTrue(NativePayloadCodec.decodeFlag("true"));
        assertTrue(NativePayloadCodec.decodeFlag("TRUE"));
        assertFalse(NativePayloadCodec.decodeFlag("0"));
        assertFalse(NativePayloadCodec.decodeFlag("false"));
        assertFalse(NativePayloadCodec.decodeFlag(""));
        assertFalse(NativePayloadCodec.decodeFlag(null));
    }

    @Test
    public void matchesCppWireFormatExpectations() {
        // Mirrors payload_codec::PayloadBuilder output byte-for-byte.
        String cppWire = "status=RESTRICTED\terrno=13\tscope=pagemap\n"
                + "code=hook_maps\tlocation=/data/app/a\\=b,c/lib.so\tdetail=line1\\nline2\\tcol\\=2\\\\end";
        NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(cppWire);
        assertFalse(decoded.isMalformed());
        assertEquals(NativePayloadCodec.Status.RESTRICTED, decoded.getStatus());
        assertEquals(13, decoded.getErrno());
        assertEquals("pagemap", decoded.getHeaderField("scope"));
        List<Map<String, String>> records = decoded.getRecords();
        assertEquals(1, records.size());
        assertEquals("hook_maps", records.get(0).get("code"));
        assertEquals("/data/app/a=b,c/lib.so", records.get(0).get("location"));
        assertEquals("line1\nline2\tcol=2\\end", records.get(0).get("detail"));
    }
}
