package com.wsttxm.riskenginesdk;

import android.os.IBinder;

import com.wsttxm.riskenginesdk.process.Keystore2ParcelClient;

import org.junit.Test;

import java.lang.reflect.Method;
import java.util.Collections;

import static org.junit.Assert.*;

/**
 * Pure-JVM unit tests for {@link Keystore2ParcelClient} VINTF-stable wire constants,
 * {@code ServiceErrorException} classification, and null-safe degradation.
 */
public class Keystore2ParcelClientTest {

    @Test
    public void frozenVintfTransactionCodesAndConstants_matchAospKeystore2Aidl() {
        assertEquals(IBinder.FIRST_CALL_TRANSACTION, Keystore2ParcelClient.TX_KS_GET_SECURITY_LEVEL);
        assertEquals(IBinder.FIRST_CALL_TRANSACTION + 1, Keystore2ParcelClient.TX_KS_GET_KEY_ENTRY);
        assertEquals(IBinder.FIRST_CALL_TRANSACTION + 4, Keystore2ParcelClient.TX_KS_DELETE_KEY);
        assertEquals(IBinder.FIRST_CALL_TRANSACTION + 5, Keystore2ParcelClient.TX_KS_GRANT);
        assertEquals(IBinder.FIRST_CALL_TRANSACTION + 6, Keystore2ParcelClient.TX_KS_UNGRANT);

        assertEquals(IBinder.FIRST_CALL_TRANSACTION, Keystore2ParcelClient.TX_SL_CREATE_OPERATION);
        assertEquals(IBinder.FIRST_CALL_TRANSACTION + 1, Keystore2ParcelClient.TX_SL_GENERATE_KEY);
        assertEquals(IBinder.FIRST_CALL_TRANSACTION + 5, Keystore2ParcelClient.TX_SL_DELETE_KEY);

        assertEquals(IBinder.FIRST_CALL_TRANSACTION, Keystore2ParcelClient.TX_OP_UPDATE_AAD);
        assertEquals(IBinder.FIRST_CALL_TRANSACTION + 1, Keystore2ParcelClient.TX_OP_UPDATE);
        assertEquals(IBinder.FIRST_CALL_TRANSACTION + 2, Keystore2ParcelClient.TX_OP_FINISH);
        assertEquals(IBinder.FIRST_CALL_TRANSACTION + 3, Keystore2ParcelClient.TX_OP_ABORT);

        assertEquals(0, Keystore2ParcelClient.DOMAIN_APP);
        assertEquals(1, Keystore2ParcelClient.DOMAIN_GRANT);
        assertEquals(4, Keystore2ParcelClient.DOMAIN_KEY_ID);
        assertEquals(4, Keystore2ParcelClient.PERM_GET_INFO);
        assertEquals(256, Keystore2ParcelClient.PERM_USE);
        assertEquals(7, Keystore2ParcelClient.RESPONSE_KEY_NOT_FOUND);
    }

    @Test
    public void keyDescriptorAndKeyParamFactories_populateExpectedWireFields() {
        Keystore2ParcelClient.KeyDescriptor app = Keystore2ParcelClient.KeyDescriptor.app("alias1");
        assertEquals(Keystore2ParcelClient.DOMAIN_APP, app.domain);
        assertEquals(-1L, app.nspace);
        assertEquals("alias1", app.alias);
        assertNull(app.blob);

        Keystore2ParcelClient.KeyDescriptor grant = Keystore2ParcelClient.KeyDescriptor.grant(42L);
        assertEquals(Keystore2ParcelClient.DOMAIN_GRANT, grant.domain);
        assertEquals(42L, grant.nspace);
        assertNull(grant.alias);

        Keystore2ParcelClient.KeyDescriptor keyId = Keystore2ParcelClient.KeyDescriptor.keyId(99L, "k");
        assertEquals(Keystore2ParcelClient.DOMAIN_KEY_ID, keyId.domain);
        assertEquals(99L, keyId.nspace);
        assertEquals("k", keyId.alias);

        Keystore2ParcelClient.KeyParam alg = Keystore2ParcelClient.KeyParam.ofInt(
                0x10000002, Keystore2ParcelClient.VAL_ALGORITHM, 3);
        assertEquals(0x10000002, alg.tag);
        assertEquals(Keystore2ParcelClient.VAL_ALGORITHM, alg.valueType);
        assertEquals(3, alg.intValue);

        Keystore2ParcelClient.KeyParam boolParam = Keystore2ParcelClient.KeyParam.ofBool(0x700001F7, true);
        assertEquals(Keystore2ParcelClient.VAL_BOOL, boolParam.valueType);
        assertEquals(1, boolParam.intValue);

        byte[] challenge = new byte[]{1, 2, 3, 4};
        Keystore2ParcelClient.KeyParam blobParam = Keystore2ParcelClient.KeyParam.ofBlob(0x900002C4, challenge);
        assertEquals(Keystore2ParcelClient.VAL_BLOB, blobParam.valueType);
        assertArrayEquals(challenge, blobParam.blobValue);
    }

    @Test
    public void serviceErrorException_keyNotFoundClassificationMatchesIsolatedService() throws Exception {
        Keystore2ParcelClient.ServiceErrorException knf =
                new Keystore2ParcelClient.ServiceErrorException(
                        Keystore2ParcelClient.RESPONSE_KEY_NOT_FOUND, "KEY_NOT_FOUND");
        assertEquals(7, knf.getErrorCode());
        assertTrue(knf.getMessage().contains("7"));

        Keystore2ParcelClient.ServiceErrorException permDenied =
                new Keystore2ParcelClient.ServiceErrorException(6, "PERMISSION_DENIED");
        assertEquals(6, permDenied.getErrorCode());

        Class<?> svcClass = Class.forName("com.wsttxm.riskenginesdk.process.RiskIsolatedProbeService");
        Method m = svcClass.getDeclaredMethod("isStrictKeyNotFoundThrowable", Throwable.class);
        m.setAccessible(true);
        assertEquals(Boolean.TRUE, m.invoke(null, knf));
        assertEquals(Boolean.FALSE, m.invoke(null, permDenied));
        assertEquals(Boolean.FALSE, m.invoke(null, new SecurityException(knf)));
    }

    @Test
    public void nullBinderCalls_degradeGracefullyWithoutThrowing() throws Exception {
        assertNull(Keystore2ParcelClient.getSecurityLevel(null, 1));
        assertNull(Keystore2ParcelClient.getKeyEntry(null, Keystore2ParcelClient.KeyDescriptor.app("a")));
        assertFalse(Keystore2ParcelClient.deleteKey(null, Keystore2ParcelClient.KeyDescriptor.app("a")));
        assertNull(Keystore2ParcelClient.grant(null, Keystore2ParcelClient.KeyDescriptor.app("a"), 1000, 260));
        assertFalse(Keystore2ParcelClient.ungrant(null, Keystore2ParcelClient.KeyDescriptor.app("a"), 1000));
        assertNull(Keystore2ParcelClient.generateKey(
                null, Keystore2ParcelClient.KeyDescriptor.app("a"), null, Collections.emptyList(), 0, new byte[0]));
        assertNull(Keystore2ParcelClient.createOperation(
                null, Keystore2ParcelClient.KeyDescriptor.app("a"), Collections.emptyList(), false));
        assertFalse(Keystore2ParcelClient.updateAad(null, new byte[]{1}));
        assertNull(Keystore2ParcelClient.update(null, new byte[]{1}));
        assertFalse(Keystore2ParcelClient.abort(null));
    }

    @Test
    public void parcelableEndValidation_blocksIntegerOverflowAndBoundsOverrun() {
        assertEquals(20, Keystore2ParcelClient.computeValidatedParcelableEnd(8, 12, 64, "KeyDescriptor"));
        assertEquals(64, Keystore2ParcelClient.computeValidatedParcelableEnd(60, 4, 64, "KeyDescriptor"));

        try {
            Keystore2ParcelClient.computeValidatedParcelableEnd(16, Integer.MAX_VALUE, 128, "KeyMetadata");
            fail("Must reject Integer.MAX_VALUE overflow");
        } catch (IllegalArgumentException expected) {
        }
        try {
            Keystore2ParcelClient.computeValidatedParcelableEnd(16, 3, 128, "KeyMetadata");
            fail("Must reject size < 4");
        } catch (IllegalArgumentException expected) {
        }
        try {
            Keystore2ParcelClient.computeValidatedParcelableEnd(100, 32, 128, "Authorization");
            fail("Must reject overrun past parent limitEnd");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void serviceSpecificHeaderSkip_validatesZeroAndNonZeroRemoteStackTraceHeaders() {
        // Native/Rust keystore2 writes headerSize=0 followed by 4-byte errorCode
        assertEquals(24, Keystore2ParcelClient.computeSkippedHeaderPosition(24, 0, 4));
        // Java server with 16-byte remote stack trace header followed by 4-byte errorCode
        assertEquals(40, Keystore2ParcelClient.computeSkippedHeaderPosition(24, 16, 20));

        try {
            Keystore2ParcelClient.computeSkippedHeaderPosition(24, -4, 16);
            fail("Must reject negative headerSize");
        } catch (IllegalArgumentException expected) {
        }
        try {
            Keystore2ParcelClient.computeSkippedHeaderPosition(24, 16, 16);
            fail("Must reserve at least 4 bytes for trailing errorCode");
        } catch (IllegalArgumentException expected) {
        }
        try {
            Keystore2ParcelClient.computeSkippedHeaderPosition(24, Integer.MAX_VALUE, 32);
            fail("Must reject overflowing headerSize");
        } catch (IllegalArgumentException expected) {
        }
    }
}
