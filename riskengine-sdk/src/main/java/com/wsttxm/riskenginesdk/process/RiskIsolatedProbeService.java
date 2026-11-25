package com.wsttxm.riskenginesdk.process;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.function.BooleanSupplier;
import java.util.function.LongFunction;

/**
 * On-demand {@code android:isolatedProcess="true"} helper service used to collect a clean
 * cross-process {@code /proc/self/mountinfo} view outside the main app UID's mount namespace
 * hiding rules (Shamiko / Magisk DenyList / KernelSU selective unmount).
 *
 * <p>Fail-closed security boundary: {@link #onBind(Intent)} refuses binding whenever
 * {@link Process#isIsolated()} returns {@code false}. Host applications may safely remove this
 * service declaration using {@code tools:node="remove"} in their own manifest; the client will
 * degrade gracefully to {@code UNAVAILABLE}.
 */
public final class RiskIsolatedProbeService extends Service {

    static final String DESCRIPTOR = "com.wsttxm.riskenginesdk.process.IRiskIsolatedProbe";
    static final int TRANSACTION_COLLECT_MOUNT_VIEW = IBinder.FIRST_CALL_TRANSACTION + 1;
    static final int TRANSACTION_GET_ISOLATED_UID = IBinder.FIRST_CALL_TRANSACTION + 2;
    static final int TRANSACTION_READ_GRANTED_KEY_CHAIN = IBinder.FIRST_CALL_TRANSACTION + 3;

    // Hard cap well below Android's 1 MiB Binder transaction buffer to prevent TransactionTooLargeException.
    private static final int MAX_PAYLOAD_CHARS = 256 * 1024;

    private final BooleanSupplier isolatedChecker;
    private final LongFunction<String> grantedChainReader;

    public RiskIsolatedProbeService() {
        this(RiskIsolatedProbeService::isProcessIsolatedSafe, null);
    }

    /** Package-private constructor seam for deterministic pure-JVM unit tests. */
    RiskIsolatedProbeService(BooleanSupplier isolatedChecker) {
        this(isolatedChecker, null);
    }

    /** Package-private constructor seam for deterministic pure-JVM unit tests of Domain.GRANT readback. */
    RiskIsolatedProbeService(BooleanSupplier isolatedChecker,
                             LongFunction<String> grantedChainReader) {
        this.isolatedChecker = isolatedChecker != null
                ? isolatedChecker : RiskIsolatedProbeService::isProcessIsolatedSafe;
        this.grantedChainReader = grantedChainReader;
    }

    private final Binder binder = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                throws RemoteException {
            if (code == INTERFACE_TRANSACTION) {
                if (reply != null) {
                    reply.writeString(DESCRIPTOR);
                }
                return true;
            }
            if (code == TRANSACTION_COLLECT_MOUNT_VIEW) {
                data.enforceInterface(DESCRIPTOR);
                enforceIsolatedProcess();
                String payload = collectBoundedMountInfoPayload();
                if (reply != null) {
                    reply.writeNoException();
                    reply.writeString(payload);
                }
                return true;
            }
            if (code == TRANSACTION_GET_ISOLATED_UID) {
                data.enforceInterface(DESCRIPTOR);
                enforceIsolatedProcess();
                int uid = Process.myUid();
                if (reply != null) {
                    reply.writeNoException();
                    reply.writeInt(uid);
                }
                return true;
            }
            if (code == TRANSACTION_READ_GRANTED_KEY_CHAIN) {
                data.enforceInterface(DESCRIPTOR);
                enforceIsolatedProcess();
                long grantId = data.readLong();
                IBinder optionalKs2 = (data.dataAvail() > 0 && data.readInt() != 0)
                        ? data.readStrongBinder()
                        : null;
                String payload = grantedChainReader != null
                        ? grantedChainReader.apply(grantId)
                        : readGrantedCertificateChainSummary(grantId, optionalKs2);
                if (reply != null) {
                    reply.writeNoException();
                    reply.writeString(payload);
                }
                return true;
            }
            return super.onTransact(code, data, reply, flags);
        }
    };

    /** Package-private helper allowing pure-JVM verification of the fail-closed transaction guard. */
    void enforceIsolatedProcess() {
        if (!isolatedChecker.getAsBoolean()) {
            throw new SecurityException("RiskIsolatedProbeService requires isolated process");
        }
    }

    /** Package-private test seam exercising grant readback guard without Android native Parcel. */
    String handleReadGrantedChainForTest(long grantId) {
        enforceIsolatedProcess();
        return grantedChainReader != null
                ? grantedChainReader.apply(grantId)
                : readGrantedCertificateChainSummary(grantId, null);
    }

    /** Package-private test seam exercising UID query guard without Android native Parcel. */
    int handleGetIsolatedUidForTest() {
        enforceIsolatedProcess();
        return Process.myUid();
    }

    @Override
    public IBinder onBind(Intent intent) {
        // Fail closed if the manifest isolatedProcess attribute was stripped or misconfigured.
        if (!isolatedChecker.getAsBoolean()) {
            return null;
        }
        return binder;
    }

    private static boolean isProcessIsolatedSafe() {
        try {
            return Process.isIsolated();
        } catch (Exception | LinkageError e) {
            return false;
        }
    }

    private static String collectBoundedMountInfoPayload() {
        List<String> lines = readSelfMountInfoLines();
        if (lines.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(Math.min(16384, lines.size() * 96));
        for (String line : lines) {
            if (sb.length() + line.length() + 1 > MAX_PAYLOAD_CHARS) {
                break;
            }
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    private static List<String> readSelfMountInfoLines() {
        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/mountinfo"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
            return lines;
        } catch (Exception | LinkageError e) {
            return Collections.emptyList();
        }
    }

    /**
     * Reads a Keystore2 Domain.GRANT certificate chain (API 31+) inside this isolated process
     * and returns a compact summary frame:
     * {@code OK|<count>|<orderedChainSha256>|<cert0Sha256>,<cert1Sha256>,...}
     * or {@code KEY_NOT_FOUND|<reason>} / {@code UNAVAILABLE|<reason>}.
     */
    private String readGrantedCertificateChainSummary(long grantId, IBinder optionalKs2Binder) {
        if (Build.VERSION.SDK_INT < 31) {
            return "UNAVAILABLE|api_below_31";
        }
        // Path A: android.security.keystore.KeyStoreManager (public on API 36, hidden on some API 35 builds)
        try {
            Class<?> ksmClass = Class.forName("android.security.keystore.KeyStoreManager");
            Object ksm = null;
            try {
                ksm = getSystemService(ksmClass);
            } catch (Exception | LinkageError ignored) {
            }
            if (ksm == null) {
                try {
                    Method getInstance = ksmClass.getDeclaredMethod("getInstance");
                    getInstance.setAccessible(true);
                    ksm = getInstance.invoke(null);
                } catch (Exception | LinkageError ignored) {
                }
            }
            if (ksm != null) {
                Method getChain = resolveMethod(ksmClass, "getGrantedCertificateChainFromId", long.class);
                Object rawResult = getChain.invoke(ksm, grantId);
                List<Certificate> certs = extractCertificates(rawResult);
                if (certs == null) {
                    return "UNAVAILABLE|unexpected_chain_return_type";
                }
                if (certs.isEmpty()) {
                    return "UNAVAILABLE|empty_granted_chain";
                }
                return formatChainDigestSummary(certs);
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            if (isStrictKeyNotFoundThrowable(e)) {
                return "KEY_NOT_FOUND|" + unwrapCause(e).getClass().getSimpleName();
            }
            // Fall through to Path B on API 31-35 when KeyStoreManager is absent or restricted
        }

        // Path B: Keystore2 private IKeystoreService Binder fallback (API 31-35)
        return readGrantedChainViaKeystore2Binder(grantId, optionalKs2Binder);
    }

    private String readGrantedChainViaKeystore2Binder(long grantId, IBinder optionalKs2Binder) {
        try {
            IBinder binder = optionalKs2Binder != null
                    ? optionalKs2Binder
                    : Keystore2ParcelClient.lookupServiceBinder();
            if (binder == null) {
                return "UNAVAILABLE|keystore2_binder_unavailable";
            }

            Keystore2ParcelClient.KeyEntryResponse response = Keystore2ParcelClient.getKeyEntry(
                    binder, Keystore2ParcelClient.KeyDescriptor.grant(grantId));
            if (response == null) {
                return "UNAVAILABLE|keystore2_response_null";
            }
            if (response.metadata == null) {
                return "UNAVAILABLE|keystore2_metadata_null";
            }
            List<Certificate> certs = decodeCerts(
                    response.metadata.certificate, response.metadata.certificateChain);
            if (certs.isEmpty()) {
                return "UNAVAILABLE|empty_keystore2_cert_chain";
            }
            return formatChainDigestSummary(certs);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            if (isStrictKeyNotFoundThrowable(e)) {
                return "KEY_NOT_FOUND|" + unwrapCause(e).getClass().getSimpleName();
            }
            return "UNAVAILABLE|" + unwrapCause(e).getClass().getSimpleName();
        }
    }

    private static List<Certificate> decodeCerts(byte[] leafBytes, byte[] chainBytes) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<Certificate> out = new ArrayList<>();
        if (leafBytes != null && leafBytes.length > 0) {
            out.add(cf.generateCertificate(new ByteArrayInputStream(leafBytes)));
        }
        if (chainBytes != null && chainBytes.length > 0) {
            Collection<? extends Certificate> rest =
                    cf.generateCertificates(new ByteArrayInputStream(chainBytes));
            out.addAll(rest);
        }
        return out;
    }

    private static Method resolveMethod(Class<?> cls, String name, Class<?>... params)
            throws NoSuchMethodException {
        Method m;
        try {
            m = cls.getMethod(name, params);
        } catch (NoSuchMethodException ignored) {
            m = cls.getDeclaredMethod(name, params);
        }
        m.setAccessible(true);
        return m;
    }

    private static List<Certificate> extractCertificates(Object rawResult) {
        if (rawResult instanceof Collection<?>) {
            Collection<?> rawCol = (Collection<?>) rawResult;
            List<Certificate> certs = new ArrayList<>(rawCol.size());
            for (Object item : rawCol) {
                if (item instanceof Certificate) {
                    certs.add((Certificate) item);
                }
            }
            return certs;
        }
        if (rawResult instanceof Certificate[]) {
            Certificate[] arr = (Certificate[]) rawResult;
            List<Certificate> certs = new ArrayList<>(arr.length);
            for (Certificate item : arr) {
                if (item != null) {
                    certs.add(item);
                }
            }
            return certs;
        }
        return null;
    }

    /**
     * Strictly classifies Keystore2 KEY_NOT_FOUND exceptions while excluding reflection,
     * linkage, security, and generic availability errors so visibility loss never false-positives.
     */
    static boolean isStrictKeyNotFoundThrowable(Throwable t) {
        if (t == null) {
            return false;
        }
        // Scan full cause chain; immediately fail-closed (false) on platform/reflection/visibility failures
        Throwable cur = t;
        int guard = 0;
        boolean matchedKeyNotFound = false;
        while (cur != null && guard++ < 8) {
            if (cur instanceof java.lang.reflect.InvocationTargetException) {
                Throwable target = ((java.lang.reflect.InvocationTargetException) cur).getTargetException();
                if (target == null || target == cur) {
                    break;
                }
                cur = target;
                continue;
            }
            if (cur instanceof ReflectiveOperationException
                    || cur instanceof LinkageError
                    || cur instanceof SecurityException
                    || cur instanceof UnsupportedOperationException
                    || cur instanceof IllegalArgumentException) {
                return false;
            }
            if (cur instanceof UnrecoverableKeyException) {
                String msg = cur.getMessage() == null ? "" : cur.getMessage().toLowerCase(Locale.ROOT);
                if (msg.contains("no key found by the given alias")
                        || msg.contains("key_not_found")) {
                    matchedKeyNotFound = true;
                }
            }
            if (cur instanceof Keystore2ParcelClient.ServiceErrorException) {
                if (((Keystore2ParcelClient.ServiceErrorException) cur).getErrorCode()
                        == Keystore2ParcelClient.RESPONSE_KEY_NOT_FOUND) {
                    matchedKeyNotFound = true;
                }
            }
            if ("ServiceSpecificException".equals(cur.getClass().getSimpleName())) {
                Integer errCode = readIntFieldSafe(cur, "errorCode");
                if (errCode != null) {
                    if (errCode == 7) {
                        matchedKeyNotFound = true;
                    }
                } else {
                    String msg = cur.getMessage() == null ? "" : cur.getMessage().toLowerCase(Locale.ROOT);
                    if (msg.contains("key_not_found") || msg.contains("(code 7)")) {
                        matchedKeyNotFound = true;
                    }
                }
            }
            if (cur.getCause() == cur) {
                break;
            }
            cur = cur.getCause();
        }
        return matchedKeyNotFound;
    }

    private static Integer readIntFieldSafe(Object obj, String fieldName) {
        try {
            Field f = obj.getClass().getField(fieldName);
            f.setAccessible(true);
            return f.getInt(obj);
        } catch (Exception ignored) {
            try {
                Field f = obj.getClass().getDeclaredField(fieldName);
                f.setAccessible(true);
                return f.getInt(obj);
            } catch (Exception ignored2) {
                return null;
            }
        }
    }

    /** Formats an ordered certificate chain into a deterministic SHA-256 summary frame. */
    public static String formatChainDigestSummary(List<? extends Certificate> certs) {
        if (certs == null || certs.isEmpty()) {
            return "UNAVAILABLE|empty_chain";
        }
        try {
            MessageDigest chainMd = MessageDigest.getInstance("SHA-256");
            List<String> perCertHex = new ArrayList<>(certs.size());
            for (Certificate cert : certs) {
                byte[] encoded = cert.getEncoded();
                MessageDigest itemMd = MessageDigest.getInstance("SHA-256");
                String itemHex = toHex(itemMd.digest(encoded));
                perCertHex.add(itemHex);
                chainMd.update(encoded);
                chainMd.update((byte) 0xFF);
            }
            String chainHex = toHex(chainMd.digest());
            return "OK|" + certs.size() + "|" + chainHex + "|" + String.join(",", perCertHex);
        } catch (Exception e) {
            return "UNAVAILABLE|" + e.getClass().getSimpleName();
        }
    }

    private static Throwable unwrapCause(Throwable t) {
        Throwable cur = t;
        int guard = 0;
        while (cur.getCause() != null && cur.getCause() != cur && guard++ < 8) {
            cur = cur.getCause();
        }
        return cur;
    }

    private static String toHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        final char[] hex = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = hex[v >>> 4];
            out[i * 2 + 1] = hex[v & 0x0F];
        }
        return new String(out);
    }
}
