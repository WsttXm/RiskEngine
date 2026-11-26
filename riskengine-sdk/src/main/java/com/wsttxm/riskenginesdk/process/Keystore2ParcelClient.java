package com.wsttxm.riskenginesdk.process;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

import java.lang.reflect.Method;
import java.util.List;

/**
 * Pure public-SDK Binder wire client for Android 12+ (API 31+) VINTF-stable Keystore2 AIDL
 * services ({@code android.system.keystore2.IKeystoreService}, {@code IKeystoreSecurityLevel},
 * and {@code IKeystoreOperation}).
 *
 * <p>Uses {@link IBinder#transact(int, Parcel, Parcel, int)} and {@link Parcel} directly against
 * the ABI-frozen Keystore2/KeyMint VINTF wire layout, completely avoiding hidden-API reflection on
 * {@code IKeystoreService$Stub.asInterface}, {@code KeyDescriptor}, or {@code KeyParameter} which
 * Android 12&ndash;16 ART denies as {@code (blocked, reflection, denied)} for {@code targetSdk >= 30}.</p>
 */
public final class Keystore2ParcelClient {

    public static final String SERVICE_NAME = "android.system.keystore2.IKeystoreService/default";

    public static final String DESC_KEYSTORE_SERVICE =
            "android.system.keystore2.IKeystoreService";
    public static final String DESC_SECURITY_LEVEL =
            "android.system.keystore2.IKeystoreSecurityLevel";
    public static final String DESC_OPERATION =
            "android.system.keystore2.IKeystoreOperation";

    // Frozen VINTF AIDL transaction codes (IKeystoreService)
    public static final int TX_KS_GET_SECURITY_LEVEL = IBinder.FIRST_CALL_TRANSACTION;      // 1
    public static final int TX_KS_GET_KEY_ENTRY = IBinder.FIRST_CALL_TRANSACTION + 1;       // 2
    public static final int TX_KS_DELETE_KEY = IBinder.FIRST_CALL_TRANSACTION + 4;          // 5
    public static final int TX_KS_GRANT = IBinder.FIRST_CALL_TRANSACTION + 5;               // 6
    public static final int TX_KS_UNGRANT = IBinder.FIRST_CALL_TRANSACTION + 6;             // 7

    // Frozen VINTF AIDL transaction codes (IKeystoreSecurityLevel)
    public static final int TX_SL_CREATE_OPERATION = IBinder.FIRST_CALL_TRANSACTION;        // 1
    public static final int TX_SL_GENERATE_KEY = IBinder.FIRST_CALL_TRANSACTION + 1;        // 2
    public static final int TX_SL_DELETE_KEY = IBinder.FIRST_CALL_TRANSACTION + 5;          // 6

    // Frozen VINTF AIDL transaction codes (IKeystoreOperation)
    public static final int TX_OP_UPDATE_AAD = IBinder.FIRST_CALL_TRANSACTION;              // 1
    public static final int TX_OP_UPDATE = IBinder.FIRST_CALL_TRANSACTION + 1;              // 2
    public static final int TX_OP_FINISH = IBinder.FIRST_CALL_TRANSACTION + 2;              // 3
    public static final int TX_OP_ABORT = IBinder.FIRST_CALL_TRANSACTION + 3;               // 4

    // android.system.keystore2.Domain
    public static final int DOMAIN_APP = 0;
    public static final int DOMAIN_GRANT = 1;
    public static final int DOMAIN_SELINUX = 2;
    public static final int DOMAIN_BLOB = 3;
    public static final int DOMAIN_KEY_ID = 4;

    // android.system.keystore2.KeyPermission
    public static final int PERM_GET_INFO = 4;
    public static final int PERM_USE = 256;

    // android.hardware.security.keymint.KeyParameterValue union discriminants
    public static final int VAL_INVALID = 0;
    public static final int VAL_ALGORITHM = 1;
    public static final int VAL_BLOCK_MODE = 2;
    public static final int VAL_PADDING_MODE = 3;
    public static final int VAL_DIGEST = 4;
    public static final int VAL_EC_CURVE = 5;
    public static final int VAL_ORIGIN = 6;
    public static final int VAL_KEY_PURPOSE = 7;
    public static final int VAL_HARDWARE_AUTH_TYPE = 8;
    public static final int VAL_SECURITY_LEVEL = 9;
    public static final int VAL_BOOL = 10;
    public static final int VAL_INTEGER = 11;
    public static final int VAL_LONG_INTEGER = 12;
    public static final int VAL_DATE_TIME = 13;
    public static final int VAL_BLOB = 14;

    // android.system.keystore2.ResponseCode
    public static final int RESPONSE_KEY_NOT_FOUND = 7;

    // Binder Parcel.EX_SERVICE_SPECIFIC
    private static final int EX_NONE = 0;
    private static final int EX_SERVICE_SPECIFIC = -8;
    private static final int NON_NULL = 1;
    private static final int MAX_AUTH_SKIP_COUNT = 512;

    private Keystore2ParcelClient() {
    }

    /** Typed exception representing Binder {@code EX_SERVICE_SPECIFIC} from Keystore2/KeyMint. */
    public static final class ServiceErrorException extends RuntimeException {
        private final int errorCode;

        public ServiceErrorException(int errorCode, String message) {
            super("Keystore2 ServiceError(" + errorCode + ")"
                    + (message != null && !message.isEmpty() ? ": " + message : ""));
            this.errorCode = errorCode;
        }

        public int getErrorCode() {
            return errorCode;
        }
    }

    /** Wire model for {@code android.system.keystore2.KeyDescriptor}. */
    public static final class KeyDescriptor {
        public final int domain;
        public final long nspace;
        public final String alias;
        public final byte[] blob;

        public KeyDescriptor(int domain, long nspace, String alias, byte[] blob) {
            this.domain = domain;
            this.nspace = nspace;
            this.alias = alias;
            this.blob = blob;
        }

        public static KeyDescriptor app(String alias) {
            return new KeyDescriptor(DOMAIN_APP, -1L, alias, null);
        }

        public static KeyDescriptor grant(long grantId) {
            return new KeyDescriptor(DOMAIN_GRANT, grantId, null, null);
        }

        public static KeyDescriptor keyId(long nspace, String alias) {
            return new KeyDescriptor(DOMAIN_KEY_ID, nspace, alias, null);
        }
    }

    /** Wire model for {@code android.hardware.security.keymint.KeyParameter}. */
    public static final class KeyParam {
        public final int tag;
        public final int valueType;
        public final int intValue;
        public final long longValue;
        public final byte[] blobValue;

        private KeyParam(int tag, int valueType, int intValue, long longValue, byte[] blobValue) {
            this.tag = tag;
            this.valueType = valueType;
            this.intValue = intValue;
            this.longValue = longValue;
            this.blobValue = blobValue;
        }

        public static KeyParam ofInt(int tag, int valueType, int value) {
            return new KeyParam(tag, valueType, value, 0L, null);
        }

        public static KeyParam ofBool(int tag, boolean value) {
            return new KeyParam(tag, VAL_BOOL, value ? 1 : 0, 0L, null);
        }

        public static KeyParam ofLong(int tag, int valueType, long value) {
            return new KeyParam(tag, valueType, 0, value, null);
        }

        public static KeyParam ofBlob(int tag, byte[] blob) {
            return new KeyParam(tag, VAL_BLOB, 0, 0L, blob);
        }
    }

    /** Wire model for {@code android.system.keystore2.KeyMetadata}. */
    public static final class KeyMetadata {
        public final KeyDescriptor key;
        public final int keySecurityLevel;
        public final byte[] certificate;
        public final byte[] certificateChain;
        public final long modificationTimeMs;

        public KeyMetadata(
                KeyDescriptor key,
                int keySecurityLevel,
                byte[] certificate,
                byte[] certificateChain,
                long modificationTimeMs) {
            this.key = key;
            this.keySecurityLevel = keySecurityLevel;
            this.certificate = certificate;
            this.certificateChain = certificateChain;
            this.modificationTimeMs = modificationTimeMs;
        }
    }

    /** Wire model for {@code android.system.keystore2.KeyEntryResponse}. */
    public static final class KeyEntryResponse {
        public final IBinder securityLevelBinder;
        public final KeyMetadata metadata;

        public KeyEntryResponse(IBinder securityLevelBinder, KeyMetadata metadata) {
            this.securityLevelBinder = securityLevelBinder;
            this.metadata = metadata;
        }
    }

    /** Result of {@code generateKey} containing both raw reply bytes and parsed metadata. */
    public static final class GenerateKeyReply {
        public final byte[] rawReplyBytes;
        public final KeyMetadata metadata;

        public GenerateKeyReply(byte[] rawReplyBytes, KeyMetadata metadata) {
            this.rawReplyBytes = rawReplyBytes;
            this.metadata = metadata;
        }
    }

    /** Looks up the {@code keystore2} Binder handle via greylisted {@code ServiceManager.getService}. */
    public static IBinder lookupServiceBinder() {
        try {
            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Method getService = smClass.getMethod("getService", String.class);
            Object raw = getService.invoke(null, SERVICE_NAME);
            return raw instanceof IBinder ? (IBinder) raw : null;
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            return null;
        }
    }

    /** Calls {@code IKeystoreService.getSecurityLevel(int)} over raw {@link IBinder#transact}. */
    public static IBinder getSecurityLevel(IBinder ksServiceBinder, int securityLevel)
            throws RemoteException {
        if (ksServiceBinder == null) {
            return null;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESC_KEYSTORE_SERVICE);
            data.writeInt(securityLevel);
            if (!ksServiceBinder.transact(TX_KS_GET_SECURITY_LEVEL, data, reply, 0)) {
                return null;
            }
            checkReplyException(reply);
            return reply.readStrongBinder();
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /** Calls {@code IKeystoreService.getKeyEntry(KeyDescriptor)} over raw {@link IBinder#transact}. */
    public static KeyEntryResponse getKeyEntry(IBinder ksServiceBinder, KeyDescriptor key)
            throws RemoteException {
        if (ksServiceBinder == null || key == null) {
            return null;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESC_KEYSTORE_SERVICE);
            writeKeyDescriptor(data, key);
            if (!ksServiceBinder.transact(TX_KS_GET_KEY_ENTRY, data, reply, 0)) {
                return null;
            }
            checkReplyException(reply);
            return readKeyEntryResponse(reply);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /** Calls {@code IKeystoreService.deleteKey(KeyDescriptor)} over raw {@link IBinder#transact}. */
    public static boolean deleteKey(IBinder ksServiceBinder, KeyDescriptor key)
            throws RemoteException {
        if (ksServiceBinder == null || key == null) {
            return false;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESC_KEYSTORE_SERVICE);
            writeKeyDescriptor(data, key);
            if (!ksServiceBinder.transact(TX_KS_DELETE_KEY, data, reply, 0)) {
                return false;
            }
            checkReplyException(reply);
            return true;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /** Calls {@code IKeystoreService.grant(KeyDescriptor, int, int)} over raw {@link IBinder#transact}. */
    public static KeyDescriptor grant(
            IBinder ksServiceBinder, KeyDescriptor key, int granteeUid, int accessVector)
            throws RemoteException {
        if (ksServiceBinder == null || key == null) {
            return null;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESC_KEYSTORE_SERVICE);
            writeKeyDescriptor(data, key);
            data.writeInt(granteeUid);
            data.writeInt(accessVector);
            if (!ksServiceBinder.transact(TX_KS_GRANT, data, reply, 0)) {
                return null;
            }
            checkReplyException(reply);
            return readKeyDescriptor(reply);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /** Calls {@code IKeystoreService.ungrant(KeyDescriptor, int)} over raw {@link IBinder#transact}. */
    public static boolean ungrant(IBinder ksServiceBinder, KeyDescriptor key, int granteeUid)
            throws RemoteException {
        if (ksServiceBinder == null || key == null) {
            return false;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESC_KEYSTORE_SERVICE);
            writeKeyDescriptor(data, key);
            data.writeInt(granteeUid);
            if (!ksServiceBinder.transact(TX_KS_UNGRANT, data, reply, 0)) {
                return false;
            }
            checkReplyException(reply);
            return true;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /**
     * Calls {@code IKeystoreSecurityLevel.generateKey(key, attestationKey, params, flags, entropy)}
     * and captures both the exact raw Binder reply bytes (for {@code TAG_USER_ID} inspection) and
     * the parsed {@link KeyMetadata}.
     */
    public static GenerateKeyReply generateKey(
            IBinder secLevelBinder,
            KeyDescriptor key,
            KeyDescriptor attestationKey,
            List<KeyParam> params,
            int flags,
            byte[] entropy) throws RemoteException {
        if (secLevelBinder == null || key == null) {
            return null;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESC_SECURITY_LEVEL);
            writeKeyDescriptor(data, key);
            writeKeyDescriptor(data, attestationKey);
            writeKeyParamArray(data, params);
            data.writeInt(flags);
            data.writeByteArray(entropy);
            if (!secLevelBinder.transact(TX_SL_GENERATE_KEY, data, reply, 0)) {
                return null;
            }
            byte[] rawReply = reply.marshall();
            reply.setDataPosition(0);
            checkReplyException(reply);
            KeyMetadata metadata = readKeyMetadata(reply);
            return new GenerateKeyReply(rawReply, metadata);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /**
     * Calls {@code IKeystoreSecurityLevel.createOperation(key, operationParameters, forced)} and
     * returns the {@code IKeystoreOperation} Binder handle.
     */
    public static IBinder createOperation(
            IBinder secLevelBinder,
            KeyDescriptor key,
            List<KeyParam> operationParams,
            boolean forced) throws RemoteException {
        if (secLevelBinder == null || key == null) {
            return null;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESC_SECURITY_LEVEL);
            writeKeyDescriptor(data, key);
            writeKeyParamArray(data, operationParams);
            data.writeInt(forced ? 1 : 0);
            if (!secLevelBinder.transact(TX_SL_CREATE_OPERATION, data, reply, 0)) {
                return null;
            }
            checkReplyException(reply);
            return readCreateOperationHandle(reply);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /** Calls {@code IKeystoreOperation.updateAad(byte[])}. */
    public static boolean updateAad(IBinder opBinder, byte[] aadInput) throws RemoteException {
        if (opBinder == null) {
            return false;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESC_OPERATION);
            data.writeByteArray(aadInput);
            if (!opBinder.transact(TX_OP_UPDATE_AAD, data, reply, 0)) {
                return false;
            }
            checkReplyException(reply);
            return true;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /** Calls {@code IKeystoreOperation.update(byte[])}. Throws {@link RemoteException} if transact fails. */
    public static byte[] update(IBinder opBinder, byte[] input) throws RemoteException {
        if (opBinder == null) {
            return null;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESC_OPERATION);
            data.writeByteArray(input);
            if (!opBinder.transact(TX_OP_UPDATE, data, reply, 0)) {
                throw new RemoteException("IKeystoreOperation.update transact returned false");
            }
            checkReplyException(reply);
            return reply.createByteArray();
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /** Calls {@code IKeystoreOperation.abort()}. */
    public static boolean abort(IBinder opBinder) throws RemoteException {
        if (opBinder == null) {
            return false;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESC_OPERATION);
            if (!opBinder.transact(TX_OP_ABORT, data, reply, 0)) {
                return false;
            }
            checkReplyException(reply);
            return true;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    // ==================== Stable-AIDL Parcel Framing Helpers ====================

    static void checkReplyException(Parcel reply) {
        int code = reply.readInt();
        if (code == EX_NONE) {
            return;
        }
        if (code == EX_SERVICE_SPECIFIC) {
            String message = reply.readString();
            // AOSP Parcel.writeException / libbinder Status::writeToParcel wire layout:
            // int32(-8) -> String16(message) -> int32(remoteStackTraceHeaderSize) -> [headerBytes] -> int32(errorCode)
            int headerSize = reply.readInt();
            int avail = reply.dataAvail();
            int nextPos = computeSkippedHeaderPosition(reply.dataPosition(), headerSize, avail);
            reply.setDataPosition(nextPos);
            int errorCode = reply.readInt();
            throw new ServiceErrorException(errorCode, message);
        }
        // Rewind so public Parcel.readException() handles standard Binder exceptions and
        // any EX_HAS_REPLY_HEADER / EX_HAS_NOTED_APPOPS_REPLY_HEADER frames cleanly.
        reply.setDataPosition(0);
        reply.readException();
    }

    /**
     * Overflow-safe validation of the remote-stack-trace header size inside a Binder
     * {@code EX_SERVICE_SPECIFIC (-8)} reply parcel before reading the trailing {@code errorCode}.
     */
    public static int computeSkippedHeaderPosition(int currentPos, int headerSize, int dataAvail) {
        if (currentPos < 0 || dataAvail < 4 || headerSize < 0 || headerSize > dataAvail - 4) {
            throw new IllegalArgumentException(
                    "Invalid EX_SERVICE_SPECIFIC headerSize=" + headerSize + ", avail=" + dataAvail);
        }
        return currentPos + headerSize;
    }

    /**
     * Overflow-safe validation of a stable-AIDL length-prefixed parcelable end offset against
     * {@code limitEnd} (either {@code parcel.dataSize()} or an enclosing parcelable's end offset).
     */
    public static int computeValidatedParcelableEnd(
            int startPos, int size, int limitEnd, String name) {
        if (startPos < 0 || limitEnd < 0 || startPos > limitEnd) {
            throw new IllegalArgumentException(
                    "Invalid " + name + " startPos=" + startPos + ", limitEnd=" + limitEnd);
        }
        if (size < 4 || size > limitEnd - startPos) {
            throw new IllegalArgumentException(
                    "Invalid " + name + " parcelable size=" + size
                            + " at " + startPos + " (limit=" + limitEnd + ")");
        }
        return startPos + size;
    }

    private static int readParcelableEnd(Parcel in, int limitEnd, String name) {
        int startPos = in.dataPosition();
        int size = in.readInt();
        return computeValidatedParcelableEnd(startPos, size, limitEnd, name);
    }

    public static void writeKeyDescriptor(Parcel out, KeyDescriptor desc) {
        if (desc == null) {
            out.writeInt(0);
            return;
        }
        out.writeInt(NON_NULL);
        int startPos = out.dataPosition();
        out.writeInt(0); // size placeholder
        out.writeInt(desc.domain);
        out.writeLong(desc.nspace);
        out.writeString(desc.alias);
        out.writeByteArray(desc.blob);
        int endPos = out.dataPosition();
        out.setDataPosition(startPos);
        out.writeInt(endPos - startPos);
        out.setDataPosition(endPos);
    }

    public static KeyDescriptor readKeyDescriptor(Parcel in) {
        return readKeyDescriptor(in, in.dataSize());
    }

    private static KeyDescriptor readKeyDescriptor(Parcel in, int limitEnd) {
        if (in.readInt() == 0) {
            return null;
        }
        int endPos = readParcelableEnd(in, limitEnd, "KeyDescriptor");
        int domain = 0;
        long nspace = 0L;
        String alias = null;
        byte[] blob = null;
        try {
            if (in.dataPosition() < endPos) {
                domain = in.readInt();
            }
            if (in.dataPosition() < endPos) {
                nspace = in.readLong();
            }
            if (in.dataPosition() < endPos) {
                alias = in.readString();
            }
            if (in.dataPosition() < endPos) {
                blob = in.createByteArray();
            }
        } finally {
            in.setDataPosition(endPos);
        }
        return new KeyDescriptor(domain, nspace, alias, blob);
    }

    public static void writeKeyParamArray(Parcel out, List<KeyParam> params) {
        if (params == null) {
            out.writeInt(-1);
            return;
        }
        out.writeInt(params.size());
        for (KeyParam p : params) {
            writeKeyParam(out, p);
        }
    }

    public static void writeKeyParam(Parcel out, KeyParam p) {
        if (p == null) {
            out.writeInt(0);
            return;
        }
        out.writeInt(NON_NULL);
        int startPos = out.dataPosition();
        out.writeInt(0); // size placeholder
        out.writeInt(p.tag);
        // KeyParameterValue is a stable AIDL union (non-null flag + _tag + value; no inner size)
        out.writeInt(NON_NULL);
        out.writeInt(p.valueType);
        if (p.valueType >= VAL_INVALID && p.valueType <= VAL_INTEGER) {
            out.writeInt(p.intValue);
        } else if (p.valueType == VAL_LONG_INTEGER || p.valueType == VAL_DATE_TIME) {
            out.writeLong(p.longValue);
        } else if (p.valueType == VAL_BLOB) {
            out.writeByteArray(p.blobValue);
        } else {
            throw new IllegalArgumentException("Unsupported KeyParameterValue tag: " + p.valueType);
        }
        int endPos = out.dataPosition();
        out.setDataPosition(startPos);
        out.writeInt(endPos - startPos);
        out.setDataPosition(endPos);
    }

    public static KeyEntryResponse readKeyEntryResponse(Parcel in) {
        if (in.readInt() == 0) {
            return null;
        }
        int endPos = readParcelableEnd(in, in.dataSize(), "KeyEntryResponse");
        IBinder secBinder = null;
        KeyMetadata metadata = null;
        try {
            if (in.dataPosition() < endPos) {
                secBinder = in.readStrongBinder();
            }
            if (in.dataPosition() < endPos) {
                metadata = readKeyMetadata(in, endPos);
            }
        } finally {
            in.setDataPosition(endPos);
        }
        return new KeyEntryResponse(secBinder, metadata);
    }

    public static KeyMetadata readKeyMetadata(Parcel in) {
        return readKeyMetadata(in, in.dataSize());
    }

    private static KeyMetadata readKeyMetadata(Parcel in, int limitEnd) {
        if (in.readInt() == 0) {
            return null;
        }
        int endPos = readParcelableEnd(in, limitEnd, "KeyMetadata");
        KeyDescriptor key = null;
        int secLevel = 0;
        byte[] cert = null;
        byte[] chain = null;
        long modTimeMs = 0L;
        try {
            if (in.dataPosition() < endPos) {
                key = readKeyDescriptor(in, endPos);
            }
            if (in.dataPosition() < endPos) {
                secLevel = in.readInt();
            }
            if (in.dataPosition() < endPos) {
                skipAuthorizationArray(in, endPos);
            }
            if (in.dataPosition() < endPos) {
                cert = in.createByteArray();
            }
            if (in.dataPosition() < endPos) {
                chain = in.createByteArray();
            }
            if (in.dataPosition() < endPos) {
                modTimeMs = in.readLong();
            }
        } finally {
            in.setDataPosition(endPos);
        }
        return new KeyMetadata(key, secLevel, cert, chain, modTimeMs);
    }

    private static void skipAuthorizationArray(Parcel in, int limitEnd) {
        int count = in.readInt();
        if (count <= 0) {
            return;
        }
        if (count > MAX_AUTH_SKIP_COUNT) {
            throw new IllegalArgumentException("Excessive Authorization count: " + count);
        }
        for (int i = 0; i < count && in.dataPosition() < limitEnd; i++) {
            int present = in.readInt();
            if (present == 0) {
                continue;
            }
            int elemEnd = readParcelableEnd(in, limitEnd, "Authorization");
            in.setDataPosition(elemEnd);
        }
    }

    public static IBinder readCreateOperationHandle(Parcel in) {
        if (in.readInt() == 0) {
            return null;
        }
        int endPos = readParcelableEnd(in, in.dataSize(), "CreateOperationResponse");
        IBinder opBinder = null;
        try {
            if (in.dataPosition() < endPos) {
                opBinder = in.readStrongBinder();
            }
        } finally {
            in.setDataPosition(endPos);
        }
        return opBinder;
    }
}
