package com.wsttxm.riskenginesdk.process;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.wsttxm.riskenginesdk.core.SafeExecutor;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.util.CLog;

import java.lang.reflect.Method;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Ephemeral client for {@link RiskIsolatedProbeService}.
 *
 * <p>Lifecycle guarantees:
 * <ul>
 *   <li>Runs under a bounded {@link SafeExecutor#safeWithTimeout} budget.</li>
 *   <li>ALWAYS invokes {@code unbindService()} in {@code finally} so the isolated process is
 *       never kept resident in memory.</li>
 *   <li>Degrades cleanly to {@code UNAVAILABLE} when disabled in config or when the host strips
 *       the service via {@code tools:node="remove"}.</li>
 * </ul>
 */
public final class IsolatedProbeClient {

    public static final long DEFAULT_TIMEOUT_MS = 1500L;
    public static final long DEFAULT_GRANT_TIMEOUT_MS = 4000L;

    /** Result object returned by an on-demand isolated-process mount diff probe. */
    public static final class IsolatedMountReport {
        private final MountViewNormalizer.MountDiffResult diffResult;
        private final long durationMs;

        public IsolatedMountReport(MountViewNormalizer.MountDiffResult diffResult,
                                   long durationMs) {
            this.diffResult = diffResult;
            this.durationMs = Math.max(0L, durationMs);
        }

        public MountViewNormalizer.MountDiffResult getDiffResult() {
            return diffResult;
        }

        public long getDurationMs() {
            return durationMs;
        }
    }

    /** Result object returned by an ephemeral Keystore2 Domain.APP vs Domain.GRANT probe. */
    public static final class IsolatedGrantReport {
        public enum GrantReadStatus {
            OK,
            KEY_NOT_FOUND_ON_GRANT,
            KEY_NOT_FOUND_ON_READBACK,
            UNAVAILABLE
        }

        private final String appChainSummary;
        private final String grantChainSummary;
        private final GrantReadStatus grantReadStatus;
        private final int isolatedUid;
        private final long durationMs;
        private final String detail;

        public IsolatedGrantReport(
                String appChainSummary,
                String grantChainSummary,
                GrantReadStatus grantReadStatus,
                int isolatedUid,
                long durationMs,
                String detail) {
            this.appChainSummary = appChainSummary;
            this.grantChainSummary = grantChainSummary;
            this.grantReadStatus = grantReadStatus == null ? GrantReadStatus.UNAVAILABLE : grantReadStatus;
            this.isolatedUid = isolatedUid;
            this.durationMs = Math.max(0L, durationMs);
            this.detail = detail;
        }

        public String getAppChainSummary() {
            return appChainSummary;
        }

        public String getGrantChainSummary() {
            return grantChainSummary;
        }

        public GrantReadStatus getGrantReadStatus() {
            return grantReadStatus;
        }

        public int getIsolatedUid() {
            return isolatedUid;
        }

        public long getDurationMs() {
            return durationMs;
        }

        public String getDetail() {
            return detail;
        }
    }

    /** Injectable seam for pure-JVM testing of Keystore2 Domain.GRANT isolated probes. */
    public interface GrantProbeAdapter {
        int getSdkInt();
        boolean isServiceDeclared(Context context, Intent intent);
        boolean bindIsolated(Context context, Intent intent, String instanceName, ServiceConnection connection);
        void unbind(Context context, ServiceConnection connection);
        int transactGetIsolatedUid(IBinder binder) throws Exception;
        String transactReadGrantedChain(IBinder binder, long grantId) throws Exception;
        String generateEphemeralAppChainSummary(String alias, byte[] challenge) throws Exception;
        long grantKeyAccess(Context context, String alias, int granteeUid) throws Exception;
        void revokeKeyAccess(Context context, String alias, int granteeUid);
        void deleteEphemeralAlias(String alias);
    }

    private static final GrantProbeAdapter DEFAULT_GRANT_ADAPTER = new GrantProbeAdapter() {
        @Override
        public int getSdkInt() {
            return Build.VERSION.SDK_INT;
        }

        @Override
        public boolean isServiceDeclared(Context context, Intent intent) {
            return DEFAULT_ADAPTER.isServiceDeclared(context, intent);
        }

        @Override
        public boolean bindIsolated(
                Context context, Intent intent, String instanceName, ServiceConnection connection) {
            return context.bindIsolatedService(
                    intent, Context.BIND_AUTO_CREATE, instanceName, Runnable::run, connection);
        }

        @Override
        public void unbind(Context context, ServiceConnection connection) {
            context.unbindService(connection);
        }

        @Override
        public int transactGetIsolatedUid(IBinder binder) throws Exception {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(RiskIsolatedProbeService.DESCRIPTOR);
                boolean ok = binder.transact(
                        RiskIsolatedProbeService.TRANSACTION_GET_ISOLATED_UID, data, reply, 0);
                if (!ok) {
                    return -1;
                }
                reply.readException();
                return reply.readInt();
            } finally {
                data.recycle();
                reply.recycle();
            }
        }

        @Override
        public String transactReadGrantedChain(IBinder binder, long grantId) throws Exception {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(RiskIsolatedProbeService.DESCRIPTOR);
                data.writeLong(grantId);
                IBinder ks2Binder = lookupKeystore2Binder();
                data.writeInt(ks2Binder != null ? 1 : 0);
                if (ks2Binder != null) {
                    data.writeStrongBinder(ks2Binder);
                }
                boolean ok = binder.transact(
                        RiskIsolatedProbeService.TRANSACTION_READ_GRANTED_KEY_CHAIN, data, reply, 0);
                if (!ok) {
                    return "UNAVAILABLE|binder_transact_false";
                }
                reply.readException();
                return reply.readString();
            } finally {
                data.recycle();
                reply.recycle();
            }
        }

        @Override
        public String generateEphemeralAppChainSummary(String alias, byte[] challenge) throws Exception {
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(spec);
            kpg.generateKeyPair();

            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Certificate[] chain = ks.getCertificateChain(alias);
            if (chain == null || chain.length == 0) {
                return "KEY_NOT_FOUND|owner_chain_empty";
            }
            return RiskIsolatedProbeService.formatChainDigestSummary(Arrays.asList(chain));
        }

        @Override
        public long grantKeyAccess(Context context, String alias, int granteeUid) throws Exception {
            // Path A: android.security.keystore.KeyStoreManager (public on API 36, hidden on some API 35 builds)
            Object ksm = resolveKeyStoreManager(context);
            if (ksm != null) {
                try {
                    Method grant = resolveMethod(ksm.getClass(), "grantKeyAccess", String.class, int.class);
                    Object res = grant.invoke(ksm, alias, granteeUid);
                    if (res instanceof Number) {
                        return ((Number) res).longValue();
                    }
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    if (RiskIsolatedProbeService.isStrictKeyNotFoundThrowable(e)) {
                        if (e instanceof Exception) {
                            throw (Exception) e;
                        }
                        throw new IllegalStateException(e);
                    }
                    // Fall through to Path B on API 31-35 when KeyStoreManager grant is hidden/restricted
                }
            }

            // Path B: Keystore2 VINTF-stable Binder wire grant(KeyDescriptor, granteeUid, accessVector)
            IBinder ks2Binder = Keystore2ParcelClient.lookupServiceBinder();
            if (ks2Binder == null) {
                throw new UnsupportedOperationException("Keystore2 grant binder unavailable");
            }
            int accessVector = Keystore2ParcelClient.PERM_GET_INFO | Keystore2ParcelClient.PERM_USE;
            Keystore2ParcelClient.KeyDescriptor grantDesc = Keystore2ParcelClient.grant(
                    ks2Binder,
                    Keystore2ParcelClient.KeyDescriptor.app(alias),
                    granteeUid,
                    accessVector);
            if (grantDesc == null) {
                throw new IllegalStateException("Keystore2 grant() returned null descriptor");
            }
            return grantDesc.nspace;
        }

        @Override
        public void revokeKeyAccess(Context context, String alias, int granteeUid) {
            boolean revoked = false;
            try {
                Object ksm = resolveKeyStoreManager(context);
                if (ksm != null) {
                    Method revoke = resolveMethod(ksm.getClass(), "revokeKeyAccess", String.class, int.class);
                    revoke.invoke(ksm, alias, granteeUid);
                    revoked = true;
                }
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                // Fall through to Path B cleanup
            }
            if (!revoked) {
                try {
                    IBinder ks2Binder = Keystore2ParcelClient.lookupServiceBinder();
                    if (ks2Binder != null) {
                        Keystore2ParcelClient.ungrant(
                                ks2Binder,
                                Keystore2ParcelClient.KeyDescriptor.app(alias),
                                granteeUid);
                    }
                } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                    // Best-effort cleanup in finally
                }
            }
        }

        @Override
        public void deleteEphemeralAlias(String alias) {
            try {
                KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);
                if (ks.containsAlias(alias)) {
                    ks.deleteEntry(alias);
                }
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                // Best-effort cleanup in finally
            }
        }

        private Object resolveKeyStoreManager(Context context) {
            try {
                Class<?> cls = Class.forName("android.security.keystore.KeyStoreManager");
                if (context != null) {
                    try {
                        Object svc = context.getSystemService(cls);
                        if (svc != null) {
                            return svc;
                        }
                    } catch (Exception | LinkageError ignored) {
                    }
                }
                try {
                    Method getInstance = resolveMethod(cls, "getInstance");
                    Object inst = getInstance.invoke(null);
                    if (inst != null) {
                        return inst;
                    }
                } catch (Exception | LinkageError ignored) {
                }
            } catch (Exception | LinkageError ignored) {
            }
            return null;
        }

        private IBinder lookupKeystore2Binder() {
            return Keystore2ParcelClient.lookupServiceBinder();
        }

        private Method resolveMethod(Class<?> cls, String name, Class<?>... params)
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
    };

    /** Injectable seam allowing deterministic pure-JVM unit testing of bind/unbind/timeout paths. */
    public interface ServiceProbeAdapter {
        boolean isServiceDeclared(Context context, Intent intent);

        boolean bind(Context context, Intent intent, ServiceConnection connection);

        void unbind(Context context, ServiceConnection connection);

        String transactMountView(IBinder binder) throws Exception;
    }

    private static final ServiceProbeAdapter DEFAULT_ADAPTER = new ServiceProbeAdapter() {
        @Override
        public boolean isServiceDeclared(Context context, Intent intent) {
            try {
                PackageManager pm = context.getPackageManager();
                if (pm == null) {
                    return false;
                }
                ResolveInfo info = pm.resolveService(intent, 0);
                return info != null && info.serviceInfo != null;
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                return false;
            }
        }

        @Override
        public boolean bind(Context context, Intent intent, ServiceConnection connection) {
            return context.bindService(intent, connection, Context.BIND_AUTO_CREATE);
        }

        @Override
        public void unbind(Context context, ServiceConnection connection) {
            context.unbindService(connection);
        }

        @Override
        public String transactMountView(IBinder binder) throws Exception {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(RiskIsolatedProbeService.DESCRIPTOR);
                boolean ok = binder.transact(
                        RiskIsolatedProbeService.TRANSACTION_COLLECT_MOUNT_VIEW,
                        data, reply, 0);
                if (!ok) {
                    return null;
                }
                reply.readException();
                return reply.readString();
            } finally {
                data.recycle();
                reply.recycle();
            }
        }
    };

    private IsolatedProbeClient() {}

    /** Executes an ephemeral isolated-process mount diff probe with the default timeout. */
    public static SignalResult<IsolatedMountReport> probeMountView(Context context,
                                                                   SignalSnapshot signals,
                                                                   boolean enabled) {
        return probeMountViewForTest(context, signals, enabled, DEFAULT_TIMEOUT_MS, DEFAULT_ADAPTER);
    }

    /** Internal test seam to exercise RiskIsolatedProbeService fail-closed onBind() on JVM. */
    public static IBinder bindServiceForTest(java.util.function.BooleanSupplier isolatedChecker,
                                             Intent intent) {
        return new RiskIsolatedProbeService(isolatedChecker).onBind(intent);
    }

    /** Internal test seam to exercise RiskIsolatedProbeService grant readback on JVM. */
    public static IBinder bindGrantServiceForTest(java.util.function.BooleanSupplier isolatedChecker,
                                                  java.util.function.LongFunction<String> grantReader,
                                                  Intent intent) {
        return new RiskIsolatedProbeService(isolatedChecker, grantReader).onBind(intent);
    }

    /** Internal test seam to exercise RiskIsolatedProbeService fail-closed grant transaction guard on JVM. */
    public static String readGrantedChainForTest(java.util.function.BooleanSupplier isolatedChecker,
                                                 java.util.function.LongFunction<String> grantReader,
                                                 long grantId) {
        return new RiskIsolatedProbeService(isolatedChecker, grantReader)
                .handleReadGrantedChainForTest(grantId);
    }

    /** Internal test seam to exercise RiskIsolatedProbeService fail-closed UID transaction guard on JVM. */
    public static int getIsolatedUidForTest(java.util.function.BooleanSupplier isolatedChecker) {
        return new RiskIsolatedProbeService(isolatedChecker).handleGetIsolatedUidForTest();
    }

    /**
     * Runs an ephemeral Keystore2 Domain.APP vs Domain.GRANT chain comparison using a dynamically
     * bound isolated UID via {@link Context#bindIsolatedService}. Always revokes grant, deletes
     * the temporary keystore alias, and calls {@code unbindService()} in {@code finally}.
     */
    public static SignalResult<IsolatedGrantReport> probeGrantDomainChain(
            Context context, boolean enabled) {
        return probeGrantDomainChainForTest(context, enabled, DEFAULT_GRANT_TIMEOUT_MS, DEFAULT_GRANT_ADAPTER);
    }

    public static SignalResult<IsolatedGrantReport> probeGrantDomainChainForTest(
            Context context,
            boolean enabled,
            long timeoutMs,
            GrantProbeAdapter adapter) {
        if (!enabled) {
            return SignalResult.unavailable("isolated_probe_disabled");
        }
        if (adapter == null) {
            return SignalResult.unavailable("grant_adapter_null");
        }
        if (adapter.getSdkInt() < 31) {
            return SignalResult.unavailable("api_below_31");
        }
        if (context == null) {
            return SignalResult.unavailable("context_unavailable");
        }
        Context appContext = context.getApplicationContext();
        Context bindContext = appContext != null ? appContext : context;
        long effectiveTimeoutMs = Math.max(50L, timeoutMs);

        Intent intent = new Intent(bindContext, RiskIsolatedProbeService.class);
        if (!adapter.isServiceDeclared(bindContext, intent)) {
            return SignalResult.unavailable("isolated_service_not_declared");
        }

        long startNanos = System.nanoTime();
        CountDownLatch connectedLatch = new CountDownLatch(1);
        AtomicReference<IBinder> binderRef = new AtomicReference<>();
        AtomicBoolean nullBinding = new AtomicBoolean(false);
        AtomicBoolean bound = new AtomicBoolean(false);
        AtomicBoolean cancelled = new AtomicBoolean(false);
        AtomicBoolean aliasTouched = new AtomicBoolean(false);
        AtomicBoolean grantCreated = new AtomicBoolean(false);
        AtomicReference<Integer> grantedUidRef = new AtomicReference<>(-1);

        final String tempAlias = "riskengine_ephem_grant_" + UUID.randomUUID().toString().replace("-", "");
        final String instanceName = "grant_" + UUID.randomUUID().toString().replace("-", "");

        ServiceConnection connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                binderRef.set(service);
                connectedLatch.countDown();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                binderRef.set(null);
            }

            @Override
            public void onNullBinding(ComponentName name) {
                nullBinding.set(true);
                connectedLatch.countDown();
            }

            @Override
            public void onBindingDied(ComponentName name) {
                connectedLatch.countDown();
            }
        };

        try {
            SafeExecutor.SafeResult<SignalResult<IsolatedGrantReport>> exec =
                    SafeExecutor.safeWithTimeoutOrInline(
                            effectiveTimeoutMs,
                            () -> executeGrantProbe(
                                    bindContext, intent, instanceName, tempAlias,
                                    effectiveTimeoutMs, startNanos, adapter, connection,
                                    connectedLatch, binderRef, nullBinding, bound,
                                    cancelled, aliasTouched, grantCreated, grantedUidRef));
            if (exec.isTimedOut()) {
                cancelled.set(true);
                return SignalResult.unavailable("isolated_grant_probe_timeout");
            }
            if (!exec.isSuccess() || exec.getOrNull() == null) {
                cancelled.set(true);
                Throwable err = exec.getError();
                return SignalResult.unavailable(
                        err == null ? "isolated_grant_probe_failed" : err.getClass().getSimpleName());
            }
            return exec.getOrNull();
        } finally {
            cancelled.set(true);
            cleanupGrantProbe(bindContext, tempAlias, aliasTouched, grantCreated, grantedUidRef, bound, connection, adapter);
        }
    }

    private static SignalResult<IsolatedGrantReport> executeGrantProbe(
            Context bindContext,
            Intent intent,
            String instanceName,
            String tempAlias,
            long timeoutMs,
            long startNanos,
            GrantProbeAdapter adapter,
            ServiceConnection connection,
            CountDownLatch connectedLatch,
            AtomicReference<IBinder> binderRef,
            AtomicBoolean nullBinding,
            AtomicBoolean bound,
            AtomicBoolean cancelled,
            AtomicBoolean aliasTouched,
            AtomicBoolean grantCreated,
            AtomicReference<Integer> grantedUidRef) {
        try {
            if (isCancelledOrInterrupted(cancelled)) {
                return SignalResult.unavailable("isolated_grant_probe_cancelled");
            }
            boolean bindRequested;
            try {
                bindRequested = adapter.bindIsolated(bindContext, intent, instanceName, connection);
            } catch (SecurityException | IllegalArgumentException | UnsupportedOperationException e) {
                return SignalResult.unavailable("bind_isolated_denied:" + e.getClass().getSimpleName());
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                return SignalResult.unavailable("bind_isolated_error:" + e.getClass().getSimpleName());
            }
            if (!bindRequested) {
                return SignalResult.unavailable("bind_isolated_returned_false");
            }
            bound.set(true);
            if (isCancelledOrInterrupted(cancelled)) {
                return SignalResult.unavailable("isolated_grant_probe_cancelled");
            }

            long waitMs = Math.max(20L, timeoutMs - 20L);
            boolean latched;
            try {
                latched = connectedLatch.await(waitMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return SignalResult.unavailable("isolated_grant_interrupted");
            }
            if (!latched) {
                return SignalResult.unavailable("isolated_grant_connect_timeout");
            }
            if (isCancelledOrInterrupted(cancelled)) {
                return SignalResult.unavailable("isolated_grant_probe_cancelled");
            }
            if (nullBinding.get()) {
                return SignalResult.unavailable("isolated_service_refused_non_isolated");
            }
            IBinder binder = binderRef.get();
            if (binder == null) {
                return SignalResult.unavailable("isolated_grant_binder_null");
            }

            int isolatedUid;
            try {
                isolatedUid = adapter.transactGetIsolatedUid(binder);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                return SignalResult.unavailable("isolated_uid_error:" + e.getClass().getSimpleName());
            }
            if (isolatedUid < 0) {
                return SignalResult.unavailable("isolated_uid_invalid");
            }
            grantedUidRef.set(isolatedUid);
            if (isCancelledOrInterrupted(cancelled)) {
                return SignalResult.unavailable("isolated_grant_probe_cancelled");
            }

            byte[] challenge = new byte[32];
            new SecureRandom().nextBytes(challenge);
            String appSummary;
            aliasTouched.set(true);
            try {
                appSummary = adapter.generateEphemeralAppChainSummary(tempAlias, challenge);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                return SignalResult.unavailable("owner_keygen_failed:" + e.getClass().getSimpleName());
            } finally {
                // Re-arm after keygen settles so if an outer timeout drained aliasTouched mid-IPC,
                // this worker's finally still guarantees deletion of the persisted ephemeral key.
                aliasTouched.set(true);
            }
            if (isCancelledOrInterrupted(cancelled)) {
                return SignalResult.unavailable("isolated_grant_probe_cancelled");
            }
            if (appSummary == null || !appSummary.startsWith("OK|")) {
                return SignalResult.unavailable("owner_chain_unavailable");
            }

            long grantId;
            try {
                grantId = adapter.grantKeyAccess(bindContext, tempAlias, isolatedUid);
                grantCreated.set(true);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
                if (isKeyNotFoundThrowable(e)) {
                    // Owner Domain.APP returned a chain, yet Keystore2 grant reports KEY_NOT_FOUND
                    // -> synthetic/intercepted key not persisted in real Keystore2!
                    return SignalResult.success(new IsolatedGrantReport(
                            appSummary,
                            null,
                            IsolatedGrantReport.GrantReadStatus.KEY_NOT_FOUND_ON_GRANT,
                            isolatedUid,
                            elapsed,
                            "grant_key_not_found_after_owner_chain"));
                }
                return SignalResult.unavailable("grant_unavailable:" + e.getClass().getSimpleName());
            }
            if (isCancelledOrInterrupted(cancelled)) {
                return SignalResult.unavailable("isolated_grant_probe_cancelled");
            }

            String grantSummary;
            try {
                grantSummary = adapter.transactReadGrantedChain(binder, grantId);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                return SignalResult.unavailable("isolated_readback_error:" + e.getClass().getSimpleName());
            }

            long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
            if (grantSummary == null || grantSummary.startsWith("UNAVAILABLE|")) {
                return SignalResult.unavailable(
                        grantSummary == null ? "grant_readback_null" : grantSummary);
            }
            if (grantSummary.startsWith("KEY_NOT_FOUND|")) {
                return SignalResult.success(new IsolatedGrantReport(
                        appSummary,
                        grantSummary,
                        IsolatedGrantReport.GrantReadStatus.KEY_NOT_FOUND_ON_READBACK,
                        isolatedUid,
                        elapsed,
                        grantSummary));
            }
            if (!grantSummary.startsWith("OK|")) {
                return SignalResult.unavailable("grant_readback_malformed");
            }
            return SignalResult.success(new IsolatedGrantReport(
                    appSummary,
                    grantSummary,
                    IsolatedGrantReport.GrantReadStatus.OK,
                    isolatedUid,
                    elapsed,
                    "ok"));
        } finally {
            cleanupGrantProbe(bindContext, tempAlias, aliasTouched, grantCreated, grantedUidRef, bound, connection, adapter);
        }
    }

    private static boolean isCancelledOrInterrupted(AtomicBoolean cancelled) {
        return cancelled.get() || Thread.currentThread().isInterrupted();
    }

    private static void cleanupGrantProbe(
            Context bindContext,
            String tempAlias,
            AtomicBoolean aliasTouched,
            AtomicBoolean grantCreated,
            AtomicReference<Integer> grantedUidRef,
            AtomicBoolean bound,
            ServiceConnection connection,
            GrantProbeAdapter adapter) {
        if (grantCreated.compareAndSet(true, false)) {
            Integer uid = grantedUidRef.get();
            if (uid != null && uid >= 0) {
                try {
                    adapter.revokeKeyAccess(bindContext, tempAlias, uid);
                } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                }
            }
        }
        if (aliasTouched.compareAndSet(true, false)) {
            try {
                adapter.deleteEphemeralAlias(tempAlias);
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            }
        }
        if (bound.compareAndSet(true, false)) {
            try {
                adapter.unbind(bindContext, connection);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                CLog.w("Failed to unbind RiskIsolatedProbeService (grant): " + e.getMessage());
            }
        }
    }

    private static boolean isKeyNotFoundThrowable(Throwable t) {
        return RiskIsolatedProbeService.isStrictKeyNotFoundThrowable(t);
    }

    /** Internal test seam allowing deterministic JVM verification of bind/unbind/timeout flows. */
    public static SignalResult<IsolatedMountReport> probeMountViewForTest(
            Context context,
            SignalSnapshot signals,
            boolean enabled,
            long timeoutMs,
            ServiceProbeAdapter adapter) {
        if (!enabled) {
            return SignalResult.unavailable("isolated_probe_disabled");
        }
        if (context == null) {
            return SignalResult.unavailable("context_unavailable");
        }
        Context appContext = context.getApplicationContext();
        Context bindContext = appContext != null ? appContext : context;
        long effectiveTimeoutMs = Math.max(50L, timeoutMs);

        Intent intent = new Intent(bindContext, RiskIsolatedProbeService.class);
        if (!adapter.isServiceDeclared(bindContext, intent)) {
            return SignalResult.unavailable("isolated_service_not_declared");
        }

        long startNanos = System.nanoTime();
        CountDownLatch connectedLatch = new CountDownLatch(1);
        AtomicReference<IBinder> binderRef = new AtomicReference<>();
        AtomicBoolean nullBinding = new AtomicBoolean(false);
        AtomicBoolean bound = new AtomicBoolean(false);

        ServiceConnection connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                binderRef.set(service);
                connectedLatch.countDown();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                binderRef.set(null);
            }

            @Override
            public void onNullBinding(ComponentName name) {
                nullBinding.set(true);
                connectedLatch.countDown();
            }

            @Override
            public void onBindingDied(ComponentName name) {
                connectedLatch.countDown();
            }
        };

        try {
            SafeExecutor.SafeResult<SignalResult<IsolatedMountReport>> exec =
                    SafeExecutor.safeWithTimeoutOrInline(
                            effectiveTimeoutMs,
                            () -> executeBoundProbe(
                                    bindContext, intent, signals, effectiveTimeoutMs,
                                    startNanos, adapter, connection, connectedLatch,
                                    binderRef, nullBinding, bound));

            if (exec.isTimedOut()) {
                return SignalResult.unavailable("isolated_probe_timeout");
            }
            if (!exec.isSuccess() || exec.getOrNull() == null) {
                Throwable err = exec.getError();
                String reason = err == null
                        ? "isolated_probe_failed" : err.getClass().getSimpleName();
                return SignalResult.error(reason);
            }
            return exec.getOrNull();
        } finally {
            unbindIfBound(bound, bindContext, connection, adapter);
        }
    }

    private static SignalResult<IsolatedMountReport> executeBoundProbe(
            Context bindContext,
            Intent intent,
            SignalSnapshot signals,
            long timeoutMs,
            long startNanos,
            ServiceProbeAdapter adapter,
            ServiceConnection connection,
            CountDownLatch connectedLatch,
            AtomicReference<IBinder> binderRef,
            AtomicBoolean nullBinding,
            AtomicBoolean bound) {
        try {
            boolean bindRequested;
            try {
                bindRequested = adapter.bind(bindContext, intent, connection);
            } catch (SecurityException | IllegalArgumentException e) {
                return SignalResult.unavailable(
                        "isolated_service_bind_denied:" + e.getClass().getSimpleName());
            } catch (Exception | LinkageError e) {
                return SignalResult.error(e.getClass().getSimpleName());
            }

            if (!bindRequested) {
                return SignalResult.unavailable("isolated_service_bind_returned_false");
            }
            bound.set(true);

            long waitMs = Math.max(20L, timeoutMs - 20L);
            boolean latched;
            try {
                latched = connectedLatch.await(waitMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return SignalResult.unavailable("isolated_probe_interrupted");
            }
            if (!latched) {
                return SignalResult.unavailable("isolated_service_connect_timeout");
            }
            if (nullBinding.get()) {
                return SignalResult.unavailable("isolated_service_refused_non_isolated");
            }
            IBinder binder = binderRef.get();
            if (binder == null) {
                return SignalResult.unavailable("isolated_service_binder_null");
            }

            String isolatedPayload;
            try {
                isolatedPayload = adapter.transactMountView(binder);
            } catch (Exception | LinkageError e) {
                return SignalResult.error("isolated_transact_" + e.getClass().getSimpleName());
            }

            if (isolatedPayload == null || isolatedPayload.isBlank()) {
                return SignalResult.unavailable("isolated_mountinfo_empty");
            }

            List<String> isolatedLines = splitLines(isolatedPayload);
            List<String> mainLines = readMainMountInfoLines(signals);
            if (mainLines.isEmpty()) {
                return SignalResult.unavailable("main_mountinfo_unreadable");
            }

            MountViewNormalizer.MountDiffResult diff =
                    MountViewNormalizer.diffViews(mainLines, isolatedLines);
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
            return SignalResult.success(new IsolatedMountReport(diff, elapsedMs));
        } finally {
            unbindIfBound(bound, bindContext, connection, adapter);
        }
    }

    private static void unbindIfBound(AtomicBoolean bound,
                                      Context bindContext,
                                      ServiceConnection connection,
                                      ServiceProbeAdapter adapter) {
        if (bound.compareAndSet(true, false)) {
            try {
                adapter.unbind(bindContext, connection);
            } catch (Exception | LinkageError e) {
                CLog.w("Failed to unbind RiskIsolatedProbeService: " + e.getMessage());
            }
        }
    }

    private static List<String> readMainMountInfoLines(SignalSnapshot signals) {
        if (signals == null) {
            return Collections.emptyList();
        }
        SignalResult<String> file = signals.getTextFile("/proc/self/mountinfo");
        if (file == null || !file.isSuccess() || file.getValue() == null || file.getValue().isBlank()) {
            return Collections.emptyList();
        }
        return splitLines(file.getValue());
    }

    private static List<String> splitLines(String text) {
        if (text == null || text.isEmpty()) {
            return Collections.emptyList();
        }
        String[] raw = text.split("\\r?\\n");
        List<String> out = new ArrayList<>(raw.length);
        for (String line : raw) {
            if (!line.isBlank()) {
                out.add(line);
            }
        }
        return out;
    }
}
