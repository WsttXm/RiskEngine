package com.wsttxm.riskenginesdk.detector.probe.threat;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;

/**
 * Exact Thanox IPC verification probe via the {@code dropbox} system service Binder.
 *
 * <p>Sends the Thanox {@code IPC_TRANS_CODE_THANOS_SERVER} transaction with interface token
 * {@code github.tornaco.android.thanos.core.IThanos} and strictly verifies that the returned
 * server {@link IBinder#getInterfaceDescriptor()} equals
 * {@code "github.tornaco.android.thanos.core.IThanos"}.</p>
 *
 * <p>Eliminates OriginOS and stock OEM {@code dropbox} false positives where {@code transact()}
 * may return {@code true} or an unrelated Binder descriptor.</p>
 */
public final class ThanoxIpcProbe {

    public static final String FAMILY_HMA_HIDING = "hma_hiding";
    public static final String THANOX_DESCRIPTOR = "github.tornaco.android.thanos.core.IThanos";
    public static final int THANOX_TRANSACTION =
            "github.tornaco.android.thanos.core.IPC_TRANS_CODE_THANOS_SERVER".hashCode();

    public enum ProbeState {
        DETECTED,
        CLEAN,
        UNAVAILABLE
    }

    /** Injectable Binder transaction adapter so pure-JVM tests run without native Parcel stubs. */
    public interface DropBoxTransactAdapter {
        /**
         * Queries the {@code dropbox} Binder with {@link #THANOX_TRANSACTION} and
         * {@link #THANOX_DESCRIPTOR}.
         */
        TransactOutcome queryDropBox();
    }

    public static final class TransactOutcome {
        public enum Kind {
            SERVICE_UNAVAILABLE,
            NOT_HANDLED,
            EMPTY_OR_NO_BINDER,
            RETURNED_BINDER,
            ERROR
        }

        private final Kind kind;
        private final String returnedDescriptor;
        private final String detail;

        public TransactOutcome(Kind kind, String returnedDescriptor, String detail) {
            this.kind = kind;
            this.returnedDescriptor = returnedDescriptor;
            this.detail = detail == null ? "" : detail;
        }

        public Kind getKind() {
            return kind;
        }

        public String getReturnedDescriptor() {
            return returnedDescriptor;
        }

        public String getDetail() {
            return detail;
        }
    }

    public static final class ProbeOutcome {
        private final ProbeState state;
        private final List<EvidenceItem> evidenceItems;
        private final List<String> details;
        private final String observedDescriptor;
        private final String diagnostic;

        ProbeOutcome(ProbeState state,
                     List<EvidenceItem> evidenceItems,
                     List<String> details,
                     String observedDescriptor,
                     String diagnostic) {
            this.state = state;
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
            this.details = Collections.unmodifiableList(details);
            this.observedDescriptor = observedDescriptor;
            this.diagnostic = diagnostic == null ? "" : diagnostic;
        }

        public ProbeState getState() {
            return state;
        }

        public List<EvidenceItem> getEvidenceItems() {
            return evidenceItems;
        }

        public List<String> getDetails() {
            return details;
        }

        public String getObservedDescriptor() {
            return observedDescriptor;
        }

        public String getDiagnostic() {
            return diagnostic;
        }

        public boolean isDetected() {
            return !evidenceItems.isEmpty();
        }
    }

    private final DropBoxTransactAdapter adapter;

    public ThanoxIpcProbe() {
        this(defaultDropBoxAdapter());
    }

    public ThanoxIpcProbe(DropBoxTransactAdapter adapter) {
        this.adapter = adapter;
    }

    public ProbeOutcome probe() {
        if (adapter == null) {
            return new ProbeOutcome(ProbeState.UNAVAILABLE, Collections.emptyList(),
                    Collections.emptyList(), null, "adapter_null");
        }
        TransactOutcome out;
        try {
            out = adapter.queryDropBox();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return new ProbeOutcome(ProbeState.UNAVAILABLE, Collections.emptyList(),
                    Collections.emptyList(), null, "adapter_exception");
        }
        if (out == null) {
            return new ProbeOutcome(ProbeState.UNAVAILABLE, Collections.emptyList(),
                    Collections.emptyList(), null, "outcome_null");
        }

        switch (out.getKind()) {
            case RETURNED_BINDER:
                String desc = out.getReturnedDescriptor();
                if (THANOX_DESCRIPTOR.equals(desc)) {
                    List<String> details = Collections.singletonList("thanox_ipc_active:" + desc);
                    List<EvidenceItem> items = Collections.singletonList(new EvidenceItem(
                            "thanox_ipc_active",
                            EvidenceItem.SourceLayer.JAVA,
                            "dropbox",
                            desc,
                            FAMILY_HMA_HIDING,
                            EvidenceItem.Rank.STRONG));
                    return new ProbeOutcome(ProbeState.DETECTED, items, details, desc, "matched");
                }
                // Non-Thanos descriptor (e.g. OriginOS or stock dropbox reply) -> strictly 0 FP!
                return new ProbeOutcome(ProbeState.CLEAN, Collections.emptyList(),
                        Collections.emptyList(), desc, "non_thanox_descriptor");

            case NOT_HANDLED:
                return new ProbeOutcome(ProbeState.CLEAN, Collections.emptyList(),
                        Collections.emptyList(), null, "not_handled");

            case EMPTY_OR_NO_BINDER:
                return new ProbeOutcome(ProbeState.CLEAN, Collections.emptyList(),
                        Collections.emptyList(), null, "empty_or_no_binder");

            case SERVICE_UNAVAILABLE:
            case ERROR:
            default:
                return new ProbeOutcome(ProbeState.UNAVAILABLE, Collections.emptyList(),
                        Collections.emptyList(), null, out.getDetail());
        }
    }

    private static DropBoxTransactAdapter defaultDropBoxAdapter() {
        return () -> {
            IBinder service = lookupDropBoxService();
            if (service == null) {
                return new TransactOutcome(
                        TransactOutcome.Kind.SERVICE_UNAVAILABLE, null, "dropbox_unavailable");
            }
            Parcel data = null;
            Parcel reply = null;
            try {
                data = Parcel.obtain();
                reply = Parcel.obtain();
                data.writeInterfaceToken(THANOX_DESCRIPTOR);
                if (!service.transact(THANOX_TRANSACTION, data, reply, 0)) {
                    return new TransactOutcome(
                            TransactOutcome.Kind.NOT_HANDLED, null, "not_handled");
                }
                if (reply.dataSize() == 0) {
                    return new TransactOutcome(
                            TransactOutcome.Kind.EMPTY_OR_NO_BINDER, null, "empty_reply");
                }
                reply.setDataPosition(0);
                IBinder server = reply.readStrongBinder();
                if (server == null) {
                    return new TransactOutcome(
                            TransactOutcome.Kind.EMPTY_OR_NO_BINDER, null, "no_strong_binder");
                }
                String descriptor = server.getInterfaceDescriptor();
                return new TransactOutcome(
                        TransactOutcome.Kind.RETURNED_BINDER, descriptor, "returned_binder");
            } catch (SecurityException e) {
                return new TransactOutcome(TransactOutcome.Kind.ERROR, null, "security_denied");
            } catch (RemoteException e) {
                return new TransactOutcome(TransactOutcome.Kind.ERROR, null, "remote_error");
            } catch (RuntimeException | LinkageError | OutOfMemoryError e) {
                return new TransactOutcome(TransactOutcome.Kind.ERROR, null, "malformed_reply");
            } finally {
                if (data != null) {
                    data.recycle();
                }
                if (reply != null) {
                    reply.recycle();
                }
            }
        };
    }

    private static IBinder lookupDropBoxService() {
        try {
            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Method getService = smClass.getMethod("getService", String.class);
            Object raw = getService.invoke(null, "dropbox");
            return raw instanceof IBinder ? (IBinder) raw : null;
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            return null;
        }
    }
}
