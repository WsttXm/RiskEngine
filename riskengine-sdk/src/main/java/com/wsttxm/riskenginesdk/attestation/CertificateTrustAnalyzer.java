package com.wsttxm.riskenginesdk.attestation;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Validates an X.509 Android Key Attestation certificate chain:
 * <ol>
 *   <li>Cryptographic signature verification along every link + self-signed root</li>
 *   <li>Issuer / Subject DN continuity &amp; CA basic-constraints check</li>
 *   <li>Validity window check ({@code notBefore <= evalDate <= notAfter})</li>
 *   <li>Google Hardware Attestation Root SPKI/DER anchor match</li>
 *   <li>Monotonic offline CRL check against every certificate serial in the chain</li>
 * </ol>
 */
public final class CertificateTrustAnalyzer {

    public enum TrustRoot {
        GOOGLE,
        AOSP_SOFTWARE,
        FACTORY_OR_UNKNOWN,
        NONE
    }

    public static final class TrustResult {
        private final TrustRoot trustRoot;
        private final int chainLength;
        private final boolean chainSignatureValid;
        private final boolean googleRootMatched;
        private final boolean validityWindowValid;
        private final boolean issuerChainValid;
        private final boolean anyCertRevoked;
        private final String rootSpkiSha256;
        private final List<String> revokedSerials;
        private final List<String> issuerMismatches;
        private final List<String> validityIssues;
        private final String signatureError;

        private TrustResult(Builder b) {
            this.trustRoot = b.trustRoot;
            this.chainLength = b.chainLength;
            this.chainSignatureValid = b.chainSignatureValid;
            this.googleRootMatched = b.googleRootMatched;
            this.validityWindowValid = b.validityIssues.isEmpty() && b.chainLength > 0;
            this.issuerChainValid = b.issuerMismatches.isEmpty() && b.chainLength > 0;
            this.anyCertRevoked = !b.revokedSerials.isEmpty();
            this.rootSpkiSha256 = b.rootSpkiSha256;
            this.revokedSerials = Collections.unmodifiableList(new ArrayList<>(b.revokedSerials));
            this.issuerMismatches = Collections.unmodifiableList(new ArrayList<>(b.issuerMismatches));
            this.validityIssues = Collections.unmodifiableList(new ArrayList<>(b.validityIssues));
            this.signatureError = b.signatureError;
        }

        public TrustRoot getTrustRoot() {
            return trustRoot;
        }

        public int getChainLength() {
            return chainLength;
        }

        public boolean isChainSignatureValid() {
            return chainSignatureValid;
        }

        public boolean isGoogleRootMatched() {
            return googleRootMatched;
        }

        public boolean isValidityWindowValid() {
            return validityWindowValid;
        }

        public boolean isIssuerChainValid() {
            return issuerChainValid;
        }

        public boolean isAnyCertRevoked() {
            return anyCertRevoked;
        }

        public String getRootSpkiSha256() {
            return rootSpkiSha256;
        }

        public List<String> getRevokedSerials() {
            return revokedSerials;
        }

        public List<String> getIssuerMismatches() {
            return issuerMismatches;
        }

        public List<String> getValidityIssues() {
            return validityIssues;
        }

        public String getSignatureError() {
            return signatureError;
        }

        /** True only if chain >= 2, signatures valid, issuer chain valid, validity valid, Google root matched, and not revoked. */
        public boolean isFullyTrustedGoogleHardware() {
            return chainLength >= 2
                    && chainSignatureValid
                    && issuerChainValid
                    && validityWindowValid
                    && googleRootMatched
                    && !anyCertRevoked;
        }

        static final class Builder {
            TrustRoot trustRoot = TrustRoot.NONE;
            int chainLength;
            boolean chainSignatureValid;
            boolean googleRootMatched;
            String rootSpkiSha256;
            final List<String> revokedSerials = new ArrayList<>();
            final List<String> issuerMismatches = new ArrayList<>();
            final List<String> validityIssues = new ArrayList<>();
            String signatureError;

            TrustResult build() {
                return new TrustResult(this);
            }
        }
    }

    private static final String[] AOSP_PATTERNS = {
        "android keystore software attestation",
        "software attestation",
        "cn=android, o=android, c=us",
        "cn=android,o=android,c=us"
    };

    private final GoogleAttestationRootStore rootStore;

    public CertificateTrustAnalyzer() {
        this(GoogleAttestationRootStore.getDefault());
    }

    public CertificateTrustAnalyzer(GoogleAttestationRootStore rootStore) {
        this.rootStore = rootStore == null ? GoogleAttestationRootStore.getDefault() : rootStore;
    }

    public TrustResult inspect(List<X509Certificate> chain) {
        return inspect(chain, new Date());
    }

    public TrustResult inspect(List<X509Certificate> chain, Date evaluationTime) {
        TrustResult.Builder b = new TrustResult.Builder();
        if (chain == null || chain.isEmpty()) {
            return b.build();
        }
        for (X509Certificate cert : chain) {
            if (cert == null) {
                b.signatureError = "Null certificate in chain";
                return b.build();
            }
        }

        Date evalDate = evaluationTime == null ? new Date() : evaluationTime;
        b.chainLength = chain.size();

        X509Certificate root = chain.get(chain.size() - 1);
        b.rootSpkiSha256 = GoogleAttestationRootStore.sha256SpkiHex(root);
        b.googleRootMatched = rootStore.matchesGoogleRoot(root);

        // 1. Cryptographic signature verification along chain + root self-signature
        try {
            for (int i = 0; i < chain.size() - 1; i++) {
                X509Certificate child = chain.get(i);
                X509Certificate issuer = chain.get(i + 1);
                child.verify(issuer.getPublicKey());
            }
            root.verify(root.getPublicKey());
            b.chainSignatureValid = true;
        } catch (Exception | LinkageError e) {
            b.chainSignatureValid = false;
            b.signatureError = e.getClass().getSimpleName()
                    + (e.getMessage() != null ? ": " + e.getMessage() : "");
        }

        // 2. Issuer/Subject continuity, CA BasicConstraints, pathLenConstraint & KeyUsage.keyCertSign
        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate child = chain.get(i);
            X509Certificate issuer = chain.get(i + 1);
            int issuerIdx = i + 1;
            if (child.getIssuerX500Principal() == null
                    || issuer.getSubjectX500Principal() == null
                    || !child.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                b.issuerMismatches.add("cert_" + i + "_issuer_mismatch");
            }
            int pathLen = issuer.getBasicConstraints();
            if (pathLen < 0) {
                b.issuerMismatches.add("cert_" + issuerIdx + "_not_ca");
            } else {
                // RFC 5280 §6.1.4: count non-self-issued intermediate CAs strictly between leaf (0) and issuerIdx
                int nonSelfIssuedIntermediates = 0;
                for (int k = 1; k < issuerIdx; k++) {
                    X509Certificate mid = chain.get(k);
                    boolean selfIssued = mid.getIssuerX500Principal() != null
                            && mid.getSubjectX500Principal() != null
                            && mid.getIssuerX500Principal().equals(mid.getSubjectX500Principal());
                    if (!selfIssued) {
                        nonSelfIssuedIntermediates++;
                    }
                }
                if (nonSelfIssuedIntermediates > pathLen) {
                    b.issuerMismatches.add("cert_" + issuerIdx + "_pathlen_exceeded");
                }
            }
            boolean[] keyUsage = issuer.getKeyUsage();
            if (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5])) {
                b.issuerMismatches.add("cert_" + issuerIdx + "_missing_key_cert_sign");
            }
        }
        // Root must be self-issued, and a single-cert chain must still have CA basicConstraints
        if (root.getIssuerX500Principal() == null
                || root.getSubjectX500Principal() == null
                || !root.getIssuerX500Principal().equals(root.getSubjectX500Principal())) {
            b.issuerMismatches.add("root_not_self_issued");
        }
        if (chain.size() == 1 && root.getBasicConstraints() < 0) {
            b.issuerMismatches.add("cert_0_not_ca");
        }

        // 3. Validity window & CRL revoked serial membership across all certs in chain
        boolean anyAosp = false;
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate cert = chain.get(i);
            try {
                cert.checkValidity(evalDate);
            } catch (Exception e) {
                b.validityIssues.add("cert_" + i + ":" + e.getClass().getSimpleName());
            }

            BigInteger serial = cert.getSerialNumber();
            if (serial != null && rootStore.isRevokedSerial(serial)) {
                BigInteger unsigned = serial.signum() < 0
                        ? new BigInteger(1, serial.toByteArray())
                        : serial;
                String normalized = GoogleAttestationRootStore.normalizeSerialToken(unsigned.toString(16));
                b.revokedSerials.add(normalized != null ? normalized : unsigned.toString());
            }

            if (looksLikeAospSoftwareCert(cert)) {
                anyAosp = true;
            }
        }

        if (b.googleRootMatched) {
            b.trustRoot = TrustRoot.GOOGLE;
        } else if (anyAosp) {
            b.trustRoot = TrustRoot.AOSP_SOFTWARE;
        } else {
            b.trustRoot = TrustRoot.FACTORY_OR_UNKNOWN;
        }

        return b.build();
    }

    private static boolean looksLikeAospSoftwareCert(X509Certificate cert) {
        String subject = cert.getSubjectX500Principal() == null
                ? ""
                : cert.getSubjectX500Principal().getName().toLowerCase(Locale.US);
        String issuer = cert.getIssuerX500Principal() == null
                ? ""
                : cert.getIssuerX500Principal().getName().toLowerCase(Locale.US);
        for (String pattern : AOSP_PATTERNS) {
            if (subject.contains(pattern) || issuer.contains(pattern)) {
                return true;
            }
        }
        return false;
    }
}
