package com.wsttxm.riskenginesdk;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable host policy controlling {@code threat_apps} detection rules and HMA side-channel
 * probes.
 *
 * <p>Allows hosts to supplement the built-in official release certificate and package catalogs
 * with custom package names, custom signing certificate SHA-256 digests, custom dangerous
 * permission combinations, and per-probe HMA feature toggles without requiring
 * {@code QUERY_ALL_PACKAGES}.
 */
public final class ThreatAppPolicy {

    /** Immutable default policy with built-in catalog and all HMA side-channel probes enabled. */
    public static final ThreatAppPolicy DEFAULT = new Builder().build();

    /**
     * Rule matching an inspected app that declares every permission in {@link #getPermissions()}.
     */
    public static final class PermissionComboRule {
        private final String name;
        private final Set<String> permissions;

        public PermissionComboRule(String name, Collection<String> permissions) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("PermissionComboRule name must not be blank");
            }
            if (permissions == null) {
                throw new IllegalArgumentException(
                        "PermissionComboRule permissions must not be null");
            }
            Set<String> normalized = new LinkedHashSet<>();
            for (String perm : permissions) {
                if (perm != null && !perm.isBlank()) {
                    normalized.add(perm.trim());
                }
            }
            if (normalized.isEmpty()) {
                throw new IllegalArgumentException(
                        "PermissionComboRule must declare at least one permission");
            }
            this.name = name.trim();
            this.permissions = Collections.unmodifiableSet(normalized);
        }

        public String getName() {
            return name;
        }

        public Set<String> getPermissions() {
            return permissions;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof PermissionComboRule)) return false;
            PermissionComboRule that = (PermissionComboRule) o;
            return name.equals(that.name) && permissions.equals(that.permissions);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, permissions);
        }

        @Override
        public String toString() {
            return "PermissionComboRule{name='" + name + "', permissions=" + permissions + '}';
        }
    }

    private final Set<String> additionalPackages;
    private final Set<String> additionalCertSha256s;
    private final List<PermissionComboRule> dangerousPermissionCombos;
    private final boolean enableBuiltInCatalog;
    private final boolean enableNativePayloadInspection;
    private final boolean enableZygotePreloadInspection;
    private final boolean enableHmaUidVisibilityProbe;
    private final boolean enableHmaCrossUserProbe;
    private final boolean enableHmaOrderedBroadcastProbe;
    private final boolean enableHmaPermissionServiceProbe;
    private final boolean enableThanoxIpcProbe;

    private ThreatAppPolicy(Builder builder) {
        this.additionalPackages = builder.additionalPackages.isEmpty()
                ? Collections.emptySet()
                : Collections.unmodifiableSet(new LinkedHashSet<>(builder.additionalPackages));
        this.additionalCertSha256s = builder.additionalCertSha256s.isEmpty()
                ? Collections.emptySet()
                : Collections.unmodifiableSet(new LinkedHashSet<>(builder.additionalCertSha256s));
        this.dangerousPermissionCombos = builder.dangerousPermissionCombos.isEmpty()
                ? Collections.emptyList()
                : Collections.unmodifiableList(new ArrayList<>(builder.dangerousPermissionCombos));
        this.enableBuiltInCatalog = builder.enableBuiltInCatalog;
        this.enableNativePayloadInspection = builder.enableNativePayloadInspection;
        this.enableZygotePreloadInspection = builder.enableZygotePreloadInspection;
        this.enableHmaUidVisibilityProbe = builder.enableHmaUidVisibilityProbe;
        this.enableHmaCrossUserProbe = builder.enableHmaCrossUserProbe;
        this.enableHmaOrderedBroadcastProbe = builder.enableHmaOrderedBroadcastProbe;
        this.enableHmaPermissionServiceProbe = builder.enableHmaPermissionServiceProbe;
        this.enableThanoxIpcProbe = builder.enableThanoxIpcProbe;
    }

    public Set<String> getAdditionalPackages() {
        return additionalPackages;
    }

    public Set<String> getAdditionalCertSha256s() {
        return additionalCertSha256s;
    }

    public List<PermissionComboRule> getDangerousPermissionCombos() {
        return dangerousPermissionCombos;
    }

    public boolean isEnableBuiltInCatalog() {
        return enableBuiltInCatalog;
    }

    public boolean isEnableNativePayloadInspection() {
        return enableNativePayloadInspection;
    }

    public boolean isEnableZygotePreloadInspection() {
        return enableZygotePreloadInspection;
    }

    public boolean isEnableHmaUidVisibilityProbe() {
        return enableHmaUidVisibilityProbe;
    }

    public boolean isEnableHmaCrossUserProbe() {
        return enableHmaCrossUserProbe;
    }

    public boolean isEnableHmaOrderedBroadcastProbe() {
        return enableHmaOrderedBroadcastProbe;
    }

    public boolean isEnableHmaPermissionServiceProbe() {
        return enableHmaPermissionServiceProbe;
    }

    public boolean isEnableThanoxIpcProbe() {
        return enableThanoxIpcProbe;
    }

    /** Returns {@code true} if at least one HMA or Thanox side-channel probe is enabled. */
    public boolean isAnyHmaProbeEnabled() {
        return enableHmaUidVisibilityProbe
                || enableHmaCrossUserProbe
                || enableHmaOrderedBroadcastProbe
                || enableHmaPermissionServiceProbe
                || enableThanoxIpcProbe;
    }

    /**
     * Normalizes a SHA-256 certificate digest (strips whitespace and {@code ':'} separators,
     * lowercases) and validates it is exactly 64 hex characters.
     */
    public static String normalizeSha256Hex(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("Certificate SHA-256 digest must not be null");
        }
        StringBuilder sb = new StringBuilder(64);
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == ':' || Character.isWhitespace(c)) {
                continue;
            }
            char lower = Character.toLowerCase(c);
            if ((lower >= '0' && lower <= '9') || (lower >= 'a' && lower <= 'f')) {
                sb.append(lower);
            } else {
                throw new IllegalArgumentException(
                        "Invalid hex character in certificate SHA-256 digest: " + raw);
            }
        }
        if (sb.length() != 64) {
            throw new IllegalArgumentException(
                    "Certificate SHA-256 digest must be 64 hex chars, got " + sb.length());
        }
        return sb.toString();
    }

    /** Returns a copy of this policy with additional package names merged in. */
    public ThreatAppPolicy withAdditionalPackages(Collection<String> extraPackages) {
        if (extraPackages == null || extraPackages.isEmpty()) {
            return this;
        }
        Builder builder = toBuilder();
        for (String pkg : extraPackages) {
            if (pkg != null && !pkg.isBlank()) {
                builder.additionalPackages.add(pkg.trim());
            }
        }
        return builder.build();
    }

    public Builder toBuilder() {
        Builder builder = new Builder();
        builder.additionalPackages.addAll(this.additionalPackages);
        builder.additionalCertSha256s.addAll(this.additionalCertSha256s);
        builder.dangerousPermissionCombos.addAll(this.dangerousPermissionCombos);
        builder.enableBuiltInCatalog = this.enableBuiltInCatalog;
        builder.enableNativePayloadInspection = this.enableNativePayloadInspection;
        builder.enableZygotePreloadInspection = this.enableZygotePreloadInspection;
        builder.enableHmaUidVisibilityProbe = this.enableHmaUidVisibilityProbe;
        builder.enableHmaCrossUserProbe = this.enableHmaCrossUserProbe;
        builder.enableHmaOrderedBroadcastProbe = this.enableHmaOrderedBroadcastProbe;
        builder.enableHmaPermissionServiceProbe = this.enableHmaPermissionServiceProbe;
        builder.enableThanoxIpcProbe = this.enableThanoxIpcProbe;
        return builder;
    }

    public static final class Builder {
        private final Set<String> additionalPackages = new LinkedHashSet<>();
        private final Set<String> additionalCertSha256s = new LinkedHashSet<>();
        private final List<PermissionComboRule> dangerousPermissionCombos = new ArrayList<>();
        private boolean enableBuiltInCatalog = true;
        private boolean enableNativePayloadInspection = true;
        private boolean enableZygotePreloadInspection = true;
        private boolean enableHmaUidVisibilityProbe = true;
        private boolean enableHmaCrossUserProbe = true;
        private boolean enableHmaOrderedBroadcastProbe = true;
        private boolean enableHmaPermissionServiceProbe = true;
        private boolean enableThanoxIpcProbe = true;

        public Builder additionalPackages(String... packages) {
            if (packages == null) {
                throw new IllegalArgumentException("additionalPackages must not be null");
            }
            for (String pkg : packages) {
                if (pkg != null && !pkg.isBlank()) {
                    additionalPackages.add(pkg.trim());
                }
            }
            return this;
        }

        public Builder additionalPackages(Collection<String> packages) {
            if (packages == null) {
                throw new IllegalArgumentException("additionalPackages must not be null");
            }
            for (String pkg : packages) {
                if (pkg != null && !pkg.isBlank()) {
                    additionalPackages.add(pkg.trim());
                }
            }
            return this;
        }

        public Builder additionalCertSha256s(String... sha256HexList) {
            if (sha256HexList == null) {
                throw new IllegalArgumentException("additionalCertSha256s must not be null");
            }
            for (String digest : sha256HexList) {
                if (digest != null && !digest.isBlank()) {
                    additionalCertSha256s.add(normalizeSha256Hex(digest));
                }
            }
            return this;
        }

        public Builder additionalCertSha256s(Collection<String> sha256HexList) {
            if (sha256HexList == null) {
                throw new IllegalArgumentException("additionalCertSha256s must not be null");
            }
            for (String digest : sha256HexList) {
                if (digest != null && !digest.isBlank()) {
                    additionalCertSha256s.add(normalizeSha256Hex(digest));
                }
            }
            return this;
        }

        public Builder addDangerousPermissionCombo(String ruleName, String... permissions) {
            if (permissions == null) {
                throw new IllegalArgumentException("permissions must not be null");
            }
            List<String> list = new ArrayList<>(permissions.length);
            Collections.addAll(list, permissions);
            dangerousPermissionCombos.add(new PermissionComboRule(ruleName, list));
            return this;
        }

        public Builder addDangerousPermissionCombo(PermissionComboRule rule) {
            if (rule == null) {
                throw new IllegalArgumentException("rule must not be null");
            }
            dangerousPermissionCombos.add(rule);
            return this;
        }

        public Builder enableBuiltInCatalog(boolean value) {
            enableBuiltInCatalog = value;
            return this;
        }

        public Builder enableNativePayloadInspection(boolean value) {
            enableNativePayloadInspection = value;
            return this;
        }

        public Builder enableZygotePreloadInspection(boolean value) {
            enableZygotePreloadInspection = value;
            return this;
        }

        /** Master switch for all HMA and Thanox behavioral side-channel probes. */
        public Builder enableHmaProbes(boolean value) {
            enableHmaUidVisibilityProbe = value;
            enableHmaCrossUserProbe = value;
            enableHmaOrderedBroadcastProbe = value;
            enableHmaPermissionServiceProbe = value;
            enableThanoxIpcProbe = value;
            return this;
        }

        public Builder enableHmaUidVisibilityProbe(boolean value) {
            enableHmaUidVisibilityProbe = value;
            return this;
        }

        public Builder enableHmaCrossUserProbe(boolean value) {
            enableHmaCrossUserProbe = value;
            return this;
        }

        public Builder enableHmaOrderedBroadcastProbe(boolean value) {
            enableHmaOrderedBroadcastProbe = value;
            return this;
        }

        public Builder enableHmaPermissionServiceProbe(boolean value) {
            enableHmaPermissionServiceProbe = value;
            return this;
        }

        public Builder enableThanoxIpcProbe(boolean value) {
            enableThanoxIpcProbe = value;
            return this;
        }

        public ThreatAppPolicy build() {
            return new ThreatAppPolicy(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ThreatAppPolicy)) return false;
        ThreatAppPolicy that = (ThreatAppPolicy) o;
        return enableBuiltInCatalog == that.enableBuiltInCatalog
                && enableNativePayloadInspection == that.enableNativePayloadInspection
                && enableZygotePreloadInspection == that.enableZygotePreloadInspection
                && enableHmaUidVisibilityProbe == that.enableHmaUidVisibilityProbe
                && enableHmaCrossUserProbe == that.enableHmaCrossUserProbe
                && enableHmaOrderedBroadcastProbe == that.enableHmaOrderedBroadcastProbe
                && enableHmaPermissionServiceProbe == that.enableHmaPermissionServiceProbe
                && enableThanoxIpcProbe == that.enableThanoxIpcProbe
                && additionalPackages.equals(that.additionalPackages)
                && additionalCertSha256s.equals(that.additionalCertSha256s)
                && dangerousPermissionCombos.equals(that.dangerousPermissionCombos);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                additionalPackages,
                additionalCertSha256s,
                dangerousPermissionCombos,
                enableBuiltInCatalog,
                enableNativePayloadInspection,
                enableZygotePreloadInspection,
                enableHmaUidVisibilityProbe,
                enableHmaCrossUserProbe,
                enableHmaOrderedBroadcastProbe,
                enableHmaPermissionServiceProbe,
                enableThanoxIpcProbe);
    }

    @Override
    public String toString() {
        return String.format(Locale.US,
                "ThreatAppPolicy{pkgs=%d, certs=%d, combos=%d, hma=%s}",
                additionalPackages.size(),
                additionalCertSha256s.size(),
                dangerousPermissionCombos.size(),
                isAnyHmaProbeEnabled());
    }
}
