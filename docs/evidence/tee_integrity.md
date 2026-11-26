# Evidence Contract Record — `tee_integrity`

- **Detector**: `tee_integrity` (`TeeIntegrityDetector`)
- **ScanTier**: `POSTPONED` (5s detector budget, per-probe `SafeExecutor.safeWithTimeoutOrInline`)
- **EvidenceFamily**: `tee_tamper`
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| `AttestationCapability` + `CertificateTrustAnalyzer` + `AttestationExtensionParser` + `RkpExtensionParser` | `tee_keybox_revoked`, `tee_chain_signature_invalid`, `tee_issuer_chain_invalid`, `tee_aosp_root_spoofed_hw`, `tee_attestation_extension_invalid`, `tee_challenge_mismatch`, `tee_leaf_extension_shadow`, `tee_rkp_extension_invalid` | `tee_tamper` | `STRONG` | StrongBox->TEE ephemeral EC P-256 attestation verified against embedded Google Hardware Attestation Root SPKI anchors, monotonic offline revoked-keybox CRL floor (1,699 serials), full RFC 5280 chain/`pathLenConstraint`/`KeyUsage` validation, root-first OID `.17` parsing, and strict canonical CBOR RKP OID `.30` parsing |
| `TeeNativeProbe` (`tee_binder_probe.cpp`) | `tee_trickystore_maps`, `tee_binder_ioctl_hook`, `tee_binder_version_mismatch`, `tee_leaf_der_forged`, `tee_binder_honeypot_timing` | `tee_tamper` | `STRONG` / `MEDIUM` | 5-vector TrickyStore / Binder interception check: maps scan, `libbinder.so` `ioctl` GOT + 16B inline hook via `PipeMemoryReader`, 3-way `BINDER_VERSION` Libc/syscall/64-bit inline-asm parity, native Leaf DER check (non-minimal lengths + 32-hex template excluding Issuer DN), and 3-round rotating-order Binder Honeypot median/MAD timing |
| `GrantDomainSplitProbe` (`RiskIsolatedProbeService`) | `tee_grant_chain_split`, `tee_grant_synthetic_key` | `tee_tamper` | `STRONG` (Hard Trigger) | Ephemeral isolated-UID `Domain.APP` vs `Domain.GRANT` certificate chain comparison via `Keystore2ParcelClient` public `IBinder.transact` + `Parcel` wire protocol (API 31–35) and `KeyStoreManager` (API 36+) |
| `Keystore2DeepProbe` | `tee_parcel_tag_user_id_anomaly`, `tee_api35_post_processing_drift`, `tee_overwrite_readback_cache_hit`, `tee_strongbox_level_mismatch` | `tee_tamper` | `STRONG` / `MEDIUM` | `generateKey` reply parcel `TAG_USER_ID` fingerprint, API 35+ RKP vs `PURPOSE_ATTEST_KEY` paired sampling, distinct-serial (`0x52451001`/`0x52451002`) + SPKI SHA-256 overwrite-readback anti-cache trap, and StrongBox `KeyInfo` constraint check |
| `VintfHalAndErrorPathProbe` | `tee_vintf_hal_version_mismatch`, `tee_km_att_version_mismatch`, `tee_error_path_anomaly` | `tee_tamper` | `STRONG` / `MEDIUM` | `/vendor/etc/vintf` KeyMint/Keymaster HAL version parity against attested security level, `actualKm != actualAtt` check (gated on `vendorApiLevel > 202504`), and KeyMint operation error-path constraints |

## Producing Subsystem

- Android Hardware Keystore / Keystore2 (`android.system.keystore2.IKeystoreService`), TEE / StrongBox KeyMint HAL, and Remote Key Provisioning (RKP).
- Native `libbinder.so`, kernel `/dev/binder` (`BINDER_VERSION` ioctl), and `/vendor/etc/vintf` manifests.
- Ephemeral isolated process (`RiskIsolatedProbeService` bound via `bindIsolatedService`).

## Mechanism (AOSP/Linux/ACK)

- **Zero-Dependency Strict Parsers (`D50`, `D51`)**: Pure-Java `DerReader` and `CanonicalCborReader` reject BER non-minimal lengths, duplicate `AuthorizationList` tags, duplicate/non-canonical/trailing CBOR items, and leaf OID `.17` shadowing (root-first chain scanning with `hwTags` overriding `swTags`, zero PII skipping tags 713/714/715/723). `GoogleAttestationRootStore` embeds verified Google Root SPKI/DER SHA-256 anchors and a 1,699-serial offline CRL floor (dual-matching 64-bit decimal and 128-bit lowercase hex + unsigned fallback) with zero runtime network I/O.
- **Public Wire-Protocol Keystore2 Client (`D66`)**: Uses `Keystore2ParcelClient` over public `IBinder.transact` + `Parcel` speaking frozen VINTF-stable Keystore2 AIDL wire format (zero blocked Android 12–16 `Stub.asInterface` hidden-API reflection).
- **Grant-Domain Chain Split (`D55`)**: Creates an ephemeral attested key in `Domain.APP`, grants it to the ephemeral isolated service UID (`Domain.GRANT`), compares leaf/chain parity across UIDs, and guarantees `ungrant` + alias deletion + `unbindService` in `finally` with timeout cancellation guards.
- **`TrustTier.STRONG_HARDWARE` Elevation (`D57`)**: When `tee_integrity` confirms a Google-rooted locked/`VERIFIED` hardware chain on a `SAFE`/`COMPLETE` report, `DataAggregator` elevates `RiskReport.TrustTier` to `STRONG_HARDWARE`.

## Applicable API Range

- **Core Attestation, `TeeNativeProbe`, `VintfHalAndErrorPathProbe`**: Android 11–17 (API 30–37), both 64-bit ABIs (`arm64-v8a`, `x86_64`).
- **`GrantDomainSplitProbe` & `Keystore2DeepProbe`**: Android 12–17 (API 31–37; `KeyStoreManager` on API 36+, `Keystore2ParcelClient` wire protocol on API 31–35; RKP vs `PURPOSE_ATTEST_KEY` paired sampling on API 35+).

## Visibility Boundaries

- Devices lacking hardware Keystore attestation, unprovisioned factory keyboxes, offline StrongBox exhaustion, or stripped `RiskIsolatedProbeService` degrade individual probes cleanly to `UNAVAILABLE`/`UNSUPPORTED` (`LOCAL_VERIFIED` TrustTier) and NEVER escalate to `DANGER` or degrade `SAFE` to `UNKNOWN` (`D57`).
- Ephemeral attestation aliases are unconditionally deleted in `finally` blocks so Keystore storage never leaks.

## False-Positive Defenses

- **X.509 Issuer DN `HEX_TEMPLATE_32` exclusion (`D67`)**: Both Java `DerReader.findX509IssuerRange` and Native `tee_binder_probe.cpp:find_x509_issuer_range` strictly validate RFC 5280 §4.1.2 TBS field sequencing and exclude only `TBSCertificate.issuer` from `HEX_TEMPLATE_32` matching (Google Titan M2 Batch CA Issuer DNs contain legitimate 32-hex `serialNumber`), while retaining `NON_MINIMAL_LENGTH` checks inside Issuer and full `HEX_TEMPLATE_32` checks in Subject/extensions.
- **OEM `KeyMintQuirks` (`D56`, `D66`)**: Standalone non-AEAD `updateAad()` acceptance is diagnostic-only (verified on stock Pixel 6 Trusty KeyMint v2 + Samsung/Xiaomi MediaTek); `actualKm != actualAtt` is gated strictly on `vendorApiLevel > 202504`; StrongBox `KeyInfo` uses nullable `Boolean` so transient slot exhaustion never triggers mismatch FP; non-hardware tiers are excluded from `/vendor` VINTF matching.
- **Distinct overwrite-readback serials (`D56`)**: Stamps explicit serials `0x52451001`/`0x52451002` + SPKI SHA-256 comparison to avoid AOSP `BigInteger.ONE` default-serial false positives.
- **Fail-closed `isStrictKeyNotFoundThrowable` (`D55`)**: Reflection/SELinux/non-`KEY_NOT_FOUND` (`errorCode != 7`) errors in `GrantDomainSplitProbe` degrade to `UNAVAILABLE`, never false-positiving.

## Result State Mapping

- **Hard-trigger tokens (`tee_grant_chain_split`, `tee_binder_ioctl_hook`, `tee_keybox_revoked`)**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 9`, `informational = false`, reported in `RiskReport.getHardTriggers()` (elevates overall report to `DEADLY` with a `95–100` score floor across all 4 scenes unless suppressed by `RiskPolicy`).
- **Other strong TEE tamper findings (`tee_chain_signature_invalid`, `tee_aosp_root_spoofed_hw`, `tee_leaf_der_forged`, `tee_overwrite_readback_cache_hit`, etc.)**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 9`, `informational = false` (actionable in all 4 scenes).
- **Medium findings (`tee_binder_honeypot_timing`, `tee_api35_post_processing_drift`, `tee_strongbox_level_mismatch`, etc.)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 4`, `informational = false`.
- **Clean (including hardware-unavailable graceful degradation)**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0` (`hardware_attested_locked_verified:<TIER>` summary when Google-rooted locked hardware attestation succeeds).
