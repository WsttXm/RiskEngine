# Implementation status, September 2026

Records what landed and what remains after the device-fingerprint and
detection-hardening work.

## Build state

All four ABIs compile clean with zero warnings: arm64-v8a, armeabi-v7a, x86,
x86_64. Java layer compiles clean.

Unit tests: 56 run, 0 fail after the September code-review fixes. The two stale
expectations previously recorded here were updated to match the unconditional
detectors and synthesized `fingerprint_id` coverage behavior.

## Fingerprint

- **Layered ID.** Hardware, system and volatile digests computed separately so
  "same device, new firmware" is distinguishable from "different device".
  Coverage counts travel with the ID, so a thin measurement is never mistaken
  for a confident one. `FingerprintId.isHardwareLayerReliable()` gates that.
- **Persistence.** Per-install salt plus last-observed digests in private
  preferences, giving continuity reporting across runs. A hardware-layer change
  between observations raises a detection, since hardware should not change.
  A degraded run reports as inconclusive rather than as a mismatch.
- **New dimensions.** GPU vendor/renderer/extensions via an offscreen EGL
  pbuffer; full sensor tuples hashed into a stable set id; camera physical
  sensor size, focal lengths, apertures and ISO range; display modes and HDR
  capability; CPU topology with per-core frequency clusters and the
  implementer/part multiset; memory and battery specification; system shared
  library set; per-partition build fingerprints.
- **Shell dependency removed** from property reads. Forking `/system/bin/sh`
  for `getprop` was noisy, hookable and blockable; native access is the only
  path now.

The salt is per-install by design, so IDs do not survive reinstall. That keeps
the identifier from becoming a permanent device-wide tracker. Cross-reinstall
linkage via `AndroidKeyStore` is deliberately **not** implemented.

## Security detection

- **Mount-namespace diff** against pid 1, which catches Zygisk DenyList and
  Shamiko style per-process unmounting that path probing cannot see. When
  `/proc/1/mountinfo` is unreadable, which is normal for an unprivileged app,
  that is recorded as coverage loss, never as evidence.
- **KernelSU prctl probe**, finding a kernel-resident manager even when every
  userspace artifact is renamed.
- **Directory-listing cross-check**: a file that stats but is absent from its
  parent's `getdents64` listing is a contradiction no honest filesystem makes.
- **ART-level hook detection**: access-flag inspection via public reflection,
  ClassLoader chain walking, and JNIEnv slot verification. Catches renamed
  LSPosed builds by mechanism rather than by any matchable name. Modifiers are
  read through stable reflection API rather than ArtMethod struct offsets,
  which shift between releases.
- **Integrity widened** from 6 to 18 libc symbols. Self-text hashing now covers
  every executable segment in full, in 64KB windows, instead of the first 4096
  bytes of the first segment. CRC32 replaced with FNV-1a, since CRC is linear
  and trivially compensated for.
- **Frida abstract socket detection** via `/proc/net/unix`, passive so the agent
  cannot observe or refuse it. Plus W+X self-segment detection.
- **JNI self-table verification**: every pointer this library registered must
  still resolve inside this library. Guards the bridge all other results travel
  through.
- **Periodic re-verification.** A native thread re-runs the cheap live-code
  checks at jittered intervals and latches findings, so a hook installed after
  the initial snapshot still surfaces. Only the cheap checks repeat; full root
  and emulator scans are far too expensive. Stopped on `RiskEngine.shutdown()`.
- **Cloud phone and emulator** gained the decisive modern signal, a virtualized
  GPU renderer, plus cloud vendor properties, wired-interface enumeration and
  `ro.build.characteristics`.
- **Sandbox** gained dexElements counting and UID consistency, which find
  cloning containers absent from any package list.
- **`ConsistencyDetector`**, signature-free cross-source checks: partition
  fingerprint agreement, Build versus properties, core count across three
  sources, ABI versus os.arch, SDK versus release, fingerprint shape, verified
  boot state. These find the contradictions a spoofing tool leaves rather than
  recognising the tool, so they do not go stale.
- **`native_tamper` escalation**: a missing or unreadable library map now
  escalates in LOGIN and PAYMENT scenes instead of degrading to unavailable,
  because "hide the checker, then report clean" is the expected attack shape.

## Architecture

- **Sealed native verdict.** Ranking and scoring moved into native, returned as
  an opaque MAC-authenticated blob and verified back in native with a nonce
  freshness check. This raises bypass cost from a one-line Java hook to native
  memory access. It does **not** stop an attacker who already has native
  execution, because the key lives in process memory. Stated so the limit is
  not mistaken for a guarantee.
- **String obfuscation** moved from a single fixed XOR key to a per-site
  rolling keystream, so frequency analysis across the library no longer
  recovers strings.
- **Release hardening**: version script exporting only `JNI_OnLoad`, thin LTO,
  unwind tables dropped, section GC, symbol stripping.

## Remaining

1. **`ObfuscatedLists` is scaffolding only.** The decoder exists but
   `DetectionLists` still holds plaintext. Wiring it up needs a generator step
   to produce the encoded arrays. The honest limit: this raises the cost of a
   `strings` sweep but does not defeat an analyst who reads the decoder.
2. **Keystore-backed cross-reinstall linkage**, if that trade-off is wanted.
3. **Real-device CI matrix.** `doc/Adversarial_Matrix.md` is an expectation
   document with nothing automated verifying it. The device workflow was
   deleted in 64371c8 and one instrumented test remains against 914 lines of
   unit tests. False positives on stock OEM devices are the main correctness
   exposure and unit tests cannot cover it.
4. **Fix the two failing tests** listed above.
5. **`GpuInfoCollector` needs device validation.** EGL pbuffer creation on a
   worker thread is correct in principle but untested on real hardware, and OEM
   driver behaviour varies.
