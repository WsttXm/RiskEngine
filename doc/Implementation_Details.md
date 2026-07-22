# RiskEngine Implementation Details

This document describes the contracts implemented by the current source. See [README.md](../README.md) for integration guidance.

## 1. Architecture and collection flow

```text
host call
  -> RiskEngine lifecycle snapshot
  -> single coordinator serializes requests
  -> collectionLock (queue wait is inside the deadline)
  -> SignalSnapshot.reset()
  -> parallel collectors on worker pool
  -> parallel detectors on worker pool
  -> DataAggregator
  -> immutable RiskReport
```

- `TaskScheduler` separates one coordinator from four workers so a task waiting for a batch cannot starve that batch.
- The coordinator queue is bounded at 16. Rejected asynchronous requests call `onError`.
- `collectTimeout` starts when the request is queued. Work missing the deadline becomes explicit timeout/error coverage.
- Synchronous collection rejects the Android main thread. Asynchronous callbacks are not moved to the main thread.
- `shutdown()` advances the lifecycle generation, cancels work, and clears registries. Results from older generations are not delivered.

## 2. Lifecycle API

| API | Behavior |
| --- | --- |
| `init(context, config)` | Strict initialization; duplicate calls throw |
| `initIfNeeded(context, config)` | Atomic initialize-if-absent; returns whether this call initialized |
| `collect(callback)` | Full asynchronous collection on SDK threads |
| `collectSync()` | Full synchronous collection; forbidden on main thread |
| `collectReportJson()` | Collect then serialize JSON |
| `reportToJson(report)` | Serialize an existing report without collecting again |
| `getReportJson()` | Deprecated compatibility alias for `collectReportJson()` |
| `shutdown()` | Cancel work and release resources |

## 3. Result semantics

### 3.1 Collectors

`CollectorResult.Status` is `SUCCESS`, `EMPTY`, `ERROR`, or `UNSUPPORTED`. `compareSources=true` is used only when all values represent the same semantic field from different sources. Inconsistency is recorded by `DeviceFingerprint` and emitted as `multi_source_validation`.

### 3.2 Detectors

Risk presentation and execution are independent:

| Type | Values |
| --- | --- |
| Risk presentation | `DetectionStatus.NORMAL / WARNING / DANGER / UNKNOWN` |
| Execution | `SAFE / RISK / PARTIAL / UNAVAILABLE / DISABLED / TIMEOUT / ERROR` |

`DetectionResult` also exposes `checksAttempted`, `checksSucceeded`, `checksFailed`, and `failureReasons`. Multi-check root, hook, emulator, and debug detectors record real subcheck coverage. They do not return safe when every key subcheck failed.

`isInformational()` marks context that does not enter `riskScore`. Deprecated `isWarnOnly()` remains for compatibility.

### 3.3 Report and scoring

| Level | Rule |
| --- | --- |
| `SAFE` | Score 0, no informational/risk result, complete coverage |
| `LOW` | Score 1–3, or informational signals only |
| `MEDIUM` | Score at least 4, or at least two actionable warnings |
| `HIGH` | Score at least 10, or at least one actionable danger |
| `DEADLY` | Score at least 18, at least three actionable dangers, or a hard trigger |
| `UNKNOWN` | No known risk and key coverage is unavailable |

High-confidence Frida PID/port or maps Frida/Gadget combinations can hard-trigger `DEADLY`. Multi-source inconsistency raises a lower known result to at least `MEDIUM`.

- `riskScore` sums actionable results only.
- `maxRiskScore` is technical capacity, not a UI percentage denominator.
- `displayThresholdMaximum` is the severe threshold, 18.
- `reportStatus` is `COMPLETE`, `PARTIAL`, or `UNAVAILABLE`.
- `checkCount` and `completedCheckCount` combine detectors and raw collectors without double-counting `collector:*` signals or synthesized fields.
- `coveragePercent` is completed checks divided by total checks.

Aggregation freezes `RiskReport`, `DeviceFingerprint`, and nested collector results.

## 4. Privacy configuration

| Profile | Default identifier collection |
| --- | --- |
| `MINIMAL` | No Android ID, boot ID, or Widevine |
| `BALANCED` | App-scoped Android ID hash only; default |
| `DIAGNOSTIC` | App-scoped Android ID, boot ID, and Widevine hashes |

`collectAndroidId`, `collectBootId`, and `collectDrmId` override a profile. The SDK does not collect raw IMEI, IMSI, MAC, SSID, or BSSID. The package name scopes deterministic hashes, making them pseudonyms rather than encryption, anonymization, or an absolute non-reversibility guarantee.

## 5. Shared signals and performance

Each report resets one `SignalSnapshot`. Typed `SignalResult<T>` values preserve success, empty, unavailable, and error outcomes. Collectors and detectors share cached ADB state, system properties, `/proc/self/maps`, local listening ports, process snapshots, text files, path existence, container signals, and structured shell results.

This removes duplicate ADB collection and lets Java hook/debug checks share maps and port snapshots. Native hook maps remain an independent raw-syscall read path to reduce libc-hook blind spots.

## 6. Shell and native boundaries

`ShellExecutor.Result` distinguishes `SUCCESS`, `INVALID_COMMAND`, `TIMEOUT`, `NON_ZERO_EXIT`, `INTERRUPTED`, and `EXECUTION_ERROR`, and carries stdout, stderr, exit code, duration, and failure reason. String-only helpers are deprecated.

Native detector methods expose structured `SignalResult<T>` wrappers so Java can distinguish an unavailable library, JNI error, and valid negative result.

JNI strings do not pass untrusted bytes to `NewStringUTF`. The implementation caps input length, validates UTF-8, replaces malformed sequences, and constructs UTF-16 with `NewString`; C++ allocation failures and JNI string-access failures do not leave exceptions across the boundary. JNI registration failures clear pending exceptions and log the target class. Native builds explicitly enable strong stack protection, release FORTIFY, format checks, RELRO/NOW, a non-executable stack, 16 KiB page alignment, hidden symbols, and compiler warnings.

## 7. Demo presentation contract

The Demo presents:

1. localized risk conclusion, primary reason, and action;
2. score against the severe threshold of 18, coverage, elapsed time, and counts;
3. detector reason, risk/execution status, score, and subcheck coverage;
4. collector labels, readable units, and source details;
5. synthesized SDK fields in a separate section.

Collection errors use gray and 0% rather than looking like maximum risk. Internal unavailable tokens are translated. Identifier hashes are shortened in summaries and byte capacities are formatted as GB. Copy produces a redacted summary without identifier hashes, raw properties, paths, or PIDs. Haptics fire only for newly delivered results, not Activity recreation.

## 8. Build, test, and release

```bash
./gradlew :riskengine-sdk:test :riskengine-sdk:lint
./gradlew :riskengine-sdk:assembleRelease :riskengine-sdk:sourceReleaseJar
./gradlew :demo:lintDebug :demo:assembleDebug
```

- PRs and every branch push run unit tests, lint, AAR/POM/sources, Demo Debug APK, and archive integrity checks.
- `integration-test` depends only on the generated release AAR and verifies that a standalone host compiles and links the public API.
- A weekly/manual API 30, 33, 35, and 36 x86_64 emulator matrix runs instrumentation tests.
- `vMAJOR.MINOR.PATCH` tags publish AAR, sources, POM, temporary Debug APK, and SHA-256 checksums.
- The temporary Debug APK is intentionally for sideload testing only. CI stores no production signing key. Different tags can have different temporary keys, requiring uninstall on signature mismatch.

## 9. Verification boundaries

- The x86_64 emulator matrix does not replace real ARM64 OEM hardware. Native anti-hook policy, anonymous executable-region allowlists, and OEM false-positive rates require continuing physical-device regression.
- Advanced adversaries can tamper with local signals. This SDK complements rather than replaces server risk analysis, hardware attestation, or Play Integrity.
- See [Pending_Items.md](./Pending_Items.md) for concrete owners and acceptance criteria.
