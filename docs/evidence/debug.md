# Evidence Contract Record — `debug`

- **Detector**: `debug` (`DebugDetector`)
- **ScanTier**: `CRITICAL` (plus continuous `TracerPid` monitoring inside `periodic_monitor.cpp`)
- **EvidenceFamily**: `debugger`
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Native `native_debug_detector.cpp` (`nGetDebugEvidenceRaw`) | `tracer_pid`, `tracer_pid_mismatch`, `stat_tracing_stop`, `wchan_ptrace_stop` | `debugger` | `STRONG` | Dual-path `TracerPid > 0` (`/proc/self/status` vs `/proc/<pid>/task/<pid>/status` + per-thread `status`), cross-path `TracerPid` mismatch (hooked `/proc/self/status`), `/proc/self/task/*/stat` field-3 lowercase `'t'` (`tracing stop`), and `/proc/self/task/*/wchan` containing `ptrace_stop` |
| Native JDWP checks (`native_debug_detector.cpp`) | `jdwp_thread`, `jdwp_socket` | `debugger` | `MEDIUM` (release) / `INFO` (debuggable) | Active JDWP threads (`/proc/self/task/*/comm`) or `@jdwp-control` abstract Unix socket presence |
| Java `android.os.Debug` | `debugger_connected` | `debugger` | `MEDIUM` | `Debug.isDebuggerConnected()` or `Debug.waitingForDebugger()` |
| Java `/proc/self/maps` | `maps_debugger` | `debugger` | `STRONG` / `MEDIUM` | Executable/readonly memory mappings referencing `android_server`, `gdbserver`, `lldb`, or `frida` |
| Java `ApplicationInfo` | `debuggable_flag` | `debugger` | `INFO` | `ApplicationInfo.FLAG_DEBUGGABLE` set on the host APK (strictly informational in all 4 scenes) |
| Java loopback port scan | `ida_port_open` | `debugger` | `WEAK` | Loopback listener on default IDA Pro port `23946` (when `/proc/net/tcp{,6}` is readable) |

## Producing Subsystem

- Linux kernel `ptrace` / task state (`fs/proc/array.c`: `/proc/self/status`, `/proc/<pid>/task/<tid>/{status,stat,wchan,comm}`).
- Android ART JDWP agent and abstract Unix socket `@jdwp-control`.
- Android `ApplicationInfo` flags and `android.os.Debug` runtime state.
- Opt-in kernel `prctl(PR_SET_DUMPABLE, 0)` (controlled via `RiskEngineConfig.Builder.enableAntiDumpable(boolean)`, default `false`).

## Mechanism (AOSP/Linux/ACK)

- **Dual-Path `TracerPid` & Mismatch Detection (`D22`)**: Native code reads `TracerPid` via raw Linux syscalls from both `/proc/self/status` and `/proc/<pid>/task/<pid>/status` (plus all sibling threads under `/proc/self/task/`). If a user-space hook zeroes only `/proc/self/status` while the task path reports a non-zero tracer, `tracer_pid_mismatch` (`STRONG`) fires immediately.
- **Last-`')'` `stat` Field-3 Parsing**: Parses `/proc/self/task/<tid>/stat` strictly from the *last* `')'` character (preventing comm names containing spaces or parentheses from shifting fields) and checks for lowercase `'t'` (Linux kernel `TASK_TRACED` tracing stop).
- **Fallback Chain**: `DebugDetector` prefers `nGetDebugEvidenceRaw` (`NativePayloadCodec` frame), falls back to legacy `nativeGetTracerPidRaw`, and finally falls back to Java `/proc/self/status` if native loading is unavailable.
- **Opt-In Anti-Dumpable**: `nSetAntiDumpableRaw` executes raw `my_prctl(PR_SET_DUMPABLE, 0/1)` only when explicitly enabled by the host (never auto-invoked in `JNI_OnLoad`, preserving ptrace-based crash reporters by default).

## Applicable API Range

- Android 11–17 (API 30–37), both 64-bit ABIs (`arm64-v8a`, `x86_64`).

## Visibility Boundaries

- On Android 10+ (API 30+), SELinux denies unprivileged `/proc/net/tcp{,6}` reads; `checkIdaPort` treats `SignalResult.Status.UNAVAILABLE` as expected visibility loss (`coverage.success()`) so clean devices remain `SAFE` (`D39`).
- Kernel-level `ptrace` hiding patches that sanitize `TracerPid`, `stat`, and `wchan` simultaneously in kernel space cannot be seen from user-space procfs alone.
- `enableAntiDumpable(false)` (default) leaves `PR_SET_DUMPABLE` untouched to avoid breaking native crash-reporting SDKs.

## False-Positive Defenses

- **Debuggable-build idle JDWP downgrade (`D47`)**: On Android 11+, ART automatically spawns an idle `"ADB-JDWP Connection Control Thread"` on every `FLAG_DEBUGGABLE` build even with no debugger attached. `DebugDetector` evaluates `FLAG_DEBUGGABLE` first and downgrades idle `jdwp_thread`/`jdwp_socket` to `Rank.INFO`/informational ONLY when `debuggableApp == true` and no active debugger/tracer is attached; release builds (`FLAG_DEBUGGABLE == false`) still score `MEDIUM/4`, and active `Debug.isDebuggerConnected()` still scores `MEDIUM/4`.
- **`debuggable_flag`-only informational lock (`D22`)**: Preserves `LOW/1` (`informational = true`) across all 4 `CollectScene`s (including `DIAGNOSTIC`) when `debuggable_flag` is the sole finding.
- **Last-`')'` `stat` parsing**: Eliminates false `'t'` matches on thread names containing parentheses or spaces.

## Result State Mapping

- **Strong finding (`tracer_pid`, `tracer_pid_mismatch`, `stat_tracing_stop`, `wchan_ptrace_stop`, debugger `maps` strong hit)**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 8`, `informational = false` (actionable in all 4 scenes).
- **Medium finding (`debugger_connected`, release-build `jdwp_thread`/`jdwp_socket`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 4`, `informational = false` (actionable in all 4 scenes).
- **Weak/Info-only finding (`debuggable_flag`, debuggable-build idle JDWP, `ida_port_open`)**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 1`, `informational = true`.
- **Clean with usable checks**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
