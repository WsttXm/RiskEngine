# Evidence Contract Record — `hook_framework`

- **Detector**: `hook_framework` (`HookFrameworkDetector`)
- **ScanTier**: `CRITICAL` (fast pass: Xposed/Frida/maps/fd/threads/COW-safe self-integrity/monitor snapshot) + `POSTPONED` (`ZygiskProbe`, `LsposedProbe`, extra Frida D-Bus ports `27043–27045`) + periodic background monitor (`periodic_monitor.cpp`)
- **EvidenceFamily**: `frida`, `xposed`, `hook_integrity`
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Java Xposed / Frida | `xposed_hooks_active`, `frida_dbus_port`, `frida_pid_port` | `xposed` / `frida` | `STRONG` | Active `XposedBridge.sHookedMethodCallbacks`, loopback Frida D-Bus `AUTH` `REJECTED` handshake (`27042` fast + `27043–27045` postponed), or Frida PID port match |
| Java Xposed / Frida weak | `xposed_class_found`, `xposed_stack`, `frida_port_open` | `xposed` / `frida` | `MEDIUM` / `WEAK` | Loaded `XposedBridge` class, Xposed/LSPosed frame on current stack, or open listening port `27042` |
| Native Hook & FD/Thread scan (`native_hook_detector.cpp`) | `maps:frida`, `maps:gadget`, `fd:linjector`, `fd:frida`, `frida_thread`, `anon_rx_elf`, `dl_phdr_unmapped`, `sigaction_hook` | `frida` / `hook_integrity` | `STRONG` / `MEDIUM` | Streaming `/proc/self/maps` (`for_each_self_map`), raw `/proc/self/fd` symlink scan (`linjector`/`frida-gadget`/`libgadget`), dual `comm`+`status Name:` thread scan (`pool-frida`/`pool-spawner`/`frida-helper`/`gdbus`), `PipeMemoryReader` 16B-validated anon `r-xp` ELF headers, `dl_iterate_phdr` vs `maps` diff, and read-only `sigaction` integrity |
| COW-Safe Native Self-Integrity (`native_integrity.cpp`, `SelfIntegrityProbe`) | `text_mismatch`, `inline_hook`, `got_hook`, `jni_self_hook`, `fn_prologue_hook`, `memfd_private_elf`, `art_native_cleared` | `hook_integrity` | `STRONG` (Hard Trigger) | 64 KiB windowed SHA-256 on `libriskengine.so` executable sections (`SHF_EXECINSTR`/`PT_LOAD`), pagemap COW-only (`ANONYMOUS_PAGE`/`SWAPPED`) windowed SHA-256 on `libc.so`/`libdl.so`/`libart.so`, 64-bit (`arm64-v8a`, `x86_64`) trampolines, XOR-masked JNI table + 4 core fn prologue hashes, and PLT+RELA/REL `STT_FUNC` GOT scan |
| Periodic Monitor (`periodic_monitor.cpp`) | `late_text_mismatch`, `late_frida_fd`, `late_wx_self`, `late_memfd_elf` | `hook_integrity` / `frida` | `STRONG` (Hard Trigger) | Background push-event monitor (2–4s initial pass, 20–26s foreground jitter, 120s background backoff, `>10s` resume immediate recheck) |
| `POSTPONED` `ZygiskProbe` (`zygisk_atexit_probe.cpp`) | `zygisk_atexit_anon_exec`, `zygisk_atexit_hole` | `hook_integrity` / `xposed` | `STRONG` / `MEDIUM` | Disk `libc.so` `SHT_SYMTAB` lookup for `_ZL7g_array` / LLVM SRA splits + `_ZL13g_atexit_lock` (non-blocking `pthread_mutex_trylock` + `PipeMemoryReader`), flagging anon-executable callbacks (`STRONG`) and `>= 3` contiguous runtime-anchored holes (`MEDIUM`) |
| `POSTPONED` `LsposedProbe` | `lsposed_binder_magic`, `lsposed_gid_mismatch`, `lsposed_protected_stack`, `lsposed_thread_stack`, `lsposed_uncaught_handler` | `xposed` | `STRONG` / `MEDIUM` | Binder magic `0x5F4C5350` (`activity`/`serial`), Zygote granted-permission vs `/proc/self/status` `Groups:` AOSP `platform.xml` GID audit, protected-API exception stack, `Thread.getAllStackTraces()`, and `UncaughtExceptionHandler` inspection |

## Producing Subsystem

- Linux `/proc/self/{maps,fd,task,pagemap}` and dynamic linker `dl_iterate_phdr`.
- Bionic `libc.so` `atexit` array (`_ZL7g_array`) and signal handlers (`sigaction`).
- Android ART runtime (`libart.so`), `libsigchain.so`, Binder IPC, and loopback TCP stack.

## Mechanism (AOSP/Linux/ACK)

- **Zero-Crash COW-Safe Memory Reading (`safe_mem::PipeMemoryReader`)**: All runtime code-page reads use raw `__NR_pipe2(O_CLOEXEC | O_NONBLOCK)` + fixed 4 KiB `__NR_write`/`__NR_read` chunks (never direct pointer dereference and never `/proc/self/mem`, preventing SIGSEGV/XOM faults and COW page pinning).
- **Fast-Path `memcmp` + Windowed SHA-256 (`D26`)**: Compares on-disk ELF executable bytes against memory via `memcmp` per 4 KiB chunk, confirming mismatches with 64 KiB windowed SHA-256 and checking `extractNativeLibs=false` APK-offset mappings + 16KB ELF `LOAD` alignment.
- **Zygisk `atexit` Forensics (`D40`)**: Pre-allocates all buffers before attempting non-blocking `pthread_mutex_trylock` on `_ZL13g_atexit_lock`, copies metadata/entries solely via `PipeMemoryReader`, and intersects pre/post `/proc/self/maps` snapshots to prove stable owners.
- **Bridge Tamper Correlation (`C6`)**: When `NativeCollectorBridge` or native integrity checks report tampering (`C6:bridge_or_integrity_tamper`), `CorrelationEngine` emits a `DEADLY/10` hard trigger.

## Applicable API Range

- **Core Xposed, Frida, COW-safe self-integrity, `fd`/`task`/`dl_phdr`, `LsposedProbe`, `periodic_monitor`**: Android 11–17 (API 30–37), both 64-bit ABIs (`arm64-v8a`, `x86_64`).
- **`ZygiskProbe`**: API 30–37 where `libc.so` exposes `SHT_SYMTAB` symbols (`UNSUPPORTED` on stripped `libc.so`, `UNAVAILABLE/BUSY` on lock contention).
- **Frida loopback D-Bus probe (`27042–27045`)**: Guarded by host `INTERNET` permission (zero `<uses-permission>` in SDK Manifest; gracefully skipped if absent, 35ms bounded socket timeout).

## Visibility Boundaries

- On Android 10+ (API 30+), SELinux restricts `/proc/net/tcp{,6}` for ordinary apps; `ProcfsUtils.findLoopbackListeningPortsResult()` returns `UNAVAILABLE`, which is treated as expected visibility absence rather than an error (`D39`).
- Stripped `libc.so` or locked `_ZL13g_atexit_lock` degrades `ZygiskProbe` cleanly to `UNSUPPORTED`/`BUSY` without blocking or false-positiving.
- Kernel-level inline hooks outside user-space `libc`/`libdl`/`libart`/`libriskengine` are outside user-space self-integrity visibility.

## False-Positive Defenses

- **ART `libsigchain.so` GOT exemption (`D45`)**: Exempts ONLY ART `libsigchain.so` interposed signal symbols (`sigaction*`/`sigprocmask*`/`signal`/`bsd_signal`/`sigset`/`sigwait*`) resolved to trusted `/apex/com.android.{art,runtime}/` or `/system/lib{,64}/` paths ending with `/libsigchain.so`.
- **`gmain` thread noise suppression (`D39`)**: Keeps `gmain` strictly collaborative/ignored (never standalone Frida) because legitimate GLib/WebView stacks can spawn `gmain`.
- **4KB/16KB alignment & `dlopen` TOCTOU guard (`D39`)**: Uses half-open interval overlap for `dl_iterate_phdr` vs `maps` diff plus live `find_self_map_containing` re-verification before flagging unmapped libraries.
- **Branch-in-image guard (`D10`)**: `looks_like_trampoline` ignores intra-library relative branches (`branch_stays_in_image`).
- **Diagnostic-only context preservation**: `loader_depth` and monitor `passes:N` diagnostics never elevate a clean device from `SAFE` to `WARNING`.

## Result State Mapping

- **Hard-trigger / `strong >= 2` or (`strong >= 1 && medium >= 2`)**: `RiskLevel.DEADLY`, `DetectionStatus.DANGER`, `score = 10`, `informational = false` (hard-trigger tokens: `inline_hook:`, `got_hook:`, `text_mismatch`, `late_text_mismatch`, `jni_self_hook:`, `fn_prologue_hook:`, `maps:frida`, `maps:gadget`, `frida_pid_port`, `memfd_private_elf:`, `late_wx_self`, `late_frida_fd`, `art_native_cleared:`, `fd:linjector`).
- **`strong >= 1` or `medium >= 2`**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 8`, `informational = false`.
- **`medium == 1` only**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 2`, `informational = true` (actionable in `DIAGNOSTIC`; `missing_map` elevates in `LOGIN`/`PAYMENT`).
- **`weak >= 1` only**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 1`, `informational = true`.
- **Zero risk signals**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
