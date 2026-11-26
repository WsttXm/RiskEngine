# Drop 32-Bit Native ABI Support (`armeabi-v7a` and `x86`)

Status: accepted

Starting in v2.0.1, `:riskengine-sdk` ships and compiles native code exclusively for the two 64-bit Android ABIs (`arm64-v8a` and `x86_64`), removing `armeabi-v7a` and `x86` from `abiFilters`, CMake/C++ native sources, L2 host tests, and ELF hardening gates.

## Considered Options

- **Keep all four ABIs (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`)**: Preserves native library loading if a host app still runs as a 32-bit process, but doubles AAR native payload size, lengthens every NDK/ThinLTO build, and forces permanent maintenance of ARM32/Thumb-2/i386 inline syscall assembly, `Elf32_*` parsers, and 32-bit trampoline decoders that cannot be meaningfully exercised on modern 64-bit CI or hardware.
- **Strip 32-bit `.so` from `abiFilters` while leaving 32-bit C++ code intact**: Reduces AAR size immediately, but leaves uncompiled, untested 32-bit assembly and ELF32 branches in `src/main/cpp/` to silently bit-rot.
- **Drop 32-bit ABIs completely across build, native code, tests, and gates while keeping `x86_64` for emulator/CI testing (chosen)**: Halves AAR native payload (tightening the release AAR budget from `8 MiB` to `4 MiB`), removes ~300 lines of 32-bit syscall/ELF32/trampoline maintenance surface, enforces a compile-time 64-bit guard (`CMakeLists.txt` + `__LP64__`), and keeps `x86_64` so Linux KVM L3 instrumentation tests remain fast and deterministic.

## Consequences

- `:riskengine-sdk` release AARs now ship strictly `jni/arm64-v8a/libriskengine.so` and `jni/x86_64/libriskengine.so` (enforced by `scripts/check-elf-hardening.sh`, which also rejects any unexpected `.so` and caps AAR size at `4 MiB`).
- Attempting to configure or compile the native library for a 32-bit ABI fails fast in CMake (`ANDROID_ABI` check) and C++ (`#if !defined(__LP64__)`).
- Host apps integrating `:riskengine-sdk` must not force a 32-bit process by bundling 32-bit-only `.so` files from other dependencies without configuring `abiFilters += listOf("arm64-v8a")` (or `listOf("arm64-v8a", "x86_64")`). If a host process still boots in 32-bit mode, `NativeCollectorBridge.ensureNativeLoaded()` catches `LinkageError` and degrades native probes cleanly to `native_unavailable` rather than crashing the host.
- Java and native detection rules that inspect *external* host/emulator spoofing indicators (such as `i386`/`i686` strings in `ConsistencyDetector`/`EmulatorDetector` or Houdini binary translation paths in `virtualization_traps.cpp`) are intentionally preserved.
