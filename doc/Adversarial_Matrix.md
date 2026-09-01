# Adversarial device matrix

Local-only expectations. This file records what a report should contain; it is not a bypass guide.

| Environment | Expected family tokens | Must not be SAFE when |
|---|---|---|
| Stock OEM phone | no DANGER | n/a |
| Magisk (unhidden) | `magisk:` / `mount:magisk` | root or mount_analysis DANGER |
| Magisk + Shamiko DenyList | `syscall_mismatch` and/or `UNKNOWN/PARTIAL`, never silent SAFE if checks fail | coverage failure |
| KernelSU | `ksu:` | root DANGER |
| APatch | `apatch:` | root DANGER |
| LSPosed | `maps:lsposed` / `xposed_*` | hook WARNING+ |
| Frida default | `maps:frida` / `frida_pid` | hook hard-trigger |
| Frida gadget renamed | `inline_hook:` / `got_hook:` | hook or signal_correlation |
| LDPlayer / MuMu | `emu_file` / `emu_pkg` / `qemu_*` | emulator MEDIUM+ |
| ARM64 AVD | `qemu_pipe` / `ranchu` / `generic_fingerprint` | emulator not NORMAL |
| Cloud phone APK | `cloud_pkg:` | cloud_phone MEDIUM |

Normal devices: zero actionable DANGER from emulator hardware-noise tokens alone (`aosp_sensor`, missing telephony on tablets).
