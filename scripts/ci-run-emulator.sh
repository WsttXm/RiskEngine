#!/usr/bin/env bash
# Deterministic Android KVM Emulator Runner for CI L3 Instrumentation Tests.
# Replaces black-box post-boot ADB races (e.g. API 30 DeadSystemException on premature
# `input keyevent 82`) with explicit service-readiness polling, backoff retries,
# full-boot self-healing retry, and failure logcat/emulator log capture.
set -euo pipefail

if [[ "$#" -lt 1 ]]; then
  echo "Usage: API_LEVEL=30 [TARGET=default] [ARCH=x86_64] [PROFILE=pixel_6] $0 <command...>" >&2
  exit 2
fi

API_LEVEL="${API_LEVEL:?API_LEVEL environment variable is required}"
TARGET="${TARGET:-default}"
ARCH="${ARCH:-x86_64}"
PROFILE="${PROFILE:-pixel_6}"
AVD_NAME="${AVD_NAME:-ci_api${API_LEVEL}}"
LOG_DIR="${LOG_DIR:-emulator-logs}"
EMU_PORT="${EMU_PORT:-5554}"
SERIAL="emulator-${EMU_PORT}"
BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-300}"
MAX_BOOT_ATTEMPTS="${MAX_BOOT_ATTEMPTS:-2}"
MEMORY_MB="${MEMORY_MB:-4096}"
CORES="${CORES:-2}"

SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/usr/local/lib/android/sdk}}"
if [[ ! -d "$SDK_ROOT" ]]; then
  echo "ERROR: Android SDK root not found: ${SDK_ROOT}" >&2
  exit 1
fi

find_sdk_tool() {
  local tool="$1"
  shift
  local candidate
  for candidate in "$@"; do
    if [[ -x "$candidate" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  if command -v "$tool" >/dev/null 2>&1; then
    command -v "$tool"
    return 0
  fi
  return 1
}

SDKMANAGER="$(find_sdk_tool sdkmanager \
  "${SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager" \
  "${SDK_ROOT}/cmdline-tools/bin/sdkmanager" \
  "${SDK_ROOT}/tools/bin/sdkmanager" || true)"
AVDMANAGER="$(find_sdk_tool avdmanager \
  "${SDK_ROOT}/cmdline-tools/latest/bin/avdmanager" \
  "${SDK_ROOT}/cmdline-tools/bin/avdmanager" \
  "${SDK_ROOT}/tools/bin/avdmanager" || true)"
ADB_BIN="$(find_sdk_tool adb "${SDK_ROOT}/platform-tools/adb" || true)"
EMULATOR_BIN="$(find_sdk_tool emulator "${SDK_ROOT}/emulator/emulator" || true)"

for pair in "sdkmanager:${SDKMANAGER}" "avdmanager:${AVDMANAGER}" "adb:${ADB_BIN}"; do
  name="${pair%%:*}"
  val="${pair#*:}"
  if [[ -z "$val" ]]; then
    echo "ERROR: Required Android SDK tool '${name}' not found under ${SDK_ROOT}" >&2
    exit 1
  fi
done

mkdir -p "$LOG_DIR"

SYS_IMAGE="system-images;android-${API_LEVEL};${TARGET};${ARCH}"
echo "==> Ensuring Android emulator and system image '${SYS_IMAGE}' are installed"
yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
if [[ -z "$EMULATOR_BIN" ]]; then
  "$SDKMANAGER" --install "emulator" --channel=0 >/dev/null
  EMULATOR_BIN="${SDK_ROOT}/emulator/emulator"
fi
"$SDKMANAGER" --install "$SYS_IMAGE" --channel=0 >/dev/null

if [[ ! -x "$EMULATOR_BIN" ]]; then
  echo "ERROR: Android emulator binary missing at ${EMULATOR_BIN}" >&2
  exit 1
fi

EMU_PID=""

dump_diagnostics() {
  local tag="$1"
  echo "==> Capturing emulator diagnostics (${tag}) into ${LOG_DIR}/"
  if "$ADB_BIN" -s "$SERIAL" get-state >/dev/null 2>&1; then
    timeout 15 "$ADB_BIN" -s "$SERIAL" logcat -d -v time 2>&1 | tail -n 1500 \
      > "${LOG_DIR}/logcat-api${API_LEVEL}-${tag}.txt" || true
    timeout 10 "$ADB_BIN" -s "$SERIAL" shell ps -A 2>&1 \
      > "${LOG_DIR}/ps-api${API_LEVEL}-${tag}.txt" || true
  fi
}

stop_emulator() {
  if "$ADB_BIN" -s "$SERIAL" get-state >/dev/null 2>&1; then
    timeout 10 "$ADB_BIN" -s "$SERIAL" emu kill >/dev/null 2>&1 || true
  fi
  if [[ -n "${EMU_PID}" ]] && kill -0 "${EMU_PID}" 2>/dev/null; then
    local waited=0
    while kill -0 "${EMU_PID}" 2>/dev/null && (( waited < 15 )); do
      sleep 1
      waited=$((waited + 1))
    done
    if kill -0 "${EMU_PID}" 2>/dev/null; then
      kill -9 "${EMU_PID}" 2>/dev/null || true
    fi
    wait "${EMU_PID}" 2>/dev/null || true
  fi
  EMU_PID=""
}

on_exit() {
  local exit_code="$?"
  if [[ "$exit_code" -ne 0 ]]; then
    dump_diagnostics "failure"
  fi
  stop_emulator
  exit "$exit_code"
}
trap on_exit EXIT

adb_shell_retry() {
  local desc="$1"
  shift
  local max_tries=5
  local try=1
  local out=""
  while (( try <= max_tries )); do
    if [[ -n "${EMU_PID}" ]] && ! kill -0 "${EMU_PID}" 2>/dev/null; then
      echo "ERROR: Emulator process exited while running: ${desc}" >&2
      return 1
    fi
    if out="$("$ADB_BIN" -s "$SERIAL" shell "$@" 2>&1)"; then
      if [[ "$out" != *"DeadSystemException"* && "$out" != *"Can't find service"* ]]; then
        return 0
      fi
    fi
    echo "WARN: '${desc}' attempt ${try}/${max_tries} failed: ${out}" >&2
    sleep 3
    try=$((try + 1))
  done
  echo "ERROR: '${desc}' failed after ${max_tries} attempts" >&2
  return 1
}

wait_for_emulator_ready() {
  local deadline=$((SECONDS + BOOT_TIMEOUT_SECONDS))
  echo "==> Waiting for ${SERIAL} (API ${API_LEVEL}) to reach full framework readiness (timeout ${BOOT_TIMEOUT_SECONDS}s)"

  # 1. Wait for adb transport online
  while (( SECONDS < deadline )); do
    if ! kill -0 "${EMU_PID}" 2>/dev/null; then
      echo "ERROR: Emulator process exited prematurely during early boot" >&2
      return 1
    fi
    if [[ "$("$ADB_BIN" -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')" == "device" ]]; then
      break
    fi
    sleep 2
  done
  if [[ "$("$ADB_BIN" -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')" != "device" ]]; then
    echo "ERROR: Timed out waiting for adb device state" >&2
    return 1
  fi

  # 2. Wait for sys.boot_completed=1 and boot completion signals
  while (( SECONDS < deadline )); do
    if ! kill -0 "${EMU_PID}" 2>/dev/null; then
      echo "ERROR: Emulator process exited prematurely before boot completion" >&2
      return 1
    fi
    local boot_completed dev_bootcomplete bootanim
    boot_completed="$("$ADB_BIN" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
    dev_bootcomplete="$("$ADB_BIN" -s "$SERIAL" shell getprop dev.bootcomplete 2>/dev/null | tr -d '\r')"
    bootanim="$("$ADB_BIN" -s "$SERIAL" shell getprop init.svc.bootanim 2>/dev/null | tr -d '\r')"
    if [[ "$boot_completed" == "1" && ( "$dev_bootcomplete" == "1" || "$bootanim" == "stopped" ) ]]; then
      break
    fi
    sleep 2
  done

  if [[ "$("$ADB_BIN" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]]; then
    echo "ERROR: Timed out waiting for sys.boot_completed=1" >&2
    return 1
  fi

  # 3. Wait for core system_server services (input + package) to answer Binder calls
  while (( SECONDS < deadline )); do
    if ! kill -0 "${EMU_PID}" 2>/dev/null; then
      echo "ERROR: Emulator process exited while waiting for system services" >&2
      return 1
    fi
    local input_svc pkg_svc pm_android
    input_svc="$("$ADB_BIN" -s "$SERIAL" shell service check input 2>/dev/null | tr -d '\r')"
    pkg_svc="$("$ADB_BIN" -s "$SERIAL" shell service check package 2>/dev/null | tr -d '\r')"
    pm_android="$("$ADB_BIN" -s "$SERIAL" shell pm path android 2>/dev/null | tr -d '\r')"
    if [[ "$input_svc" == *"found"* && "$input_svc" != *"not found"* \
       && "$pkg_svc" == *"found"* && "$pkg_svc" != *"not found"* \
       && "$pm_android" == package:* ]]; then
      # Brief settle window to confirm system_server stays healthy right after boot_completed
      sleep 3
      local pm_recheck
      pm_recheck="$("$ADB_BIN" -s "$SERIAL" shell pm path android 2>/dev/null | tr -d '\r')"
      if [[ "$pm_recheck" == package:* ]]; then
        echo "==> Emulator ${SERIAL} core services are ready (pm=${pm_recheck})"
        return 0
      fi
    fi
    sleep 2
  done

  echo "ERROR: Timed out waiting for system_server input/package services" >&2
  return 1
}

configure_emulator_for_tests() {
  adb_shell_retry "disable window animations" settings put global window_animation_scale 0.0
  adb_shell_retry "disable transition animations" settings put global transition_animation_scale 0.0
  adb_shell_retry "disable animator duration" settings put global animator_duration_scale 0.0
  adb_shell_retry "dismiss keyguard" wm dismiss-keyguard
  adb_shell_retry "unlock screen keyevent 82" input keyevent 82
}

boot_attempt=1
boot_ready=0
while (( boot_attempt <= MAX_BOOT_ATTEMPTS )); do
  echo "==> Boot attempt ${boot_attempt}/${MAX_BOOT_ATTEMPTS}: creating AVD '${AVD_NAME}' (profile=${PROFILE}, memory=${MEMORY_MB}MB, cores=${CORES})"
  stop_emulator
  "$ADB_BIN" start-server >/dev/null 2>&1 || true

  echo no | "$AVDMANAGER" create avd --force \
    -n "$AVD_NAME" \
    --package "$SYS_IMAGE" \
    --device "$PROFILE" >/dev/null

  EMU_LOG="${LOG_DIR}/emulator-api${API_LEVEL}-attempt${boot_attempt}.log"
  echo "==> Launching ${EMULATOR_BIN} -avd ${AVD_NAME} (log: ${EMU_LOG})"
  "$EMULATOR_BIN" \
    -avd "$AVD_NAME" \
    -port "$EMU_PORT" \
    -no-snapshot-load \
    -no-snapshot-save \
    -no-window \
    -gpu swiftshader_indirect \
    -noaudio \
    -no-boot-anim \
    -memory "$MEMORY_MB" \
    -cores "$CORES" \
    >"$EMU_LOG" 2>&1 &
  EMU_PID="$!"

  if wait_for_emulator_ready && configure_emulator_for_tests; then
    boot_ready=1
    break
  fi

  echo "WARN: Emulator boot/setup failed on attempt ${boot_attempt}/${MAX_BOOT_ATTEMPTS}" >&2
  dump_diagnostics "boot-attempt${boot_attempt}"
  stop_emulator
  boot_attempt=$((boot_attempt + 1))
done

if (( boot_ready != 1 )); then
  echo "ERROR: Failed to boot and stabilize API ${API_LEVEL} emulator after ${MAX_BOOT_ATTEMPTS} attempts." >&2
  exit 1
fi

echo "==> Running instrumentation command on ${SERIAL}: $*"
export ANDROID_SERIAL="$SERIAL"
"$@"
