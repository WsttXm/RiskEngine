#!/usr/bin/env bash
# ============================================================
#  RiskEngine SDK Quick Build Script
#  Target: Android SDK project at repository root
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[ OK ]${NC}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
err()   { printf "${RED}[ERR ]${NC}  %s\n" "$*" >&2; }

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    cat <<EOF
Usage: $0 <command>

Commands:
  sdk       Build RiskEngine SDK (Android AAR)
  demo      Build Demo APK (debug)
  clean     Clean Gradle build outputs
  all       Build SDK AAR and Demo APK
  help      Show this help message

Environment:
  JDK 17+
  Android SDK (API 36), NDK, CMake 3.22+
EOF
}

check_java() {
    if ! command -v java &>/dev/null; then
        err "Java not found. Install JDK 17+."
        exit 1
    fi
    local ver
    ver=$(java -version 2>&1 | head -1 | sed 's/.*"\(.*\)".*/\1/' | cut -d. -f1)
    if [[ "$ver" -lt 17 ]]; then
        err "JDK 17+ required, found version $ver"
        exit 1
    fi
    ok "Java $ver"
}

check_android_sdk() {
    if [[ -z "${ANDROID_HOME:-}" && -z "${ANDROID_SDK_ROOT:-}" ]]; then
        local default_sdk="$HOME/Library/Android/sdk"
        if [[ -d "$default_sdk" ]]; then
            export ANDROID_HOME="$default_sdk"
            warn "ANDROID_HOME not set, using default: $default_sdk"
        else
            err "ANDROID_HOME or ANDROID_SDK_ROOT not set and SDK not found at default path."
            exit 1
        fi
    fi
    ok "Android SDK: ${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
}

run_gradle() {
    cd "$ROOT_DIR"
    chmod +x gradlew
    ./gradlew "$@" --no-daemon
}

build_sdk() {
    info "Building RiskEngine SDK..."
    check_java
    check_android_sdk
    run_gradle :riskengine-sdk:assembleRelease
    local aar
    aar=$(find "$ROOT_DIR/riskengine-sdk/build/outputs/aar" -name "*.aar" 2>/dev/null | head -1)
    if [[ -n "$aar" ]]; then
        ok "SDK AAR: $aar"
    else
        warn "AAR not found under riskengine-sdk/build/outputs/aar/."
    fi
}

build_demo() {
    info "Building Demo APK..."
    check_java
    check_android_sdk
    run_gradle :demo:assembleDebug
    local apk
    apk=$(find "$ROOT_DIR/demo/build/outputs/apk/debug" -name "*.apk" 2>/dev/null | head -1)
    if [[ -n "$apk" ]]; then
        ok "Demo APK: $apk"
        if command -v adb &>/dev/null && adb devices | grep -q "device$"; then
            info "Connected device detected, installing..."
            adb install -r "$apk"
            ok "Demo APK installed."
        fi
    else
        warn "APK not found under demo/build/outputs/apk/debug/."
    fi
}

clean_all() {
    info "Cleaning build outputs..."
    run_gradle clean
    ok "Build outputs cleaned."
}

build_all() {
    build_sdk
    echo ""
    build_demo
    echo ""
    ok "All builds completed."
}

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

case "$1" in
    sdk) build_sdk ;;
    demo) build_demo ;;
    clean) clean_all ;;
    all) build_all ;;
    help|-h|--help) usage ;;
    *)
        err "Unknown command: $1"
        usage
        exit 1
        ;;
esac
