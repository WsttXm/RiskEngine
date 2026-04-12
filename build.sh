#!/usr/bin/env bash
# ============================================================
#  RiskEngine Quick Build Script
#  Target: macOS ARM64 (Apple Silicon)
# ============================================================
set -euo pipefail

# ---------- Color helpers ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[ OK ]${NC}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
err()   { printf "${RED}[ERR ]${NC}  %s\n" "$*" >&2; }

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_DIR="$ROOT_DIR/RiskEngineServer"
SDK_DIR="$ROOT_DIR/RiskEngineSdk"

# ---------- Usage ----------
usage() {
    cat <<EOF
Usage: $0 <command>

Commands:
  server        Build RiskEngine Server (Spring Boot JAR)
  server-run    Build & run Server locally (H2 dev mode, no MySQL needed)
  sdk           Build RiskEngine SDK (Android AAR)
  demo          Build Demo APK (debug)
  docker        Build & start Server + MySQL via Docker Compose
  docker-stop   Stop Docker Compose services
  clean         Clean all build outputs
  all           Build Server + SDK
  help          Show this help message

Environment:
  macOS ARM64 (Apple Silicon)
  Server: JDK 17+, Gradle 9.4
  SDK:    JDK 17+, Android SDK (API 36), NDK, CMake 3.22+
EOF
}

# ---------- Prerequisite checks ----------
check_java() {
    if ! command -v java &>/dev/null; then
        err "Java not found. Install JDK 17+:"
        err "  brew install openjdk@17"
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

check_docker() {
    if ! command -v docker &>/dev/null; then
        err "Docker not found. Install Docker Desktop for Mac:"
        err "  https://docs.docker.com/desktop/setup/install/mac-install/"
        exit 1
    fi
    if ! docker info &>/dev/null; then
        err "Docker daemon is not running. Start Docker Desktop first."
        exit 1
    fi
    ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')"
}

check_android_sdk() {
    if [[ -z "${ANDROID_HOME:-}" && -z "${ANDROID_SDK_ROOT:-}" ]]; then
        # Try common default path on macOS
        local default_sdk="$HOME/Library/Android/sdk"
        if [[ -d "$default_sdk" ]]; then
            export ANDROID_HOME="$default_sdk"
            warn "ANDROID_HOME not set, using default: $default_sdk"
        else
            err "ANDROID_HOME or ANDROID_SDK_ROOT not set and SDK not found at default path."
            err "Install Android Studio or set ANDROID_HOME manually."
            exit 1
        fi
    fi
    ok "Android SDK: ${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
}

# ---------- Build commands ----------
build_server() {
    info "Building RiskEngine Server..."
    check_java
    cd "$SERVER_DIR"
    chmod +x gradlew
    ./gradlew bootJar --no-daemon -x test
    local jar
    jar=$(ls -1 build/libs/*.jar 2>/dev/null | head -1)
    ok "Server JAR: $jar"
}

run_server() {
    build_server
    info "Starting Server in dev mode (H2 database)..."
    local jar
    jar=$(ls -1 "$SERVER_DIR/build/libs/"*.jar 2>/dev/null | head -1)
    info "Admin login: admin / admin123"
    info "Web UI:  http://localhost:8080"
    info "H2 Console: http://localhost:8080/h2-console"
    echo ""
    java -jar "$jar" --spring.profiles.active=dev
}

build_sdk() {
    info "Building RiskEngine SDK..."
    check_java
    check_android_sdk
    cd "$SDK_DIR"
    chmod +x gradlew
    ./gradlew :riskengine-sdk:assembleRelease --no-daemon
    local aar
    aar=$(find riskengine-sdk/build/outputs/aar -name "*.aar" 2>/dev/null | head -1)
    if [[ -n "$aar" ]]; then
        ok "SDK AAR: $aar"
    else
        warn "AAR not found under riskengine-sdk/build/outputs/aar/ — check build output above."
    fi
}

build_demo() {
    info "Building Demo APK..."
    check_java
    check_android_sdk
    cd "$SDK_DIR"
    chmod +x gradlew
    ./gradlew :demo:assembleDebug --no-daemon
    local apk
    apk=$(find demo/build/outputs/apk/debug -name "*.apk" 2>/dev/null | head -1)
    if [[ -n "$apk" ]]; then
        ok "Demo APK: $apk"
        # Install to connected device if adb is available
        if command -v adb &>/dev/null && adb devices | grep -q "device$"; then
            info "Connected device detected, installing..."
            adb install -r "$apk"
            ok "Demo APK installed."
        fi
    else
        warn "APK not found under demo/build/outputs/apk/debug/ — check build output above."
    fi
}

docker_up() {
    info "Starting RiskEngine via Docker Compose..."
    check_docker
    cd "$SERVER_DIR"
    docker compose up --build -d
    echo ""
    ok "Services started!"
    info "Web UI:  http://localhost:8080"
    info "MySQL:   localhost:3306 (risk_engine / risk_engine_pass)"
    info "Admin:   admin / admin123"
    info "Logs:    cd RiskEngineServer && docker compose logs -f"
}

docker_down() {
    info "Stopping Docker Compose services..."
    check_docker
    cd "$SERVER_DIR"
    docker compose down
    ok "Services stopped."
}

clean_all() {
    info "Cleaning build outputs..."
    if [[ -f "$SERVER_DIR/gradlew" ]]; then
        cd "$SERVER_DIR"
        chmod +x gradlew
        ./gradlew clean --no-daemon 2>/dev/null || true
        ok "Server cleaned"
    fi
    if [[ -f "$SDK_DIR/gradlew" ]]; then
        cd "$SDK_DIR"
        chmod +x gradlew
        ./gradlew clean --no-daemon 2>/dev/null || true
        ok "SDK cleaned"
    fi
    ok "All build outputs cleaned."
}

build_all() {
    build_server
    echo ""
    build_sdk
    echo ""
    ok "All builds completed."
}

# ---------- Main ----------
if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

case "$1" in
    server)      build_server ;;
    server-run)  run_server ;;
    sdk)         build_sdk ;;
    demo)        build_demo ;;
    docker)      docker_up ;;
    docker-stop) docker_down ;;
    clean)       clean_all ;;
    all)         build_all ;;
    help|-h|--help) usage ;;
    *)
        err "Unknown command: $1"
        usage
        exit 1
        ;;
esac
