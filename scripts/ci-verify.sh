#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_CLEAN=0
GRADLE_EXTRA_ARGS=()

for arg in "$@"; do
  if [[ "$arg" == "--clean" ]]; then
    RUN_CLEAN=1
  else
    GRADLE_EXTRA_ARGS+=("$arg")
  fi
done

read_prop() {
  local key="$1"
  local val
  val="$(grep -E "^${key}=" gradle.properties | tail -n 1 | cut -d'=' -f2- | tr -d '\r' | xargs)"
  if [[ -z "$val" ]]; then
    echo "ERROR: Missing required property '${key}' in gradle.properties" >&2
    exit 1
  fi
  printf '%s' "$val"
}

EXPECTED_JAVA="$(read_prop androidJavaVersion)"
EXPECTED_COMPILE_SDK="$(read_prop androidCompileSdk)"
EXPECTED_BUILD_TOOLS="$(read_prop androidBuildToolsVersion)"
EXPECTED_CMAKE="$(read_prop androidCmakeVersion)"
EXPECTED_NDK="$(read_prop androidNdkVersion)"

echo "==> Toolchain contract (from gradle.properties)"
echo "    JDK: ${EXPECTED_JAVA} | compileSdk: ${EXPECTED_COMPILE_SDK} | build-tools: ${EXPECTED_BUILD_TOOLS} | cmake: ${EXPECTED_CMAKE} | ndk: ${EXPECTED_NDK}"

# 1. Verify JDK major version matches CI
JAVA_VERSION_LINE="$(java -version 2>&1 | head -n 1)"
JAVA_MAJOR="$(printf '%s\n' "$JAVA_VERSION_LINE" | sed -E 's/.*"([0-9]+).*/\1/')"
echo "==> Active JDK: ${JAVA_VERSION_LINE}"
if [[ "${SKIP_JDK_CHECK:-0}" != "1" && "$JAVA_MAJOR" != "$EXPECTED_JAVA" ]]; then
  echo "ERROR: Active JDK major version is ${JAVA_MAJOR}, expected ${EXPECTED_JAVA} (CI uses JDK ${EXPECTED_JAVA})." >&2
  echo "       Set JAVA_HOME to JDK ${EXPECTED_JAVA} (or pass SKIP_JDK_CHECK=1 to bypass locally)." >&2
  exit 1
fi

# 2. Catch macOS case-insensitive filesystem traps in C/C++ local #include paths
if command -v python3 >/dev/null 2>&1; then
  echo "==> Checking C/C++ local #include path casing (Linux case-sensitivity guard)"
  python3 - <<'PY'
import os, re, sys

cpp_root = os.path.join("riskengine-sdk", "src", "main", "cpp")
include_re = re.compile(r'^\s*#\s*include\s+"([^"]+)"')
errors = []

def exact_case_exists(base_dir, rel_path):
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p]
    cur = os.path.abspath(base_dir)
    for part in parts:
        if part == ".":
            continue
        if part == "..":
            cur = os.path.dirname(cur)
            continue
        if not os.path.isdir(cur):
            return False
        entries = os.listdir(cur)
        if part not in entries:
            return False
        cur = os.path.join(cur, part)
    return os.path.isfile(cur)

for dirpath, _, filenames in os.walk(cpp_root):
    for fn in filenames:
        if not fn.endswith((".c", ".cc", ".cpp", ".h", ".hpp")):
            continue
        full = os.path.join(dirpath, fn)
        with open(full, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                m = include_re.match(line)
                if not m:
                    continue
                inc = m.group(1)
                if not (exact_case_exists(dirpath, inc) or exact_case_exists(cpp_root, inc)):
                    errors.append(f"{full}:{lineno}: #include \"{inc}\" does not match exact file casing on disk")

if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
PY
fi

# 3. Run the exact Gradle verification task graph used by CI and Release workflows
TASKS=()
if [[ "$RUN_CLEAN" -eq 1 ]]; then
  TASKS+=(clean)
fi
TASKS+=(
  :riskengine-sdk:test
  :riskengine-sdk:lint
  :riskengine-sdk:assembleRelease
  :riskengine-sdk:sourceReleaseJar
  :riskengine-sdk:generatePomFileForReleasePublication
  :riskengine-sdk:apiCheck
  :integration-test:assembleDebug
  :integration-test:assembleDebugAndroidTest
  :integration-test:lintDebug
  :demo:lintDebug
  :demo:assembleDebug
)

echo "==> Running Gradle verification tasks"
if [[ "${#GRADLE_EXTRA_ARGS[@]}" -gt 0 ]]; then
  ./gradlew "${TASKS[@]}" "${GRADLE_EXTRA_ARGS[@]}" --no-daemon
else
  ./gradlew "${TASKS[@]}" --no-daemon
fi

# 4. Ensure generated detection lists are up to date with artifact_paths.ini
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "==> Verifying generated detection lists are committed and in sync"
  if ! git diff --exit-code -- \
    riskengine-sdk/src/main/java/com/wsttxm/riskenginesdk/generated/DetectionLists.java \
    riskengine-sdk/src/main/cpp/generated/detection_lists.h; then
    echo "ERROR: Generated detection lists drifted from artifact_paths.ini." >&2
    echo "       Run './gradlew :riskengine-sdk:generateDetectionLists' and commit the updated files." >&2
    exit 1
  fi
fi

# 5. Verify distributable artifacts exist, are non-empty, and pass archive integrity checks
echo "==> Verifying distributable artifacts"
test -s riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar
test -s riskengine-sdk/build/intermediates/source_jar/release/release-sources.jar
test -s riskengine-sdk/build/publications/release/pom-default.xml
test -s demo/build/outputs/apk/debug/demo-debug.apk
test -s integration-test/build/outputs/apk/debug/integration-test-debug.apk
test -s integration-test/build/outputs/apk/androidTest/debug/integration-test-debug-androidTest.apk

unzip -tq riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar
unzip -tq demo/build/outputs/apk/debug/demo-debug.apk
unzip -tq integration-test/build/outputs/apk/debug/integration-test-debug.apk
unzip -tq integration-test/build/outputs/apk/androidTest/debug/integration-test-debug-androidTest.apk

# 6. Run CI Static Governance Gates 1–6 & Python gate self-tests
echo "==> Running CI Static Governance Gates 1–6"
python3 -B scripts/check-evidence-records.py
CHECK_JNI_DEX=1 ./scripts/check-elf-hardening.sh riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar
python3 -B scripts/check-single-source-sync.py
python3 -B scripts/check-public-api.py --mode check \
  --aar riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar \
  --pom riskengine-sdk/build/publications/release/pom-default.xml \
  --api-file riskengine-sdk/api/riskengine-sdk.api
python3 -B scripts/check-boundary-guards.py
python3 -B scripts/refresh_google_attestation_roots.py --dry-run
python3 -B scripts/test_static_gates.py
python3 -B scripts/test_api_and_boundary_gates.py

# 7. Run L2 Offline C++ Host Unit Test Suite
echo "==> Running L2 Offline C++ Host Unit Tests"
./scripts/run-cpp-tests.sh

echo "==> All CI verification checks passed."
