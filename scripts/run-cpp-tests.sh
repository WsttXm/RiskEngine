#!/usr/bin/env bash
# Offline L2 C++ Host Unit Test Runner (CMake + CTest, zero network downloads)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${ROOT_DIR}/riskengine-sdk/src/test/cpp"
BUILD_DIR="${ROOT_DIR}/build/cpp-host-tests"

if ! command -v cmake >/dev/null 2>&1; then
  echo "ERROR: cmake not found in PATH." >&2
  exit 1
fi
if ! command -v ctest >/dev/null 2>&1; then
  echo "ERROR: ctest not found in PATH." >&2
  exit 1
fi

echo "==> Configuring offline L2 C++ host tests (${SRC_DIR} -> ${BUILD_DIR})"
cmake -S "${SRC_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=RelWithDebInfo

echo "==> Building offline L2 C++ host tests"
cmake --build "${BUILD_DIR}" --parallel

echo "==> Running CTest suite"
ctest --test-dir "${BUILD_DIR}" --output-on-failure

echo "==> L2 C++ host tests PASSED."
