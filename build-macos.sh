#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="build/macos"

echo "==> Configuring (out-of-source build in ${BUILD_DIR})"
mkdir -p "${BUILD_DIR}"
cmake -B "${BUILD_DIR}" -S . -DPKCS11_V32=ON

echo "==> Building"
cmake --build "${BUILD_DIR}" -- "$@"

echo "==> Done. Artifacts in ${BUILD_DIR}/"
