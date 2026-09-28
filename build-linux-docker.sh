#!/usr/bin/env bash
set -euo pipefail

IMAGE="ubuntu:24.04"
BUILD_DIR="build/linux"

echo "==> Building in Docker (${IMAGE})"

docker run --rm \
  -v "$(pwd)":/src \
  -w /src \
  "${IMAGE}" bash -c "
    set -euo pipefail
    echo '==> Installing dependencies'
    apt-get update -qq
    apt-get install -y -qq cmake gcc libssl-dev libseccomp-dev

    echo '==> Configuring (out-of-source build in ${BUILD_DIR})'
    mkdir -p '${BUILD_DIR}'
    cmake -B '${BUILD_DIR}' -S . -DPKCS11_V32=ON

    echo '==> Building'
    cmake --build '${BUILD_DIR}' \"\$@\"
  " -- "$@"

echo "==> Done. Artifacts in ${BUILD_DIR}/"
