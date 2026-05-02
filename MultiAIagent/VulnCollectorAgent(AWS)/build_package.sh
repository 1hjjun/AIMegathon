#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$ROOT_DIR/build/deployment_package"
DIST_DIR="$ROOT_DIR/dist"
ZIP_PATH="$DIST_DIR/deployment_package.zip"
TARGET_PLATFORM="${TARGET_PLATFORM:-manylinux2014_aarch64}"
TARGET_PYTHON_VERSION="${TARGET_PYTHON_VERSION:-3.13}"

rm -rf "$BUILD_DIR" "$ZIP_PATH"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

if command -v uv >/dev/null 2>&1; then
  uv pip install \
    --python-platform "$TARGET_PLATFORM" \
    --python-version "$TARGET_PYTHON_VERSION" \
    --target "$BUILD_DIR" \
    -r "$ROOT_DIR/requirements.txt"
elif command -v python3.13 >/dev/null 2>&1; then
  python3.13 -m pip install \
    --only-binary=:all: \
    --platform "$TARGET_PLATFORM" \
    --implementation cp \
    --python-version 3.13 \
    --abi cp313 \
    --target "$BUILD_DIR" \
    -r "$ROOT_DIR/requirements.txt"
else
  echo "uv 또는 python3.13 이 필요합니다." >&2
  exit 1
fi

cp "$ROOT_DIR/runtime_app.py" "$BUILD_DIR/runtime_app.py"
cp -R "$ROOT_DIR/vuln_collector_agent" "$BUILD_DIR/vuln_collector_agent"

if find "$BUILD_DIR" -type f \( -name '*.dylib' -o -name '*darwin*.so' -o -name '*x86_64-linux-gnu.so' \) | grep -q .; then
  echo "ARM64가 아닌 바이너리가 포함되었습니다." >&2
  exit 1
fi

(
  cd "$BUILD_DIR"
  zip -qr "$ZIP_PATH" .
)

echo "Built: $ZIP_PATH"
