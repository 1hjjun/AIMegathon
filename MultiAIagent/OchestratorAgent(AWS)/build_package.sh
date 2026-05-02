#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$ROOT_DIR/build/deployment_package"
DIST_DIR="$ROOT_DIR/dist"
ZIP_PATH="$DIST_DIR/deployment_package.zip"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

if command -v uv >/dev/null 2>&1; then
  uv pip install \
    --python-platform aarch64-manylinux2014 \
    --python-version 3.13 \
    --target="$BUILD_DIR" \
    --only-binary=:all: \
    -r "$ROOT_DIR/requirements.txt"
elif command -v python3.13 >/dev/null 2>&1; then
  python3.13 -m pip install \
    --platform manylinux2014_aarch64 \
    --python-version 3.13 \
    --implementation cp \
    --only-binary=:all: \
    --target "$BUILD_DIR" \
    -r "$ROOT_DIR/requirements.txt"
else
  echo "uv 또는 python3.13 이 필요합니다."
  exit 1
fi

cp "$ROOT_DIR/main.py" "$BUILD_DIR/main.py"
cp "$ROOT_DIR/orchestrator_pipeline.py" "$BUILD_DIR/orchestrator_pipeline.py"
cp "$ROOT_DIR/pipeline_stages.py" "$BUILD_DIR/pipeline_stages.py"
cp "$ROOT_DIR/runtime_agents.py" "$BUILD_DIR/runtime_agents.py"

find "$BUILD_DIR" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "$BUILD_DIR" -type f -name "*.pyc" -delete

rm -f "$ZIP_PATH"
(
  cd "$BUILD_DIR"
  zip -qr "$ZIP_PATH" .
)

echo "완료: $ZIP_PATH"
