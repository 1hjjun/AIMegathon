#!/usr/bin/env bash
# EC2에서 agent_extract_asset.py 를 실행하기 위한 원스텝 스크립트
# 사용법: bash run_agent.sh [--env production] [--exposure public] [--criticality high]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# 1. .env 로드 (GEMINI_API_KEY 등)
# ---------------------------------------------------------------------------
ENV_FILE="$SCRIPT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    # 주석·빈 줄 제외하고 export
    set -o allexport
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +o allexport
    echo "[setup] .env 로드 완료"
else
    echo "[ERROR] .env 파일이 없습니다: $ENV_FILE"
    echo "        GEMINI_API_KEY=<your-key> 형식으로 .env 를 만들어 주세요."
    exit 1
fi

if [ -z "${GEMINI_API_KEY:-}" ]; then
    echo "[ERROR] GEMINI_API_KEY 가 설정되지 않았습니다."
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. google-genai 패키지 설치 (없을 때만)
# ---------------------------------------------------------------------------
if ! python3 -c "from google import genai" 2>/dev/null; then
    echo "[setup] google-genai 설치 중..."
    # Amazon Linux / RHEL 계열은 --user 로 설치
    pip3 install --quiet --user google-genai 2>/dev/null \
        || pip3 install --quiet google-genai
    echo "[setup] google-genai 설치 완료"
else
    echo "[setup] google-genai 이미 설치됨"
fi

# PATH 에 ~/.local/bin 추가 (--user 설치 시 필요)
export PATH="$HOME/.local/bin:$PATH"

# ---------------------------------------------------------------------------
# 3. agent_extract_asset.py 실행
# ---------------------------------------------------------------------------
AGENT_SCRIPT="$SCRIPT_DIR/agent_extract_asset.py"
PAYLOAD="$SCRIPT_DIR/payload.json"
OUTPUT="/tmp/asset_info.json"

if [ ! -f "$AGENT_SCRIPT" ]; then
    echo "[ERROR] 스크립트 없음: $AGENT_SCRIPT"
    exit 1
fi

if [ ! -f "$PAYLOAD" ]; then
    echo "[ERROR] payload.json 없음: $PAYLOAD"
    exit 1
fi

echo "[setup] 실행 시작: $AGENT_SCRIPT"
echo "-------------------------------------------"

python3 "$AGENT_SCRIPT" \
    --payload "$PAYLOAD" \
    --output  "$OUTPUT" \
    "$@"          # 나머지 인자 (--env, --exposure, --criticality) 그대로 전달

echo "-------------------------------------------"
echo "[done] 결과 파일: $OUTPUT"
