#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="$ROOT_DIR/dist"
PROJECT_ENV="$ROOT_DIR/../../.env"

load_project_env() {
  if [[ ! -f "$PROJECT_ENV" ]]; then
    return 0
  fi
  eval "$(
    python3.13 - <<'PY' "$PROJECT_ENV"
import shlex
import sys
from pathlib import Path

path = Path(sys.argv[1])
for line in path.read_text(encoding="utf-8").splitlines():
    raw = line.strip()
    if not raw or raw.startswith("#") or "=" not in raw:
        continue
    key, value = raw.split("=", 1)
    key = key.strip()
    value = value.strip()
    if not key:
        continue
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1]
    print(f"export {key}={shlex.quote(value)}")
PY
  )"
}

load_project_env

MODE="${1:-}"
if [[ $# -gt 0 ]]; then
  shift
fi

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
ROLE_ARN="${ROLE_ARN:-arn:aws:iam::842337469411:role/service-role/AmazonBedrockAgentCoreRuntimeDefaultServiceRole-k0y7q}"
NETWORK_MODE="${NETWORK_MODE:-PUBLIC}"
IDLE_TIMEOUT="${IDLE_TIMEOUT:-3600}"
MAX_LIFETIME="${MAX_LIFETIME:-28800}"
DESCRIPTION="${DESCRIPTION:-patch impact agent container runtime}"
RUNTIME_NAME="${RUNTIME_NAME:-patch_impact_agent2}"
RUNTIME_ID="${RUNTIME_ID:-}"
RUNTIME_ARN="${RUNTIME_ARN:-}"
CONTAINER_URI="${CONTAINER_URI:-}"

usage() {
  cat <<'EOF'
사용법:
  ./deploy_container_runtime.sh create [옵션]
  ./deploy_container_runtime.sh update [옵션]

옵션:
  --runtime-name <name>     create 시 런타임 이름
  --runtime-id <id>         update 시 런타임 ID
  --runtime-arn <arn>       update 시 런타임 ARN (ID 자동 추출)
  --container-uri <uri>     ECR 이미지 URI
  --role-arn <arn>          AgentCore 서비스 역할 ARN
  --region <region>         AWS 리전
  --description <text>      런타임 설명
  --idle-timeout <sec>      idleRuntimeSessionTimeout
  --max-lifetime <sec>      maxLifetime

기본값:
  - container URI를 안 주면 dist/container_uri.txt 를 먼저 읽습니다.
  - update 에서 runtime-id가 없고 runtime-arn만 있으면 ARN 마지막 토큰을 ID로 씁니다.

예시:
  ./deploy_container_runtime.sh create
  ./deploy_container_runtime.sh update --runtime-arn arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/patch_impact_agent2-2Zl5H0Gf4T
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-name)
      RUNTIME_NAME="${2:?missing value for --runtime-name}"
      shift 2
      ;;
    --runtime-id)
      RUNTIME_ID="${2:?missing value for --runtime-id}"
      shift 2
      ;;
    --runtime-arn)
      RUNTIME_ARN="${2:?missing value for --runtime-arn}"
      shift 2
      ;;
    --container-uri)
      CONTAINER_URI="${2:?missing value for --container-uri}"
      shift 2
      ;;
    --role-arn)
      ROLE_ARN="${2:?missing value for --role-arn}"
      shift 2
      ;;
    --region)
      AWS_REGION="${2:?missing value for --region}"
      shift 2
      ;;
    --description)
      DESCRIPTION="${2:?missing value for --description}"
      shift 2
      ;;
    --idle-timeout)
      IDLE_TIMEOUT="${2:?missing value for --idle-timeout}"
      shift 2
      ;;
    --max-lifetime)
      MAX_LIFETIME="${2:?missing value for --max-lifetime}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "알 수 없는 옵션: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$MODE" ]]; then
  echo "create 또는 update 모드를 지정해야 합니다." >&2
  usage
  exit 1
fi

if [[ -z "$CONTAINER_URI" && -f "$DIST_DIR/container_uri.txt" ]]; then
  CONTAINER_URI="$(tr -d '\r\n' < "$DIST_DIR/container_uri.txt")"
fi

if [[ -z "$CONTAINER_URI" ]]; then
  echo "CONTAINER_URI가 비어 있습니다. --container-uri로 넘기거나 build_and_push_container.sh를 먼저 실행하세요." >&2
  exit 1
fi

if [[ -z "$RUNTIME_ID" && -n "$RUNTIME_ARN" ]]; then
  RUNTIME_ID="${RUNTIME_ARN##*/}"
fi

ARTIFACT_JSON="{\"containerConfiguration\":{\"containerUri\":\"$CONTAINER_URI\"}}"
NETWORK_CONFIG="networkMode=$NETWORK_MODE"
PROTOCOL_CONFIG="serverProtocol=HTTP"
LIFECYCLE_CONFIG="idleRuntimeSessionTimeout=$IDLE_TIMEOUT,maxLifetime=$MAX_LIFETIME"

if [[ "$MODE" == "create" ]]; then
  echo "[create] runtime=$RUNTIME_NAME"
  aws bedrock-agentcore-control create-agent-runtime \
    --region "$AWS_REGION" \
    --agent-runtime-name "$RUNTIME_NAME" \
    --agent-runtime-artifact "$ARTIFACT_JSON" \
    --role-arn "$ROLE_ARN" \
    --network-configuration "$NETWORK_CONFIG" \
    --protocol-configuration "$PROTOCOL_CONFIG" \
    --lifecycle-configuration "$LIFECYCLE_CONFIG" \
    --description "$DESCRIPTION" \
    --output json
  exit 0
fi

if [[ "$MODE" == "update" ]]; then
  if [[ -z "$RUNTIME_ID" ]]; then
    echo "update 모드에서는 --runtime-id 또는 --runtime-arn 이 필요합니다." >&2
    exit 1
  fi

  echo "[update] runtime-id=$RUNTIME_ID"
  aws bedrock-agentcore-control update-agent-runtime \
    --region "$AWS_REGION" \
    --agent-runtime-id "$RUNTIME_ID" \
    --agent-runtime-artifact "$ARTIFACT_JSON" \
    --role-arn "$ROLE_ARN" \
    --network-configuration "$NETWORK_CONFIG" \
    --protocol-configuration "$PROTOCOL_CONFIG" \
    --lifecycle-configuration "$LIFECYCLE_CONFIG" \
    --description "$DESCRIPTION" \
    --output json
  exit 0
fi

echo "지원하지 않는 모드입니다: $MODE" >&2
usage
exit 1
