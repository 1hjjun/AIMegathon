"""오케스트레이터 에이전트 — AgentCore Runtime entrypoint.

전체 파이프라인 관리:
  취약점 페이로드 수신
    → ① asset_matching (auto_discover) : VPC 자동 탐색 + EC2 수집 → infra_context
    → ② risk_eval                      : CVE + infra_context → 위험도 리포트

호출 페이로드 스키마:
    {
      "cve_payload":   { "records": [...] },  # 필수
      "stack_name":    "megathon",             # 선택, 기본값 megathon
      "region":        "ap-northeast-2"        # 선택
    }
"""
import json
import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from bedrock_agentcore import BedrockAgentCoreApp

# ---------------------------------------------------------------------------
# 설정 — AgentCore ARN 은 재배포 전까지 고정
# ---------------------------------------------------------------------------

DEFAULT_REGION     = os.environ.get("DEFAULT_REGION", "ap-northeast-2")
DEFAULT_STACK_NAME = os.environ.get("CF_STACK_NAME", "megathon")

ASSET_MATCHING_ARN = os.environ.get(
    "ASSET_MATCHING_ARN",
    "arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/asset_matching_agent-zoDcgCEt8u",
)
RISK_EVAL_ARN = os.environ.get(
    "RISK_EVAL_ARN",
    "arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/risk_evaluation_agent-A2PkRd5CzC",
)

app = BedrockAgentCoreApp()

# ---------------------------------------------------------------------------
# 클라이언트 헬퍼
# ---------------------------------------------------------------------------

_clients: dict = {}

def _client(service: str, region: str):
    key = (service, region)
    if key not in _clients:
        cfg = Config(read_timeout=600, connect_timeout=10) if service == "bedrock-agentcore" else None
        _clients[key] = boto3.client(service, region_name=region, config=cfg)
    return _clients[key]


# ---------------------------------------------------------------------------
# VPC 자동 발견
# ---------------------------------------------------------------------------

def _discover_vpc_id(stack_name: str, region: str) -> str:
    """CloudFormation 스택 태그로 VPC ID 를 자동 탐색."""
    ec2 = _client("ec2", region)
    resp = ec2.describe_vpcs(Filters=[
        {"Name": "tag:aws:cloudformation:stack-name", "Values": [stack_name]},
        {"Name": "tag:aws:cloudformation:logical-id",  "Values": ["VPC"]},
        {"Name": "state", "Values": ["available"]},
    ])
    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        raise RuntimeError(
            f"스택 '{stack_name}' 에서 VPC 를 찾을 수 없습니다. "
            "스택이 올라와 있는지 확인해 주세요."
        )
    return vpcs[0]["VpcId"]


# ---------------------------------------------------------------------------
# 에이전트 호출 헬퍼
# ---------------------------------------------------------------------------

def _invoke(arn: str, payload: dict, region: str) -> dict:
    """AgentCore 런타임 호출 후 JSON 파싱해서 반환."""
    client = _client("bedrock-agentcore", region)
    try:
        resp = client.invoke_agent_runtime(
            agentRuntimeArn=arn,
            payload=json.dumps(payload).encode("utf-8"),
        )
    except ClientError as e:
        raise RuntimeError(f"AgentCore 호출 실패 ({arn.split('/')[-1]}): {e}")

    raw = resp["response"].read()
    # 응답이 JSON string 안에 JSON 이 또 들어있는 경우 두 번 파싱
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        return parsed
    except json.JSONDecodeError:
        return {"raw": raw.decode("utf-8", errors="replace")}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

@app.entrypoint
def invoke(payload):
    payload = payload or {}
    region     = payload.get("region", DEFAULT_REGION)
    stack_name = payload.get("stack_name", DEFAULT_STACK_NAME)

    cve_payload = payload.get("cve_payload") or payload.get("vulnerability_payload")
    if not cve_payload:
        return {"error": "cve_payload (또는 vulnerability_payload) 가 필요합니다."}

    # ── Step 1. VPC 자동 발견 ──────────────────────────────────────────────
    print(f"[Orchestrator] Step 1: VPC 자동 탐색 (stack={stack_name})")
    try:
        vpc_id = _discover_vpc_id(stack_name, region)
    except RuntimeError as e:
        return {"error": str(e)}
    print(f"[Orchestrator] VPC 발견: {vpc_id}")

    # ── Step 2. asset_matching — auto_discover ─────────────────────────────
    print("[Orchestrator] Step 2: asset_matching auto_discover 호출")
    am_payload = {
        "mode":       "auto_discover",
        "cve_payload": cve_payload,
        "vpc_id":     vpc_id,
        "region":     region,
        "metadata": {
            "environment":          "production",
            "business_criticality": "high",
        },
    }
    try:
        am_result = _invoke(ASSET_MATCHING_ARN, am_payload, region)
    except RuntimeError as e:
        return {"error": str(e)}

    if "error" in am_result:
        return {"error": f"asset_matching 실패: {am_result['error']}"}

    infra_context = am_result.get("infra_context") or am_result
    print(f"[Orchestrator] infra_context 수신: 자산 {len(infra_context.get('assets', []))}개")

    # ── Step 3. risk_eval ─────────────────────────────────────────────────
    print("[Orchestrator] Step 3: risk_eval 호출")
    re_payload = {
        "vulnerability_payload": cve_payload,
        "infra_context":         infra_context,
        "asset_matching_arn":    ASSET_MATCHING_ARN,  # swarm 직접 질의용
        "region":                region,
    }
    try:
        re_result = _invoke(RISK_EVAL_ARN, re_payload, region)
    except RuntimeError as e:
        return {"error": str(e)}

    print("[Orchestrator] 파이프라인 완료")

    # ── 최종 결과 ──────────────────────────────────────────────────────────
    return {
        "vpc_id":       vpc_id,
        "infra_context": infra_context,
        "risk_report":  re_result,
    }


if __name__ == "__main__":
    app.run()
