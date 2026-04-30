"""위험도 평가 에이전트 — AgentCore Runtime entrypoint.

호출 페이로드 스키마:
    {
      "vulnerability_payload": { "records": [...] },   # 필수, risk_assessment_payloads.json 형식
      "infra_context":         { "assets": [...], ... },# 선택, 이미 수집된 자산 데이터
      "vpc_id":                "vpc-...",                # 선택, infra_context 없을 때 자산매칭 자동 호출용
      "cve_payload":           { "records": [...] },    # 선택, 자산매칭에 넘길 CVE 페이로드 (없으면 vulnerability_payload 재사용)
      "region":                "ap-northeast-2",         # 선택, 자산매칭 호출 리전
      "asset_matching_arn":    "arn:...",                # 선택, 환경변수 ASSET_MATCHING_ARN 으로도 지정 가능
      "metadata":              {...},                    # 선택, 자산매칭 호출 시 부가 메타데이터
      "prompt":                "..."                     # 선택, 기본 프롬프트 override
    }

응답: 정제된 위험도 평가 JSON 배열 문자열.
"""
import json
import os
import re

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from pydantic import BaseModel, Field
from typing import List, Optional

import risk_assessment_refiner
import infra_context_refiner

from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent, tool

# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "global.anthropic.claude-haiku-4-5-20251001-v1:0",
)
DEFAULT_REGION = os.environ.get("DEFAULT_REGION", "ap-northeast-2")
ASSET_MATCHING_ARN_ENV = "ASSET_MATCHING_ARN"

app = BedrockAgentCoreApp()

# 현재 invoke 의 컨텍스트 (도구 함수에서 참조)
_runtime_state: dict = {
    "infra_context": None,
    "asset_matching_arn": None,
    "region": DEFAULT_REGION,
    "final_report": None,
}

# boto3 client 캐시
_boto3_clients: dict = {}


def _client(service: str, region: str):
    key = (service, region)
    if key not in _boto3_clients:
        # bedrock-agentcore 호출은 SSM 수집까지 포함해 수 분 걸릴 수 있어 타임아웃을 넉넉히 설정
        cfg = Config(read_timeout=600, connect_timeout=10) if service == "bedrock-agentcore" else None
        _boto3_clients[key] = boto3.client(service, region_name=region, config=cfg)
    return _boto3_clients[key]


# ---------------------------------------------------------------------------
# 데이터 규격
# ---------------------------------------------------------------------------

class ImpactedAsset(BaseModel):
    instance_id: str = Field(description="AWS EC2 인스턴스 ID")
    calculated_risk: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW 중 하나")
    reasoning: str = Field(description="해당 자산의 위험도가 산출된 보안 논리적 근거")
    remediation: str = Field(description="보안 권고 조치 사항")


class FinalReport(BaseModel):
    cve_id: str = Field(description="분석 대상 취약점 번호")
    title: str = Field(description="취약점 명칭")
    impacted_assets: List[ImpactedAsset] = Field(description="영향을 받는 자산 리스트")
    summary: str = Field(description="보안 분석가 관점의 전체 종합 의견")


# ---------------------------------------------------------------------------
# 자산매칭 에이전트 호출 헬퍼
# ---------------------------------------------------------------------------

def _invoke_asset_matching(payload: dict) -> dict:
    """asset_matching_agent (AgentCore Runtime) 호출."""
    arn = _runtime_state.get("asset_matching_arn")
    if not arn:
        raise RuntimeError(
            f"자산매칭 ARN 미설정. payload.asset_matching_arn 또는 환경변수 {ASSET_MATCHING_ARN_ENV} 필요."
        )
    region = _runtime_state.get("region", DEFAULT_REGION)
    client = _client("bedrock-agentcore", region)
    try:
        resp = client.invoke_agent_runtime(
            agentRuntimeArn=arn,
            payload=json.dumps(payload).encode("utf-8"),
        )
    except ClientError as e:
        raise RuntimeError(f"asset_matching invoke 실패: {e}")

    raw = resp["response"].read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": f"asset_matching 응답 파싱 실패: {raw[:200]!r}"}


# ---------------------------------------------------------------------------
# 도구
# ---------------------------------------------------------------------------

@tool
def query_asset_details(instance_id: str, question: str) -> str:
    """
    특정 EC2 인스턴스에 대해 자산 매칭 에이전트에게 추가 조사를 요청한다.
    위험도 평가 시 자산 정보가 부족하다면 이 도구로 실시간 추가 조사를 수행한다.

    Args:
        instance_id: 조사 대상 EC2 인스턴스 ID (예: i-0123abcd).
        question: 자산 매칭 에이전트에게 보낼 구체적 질문
                  (예: "log4j 의 JndiLookup mitigation 이 적용되어 있는가?").

    Returns:
        자산 매칭 에이전트의 답변 텍스트 (answer + confidence + evidence).
    """
    infra = _runtime_state.get("infra_context") or {}
    assets = infra.get("assets") if isinstance(infra, dict) else None
    if not assets:
        return "[ERROR] infra_context 없음 — 자산 매칭 결과를 먼저 받아야 합니다."

    asset = next((a for a in assets if a.get("asset_id") == instance_id), None)
    if asset is None:
        ids = ", ".join(a.get("asset_id", "") for a in assets)
        return f"[ERROR] {instance_id} 자산 미존재. 가능한 ID: {ids}"

    body = _invoke_asset_matching({
        "mode": "query",
        "asset_info": asset,
        "instance_id": instance_id,
        "question": question,
        "region": _runtime_state.get("region", DEFAULT_REGION),
    })

    if "error" in body:
        return f"[ERROR] {body['error']}"
    answer = body.get("answer", "")
    confidence = body.get("confidence", "")
    evidence = body.get("evidence", [])
    return (
        f"[answer]     {answer}\n"
        f"[confidence] {confidence}\n"
        f"[evidence]   {json.dumps(evidence, ensure_ascii=False)}"
    )


@tool
def finalize_report(report: FinalReport):
    """위험도 평가가 완전히 끝났을 때 최종 리포트를 저장한다."""
    data = report.dict()
    _runtime_state["final_report"] = data
    with open("risk_evaluation_result.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return "FINAL_COMPLETE"


# ---------------------------------------------------------------------------
# 페이로드 검증
# ---------------------------------------------------------------------------

def _ensure_infra_context(payload: dict) -> dict:
    """payload 에서 infra_context 를 추출한다. 없으면 에러 — 오케스트레이터가 제공해야 함."""
    infra = payload.get("infra_context")
    if isinstance(infra, dict) and infra.get("assets"):
        return infra
    raise RuntimeError(
        "infra_context 가 없습니다. 오케스트레이터가 asset_matching 결과를 전달해야 합니다."
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

@app.entrypoint
def invoke(payload):
    payload = payload or {}

    # 1) 런타임 상태 초기화
    _runtime_state["region"] = payload.get("region") or DEFAULT_REGION
    _runtime_state["asset_matching_arn"] = (
        payload.get("asset_matching_arn") or os.environ.get(ASSET_MATCHING_ARN_ENV)
    )

    # 2) 입력 데이터 확보
    vuln_payload = payload.get("vulnerability_payload") or payload.get("cve_payload")
    if not vuln_payload:
        return {"error": "vulnerability_payload (또는 cve_payload) 가 필요합니다."}

    try:
        infra_context = _ensure_infra_context(payload)
    except RuntimeError as e:
        return {"error": str(e)}

    _runtime_state["infra_context"] = infra_context

    # 3) refiner 로 정제 (dict 직접 전달)
    vuln_list = risk_assessment_refiner.get_refined_vulnerability(vuln_payload)
    asset_info = infra_context_refiner.get_refined_asset_report(infra_context)

    # 4) 프롬프트 구성
    user_message = payload.get("prompt", "현재 수집된 자산과 취약점을 비교하여 위험도를 평가해줘.")
    user_message = f"""
{user_message}

제공된 모든 취약점과 자산의 교집합을 분석하여 '누락 없이' 전수 리포트를 작성하십시오.

[참조 데이터]
- 취약점        : {json.dumps(vuln_list, ensure_ascii=False)}
- 현재 자산 상태 : {json.dumps(asset_info, ensure_ascii=False)}

# ANALYSIS LOGIC
- 단계 1: 각 취약점(CVE)을 순회합니다.
- 단계 2: 해당 취약점의 영향을 받는 모든 EC2 인스턴스를 식별합니다.
- 단계 3: 취약점 1개당 영향을 받는 자산이 여러 개일 경우, 'impacted_assets' 리스트에 모두 포함하십시오.
- 단계 4: 모든 취약점에 대해 위 과정을 반복하여 하나의 JSON 배열로 응답하십시오.

# 추가 조사가 필요할 때
- 자산 정보가 부족해 위험도 판단이 어려우면 'query_asset_details(instance_id, question)' 도구를 호출해 자산 매칭 에이전트에게 실시간 추가 조사를 요청할 수 있습니다.
- 도구의 응답을 받은 뒤 최종 JSON 을 생성하십시오.
- 단순 호기심 차원의 질의는 자제하고, 위험도 산정에 결정적인 정보(예: mitigation 적용 여부, 외부 노출 포트의 실제 service 등)에만 사용하십시오.

# OUTPUT FORMAT (STRICT)
응답은 반드시 아래 형태의 json 구조여야 합니다:

[
    {{
    "cve_id": "첫 번째 CVE 번호",
    "title": "첫 번째 취약점 명칭",
    "impacted_assets": [
        {{
            "instance_id": "string",
            "calculated_risk": "CRITICAL | HIGH | MEDIUM | LOW",
            "exploit_available": "Yes | No",
            "asset_criticality": "Prod | Dev",
            "exposure_level": "Public | Internal",
            "potential_impact": "공격 성공 시 예상되는 직접적인 피해 내용",
            "summary": "자산별 위험도 요약"
        }}
    ]
    }}
]

# CRITICAL CONSTRAINT
- 입력된 데이터 중 어느 하나라도 분석에서 누락되면 안 됩니다.
- 텍스트 설명 없이 오직 JSON 배열만 출력하십시오.
- 모든 설명 및 Json의 Value값은 15자 이내의 핵심 키워드로만 작성하십시오.
- 줄바꿈을 절대 사용하지 마십시오.

"RESPONSE MUST BE A SINGLE JSON ARRAY ONLY. DO NOT INCLUDE ANY TEXT OUTSIDE THE JSON."
"""

    # 5) Agent 실행 (도구: query_asset_details, finalize_report)
    _runtime_state["final_report"] = None
    agent = Agent(model=BEDROCK_MODEL_ID)
    result = agent(user_message, tools=[query_asset_details, finalize_report])

    # 6) 결과 파싱 — finalize_report 호출 결과 우선, 없으면 텍스트에서 파싱
    if _runtime_state["final_report"] is not None:
        return json.dumps(_runtime_state["final_report"], indent=4, ensure_ascii=False)

    # 텍스트 응답에서 JSON 추출 시도
    try:
        content_blocks = result.message.get("content", [])
        raw_text = ""
        for block in content_blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                raw_text = block.get("text", "").strip()
                break
        if not raw_text:
            raw_text = str(result).strip()
    except Exception:
        raw_text = str(result).strip()

    if "```" in raw_text:
        parts = raw_text.split("```")
        for part in parts:
            part = part.lstrip("json").strip()
            if part.startswith("[") or part.startswith("{"):
                raw_text = part
                break

    try:
        final_data = json.loads(raw_text)
        return json.dumps(final_data, indent=4, ensure_ascii=False)
    except Exception:
        try:
            clean_text = re.sub(r"\s+", " ", raw_text)
            fixed_data = json.loads(clean_text)
            return json.dumps(fixed_data, indent=4, ensure_ascii=False)
        except Exception:
            return f"JSON 파싱 실패. 원본 데이터: {raw_text[:500]}"


if __name__ == "__main__":
    app.run()
