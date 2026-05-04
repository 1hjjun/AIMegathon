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
    "global.anthropic.claude-sonnet-4-6",
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
    "query_log": [],   # swarm 호출 기록
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
    base_cvss: Optional[float] = Field(default=None, description="CVE 기본 CVSS 점수")
    calculated_risk: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW 중 하나")
    exposure_level: str = Field(description="Public 또는 Internal")
    mitigations_found: List[str] = Field(default_factory=list, description="적용된 완화 조치 목록")
    risk_adjustment_reason: str = Field(description="기본 CVSS 대비 위험도 조정 근거")
    remediation: str = Field(description="보안 권고 조치 사항")


class FinalReport(BaseModel):
    cve_id: str = Field(description="분석 대상 취약점 번호")
    title: str = Field(description="취약점 명칭")
    impacted_assets: List[ImpactedAsset] = Field(description="영향을 받는 자산 리스트")


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


def _raw_query(instance_id: str, asset: dict, question: str, query_type: str) -> dict:
    """asset_matching 직접 호출 — query_log 에 기록하고 결과 반환."""
    _runtime_state["query_log"].append({
        "instance_id": instance_id,
        "question": question,
        "type": query_type,
    })
    body = _invoke_asset_matching({
        "mode": "query",
        "asset_info": asset,
        "instance_id": instance_id,
        "question": question,
        "region": _runtime_state.get("region", DEFAULT_REGION),
    })
    if "error" in body:
        _runtime_state["query_log"][-1]["error"] = body["error"]
        return {"answer": f"[ERROR] {body['error']}", "confidence": "none", "evidence": []}
    answer = body.get("answer", "")
    confidence = body.get("confidence", "")
    evidence = body.get("evidence", [])
    _runtime_state["query_log"][-1].update({"answer": answer[:200], "confidence": confidence})
    return {"answer": answer, "confidence": confidence, "evidence": evidence}


# CVE 별 mitigation 질문 (combined query 구성용)
_CVE_MITIGATION_QUESTIONS: dict = {
    "CVE-2021-44228": "log4j2.formatMsgNoLookups=true 설정 적용 여부 또는 JndiLookup 클래스 jar 제거 여부",
    "CVE-2021-23017": "nginx resolver 지시문 활성화 여부 및 실제 DNS 쿼리 처리 여부",
}

# CVE 가 영향을 미치는 소프트웨어 키워드 (tier 스킵 판단용)
_CVE_AFFECTED_SOFTWARE: dict = {
    "CVE-2021-44228": ["log4j"],
    "CVE-2021-23017": ["nginx"],
}


def _tier_relevant_cves(asset: dict, vuln_list: list) -> list[str]:
    """해당 asset 의 installed_software 와 CVE 영향 소프트웨어를 대조, 관련 CVE ID 목록 반환."""
    installed = {
        (sw.get("name") or sw.get("product") or "").lower()
        for sw in asset.get("installed_software", [])
    }
    relevant = []
    for vuln in vuln_list:
        cve_id = vuln.get("cve_id", "")
        keywords = _CVE_AFFECTED_SOFTWARE.get(cve_id, [])
        if any(kw in name for kw in keywords for name in installed):
            relevant.append(cve_id)
    return relevant


def _prefetch_evidence(vuln_list: list) -> dict:
    """tier 대표 인스턴스당 1회 combined query 로 모든 필요 정보를 한꺼번에 수집.

    - 취약 소프트웨어가 없는 tier 는 스킵
    - tier 당 호출 1회 (mitigation + root + exposure 를 단일 질문으로 묶음)

    반환값:
        {
            tier_name: {
                "instance_id": "i-xxx",
                "relevant_cves": ["CVE-..."],
                "answer": "combined answer text",
                "confidence": "high|medium|low",
            }
        }
    """
    infra = _runtime_state.get("infra_context") or {}
    all_assets = infra.get("assets", [])
    if not all_assets or not _runtime_state.get("asset_matching_arn"):
        return {}

    tier_rep: dict = {}
    for asset in all_assets:
        tier = asset.get("tier") or "unknown"
        if tier not in tier_rep:
            tier_rep[tier] = asset

    result: dict = {}
    for tier, asset in tier_rep.items():
        instance_id = asset.get("asset_id")
        if not instance_id:
            continue

        relevant_cves = _tier_relevant_cves(asset, vuln_list)
        if not relevant_cves:
            continue  # 이 tier 에는 취약 소프트웨어 없음 — 스킵

        # 취약 CVE 별 mitigation 항목 조합
        mitigation_items = "\n".join(
            f"  - [{cve_id}] {_CVE_MITIGATION_QUESTIONS.get(cve_id, '완화 조치 적용 여부')}"
            for cve_id in relevant_cves
        )

        combined_question = (
            "아래 3가지를 한번에 답해주세요.\n\n"
            f"[1] 취약점별 완화 조치(mitigation) 적용 여부:\n{mitigation_items}\n\n"
            "[2] 취약 프로세스(java, nginx, apache 등)가 root 권한(UID 0)으로 실행 중입니까?\n\n"
            "[3] 이 인스턴스에 public IP 가 할당되어 있거나 public subnet 에 위치합니까?"
        )

        response = _raw_query(instance_id, asset, combined_question, "combined_security_check")
        result[tier] = {
            "instance_id": instance_id,
            "relevant_cves": relevant_cves,
            "answer": response.get("answer", ""),
            "confidence": response.get("confidence", ""),
        }

    return result


def _format_evidence_block(evidence: dict) -> str:
    """pre-fetch 결과를 프롬프트에 삽입할 텍스트로 변환."""
    if not evidence:
        return "(사전 조사 결과 없음 — asset_matching_arn 미설정 또는 취약 소프트웨어 없음)"

    lines = []
    for tier, info in evidence.items():
        lines.append(
            f"  [tier={tier} | 대표={info['instance_id']} | 관련CVE={info['relevant_cves']}]"
        )
        lines.append(f"    조사 결과 (신뢰도: {info.get('confidence', '?')}):")
        for line in info.get("answer", "").splitlines():
            lines.append(f"      {line}")
    return "\n".join(lines)


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
    _runtime_state["query_log"].append({"instance_id": instance_id, "question": question})

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
    # 결과를 query_log 에 기록
    _runtime_state["query_log"][-1].update({"answer": answer[:200], "confidence": confidence})
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

    # 4) 사전 증거 수집 — LLM 이 추론하지 않도록 Python 이 직접 조사
    _runtime_state["query_log"] = []
    prefetch_evidence = _prefetch_evidence(vuln_list)
    evidence_block = _format_evidence_block(prefetch_evidence)

    # 5) 프롬프트 구성
    user_message = f"""
다음 취약점과 자산 목록을 분석하여 누락 없이 전수 위험도 리포트를 작성하십시오.

[참조 데이터]
- 취약점 목록   : {json.dumps(vuln_list, ensure_ascii=False)}
- 자산 목록     : {json.dumps(asset_info, ensure_ascii=False)}

# 사전 수집된 실측 증거 (asset_matching 에이전트가 실제 인스턴스를 조사한 결과)
아래 데이터는 추론이 아닌 실제 조사 결과입니다. 반드시 이 데이터를 우선 사용하십시오.
같은 tier 내 다른 인스턴스에는 대표 인스턴스의 조사 결과를 동일하게 적용하십시오.

{evidence_block}

# STEP 1 — 취약 자산 식별
각 CVE 가 영향을 미치는 소프트웨어를 자산 목록의 installed_software 와 대조하여 취약 인스턴스를 찾으십시오.

# STEP 2 — 위험도 결정 (위의 사전 수집 증거 사용)
위에서 사전 수집한 실측 증거를 기반으로 아래 규칙을 적용하십시오.
추가로 불명확한 사항이 있으면 query_asset_details 도구로 추가 조사할 수 있습니다.

mitigation 적용 여부 해석:
- "적용됨" / "yes" / "설정 확인됨" → mitigations_found 에 기록, risk 2단계 하향
- "미적용" / "no" / "확인 안됨"   → mitigations_found = [], risk 유지

root_process 해석:
- "root 실행" / "yes"   → risk 유지 또는 상향
- "non-root" / "no"     → risk 1단계 하향

exposure 해석:
- "공인 IP" / "public"  → exposure_level = "Public"
- "내부망" / "private"  → exposure_level = "Internal", risk 1단계 하향 가능

# STEP 3 — 최종 위험도 결정 규칙
| 조건                                         | 조정           |
|----------------------------------------------|----------------|
| mitigation 적용됨                            | -2단계         |
| non-root 실행                                | -1단계         |
| 내부망(Internal)                             | -1단계         |
| mitigation 미적용 + root + 인터넷 노출       | 기준점 유지    |
단계 순서: CRITICAL → HIGH → MEDIUM → LOW

# OUTPUT FORMAT (STRICT JSON ARRAY ONLY)
[
  {{
    "cve_id": "CVE-XXXX-XXXXX",
    "title": "취약점 명칭",
    "impacted_assets": [
      {{
        "instance_id": "i-xxxxxxxxxxxxxxxxx",
        "base_cvss": 10.0,
        "calculated_risk": "CRITICAL | HIGH | MEDIUM | LOW",
        "exposure_level": "Public | Internal",
        "mitigations_found": ["적용된 완화조치 목록, 없으면 빈 배열"],
        "risk_adjustment_reason": "사전 수집 증거 기반: mitigation 미적용 + root 실행으로 CRITICAL 유지",
        "remediation": "권고 조치"
      }}
    ]
  }}
]

RESPONSE MUST BE A SINGLE JSON ARRAY ONLY. NO TEXT OUTSIDE THE JSON. NO LINE BREAKS INSIDE VALUES.
"""

    # 6) Agent 실행 (도구: query_asset_details — 추가 조사용, finalize_report)
    _runtime_state["final_report"] = None

    system_prompt = (
        "당신은 CVE 취약점 지식을 보유한 보안 위험도 평가 전문가입니다. "
        "프롬프트에 '사전 수집된 실측 증거' 블록이 제공됩니다. "
        "이 데이터는 추론이 아닌 실제 인스턴스 조사 결과이므로 반드시 우선 사용하십시오. "
        "추가 조사가 필요하면 query_asset_details 도구를 활용할 수 있습니다."
    )
    agent = Agent(model=BEDROCK_MODEL_ID, system_prompt=system_prompt)
    result = agent(user_message, tools=[query_asset_details, finalize_report])

    query_log = _runtime_state.get("query_log", [])

    # 6) 결과 파싱 — finalize_report 호출 결과 우선, 없으면 텍스트에서 파싱
    if _runtime_state["final_report"] is not None:
        out = _runtime_state["final_report"]
        if isinstance(out, list):
            out = {"risk_report": out, "swarm_queries": query_log}
        return json.dumps(out, indent=4, ensure_ascii=False)

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
        return json.dumps({"risk_report": final_data, "swarm_queries": query_log}, indent=4, ensure_ascii=False)
    except Exception:
        try:
            clean_text = re.sub(r"\s+", " ", raw_text)
            fixed_data = json.loads(clean_text)
            return json.dumps({"risk_report": fixed_data, "swarm_queries": query_log}, indent=4, ensure_ascii=False)
        except Exception:
            return f"JSON 파싱 실패. 원본 데이터: {raw_text[:500]}"


if __name__ == "__main__":
    app.run()