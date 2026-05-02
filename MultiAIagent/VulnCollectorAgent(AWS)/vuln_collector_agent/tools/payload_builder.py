import json
import os
import re
import time
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

try:
    from .tooling import tool
except ImportError:
    from tools.tooling import tool

_BASE_DIR = Path(__file__).parent.parent
_PROMPTS_DIR = _BASE_DIR / "prompts"
_NORMALIZER_PROMPT_PATH = _PROMPTS_DIR / "normalizer_system_prompt.txt"
_EVIDENCE_GATE_PROMPT_PATH = _PROMPTS_DIR / "evidence_gate_system_prompt.txt"
_VENDOR_FOLLOWUP_PROMPT_PATH = _PROMPTS_DIR / "vendor_followup_system_prompt.txt"
_DEFAULT_BEDROCK_MODEL = "global.anthropic.claude-haiku-4-5-20251001-v1:0"
_BEDROCK_REGION = os.getenv("BEDROCK_REGION", "ap-northeast-2").strip() or "ap-northeast-2"
_BEDROCK_CLIENT: Any | None = None

_RISK_ASSESSMENT_FIELD_DESCRIPTIONS = {
    "agent": "이 payload를 생성한 주체입니다. risk_assessment는 보안 심각도와 악용 가능성 판단을 담당합니다.",
    "source_dataset": "이 payload를 만드는 데 사용된 입력 데이터셋 이름입니다.",
    "_meta": "사람이나 downstream agent를 위한 읽기 가이드입니다. records만 필요하면 무시해도 됩니다.",
    "record_count": "records 안에 들어 있는 CVE 레코드 수입니다.",
    "records": "CVE별 보안 위험도 평가 레코드 목록입니다.",
}

_RISK_ASSESSMENT_META = {
    "payload_purpose": "각 취약점이 얼마나 위험한지, 왜 위험한지, 그리고 그 판단에 어떤 근거가 사용되었는지를 요약합니다.",
    "recommended_reading_order": [
        "records[].severity",
        "records[].security_domain",
        "records[].risk_signals",
        "records[].analyst_summary",
        "records[].common_consequences",
    ],
    "record_field_guide": {
        "cve_id": "CVE 식별자입니다.",
        "title": "짧은 취약점 제목입니다.",
        "description": "원문 취약점 설명입니다.",
        "cvss": {
            "score": "사용 가능한 경우 CVSS 기본 점수입니다.",
            "vector": "원본 CVSS vector 문자열입니다.",
            "provider": "선택된 CVSS 레코드를 제공한 출처입니다.",
            "vector_details": {
                "version": "CVSS 규격 버전입니다.",
                "attack_vector": "공격이 대상에 도달하는 방식입니다.",
                "attack_complexity": "악용에 특별한 조건이 필요한지 나타냅니다.",
                "privileges_required": "공격자 권한이 필요한지 나타냅니다.",
                "user_interaction": "피해자 상호작용이 필요한지 나타냅니다.",
                "scope": "악용 시 보안 범위가 바뀌는지 나타냅니다.",
                "confidentiality_impact": "예상되는 기밀성 영향입니다.",
                "integrity_impact": "예상되는 무결성 영향입니다.",
                "availability_impact": "예상되는 가용성 영향입니다.",
            },
        },
        "severity": "전체 근거를 바탕으로 AI가 정리한 심각도 구간입니다.",
        "security_domain": "remote-code-execution, memory-corruption 같은 취약점 범주를 정규화한 값입니다.",
        "weaknesses": "이 CVE와 연결된 CWE 식별자 목록입니다.",
        "cwe_names": "사람이 읽기 쉬운 CWE 이름 목록입니다.",
        "risk_signals": {
            "network_exploitable": "직접적인 네트워크 악용 가능성에 대한 판단입니다. 값은 true | false | unknown 이며, 불명확하면 unknown 을 사용합니다.",
            "no_privileges_required": "공격자 권한 필요 여부에 대한 판단입니다. 값은 true | false | unknown 이며, 불명확하면 unknown 을 사용합니다.",
            "no_user_interaction": "피해자 상호작용 필요 여부에 대한 판단입니다. 값은 true | false | unknown 이며, 불명확하면 unknown 을 사용합니다.",
            "attack_complexity": "악용 난이도를 정규화한 요약입니다.",
            "scope": "영향 범위를 정규화한 요약입니다.",
            "exploit_path_summary": "가능한 악용 경로와 전제조건을 평문으로 짧게 요약한 값입니다.",
        },
        "common_consequences": "예상되는 공격자 관점 결과 또는 보안 영향을 요약한 목록입니다.",
        "analyst_summary": "사람이 빠르게 트리아지할 수 있도록 정리한 짧은 보안 요약입니다.",
    },
}

_OPERATIONAL_IMPACT_META = {
    "payload_purpose": "각 취약점의 remediation이 운영에 어떤 영향을 줄 수 있는지, 무엇을 점검하고 어떤 방식으로 배포해야 하는지 요약합니다.",
    "recommended_reading_order": [
        "records[].product_name",
        "records[].fixed_version",
        "records[].patch_type",
        "records[].operational_impacts",
        "records[].dependency_touchpoints",
        "records[].rollout_considerations",
        "records[].validation_focus",
        "records[].mitigation_summaries",
    ],
    "record_field_guide": {
        "cve_id": "CVE 식별자입니다.",
        "title": "짧은 취약점 제목입니다.",
        "product_name": "영향을 받는 제품 또는 라이브러리 이름입니다.",
        "affected_components": "패치 범위에 영향을 주는 컴포넌트나 하위 컴포넌트입니다. 값이 비어 있으면 아예 생략될 수 있습니다.",
        "affected_version_range": "근거에서 도출한 영향 버전 범위입니다. 값이 비어 있으면 아예 생략될 수 있습니다.",
        "fixed_version": "근거상 확인된 첫 수정 버전입니다.",
        "patch_type": "service_upgrade, library_upgrade 같은 조치 유형입니다.",
        "security_domain": "문맥 유지용 보안 범주입니다.",
        "operational_impacts": "부주의한 remediation이 운영에 어떤 장애를 줄 수 있는지 정리한 내용입니다.",
        "dependency_touchpoints": "패치 전 점검해야 할 코드, 패키징, 설정, 런타임, 인프라 접점을 정리한 내용입니다.",
        "code_connectivity_risks": "인접 코드 경로나 런타임 연결이 blast radius를 어떻게 넓힐 수 있는지 설명합니다.",
        "rollout_considerations": "운영 중단을 줄이고 rollback 가능성을 보존하기 위한 배포 고려사항입니다.",
        "validation_focus": "패치 전후 우선 확인해야 할 검증 항목입니다.",
        "mitigation_summaries": "짧고 행동 지향적인 조치 요약입니다.",
        "vendor_specific_guidance": "필요할 때만 담기는 vendor-specific 운영 가이드입니다.",
        "notes": "운영적으로 의미 있는 짧은 메모입니다.",
    },
}

_OPERATIONAL_IMPACT_FIELD_DESCRIPTIONS = {
    "agent": "이 payload를 생성한 주체입니다. operational_impact는 패치, 의존성, rollout, 검증 판단을 담당합니다.",
    "source_dataset": "이 payload를 만드는 데 사용된 입력 데이터셋 이름입니다.",
    "_meta": "사람이나 downstream agent를 위한 읽기 가이드입니다. records만 필요하면 무시해도 됩니다.",
    "record_count": "records 안에 들어 있는 CVE 레코드 수입니다.",
    "records": "CVE별 운영 영향 평가 레코드 목록입니다.",
}


class RiskSignals(BaseModel):
    network_exploitable: str = "unknown"
    no_privileges_required: str = "unknown"
    no_user_interaction: str = "unknown"
    attack_complexity: str = "unknown"
    scope: str = "unknown"
    exploit_path_summary: str = "unknown"

    @model_validator(mode="before")
    @classmethod
    def _coerce_input(cls, value: Any) -> Any:
        if isinstance(value, list):
            summary = " ".join(str(item).strip() for item in value if str(item).strip())
            return {"exploit_path_summary": summary or "unknown"}
        if isinstance(value, str):
            return {"exploit_path_summary": value.strip() or "unknown"}
        return value

    @field_validator(
        "network_exploitable",
        "no_privileges_required",
        "no_user_interaction",
        mode="before",
    )
    @classmethod
    def _coerce_tri_state(cls, value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        text = str(value or "").strip().lower()
        if text in {"true", "false", "unknown"}:
            return text
        if text in {"yes", "y"}:
            return "true"
        if text in {"no", "n"}:
            return "false"
        return "unknown"


class RiskPayload(BaseModel):
    severity: str = "unknown"
    security_domain: str = "unknown"
    risk_signals: RiskSignals = Field(default_factory=RiskSignals)
    common_consequences: list[str] = Field(default_factory=list)
    analyst_summary: str = "unknown"

    @field_validator("common_consequences", mode="before")
    @classmethod
    def _coerce_common_consequences(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            text = value.strip()
            return [text] if text else []
        return value


class OperationalPayload(BaseModel):
    product_name: str = "unknown"
    affected_components: list[str] = Field(default_factory=list)
    affected_version_range: list[str] = Field(default_factory=list)
    fixed_version: str = "unknown"
    patch_type: str = "unknown"
    security_domain: str = "unknown"
    operational_impacts: list[str] = Field(default_factory=list)
    dependency_touchpoints: list[str] = Field(default_factory=list)
    code_connectivity_risks: list[str] = Field(default_factory=list)
    rollout_considerations: list[str] = Field(default_factory=list)
    validation_focus: list[str] = Field(default_factory=list)
    mitigation_summaries: list[str] = Field(default_factory=list)
    vendor_specific_guidance: list[str] = Field(default_factory=list)
    notes: str = "unknown"

    @field_validator("notes", mode="before")
    @classmethod
    def _coerce_notes(cls, value: Any) -> Any:
        if value is None:
            return "unknown"
        if isinstance(value, list):
            parts = [str(item).strip() for item in value if str(item).strip()]
            return " ".join(parts) if parts else "unknown"
        return value

    @field_validator(
        "affected_components",
        "affected_version_range",
        "operational_impacts",
        "dependency_touchpoints",
        "code_connectivity_risks",
        "rollout_considerations",
        "validation_focus",
        "mitigation_summaries",
        "vendor_specific_guidance",
        mode="before",
    )
    @classmethod
    def _coerce_list_fields(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            text = value.strip()
            return [text] if text else []
        if isinstance(value, dict):
            preferred = value.get("url") or value.get("title") or value.get("name")
            if preferred:
                return [str(preferred).strip()]
            return [json.dumps(value, ensure_ascii=False)]
        if isinstance(value, list):
            normalized: list[str] = []
            for item in value:
                if item is None:
                    continue
                if isinstance(item, str):
                    text = item.strip()
                    if text:
                        normalized.append(text)
                    continue
                if isinstance(item, dict):
                    preferred = item.get("url") or item.get("title") or item.get("name")
                    if preferred:
                        normalized.append(str(preferred).strip())
                    else:
                        normalized.append(json.dumps(item, ensure_ascii=False))
                    continue
                text = str(item).strip()
                if text:
                    normalized.append(text)
            return normalized
        return value


class VulnerabilityPayloadBundle(BaseModel):
    risk_payload: RiskPayload = Field(validation_alias="risk_assessment")
    operational_payload: OperationalPayload = Field(validation_alias="operational_impact")


class OperationalEvidenceDecision(BaseModel):
    collect_operational_evidence: bool = False
    confidence: str = "unknown"
    rationale: str = "unknown"
    evidence_targets: list[str] = Field(default_factory=list)


class VendorFollowupDecision(BaseModel):
    investigate_vendor_context: bool = False
    confidence: str = "unknown"
    rationale: str = "unknown"
    vendor_domains: list[str] = Field(default_factory=list)
    vendor_urls: list[str] = Field(default_factory=list)


_ANALYSIS_CACHE: dict[str, VulnerabilityPayloadBundle] = {}
_EVIDENCE_DECISION_CACHE: dict[str, OperationalEvidenceDecision] = {}
_VENDOR_FOLLOWUP_DECISION_CACHE: dict[str, VendorFollowupDecision] = {}

TModel = TypeVar("TModel", bound=BaseModel)


@tool
def load_collected_records(input_path: str = "data/focused_selected_raw_cves.json") -> dict:
    path = _BASE_DIR / input_path
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


MAX_RETRIES = 3
RETRY_DELAY = 5


def _bedrock_model_id() -> str:
    return (os.getenv("BEDROCK_MODEL_ID") or _DEFAULT_BEDROCK_MODEL).strip()


def _load_normalizer_prompt() -> str:
    return _NORMALIZER_PROMPT_PATH.read_text(encoding="utf-8").strip()


def _load_evidence_gate_prompt() -> str:
    return _EVIDENCE_GATE_PROMPT_PATH.read_text(encoding="utf-8").strip()


def _load_vendor_followup_prompt() -> str:
    return _VENDOR_FOLLOWUP_PROMPT_PATH.read_text(encoding="utf-8").strip()


def _extract_json_blob(text: str) -> Any:
    text = text.strip()
    if not text:
        raise ValueError("LLM response was empty")

    fence_match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for idx, ch in enumerate(text):
        if ch not in '[{':
            continue
        try:
            parsed, _ = decoder.raw_decode(text[idx:])
            return parsed
        except json.JSONDecodeError:
            continue
    raise ValueError("LLM JSON response could not be parsed")


def _bedrock_runtime_client() -> Any:
    global _BEDROCK_CLIENT
    if _BEDROCK_CLIENT is None:
        _BEDROCK_CLIENT = boto3.client(
            "bedrock-runtime",
            region_name=_BEDROCK_REGION,
            config=Config(read_timeout=600, connect_timeout=10),
        )
    return _BEDROCK_CLIENT


def _extract_bedrock_text(response: dict[str, Any]) -> str:
    message = response.get("output", {}).get("message", {})
    contents = message.get("content", []) if isinstance(message, dict) else []
    chunks: list[str] = []
    for item in contents:
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        if isinstance(text, str) and text.strip():
            chunks.append(text.strip())
    return "\n".join(chunks).strip()


def _generate_response(instructions: str, prompt: str) -> str:
    last_exc: Exception | None = None
    candidates = [_bedrock_model_id()]
    for model_name in candidates:
        for attempt in range(MAX_RETRIES):
            try:
                response = _bedrock_runtime_client().converse(
                    modelId=model_name,
                    system=[{"text": instructions}],
                    messages=[
                        {
                            "role": "user",
                            "content": [{"text": prompt}],
                        }
                    ],
                    inferenceConfig={"temperature": 0},
                )
                output_text = _extract_bedrock_text(response)
                if not output_text:
                    raise RuntimeError("Bedrock response text was empty")
                return output_text
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                message = str(exc)
                transient = any(
                    token in message
                    for token in ("429", "500", "502", "503", "timeout", "Timeout", "Throttling")
                )
                if transient and attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                    continue
                if transient:
                    break
                raise
    raise RuntimeError(f"All model attempts failed: {last_exc}")


def _call_llm_model(system_prompt: str, prompt: str, model_type: type[TModel]) -> TModel:
    output_text = _generate_response(system_prompt, prompt)
    payload = _extract_json_blob(output_text)
    try:
        return model_type.model_validate(payload)
    except ValidationError as exc:
        raise RuntimeError(f"Structured output validation failed for {model_type.__name__}: {exc}") from exc


def _cpe_criteria(record: dict) -> list[str]:
    collected = []

    def walk(value) -> None:
        if isinstance(value, dict):
            for key in ("cpeMatch", "cpe_match"):
                items = value.get(key)
                if isinstance(items, list):
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        criteria = item.get("criteria") or item.get("cpe23Uri")
                        if isinstance(criteria, str) and criteria not in collected:
                            collected.append(criteria)

            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(record.get("nvd_cpe_configurations") or [])
    return collected


def _cwe_names(record: dict) -> list[str]:
    names = []
    for item in record.get("cwe_details", []):
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str) and name and name not in names:
            names.append(name)
    return names


def _cvss_detail_string(record: dict, field_name: str) -> str:
    cvss = record.get("cvss") if isinstance(record.get("cvss"), dict) else {}
    vector_details = cvss.get("vector_details") if isinstance(cvss.get("vector_details"), dict) else {}
    value = str(vector_details.get(field_name) or "").strip().lower()
    return value or "unknown"


def _fallback_common_consequences(record: dict) -> list[str]:
    consequences: list[str] = []

    def add(value: str) -> None:
        text = value.strip()
        if text and text not in consequences:
            consequences.append(text)

    description = f"{record.get('title') or ''} {record.get('description') or ''}".lower()
    if "arbitrary code execution" in description or "execute arbitrary code" in description:
        add("임의 코드 실행")
    if any(token in description for token in ("crash", "denial of service", "service disruption")):
        add("서비스 장애 또는 프로세스 충돌")
    if any(token in description for token in ("memory overwrite", "memory corruption")):
        add("메모리 손상")
    if any(token in description for token in ("information disclosure", "confidentiality")):
        add("민감 정보 노출")

    for cwe_detail in record.get("cwe_details", []) if isinstance(record.get("cwe_details"), list) else []:
        if not isinstance(cwe_detail, dict):
            continue
        for consequence in cwe_detail.get("common_consequences", []) if isinstance(cwe_detail.get("common_consequences"), list) else []:
            if not isinstance(consequence, dict):
                continue
            impacts = consequence.get("impact", []) if isinstance(consequence.get("impact"), list) else []
            for impact in impacts:
                impact_text = str(impact).strip()
                lowered = impact_text.lower()
                if "execute unauthorized code" in lowered:
                    add("임의 코드 실행")
                elif "dos" in lowered or "crash" in lowered or "instability" in lowered:
                    add("서비스 장애 또는 프로세스 충돌")
                elif "modify memory" in lowered or "memory" in lowered:
                    add("메모리 손상")
                elif "bypass protection mechanism" in lowered:
                    add("보호 메커니즘 우회")
                elif "confidentiality" in lowered or "information disclosure" in lowered:
                    add("민감 정보 노출")

    return consequences[:4]


def _merged_risk_signals(record: dict, risk: RiskPayload) -> dict[str, Any]:
    signals = risk.risk_signals.model_dump()
    if str(signals.get("attack_complexity") or "").strip().lower() == "unknown":
        signals["attack_complexity"] = _cvss_detail_string(record, "attack_complexity")
    if str(signals.get("scope") or "").strip().lower() == "unknown":
        signals["scope"] = _cvss_detail_string(record, "scope")
    return signals


def _upstream_identity_tokens(record: dict) -> list[str]:
    title = (record.get("title") or "").split(":", 1)[0]
    raw_tokens = [token.lower() for token in title.replace("/", " ").replace("-", " ").split()]
    tokens = []
    ignored = {"and", "the", "for", "with", "does", "not", "when", "used", "features"}

    for token in raw_tokens:
        normalized = "".join(ch for ch in token if ch.isalnum())
        if len(normalized) < 3 or normalized in ignored:
            continue
        if normalized not in tokens:
            tokens.append(normalized)

    if tokens:
        return tokens

    for criteria in _cpe_criteria(record):
        parts = criteria.split(":")
        for index in (3, 4):
            if len(parts) <= index:
                continue
            token = "".join(ch for ch in parts[index].lower() if ch.isalnum())
            if len(token) >= 3 and token not in tokens:
                tokens.append(token)

    return tokens


def _upstream_vendor_previews(record: dict) -> list[dict]:
    operational_evidence = record.get("operational_evidence") or {}
    nvd_context = operational_evidence.get("nvd_context") or {}
    previews = [
        preview for preview in (nvd_context.get("vendor_advisories") or [])
        if isinstance(preview, dict)
    ]
    if not previews:
        return []

    tokens = _upstream_identity_tokens(record)
    if not tokens:
        return previews

    matched = []
    for preview in previews:
        domain = urlparse(preview.get("url") or "").netloc.lower()
        if any(token in domain for token in tokens):
            matched.append(preview)

    return matched or previews


def _enforce_upstream_vendor_followup(record: dict, decision: VendorFollowupDecision) -> VendorFollowupDecision:
    if not decision.investigate_vendor_context:
        return decision

    upstream_previews = _upstream_vendor_previews(record)
    upstream_urls: list[str] = []
    for preview in upstream_previews:
        url = preview.get("url")
        if isinstance(url, str) and url:
            upstream_urls.append(url)

    if not upstream_urls:
        return decision

    filtered_urls: list[str] = [url for url in decision.vendor_urls if url in upstream_urls]
    if not filtered_urls:
        filtered_urls = upstream_urls[:2]

    filtered_domains: list[str] = []
    for url in filtered_urls:
        domain = urlparse(url).netloc
        if domain and domain not in filtered_domains:
            filtered_domains.append(domain)

    rationale = decision.rationale
    if filtered_urls != decision.vendor_urls:
        rationale = f"{decision.rationale} Upstream maintainer guidance was prioritized over downstream ecosystem pages."

    return VendorFollowupDecision(
        investigate_vendor_context=True,
        confidence=decision.confidence,
        rationale=rationale,
        vendor_domains=filtered_domains,
        vendor_urls=filtered_urls,
    )


def _drop_empty_selected_fields(payload: dict, field_names: list[str]) -> dict:
    compact = dict(payload)
    for field_name in field_names:
        value = compact.get(field_name)
        if isinstance(value, list) and not value:
            compact.pop(field_name, None)
    return compact


def _record_prompt(record: dict) -> str:
    pretty_record = json.dumps(record, ensure_ascii=False, indent=2)
    return (
        "Analyze the following collected CVE record and return the structured vulnerability payload bundle.\n\n"
        f"{pretty_record}"
    )


def _evidence_gate_prompt(record: dict) -> str:
    pretty_record = json.dumps(record, ensure_ascii=False, indent=2)
    return (
        "Decide whether the following collected CVE record needs extra operational remediation evidence before final synthesis.\n\n"
        f"{pretty_record}"
    )


def _vendor_followup_prompt(record: dict) -> str:
    pretty_record = json.dumps(record, ensure_ascii=False, indent=2)
    return (
        "Decide whether the following collected CVE record needs deeper vendor-specific downstream investigation. "
        "If yes, choose only vendor advisory URLs already present in the record.\n\n"
        f"{pretty_record}"
    )


@tool
def decide_operational_evidence_requirement(record: dict) -> dict:
    cve_id = record.get("cve_id") or "unknown"
    cached = _EVIDENCE_DECISION_CACHE.get(cve_id)
    if cached is not None:
        return cached.model_dump()

    structured_output = _call_llm_model(
        _load_evidence_gate_prompt(),
        _evidence_gate_prompt(record),
        OperationalEvidenceDecision,
    )

    _EVIDENCE_DECISION_CACHE[cve_id] = structured_output
    return structured_output.model_dump()


@tool
def decide_vendor_followup_requirement(record: dict) -> dict:
    cve_id = record.get("cve_id") or "unknown"
    cached = _VENDOR_FOLLOWUP_DECISION_CACHE.get(cve_id)
    if cached is not None:
        return cached.model_dump()

    operational_evidence = record.get("operational_evidence") or {}
    nvd_context = operational_evidence.get("nvd_context") or {}
    if not nvd_context.get("vendor_advisories"):
        result = VendorFollowupDecision(
            investigate_vendor_context=False,
            confidence="high",
            rationale="No vendor advisory previews are available to support controlled downstream follow-up.",
            vendor_domains=[],
            vendor_urls=[],
        )
        _VENDOR_FOLLOWUP_DECISION_CACHE[cve_id] = result
        return result.model_dump()

    structured_output = _call_llm_model(
        _load_vendor_followup_prompt(),
        _vendor_followup_prompt(record),
        VendorFollowupDecision,
    )

    structured_output = _enforce_upstream_vendor_followup(record, structured_output)
    _VENDOR_FOLLOWUP_DECISION_CACHE[cve_id] = structured_output
    return structured_output.model_dump()


def _normalize_record_with_agent(record: dict) -> VulnerabilityPayloadBundle:
    cve_id = record.get("cve_id") or "unknown"
    cached = _ANALYSIS_CACHE.get(cve_id)
    if cached is not None:
        return cached

    structured_output = _call_llm_model(
        _load_normalizer_prompt(),
        _record_prompt(record),
        VulnerabilityPayloadBundle,
    )

    bundle = structured_output
    _ANALYSIS_CACHE[cve_id] = bundle
    return bundle


def _normalized_records(dataset: dict) -> list[VulnerabilityPayloadBundle]:
    return [
        _normalize_record_with_agent(record)
        for record in dataset.get("records", [])
        if isinstance(record, dict)
    ]


@tool
def build_risk_assessment_payloads(dataset: dict) -> dict:
    normalized_records = _normalized_records(dataset)
    records = []

    for record, normalized in zip(dataset.get("records", []), normalized_records):
        risk = normalized.risk_payload
        common_consequences = risk.common_consequences or _fallback_common_consequences(record)
        records.append({
            "cve_id": record.get("cve_id"),
            "title": record.get("title"),
            "description": record.get("description"),
            "cvss": record.get("cvss") or {},
            "severity": risk.severity,
            "security_domain": risk.security_domain,
            "weaknesses": record.get("weaknesses", []),
            "cwe_names": _cwe_names(record),
            "risk_signals": _merged_risk_signals(record, risk),
            "common_consequences": common_consequences,
            "analyst_summary": risk.analyst_summary,
        })

    return {
        "agent": "risk_assessment",
        "source_dataset": "focused_selected_raw_cves.json",
        "field_descriptions": _RISK_ASSESSMENT_FIELD_DESCRIPTIONS,
        "_meta": _RISK_ASSESSMENT_META,
        "record_count": len(records),
        "records": records,
    }


@tool
def build_operational_impact_payloads(dataset: dict) -> dict:
    normalized_records = _normalized_records(dataset)
    records = []

    for record, normalized in zip(dataset.get("records", []), normalized_records):
        operational = normalized.operational_payload
        payload_record = {
            "cve_id": record.get("cve_id"),
            "title": record.get("title"),
            "product_name": operational.product_name,
            "affected_components": operational.affected_components,
            "affected_version_range": operational.affected_version_range,
            "fixed_version": operational.fixed_version,
            "patch_type": operational.patch_type,
            "security_domain": operational.security_domain,
            "operational_impacts": operational.operational_impacts,
            "dependency_touchpoints": operational.dependency_touchpoints,
            "code_connectivity_risks": operational.code_connectivity_risks,
            "rollout_considerations": operational.rollout_considerations,
            "validation_focus": operational.validation_focus,
            "mitigation_summaries": operational.mitigation_summaries,
            "vendor_specific_guidance": operational.vendor_specific_guidance,
            "notes": operational.notes,
        }
        records.append(_drop_empty_selected_fields(
            payload_record,
            ["affected_components", "affected_version_range"],
        ))

    return {
        "agent": "operational_impact",
        "source_dataset": "focused_selected_raw_cves.json",
        "field_descriptions": _OPERATIONAL_IMPACT_FIELD_DESCRIPTIONS,
        "_meta": _OPERATIONAL_IMPACT_META,
        "record_count": len(records),
        "records": records,
    }
