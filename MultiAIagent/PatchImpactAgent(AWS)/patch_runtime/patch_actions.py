from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union


AGENT_ROOT = Path(__file__).resolve().parent
OUTPUT_RESULT_DIR = AGENT_ROOT.parent / "OutputResult"
RESULT_DIR = OUTPUT_RESULT_DIR / "PatchImAgent"
STAGE1_RESULT_DIR = RESULT_DIR / "stage1_prejudge"
STAGE2_RESULT_DIR = RESULT_DIR / "stage2_followup"

DEFAULT_RISK_PATH = OUTPUT_RESULT_DIR / "RiskevalAgent" / "risk_evaluation_result.json"
DEFAULT_INFRA_PATH = OUTPUT_RESULT_DIR / "AssetAgent" / "infra_context.json"
DEFAULT_OPERATIONAL_PATH = OUTPUT_RESULT_DIR / "VulAgent" / "operational_impact_payloads.json"
PATCH_IMPACT_RESULT_PATH = STAGE1_RESULT_DIR / "patch_impact_prejudge_result.json"
ADDITIONAL_ASSET_REQUEST_PATH = STAGE2_RESULT_DIR / "additional_asset_request.json"
DEFAULT_FOLLOWUP_CONTEXT_PATH = OUTPUT_RESULT_DIR / "SwarmAgent" / "additional_asset_response.json"

DEFAULT_BEDROCK_MODEL = (
    os.environ.get("PATCH_IMPACT_BEDROCK_MODEL")
    or os.environ.get("BEDROCK_MODEL_ID")
    or "global.anthropic.claude-haiku-4-5-20251001-v1:0"
)
MAX_RETRIES = 3
RETRY_DELAY = 5

JSONDict = dict[str, Any]


FIELD_DESCRIPTIONS = {
    "overall_dependency_operational_impact": "해당 CVE를 전체적으로 봤을 때 패치 적용의 운영 영향도를 요약한 1차 값입니다.",
    "dependency": "취약 소프트웨어가 다른 코드, 라이브러리, 서비스, 인프라 구성요소와 얼마나 강하게 연결되어 있는지에 대한 1차 판단입니다.",
    "dependency_reason": "dependency 값을 그렇게 판단한 이유입니다.",
    "dependency_impact": "해당 패치를 적용했을 때 운영 서비스에 미치는 영향도에 대한 1차 판단입니다.",
    "dependency_impact_reason": "dependency_impact 값을 그렇게 판단한 이유입니다.",
    "dependency_operational_impact": "기존 호환용 필드입니다. 현재는 dependency_impact 와 같은 의미의 1차 값으로 취급합니다.",
    "reasoning_summary": "왜 그런 1차 판단을 했는지에 대한 짧은 한국어 설명입니다. dependency_reason 또는 dependency_impact_reason 의 요약값으로도 사용됩니다.",
    "missing_information": "신뢰도 있는 패치 판단을 위해 아직 부족한 사실 정보입니다.",
    "action_plan_direction": "운영 영향과 의존성을 종합해 권장하는 큰 조치 방향입니다. manual_approval | auto_update | wait_for_maintenance 중 하나입니다.",
    "estimated_downtime": "예상 다운타임입니다. 추정이 어렵다면 unknown 으로 둡니다.",
    "os_reboot_required": "패치 완료를 위해 OS 재부팅이 필요한지 여부입니다.",
    "data_loss_risk": "패치 과정에서 데이터베이스나 중요 로그 유실 위험이 있는지 여부입니다.",
    "config_overwrite_risk": "패치 과정에서 설정 파일 유실 또는 덮어쓰기 위험이 있는지 여부입니다.",
    "rollback_complexity": "패치 실패 시 이전 상태로 되돌리는 복잡도입니다.",
    "requires_rolling_update": "서비스 중단 최소화를 위해 순차 업데이트가 필요한지 여부입니다.",
    "maintenance_window_time": "유지보수 시간에만 수행해야 할 경우 그 시간 정보입니다.",
    "action": "운영 피해를 최소화하기 위해 실제로 무엇을 어떻게 해야 하는지에 대한 1차 결론입니다.",
    "recommended_action": "현재 증거만 봤을 때 우선 시도해볼 만한 1차 조치 방향입니다.",
    "needs_additional_asset_context": "현재 증거가 부족해 asset agent follow-up 이 필요한지 여부입니다.",
    "additional_asset_questions": "추가 확인이 필요할 때 asset agent 에게 보내야 하는 구체적 질문 목록입니다.",
    "llm_handoff_prompt": "asset agent follow-up 요청에 바로 넘길 수 있는 handoff 프롬프트입니다.",
}


SELECTION_CRITERIA = {
    "overall_dependency_operational_impact": {
        "none": "패치가 운영 흐름에 사실상 영향을 주지 않으며 연계 요소도 거의 없습니다.",
        "low": "운영 영향이 작고 우회 가능하며 핵심 기능 중단 가능성이 낮습니다.",
        "medium": "일부 중요 기능 저하나 제한적 서비스 영향이 예상됩니다.",
        "high": "핵심 기능 중단, 서비스 전반 장애, 사용자 영향 확대 가능성이 큽니다.",
        "unknown": "현재 정보만으로 운영 영향도를 신뢰성 있게 판단하기 어렵습니다.",
    },
    "dependency": {
        "none": "취약 소프트웨어가 독립적으로 존재하며 다른 서비스, 코드, 인프라와의 연결이 사실상 확인되지 않습니다.",
        "low": "연결은 있으나 영향 범위가 작고 대체 경로나 우회 수단이 있습니다.",
        "medium": "여러 구성요소와 연결되어 있으며 패치 시 일부 기능이나 연계 서비스 확인이 필요합니다.",
        "high": "핵심 서비스, 공용 라이브러리, 주요 인프라 흐름과 강하게 연결되어 있어 영향 전파 가능성이 큽니다.",
        "unknown": "현재 정보만으로 실제 연결 구조를 확인하기 어렵습니다.",
    },
    "dependency_impact": {
        "none": "패치 적용 후 운영 기능 영향이 사실상 없습니다.",
        "low": "사소한 기능 저하나 짧은 순간 영향만 예상됩니다.",
        "medium": "일부 기능 제한, 서비스 재기동, 연계 서비스 확인이 필요합니다.",
        "high": "핵심 기능 중단, 전체 서비스 장애, 강한 연계 영향 가능성이 큽니다.",
        "unknown": "현재 정보만으로 패치 영향 범위를 판단하기 어렵습니다.",
    },
    "action_plan_direction": {
        "auto_update": "영향과 불확실성이 낮아 검증 후 비교적 바로 진행 가능한 경우입니다.",
        "manual_approval": "운영 영향이 크거나 불확실성이 남아 있어 담당자 검토가 필요한 경우입니다.",
        "wait_for_maintenance": "즉시 반영보다 유지보수 시간 확보 후 계획적으로 반영하는 것이 적절한 경우입니다.",
    },
    "rollback_complexity": {
        "none": "사실상 롤백이 필요 없거나 즉시 원복 가능합니다.",
        "low": "패키지 버전 복구, 단순 재기동 등으로 쉽게 되돌릴 수 있습니다.",
        "medium": "서비스 재배포, 설정 복구, 검증 절차가 일부 필요합니다.",
        "high": "데이터 정합성, 다중 서비스 연계, 복잡한 재배포 절차 등으로 원복 부담이 큽니다.",
        "unknown": "현재 정보만으로 롤백 난이도를 판단하기 어렵습니다.",
    },
}


def _resolve_path(path_value: Optional[Union[str, Path]], base_dir: Path = AGENT_ROOT) -> Optional[Path]:
    if path_value is None:
        return None
    path = Path(path_value)
    if not path.is_absolute():
        path = base_dir / path
    return path


def _load_json_file(path_value: Optional[Union[str, Path]], default: Any) -> Any:
    path = _resolve_path(path_value)
    if path is None or not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default


def _save_json_file(path_value: Union[str, Path], data: Any) -> Path:
    path = _resolve_path(path_value)
    if path is None:
        raise ValueError("저장 경로가 필요합니다.")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    return path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"critical", "high", "medium", "low"}:
        return normalized
    return "unknown"


def _normalize_impact(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"none", "high", "medium", "low", "unknown"}:
        return normalized
    return "unknown"


def _normalize_confidence(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"high", "medium", "low"}:
        return normalized
    return "medium"


def _normalize_truth_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    normalized = str(value or "").strip().lower()
    if normalized in {"true", "false", "unknown"}:
        return normalized
    if normalized in {"yes", "y", "applied", "confirmed", "required"}:
        return "true"
    if normalized in {"no", "n", "not_applied", "not_confirmed", "not_required"}:
        return "false"
    return "unknown"


def _normalize_complexity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"none", "high", "medium", "low", "unknown"}:
        return normalized
    return "unknown"


def _normalize_action_plan_direction(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"manual_approval", "auto_update", "wait_for_maintenance"}:
        return normalized
    return ""


def _safe_string(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text or default


def _fallback_estimated_downtime(impact_level: str) -> str:
    if impact_level == "none":
        return "0분"
    if impact_level == "low":
        return "0-5분"
    if impact_level == "medium":
        return "5-15분"
    if impact_level == "high":
        return "15분 이상"
    return "unknown"


def _fallback_rollback_complexity(followup_findings: dict[str, Any]) -> str:
    rollback_available = _normalize_truth_value(followup_findings.get("rollback_available"))
    if rollback_available == "true":
        return "low"
    if rollback_available == "false":
        return "high"
    return "unknown"


def _fallback_action_plan_direction(
    dependency_impact: str,
    requires_rolling_update: str,
    maintenance_window_time: str,
) -> str:
    if maintenance_window_time and maintenance_window_time != "unknown":
        return "wait_for_maintenance"
    if dependency_impact == "high":
        return "manual_approval"
    if requires_rolling_update == "true":
        return "wait_for_maintenance"
    return "auto_update"


def _extract_json_blob(text: str) -> Any:
    text = text.strip()
    if not text:
        raise ValueError("LLM 응답이 비어 있습니다.")

    fence_match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for idx, ch in enumerate(text):
        if ch not in "[{":
            continue
        try:
            parsed, _ = decoder.raw_decode(text[idx:])
            return parsed
        except json.JSONDecodeError:
            continue
    raise ValueError("LLM JSON 응답을 파싱하지 못했습니다.")


def _normalize_json_like(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and stripped[0] in "[{":
            try:
                return _extract_json_blob(stripped)
            except ValueError:
                return value
    return value


def _count_candidate_records(value: Any) -> int:
    normalized = _normalize_json_like(value)
    if isinstance(normalized, list):
        return len([item for item in normalized if isinstance(item, dict)])
    if isinstance(normalized, dict):
        records = normalized.get("records")
        if isinstance(records, list):
            return len([item for item in records if isinstance(item, dict)])
    return 0


def _resolve_bedrock_model(value: Any) -> str:
    resolved = str(value or "").strip()
    return resolved or DEFAULT_BEDROCK_MODEL


def _call_llm_json(
    system_prompt: str,
    payload: Any,
    *,
    bedrock_model: Any = None,
) -> Any:
    from patch_runtime.bedrock_json import call_bedrock_text

    prompt = json.dumps(payload, ensure_ascii=False, indent=2)
    output_text = call_bedrock_text(
        instructions=system_prompt,
        prompt=prompt,
        model_name=_resolve_bedrock_model(bedrock_model),
        max_retries=MAX_RETRIES,
        retry_delay=RETRY_DELAY,
    )
    return _extract_json_blob(output_text)


def _asset_summary(asset: Optional[dict[str, Any]]) -> dict[str, Any]:
    asset = asset if isinstance(asset, dict) else {}
    metadata = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
    installed = asset.get("installed_software") if isinstance(asset.get("installed_software"), list) else []
    primary_paths = [str(item.get("source_path") or "").strip() for item in installed if isinstance(item, dict) and item.get("source_path")]
    primary_product = next((item for item in installed if isinstance(item, dict)), {})
    product_name = _safe_string(primary_product.get("product"))
    vendor_name = _safe_string(primary_product.get("vendor"))
    product_version = _safe_string(primary_product.get("version"))
    if vendor_name and vendor_name != "unknown" and product_name and product_name != "unknown":
        display_name = f"{vendor_name} {product_name}"
    else:
        display_name = product_name or vendor_name or "unknown"
    installed_product_path = primary_paths[0] if primary_paths else "unknown"
    if installed_product_path != "unknown" and product_version and product_version != "unknown":
        installed_product_path = f"{installed_product_path} ({display_name} {product_version})".strip()
    return {
        "tier": str(asset.get("tier") or "unknown"),
        "environment": str(metadata.get("environment") or "unknown"),
        "business_criticality": str(metadata.get("business_criticality") or "unknown"),
        "network_exposure": str(metadata.get("network_exposure") or "unknown"),
        "installed_product_path": installed_product_path,
        "installed_product_name": display_name,
        "installed_product_version": product_version or "unknown",
    }


def _index_assets(data: Any) -> dict[str, dict[str, Any]]:
    assets = data.get("assets", []) if isinstance(data, dict) else []
    return {
        str(asset.get("asset_id")): asset
        for asset in assets
        if isinstance(asset, dict) and asset.get("asset_id")
    }


def _index_operational_records(data: Any) -> dict[str, dict[str, Any]]:
    records = data.get("records", []) if isinstance(data, dict) else []
    return {
        str(record.get("cve_id")): record
        for record in records
        if isinstance(record, dict) and record.get("cve_id")
    }


def _coerce_risk_records(risk_result: Any) -> list[dict[str, Any]]:
    if isinstance(risk_result, list):
        return [item for item in risk_result if isinstance(item, dict)]
    if isinstance(risk_result, dict) and isinstance(risk_result.get("records"), list):
        return [item for item in risk_result.get("records", []) if isinstance(item, dict)]
    return []


def _build_stage1_dataset(risk_result: Any, infra_context: Any, operational_payload: Any) -> dict[str, Any]:
    assets_by_id = _index_assets(infra_context)
    operational_map = _index_operational_records(operational_payload)
    risk_records = []
    for record in _coerce_risk_records(risk_result):
        cve_id = str(record.get("cve_id") or "").strip()
        operational_record = operational_map.get(cve_id, {})
        impacted_assets = []
        for item in record.get("impacted_assets", []) if isinstance(record.get("impacted_assets"), list) else []:
            if not isinstance(item, dict):
                continue
            instance_id = str(item.get("instance_id") or "").strip()
            asset_context = assets_by_id.get(instance_id)
            impacted_assets.append({
                "instance_id": instance_id,
                "risk_view": item,
                "asset_context": asset_context or {},
                "asset_context_summary": _asset_summary(asset_context),
            })
        risk_records.append({
            "cve_id": cve_id,
            "title": str(record.get("title") or "").strip(),
            "description": str(record.get("description") or "").strip(),
            "operational_context": operational_record,
            "impacted_assets": impacted_assets,
        })
    return {
        "purpose": "preliminary_patch_impact_evaluation",
        "risk_records": risk_records,
        "infra_context": infra_context if isinstance(infra_context, dict) else {},
    }


def _build_followup_handoff_prompt(
    cve_id: str,
    title: str,
    asset_id: str,
    severity: str,
    dependency: str,
    dependency_impact: str,
    action_plan_direction: str,
    missing_information: list[str],
    questions: list[str],
) -> str:
    missing_text = json.dumps(missing_information, ensure_ascii=False)
    questions_text = json.dumps(questions, ensure_ascii=False)
    return (
        "당신은 patch_impact_agent를 돕는 자산 수집 보조 에이전트입니다.\n"
        f"- CVE: {cve_id}\n"
        f"- 제목: {title}\n"
        f"- 자산: {asset_id}\n"
        f"- 현재 보안 위험도: {severity}\n"
        f"- 현재 1차 추정 dependency: {dependency}\n"
        f"- 현재 1차 추정 dependency_impact: {dependency_impact}\n"
        f"- 현재 1차 조치 방향: {action_plan_direction}\n"
        f"- 아직 부족한 정보: {missing_text}\n"
        f"- 확인 질문: {questions_text}\n"
        "운영 판단이나 추측은 하지 말고, 위 질문에 답할 수 있는 관측 가능한 사실만 수집하세요. "
        "예: 설치 버전, 실제 파일 경로, systemd unit 설정, ExecReload 존재 여부, 패키지 업데이트 후보 버전, "
        "프로세스/포트/로드밸런서 연결 여부 같은 사실만 JSON으로 답변해줘."
    )


def _derive_product_hint(patch_context: dict[str, Any], asset_decision: dict[str, Any]) -> str:
    asset_context_summary = asset_decision.get("asset_context_summary") if isinstance(asset_decision.get("asset_context_summary"), dict) else {}
    installed_name = _safe_string(asset_context_summary.get("installed_product_name"))
    if installed_name and installed_name != "unknown":
        return installed_name
    installed_path = _safe_string(asset_context_summary.get("installed_product_path"))
    if installed_path and installed_path != "unknown":
        basename = Path(installed_path).name.strip()
        if basename:
            return basename
    return _safe_string(patch_context.get("product_name"), "target service")


def _backfill_patch_context_from_assets(patch_context: dict[str, Any], asset_decisions: list[dict[str, Any]]) -> dict[str, Any]:
    context = dict(patch_context) if isinstance(patch_context, dict) else {}
    if _safe_string(context.get("product_name")) not in {"", "unknown", "n/a", "N/A"}:
        return context
    for asset_decision in asset_decisions:
        if not isinstance(asset_decision, dict):
            continue
        summary = asset_decision.get("asset_context_summary") if isinstance(asset_decision.get("asset_context_summary"), dict) else {}
        installed_name = _safe_string(summary.get("installed_product_name"))
        if installed_name and installed_name != "unknown":
            context["product_name"] = installed_name
            return context
    return context


def _append_install_observation(text: str, asset_context_summary: dict[str, Any]) -> str:
    base = _safe_string(text)
    if not isinstance(asset_context_summary, dict):
        return base
    installed_path = _safe_string(asset_context_summary.get("installed_product_path"))
    installed_version = _safe_string(asset_context_summary.get("installed_product_version"))
    if installed_path == "unknown" and installed_version == "unknown":
        return base
    fragments: list[str] = []
    if installed_path != "unknown" and installed_path not in base:
        fragments.append(f"설치 경로는 {installed_path} 입니다.")
    if installed_version != "unknown" and installed_version not in base:
        fragments.append(f"확인된 설치 버전은 {installed_version} 입니다.")
    if not fragments:
        return base
    if base:
        return f"{base} {' '.join(fragments)}".strip()
    return " ".join(fragments).strip()


def _derive_service_hint(patch_context: dict[str, Any], asset_decision: dict[str, Any]) -> str:
    asset_context_summary = asset_decision.get("asset_context_summary") if isinstance(asset_decision.get("asset_context_summary"), dict) else {}
    installed_path = _safe_string(asset_context_summary.get("installed_product_path"))
    if installed_path and installed_path != "unknown":
        basename = Path(installed_path).name.strip()
        if basename.endswith(".jar"):
            return "application service"
        if basename:
            return basename
    product_name = _safe_string(patch_context.get("product_name")).lower()
    if "nginx" in product_name:
        return "nginx"
    if "log4j" in product_name:
        return "application service"
    return "target service"


def _fallback_followup_questions(patch_context: dict[str, Any], asset_decision: dict[str, Any]) -> list[str]:
    product_hint = _derive_product_hint(patch_context, asset_decision)
    service_hint = _derive_service_hint(patch_context, asset_decision)
    return [
        f"패키지 매니저 또는 실행 파일 기준으로 현재 설치된 {product_hint} 버전과 실제 설치 경로를 확인",
        f"systemctl cat {service_hint} 또는 서비스 설정에서 ExecStart, ExecReload, 재기동 관련 설정 존재 여부를 확인",
    ]


def _rewrite_followup_question(
    question: str,
    *,
    patch_context: dict[str, Any],
    asset_decision: dict[str, Any],
) -> str:
    text = _safe_string(question)
    if not text:
        return ""

    lowered = text.lower()
    product_hint = _derive_product_hint(patch_context, asset_decision)
    service_hint = _derive_service_hint(patch_context, asset_decision)

    if any(keyword in text for keyword in ("평균 트래픽", "피크 시간대", "트래픽")):
        return ""
    if any(keyword in text for keyword in ("운영 영향", "사용자 영향", "핵심 기능", "필수 기능")):
        if "resolver" in lowered:
            return "nginx.conf 또는 include 된 설정 파일에 resolver 지시문이 존재하는지, 존재하면 파일 경로와 해당 줄을 확인"
        return ""
    if "resolver" in lowered:
        return "nginx.conf 또는 include 된 설정 파일에 resolver 지시문이 존재하는지, 존재하면 파일 경로와 해당 줄을 확인"
    if any(keyword in lowered for keyword in ("무중단 업그레이드", "rolling restart", "graceful reload", "reload 가능", "execreload")):
        return f"systemctl cat {service_hint} 또는 서비스 설정에서 ExecReload 존재 여부와 reload 지원 관련 설정을 확인"
    if any(keyword in text for keyword in ("패키지 버전", "업데이트 가용성", "보안 업데이트 가용성", "candidate version", "fixed version")):
        return f"패키지 매니저 또는 실행 파일 기준으로 현재 설치된 {product_hint} 버전과 업데이트 가능한 후보 버전을 확인"
    if any(keyword in text for keyword in ("재시작", "재기동", "restart")):
        return f"systemctl status {service_hint} 또는 서비스 설정에서 재기동이 필요한 구조인지, ExecReload/ExecStart 정보를 확인"
    if any(keyword in text for keyword in ("로드밸런서", "target group", "alb", "nlb", "바인딩")):
        return "현재 인스턴스가 ALB/NLB target group 또는 유사한 로드밸런서 대상에 연결되어 있는지 확인"
    return text


def _normalize_followup_questions(
    patch_context: dict[str, Any],
    asset_decision: dict[str, Any],
) -> list[str]:
    raw_questions = asset_decision.get("additional_asset_questions", [])
    questions = [str(item).strip() for item in raw_questions if str(item).strip()]
    normalized: list[str] = []
    seen: set[str] = set()

    for question in questions:
        rewritten = _rewrite_followup_question(
            question,
            patch_context=patch_context,
            asset_decision=asset_decision,
        )
        if not rewritten or rewritten in seen:
            continue
        seen.add(rewritten)
        normalized.append(rewritten)
        if len(normalized) >= 2:
            break

    if not normalized:
        for fallback in _fallback_followup_questions(patch_context, asset_decision):
            rewritten = _safe_string(fallback)
            if not rewritten or rewritten in seen:
                continue
            seen.add(rewritten)
            normalized.append(rewritten)
            if len(normalized) >= 2:
                break

    return normalized


def _build_additional_requests(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        cve_id = str(record.get("cve_id") or "").strip()
        title = str(record.get("title") or "").strip()
        patch_context = record.get("patch_context") if isinstance(record.get("patch_context"), dict) else {}
        for asset_decision in record.get("asset_decisions", []) if isinstance(record.get("asset_decisions"), list) else []:
            if not isinstance(asset_decision, dict):
                continue
            questions = [str(q).strip() for q in asset_decision.get("additional_asset_questions", []) if str(q).strip()]
            if not asset_decision.get("needs_additional_asset_context") or not questions:
                continue
            severity = _normalize_severity(asset_decision.get("security_severity"))
            dependency = _normalize_impact(asset_decision.get("dependency"))
            dependency_impact = _normalize_impact(asset_decision.get("dependency_impact") or asset_decision.get("dependency_operational_impact"))
            action_plan_direction = _normalize_action_plan_direction(asset_decision.get("action_plan_direction"))
            missing_information = [str(item).strip() for item in asset_decision.get("missing_information", []) if str(item).strip()]
            instance_id = str(asset_decision.get("instance_id") or "").strip()
            requests.append({
                "request_type": "additional_asset_context",
                "cve_id": cve_id,
                "title": title,
                "instance_id": instance_id,
                "product_name": str(patch_context.get("product_name") or "unknown"),
                "dependency": dependency,
                "dependency_impact": dependency_impact,
                "action_plan_direction": action_plan_direction,
                "security_severity": severity,
                "missing_information": missing_information,
                "questions": questions,
                "llm_handoff_prompt": _build_followup_handoff_prompt(
                    cve_id=cve_id,
                    title=title,
                    asset_id=instance_id,
                    severity=severity,
                    dependency=dependency,
                    dependency_impact=dependency_impact,
                    action_plan_direction=action_plan_direction,
                    missing_information=missing_information,
                    questions=questions,
                ),
            })
    return requests


def _coerce_stage1_records(raw_records: Any) -> list[dict[str, Any]]:
    records = raw_records if isinstance(raw_records, list) else []
    normalized_records: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        patch_context = record.get("patch_context") if isinstance(record.get("patch_context"), dict) else {}
        asset_decisions = []
        for asset_decision in record.get("asset_decisions", []) if isinstance(record.get("asset_decisions"), list) else []:
            if not isinstance(asset_decision, dict):
                continue
            dependency = _normalize_impact(asset_decision.get("dependency") or asset_decision.get("dependency_operational_impact"))
            dependency_impact = _normalize_impact(asset_decision.get("dependency_impact") or asset_decision.get("dependency_operational_impact") or dependency)
            asset_context_summary = asset_decision.get("asset_context_summary") if isinstance(asset_decision.get("asset_context_summary"), dict) else {}
            dependency_reason = _append_install_observation(
                _safe_string(asset_decision.get("dependency_reason"), _safe_string(asset_decision.get("reasoning_summary"))),
                asset_context_summary,
            )
            dependency_impact_reason = _append_install_observation(
                _safe_string(asset_decision.get("dependency_impact_reason"), _safe_string(asset_decision.get("reasoning_summary"))),
                asset_context_summary,
            )
            estimated_downtime = _safe_string(asset_decision.get("estimated_downtime"), _fallback_estimated_downtime(dependency_impact))
            os_reboot_required = _normalize_truth_value(asset_decision.get("os_reboot_required"))
            data_loss_risk = _normalize_truth_value(asset_decision.get("data_loss_risk"))
            config_overwrite_risk = _normalize_truth_value(asset_decision.get("config_overwrite_risk"))
            followup_findings = asset_decision.get("followup_findings") if isinstance(asset_decision.get("followup_findings"), dict) else {}
            rollback_complexity = _normalize_complexity(asset_decision.get("rollback_complexity") or _fallback_rollback_complexity(followup_findings))
            requires_rolling_update = _normalize_truth_value(asset_decision.get("requires_rolling_update"))
            maintenance_window_time = _safe_string(asset_decision.get("maintenance_window_time"))
            action_plan_direction = _normalize_action_plan_direction(asset_decision.get("action_plan_direction"))
            if not action_plan_direction:
                action_plan_direction = _fallback_action_plan_direction(dependency_impact, requires_rolling_update, maintenance_window_time)
            if action_plan_direction == "wait_for_maintenance" and not maintenance_window_time:
                maintenance_window_time = "unknown"
            recommended_action = asset_decision.get("recommended_action") if isinstance(asset_decision.get("recommended_action"), dict) else {
                "primary_action": "수동 분석 후 조치 방향을 다시 정한다.",
                "supplementary_action_guidance": "추가 맥락 확인 후 운영 반영 여부를 정한다.",
                "next_step": "필요한 근거를 더 수집한다.",
            }
            action = _safe_string(asset_decision.get("action"), _safe_string(recommended_action.get("primary_action")))
            additional_asset_questions = _normalize_followup_questions(patch_context, asset_decision)
            needs_additional_asset_context = bool(asset_decision.get("needs_additional_asset_context")) and bool(additional_asset_questions)
            asset_decisions.append({
                "instance_id": str(asset_decision.get("instance_id") or "").strip(),
                "security_severity": _normalize_severity(asset_decision.get("security_severity")),
                "dependency": dependency,
                "dependency_reason": dependency_reason,
                "dependency_impact": dependency_impact,
                "dependency_impact_reason": dependency_impact_reason,
                "dependency_operational_impact": dependency_impact,
                "confidence": _normalize_confidence(asset_decision.get("confidence")),
                "asset_context_summary": asset_context_summary,
                "reasoning_summary": _append_install_observation(
                    _safe_string(asset_decision.get("reasoning_summary"), dependency_impact_reason),
                    asset_context_summary,
                ),
                "missing_information": [str(item).strip() for item in asset_decision.get("missing_information", []) if str(item).strip()],
                "action_plan_direction": action_plan_direction,
                "estimated_downtime": estimated_downtime,
                "os_reboot_required": os_reboot_required,
                "data_loss_risk": data_loss_risk,
                "config_overwrite_risk": config_overwrite_risk,
                "rollback_complexity": rollback_complexity,
                "requires_rolling_update": requires_rolling_update,
                "maintenance_window_time": maintenance_window_time,
                "action": action,
                "recommended_action": recommended_action,
                "needs_additional_asset_context": needs_additional_asset_context,
                "additional_asset_questions": additional_asset_questions,
            })
        overall_impact = _normalize_impact(record.get("overall_dependency_operational_impact"))
        if overall_impact == "unknown":
            impacts = [item.get("dependency_operational_impact") for item in asset_decisions]
            if "high" in impacts:
                overall_impact = "high"
            elif "medium" in impacts:
                overall_impact = "medium"
            elif "low" in impacts:
                overall_impact = "low"
        normalized_records.append({
            "cve_id": str(record.get("cve_id") or "").strip(),
            "title": str(record.get("title") or "").strip(),
            "patch_context": _backfill_patch_context_from_assets(patch_context, asset_decisions),
            "overall_dependency_operational_impact": overall_impact,
            "requires_additional_asset_context": any(item.get("needs_additional_asset_context") for item in asset_decisions),
            "summary": str(record.get("summary") or "").strip(),
            "asset_decisions": asset_decisions,
        })
    return normalized_records


def _extract_stage1_records(raw_result: Any) -> list[dict[str, Any]]:
    if isinstance(raw_result, list):
        return _coerce_stage1_records(raw_result)
    if isinstance(raw_result, dict):
        if isinstance(raw_result.get("records"), list):
            return _coerce_stage1_records(raw_result.get("records"))
        if isinstance(raw_result.get("results"), list):
            return _coerce_stage1_records(raw_result.get("results"))
        if isinstance(raw_result.get("items"), list):
            return _coerce_stage1_records(raw_result.get("items"))
        if raw_result.get("cve_id") or isinstance(raw_result.get("asset_decisions"), list):
            return _coerce_stage1_records([raw_result])
    return []


def _stage1_system_prompt() -> str:
    return """당신은 patch_impact_agent 의 1차 판단 AI 입니다.
목표는 보안 심각도를 다시 계산하는 것이 아니라, 패치를 실제로 적용할 때의 dependency/operational impact 와 1차 조치 방향을 판단하는 것입니다.

규칙 기반 점수표를 흉내 내지 말고, 아래 입력 전체를 함께 읽고 자연스럽게 종합 판단하세요.
입력에는 위험도 평가 결과, 자산 인벤토리, 운영 영향 payload 가 함께 주어집니다.

판단 개념을 아래처럼 이해하세요:
1. dependency 는 취약 소프트웨어가 다른 코드, 라이브러리, 서비스, 인프라와 얼마나 강하게 연결되어 있는지에 대한 판단입니다.
2. dependency_impact 는 해당 패치를 적용했을 때 운영 서비스에 미치는 영향도에 대한 판단입니다.
3. dependency 와 dependency_impact 는 같은 값이 아닐 수 있습니다.
4. low 는 영향이 작고 우회 가능성이 큰 경우입니다.
5. medium 은 일부 기능 제한, 재기동, 연계 서비스 점검이 필요할 수 있는 경우입니다.
6. high 는 핵심 기능 중단, 전체 서비스 장애, 강한 의존성 전파 가능성이 큰 경우입니다.
7. none 은 사실상 의존성이나 운영 영향이 거의 없는 경우입니다.
8. unknown 은 정보 부족으로 신뢰성 있는 판단이 어려운 경우입니다.
9. action_plan_direction 은 manual_approval | auto_update | wait_for_maintenance 중 하나를 고르는 것입니다.
10. action 은 최종 단계의 확정 결론이 아니라, 현재 증거 기준에서 가장 적절해 보이는 1차 조치 결론입니다.
11. 질문이 필요하다면 운영 판단 질문이 아니라 관측 가능한 사실 질문만 만드세요.
12. 질문은 자산 에이전트가 한두 번의 명령 또는 파일 조회로 답할 수 있어야 합니다.
13. 한 자산당 추가 질문은 최대 2개까지만 만드세요.
14. "평균 트래픽", "피크 시간대", "이 설정이 필수 기능인지", "운영상 가능한지" 같은 해석형 질문은 금지합니다.
15. 자산 에이전트에는 설치 버전, 실제 파일 경로, systemd unit, ExecReload 존재 여부, 패키지 업데이트 후보 버전, 로드밸런서 연결 여부 같은 사실만 묻게 하세요.
16. operational payload 의 product_name 이 unknown 이어도 impacted_assets 의 installed_software 와 installed_product_path 에 실제 제품명, 설치 버전, 설치 경로가 있으면 그것을 사용하세요.
17. reasoning_summary, dependency_reason, dependency_impact_reason 에는 가능하면 실제 설치 경로와 설치 버전을 자연스럽게 드러내세요.

반드시 지킬 것:
1. 입력에 실제로 있는 근거만 사용하세요.
2. 자산이 실제 영향 대상인지 애매하면 억지로 확정하지 말고 추가 질문을 만드세요.
3. 질문은 infra_matching_agent 가 답할 수 있는 구체적 사실 질문으로만 만드세요.
4. 각 자산마다 먼저 1차 조치 방향을 제시하세요.
5. 정보가 부족해 follow-up 이 필요하면 asset_decisions 를 비워두지 마세요. 가장 가능성 높은 candidate asset 을 최소 1개 넣고, 그 자산에 대해 needs_additional_asset_context=true 와 추가 질문을 생성하세요.
6. 추가 질문은 반드시 최대 2개까지만 생성하세요.
7. 출력은 반드시 JSON object 하나만 반환하세요. 마크다운 금지.

반환 JSON 스키마:
{
  "records": [
    {
      "cve_id": "string",
      "title": "string",
      "patch_context": {
        "product_name": "string",
        "patch_type": "string",
        "fixed_version": "string",
        "validation_focus": ["string"],
        "rollout_considerations": ["string"]
      },
      "overall_dependency_operational_impact": "none | high | medium | low | unknown",
      "requires_additional_asset_context": true,
      "summary": "string",
      "asset_decisions": [
        {
          "instance_id": "string",
          "security_severity": "critical | high | medium | low | unknown",
          "dependency": "none | high | medium | low | unknown",
          "dependency_reason": "한국어 문자열",
          "dependency_impact": "none | high | medium | low | unknown",
          "dependency_impact_reason": "한국어 문자열",
          "confidence": "high | medium | low",
          "asset_context_summary": {
            "tier": "string",
            "environment": "string",
            "business_criticality": "string",
            "network_exposure": "string",
            "installed_product_path": "string"
          },
          "reasoning_summary": "한국어 문자열",
          "missing_information": ["string"],
          "action_plan_direction": "manual_approval | auto_update | wait_for_maintenance",
          "estimated_downtime": "예: 0분 | 0-5분 | 5-15분 | 15분 이상 | unknown",
          "os_reboot_required": "true | false | unknown",
          "data_loss_risk": "true | false | unknown",
          "config_overwrite_risk": "true | false | unknown",
          "rollback_complexity": "none | high | medium | low | unknown",
          "requires_rolling_update": "true | false | unknown",
          "maintenance_window_time": "예: 2026-05-03 02:00-03:00 KST | unknown | 빈 문자열",
          "action": "한국어 문자열",
          "recommended_action": {
            "primary_action": "string",
            "supplementary_action_guidance": "string",
            "next_step": "string"
          },
          "needs_additional_asset_context": true,
          "additional_asset_questions": ["최대 2개의 구체적 사실 질문"]
        }
      ]
    }
  ]
}
"""


def run_patch_impact_evaluation(
    risk_result: Optional[Any] = None,
    infra_context: Optional[Any] = None,
    operational_payload: Optional[Any] = None,
    metric_data: Optional[Any] = None,
    bedrock_model: Any = None,
    save_path: Union[str, Path] = PATCH_IMPACT_RESULT_PATH,
    additional_request_path: Union[str, Path] = ADDITIONAL_ASSET_REQUEST_PATH,
) -> JSONDict:
    if risk_result is None:
        risk_result = _load_json_file(DEFAULT_RISK_PATH, [])
    if infra_context is None:
        infra_context = _load_json_file(DEFAULT_INFRA_PATH, {})
    if operational_payload is None:
        operational_payload = _load_json_file(DEFAULT_OPERATIONAL_PATH, {})

    raw_input_debug = {
        "risk_result_type": type(risk_result).__name__,
        "risk_result_candidate_record_count": _count_candidate_records(risk_result),
        "infra_context_type": type(infra_context).__name__,
        "operational_payload_type": type(operational_payload).__name__,
    }
    risk_result = _normalize_json_like(risk_result)
    infra_context = _normalize_json_like(infra_context)
    operational_payload = _normalize_json_like(operational_payload)
    stage_payload = _build_stage1_dataset(risk_result, infra_context, operational_payload)
    raw_result = _call_llm_json(
        _stage1_system_prompt(),
        stage_payload,
        bedrock_model=bedrock_model,
    )
    records = _extract_stage1_records(raw_result)
    additional_requests = _build_additional_requests(records)
    additional_request_payload = {"requests": additional_requests, "request_count": len(additional_requests)}

    final_result = {
        "agent": "patch_impact_agent",
        "generated_at": _utc_now(),
        "raw_stage1_response_type": type(raw_result).__name__,
        "input_files": {
            "risk_evaluation_result": str(DEFAULT_RISK_PATH),
            "infra_context": str(DEFAULT_INFRA_PATH),
            "operational_impact_payloads": str(DEFAULT_OPERATIONAL_PATH),
        },
        "debug": {
            "raw_input": raw_input_debug,
            "stage1_input_record_count": len(stage_payload.get("risk_records", [])),
            "raw_stage1_response": raw_result,
        },
        "field_descriptions": FIELD_DESCRIPTIONS,
        "selection_criteria": SELECTION_CRITERIA,
        "records": records,
    }

    _save_json_file(save_path, final_result)
    _save_json_file(additional_request_path, additional_request_payload)
    return final_result


def run_patch_impact_finalization(
    prejudge_result: Optional[Any] = None,
    additional_asset_context: Optional[Any] = None,
    metric_data: Optional[Any] = None,
    bedrock_model: Any = None,
    save_path: Optional[Union[str, Path]] = None,
) -> JSONDict:
    from patch_runtime.finalize_patch import finalize_patch_strategy

    if prejudge_result is None:
        prejudge_result = _load_json_file(PATCH_IMPACT_RESULT_PATH, {})
    if additional_asset_context is None:
        additional_asset_context = _load_json_file(DEFAULT_FOLLOWUP_CONTEXT_PATH, {})
    return finalize_patch_strategy(
        prejudge_result=prejudge_result if isinstance(prejudge_result, dict) else {},
        additional_asset_context=additional_asset_context if isinstance(additional_asset_context, dict) else {},
        metric_data=metric_data if isinstance(metric_data, dict) else None,
        bedrock_model=bedrock_model,
        save_path=save_path,
    )


def load_latest_result(default: Any = None) -> Any:
    return _load_json_file(PATCH_IMPACT_RESULT_PATH, default)


def handle_agent_request(request: JSONDict) -> JSONDict:
    action = str(request.get("action") or "evaluate_patch_impact").strip().lower()

    if action in {"evaluate_patch_impact", "bootstrap", "init"}:
        result = run_patch_impact_evaluation(
            risk_result=request.get("risk_result"),
            infra_context=request.get("infra_context"),
            operational_payload=request.get("operational_payload"),
            metric_data=request.get("metric_data"),
            bedrock_model=request.get("bedrock_model_id") or request.get("patch_impact_bedrock_model"),
            save_path=request.get("save_path") or PATCH_IMPACT_RESULT_PATH,
            additional_request_path=request.get("additional_request_path") or ADDITIONAL_ASSET_REQUEST_PATH,
        )
        return {
            "action": action,
            "status": "ok",
            "result_path": str(_resolve_path(request.get("save_path") or PATCH_IMPACT_RESULT_PATH)),
            "additional_request_path": str(_resolve_path(request.get("additional_request_path") or ADDITIONAL_ASSET_REQUEST_PATH)),
            "additional_request": _load_json_file(request.get("additional_request_path") or ADDITIONAL_ASSET_REQUEST_PATH, {"requests": [], "request_count": 0}),
            "request_debug": {
                "keys": sorted(request.keys()),
                "debug_risk_result_count_hint": request.get("debug_risk_result_count_hint"),
                "debug_infra_asset_count_hint": request.get("debug_infra_asset_count_hint"),
                "risk_result_type": type(request.get("risk_result")).__name__,
                "infra_context_type": type(request.get("infra_context")).__name__,
                "operational_payload_type": type(request.get("operational_payload")).__name__,
            },
            "result": result,
        }

    if action in {"run_followup_conversation", "followup", "followup_conversation"}:
        from patch_runtime.followup_actions import run_patch_followup_conversation

        result = run_patch_followup_conversation(
            requests=request.get("requests") or request.get("additional_request"),
            prejudge_result=request.get("prejudge_result"),
            infra_context=request.get("infra_context"),
            region=_safe_string(request.get("region"), "ap-northeast-2"),
            infra_matching_runtime_arn=request.get("infra_matching_runtime_arn"),
            save_path=request.get("save_path"),
        )
        resolved_path = _resolve_path(request.get("save_path"), AGENT_ROOT) if request.get("save_path") else None
        return {
            "action": action,
            "status": "ok",
            "result_path": str(resolved_path) if resolved_path else "",
            "result": result,
        }

    if action in {"finalize_patch_impact", "finalize"}:
        result = run_patch_impact_finalization(
            prejudge_result=request.get("prejudge_result"),
            additional_asset_context=request.get("additional_asset_context"),
            metric_data=request.get("metric_data"),
            bedrock_model=request.get("bedrock_model_id") or request.get("patch_impact_bedrock_model"),
            save_path=request.get("save_path"),
        )
        resolved_path = _resolve_path(request.get("save_path"), AGENT_ROOT) if request.get("save_path") else None
        return {
            "action": action,
            "status": "ok",
            "result_path": str(resolved_path) if resolved_path else "",
            "result": result,
        }

    if action in {"query_patch_impact", "query"}:
        cve_id = str(request.get("cve_id") or "").strip()
        instance_id = str(request.get("instance_id") or "").strip()
        latest = load_latest_result(default={"records": []})
        records = latest.get("records", []) if isinstance(latest, dict) else []

        filtered = []
        for record in records:
            if cve_id and str(record.get("cve_id") or "").strip() != cve_id:
                continue
            if instance_id:
                asset_decisions = record.get("asset_decisions", [])
                matched = [item for item in asset_decisions if str(item.get("instance_id") or "").strip() == instance_id]
                if not matched:
                    continue
                record = dict(record)
                record["asset_decisions"] = matched
            filtered.append(record)

        return {
            "action": action,
            "status": "ok",
            "result_count": len(filtered),
            "records": filtered,
        }

    raise ValueError(f"지원하지 않는 action 입니다: {action}")


def invoke(payload: JSONDict) -> JSONDict:
    if not isinstance(payload, dict):
        raise ValueError("payload는 JSON object 형태여야 합니다.")
    return handle_agent_request(payload)
