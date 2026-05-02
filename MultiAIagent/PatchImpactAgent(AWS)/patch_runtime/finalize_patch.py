from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from patch_runtime.bedrock_json import call_bedrock_text


AGENT_ROOT = Path(__file__).resolve().parent
DEFAULT_SAVE_PATH = AGENT_ROOT.parent / "OutputResult" / "PatchImAgent" / "stage3_final" / "patch_impact_final_result.json"
DEFAULT_BEDROCK_MODEL = (
    os.environ.get("PATCH_IMPACT_BEDROCK_MODEL")
    or os.environ.get("BEDROCK_MODEL_ID")
    or "global.anthropic.claude-haiku-4-5-20251001-v1:0"
)
MAX_RETRIES = 3
RETRY_DELAY = 5


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _save_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _normalize_impact(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"none", "high", "medium", "low", "unknown"}:
        return normalized
    return "unknown"


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


def _normalize_action_decision(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"manual_approval", "auto_update", "wait_for_maintenance"}:
        return normalized
    return ""


def _safe_string(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text or default


def _build_meta() -> dict[str, Any]:
    return {
        "payload_purpose": "각 취약점별 패치 적용 시 자산별 의존성, 운영 영향도, 그리고 최종 조치 방향을 요약합니다.",
        "recommended_reading_order": [
            "records[].cve_id",
            "records[].patch_context",
            "records[].overall_dependency_operational_impact",
            "records[].asset_decisions[].dependency",
            "records[].asset_decisions[].dependency_impact",
            "records[].asset_decisions[].action_plan_direction",
            "records[].asset_decisions[].action",
        ],
        "record_field_guide": {
            "cve_id": "판단 대상 취약점 ID 입니다.",
            "title": "취약점 제목입니다.",
            "patch_context": "패치 대상 제품과 패치 방식, 검증 포인트를 담은 문맥 정보입니다.",
            "overall_dependency_operational_impact": "해당 CVE를 전체적으로 봤을 때 패치 적용의 운영 영향도를 요약한 값입니다.",
            "asset_decisions": "자산별 최종 판단 목록입니다.",
            "asset_decisions[].instance_id": "판단 대상 EC2 인스턴스 ID 입니다.",
            "asset_decisions[].dependency": "취약 소프트웨어가 다른 코드, 라이브러리, 서비스, 인프라 구성요소와 얼마나 강하게 연결되어 있는지 평가한 값입니다.",
            "asset_decisions[].dependency_reason": "dependency 값을 그렇게 판단한 이유입니다. 가능하면 어떤 서비스, 코드베이스, 설정, 인프라와 연결되는지 구체적으로 적습니다.",
            "asset_decisions[].dependency_impact": "해당 패치를 적용했을 때 운영 서비스에 미치는 영향도를 평가한 값입니다.",
            "asset_decisions[].dependency_impact_reason": "dependency_impact 값을 그렇게 판단한 이유입니다. 일부 기능 저하인지, 핵심 기능 중단인지, 전체 서비스 영향인지 등을 구체적으로 적습니다.",
            "asset_decisions[].action_plan_direction": "운영 영향과 의존성을 종합해 권장하는 큰 조치 방향입니다. manual_approval | auto_update | wait_for_maintenance 중 하나입니다.",
            "asset_decisions[].estimated_downtime": "자동 패치 또는 실제 패치 수행 시 예상되는 다운타임입니다. 추정이 어렵다면 unknown 으로 둡니다.",
            "asset_decisions[].os_reboot_required": "패치 완료를 위해 OS 재부팅이 필요한지 여부입니다. 값은 true | false | unknown 입니다.",
            "asset_decisions[].data_loss_risk": "패치 과정에서 데이터베이스나 중요 로그 파일 유실 위험이 있는지 나타냅니다. 값은 true | false | unknown 입니다.",
            "asset_decisions[].config_overwrite_risk": "패치 과정에서 설정 파일 유실 또는 덮어쓰기 위험이 있는지 나타냅니다. 값은 true | false | unknown 입니다.",
            "asset_decisions[].rollback_complexity": "패치 장애 발생 시 이전 상태로 되돌리는 복잡도입니다. 값은 none | low | medium | high | unknown 입니다.",
            "asset_decisions[].requires_rolling_update": "서비스 중단 최소화를 위해 한 대씩 순차 업데이트가 필요한지 여부입니다. 값은 true | false | unknown 입니다.",
            "asset_decisions[].maintenance_window_time": "action_plan_direction 이 wait_for_maintenance 일 때 대기하거나 수행해야 하는 유지보수 시간 정보입니다. 해당 없으면 빈 문자열 또는 unknown 으로 둡니다.",
            "asset_decisions[].action": "최종적으로 무엇을 어떻게 해야 하는지에 대한 구체적인 결론입니다. 운영 피해를 최소화하는 방향으로 한국어로 작성합니다.",
        },
        "selection_criteria": {
            "overall_dependency_operational_impact": {
                "none": "패치가 운영 흐름에 사실상 영향을 주지 않으며 연계 요소도 거의 없습니다.",
                "low": "영향 범위가 작고 우회 가능하며 핵심 기능 중단 가능성이 낮습니다.",
                "medium": "일부 기능 저하나 제한적 서비스 영향이 예상되며 사전 확인이 필요합니다.",
                "high": "핵심 기능 중단, 대규모 장애, 전체 서비스 영향 가능성이 큽니다.",
                "unknown": "현재 정보만으로 영향도를 신뢰성 있게 판단하기 어렵습니다."
            },
            "asset_decisions[].dependency": {
                "none": "취약 소프트웨어가 독립적으로 존재하며 다른 서비스, 코드, 인프라와의 연결이 사실상 확인되지 않습니다.",
                "low": "연결은 있으나 영향 범위가 작고 대체 경로나 우회 수단이 있습니다.",
                "medium": "여러 구성요소와 연결되어 있으며 패치 시 일부 기능이나 연계 서비스 확인이 필요합니다.",
                "high": "핵심 서비스, 공용 라이브러리, 주요 인프라 흐름과 강하게 연결되어 있어 영향 전파 가능성이 큽니다.",
                "unknown": "현재 정보만으로 실제 연결 구조를 확인하기 어렵습니다."
            },
            "asset_decisions[].dependency_impact": {
                "none": "패치 적용 후 운영 기능 영향이 사실상 없습니다.",
                "low": "사소한 기능 제한이나 짧은 순간 영향만 예상됩니다.",
                "medium": "일부 중요 기능 저하 또는 제한적 서비스 영향이 예상됩니다.",
                "high": "핵심 기능 중단, 사용자 영향 확대, 전체 서비스 장애 가능성이 큽니다.",
                "unknown": "의존성 영향 결과를 현재 정보만으로 판단하기 어렵습니다."
            },
            "asset_decisions[].rollback_complexity": {
                "none": "사실상 롤백이 필요 없거나 즉시 원복 가능합니다.",
                "low": "패키지 버전 복구, 단순 재기동 등으로 쉽게 되돌릴 수 있습니다.",
                "medium": "서비스 재배포, 설정 복구, 검증 절차가 일부 필요합니다.",
                "high": "데이터 정합성, 다중 서비스 연계, 복잡한 재배포 절차 등으로 원복 부담이 큽니다.",
                "unknown": "현재 정보만으로 롤백 난이도를 판단하기 어렵습니다."
            },
            "asset_decisions[].action_plan_direction": {
                "manual_approval": "운영 영향이 크거나 불확실성이 남아 있어 담당자 검토와 승인 후 진행하는 것이 적절합니다.",
                "auto_update": "영향과 불확실성이 낮아 사전 검증 후 자동 패치를 진행해도 되는 경우입니다.",
                "wait_for_maintenance": "즉시 패치보다 지정된 유지보수 시간까지 대기한 뒤 계획된 방식으로 패치하는 것이 적절합니다."
            }
        },
    }


def _fallback_reason_summary(asset_decision: dict[str, Any]) -> str:
    assessment = _safe_string((asset_decision.get("assessment_result") or {}).get("reason_summary"))
    if assessment:
        return assessment
    reasoning = _safe_string(asset_decision.get("reasoning_summary"))
    if reasoning:
        return reasoning
    final_reasoning = asset_decision.get("final_reasoning")
    if isinstance(final_reasoning, list):
        merged = " ".join(_safe_string(item) for item in final_reasoning if _safe_string(item))
        if merged:
            return merged
    return "운영 영향 판단 근거가 충분히 정리되지 않았습니다."


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


def _fallback_dependency(asset_decision: dict[str, Any], impact_level: str) -> str:
    followup_findings = asset_decision.get("followup_findings") if isinstance(asset_decision.get("followup_findings"), dict) else {}
    dependency_type = _safe_string(followup_findings.get("dependency_type")).lower()
    if dependency_type in {"none", "not applicable", "not_applicable"}:
        return "none"
    if impact_level in {"high", "medium", "low"}:
        return impact_level
    return "unknown"


def _fallback_dependency_reason(asset_decision: dict[str, Any]) -> str:
    followup_findings = asset_decision.get("followup_findings") if isinstance(asset_decision.get("followup_findings"), dict) else {}
    candidates = [
        asset_decision.get("dependency_reason"),
        followup_findings.get("summary"),
        followup_findings.get("config_compatibility_notes"),
        asset_decision.get("reasoning_summary"),
    ]
    for candidate in candidates:
        text = _safe_string(candidate)
        if text and text.lower() not in {"unknown", "none", "not applicable"}:
            return text
    return _fallback_reason_summary(asset_decision)


def _fallback_dependency_impact(asset_decision: dict[str, Any], dependency: str) -> str:
    normalized = _normalize_impact(asset_decision.get("dependency_impact") or asset_decision.get("dependency_operational_impact"))
    if normalized != "unknown":
        return normalized
    if dependency == "none":
        return "none"
    return "unknown"


def _fallback_dependency_impact_reason(asset_decision: dict[str, Any]) -> str:
    candidates = [
        asset_decision.get("dependency_impact_reason"),
        asset_decision.get("reasoning_summary"),
        asset_decision.get("action"),
    ]
    for candidate in candidates:
        text = _safe_string(candidate)
        if text:
            return text
    return _fallback_reason_summary(asset_decision)


def _fallback_action_plan_direction(asset_decision: dict[str, Any], dependency_impact: str, requires_rolling_update: str, maintenance_window_time: str) -> str:
    raw_action_plan = asset_decision.get("action_plan") if isinstance(asset_decision.get("action_plan"), dict) else {}
    decision = _normalize_action_decision(asset_decision.get("action_plan_direction") or raw_action_plan.get("decision"))
    if decision:
        return decision
    if maintenance_window_time and maintenance_window_time != "unknown":
        return "wait_for_maintenance"
    if dependency_impact == "high":
        return "manual_approval"
    if requires_rolling_update == "true":
        return "wait_for_maintenance"
    return "auto_update"


def _fallback_maintenance_window_time(asset_decision: dict[str, Any], action_plan_direction: str) -> str:
    assessment = asset_decision.get("assessment_result") if isinstance(asset_decision.get("assessment_result"), dict) else {}
    text = _safe_string(asset_decision.get("maintenance_window_time") or assessment.get("maintenance_window_time"))
    if text:
        return text
    if action_plan_direction == "wait_for_maintenance":
        return "unknown"
    return ""


def _fallback_action(asset_decision: dict[str, Any], action_plan_direction: str, dependency_impact: str) -> str:
    text = _safe_string(asset_decision.get("action"))
    if text:
        return text
    recommended_action = asset_decision.get("recommended_action") if isinstance(asset_decision.get("recommended_action"), dict) else {}
    primary_action = _safe_string(recommended_action.get("primary_action"))
    if primary_action:
        return primary_action
    if action_plan_direction == "manual_approval":
        return "운영 담당자 검토와 승인 이후 패치 적용 순서와 범위를 확정합니다."
    if action_plan_direction == "wait_for_maintenance":
        return "지정된 유지보수 시간까지 대기한 뒤 순차 배포 방식으로 패치를 적용합니다."
    if dependency_impact in {"none", "low"}:
        return "사전 점검 후 자동 패치를 진행합니다."
    return "사전 검증을 거친 뒤 안전한 방식으로 패치를 적용합니다."


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


def _resolve_bedrock_model(value: Any) -> str:
    resolved = _safe_string(value)
    return resolved or DEFAULT_BEDROCK_MODEL


def _call_llm_json(
    system_prompt: str,
    payload: Any,
    *,
    bedrock_model: Any = None,
) -> Any:
    output_text = call_bedrock_text(
        instructions=system_prompt,
        prompt=json.dumps(payload, ensure_ascii=False, indent=2),
        model_name=_resolve_bedrock_model(bedrock_model),
        max_retries=MAX_RETRIES,
        retry_delay=RETRY_DELAY,
    )
    return _extract_json_blob(output_text)


def _response_map(additional_asset_context: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    mapping: dict[tuple[str, str], dict[str, Any]] = {}
    for item in additional_asset_context.get("responses", []) if isinstance(additional_asset_context, dict) else []:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cve_id") or "").strip()
        instance_id = str(item.get("instance_id") or "").strip()
        response_wrapper = item.get("response") or {}
        result = response_wrapper.get("result") or {}
        parsed_answer = result.get("parsed_answer")
        if isinstance(parsed_answer, dict):
            mapping[(cve_id, instance_id)] = parsed_answer
    return mapping


def _stage3_system_prompt() -> str:
    return """당신은 patch_impact_agent 의 최종 판단 AI 입니다.
목표는 1차 patch 판단 결과와 추가 자산 조사 응답을 합쳐, 최종 dependency/operational impact 와 최종 조치 방향을 정리하는 것입니다.

반드시 지킬 것:
1. 규칙 기반 점수표를 흉내 내지 말고 입력 전체를 자연스럽게 종합 판단하세요.
2. follow-up 응답으로 자산 매칭이 약해졌다면 해당 자산을 제외하거나 불확실성으로 낮추세요.
3. follow-up 응답이 충분하면 requires_additional_asset_context 는 false 로 마무리하세요.
4. assessment_result 는 "패치를 적용했을 때 운영적으로 얼마나 부담이 큰가"를 나타냅니다.
5. action_plan 은 assessment_result 를 바탕으로 실제 어떤 조치를 선택할지 나타냅니다.
6. execute_code 와 rollback_code 는 근거가 직접적이지 않으면 빈 문자열로 두세요. 추측해서 명령을 만들지 마세요.
7. reasoning_summary, assessment_result.reason_summary, final_reasoning 은 한국어로 쓰세요.
8. 출력은 반드시 JSON object 하나만 반환하세요. 마크다운 금지.

반환 JSON 스키마:
{
  "records": [
    {
      "cve_id": "string",
      "title": "string",
      "patch_context": {"product_name": "string", "patch_type": "string", "fixed_version": "string", "validation_focus": ["string"], "rollout_considerations": ["string"]},
      "overall_dependency_operational_impact": "none | high | medium | low | unknown",
      "requires_additional_asset_context": false,
      "asset_decisions": [
        {
          "instance_id": "string",
          "dependency": "none | high | medium | low | unknown",
          "dependency_reason": "한국어 문자열",
          "dependency_impact": "none | high | medium | low | unknown",
          "dependency_impact_reason": "한국어 문자열",
          "action_plan_direction": "manual_approval | auto_update | wait_for_maintenance",
          "estimated_downtime": "예: 0분 | 0-5분 | 5-15분 | 15분 이상 | unknown",
          "os_reboot_required": "true | false | unknown",
          "data_loss_risk": "true | false | unknown",
          "config_overwrite_risk": "true | false | unknown",
          "rollback_complexity": "none | high | medium | low | unknown",
          "requires_rolling_update": "true | false | unknown",
          "maintenance_window_time": "예: 2026-05-03 02:00-03:00 KST | unknown | 빈 문자열",
          "action": "최종 조치 결론을 한국어로 구체적으로 작성"
        }
      ]
    }
  ]
}
"""


def finalize_patch_strategy(
    prejudge_result: dict[str, Any],
    additional_asset_context: dict[str, Any],
    metric_data: dict[str, Any] | None = None,
    bedrock_model: Any = None,
    save_path: str | Path | None = None,
) -> dict[str, Any]:
    followup_map = _response_map(additional_asset_context)
    payload = {
        "purpose": "final_patch_impact_evaluation",
        "prejudge_result": prejudge_result,
        "followup_responses": [
            {
                "cve_id": cve_id,
                "instance_id": instance_id,
                "parsed_answer": parsed_answer,
            }
            for (cve_id, instance_id), parsed_answer in followup_map.items()
        ],
    }
    raw_result = _call_llm_json(
        _stage3_system_prompt(),
        payload,
        bedrock_model=bedrock_model,
    )
    records = raw_result.get("records", []) if isinstance(raw_result, dict) and isinstance(raw_result.get("records"), list) else []

    normalized_records = []
    for record in records:
        if not isinstance(record, dict):
            continue
        asset_decisions = []
        impacts = []
        for asset_decision in record.get("asset_decisions", []) if isinstance(record.get("asset_decisions"), list) else []:
            if not isinstance(asset_decision, dict):
                continue
            dependency_impact = _normalize_impact(asset_decision.get("dependency_impact") or asset_decision.get("dependency_operational_impact"))
            dependency = _normalize_impact(asset_decision.get("dependency") or _fallback_dependency(asset_decision, dependency_impact))
            dependency_reason = _safe_string(asset_decision.get("dependency_reason"), _fallback_dependency_reason(asset_decision))
            if dependency_impact == "unknown":
                dependency_impact = _fallback_dependency_impact(asset_decision, dependency)
            dependency_impact = _normalize_impact(dependency_impact)
            dependency_impact_reason = _safe_string(asset_decision.get("dependency_impact_reason"), _fallback_dependency_impact_reason(asset_decision))
            estimated_downtime = _safe_string(
                asset_decision.get("estimated_downtime") or (
                    asset_decision.get("assessment_result", {}).get("estimated_downtime")
                    if isinstance(asset_decision.get("assessment_result"), dict)
                    else ""
                ),
                _fallback_estimated_downtime(dependency_impact),
            )
            os_reboot_required = _normalize_truth_value(
                asset_decision.get("os_reboot_required") or (
                    asset_decision.get("assessment_result", {}).get("os_reboot_required")
                    if isinstance(asset_decision.get("assessment_result"), dict)
                    else ""
                ) or (
                    asset_decision.get("followup_findings", {}).get("restart_required")
                    if isinstance(asset_decision.get("followup_findings"), dict)
                    else ""
                )
            )
            data_loss_risk = _normalize_truth_value(
                asset_decision.get("data_loss_risk") or (
                    asset_decision.get("assessment_result", {}).get("data_loss_risk")
                    if isinstance(asset_decision.get("assessment_result"), dict)
                    else ""
                )
            )
            config_overwrite_risk = _normalize_truth_value(
                asset_decision.get("config_overwrite_risk") or (
                    asset_decision.get("assessment_result", {}).get("config_overwrite_risk")
                    if isinstance(asset_decision.get("assessment_result"), dict)
                    else ""
                )
            )
            rollback_complexity = _normalize_complexity(
                asset_decision.get("rollback_complexity") or (
                    asset_decision.get("assessment_result", {}).get("rollback_complexity")
                    if isinstance(asset_decision.get("assessment_result"), dict)
                    else ""
                ) or _fallback_rollback_complexity(
                    asset_decision.get("followup_findings") if isinstance(asset_decision.get("followup_findings"), dict) else {}
                )
            )
            requires_rolling_update = _normalize_truth_value(
                asset_decision.get("requires_rolling_update") or (
                    asset_decision.get("assessment_result", {}).get("requires_rolling_update")
                    if isinstance(asset_decision.get("assessment_result"), dict)
                    else ""
                )
            )
            provisional_maintenance_window_time = _fallback_maintenance_window_time(asset_decision, "")
            action_plan_direction = _fallback_action_plan_direction(
                asset_decision,
                dependency_impact,
                requires_rolling_update,
                provisional_maintenance_window_time,
            )
            maintenance_window_time = _fallback_maintenance_window_time(asset_decision, action_plan_direction)
            action = _fallback_action(asset_decision, action_plan_direction, dependency_impact)
            impacts.append(dependency_impact)
            asset_decisions.append({
                "instance_id": _safe_string(asset_decision.get("instance_id")),
                "dependency": dependency,
                "dependency_reason": dependency_reason,
                "dependency_impact": dependency_impact,
                "dependency_impact_reason": dependency_impact_reason,
                "action_plan_direction": action_plan_direction,
                "estimated_downtime": estimated_downtime,
                "os_reboot_required": os_reboot_required,
                "data_loss_risk": data_loss_risk,
                "config_overwrite_risk": config_overwrite_risk,
                "rollback_complexity": rollback_complexity,
                "requires_rolling_update": requires_rolling_update,
                "maintenance_window_time": maintenance_window_time,
                "action": action,
            })
        overall = _normalize_impact(record.get("overall_dependency_operational_impact"))
        if overall == "unknown":
            if "high" in impacts:
                overall = "high"
            elif "medium" in impacts:
                overall = "medium"
            elif "low" in impacts:
                overall = "low"
        normalized_records.append({
            "cve_id": str(record.get("cve_id") or "").strip(),
            "title": str(record.get("title") or "").strip(),
            "patch_context": record.get("patch_context") if isinstance(record.get("patch_context"), dict) else {},
            "overall_dependency_operational_impact": overall,
            "requires_additional_asset_context": False,
            "asset_decisions": asset_decisions,
        })

    final_result = {
        "agent": "patch_impact_agent_finalizer",
        "generated_at": _utc_now(),
        "source_stage": "stage3_finalization",
        "used_followup_response_count": len(followup_map),
        "_meta": _build_meta(),
        "records": normalized_records,
    }

    output_path = Path(save_path) if save_path else DEFAULT_SAVE_PATH
    _save_json(output_path, final_result)
    return final_result
