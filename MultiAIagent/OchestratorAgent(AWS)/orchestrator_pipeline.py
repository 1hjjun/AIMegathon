from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline_stages import (
    PATCH_FINAL_RESULT_PATH,
    PATCH_FOLLOWUP_REQUEST_PATH,
    PATCH_FOLLOWUP_RESULT_PATH,
    PATCH_PRE_RESULT_PATH,
    PIPELINE_RESULT_PATH,
    run_asset_stage,
    run_patch_finalize_stage,
    run_patch_followup_stage,
    run_patch_pre_stage,
    run_risk_stage,
    run_vuln_stage,
)


MODULE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = MODULE_ROOT.parent.parent
DEFAULT_STACK_NAME = os.environ.get("CF_STACK_NAME", "megathon")
VALID_MODES = {"full", "vuln_only", "asset_only", "risk_only", "patch_only", "test"}
STAGE_ORDER = {
    "vuln": 1,
    "asset": 2,
    "risk": 3,
    "patch_pre": 4,
    "patch_followup": 5,
    "patch_final": 6,
}

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _resolve_mode(payload: dict[str, Any]) -> str:
    raw_mode = str(payload.get("mode") or "full").strip().lower()
    aliases = {
        "default": "full",
        "pipeline": "full",
        "full_pipeline": "full",
        "vuln": "vuln_only",
        "vulnerability": "vuln_only",
        "asset": "asset_only",
        "risk": "risk_only",
        "patch": "patch_only",
        "stage_test": "test",
        "inject": "test",
    }
    mode = aliases.get(raw_mode, raw_mode)
    if mode not in VALID_MODES:
        raise ValueError("mode 는 full | vuln_only | asset_only | risk_only | patch_only | test 중 하나여야 합니다.")
    return mode


def _build_config(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": _resolve_mode(payload),
        "orchestration_style": "direct_pipeline",
        "stack_name": str(payload.get("stack_name") or "").strip() or DEFAULT_STACK_NAME,
        "region": str(payload.get("region") or "ap-northeast-2"),
        "infra_matching_runtime_arn": str(payload.get("infra_matching_runtime_arn") or "").strip() or None,
        "patch_impact_runtime_arn": str(
            payload.get("patch_impact_runtime_arn") or payload.get("patch_runtime_arn") or ""
        ).strip()
        or None,
        "allow_followup": bool(payload.get("allow_followup", True)),
        "stop_stage": str(payload.get("stop_stage") or "").strip().lower() or None,
    }


def _load_followup_request_count() -> int:
    if not PATCH_FOLLOWUP_REQUEST_PATH.exists():
        return 0
    try:
        data = json.loads(PATCH_FOLLOWUP_REQUEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    return int(data.get("request_count", 0))


def _pick_payload_value(payload: dict[str, Any], key: str) -> Any:
    if key in payload and payload.get(key) is not None:
        return payload.get(key)
    test_inputs = payload.get("test_inputs")
    if isinstance(test_inputs, dict) and key in test_inputs and test_inputs.get(key) is not None:
        return test_inputs.get(key)
    return None


def _seed_state(payload: dict[str, Any]) -> dict[str, Any]:
    state: dict[str, Any] = {}

    vuln_stage = _pick_payload_value(payload, "vuln_stage")
    if isinstance(vuln_stage, dict):
        state["vuln_stage"] = vuln_stage.get("vuln_stage") if isinstance(vuln_stage.get("vuln_stage"), dict) else vuln_stage
    else:
        raw_result = _pick_payload_value(payload, "raw_result") or _pick_payload_value(payload, "raw_dataset")
        risk_assessment_payload = _pick_payload_value(payload, "risk_assessment_payload")
        operational_payload = _pick_payload_value(payload, "operational_payload") or _pick_payload_value(payload, "operational_impact_payload")
        asset_matching_payload = _pick_payload_value(payload, "asset_matching_payload")
        if any(isinstance(item, dict) for item in (raw_result, risk_assessment_payload, operational_payload, asset_matching_payload)):
            state["vuln_stage"] = {
                "agent": "vuln_collector_agent",
                "status": "injected",
                "raw_result": raw_result if isinstance(raw_result, dict) else {},
                "risk_assessment_payload": risk_assessment_payload if isinstance(risk_assessment_payload, dict) else {},
                "operational_impact_payload": operational_payload if isinstance(operational_payload, dict) else {},
                "asset_matching_payload": asset_matching_payload if isinstance(asset_matching_payload, dict) else {},
            }

    asset_stage = _pick_payload_value(payload, "asset_stage")
    if isinstance(asset_stage, dict):
        if isinstance(asset_stage.get("asset_stage"), dict):
            state["asset_stage"] = asset_stage["asset_stage"]
        elif isinstance(asset_stage.get("result"), dict):
            state["asset_stage"] = asset_stage
    else:
        infra_context = _pick_payload_value(payload, "infra_context")
        if isinstance(infra_context, dict):
            state["asset_stage"] = {
                "agent": "infra_matching_agent",
                "status": "injected",
                "result": infra_context,
            }

    risk_stage = _pick_payload_value(payload, "risk_stage")
    if isinstance(risk_stage, dict):
        if isinstance(risk_stage.get("risk_stage"), dict):
            state["risk_stage"] = risk_stage["risk_stage"]
        elif "result" in risk_stage:
            state["risk_stage"] = risk_stage
    else:
        risk_result = _pick_payload_value(payload, "risk_result")
        if isinstance(risk_result, (dict, list)):
            state["risk_stage"] = {
                "agent": "risk_evaluation_agent",
                "status": "injected",
                "result": risk_result,
            }

    patch_pre_stage = _pick_payload_value(payload, "patch_pre_stage")
    if isinstance(patch_pre_stage, dict):
        if isinstance(patch_pre_stage.get("patch_pre_stage"), dict):
            state["patch_pre_stage"] = patch_pre_stage["patch_pre_stage"]
        elif "result" in patch_pre_stage:
            state["patch_pre_stage"] = patch_pre_stage
    else:
        prejudge_result = _pick_payload_value(payload, "prejudge_result")
        if isinstance(prejudge_result, dict):
            state["patch_pre_stage"] = {
                "agent": "patch_impact_agent",
                "status": "injected",
                "result": prejudge_result,
            }

    followup_stage = (
        _pick_payload_value(payload, "followup_stage")
        or _pick_payload_value(payload, "followup_result")
        or _pick_payload_value(payload, "additional_asset_context")
    )
    if isinstance(followup_stage, dict):
        if isinstance(followup_stage.get("followup_stage"), dict):
            state["followup_stage"] = followup_stage["followup_stage"]
        else:
            state["followup_stage"] = followup_stage

    patch_final_stage = _pick_payload_value(payload, "patch_final_stage") or _pick_payload_value(payload, "patch_final_result")
    if isinstance(patch_final_stage, dict):
        if isinstance(patch_final_stage.get("patch_final_stage"), dict):
            state["patch_final_stage"] = patch_final_stage["patch_final_stage"]
        elif "result" in patch_final_stage:
            state["patch_final_stage"] = patch_final_stage
        else:
            state["patch_final_stage"] = {
                "agent": "patch_impact_agent",
                "status": "injected",
                "result": patch_final_stage,
            }

    return state


def _normalize_followup_request_payload(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        if isinstance(value.get("requests"), list):
            return {
                "requests": value["requests"],
                "request_count": int(value.get("request_count", len(value["requests"]))),
            }
        return None
    if isinstance(value, list):
        return {
            "requests": value,
            "request_count": len(value),
        }
    return None


def _write_injected_followup_request(payload: dict[str, Any]) -> dict[str, Any] | None:
    request_payload = _normalize_followup_request_payload(
        _pick_payload_value(payload, "followup_request") or _pick_payload_value(payload, "additional_request")
    )
    if request_payload is None:
        return None
    _write_json(PATCH_FOLLOWUP_REQUEST_PATH, request_payload)
    return request_payload


def _record_count(payload: Any) -> int:
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return len(payload["records"])
    if isinstance(payload, list):
        return len(payload)
    return 0


def _build_pipeline_result(state: dict[str, Any], config: dict[str, Any], agent_message: str) -> dict[str, Any]:
    pipeline = [
        "vuln_collector_agent" if state.get("vuln_stage") else None,
        "infra_matching_agent" if state.get("asset_stage") else None,
        "risk_evaluation_agent" if state.get("risk_stage") else None,
        "patch_impact_agent_stage1" if state.get("patch_pre_stage") else None,
        "patch_impact_agent_followup" if state.get("followup_stage") else None,
        "patch_impact_agent_stage3" if state.get("patch_final_stage") else None,
    ]
    result = {
        "agent": "orchestrator_agent",
        "mode": config["mode"],
        "orchestration_style": config.get("orchestration_style", "direct_pipeline"),
        "generated_at": _utc_now(),
        "stack_name": config["stack_name"],
        "region": config["region"],
        "pipeline": [step for step in pipeline if step],
        "handoff_summary": {
            "vuln_to_asset": ["asset_matching_payload"],
            "asset_to_risk": ["infra_context"],
            "vuln_to_risk": ["risk_assessment_payload"],
            "asset_to_patch": ["infra_context"],
            "vuln_to_patch": ["operational_impact_payload"],
            "risk_to_patch": ["risk_evaluation_result"],
        },
        "agent_message": agent_message,
        "vuln_stage": state.get("vuln_stage"),
        "asset_stage": state.get("asset_stage"),
        "risk_stage": state.get("risk_stage"),
        "patch_pre_stage": state.get("patch_pre_stage"),
        "followup_stage": state.get("followup_stage"),
        "patch_final_stage": state.get("patch_final_stage"),
        "artifacts": {
            "patch_pre_path": str(PATCH_PRE_RESULT_PATH),
            "patch_followup_request_path": str(PATCH_FOLLOWUP_REQUEST_PATH),
            "patch_followup_response_path": str(PATCH_FOLLOWUP_RESULT_PATH),
            "patch_final_path": str(PATCH_FINAL_RESULT_PATH),
            "pipeline_result_path": str(PIPELINE_RESULT_PATH),
        },
        "test_interface": {
            "stop_stage": config.get("stop_stage"),
            "injected_state": config.get("injected_state", []),
        },
    }
    _write_json(PIPELINE_RESULT_PATH, result)
    return result


def _resolve_asset_matching_payload(state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    vuln_stage = state.get("vuln_stage")
    if isinstance(vuln_stage, dict) and isinstance(vuln_stage.get("asset_matching_payload"), dict):
        return vuln_stage["asset_matching_payload"]
    value = _pick_payload_value(payload, "asset_matching_payload")
    if isinstance(value, dict):
        return value
    raise ValueError("asset_only 모드는 asset_matching_payload 가 필요합니다.")


def _resolve_infra_context(state: dict[str, Any], payload: dict[str, Any], *, field_name: str) -> dict[str, Any]:
    asset_stage = state.get("asset_stage")
    if isinstance(asset_stage, dict) and isinstance(asset_stage.get("result"), dict):
        return asset_stage["result"]
    value = _pick_payload_value(payload, field_name)
    if isinstance(value, dict):
        return value
    raise ValueError(f"{field_name} 가 필요합니다.")


def _resolve_risk_assessment_payload(state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    vuln_stage = state.get("vuln_stage")
    if isinstance(vuln_stage, dict) and isinstance(vuln_stage.get("risk_assessment_payload"), dict):
        return vuln_stage["risk_assessment_payload"]
    value = _pick_payload_value(payload, "risk_assessment_payload")
    if isinstance(value, dict):
        return value
    raise ValueError("risk_only 모드는 risk_assessment_payload 가 필요합니다.")


def _resolve_risk_result(state: dict[str, Any], payload: dict[str, Any]) -> Any:
    risk_stage = state.get("risk_stage")
    if isinstance(risk_stage, dict):
        risk_result = risk_stage.get("result")
        if isinstance(risk_result, (dict, list)):
            return risk_result
    value = _pick_payload_value(payload, "risk_result")
    if isinstance(value, (dict, list)):
        return value
    raise ValueError("patch_only 모드는 risk_result 가 필요합니다.")


def _resolve_operational_payload(state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    vuln_stage = state.get("vuln_stage")
    if isinstance(vuln_stage, dict) and isinstance(vuln_stage.get("operational_impact_payload"), dict):
        return vuln_stage["operational_impact_payload"]
    value = _pick_payload_value(payload, "operational_payload") or _pick_payload_value(payload, "operational_impact_payload")
    if isinstance(value, dict):
        return value
    raise ValueError("patch_only 모드는 operational_payload 가 필요합니다.")


def _should_execute(stop_stage: str | None, stage_name: str) -> bool:
    if not stop_stage:
        return True
    return STAGE_ORDER[stage_name] <= STAGE_ORDER[stop_stage]


def run_asset_only(payload: dict[str, Any]) -> dict[str, Any]:
    config = _build_config(payload)
    state = _seed_state(payload)
    config["injected_state"] = list(state.keys())
    state["asset_stage"] = run_asset_stage(
        stack_name=config["stack_name"],
        region=config["region"],
        asset_matching_payload=_resolve_asset_matching_payload(state, payload),
        infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
    )["asset_stage"]
    return _build_pipeline_result(state, config, "asset_only 모드 실행 완료")


def run_vuln_only(payload: dict[str, Any]) -> dict[str, Any]:
    config = _build_config(payload)
    state = _seed_state(payload)
    config["injected_state"] = list(state.keys())
    if "vuln_stage" not in state:
        state["vuln_stage"] = run_vuln_stage()["vuln_stage"]
    return _build_pipeline_result(state, config, "vuln_only 모드 실행 완료")


def run_risk_only(payload: dict[str, Any]) -> dict[str, Any]:
    config = _build_config(payload)
    state = _seed_state(payload)
    config["injected_state"] = list(state.keys())
    state["risk_stage"] = run_risk_stage(
        region=config["region"],
        infra_context=_resolve_infra_context(state, payload, field_name="infra_context"),
        risk_assessment_payload=_resolve_risk_assessment_payload(state, payload),
        infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
    )["risk_stage"]
    return _build_pipeline_result(state, config, "risk_only 모드 실행 완료")


def run_patch_only(payload: dict[str, Any]) -> dict[str, Any]:
    config = _build_config(payload)
    state = _seed_state(payload)
    injected_request = _write_injected_followup_request(payload)
    config["injected_state"] = list(state.keys())

    if "patch_pre_stage" not in state:
        state["patch_pre_stage"] = run_patch_pre_stage(
            region=config["region"],
            infra_context=_resolve_infra_context(state, payload, field_name="infra_context"),
            risk_result=_resolve_risk_result(state, payload),
            operational_payload=_resolve_operational_payload(state, payload),
            patch_impact_runtime_arn=config["patch_impact_runtime_arn"],
        )["patch_pre_stage"]

    request_count = int((injected_request or {}).get("request_count", _load_followup_request_count()))
    if request_count > 0 and not config["allow_followup"]:
        return _build_pipeline_result(state, config, "patch_only 모드 실행 완료 (follow-up 비활성화로 patch_pre 에서 종료)")

    if config["allow_followup"] and request_count > 0 and "followup_stage" not in state:
        state["followup_stage"] = run_patch_followup_stage(
            region=config["region"],
            infra_context=_resolve_infra_context(state, payload, field_name="infra_context"),
            prejudge_result=state.get("patch_pre_stage", {}).get("result"),
            requests=(injected_request or {}).get("requests"),
            infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
            patch_impact_runtime_arn=config["patch_impact_runtime_arn"],
        )["followup_stage"]

    state["patch_final_stage"] = run_patch_finalize_stage(
        region=config["region"],
        prejudge_result=state.get("patch_pre_stage", {}).get("result"),
        additional_asset_context=state.get("followup_stage"),
        patch_impact_runtime_arn=config["patch_impact_runtime_arn"],
    )["patch_final_stage"]
    return _build_pipeline_result(state, config, "patch_only 모드 실행 완료")


def run_orchestrator(payload: dict[str, Any]) -> dict[str, Any]:
    config = _build_config(payload)
    state = _seed_state(payload)
    injected_request = _write_injected_followup_request(payload)
    config["injected_state"] = list(state.keys())

    stop_stage = config["stop_stage"]

    if _should_execute(stop_stage, "vuln") and "vuln_stage" not in state:
        state["vuln_stage"] = run_vuln_stage()["vuln_stage"]
    if stop_stage == "vuln":
        return _build_pipeline_result(state, config, "vuln 단계까지 실행 완료")

    if _should_execute(stop_stage, "asset") and "asset_stage" not in state:
        state["asset_stage"] = run_asset_stage(
            stack_name=config["stack_name"],
            region=config["region"],
            asset_matching_payload=_resolve_asset_matching_payload(state, payload),
            infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
        )["asset_stage"]
    if stop_stage == "asset":
        return _build_pipeline_result(state, config, "asset 단계까지 실행 완료")

    if _should_execute(stop_stage, "risk") and "risk_stage" not in state:
        state["risk_stage"] = run_risk_stage(
            region=config["region"],
            infra_context=_resolve_infra_context(state, payload, field_name="infra_context"),
            risk_assessment_payload=_resolve_risk_assessment_payload(state, payload),
            infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
        )["risk_stage"]
    if stop_stage == "risk":
        return _build_pipeline_result(state, config, "risk 단계까지 실행 완료")

    if _should_execute(stop_stage, "patch_pre") and "patch_pre_stage" not in state:
        state["patch_pre_stage"] = run_patch_pre_stage(
            region=config["region"],
            infra_context=_resolve_infra_context(state, payload, field_name="infra_context"),
            risk_result=_resolve_risk_result(state, payload),
            operational_payload=_resolve_operational_payload(state, payload),
            patch_impact_runtime_arn=config["patch_impact_runtime_arn"],
        )["patch_pre_stage"]
    if stop_stage == "patch_pre":
        return _build_pipeline_result(state, config, "patch_pre 단계까지 실행 완료")

    request_count = int((injected_request or {}).get("request_count", _load_followup_request_count()))
    if request_count > 0 and not config["allow_followup"]:
        return _build_pipeline_result(state, config, "follow-up 비활성화로 patch_pre 에서 종료")

    if (
        _should_execute(stop_stage, "patch_followup")
        and config["allow_followup"]
        and request_count > 0
        and "followup_stage" not in state
    ):
        state["followup_stage"] = run_patch_followup_stage(
            region=config["region"],
            infra_context=_resolve_infra_context(state, payload, field_name="infra_context"),
            prejudge_result=state.get("patch_pre_stage", {}).get("result"),
            requests=(injected_request or {}).get("requests"),
            infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
            patch_impact_runtime_arn=config["patch_impact_runtime_arn"],
        )["followup_stage"]
    if stop_stage == "patch_followup":
        return _build_pipeline_result(state, config, "patch_followup 단계까지 실행 완료")

    if _should_execute(stop_stage, "patch_final") and "patch_final_stage" not in state:
        state["patch_final_stage"] = run_patch_finalize_stage(
            region=config["region"],
            prejudge_result=state.get("patch_pre_stage", {}).get("result"),
            additional_asset_context=state.get("followup_stage"),
            patch_impact_runtime_arn=config["patch_impact_runtime_arn"],
        )["patch_final_stage"]

    return _build_pipeline_result(state, config, "full/test 모드 실행 완료")


def invoke(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("payload는 JSON object 형태여야 합니다.")
    mode = _resolve_mode(payload)
    if mode == "asset_only":
        return run_asset_only(payload)
    if mode == "vuln_only":
        return run_vuln_only(payload)
    if mode == "risk_only":
        return run_risk_only(payload)
    if mode == "patch_only":
        return run_patch_only(payload)
    return run_orchestrator(payload)
