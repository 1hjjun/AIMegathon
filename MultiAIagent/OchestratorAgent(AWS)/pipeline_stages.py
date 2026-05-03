from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime_agents import run_agent


RUNTIME_ROOT = Path(os.environ.get("MULTIAI_RUNTIME_ROOT") or "/tmp/multiai")
ASSET_OUTPUT_DIR = RUNTIME_ROOT / "OutputResult" / "AssetAgent"
VULN_OUTPUT_DIR = RUNTIME_ROOT / "OutputResult" / "VulAgent"
RISK_OUTPUT_DIR = RUNTIME_ROOT / "OutputResult" / "RiskevalAgent"
PATCH_OUTPUT_DIR = RUNTIME_ROOT / "OutputResult" / "PatchImAgent"
SWARM_OUTPUT_DIR = RUNTIME_ROOT / "OutputResult" / "SwarmAgent"

PIPELINE_RESULT_PATH = SWARM_OUTPUT_DIR / "pipeline_result.json"
PATCH_FOLLOWUP_RESULT_PATH = SWARM_OUTPUT_DIR / "additional_asset_response.json"
PATCH_PRE_RESULT_PATH = PATCH_OUTPUT_DIR / "stage1_prejudge" / "patch_impact_prejudge_result.json"
PATCH_FOLLOWUP_REQUEST_PATH = PATCH_OUTPUT_DIR / "stage2_followup" / "additional_asset_request.json"
PATCH_FINAL_RESULT_PATH = PATCH_OUTPUT_DIR / "stage3_final" / "patch_impact_final_result.json"
ASSET_INFRA_CONTEXT_PATH = ASSET_OUTPUT_DIR / "infra_context.json"
VULN_RAW_OUTPUT_PATH = VULN_OUTPUT_DIR / "focused_selected_raw_cves.json"
VULN_RISK_PAYLOAD_PATH = VULN_OUTPUT_DIR / "risk_assessment_payloads.json"
VULN_OPERATIONAL_PAYLOAD_PATH = VULN_OUTPUT_DIR / "operational_impact_payloads.json"
VULN_ASSET_MATCHING_PAYLOAD_PATH = VULN_OUTPUT_DIR / "asset_matching_payload.json"
RISK_RESULT_PATH = RISK_OUTPUT_DIR / "risk_evaluation_result.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _load_followup_request(path: Path | None = None) -> dict[str, Any]:
    return _load_json(path or PATCH_FOLLOWUP_REQUEST_PATH, {"requests": [], "request_count": 0})


def run_vuln_stage() -> dict[str, Any]:
    vuln_stage = run_agent("vuln_collector_agent", {
        "action": "collect_vulnerabilities",
        "raw_output_path": str(VULN_RAW_OUTPUT_PATH),
        "risk_output_path": str(VULN_RISK_PAYLOAD_PATH),
        "operational_output_path": str(VULN_OPERATIONAL_PAYLOAD_PATH),
        "asset_matching_output_path": str(VULN_ASSET_MATCHING_PAYLOAD_PATH),
    })
    return {
        "agent": "orchestrator_pipeline",
        "stage": "vuln",
        "generated_at": _utc_now(),
        "vuln_stage": vuln_stage,
    }


def run_asset_stage(
    *,
    stack_name: str,
    region: str,
    asset_matching_payload: dict[str, Any],
    infra_matching_runtime_arn: str | None = None,
) -> dict[str, Any]:
    asset_stage = run_agent("infra_matching_agent", {
        "action": "bootstrap_asset_context",
        "stack_name": stack_name,
        "region": region,
        "asset_matching_payload": asset_matching_payload,
        "infra_matching_runtime_arn": infra_matching_runtime_arn,
        "save_path": str(ASSET_INFRA_CONTEXT_PATH),
    })
    return {
        "agent": "orchestrator_pipeline",
        "stage": "asset",
        "generated_at": _utc_now(),
        "asset_stage": asset_stage,
    }


def run_risk_stage(
    *,
    region: str,
    infra_context: dict[str, Any] | None = None,
    risk_assessment_payload: dict[str, Any] | None = None,
    infra_matching_runtime_arn: str | None = None,
) -> dict[str, Any]:
    risk_stage = run_agent("risk_evaluation_agent", {
        "action": "evaluate_risk",
        "region": region,
        "infra_context": infra_context if isinstance(infra_context, dict) else _load_json(ASSET_INFRA_CONTEXT_PATH, {}),
        "risk_assessment_payload": risk_assessment_payload if isinstance(risk_assessment_payload, dict) else _load_json(VULN_RISK_PAYLOAD_PATH, {}),
        "infra_matching_runtime_arn": infra_matching_runtime_arn,
        "save_path": str(RISK_RESULT_PATH),
    })
    return {
        "agent": "orchestrator_pipeline",
        "stage": "risk",
        "generated_at": _utc_now(),
        "risk_stage": risk_stage,
    }


def run_patch_pre_stage(
    *,
    region: str,
    infra_context: dict[str, Any] | None = None,
    risk_result: dict[str, Any] | list[Any] | None = None,
    operational_payload: dict[str, Any] | None = None,
    patch_impact_runtime_arn: str | None = None,
) -> dict[str, Any]:
    resolved_infra_context = infra_context if isinstance(infra_context, dict) else _load_json(ASSET_INFRA_CONTEXT_PATH, {})
    resolved_risk_result = risk_result if isinstance(risk_result, (dict, list)) else _load_json(RISK_RESULT_PATH, {})
    resolved_operational_payload = operational_payload if isinstance(operational_payload, dict) else _load_json(VULN_OPERATIONAL_PAYLOAD_PATH, {})
    patch_pre_stage = run_agent("patch_impact_agent", {
        "action": "evaluate_patch_impact",
        "region": region,
        "patch_impact_runtime_arn": patch_impact_runtime_arn,
        "infra_context": resolved_infra_context,
        "risk_result": resolved_risk_result,
        "operational_payload": resolved_operational_payload,
        "debug_risk_result_count_hint": len(resolved_risk_result) if isinstance(resolved_risk_result, list) else len(resolved_risk_result.get("records", [])) if isinstance(resolved_risk_result, dict) and isinstance(resolved_risk_result.get("records"), list) else 0,
        "debug_infra_asset_count_hint": len(resolved_infra_context.get("assets", [])) if isinstance(resolved_infra_context, dict) and isinstance(resolved_infra_context.get("assets"), list) else 0,
        "save_path": str(PATCH_PRE_RESULT_PATH),
        "additional_request_path": str(PATCH_FOLLOWUP_REQUEST_PATH),
    })
    return {
        "agent": "orchestrator_pipeline",
        "stage": "patch_pre",
        "generated_at": _utc_now(),
        "patch_pre_stage": patch_pre_stage,
    }


def run_patch_followup_stage(
    *,
    region: str,
    infra_context: dict[str, Any] | None = None,
    prejudge_result: dict[str, Any] | None = None,
    requests: list[dict[str, Any]] | None = None,
    infra_matching_runtime_arn: str | None = None,
    patch_impact_runtime_arn: str | None = None,
) -> dict[str, Any]:
    additional_request = {"requests": requests, "request_count": len(requests)} if isinstance(requests, list) else _load_followup_request()
    patch_followup_stage = run_agent("patch_impact_agent", {
        "action": "run_followup_conversation",
        "region": region,
        "patch_impact_runtime_arn": patch_impact_runtime_arn,
        "infra_matching_runtime_arn": infra_matching_runtime_arn,
        "prejudge_result": prejudge_result if isinstance(prejudge_result, dict) else {},
        "infra_context": infra_context if isinstance(infra_context, dict) else _load_json(ASSET_INFRA_CONTEXT_PATH, {}),
        "requests": additional_request.get("requests", []) if isinstance(additional_request.get("requests"), list) else [],
        "save_path": str(PATCH_FOLLOWUP_RESULT_PATH),
    })
    final_payload = patch_followup_stage.get("result") if isinstance(patch_followup_stage.get("result"), dict) else {}
    return {
        "agent": "orchestrator_pipeline",
        "stage": "patch_followup",
        "generated_at": _utc_now(),
        "followup_stage": final_payload,
    }


def run_patch_finalize_stage(
    *,
    region: str,
    prejudge_result: dict[str, Any] | None = None,
    additional_asset_context: dict[str, Any] | None = None,
    patch_impact_runtime_arn: str | None = None,
) -> dict[str, Any]:
    patch_final_stage = run_agent("patch_impact_agent", {
        "action": "finalize_patch_impact",
        "region": region,
        "patch_impact_runtime_arn": patch_impact_runtime_arn,
        "prejudge_result": prejudge_result if isinstance(prejudge_result, dict) else _load_json(PATCH_PRE_RESULT_PATH, {}),
        "additional_asset_context": additional_asset_context if isinstance(additional_asset_context, dict) else _load_json(PATCH_FOLLOWUP_RESULT_PATH, {}),
        "save_path": str(PATCH_FINAL_RESULT_PATH),
    })
    return {
        "agent": "orchestrator_pipeline",
        "stage": "patch_final",
        "generated_at": _utc_now(),
        "patch_final_stage": patch_final_stage,
    }
