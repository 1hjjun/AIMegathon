from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AGENT_ROOT = Path(__file__).resolve().parent
RUNTIME_ROOT = Path(os.environ.get("MULTIAI_RUNTIME_ROOT") or "/tmp/multiai")
STAGE2_RESULT_DIR = RUNTIME_ROOT / "OutputResult" / "PatchImAgent" / "stage2_followup"
TRACE_DIR = STAGE2_RESULT_DIR / "deep_conversations"
DEFAULT_FOLLOWUP_REQUEST_PATH = STAGE2_RESULT_DIR / "additional_asset_request.json"
DEFAULT_FOLLOWUP_RESULT_PATH = RUNTIME_ROOT / "OutputResult" / "SwarmAgent" / "additional_asset_response.json"
DEFAULT_INFRA_MATCHING_RUNTIME_ARN = (
    "arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/"
    "asset_matching_agent-zoDcgCEt8u"
)
INFRA_MATCHING_RUNTIME_ARN_ENV_KEYS = (
    "INFRA_MATCHING_AGENTCORE_ARN",
    "ASSET_MATCHING_AGENTCORE_ARN",
    "ASSET_MATCHING_ARN",
)

_AGENTCORE_CLIENT: Any | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_string(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text or default


def _normalize_text_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        text = value.strip()
        if text:
            return [text]
    return []


def _normalize_question_type(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    allowed = {
        "dependency_check",
        "shaded_copy_check",
        "config_compatibility",
        "restart_requirement",
        "rollback_check",
        "deployment_binding",
        "patch_followup",
    }
    return normalized if normalized in allowed else "patch_followup"


def _normalize_confidence(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"high", "medium", "low"}:
        return normalized
    return "low"


def _normalize_truth_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    normalized = str(value or "").strip().lower()
    if normalized in {"true", "false", "unknown"}:
        return normalized
    if normalized in {"yes", "y", "confirmed", "required"}:
        return "true"
    if normalized in {"no", "n", "not_required"}:
        return "false"
    return "unknown"


def _save_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _agentcore_client(region: str) -> Any:
    global _AGENTCORE_CLIENT
    if _AGENTCORE_CLIENT is None:
        import boto3
        from botocore.config import Config

        _AGENTCORE_CLIENT = boto3.client(
            "bedrock-agentcore",
            region_name=region,
            config=Config(read_timeout=900, connect_timeout=10),
        )
    return _AGENTCORE_CLIENT


def _resolve_infra_matching_runtime_arn(runtime_arn: str | None = None) -> str:
    direct = str(runtime_arn or "").strip()
    if direct:
        return direct
    for key in INFRA_MATCHING_RUNTIME_ARN_ENV_KEYS:
        value = str(os.environ.get(key) or "").strip()
        if value:
            return value
    return DEFAULT_INFRA_MATCHING_RUNTIME_ARN


def _extract_json_blob(text: str) -> Any:
    raw = text.strip()
    if not raw:
        return None
    fence_match = re.search(r"```(?:json)?\s*(.*?)```", raw, re.DOTALL)
    if fence_match:
        raw = fence_match.group(1).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for idx, ch in enumerate(raw):
        if ch not in "[{":
            continue
        try:
            parsed, _ = decoder.raw_decode(raw[idx:])
            return parsed
        except json.JSONDecodeError:
            continue
    return None


def _lookup_asset(infra_context: dict[str, Any], instance_id: str) -> dict[str, Any]:
    for asset in infra_context.get("assets", []) if isinstance(infra_context, dict) else []:
        if isinstance(asset, dict) and str(asset.get("asset_id") or "").strip() == instance_id:
            return asset
    return {}


def _compact_asset(asset: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for key in (
        "asset_id",
        "hostname",
        "tier",
        "availability_zone",
        "private_ip",
        "public_ip",
        "metadata",
        "installed_software",
    ):
        value = asset.get(key)
        if value not in (None, "", [], {}):
            compact[key] = value
    return compact


def _normalize_question_items(request: dict[str, Any]) -> list[dict[str, str]]:
    candidates = request.get("questions")
    if not isinstance(candidates, list):
        return []
    normalized: list[dict[str, str]] = []
    for item in candidates:
        if isinstance(item, dict):
            prompt = _safe_string(item.get("prompt") or item.get("question"))
            question_type = _normalize_question_type(item.get("question_type"))
            if prompt:
                normalized.append({"question": prompt, "question_type": question_type})
            continue
        prompt = _safe_string(item)
        if prompt:
            normalized.append({"question": prompt, "question_type": "patch_followup"})
    return normalized


def _invoke_infra_matching_query(
    runtime_arn: str,
    *,
    asset_info: dict[str, Any],
    question: str,
    instance_id: str,
    region: str,
) -> dict[str, Any]:
    payload = {
        "mode": "query",
        "region": region,
        "instance_id": instance_id,
        "asset_info": asset_info,
        "question": question,
    }
    response = _agentcore_client(region).invoke_agent_runtime(
        agentRuntimeArn=runtime_arn,
        payload=json.dumps(payload).encode("utf-8"),
    )
    raw = response["response"].read()
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    return {
        "result": "unknown",
        "answer": raw.decode("utf-8", errors="replace"),
        "evidence": [],
        "confidence": "low",
    }


def _coerce_query_answer_payload(
    result: dict[str, Any],
    *,
    instance_id: str,
    question_type: str,
) -> dict[str, Any]:
    answer = result.get("answer")
    parsed_answer = result.get("parsed_answer")
    if isinstance(parsed_answer, dict):
        normalized = dict(parsed_answer)
    elif isinstance(answer, str) and isinstance(_extract_json_blob(answer), dict):
        normalized = dict(_extract_json_blob(answer))
    else:
        normalized = {}

    normalized["instance_id"] = _safe_string(normalized.get("instance_id"), instance_id)
    normalized["question_type"] = _normalize_question_type(normalized.get("question_type") or question_type)
    normalized["result"] = _safe_string(normalized.get("result"), _safe_string(result.get("result"), "unknown")).lower() or "unknown"
    normalized["answer"] = _safe_string(normalized.get("answer"), _safe_string(answer, ""))
    normalized["details"] = normalized.get("details") if isinstance(normalized.get("details"), dict) else {}
    normalized["evidence"] = _normalize_text_list(normalized.get("evidence") or result.get("evidence"))
    normalized["confidence"] = _normalize_confidence(normalized.get("confidence") or result.get("confidence"))
    return normalized


def _merge_followup_answers(
    *,
    request: dict[str, Any],
    transcript: list[dict[str, Any]],
) -> dict[str, Any]:
    details: dict[str, Any] = {}
    evidences: list[str] = []
    seen_evidence: set[str] = set()
    uncertainties: list[str] = []
    next_questions: list[str] = []
    confidence_rank = {"low": 1, "medium": 2, "high": 3}
    best_confidence = "low"
    results: list[str] = []
    answer_parts: list[str] = []

    for turn in transcript:
        parsed = turn.get("parsed_answer") if isinstance(turn.get("parsed_answer"), dict) else {}
        result = _safe_string(parsed.get("result"), "unknown").lower()
        if result:
            results.append(result)
        answer_text = _safe_string(parsed.get("answer"))
        if answer_text:
            answer_parts.append(answer_text)
        confidence = _normalize_confidence(parsed.get("confidence"))
        if confidence_rank[confidence] > confidence_rank[best_confidence]:
            best_confidence = confidence

        parsed_details = parsed.get("details") if isinstance(parsed.get("details"), dict) else {}
        details.update(parsed_details)
        question_type = _normalize_question_type(parsed.get("question_type") or turn.get("question_type"))
        if question_type == "dependency_check" and "dependency_type" not in details:
            details["dependency_type"] = _safe_string(parsed_details.get("dependency_type"), "unknown")
        elif question_type == "config_compatibility":
            if "config_compatibility_notes" not in details:
                details["config_compatibility_notes"] = _safe_string(parsed_details.get("notes"), answer_text or "unknown")
            if "compatibility" not in details:
                details["compatibility"] = _safe_string(parsed_details.get("compatibility"), "unknown")
        elif question_type == "restart_requirement" and "restart_required" not in details:
            details["restart_required"] = _normalize_truth_value(parsed_details.get("restart_required"))
        elif question_type == "rollback_check" and "rollback_available" not in details:
            details["rollback_available"] = _normalize_truth_value(parsed_details.get("rollback_available"))
        elif question_type == "deployment_binding" and "load_balancer_binding" not in details:
            details["load_balancer_binding"] = _safe_string(parsed_details.get("load_balancer_binding"), "unknown")
        elif question_type == "shaded_copy_check":
            for key in ("shaded_copy_present", "build_manifest_found", "dynamic_modules_in_use"):
                if key not in details and key in parsed_details:
                    details[key] = parsed_details.get(key)

        for evidence in _normalize_text_list(parsed.get("evidence")):
            if evidence not in seen_evidence:
                seen_evidence.add(evidence)
                evidences.append(evidence)

        if result not in {"confirmed", "not_applicable"} and answer_text:
            uncertainties.append(answer_text)
        for question in _normalize_text_list(parsed.get("recommended_next_questions")):
            if question not in next_questions:
                next_questions.append(question)

    details.setdefault("summary", " ".join(answer_parts) if answer_parts else "추가 자산 정보가 충분하지 않습니다.")
    details.setdefault("dependency_type", "unknown")
    details.setdefault("compatibility", "unknown")
    details.setdefault("restart_required", "unknown")
    details.setdefault("rollback_available", "unknown")
    details.setdefault("config_compatibility_notes", "unknown")
    details.setdefault("load_balancer_binding", "unknown")

    final_result = "inconclusive"
    if results and all(item == "not_applicable" for item in results):
        final_result = "not_applicable"
    elif results and all(item == "confirmed" for item in results):
        final_result = "confirmed"
    elif "confirmed" in results and not any(item in {"unknown", "inconclusive"} for item in results):
        final_result = "confirmed"

    return {
        "instance_id": _safe_string(request.get("instance_id")),
        "question_type": "patch_followup",
        "result": final_result,
        "answer": details["summary"],
        "details": details,
        "evidence": evidences,
        "confidence": best_confidence,
        "remaining_uncertainties": uncertainties,
        "recommended_next_questions": next_questions,
    }


def _run_single_followup_request(
    *,
    request: dict[str, Any],
    infra_context: dict[str, Any],
    region: str,
    infra_matching_runtime_arn: str,
) -> dict[str, Any]:
    request_id = _safe_string(request.get("request_id"), f"followup-{uuid.uuid4().hex[:12]}")
    instance_id = _safe_string(request.get("instance_id"))
    asset_info = _compact_asset(_lookup_asset(infra_context, instance_id))
    questions = _normalize_question_items(request)
    transcript: list[dict[str, Any]] = []

    for turn_number, question_item in enumerate(questions, start=1):
        try:
            remote_result = _invoke_infra_matching_query(
                infra_matching_runtime_arn,
                asset_info=asset_info,
                question=question_item["question"],
                instance_id=instance_id,
                region=region,
            )
            parsed_answer = _coerce_query_answer_payload(
                remote_result,
                instance_id=instance_id,
                question_type=question_item["question_type"],
            )
        except Exception as exc:  # noqa: BLE001
            parsed_answer = {
                "instance_id": instance_id,
                "question_type": _normalize_question_type(question_item["question_type"]),
                "result": "inconclusive",
                "answer": f"asset runtime query failed: {type(exc).__name__}: {exc}",
                "details": {
                    "query_error": f"{type(exc).__name__}: {exc}",
                },
                "evidence": [],
                "confidence": "low",
                "recommended_next_questions": [],
            }
        transcript.append({
            "turn": turn_number,
            "question_type": question_item["question_type"],
            "question": question_item["question"],
            "parsed_answer": parsed_answer,
        })

    final_parsed_answer = _merge_followup_answers(request=request, transcript=transcript)
    trace = {
        "agent": "patch_impact_agent_followup",
        "generated_at": _utc_now(),
        "request_id": request_id,
        "request": request,
        "asset_info": asset_info,
        "tool_rounds_used": len(transcript),
        "transcript": transcript,
        "final_parsed_answer": final_parsed_answer,
    }
    trace_path = TRACE_DIR / f"{request_id}.json"
    _save_json(trace_path, trace)
    return {
        "request_id": request_id,
        "source_agent": _safe_string(request.get("source_agent"), "patch_impact_agent"),
        "target_agent": _safe_string(request.get("target_agent"), "infra_matching_agent"),
        "cve_id": _safe_string(request.get("cve_id")),
        "instance_id": instance_id,
        "question_bundle": request,
        "response": {
            "agent": "patch_impact_agent_followup",
            "status": "ok",
            "request_id": request_id,
            "conversation_trace_path": str(trace_path),
            "tool_rounds_used": len(transcript),
            "asset_info": asset_info,
            "transcript": transcript,
            "result": {
                "parsed_answer": final_parsed_answer,
            },
        },
    }


def run_patch_followup_conversation(
    *,
    requests: Any = None,
    prejudge_result: dict[str, Any] | None = None,
    infra_context: dict[str, Any] | None = None,
    region: str = "ap-northeast-2",
    infra_matching_runtime_arn: str | None = None,
    save_path: str | Path | None = None,
) -> dict[str, Any]:
    del prejudge_result

    if not isinstance(infra_context, dict):
        infra_context = {}
    resolved_requests = requests
    if isinstance(resolved_requests, dict):
        resolved_requests = resolved_requests.get("requests")
    if not isinstance(resolved_requests, list):
        loaded = _load_json(DEFAULT_FOLLOWUP_REQUEST_PATH, {"requests": []})
        resolved_requests = loaded.get("requests") if isinstance(loaded, dict) else []
    if not isinstance(resolved_requests, list):
        resolved_requests = []

    runtime_arn = _resolve_infra_matching_runtime_arn(infra_matching_runtime_arn)
    responses = []
    for request in resolved_requests:
        if not isinstance(request, dict):
            continue
        responses.append(
            _run_single_followup_request(
                request=request,
                infra_context=infra_context,
                region=region,
                infra_matching_runtime_arn=runtime_arn,
            )
        )

    final_payload = {
        "generated_at": _utc_now(),
        "response_count": len(responses),
        "responses": responses,
    }
    target_path = Path(save_path) if save_path else DEFAULT_FOLLOWUP_RESULT_PATH
    _save_json(target_path, final_payload)
    return final_payload
