from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


MODULE_ROOT = Path(__file__).resolve().parent
RUNTIME_ROOT = Path(os.environ.get("MULTIAI_RUNTIME_ROOT") or "/tmp/multiai")
OUTPUT_ROOT = RUNTIME_ROOT / "OutputResult"
ASSET_OUTPUT_DIR = OUTPUT_ROOT / "AssetAgent"
VULN_OUTPUT_DIR = OUTPUT_ROOT / "VulAgent"
RISK_OUTPUT_DIR = OUTPUT_ROOT / "RiskevalAgent"
PATCH_OUTPUT_DIR = OUTPUT_ROOT / "PatchImAgent"
SWARM_OUTPUT_DIR = OUTPUT_ROOT / "SwarmAgent"

ASSET_INFRA_CONTEXT_PATH = ASSET_OUTPUT_DIR / "infra_context.json"
VULN_RAW_OUTPUT_PATH = VULN_OUTPUT_DIR / "focused_selected_raw_cves.json"
VULN_RISK_PAYLOAD_PATH = VULN_OUTPUT_DIR / "risk_assessment_payloads.json"
VULN_OPERATIONAL_PAYLOAD_PATH = VULN_OUTPUT_DIR / "operational_impact_payloads.json"
VULN_ASSET_MATCHING_PAYLOAD_PATH = VULN_OUTPUT_DIR / "asset_matching_payload.json"
RISK_RESULT_PATH = RISK_OUTPUT_DIR / "risk_evaluation_result.json"
PATCH_PRE_RESULT_PATH = PATCH_OUTPUT_DIR / "stage1_prejudge" / "patch_impact_prejudge_result.json"
PATCH_FOLLOWUP_REQUEST_PATH = PATCH_OUTPUT_DIR / "stage2_followup" / "additional_asset_request.json"
PATCH_FINAL_RESULT_PATH = PATCH_OUTPUT_DIR / "stage3_final" / "patch_impact_final_result.json"
PATCH_FOLLOWUP_RESULT_PATH = SWARM_OUTPUT_DIR / "additional_asset_response.json"

DEFAULT_REGION = "ap-northeast-2"
DEFAULT_STACK_NAME = os.environ.get("CF_STACK_NAME", "megathon")
DEFAULT_AGENTCORE_READ_TIMEOUT = int(os.environ.get("AGENTCORE_READ_TIMEOUT", "900"))
DEFAULT_AGENTCORE_CONNECT_TIMEOUT = int(os.environ.get("AGENTCORE_CONNECT_TIMEOUT", "10"))
DEFAULT_INFRA_MATCHING_RUNTIME_ARN = (
    "arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/"
    "asset_matching_agent-zoDcgCEt8u"
)
DEFAULT_VULN_COLLECTOR_RUNTIME_ARN = (
    "arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/"
    "vul_collector_agent-JMTqI0Do5W"
)
DEFAULT_RISK_EVAL_RUNTIME_ARN = (
    "arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/"
    "risk_evaluation_agent-A2PkRd5CzC"
)
DEFAULT_PATCH_IMPACT_RUNTIME_ARN = (
    "arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/"
    "patch_impact_container-qNIi2mCjRa"
)

INFRA_MATCHING_RUNTIME_ARN_ENV_KEYS = (
    "INFRA_MATCHING_AGENTCORE_ARN",
    "ASSET_MATCHING_AGENTCORE_ARN",
    "ASSET_MATCHING_ARN",
)
VULN_COLLECTOR_RUNTIME_ARN_ENV_KEYS = (
    "VULN_COLLECTOR_AGENTCORE_ARN",
    "VULN_COLLECTOR_ARN",
)
RISK_EVAL_RUNTIME_ARN_ENV_KEYS = (
    "RISK_EVAL_AGENTCORE_ARN",
    "RISK_EVAL_ARN",
)
PATCH_IMPACT_RUNTIME_ARN_ENV_KEYS = (
    "PATCH_IMPACT_AGENTCORE_ARN",
    "PATCH_IMPACT_ARN",
)

_CLIENT_CACHE: dict[str, Any] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, data: Any) -> Path:
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


def _client(region: str) -> Any:
    client = _CLIENT_CACHE.get(region)
    if client is None:
        client = boto3.client(
            "bedrock-agentcore",
            region_name=region,
            config=Config(
                read_timeout=DEFAULT_AGENTCORE_READ_TIMEOUT,
                connect_timeout=DEFAULT_AGENTCORE_CONNECT_TIMEOUT,
            ),
        )
        _CLIENT_CACHE[region] = client
    return client


def _resolve_runtime_arn(payload: dict[str, Any], direct_keys: tuple[str, ...], env_keys: tuple[str, ...], default: str) -> str:
    for key in direct_keys:
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    for key in env_keys:
        value = str(os.environ.get(key) or "").strip()
        if value:
            return value
    return default


def _resolve_infra_matching_runtime_arn(payload: dict[str, Any]) -> str:
    return _resolve_runtime_arn(
        payload,
        ("infra_matching_runtime_arn", "agent_runtime_arn", "runtime_arn"),
        INFRA_MATCHING_RUNTIME_ARN_ENV_KEYS,
        DEFAULT_INFRA_MATCHING_RUNTIME_ARN,
    )


def _resolve_vuln_collector_runtime_arn(payload: dict[str, Any]) -> str:
    return _resolve_runtime_arn(
        payload,
        ("vuln_collector_runtime_arn", "vuln_runtime_arn"),
        VULN_COLLECTOR_RUNTIME_ARN_ENV_KEYS,
        DEFAULT_VULN_COLLECTOR_RUNTIME_ARN,
    )


def _resolve_risk_evaluation_runtime_arn(payload: dict[str, Any]) -> str:
    return _resolve_runtime_arn(
        payload,
        ("risk_evaluation_runtime_arn", "risk_runtime_arn"),
        RISK_EVAL_RUNTIME_ARN_ENV_KEYS,
        DEFAULT_RISK_EVAL_RUNTIME_ARN,
    )


def _resolve_patch_impact_runtime_arn(payload: dict[str, Any]) -> str:
    return _resolve_runtime_arn(
        payload,
        ("patch_impact_runtime_arn", "patch_runtime_arn"),
        PATCH_IMPACT_RUNTIME_ARN_ENV_KEYS,
        DEFAULT_PATCH_IMPACT_RUNTIME_ARN,
    )


def _invoke_agentcore_runtime(runtime_arn: str, request_payload: dict[str, Any], region: str) -> dict[str, Any]:
    try:
        response = _client(region).invoke_agent_runtime(
            agentRuntimeArn=runtime_arn,
            payload=json.dumps(request_payload).encode("utf-8"),
        )
    except ClientError as exc:
        raise RuntimeError(f"AgentCore 호출 실패 ({runtime_arn.split('/')[-1]}): {exc}") from exc

    raw = response["response"].read()
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        if isinstance(parsed, dict):
            return parsed
        return {"result": parsed}
    except json.JSONDecodeError:
        return {"raw": raw.decode("utf-8", errors="replace")}


def _load_asset_matching_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload.get("asset_matching_payload"), dict):
        return payload["asset_matching_payload"]
    return _load_json(VULN_ASSET_MATCHING_PAYLOAD_PATH, {})


def _load_risk_assessment_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload.get("risk_assessment_payload"), dict):
        return payload["risk_assessment_payload"]
    if isinstance(payload.get("cve_payload"), dict):
        return payload["cve_payload"]
    if isinstance(payload.get("vulnerability_payload"), dict):
        return payload["vulnerability_payload"]
    if isinstance(payload.get("vulnerability_data"), dict):
        return payload["vulnerability_data"]
    return _load_json(VULN_RISK_PAYLOAD_PATH, {})


def _load_infra_context(payload: dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload.get("infra_context"), dict):
        return payload["infra_context"]
    return _load_json(ASSET_INFRA_CONTEXT_PATH, {})


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


def run_infra_matching_agent(payload: dict[str, Any]) -> dict[str, Any]:
    action = str(payload.get("action") or "bootstrap_asset_context").strip().lower()

    runtime_arn = _resolve_infra_matching_runtime_arn(payload)
    if not runtime_arn:
        raise RuntimeError("ASSET_MATCHING_ARN 또는 infra_matching_runtime_arn 설정이 필요합니다.")

    region = str(payload.get("region") or DEFAULT_REGION)

    if action == "query_asset_context":
        asset_info = payload.get("asset_info") if isinstance(payload.get("asset_info"), dict) else {}
        question = str(payload.get("question") or "").strip()
        if not asset_info or not question:
            raise ValueError("query_asset_context 에는 asset_info 와 question 이 필요합니다.")

        remote_payload = {
            "mode": "query",
            "region": region,
            "instance_id": str(payload.get("instance_id") or "").strip() or None,
            "asset_info": asset_info,
            "question": question,
        }
        remote_result = _invoke_agentcore_runtime(runtime_arn, remote_payload, region)
        if "error" in remote_result:
            raise RuntimeError(f"asset_matching_agent query 호출 실패: {remote_result['error']}")

        parsed_answer = None
        answer_text = remote_result.get("answer")
        if isinstance(answer_text, str):
            parsed_answer = _extract_json_blob(answer_text)
        if not isinstance(parsed_answer, dict):
            parsed_answer = {}

        return {
            "agent": "infra_matching_agent",
            "action": action,
            "status": "ok",
            "backend": "agentcore_runtime",
            "runtime_arn": runtime_arn,
            "generated_at": _utc_now(),
            "result": remote_result,
            "parsed_answer": parsed_answer,
        }

    if action != "bootstrap_asset_context":
        raise ValueError(f"지원하지 않는 infra_matching_agent action 입니다: {action}")

    stack_name = str(payload.get("stack_name") or "").strip() or DEFAULT_STACK_NAME
    vpc_id = str(payload.get("vpc_id") or "").strip() or None
    asset_matching_payload = _load_asset_matching_payload(payload)

    remote_payload = {
        "mode": "auto_discover",
        "region": region,
        "cve_payload": asset_matching_payload,
        "metadata": {
            "environment": str(payload.get("environment") or "production"),
            "business_criticality": str(payload.get("business_criticality") or "high"),
        },
    }
    if vpc_id:
        remote_payload["vpc_id"] = vpc_id
    elif stack_name:
        remote_payload["stack_name"] = stack_name
    else:
        raise ValueError("bootstrap_asset_context 에는 stack_name 또는 vpc_id 가 필요합니다.")

    remote_result = _invoke_agentcore_runtime(runtime_arn, remote_payload, region)
    if "error" in remote_result:
        raise RuntimeError(f"asset_matching_agent 호출 실패: {remote_result['error']}")

    infra_context = remote_result.get("infra_context") if isinstance(remote_result.get("infra_context"), dict) else remote_result
    output_path = Path(payload.get("output_path") or ASSET_INFRA_CONTEXT_PATH)
    _write_json(output_path, infra_context)

    return {
        "agent": "infra_matching_agent",
        "action": action,
        "status": "ok",
        "backend": "agentcore_runtime",
        "runtime_arn": runtime_arn,
        "generated_at": _utc_now(),
        "output_path": str(output_path),
        "result": infra_context,
    }


def run_vuln_collector_agent(payload: dict[str, Any]) -> dict[str, Any]:
    action = str(payload.get("action") or "collect_vulnerabilities").strip().lower()
    if action != "collect_vulnerabilities":
        raise ValueError(f"지원하지 않는 vuln_collector_agent action 입니다: {action}")

    runtime_arn = _resolve_vuln_collector_runtime_arn(payload)
    region = str(payload.get("region") or DEFAULT_REGION)
    remote_payload: dict[str, Any] = {}
    opencve_api_key = str(os.environ.get("OPENCVE_API_KEY") or "").strip()
    if opencve_api_key:
        remote_payload["OPENCVE_API_KEY"] = opencve_api_key

    bedrock_model_id = str(os.environ.get("BEDROCK_MODEL_ID") or "").strip()
    if bedrock_model_id:
        remote_payload["BEDROCK_MODEL_ID"] = bedrock_model_id

    remote_result = _invoke_agentcore_runtime(runtime_arn, remote_payload, region)
    if "error" in remote_result:
        raise RuntimeError(f"vuln_collector_agent 호출 실패: {remote_result['error']}")

    raw_dataset = remote_result.get("raw_dataset") if isinstance(remote_result.get("raw_dataset"), dict) else {}
    risk_payload = remote_result.get("risk_assessment_payload") if isinstance(remote_result.get("risk_assessment_payload"), dict) else {}
    operational_payload = remote_result.get("operational_impact_payload") if isinstance(remote_result.get("operational_impact_payload"), dict) else {}
    asset_matching_payload = remote_result.get("asset_matching_payload") if isinstance(remote_result.get("asset_matching_payload"), dict) else {}

    raw_output_path = Path(payload.get("raw_output_path") or VULN_RAW_OUTPUT_PATH)
    risk_output_path = Path(payload.get("risk_output_path") or VULN_RISK_PAYLOAD_PATH)
    operational_output_path = Path(payload.get("operational_output_path") or VULN_OPERATIONAL_PAYLOAD_PATH)
    asset_output_path = Path(payload.get("asset_matching_output_path") or VULN_ASSET_MATCHING_PAYLOAD_PATH)
    _write_json(raw_output_path, raw_dataset)
    _write_json(risk_output_path, risk_payload)
    _write_json(operational_output_path, operational_payload)
    _write_json(asset_output_path, asset_matching_payload)

    return {
        "agent": "vuln_collector_agent",
        "action": action,
        "status": "ok",
        "backend": "agentcore_runtime",
        "runtime_arn": runtime_arn,
        "generated_at": _utc_now(),
        "cve_ids": remote_result.get("cve_ids") or [],
        "raw_output_path": str(raw_output_path),
        "risk_output_path": str(risk_output_path),
        "operational_output_path": str(operational_output_path),
        "asset_matching_output_path": str(asset_output_path),
        "raw_result": raw_dataset,
        "risk_assessment_payload": risk_payload,
        "operational_impact_payload": operational_payload,
        "asset_matching_payload": asset_matching_payload,
    }


def run_risk_evaluation_agent(payload: dict[str, Any]) -> dict[str, Any]:
    runtime_arn = _resolve_risk_evaluation_runtime_arn(payload)
    region = str(payload.get("region") or DEFAULT_REGION)
    vulnerability_data = _load_risk_assessment_payload(payload)
    infra_context = _load_infra_context(payload)

    remote_payload = {
        "cve_payload": vulnerability_data,
        "vulnerability_data": vulnerability_data,
        "infra_context": infra_context,
        "asset_info": infra_context,
        "asset_matching_arn": _resolve_infra_matching_runtime_arn(payload),
        "region": region,
    }
    if payload.get("prompt"):
        remote_payload["prompt"] = payload["prompt"]

    remote_result = _invoke_agentcore_runtime(runtime_arn, remote_payload, region)
    if "error" in remote_result:
        raise RuntimeError(f"risk_evaluation_agent 호출 실패: {remote_result['error']}")

    risk_report = remote_result.get("risk_report")
    if not isinstance(risk_report, list):
        risk_report = remote_result if isinstance(remote_result, list) else []

    save_path = Path(payload.get("save_path") or RISK_RESULT_PATH)
    raw_response_path = Path(payload.get("raw_response_path") or (RISK_OUTPUT_DIR / "risk_evaluation_raw_response.json"))
    _write_json(save_path, risk_report)
    _write_json(raw_response_path, remote_result)

    return {
        "agent": "risk_evaluation_agent",
        "action": "evaluate_risk",
        "status": "ok",
        "backend": "agentcore_runtime",
        "runtime_arn": runtime_arn,
        "generated_at": _utc_now(),
        "record_count": len(risk_report),
        "result_path": str(save_path),
        "raw_response_path": str(raw_response_path),
        "swarm_queries": remote_result.get("swarm_queries", []),
        "result": risk_report,
    }


def run_patch_impact_agent(payload: dict[str, Any]) -> dict[str, Any]:
    runtime_arn = _resolve_patch_impact_runtime_arn(payload)
    if not runtime_arn:
        raise RuntimeError("PATCH_IMPACT_ARN 또는 patch_impact_runtime_arn 설정이 필요합니다.")

    action = str(payload.get("action") or "evaluate_patch_impact").strip().lower()
    region = str(payload.get("region") or DEFAULT_REGION)
    remote_result = _invoke_agentcore_runtime(runtime_arn, payload, region)
    if "error" in remote_result:
        raise RuntimeError(f"patch_impact_agent 호출 실패: {remote_result['error']}")

    if action in {"evaluate_patch_impact", "bootstrap", "init"}:
        local_result = remote_result.get("result") if isinstance(remote_result.get("result"), dict) else remote_result
        result_path = Path(payload.get("save_path") or PATCH_PRE_RESULT_PATH)
        request_path = Path(payload.get("additional_request_path") or PATCH_FOLLOWUP_REQUEST_PATH)
        additional_request = remote_result.get("additional_request") if isinstance(remote_result.get("additional_request"), dict) else {"requests": [], "request_count": 0}
        request_debug = remote_result.get("request_debug") if isinstance(remote_result.get("request_debug"), dict) else {}
        _write_json(result_path, local_result)
        _write_json(request_path, additional_request)
        return {
            "agent": "patch_impact_agent",
            "action": action,
            "status": "ok",
            "backend": "agentcore_runtime",
            "runtime_arn": runtime_arn,
            "result_path": str(result_path),
            "additional_request_path": str(request_path),
            "request_debug": request_debug,
            "result": local_result,
        }

    if action in {"run_followup_conversation", "followup", "followup_conversation"}:
        local_result = remote_result.get("result") if isinstance(remote_result.get("result"), dict) else remote_result
        result_path = Path(payload.get("save_path") or PATCH_FOLLOWUP_RESULT_PATH)
        _write_json(result_path, local_result)
        return {
            "agent": "patch_impact_agent",
            "action": action,
            "status": "ok",
            "backend": "agentcore_runtime",
            "runtime_arn": runtime_arn,
            "result_path": str(result_path),
            "result": local_result,
        }

    if action in {"finalize_patch_impact", "finalize"}:
        local_result = remote_result.get("result") if isinstance(remote_result.get("result"), dict) else remote_result
        result_path = Path(payload.get("save_path") or PATCH_FINAL_RESULT_PATH)
        _write_json(result_path, local_result)
        return {
            "agent": "patch_impact_agent",
            "action": action,
            "status": "ok",
            "backend": "agentcore_runtime",
            "runtime_arn": runtime_arn,
            "result_path": str(result_path),
            "result": local_result,
        }

    if action in {"query_patch_impact", "query"}:
        return {
            "agent": "patch_impact_agent",
            "action": action,
            "status": "ok",
            "backend": "agentcore_runtime",
            "runtime_arn": runtime_arn,
            **remote_result,
        }

    return {
        "agent": "patch_impact_agent",
        "action": action,
        "status": "ok",
        "backend": "agentcore_runtime",
        "runtime_arn": runtime_arn,
        "result": remote_result,
    }


AGENT_REGISTRY: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "infra_matching_agent": run_infra_matching_agent,
    "vuln_collector_agent": run_vuln_collector_agent,
    "risk_evaluation_agent": run_risk_evaluation_agent,
    "patch_impact_agent": run_patch_impact_agent,
}


def run_agent(agent_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    handler = AGENT_REGISTRY.get(agent_name)
    if handler is None:
        raise KeyError(f"등록되지 않은 agent 입니다: {agent_name}")
    return handler(payload)
