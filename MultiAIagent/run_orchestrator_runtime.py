#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PROJECT_ROOT.parent
ENV_PATH_CANDIDATES = (
    PROJECT_ROOT / ".env",
    REPO_ROOT / ".env",
)
RESULT_ROOT = PROJECT_ROOT / "OchestraResult"
CONVERSATION_LOG_ROOT = PROJECT_ROOT / "Conversationlog"
PATCH_TO_ASSET_LOG_ROOT = CONVERSATION_LOG_ROOT / "PatchToAsset"
DEFAULT_REGION = "ap-northeast-2"
DEFAULT_STACK_NAME = "megathon"
DEFAULT_ORCHESTRATOR_ARN = (
    "arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/orchestrator_agent-JZKEPYHOwx"
)
DEFAULT_PATCH_IMPACT_ARN = (
    "arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/patch_impact_container-qNIi2mCjRa"
)
DEFAULT_READ_TIMEOUT = 900
DEFAULT_CONNECT_TIMEOUT = 10

MODE_OPTIONS = {
    "1": ("full", "전체 실행"),
    "2": ("vuln_only", "취약점 수집만"),
    "3": ("asset_only", "자산 수집만"),
    "4": ("risk_only", "위험 평가만"),
    "5": ("patch_only", "패치 영향도만"),
    "6": ("test", "중간 단계 주입 테스트"),
}

STOP_STAGE_OPTIONS = {
    "1": "vuln",
    "2": "asset",
    "3": "risk",
    "4": "patch_pre",
    "5": "patch_followup",
    "6": "patch_final",
}

VULN_RESULT_FILENAMES = {
    "raw_result": "focused_selected_raw_cves.json",
    "risk_assessment_payload": "risk_assessment_payloads.json",
    "operational_impact_payload": "operational_impact_payloads.json",
    "asset_matching_payload": "asset_matching_payload.json",
}


def _load_env() -> None:
    for env_path in ENV_PATH_CANDIDATES:
        if env_path.exists():
            load_dotenv(env_path)
            break


def _print_usage_guide() -> None:
    print(
        "\n[사용 방법]\n"
        "- 대괄호 [ ] 안에 보이는 값은 기본값입니다.\n"
        "- 기본값 그대로 쓰고 싶으면 그냥 엔터를 누르면 됩니다.\n"
        "- JSON 파일 경로를 물어볼 때는 기본 경로가 보이면 엔터만 눌러도 됩니다.\n"
        "- 결과는 OchestraResult 아래에 에이전트별 폴더로 저장됩니다.\n"
    )
    print(
        "[모드 설명]\n"
        "1. full\n"
        "   vuln -> asset -> risk -> patch 전체 실행\n"
        "2. vuln_only\n"
        "   취약점 수집 에이전트만 실행\n"
        "3. asset_only\n"
        "   자산 수집 에이전트만 실행\n"
        "   필요 입력: asset_matching_payload.json\n"
        "4. risk_only\n"
        "   위험 평가 에이전트만 실행\n"
        "   필요 입력: infra_context.json, risk_assessment_payloads.json\n"
        "5. patch_only\n"
        "   패치 영향도 에이전트만 실행\n"
        "   필요 입력: infra_context.json, risk_evaluation_result.json, operational_impact_payloads.json\n"
        "   patch ARN은 기본값이 새 container runtime 으로 잡혀 있고, 바꾸고 싶으면 직접 입력하면 됩니다.\n"
        "   patch는 현재 Bedrock 기반이며 OpenAI 키 입력은 더 이상 필요하지 않습니다.\n"
        "   follow-up 질문까지 할지 마지막에 한 번 더 묻습니다.\n"
        "6. test\n"
        "   중간 단계 주입 테스트\n"
        "   stop_stage 를 고르고, 그 단계에 필요한 JSON만 넣으면 됩니다.\n"
    )
    print(
        "[빠른 예시]\n"
        "- 취약점 수집만 빠르게 보고 싶다:\n"
        "  엔터 -> 2 -> 엔터 -> 엔터 -> 엔터\n"
        "- 자산 수집만 돌리고 싶다:\n"
        "  엔터 -> 3 -> 엔터 -> 엔터 -> asset_matching_payload 경로 입력(또는 기본값 엔터) -> 엔터\n"
    )


def _utc_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _safe_slug(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value.strip().lower())
    return cleaned or "run"


def _has_meaningful_json(data: Any) -> bool:
    if data is None:
        return False
    if isinstance(data, dict):
        return bool(data)
    if isinstance(data, list):
        return bool(data)
    if isinstance(data, str):
        return bool(data.strip())
    return True


def _input(prompt: str) -> str:
    return input(prompt).strip()


def _prompt_with_default(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = _input(f"{label}{suffix}: ")
    return value or (default or "")


def _prompt_yes_no(label: str, default: bool = True) -> bool:
    default_text = "Y/n" if default else "y/N"
    value = _input(f"{label} [{default_text}]: ").lower()
    if not value:
        return default
    return value in {"y", "yes", "1", "true"}


def _prompt_optional_runtime_arn(label: str, default: str | None = None) -> str:
    value = _prompt_with_default(label, default)
    return value.strip()


def _redact_secrets(data: Any) -> Any:
    secret_keys = {"api_key", "openai_api_key"}
    if isinstance(data, dict):
        redacted: dict[str, Any] = {}
        for key, value in data.items():
            if key in secret_keys and value:
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = _redact_secrets(value)
        return redacted
    if isinstance(data, list):
        return [_redact_secrets(item) for item in data]
    return data


def _choose_mode() -> tuple[str, str]:
    print("\n실행 모드 선택")
    for number, (_, label) in MODE_OPTIONS.items():
        print(f"{number}. {label}")
    selected = _input("번호 입력 [1]: ") or "1"
    if selected not in MODE_OPTIONS:
        raise ValueError("지원하지 않는 모드 번호입니다.")
    return MODE_OPTIONS[selected]


def _choose_stop_stage() -> str:
    print("\n중간 테스트 종료 stage 선택")
    for number, stage_name in STOP_STAGE_OPTIONS.items():
        print(f"{number}. {stage_name}")
    selected = _input("번호 입력 [6]: ") or "6"
    if selected not in STOP_STAGE_OPTIONS:
        raise ValueError("지원하지 않는 stop_stage 번호입니다.")
    return STOP_STAGE_OPTIONS[selected]


def _latest_from_dir(path: Path, filename: str) -> Path | None:
    if not path.exists():
        return None
    candidates = sorted(
        (candidate for candidate in path.rglob(filename) if candidate.is_file()),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for candidate in candidates:
        try:
            if _has_meaningful_json(_read_json(candidate)):
                return candidate
        except Exception:
            continue
    return candidates[0] if candidates else None


def _first_existing(paths: list[Path | None]) -> Path | None:
    for path in paths:
        if path and path.exists():
            try:
                if _has_meaningful_json(_read_json(path)):
                    return path
            except Exception:
                return path
    for path in paths:
        if path and path.exists():
            return path
    return None


def _default_input_path(key: str) -> Path | None:
    latest_root = RESULT_ROOT
    if key == "asset_matching_payload":
        return _first_existing([
            latest_root / "vuln_collector_agent" / "latest" / "asset_matching_payload.json",
            latest_root / "vuln_collector_agent" / "latest" / "asset_matching_payloads.json",
            _latest_from_dir(latest_root / "vuln_collector_agent", "asset_matching_payload.json"),
            REPO_ROOT / "vuln_runtime_result" / "asset_matching_payload.json",
            PROJECT_ROOT / "OutputResult" / "VulAgent" / "asset_matching_payload.json",
        ])
    if key == "risk_assessment_payload":
        return _first_existing([
            latest_root / "vuln_collector_agent" / "latest" / "risk_assessment_payload.json",
            latest_root / "vuln_collector_agent" / "latest" / "risk_assessment_payloads.json",
            _latest_from_dir(latest_root / "vuln_collector_agent", "risk_assessment_payloads.json"),
            REPO_ROOT / "vuln_runtime_result" / "risk_assessment_payloads.json",
            PROJECT_ROOT / "OutputResult" / "VulAgent" / "risk_assessment_payloads.json",
        ])
    if key in {"operational_payload", "operational_impact_payload"}:
        return _first_existing([
            latest_root / "vuln_collector_agent" / "latest" / "operational_impact_payload.json",
            latest_root / "vuln_collector_agent" / "latest" / "operational_impact_payloads.json",
            _latest_from_dir(latest_root / "vuln_collector_agent", "operational_impact_payloads.json"),
            REPO_ROOT / "vuln_runtime_result" / "operational_impact_payloads.json",
            PROJECT_ROOT / "OutputResult" / "VulAgent" / "operational_impact_payloads.json",
        ])
    if key == "infra_context":
        return _first_existing([
            latest_root / "asset_matching_agent" / "latest" / "infra_context.json",
            _latest_from_dir(latest_root / "asset_matching_agent", "infra_context.json"),
            PROJECT_ROOT / "OutputResult" / "AssetAgent" / "infra_context.json",
        ])
    if key == "risk_result":
        return _first_existing([
            latest_root / "risk_evaluation_agent" / "latest" / "risk_evaluation_result.json",
            latest_root / "risk_evaluation_agent" / "latest" / "risk_result.json",
            _latest_from_dir(latest_root / "risk_evaluation_agent", "risk_evaluation_result.json"),
            PROJECT_ROOT / "OutputResult" / "RiskevalAgent" / "risk_evaluation_result.json",
        ])
    if key == "prejudge_result":
        return _first_existing([
            latest_root / "patch_impact_agent" / "latest" / "patch_impact_prejudge_result.json",
            _latest_from_dir(latest_root / "patch_impact_agent", "patch_impact_prejudge_result.json"),
            PROJECT_ROOT / "OutputResult" / "PatchImAgent" / "stage1_prejudge" / "patch_impact_prejudge_result.json",
        ])
    if key == "followup_result":
        return _first_existing([
            latest_root / "patch_impact_agent" / "latest" / "additional_asset_response.json",
            _latest_from_dir(latest_root / "patch_impact_agent", "additional_asset_response.json"),
            PROJECT_ROOT / "OutputResult" / "SwarmAgent" / "additional_asset_response.json",
        ])
    if key in {"followup_request", "additional_request"}:
        return _first_existing([
            latest_root / "patch_impact_agent" / "latest" / "additional_asset_request.json",
            _latest_from_dir(latest_root / "patch_impact_agent", "additional_asset_request.json"),
            PROJECT_ROOT / "OutputResult" / "PatchImAgent" / "stage2_followup" / "additional_asset_request.json",
        ])
    if key == "raw_result":
        return _first_existing([
            latest_root / "vuln_collector_agent" / "latest" / "focused_selected_raw_cves.json",
            _latest_from_dir(latest_root / "vuln_collector_agent", "focused_selected_raw_cves.json"),
            REPO_ROOT / "vuln_runtime_result" / "focused_selected_raw_cves.json",
            PROJECT_ROOT / "OutputResult" / "VulAgent" / "focused_selected_raw_cves.json",
        ])
    return None


def _prompt_json_file(label: str, key: str, *, required: bool) -> Any:
    default_path = _default_input_path(key)
    prompt = f"{label} 파일 경로"
    raw_value = _prompt_with_default(prompt, str(default_path) if default_path else None)
    if not raw_value:
        if required:
            raise ValueError(f"{label} 파일이 필요합니다.")
        return None

    path = Path(raw_value).expanduser()
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"파일을 찾을 수 없습니다: {path}")
    return _read_json(path)


def _build_payload_interactively() -> tuple[dict[str, Any], str]:
    mode, label = _choose_mode()
    region = _prompt_with_default("리전", os.environ.get("AWS_DEFAULT_REGION") or DEFAULT_REGION)
    stack_name = _prompt_with_default("스택 이름", os.environ.get("CF_STACK_NAME") or DEFAULT_STACK_NAME)

    payload: dict[str, Any] = {
        "mode": mode,
        "region": region,
        "stack_name": stack_name,
    }

    if mode == "asset_only":
        payload["asset_matching_payload"] = _prompt_json_file("asset_matching_payload", "asset_matching_payload", required=True)
    elif mode == "risk_only":
        payload["infra_context"] = _prompt_json_file("infra_context", "infra_context", required=True)
        payload["risk_assessment_payload"] = _prompt_json_file("risk_assessment_payload", "risk_assessment_payload", required=True)
    elif mode == "patch_only":
        patch_runtime_arn = _prompt_optional_runtime_arn("Patch runtime ARN", os.environ.get("PATCH_IMPACT_ARN") or DEFAULT_PATCH_IMPACT_ARN)
        if patch_runtime_arn:
            payload["patch_impact_runtime_arn"] = patch_runtime_arn
        payload["infra_context"] = _prompt_json_file("infra_context", "infra_context", required=True)
        payload["risk_result"] = _prompt_json_file("risk_result", "risk_result", required=True)
        payload["operational_payload"] = _prompt_json_file("operational_payload", "operational_payload", required=True)
        payload["allow_followup"] = _prompt_yes_no("follow-up 질문까지 실행할까요?", default=True)
    elif mode == "test":
        stop_stage = _choose_stop_stage()
        payload["stop_stage"] = stop_stage
        if stop_stage in {"patch_pre", "patch_followup", "patch_final"}:
            patch_runtime_arn = _prompt_optional_runtime_arn("Patch runtime ARN", os.environ.get("PATCH_IMPACT_ARN") or DEFAULT_PATCH_IMPACT_ARN)
            if patch_runtime_arn:
                payload["patch_impact_runtime_arn"] = patch_runtime_arn
        test_inputs: dict[str, Any] = {}
        if stop_stage == "asset":
            test_inputs["asset_matching_payload"] = _prompt_json_file("asset_matching_payload", "asset_matching_payload", required=True)
        elif stop_stage == "risk":
            test_inputs["infra_context"] = _prompt_json_file("infra_context", "infra_context", required=True)
            test_inputs["risk_assessment_payload"] = _prompt_json_file("risk_assessment_payload", "risk_assessment_payload", required=True)
        elif stop_stage == "patch_pre":
            test_inputs["infra_context"] = _prompt_json_file("infra_context", "infra_context", required=True)
            test_inputs["risk_result"] = _prompt_json_file("risk_result", "risk_result", required=True)
            test_inputs["operational_payload"] = _prompt_json_file("operational_payload", "operational_payload", required=True)
        elif stop_stage == "patch_followup":
            test_inputs["infra_context"] = _prompt_json_file("infra_context", "infra_context", required=True)
            test_inputs["prejudge_result"] = _prompt_json_file("prejudge_result", "prejudge_result", required=True)
            followup_request = _prompt_json_file("followup_request", "followup_request", required=False)
            if followup_request is not None:
                test_inputs["followup_request"] = followup_request
        elif stop_stage == "patch_final":
            test_inputs["prejudge_result"] = _prompt_json_file("prejudge_result", "prejudge_result", required=True)
            followup_result = _prompt_json_file("followup_result", "followup_result", required=False)
            if followup_result is not None:
                test_inputs["followup_result"] = followup_result
        payload["test_inputs"] = test_inputs

    return payload, label


def _invoke_orchestrator(runtime_arn: str, region: str, payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    client = boto3.client(
        "bedrock-agentcore",
        region_name=region,
        config=Config(
            read_timeout=int(os.environ.get("ORCHESTRATOR_READ_TIMEOUT", DEFAULT_READ_TIMEOUT)),
            connect_timeout=int(os.environ.get("ORCHESTRATOR_CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT)),
        ),
    )
    session_id = "orchestrator-run-" + uuid.uuid4().hex
    response = client.invoke_agent_runtime(
        agentRuntimeArn=runtime_arn,
        runtimeSessionId=session_id,
        payload=json.dumps(payload).encode("utf-8"),
        qualifier="DEFAULT",
    )
    body = response["response"].read().decode("utf-8")
    parsed = json.loads(body)
    meta = {
        "statusCode": response.get("statusCode"),
        "runtimeSessionId": response.get("runtimeSessionId"),
        "agentRuntimeArn": runtime_arn,
        "region": region,
    }
    return parsed, meta


def _save_named_json(agent_name: str, run_tag: str, filename: str, data: Any) -> None:
    run_dir = RESULT_ROOT / agent_name / run_tag
    latest_dir = RESULT_ROOT / agent_name / "latest"
    _write_json(run_dir / filename, data)
    if _has_meaningful_json(data):
        _write_json(latest_dir / filename, data)


def _save_stage_wrapper(agent_name: str, run_tag: str, stage_data: dict[str, Any]) -> None:
    _save_named_json(agent_name, run_tag, "stage_response.json", stage_data)


def _normalize_patch_to_asset_log(followup_stage: dict[str, Any], run_tag: str) -> dict[str, Any]:
    responses = followup_stage.get("responses") if isinstance(followup_stage.get("responses"), list) else []
    conversations: list[dict[str, Any]] = []

    for item in responses:
        if not isinstance(item, dict):
            continue
        question_bundle = item.get("question_bundle") if isinstance(item.get("question_bundle"), dict) else {}
        response_wrapper = item.get("response") if isinstance(item.get("response"), dict) else {}
        result_wrapper = response_wrapper.get("result") if isinstance(response_wrapper.get("result"), dict) else {}
        parsed_answer = result_wrapper.get("parsed_answer") if isinstance(result_wrapper.get("parsed_answer"), dict) else {}
        transcript = response_wrapper.get("transcript") if isinstance(response_wrapper.get("transcript"), list) else None

        if transcript is None:
            transcript = []
            for turn_number, question_item in enumerate(question_bundle.get("questions", []), start=1):
                if isinstance(question_item, dict):
                    question = str(question_item.get("question") or question_item.get("prompt") or "").strip()
                    question_type = str(question_item.get("question_type") or "patch_followup").strip()
                else:
                    question = str(question_item or "").strip()
                    question_type = "patch_followup"
                if not question:
                    continue
                transcript.append(
                    {
                        "turn": turn_number,
                        "question_type": question_type,
                        "question": question,
                    }
                )

        conversations.append(
            {
                "request_id": str(item.get("request_id") or "").strip(),
                "cve_id": str(item.get("cve_id") or "").strip(),
                "instance_id": str(item.get("instance_id") or "").strip(),
                "source_agent": str(item.get("source_agent") or "").strip(),
                "target_agent": str(item.get("target_agent") or "").strip(),
                "tool_rounds_used": response_wrapper.get("tool_rounds_used"),
                "conversation_trace_path": response_wrapper.get("conversation_trace_path"),
                "question_bundle": question_bundle,
                "transcript": transcript,
                "final_answer": parsed_answer,
            }
        )

    return {
        "run_tag": run_tag,
        "generated_at": followup_stage.get("generated_at"),
        "response_count": followup_stage.get("response_count"),
        "conversations": conversations,
    }


def _save_patch_to_asset_conversation_log(run_tag: str, followup_stage: dict[str, Any]) -> None:
    PATCH_TO_ASSET_LOG_ROOT.mkdir(parents=True, exist_ok=True)
    run_dir = PATCH_TO_ASSET_LOG_ROOT / run_tag
    run_dir.mkdir(parents=True, exist_ok=True)

    normalized_log = _normalize_patch_to_asset_log(followup_stage, run_tag)
    _write_json(run_dir / "conversation_log.json", normalized_log)
    _write_json(PATCH_TO_ASSET_LOG_ROOT / "latest.json", normalized_log)

    for conversation in normalized_log.get("conversations", []):
        if not isinstance(conversation, dict):
            continue
        request_id = str(conversation.get("request_id") or "").strip() or f"request-{uuid.uuid4().hex[:8]}"
        _write_json(run_dir / f"{request_id}.json", conversation)


def _save_result_bundle(result: dict[str, Any], request_payload: dict[str, Any], invoke_meta: dict[str, Any]) -> dict[str, Any]:
    mode = str(result.get("mode") or request_payload.get("mode") or "unknown")
    run_tag = f"{_utc_tag()}__{_safe_slug(mode)}"
    sanitized_request_payload = _redact_secrets(request_payload)

    orchestrator_agent_name = "orchestrator_agent"
    _save_named_json(orchestrator_agent_name, run_tag, "request_payload.json", sanitized_request_payload)
    _save_named_json(orchestrator_agent_name, run_tag, "invoke_meta.json", invoke_meta)
    _save_named_json(orchestrator_agent_name, run_tag, "response.json", result)

    vuln_stage = result.get("vuln_stage") if isinstance(result.get("vuln_stage"), dict) else None
    if vuln_stage:
        _save_stage_wrapper("vuln_collector_agent", run_tag, vuln_stage)
        for key, filename in VULN_RESULT_FILENAMES.items():
            if key in vuln_stage and _has_meaningful_json(vuln_stage.get(key)):
                _save_named_json("vuln_collector_agent", run_tag, filename, vuln_stage.get(key))

    asset_stage = result.get("asset_stage") if isinstance(result.get("asset_stage"), dict) else None
    if asset_stage:
        _save_stage_wrapper("asset_matching_agent", run_tag, asset_stage)
        if "result" in asset_stage:
            _save_named_json("asset_matching_agent", run_tag, "infra_context.json", asset_stage.get("result"))

    risk_stage = result.get("risk_stage") if isinstance(result.get("risk_stage"), dict) else None
    if risk_stage:
        _save_stage_wrapper("risk_evaluation_agent", run_tag, risk_stage)
        if "result" in risk_stage:
            _save_named_json("risk_evaluation_agent", run_tag, "risk_evaluation_result.json", risk_stage.get("result"))

    patch_pre_stage = result.get("patch_pre_stage") if isinstance(result.get("patch_pre_stage"), dict) else None
    if patch_pre_stage:
        _save_stage_wrapper("patch_impact_agent", run_tag, {"stage": "patch_pre", **patch_pre_stage})
        if "result" in patch_pre_stage:
            _save_named_json("patch_impact_agent", run_tag, "patch_impact_prejudge_result.json", patch_pre_stage.get("result"))

    followup_stage = result.get("followup_stage") if isinstance(result.get("followup_stage"), dict) else None
    if followup_stage:
        _save_named_json("patch_impact_agent", run_tag, "additional_asset_response.json", followup_stage)
        _save_patch_to_asset_conversation_log(run_tag, followup_stage)

    patch_final_stage = result.get("patch_final_stage") if isinstance(result.get("patch_final_stage"), dict) else None
    if patch_final_stage:
        _save_stage_wrapper("patch_impact_agent", run_tag, {"stage": "patch_final", **patch_final_stage})
        if "result" in patch_final_stage:
            _save_named_json("patch_impact_agent", run_tag, "patch_impact_final_result.json", patch_final_stage.get("result"))

    summary = {
        "run_tag": run_tag,
        "mode": mode,
        "pipeline": result.get("pipeline", []),
        "agent_message": result.get("agent_message"),
        "orchestrator_result_dir": str(RESULT_ROOT / orchestrator_agent_name / run_tag),
        "saved_agent_dirs": {
            "vuln_collector_agent": str(RESULT_ROOT / "vuln_collector_agent" / run_tag) if vuln_stage else None,
            "asset_matching_agent": str(RESULT_ROOT / "asset_matching_agent" / run_tag) if asset_stage else None,
            "risk_evaluation_agent": str(RESULT_ROOT / "risk_evaluation_agent" / run_tag) if risk_stage else None,
            "patch_impact_agent": str(RESULT_ROOT / "patch_impact_agent" / run_tag)
            if any(stage is not None for stage in (patch_pre_stage, followup_stage, patch_final_stage))
            else None,
        },
    }
    _save_named_json(orchestrator_agent_name, run_tag, "summary.json", summary)
    return summary


def main() -> int:
    _load_env()
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)

    print("\n오케스트라 런타임 실행기")
    _print_usage_guide()
    runtime_arn = _prompt_with_default(
        "오케스트라 런타임 ARN",
        os.environ.get("ORCHESTRATOR_RUNTIME_ARN") or DEFAULT_ORCHESTRATOR_ARN,
    )
    payload, label = _build_payload_interactively()

    print("\n실행 요청")
    print(json.dumps(_redact_secrets(payload), ensure_ascii=False, indent=2))
    if not _prompt_yes_no(f"{label} 모드로 실행할까요?", default=True):
        print("취소했습니다.")
        return 0

    result, invoke_meta = _invoke_orchestrator(runtime_arn, payload["region"], payload)
    summary = _save_result_bundle(result, payload, invoke_meta)

    print("\n실행 완료")
    print(json.dumps(invoke_meta, ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
