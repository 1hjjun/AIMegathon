#!/usr/bin/env python3
"""
AI Agent 기반 자산 정보 추출기.

Gemini API (Function Calling) 를 사용하여 payload.json 을 분석하고,
shell 명령어 도구를 통해 EC2 인스턴스의 소프트웨어를 지능적으로 탐지한다.

흐름:
  payload.json 로드
    → Gemini Agent (tool-use loop)
      ├─ run_command : shell 명령 실행
      ├─ read_file   : 파일 내용 읽기
      └─ save_result : 탐지 완료, 결과 저장 후 종료
    → asset_info.json 저장
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from google import genai
from google.genai import types


# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------

MODEL_NAME = "gemini-2.5-flash"
# 503 발생 시 순서대로 시도
MODEL_FALLBACKS = [
    "gemini-2.0-flash-001",   # 안정적인 고정 버전
    "gemini-2.5-flash-lite",  # 경량 버전
    "gemini-2.0-flash",       # 이전 세대
]
MAX_AGENT_TURNS = 20
COMMAND_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 10  # 503 재시도 대기(초)

_BLOCKED = re.compile(
    r"\b(rm|rmdir|mv|dd|mkfs|fdisk|kill|killall|reboot|shutdown|halt)\b",
    re.IGNORECASE,
)

IMDS_BASE = "http://169.254.169.254/latest/meta-data"
IMDS_TIMEOUT = 2


# ---------------------------------------------------------------------------
# 도구 스키마
# ---------------------------------------------------------------------------

RUN_COMMAND_DECL = types.FunctionDeclaration(
    name="run_command",
    description=(
        "EC2 인스턴스에서 읽기/조회 목적의 shell 명령어를 실행한다. "
        "파일 삭제·프로세스 종료 등 파괴적 명령은 거부된다."
    ),
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "command": types.Schema(
                type=types.Type.STRING,
                description="실행할 shell 명령어 (bash -c 로 실행됨)",
            )
        },
        required=["command"],
    ),
)

READ_FILE_DECL = types.FunctionDeclaration(
    name="read_file",
    description="파일 경로를 받아 텍스트 내용을 반환한다.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "path": types.Schema(
                type=types.Type.STRING,
                description="읽을 파일의 절대 경로",
            )
        },
        required=["path"],
    ),
)

SAVE_RESULT_DECL = types.FunctionDeclaration(
    name="save_result",
    description=(
        "탐지를 완료했을 때 호출한다. "
        "발견된 소프트웨어 목록을 전달하면 에이전트가 종료되고 결과가 저장된다. "
        "탐지할 소프트웨어를 찾지 못한 경우에도 빈 배열로 반드시 호출해야 한다."
    ),
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "installed_software": types.Schema(
                type=types.Type.ARRAY,
                description="탐지된 소프트웨어 목록",
                items=types.Schema(
                    type=types.Type.OBJECT,
                    properties={
                        "vendor":      types.Schema(type=types.Type.STRING, description="CPE 벤더명 (예: f5, apache)"),
                        "product":     types.Schema(type=types.Type.STRING, description="CPE 제품명 (예: nginx, log4j)"),
                        "version":     types.Schema(type=types.Type.STRING, description="설치된 버전 (예: 1.18.0)"),
                        "cpe":         types.Schema(type=types.Type.STRING, description="CPE 2.3 식별자"),
                        "source_path": types.Schema(type=types.Type.STRING, description="탐지 근거 경로 (선택)"),
                    },
                    required=["vendor", "product", "version", "cpe"],
                ),
            )
        },
        required=["installed_software"],
    ),
)

AGENT_TOOLS = types.Tool(
    function_declarations=[RUN_COMMAND_DECL, READ_FILE_DECL, SAVE_RESULT_DECL]
)


# ---------------------------------------------------------------------------
# 도구 실행
# ---------------------------------------------------------------------------

def _execute_run_command(command: str) -> str:
    if _BLOCKED.search(command):
        return f"[BLOCKED] 허용되지 않는 명령어: {command}"
    try:
        result = subprocess.run(
            command, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=COMMAND_TIMEOUT,
        )
        out = result.stdout.decode(errors="replace").strip()
        return out if out else "(출력 없음)"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {COMMAND_TIMEOUT}초 초과"
    except Exception as e:
        return f"[ERROR] {e}"


def _execute_read_file(path: str) -> str:
    try:
        text = Path(path).read_text(errors="replace")
        return text[:8000] + "\n...(이하 생략)" if len(text) > 8000 else text
    except PermissionError:
        return f"[ERROR] 권한 없음: {path}"
    except FileNotFoundError:
        return f"[ERROR] 파일 없음: {path}"
    except Exception as e:
        return f"[ERROR] {e}"


def dispatch_tool(name: str, args: dict) -> str:
    if name == "run_command":
        return _execute_run_command(args["command"])
    if name == "read_file":
        return _execute_read_file(args["path"])
    return f"[ERROR] 알 수 없는 도구: {name}"


# ---------------------------------------------------------------------------
# IMDS / OS 정보
# ---------------------------------------------------------------------------

def _imds_get(path: str) -> str:
    try:
        with urllib.request.urlopen(f"{IMDS_BASE}/{path}", timeout=IMDS_TIMEOUT) as r:
            return r.read().decode().strip()
    except (urllib.error.URLError, OSError):
        return ""


def _imds_get_v2(path: str) -> str:
    try:
        req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=IMDS_TIMEOUT) as r:
            token = r.read().decode().strip()
        req2 = urllib.request.Request(
            f"{IMDS_BASE}/{path}",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with urllib.request.urlopen(req2, timeout=IMDS_TIMEOUT) as r:
            return r.read().decode().strip()
    except (urllib.error.URLError, OSError):
        return ""


def get_instance_id() -> str:
    return _imds_get("instance-id") or _imds_get_v2("instance-id") or socket.gethostname()


def get_os_info() -> dict:
    p = Path("/etc/os-release")
    if not p.exists():
        return {"vendor": "unknown", "version": "unknown"}
    kv: dict = {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if "=" not in line or line.startswith("#"):
            continue
        k, _, v = line.partition("=")
        kv[k.strip()] = v.strip().strip('"')
    vendor = kv.get("ID", "unknown").lower()
    m = re.search(r"[\d.]+", kv.get("VERSION", ""))
    version = kv.get("VERSION_ID") or (m.group(0) if m else "unknown")
    return {"vendor": vendor, "version": version}


# ---------------------------------------------------------------------------
# Gemini Agent 루프
# ---------------------------------------------------------------------------

def build_system_prompt(payload: dict) -> str:
    targets = json.dumps(payload.get("records", []), ensure_ascii=False, indent=2)
    return f"""당신은 Linux EC2 인스턴스에서 실행 중인 소프트웨어를 탐지하는 보안 자산 수집 에이전트입니다.

[탐지 목표]
아래 payload 에 정의된 취약점 대상 소프트웨어를 EC2 인스턴스에서 찾아야 합니다.
You are an expert Cybersecurity Deep Scan & SBOM (Software Bill of Materials) Analysis Agent.
Your core objective is to analyze the internal execution state and file system data of a server to determine if it is truly vulnerable to severe application-level vulnerabilities, specifically Log4j (Log4Shell, CVE-2021-44228).

You will receive deep-scan data extracted from the server, which includes:
1. Running Processes (e.g., Java processes)
2. Discovered Library Files (e.g., .jar files)
3. Environment Variables & JVM Options

{targets}

[행동 지침]
1. run_command 와 read_file 도구를 자유롭게 사용해 시스템을 조사하세요.
### Your Evaluation Logic (Step-by-Step):
1. **Execution Context Check:** Does the server run Java? If no Java processes are active, the immediate exploitation risk is extremely low, even if the file exists.
2. **Dependency Version Check:** Analyze the discovered '.jar' files. Does 'log4j-core' exist? If so, extract its version. Vulnerable versions for Log4Shell are generally >= 2.0-beta9 and <= 2.14.1.
3. **Mitigation Check:** Check the environment variables and JVM arguments. Is the mitigation flag `LOG4J_FORMAT_MSG_NO_LOOKUPS=true` or `-Dlog4j2.formatMsgNoLookups=true` present? If yes, the asset is protected despite having a vulnerable version.
4. **Final Verdict:** Synthesize the above steps. An asset is ONLY 'vulnerable' if it runs Java, has a vulnerable Log4j version, AND lacks the mitigation flags.
3. 탐지 완료 후 save_result 를 반드시 호출하세요.

[save_result 항목 형식]
- vendor  : CPE 벤더명 (예: f5, apache)
- product : CPE 제품명 (예: nginx, log4j)
- version : 실제 설치 버전 (예: 2.14.1)
- cpe     : cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
- source_path : 탐지 근거 (선택)
"""


def run_agent(payload: dict, api_key: str) -> list[dict]:
    client = genai.Client(api_key=api_key)

    config = types.GenerateContentConfig(
        system_instruction=build_system_prompt(payload),
        tools=[AGENT_TOOLS],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(mode="AUTO")
        ),
    )

    history: list[types.Content] = []

    initial_msg = types.Content(
        role="user",
        parts=[types.Part(text=(
            "payload.json 분석을 시작합니다. "
            "탐지 대상 소프트웨어를 EC2 인스턴스에서 찾아 save_result 를 호출해 주세요."
        ))],
    )
    history.append(initial_msg)

    print(f"[AGENT] 시작 — 모델: {MODEL_NAME}, 최대 턴: {MAX_AGENT_TURNS}")

    for turn in range(MAX_AGENT_TURNS):
        response = None
        # 기본 모델 + fallback 목록 순서대로 시도
        models_to_try = [MODEL_NAME] + MODEL_FALLBACKS
        for model_candidate in models_to_try:
            for attempt in range(MAX_RETRIES):
                try:
                    response = client.models.generate_content(
                        model=model_candidate,
                        contents=history,
                        config=config,
                    )
                    break  # 성공
                except Exception as e:
                    if "503" in str(e) or "UNAVAILABLE" in str(e):
                        if attempt < MAX_RETRIES - 1:
                            print(f"[AGENT] {model_candidate} 503 — {RETRY_DELAY}초 후 재시도 ({attempt + 1}/{MAX_RETRIES})")
                            time.sleep(RETRY_DELAY)
                        else:
                            print(f"[AGENT] {model_candidate} 사용 불가 — 다음 모델로 전환")
                    else:
                        raise  # 503 외 오류는 즉시 중단
            if response is not None:
                break  # 모델 전환 루프 탈출
        if response is None:
            print("[AGENT] API 응답 실패 — 중단")
            break

        candidate = response.candidates[0]
        history.append(candidate.content)

        # function call 추출
        fn_calls = [p.function_call for p in candidate.content.parts if p.function_call]

        if not fn_calls:
            text = "".join(p.text for p in candidate.content.parts if hasattr(p, "text"))
            print(f"[AGENT] 턴 {turn + 1}: 텍스트 응답 — {text[:200]}")
            break

        tool_response_parts: list[types.Part] = []
        finished = False
        installed_software: list[dict] = []

        for fc in fn_calls:
            name = fc.name
            args = dict(fc.args)
            print(f"[AGENT] 턴 {turn + 1}: {name}({json.dumps(args, ensure_ascii=False)[:120]})")

            if name == "save_result":
                installed_software = args.get("installed_software", [])
                finished = True
                tool_response_parts.append(types.Part.from_function_response(
                    name=name, response={"result": "저장 완료"}
                ))
            else:
                result = dispatch_tool(name, args)
                preview = result[:300].replace("\n", " ")
                print(f"         → {preview}{'...' if len(result) > 300 else ''}")
                tool_response_parts.append(types.Part.from_function_response(
                    name=name, response={"output": result}
                ))

        if finished:
            print(f"[AGENT] 완료 — 탐지 소프트웨어 {len(installed_software)}개")
            return installed_software

        history.append(types.Content(role="user", parts=tool_response_parts))

    print(f"[AGENT] 최대 턴 도달 — 결과 없음")
    return []


# ---------------------------------------------------------------------------
# CLI & 메인
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Gemini AI Agent 로 EC2 자산 정보를 추출합니다."
    )
    parser.add_argument("--payload", required=True, help="payload.json 경로")
    parser.add_argument("--env", dest="environment", default="production",
                        choices=["production", "staging", "development"])
    parser.add_argument("--exposure", dest="network_exposure", default="public",
                        choices=["public", "private", "internal"])
    parser.add_argument("--criticality", dest="business_criticality", default="high",
                        choices=["critical", "high", "medium", "low"])
    parser.add_argument("--output", default="asset_info.json", help="출력 파일 경로")
    parser.add_argument("--api-key", default=None,
                        help="Gemini API 키 (미지정 시 GEMINI_API_KEY 환경변수 사용)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    api_key = args.api_key or os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        print("[ERROR] Gemini API 키가 필요합니다. --api-key 또는 GEMINI_API_KEY 환경변수를 설정하세요.")
        raise SystemExit(1)

    payload_path = Path(args.payload)
    if not payload_path.exists():
        print(f"[ERROR] payload 파일 없음: {payload_path}")
        raise SystemExit(1)

    payload = json.loads(payload_path.read_text())
    print(f"[INFO] payload 로드: {len(payload.get('records', []))}개 CVE 레코드")

    instance_id = get_instance_id()
    hostname = socket.gethostname()
    os_info = get_os_info()
    print(f"[INFO] 인스턴스: {instance_id} / OS: {os_info}")

    installed_software = run_agent(payload, api_key)

    asset_info = {
        "asset_id": instance_id,
        "hostname": hostname,
        "metadata": {
            "environment": args.environment,
            "network_exposure": args.network_exposure,
            "business_criticality": args.business_criticality,
        },
        "os_info": os_info,
        "installed_software": installed_software,
    }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(asset_info, ensure_ascii=False, indent=2))
    print(f"\n[OK] 저장 완료: {output_path.resolve()}")
    print(json.dumps(asset_info, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
