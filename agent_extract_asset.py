#!/usr/bin/env python3
"""
자산 매칭 에이전트 (AI-Agent 기반).

Gemini API (Function Calling) 로 EC2 인스턴스 내부를 조사하여
취약점 평가에 필요한 자산/보안/네트워크/운영 컨텍스트를 수집한다.

두 가지 모드를 지원한다.
  1. 수집 모드 (--payload)
     payload.json 의 CVE 타겟을 받아 installed_software + network_context
     + security_context 등을 수집해 asset_info.json 으로 저장.
  2. 질의 응답 모드 (--query, swarm 대비)
     다른 Agent(위험도/운영영향 등)가 특정 질문을 주면,
     기존 asset_info.json 을 참조하면서 필요 시 EC2에서 추가 조사하여 답변한다.
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
MODEL_FALLBACKS = [
    "gemini-2.0-flash-001",
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash",
]
MAX_AGENT_TURNS = 25
COMMAND_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 10

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
        "자산 수집을 마쳤을 때 호출한다. "
        "소프트웨어·네트워크·보안·데이터 분류 정보를 종합해 전달하면 "
        "에이전트가 종료되고 asset_info.json 이 저장된다."
    ),
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "installed_software": types.Schema(
                type=types.Type.ARRAY,
                description="payload 대상 소프트웨어 탐지 결과",
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
            ),
            "network_context": types.Schema(
                type=types.Type.OBJECT,
                description="외부 공격 가능성 판단 근거",
                properties={
                    "public_ip":          types.Schema(type=types.Type.STRING,  description="IMDS 상 퍼블릭 IPv4. 없으면 빈 문자열."),
                    "listening_ports":    types.Schema(type=types.Type.ARRAY,   description="LISTEN 상태 포트 번호 목록", items=types.Schema(type=types.Type.INTEGER)),
                    "is_internet_facing": types.Schema(type=types.Type.BOOLEAN, description="public_ip 유무로 결정"),
                },
            ),
            "security_context": types.Schema(
                type=types.Type.OBJECT,
                description="폭발 반경 / 실행 권한 컨텍스트",
                properties={
                    "attached_iam_role": types.Schema(type=types.Type.STRING,  description="EC2 인스턴스 프로파일 이름 (없으면 빈 문자열)"),
                    "running_as_root":   types.Schema(type=types.Type.ARRAY,   description="root 로 실행 중인 취약 서비스의 comm 이름 (예: nginx, java)", items=types.Schema(type=types.Type.STRING)),
                    "imds_v2_enforced":  types.Schema(type=types.Type.BOOLEAN, description="IMDSv2 강제 여부 (SSRF 방어 지표)"),
                    "selinux_enforced":  types.Schema(type=types.Type.BOOLEAN, description="SELinux Enforcing 여부"),
                },
            ),
            "data_classification": types.Schema(
                type=types.Type.STRING,
                description="태그 기반 데이터 분류 (예: PII, Payment, Internal). 불확실하면 'unknown'",
            ),
        },
        required=["installed_software"],
    ),
)

ANSWER_QUERY_DECL = types.FunctionDeclaration(
    name="answer_query",
    description="질의 응답 모드 종료 시 호출. 다른 Agent의 질문에 대한 최종 답변을 전달한다.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "answer": types.Schema(type=types.Type.STRING, description="질문에 대한 짧고 명확한 답변"),
            "evidence": types.Schema(type=types.Type.ARRAY, description="답변 근거가 된 명령어 출력 또는 파일 경로", items=types.Schema(type=types.Type.STRING)),
            "confidence": types.Schema(type=types.Type.STRING, description="confidence: high / medium / low"),
        },
        required=["answer", "confidence"],
    ),
)

COLLECT_TOOLS = types.Tool(
    function_declarations=[RUN_COMMAND_DECL, READ_FILE_DECL, SAVE_RESULT_DECL]
)

QUERY_TOOLS = types.Tool(
    function_declarations=[RUN_COMMAND_DECL, READ_FILE_DECL, ANSWER_QUERY_DECL]
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
# IMDS / OS 정보 (파이썬 측에서 직접 수집)
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
# 공통 Gemini 호출 래퍼 (fallback + 재시도)
# ---------------------------------------------------------------------------

def _generate_with_fallback(client: genai.Client, contents, config):
    """기본 모델 → 503 시 재시도 → 차순위 모델로 자동 전환."""
    for model_candidate in [MODEL_NAME] + MODEL_FALLBACKS:
        for attempt in range(MAX_RETRIES):
            try:
                return client.models.generate_content(
                    model=model_candidate, contents=contents, config=config,
                )
            except Exception as e:
                if "503" in str(e) or "UNAVAILABLE" in str(e):
                    if attempt < MAX_RETRIES - 1:
                        print(f"[AGENT] {model_candidate} 503 — {RETRY_DELAY}초 후 재시도 ({attempt + 1}/{MAX_RETRIES})")
                        time.sleep(RETRY_DELAY)
                    else:
                        print(f"[AGENT] {model_candidate} 사용 불가 — 다음 모델로 전환")
                else:
                    raise
    raise RuntimeError("모든 모델 시도 실패 (503 UNAVAILABLE)")


# ---------------------------------------------------------------------------
# [수집 모드] 프롬프트 & 루프
# ---------------------------------------------------------------------------

def build_collect_system_prompt(payload: dict) -> str:
    targets = json.dumps(payload.get("records", []), ensure_ascii=False, indent=2)
    return f"""당신은 Linux EC2 인스턴스의 보안 자산 수집 에이전트입니다.
위험도 평가 에이전트와 운영 영향 에이전트가 이어서 활용할 자산 컨텍스트를
모두 모아 save_result 한 번의 호출로 저장해야 합니다.

[CVE 타겟 payload]
{targets}

[수집 항목 — 반드시 모두 채우세요]

## Phase 1. installed_software (취약 소프트웨어)
payload 의 cpe_criteria 에서 vendor / product 를 파악하고 실제 설치 버전을 확인.
- nginx   : `nginx -v` 가 실패하면 `ps aux | grep nginx` 로 실행 경로 파악 후 `<경로> -v`
- log4j 등 Java 라이브러리:
  a. `ps aux | grep java` 로 실행 중인 Java 프로세스 / jar 경로 파악
  b. `unzip -l <jar경로> | grep -i log4j` 로 내부 log4j JAR 확인
  c. `unzip -p <jar경로> META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties`
     로 버전 추출. BOOT-INF/lib/log4j-core-X.Y.Z.jar 파일명에서도 버전 확인 가능.

## Phase 2. network_context (외부 공격 가능성)
- public_ip          : `curl -s --max-time 2 http://169.254.169.254/latest/meta-data/public-ipv4`
                       출력이 비었거나 404 면 Private 인스턴스 → 빈 문자열
- listening_ports    : `ss -tuln` (없으면 `netstat -tuln`) 의 LISTEN 라인에서 포트만 숫자로 추출
- is_internet_facing : public_ip 가 존재하면 true, 없으면 false

## Phase 3. security_context (폭발 반경 / 실행 권한)
- attached_iam_role : IMDSv2 토큰 발급 후
    `TOKEN=$(curl -s --max-time 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token) && \
     curl -s --max-time 2 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/`
    (없으면 빈 문자열)
- imds_v2_enforced  : 위 IMDSv2 호출이 성공하고, 토큰 없이 호출 시 401/403 이 나오면 true
    비교 명령 : `curl -s --max-time 2 -o /dev/null -w "%{{http_code}}" http://169.254.169.254/latest/meta-data/`
- running_as_root   : `ps -eo user,comm` 결과에서 payload 대상 서비스(nginx, java, log4j 등)의
                      user 가 root 인 comm 이름만 배열로 수집
- selinux_enforced  : `getenforce` 출력이 "Enforcing" 이면 true, 아니면 false

## Phase 4. data_classification
- EC2 태그 조회 : `TOKEN=$(curl -s --max-time 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token) && \
   curl -s --max-time 2 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/tags/instance/`
- 태그 목록 중 `DataClassification` / `Service` / `Environment` 에서 힌트를 얻어
  "PII" / "Payment" / "Internal" / "unknown" 등으로 분류.
- 태그 API 가 비활성이면 "unknown" 로 기록.

[행동 규칙]
1. 필요한 만큼 run_command / read_file 도구를 호출해도 됩니다 (최대 {MAX_AGENT_TURNS} 턴).
2. 같은 명령을 반복하지 말고, 실패 시 대안 명령을 시도하세요.
3. 확실하지 않은 항목은 빈 값 / unknown 으로 기록하고 다음으로 진행합니다.
4. 모든 Phase 를 끝낸 후 반드시 save_result 를 한 번 호출하세요.
"""


def run_collect_agent(payload: dict, api_key: str) -> dict:
    """수집 모드 에이전트 루프. save_result 의 payload dict 를 그대로 반환."""
    client = genai.Client(api_key=api_key)
    config = types.GenerateContentConfig(
        system_instruction=build_collect_system_prompt(payload),
        tools=[COLLECT_TOOLS],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(mode="AUTO")
        ),
    )

    history: list[types.Content] = [types.Content(
        role="user",
        parts=[types.Part(text=(
            "payload 분석을 시작합니다. "
            "Phase 1~4 를 모두 조사한 뒤 save_result 를 한 번 호출해 주세요."
        ))],
    )]

    print(f"[AGENT] 수집 모드 시작 — 모델: {MODEL_NAME}, 최대 턴: {MAX_AGENT_TURNS}")

    for turn in range(MAX_AGENT_TURNS):
        response = _generate_with_fallback(client, history, config)
        candidate = response.candidates[0]

        if candidate.content is None:
            print(f"[AGENT] 턴 {turn + 1}: content=None (finish_reason={candidate.finish_reason}) — 재시도 없이 종료")
            break

        history.append(candidate.content)

        fn_calls = [p.function_call for p in candidate.content.parts if p.function_call]
        if not fn_calls:
            text = "".join(p.text for p in candidate.content.parts if hasattr(p, "text"))
            print(f"[AGENT] 턴 {turn + 1}: 텍스트 응답 — {text[:200]}")
            break

        tool_responses: list[types.Part] = []
        for fc in fn_calls:
            name = fc.name
            args = dict(fc.args)
            print(f"[AGENT] 턴 {turn + 1}: {name}({json.dumps(args, ensure_ascii=False)[:120]})")

            if name == "save_result":
                print(f"[AGENT] 수집 완료 — 결과 수신")
                return args
            else:
                result = dispatch_tool(name, args)
                preview = result[:300].replace("\n", " ")
                print(f"         → {preview}{'...' if len(result) > 300 else ''}")
                tool_responses.append(types.Part.from_function_response(
                    name=name, response={"output": result}
                ))

        history.append(types.Content(role="user", parts=tool_responses))

    print(f"[AGENT] 최대 턴 도달 — 수집 미완료")
    return {"installed_software": []}


# ---------------------------------------------------------------------------
# [질의 응답 모드] swarm 대비 — 다른 Agent의 질문에 자산 정보로 답변
# ---------------------------------------------------------------------------

def build_query_system_prompt(asset_info: dict) -> str:
    asset_context = json.dumps(asset_info, ensure_ascii=False, indent=2)
    return f"""당신은 자산 매칭 에이전트의 질의 응답 모드입니다.
다른 에이전트(위험도 평가·운영 영향 평가)가 이 자산에 대해 구체적인 질문을 보내면
아래 수집된 자산 정보를 우선 참고하고, 부족하면 run_command / read_file 로
EC2 에서 직접 추가 조사한 뒤 answer_query 를 호출해 답변하세요.

[이미 수집된 asset_info.json]
{asset_context}

[응답 규칙]
1. 이미 asset_info 에 답이 있으면 추가 명령 없이 바로 answer_query 를 호출.
2. 없으면 최소한의 명령만 실행해 확인한 뒤 answer_query.
3. answer 는 간결한 한 줄, evidence 에는 근거 명령/파일, confidence 는 high/medium/low 중 하나.
"""


def run_query_agent(asset_info: dict, query: str, api_key: str) -> dict:
    client = genai.Client(api_key=api_key)
    config = types.GenerateContentConfig(
        system_instruction=build_query_system_prompt(asset_info),
        tools=[QUERY_TOOLS],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(mode="AUTO")
        ),
    )

    history: list[types.Content] = [types.Content(
        role="user",
        parts=[types.Part(text=f"[질문] {query}")],
    )]

    print(f"[AGENT] 질의 응답 모드 — 질문: {query}")

    for turn in range(MAX_AGENT_TURNS):
        response = _generate_with_fallback(client, history, config)
        candidate = response.candidates[0]

        if candidate.content is None:
            print(f"[AGENT] 턴 {turn + 1}: content=None (finish_reason={candidate.finish_reason})")
            break

        history.append(candidate.content)

        fn_calls = [p.function_call for p in candidate.content.parts if p.function_call]
        if not fn_calls:
            text = "".join(p.text for p in candidate.content.parts if hasattr(p, "text"))
            return {"answer": text, "evidence": [], "confidence": "low"}

        tool_responses: list[types.Part] = []
        for fc in fn_calls:
            name = fc.name
            args = dict(fc.args)
            print(f"[AGENT] 턴 {turn + 1}: {name}({json.dumps(args, ensure_ascii=False)[:120]})")

            if name == "answer_query":
                return args
            else:
                result = dispatch_tool(name, args)
                preview = result[:300].replace("\n", " ")
                print(f"         → {preview}{'...' if len(result) > 300 else ''}")
                tool_responses.append(types.Part.from_function_response(
                    name=name, response={"output": result}
                ))

        history.append(types.Content(role="user", parts=tool_responses))

    return {"answer": "(응답 생성 실패 — 최대 턴 도달)", "evidence": [], "confidence": "low"}


# ---------------------------------------------------------------------------
# CLI & 메인
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Gemini AI Agent 기반 자산 매칭 에이전트 (수집·질의 이중 모드)."
    )
    parser.add_argument("--payload", default=None, help="[수집 모드] payload.json 경로")
    parser.add_argument("--query",   default=None, help="[질의 응답 모드] 다른 Agent가 보낸 질문 텍스트")
    parser.add_argument("--asset-info", default="asset_info.json", help="[질의 응답 모드] 참조할 asset_info.json 경로")
    parser.add_argument("--env", dest="environment", default="production",
                        choices=["production", "staging", "development"])
    parser.add_argument("--exposure", dest="network_exposure", default="public",
                        choices=["public", "private", "internal"])
    parser.add_argument("--criticality", dest="business_criticality", default="high",
                        choices=["critical", "high", "medium", "low"])
    parser.add_argument("--output", default="asset_info.json", help="[수집 모드] 출력 파일 경로")
    parser.add_argument("--api-key", default=None,
                        help="Gemini API 키 (미지정 시 GEMINI_API_KEY 환경변수 사용)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    api_key = args.api_key or os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        print("[ERROR] Gemini API 키가 필요합니다. --api-key 또는 GEMINI_API_KEY 환경변수를 설정하세요.")
        raise SystemExit(1)

    # ----- 질의 응답 모드 -----
    if args.query:
        asset_path = Path(args.asset_info)
        if not asset_path.exists():
            print(f"[ERROR] asset_info 파일 없음: {asset_path}")
            raise SystemExit(1)
        asset_info = json.loads(asset_path.read_text())
        result = run_query_agent(asset_info, args.query, api_key)
        print("\n[RESULT]")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    # ----- 수집 모드 -----
    if not args.payload:
        print("[ERROR] 수집 모드에서는 --payload 가 필요합니다. (--query 로 질의 응답 모드 사용 가능)")
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

    collected = run_collect_agent(payload, api_key)

    asset_info = {
        "asset_id": instance_id,
        "hostname": hostname,
        "metadata": {
            "environment": args.environment,
            "network_exposure": args.network_exposure,
            "business_criticality": args.business_criticality,
            "data_classification": collected.get("data_classification", "unknown"),
        },
        "network_context": collected.get("network_context", {
            "public_ip": "", "listening_ports": [], "is_internet_facing": False,
        }),
        "security_context": collected.get("security_context", {
            "attached_iam_role": "", "running_as_root": [],
            "imds_v2_enforced": False, "selinux_enforced": False,
        }),
        "os_info": os_info,
        "installed_software": collected.get("installed_software", []),
    }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(asset_info, ensure_ascii=False, indent=2))
    print(f"\n[OK] 저장 완료: {output_path.resolve()}")
    print(json.dumps(asset_info, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
