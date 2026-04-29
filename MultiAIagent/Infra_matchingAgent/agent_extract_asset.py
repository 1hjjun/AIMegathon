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
import shlex
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from google import genai
from google.genai import types


# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------

MODEL_NAME = "gemini-2.5-pro"
MODEL_FALLBACKS = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
]
_active_model: dict = {"name": None}  # 성공한 모델 이름 캐시
MAX_AGENT_TURNS = 40
COMMAND_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 10
TOOL_OUTPUT_LIMIT = 2000  # Gemini 에 돌려줄 tool 응답 최대 길이

DEFAULT_REGION = "ap-northeast-2"
SSM_POLL_INTERVAL = 1
SSM_MAX_WAIT = 45

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

def _sanitize_output(text: str) -> str:
    """tool 출력 중 큰 HTML/XML 덩어리는 짧게 대체하고 길이 제한."""
    if not text:
        return "(출력 없음)"
    low = text.lower()
    if "<!doctype html" in low or "<html" in low or "<?xml" in low:
        marker = "(HTML/XML 응답 — 엔드포인트 미활성/미지원으로 추정)"
        m = re.search(r"<title>([^<]+)</title>", text, re.IGNORECASE)
        if m:
            marker += f" [title: {m.group(1).strip()}]"
        return marker
    if len(text) > TOOL_OUTPUT_LIMIT:
        return text[:TOOL_OUTPUT_LIMIT] + "\n...(이하 생략)"
    return text


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
        return _sanitize_output(out)
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {COMMAND_TIMEOUT}초 초과"
    except Exception as e:
        return f"[ERROR] {e}"


def _execute_read_file(path: str) -> str:
    try:
        text = Path(path).read_text(errors="replace")
        return _sanitize_output(text)
    except PermissionError:
        return f"[ERROR] 권한 없음: {path}"
    except FileNotFoundError:
        return f"[ERROR] 파일 없음: {path}"
    except Exception as e:
        return f"[ERROR] {e}"


def _ssm_run_command(instance_id: str, command: str, region: str, timeout: int = SSM_MAX_WAIT) -> str:
    """AWS SSM send-command 로 EC2 에 명령을 원격 실행하고 결과를 가져온다."""
    if _BLOCKED.search(command):
        return f"[BLOCKED] 허용되지 않는 명령어: {command}"
    try:
        params = json.dumps({"commands": [command]})
        send = subprocess.run(
            ["aws", "ssm", "send-command",
             "--instance-ids", instance_id,
             "--document-name", "AWS-RunShellScript",
             "--parameters", params,
             "--region", region,
             "--query", "Command.CommandId",
             "--output", "text"],
            capture_output=True, timeout=15, text=True,
        )
        if send.returncode != 0:
            msg = (send.stderr or send.stdout).strip()
            return f"[SSM ERROR] send-command 실패: {msg}"
        cmd_id = send.stdout.strip()

        deadline = time.time() + timeout
        last_status = "Pending"
        while time.time() < deadline:
            time.sleep(SSM_POLL_INTERVAL)
            inv = subprocess.run(
                ["aws", "ssm", "get-command-invocation",
                 "--command-id", cmd_id,
                 "--instance-id", instance_id,
                 "--region", region,
                 "--output", "json"],
                capture_output=True, timeout=10, text=True,
            )
            if inv.returncode != 0:
                # 실행 시작 전이면 InvocationDoesNotExist 가 날 수 있음 → 재시도
                continue
            data = json.loads(inv.stdout)
            status = data.get("Status", "")
            last_status = status
            if status in ("Success", "Failed", "Cancelled", "TimedOut"):
                stdout = (data.get("StandardOutputContent") or "").rstrip()
                stderr = (data.get("StandardErrorContent") or "").rstrip()
                combined = "\n".join(s for s in [stdout, stderr] if s).strip()
                return _sanitize_output(combined)
        return f"[SSM TIMEOUT] {timeout}초 초과 (status={last_status})"
    except FileNotFoundError:
        return "[ERROR] aws CLI 가 설치되지 않음 (brew install awscli)"
    except subprocess.TimeoutExpired:
        return "[ERROR] aws SSM 호출 자체가 타임아웃"
    except Exception as e:
        return f"[ERROR] {e}"


def _ssm_read_file(instance_id: str, path: str, region: str) -> str:
    return _ssm_run_command(instance_id, f"cat {shlex.quote(path)}", region)


def dispatch_tool(name: str, args: dict, instance_id: str | None = None, region: str = DEFAULT_REGION) -> str:
    if name == "run_command":
        if instance_id:
            return _ssm_run_command(instance_id, args["command"], region)
        return _execute_run_command(args["command"])
    if name == "read_file":
        if instance_id:
            return _ssm_read_file(instance_id, args["path"], region)
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


def _parse_os_release(text: str) -> dict:
    if not text or text.startswith("[ERROR]") or text.startswith("[SSM") or text.startswith("[BLOCKED]"):
        return {"vendor": "unknown", "version": "unknown"}
    kv: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" not in line or line.startswith("#"):
            continue
        k, _, v = line.partition("=")
        kv[k.strip()] = v.strip().strip('"')
    vendor = kv.get("ID", "unknown").lower()
    m = re.search(r"[\d.]+", kv.get("VERSION", ""))
    version = kv.get("VERSION_ID") or (m.group(0) if m else "unknown")
    return {"vendor": vendor, "version": version}


def get_os_info() -> dict:
    p = Path("/etc/os-release")
    if not p.exists():
        return {"vendor": "unknown", "version": "unknown"}
    return _parse_os_release(p.read_text())


def get_os_info_remote(instance_id: str, region: str) -> dict:
    return _parse_os_release(_ssm_run_command(instance_id, "cat /etc/os-release", region))


def get_hostname_remote(instance_id: str, region: str) -> str:
    out = _ssm_run_command(instance_id, "hostname", region).strip()
    if out.startswith("[") or not out or out == "(출력 없음)":
        return instance_id
    return out


# ---------------------------------------------------------------------------
# AWS EC2 Discovery (auto-discover 모드 + 자동 티어 판정)
# ---------------------------------------------------------------------------

def _aws_ec2(command: list, region: str) -> dict:
    """aws ec2 <subcommand> 호출하고 JSON 파싱."""
    try:
        r = subprocess.run(
            ["aws", "ec2"] + command + ["--region", region, "--output", "json"],
            capture_output=True, timeout=30, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"aws ec2 {' '.join(command)} 실패: {(r.stderr or r.stdout).strip()}"
            )
        return json.loads(r.stdout or "{}")
    except FileNotFoundError:
        raise RuntimeError("aws CLI 가 설치되지 않음 (brew install awscli)")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"aws ec2 {' '.join(command)} 타임아웃")


def discover_vpc_instances(vpc_id: str, region: str) -> list:
    """VPC 내 running EC2 인스턴스 목록을 정규화해 반환."""
    data = _aws_ec2([
        "describe-instances",
        "--filters",
        f"Name=vpc-id,Values={vpc_id}",
        "Name=instance-state-name,Values=running",
    ], region)

    instances = []
    for resv in data.get("Reservations", []):
        for inst in resv.get("Instances", []):
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            iam_arn = inst.get("IamInstanceProfile", {}).get("Arn", "")
            instances.append({
                "instance_id": inst["InstanceId"],
                "subnet_id": inst.get("SubnetId", ""),
                "availability_zone": inst.get("Placement", {}).get("AvailabilityZone", ""),
                "private_ip": inst.get("PrivateIpAddress", ""),
                "public_ip": inst.get("PublicIpAddress", ""),
                "security_groups": [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                "tags": tags,
                "iam_instance_profile": iam_arn.split("/")[-1] if iam_arn else "",
                "name": tags.get("Name", ""),
            })
    return instances


_subnet_cache: dict = {}


def classify_subnet(subnet_id: str, region: str) -> str:
    """서브넷의 라우트 테이블로 public/private/isolated 판정."""
    if subnet_id in _subnet_cache:
        return _subnet_cache[subnet_id]

    # 1) 서브넷에 명시적으로 연결된 라우트 테이블
    data = _aws_ec2([
        "describe-route-tables",
        "--filters", f"Name=association.subnet-id,Values={subnet_id}",
    ], region)
    tables = data.get("RouteTables", [])

    # 2) 없으면 VPC의 main 라우트 테이블
    if not tables:
        subnet_data = _aws_ec2(["describe-subnets", "--subnet-ids", subnet_id], region)
        subnets = subnet_data.get("Subnets", [])
        if not subnets:
            _subnet_cache[subnet_id] = "unknown"
            return "unknown"
        vpc_id = subnets[0].get("VpcId", "")
        rt_data = _aws_ec2([
            "describe-route-tables",
            "--filters",
            f"Name=vpc-id,Values={vpc_id}",
            "Name=association.main,Values=true",
        ], region)
        tables = rt_data.get("RouteTables", [])

    routes = tables[0].get("Routes", []) if tables else []
    has_igw = any(str(r.get("GatewayId", "")).startswith("igw-") for r in routes)
    has_nat = any(str(r.get("NatGatewayId", "")).startswith("nat-") for r in routes)

    if has_igw:
        result = "public"
    elif has_nat:
        result = "private"
    else:
        result = "isolated"
    _subnet_cache[subnet_id] = result
    return result


def extract_tier(tags: dict, name: str) -> str:
    """태그 또는 Name 패턴에서 tier 추출."""
    for key in ("Tier", "tier", "Role", "role"):
        v = tags.get(key, "").lower()
        if not v:
            continue
        for t in ("web", "app", "was", "db", "database"):
            if t in v:
                return "app" if t == "was" else ("db" if t == "database" else t)

    n = (name or "").lower()
    for t in ("web", "app", "was", "db", "database"):
        if t in n:
            return "app" if t == "was" else ("db" if t == "database" else t)
    return "unknown"


def default_data_classification(tier: str) -> str:
    return {
        "web": "Internal",
        "app": "Confidential",
        "db":  "PII",
    }.get(tier, "unknown")


def _extract_ports(perm: dict) -> list:
    proto = perm.get("IpProtocol", "")
    if proto == "-1":
        return ["all"]
    fp = perm.get("FromPort")
    tp = perm.get("ToPort")
    if fp is None:
        return [proto or "unknown"]
    if fp == tp:
        return [fp]
    return [f"{fp}-{tp}"]


def build_reachability(instances: list, region: str) -> list:
    """Security Group 인바운드 규칙을 분석해 tier 간 reachability 산출."""
    all_sg_ids = sorted({sg for i in instances for sg in i["security_groups"]})
    if not all_sg_ids:
        return []

    data = _aws_ec2(["describe-security-groups", "--group-ids"] + all_sg_ids, region)
    sgs = {sg["GroupId"]: sg for sg in data.get("SecurityGroups", [])}

    sg_to_tiers: dict = {}
    for inst in instances:
        tier = inst.get("tier", "unknown")
        for sgid in inst["security_groups"]:
            sg_to_tiers.setdefault(sgid, set()).add(tier)

    reach = []
    for sgid, sg in sgs.items():
        to_tiers = sg_to_tiers.get(sgid, set())
        if not to_tiers:
            continue
        for perm in sg.get("IpPermissions", []):
            ports = _extract_ports(perm)
            for ip in perm.get("IpRanges", []):
                if ip.get("CidrIp") == "0.0.0.0/0":
                    for to_t in to_tiers:
                        reach.append({"from": "internet", "to": to_t, "ports": ports})
            for pair in perm.get("UserIdGroupPairs", []):
                src_sgid = pair.get("GroupId", "")
                for src_t in sg_to_tiers.get(src_sgid, set()):
                    for to_t in to_tiers:
                        if not (src_t == to_t and src_sgid == sgid):
                            reach.append({"from": src_t, "to": to_t, "ports": ports})

    # 중복 제거
    seen, deduped = set(), []
    for r in reach:
        key = (r["from"], r["to"], tuple(str(p) for p in r["ports"]))
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped


# ---------------------------------------------------------------------------
# 공통 Gemini 호출 래퍼 (fallback + 재시도)
# ---------------------------------------------------------------------------

def _generate_with_fallback(client: genai.Client, contents, config):
    """기본 모델 → 503 시 재시도 → 차순위 모델로 자동 전환.
    한 번 성공한 모델은 세션 내내 재사용하여 불필요한 404 호출을 회피한다."""
    if _active_model["name"]:
        candidates = [_active_model["name"]]
    else:
        candidates = [MODEL_NAME] + MODEL_FALLBACKS

    last_exc = None
    for model_candidate in candidates:
        for attempt in range(MAX_RETRIES):
            try:
                resp = client.models.generate_content(
                    model=model_candidate, contents=contents, config=config,
                )
                _active_model["name"] = model_candidate
                return resp
            except Exception as e:
                last_exc = e
                msg = str(e)
                transient = "503" in msg or "UNAVAILABLE" in msg
                not_found = "404" in msg or "NOT_FOUND" in msg or "no longer available" in msg
                if not_found:
                    print(f"[AGENT] {model_candidate} 사용 불가(404) — 다음 모델로 전환")
                    break
                if transient:
                    if attempt < MAX_RETRIES - 1:
                        print(f"[AGENT] {model_candidate} 503 — {RETRY_DELAY}초 후 재시도 ({attempt + 1}/{MAX_RETRIES})")
                        time.sleep(RETRY_DELAY)
                    else:
                        print(f"[AGENT] {model_candidate} 사용 불가 — 다음 모델로 전환")
                else:
                    raise
    # 캐시된 모델이 실패한 경우 캐시 비우고 전체 목록 재시도
    if _active_model["name"]:
        print(f"[AGENT] 캐시된 모델 {_active_model['name']} 실패 — 전체 fallback 재탐색")
        _active_model["name"] = None
        return _generate_with_fallback(client, contents, config)
    raise RuntimeError(f"모든 모델 시도 실패: {last_exc}")


# ---------------------------------------------------------------------------
# [수집 모드] 프롬프트 & 루프
# ---------------------------------------------------------------------------

def build_collect_system_prompt(payload: dict) -> str:
    targets = json.dumps(payload.get("records", []), ensure_ascii=False, indent=2)
    return f"""당신은 Linux EC2 의 **보안 자산 조사 AI 에이전트**입니다.
다음 에이전트(위험도 평가·운영 영향 평가)가 이 데이터로 CVE의 실제 위험도를 판단합니다.

## 당신의 임무 (2가지)

1. 아래 **payload** 에 담긴 CVE 대상 소프트웨어가 이 인스턴스에 설치되어 있는지,
   있다면 **정확한 버전** 을 찾아냅니다.
2. 그 취약점이 실제로 얼마나 위험한지 판단하는 데 필요한
   **자산·네트워크·권한·비즈니스 컨텍스트** 를 수집합니다.

## 입력: payload

{targets}

payload 를 스스로 읽고, product_name(예: `nginx`, `apache-log4j`) 와 cpe_criteria 에서
vendor/product 를 추출하세요. 이 인스턴스에 해당 소프트웨어가 있는지 **직접 판단** 하세요.

## 행동 원칙 (자유도)

- **어떤 shell 명령을 쓸지는 스스로 결정** 하세요. 지정된 레시피 없음.
- `run_command` / `read_file` 을 자유롭게 조합하세요.
- 파괴적 명령(rm, kill, mv, dd, mkfs, reboot 등) 은 시스템이 자동 차단합니다.
- 한 턴에 여러 tool 을 병렬로 호출해도 됩니다 (속도 향상).

## 반드시 지킬 것 (실패 패턴)

1. **같은 명령 반복 금지** — 이전 출력을 기억하세요.
2. **HTML/404 응답은 "그 기능 비활성"이라는 뜻** — 재시도하지 말고 해당 필드를 `""`/`"unknown"`/`false` 로 두고 **다음으로 넘어가세요**.
3. **installed_software 를 하나라도 확정했으면**, 나머지가 막히더라도 **지체 없이 save_result 호출**.
4. **텍스트 응답으로 종료 금지** — 최종 출력은 반드시 `save_result` 함수 호출.
5. 최대 {MAX_AGENT_TURNS} 턴 안에 종료.

## 결과물 스키마 (save_result 인자 — 형식은 엄수)

```
{{
  "installed_software": [
    {{
      "vendor":      "<CPE vendor, 예: f5, apache>",
      "product":     "<CPE product, 예: nginx, log4j>",
      "version":     "<실제 설치 버전, 예: 1.20.0, 2.14.1>",
      "cpe":         "<CPE 2.3 식별자>",
      "source_path": "<탐지 근거 경로 (선택)>"
    }}
    // 대상 소프트웨어가 없으면 빈 배열 []
  ],
  "network_context": {{
    "public_ip":          "<IMDS /public-ipv4, 없으면 ''>",
    "listening_ports":    [<LISTEN TCP 포트 번호 정수 배열>],
    "is_internet_facing": <public_ip 가 존재하면 true>
  }},
  "security_context": {{
    "attached_iam_role": "<EC2 instance profile 이름, 없으면 ''>",
    "running_as_root":   [<payload 대상 서비스 중 user=root 로 실행 중인 comm 이름들>],
    "imds_v2_enforced":  <토큰 없이 IMDS 호출 시 401 이면 true>,
    "selinux_enforced":  <getenforce == 'Enforcing' 이면 true>
  }},
  "data_classification": "<태그/호스트명 힌트 기반: PII / Payment / Internal / unknown>"
}}
```

## 조사 힌트 (막혔을 때 참고)

- **nginx 버전**: `nginx -v` 안 되면 `ps aux | grep '[n]ginx'` → 실제 바이너리 경로(예: `/usr/local/nginx/sbin/nginx`) → `<경로> -v`
- **log4j 버전**: `ps aux | grep '[j]ava'` → Java classpath 의 `log4j-core-X.Y.Z.jar` 파일명에서 버전 추출.
  Fat JAR 이면 `unzip -l <jar>` / `unzip -p <jar> META-INF/maven/.../pom.properties`
- **네트워크 포트**: `ss -tuln` / `netstat -tuln` 의 LISTEN 라인
- **IMDS v2**: 토큰 PUT → GET. iam/security-credentials/ 로 role 이름 확인
- **태그**: IMDS `/latest/meta-data/tags/instance/` 응답이 HTML 이면 미활성 → 즉시 "unknown"

## 절대 금지

- 같은 IMDS URL 을 2번 이상 호출 (한 번 HTML 응답 = 비활성 = 재시도 X)
- `ps -eo user,comm` 전체 덤프 반복 요청
- 막혔다고 텍스트로 포기 선언 — 반드시 save_result 로 종료
"""


def run_collect_agent(payload: dict, api_key: str,
                      instance_id: str | None = None,
                      region: str = DEFAULT_REGION) -> dict:
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

    exec_mode = f"SSM→{instance_id}" if instance_id else "LOCAL"
    print(f"[AGENT] 수집 모드 시작 — 모델: {MODEL_NAME}, 실행: {exec_mode}, 최대 턴: {MAX_AGENT_TURNS}")

    recovery_attempted = False
    for turn in range(MAX_AGENT_TURNS):
        response = _generate_with_fallback(client, history, config)
        candidate = response.candidates[0]

        if candidate.content is None or candidate.content.parts is None:
            print(f"[AGENT] 턴 {turn + 1}: 응답 비어 있음 (finish_reason={candidate.finish_reason})")
            if recovery_attempted:
                print(f"[AGENT] 복구 재시도도 실패 — 종료")
                break
            recovery_attempted = True
            print(f"[AGENT] 복구 시도 — 지금까지 모은 정보로 save_result 호출 유도")
            history.append(types.Content(role="user", parts=[types.Part(text=(
                "이전 응답이 깨졌습니다. 추가 조사 없이, 지금까지 확인한 정보만으로 "
                "**즉시 save_result 를 한 번 호출**해 주세요. "
                "부족한 필드는 빈 문자열 \"\" 또는 \"unknown\" 으로 두세요."
            ))]))
            continue

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
                result = dispatch_tool(name, args, instance_id, region)
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


def run_query_agent(asset_info: dict, query: str, api_key: str,
                    instance_id: str | None = None,
                    region: str = DEFAULT_REGION) -> dict:
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

    exec_mode = f"SSM→{instance_id}" if instance_id else "LOCAL"
    print(f"[AGENT] 질의 응답 모드 ({exec_mode}) — 질문: {query}")

    for turn in range(MAX_AGENT_TURNS):
        response = _generate_with_fallback(client, history, config)
        candidate = response.candidates[0]

        if candidate.content is None or candidate.content.parts is None:
            print(f"[AGENT] 턴 {turn + 1}: 응답 비어 있음 (finish_reason={candidate.finish_reason})")
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
                result = dispatch_tool(name, args, instance_id, region)
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
    parser.add_argument("--instance-id", default=None,
                        help="원격 EC2 인스턴스 ID (예: i-0123abcd). 지정 시 AWS SSM 으로 원격 실행.")
    parser.add_argument("--region", default=DEFAULT_REGION,
                        help=f"AWS 리전 (기본: {DEFAULT_REGION})")
    parser.add_argument("--vpc-id", default=None,
                        help="[auto-discover] 탐색 대상 VPC ID (예: vpc-0abcd1234)")
    parser.add_argument("--auto-discover", action="store_true",
                        help="VPC 내 running EC2 전체 자동 탐색 + 티어/노출 자동 판정")
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
        result = run_query_agent(asset_info, args.query, api_key,
                                 instance_id=args.instance_id, region=args.region)
        print("\n[RESULT]")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    # ----- 수집 모드: 공통 payload 로드 -----
    if not args.payload:
        print("[ERROR] 수집 모드에서는 --payload 가 필요합니다. (--query 로 질의 응답 모드 사용 가능)")
        raise SystemExit(1)

    payload_path = Path(args.payload)
    if not payload_path.exists():
        print(f"[ERROR] payload 파일 없음: {payload_path}")
        raise SystemExit(1)

    payload = json.loads(payload_path.read_text())
    print(f"[INFO] payload 로드: {len(payload.get('records', []))}개 CVE 레코드")

    # ----- [auto-discover 모드] VPC 내 모든 EC2 자동 탐색 + 티어 판정 -----
    if args.auto_discover:
        if not args.vpc_id:
            print("[ERROR] --auto-discover 사용 시 --vpc-id 가 필요합니다.")
            raise SystemExit(1)

        print(f"[DISCOVERY] VPC {args.vpc_id} 탐색 중 (region={args.region})...")
        try:
            instances = discover_vpc_instances(args.vpc_id, args.region)
        except RuntimeError as e:
            print(f"[ERROR] {e}")
            raise SystemExit(1)

        if not instances:
            print("[ERROR] 대상 VPC 에 running 상태의 EC2 가 없습니다.")
            raise SystemExit(1)

        print(f"[DISCOVERY] {len(instances)}개 인스턴스 발견")
        for inst in instances:
            inst["tier"] = extract_tier(inst["tags"], inst["name"])
            inst["network_exposure"] = classify_subnet(inst["subnet_id"], args.region)
            print(f"  - {inst['instance_id']} "
                  f"name={inst['name'] or '-':<20} "
                  f"tier={inst['tier']:<7} "
                  f"exposure={inst['network_exposure']:<8} "
                  f"az={inst['availability_zone']}")

        try:
            reachability = build_reachability(instances, args.region)
        except RuntimeError as e:
            print(f"[WARN] reachability 수집 실패: {e}")
            reachability = []
        print(f"[DISCOVERY] reachability 규칙 {len(reachability)}건")

        assets = []
        for idx, inst in enumerate(instances, 1):
            iid = inst["instance_id"]
            print(f"\n===== [{idx}/{len(instances)}] {iid} ({inst['tier']}) 자산 수집 =====")
            collected = run_collect_agent(payload, api_key,
                                          instance_id=iid, region=args.region)
            os_info = get_os_info_remote(iid, args.region)
            hostname = get_hostname_remote(iid, args.region)

            data_class = (
                inst["tags"].get("DataClassification")
                or collected.get("data_classification")
                or default_data_classification(inst["tier"])
            )

            assets.append({
                "asset_id": iid,
                "hostname": hostname,
                "tier": inst["tier"],
                "availability_zone": inst["availability_zone"],
                "subnet_id": inst["subnet_id"],
                "private_ip": inst["private_ip"],
                "public_ip": inst["public_ip"],
                "security_groups": inst["security_groups"],
                "iam_instance_profile": inst["iam_instance_profile"],
                "metadata": {
                    "environment": args.environment,
                    "network_exposure": inst["network_exposure"],
                    "business_criticality": args.business_criticality,
                    "data_classification": data_class,
                },
                "network_context": collected.get("network_context", {}),
                "security_context": collected.get("security_context", {}),
                "os_info": os_info,
                "installed_software": collected.get("installed_software", []),
            })

        infra = {
            "vpc_id": args.vpc_id,
            "region": args.region,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "assets": assets,
            "reachability": reachability,
        }

        output_path = Path(args.output)
        output_path.write_text(json.dumps(infra, ensure_ascii=False, indent=2))
        print(f"\n[OK] 저장 완료: {output_path.resolve()}")
        print(f"[SUMMARY] assets={len(assets)}, reachability={len(reachability)}")
        return

    if args.instance_id:
        instance_id = args.instance_id
        print(f"[INFO] 원격 모드(SSM) — 대상: {instance_id} / 리전: {args.region}")
        hostname = get_hostname_remote(instance_id, args.region)
        os_info = get_os_info_remote(instance_id, args.region)
    else:
        instance_id = get_instance_id()
        hostname = socket.gethostname()
        os_info = get_os_info()
    print(f"[INFO] 인스턴스: {instance_id} / 호스트: {hostname} / OS: {os_info}")

    collected = run_collect_agent(payload, api_key,
                                  instance_id=args.instance_id, region=args.region)

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
