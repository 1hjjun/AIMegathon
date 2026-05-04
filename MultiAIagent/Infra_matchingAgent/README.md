# 자산 매칭 에이전트

취약점 자동 위험도 판단 시스템의 **자산 매칭 에이전트**입니다.
VPC 내 3-Tier 아키텍처(web/app/db)에서 EC2 인스턴스를 자동 탐색하고,
각 인스턴스의 소프트웨어·네트워크·보안 컨텍스트를 수집해 `infra_context.json` 형태로 다음 에이전트에 전달합니다.

**AWS Bedrock AgentCore Runtime** 위에서 동작하며, **Claude Haiku 4.5** 가 LLM 백엔드입니다.
EC2 진입은 AWS SSM 으로 처리하므로 PEM 키 없이 동작합니다.

---

## 전체 팀 아키텍처

```text
[취약점 수집 Agent]  →  [자산 매칭 Agent (본 repo)]  →  [위험도 평가 Agent]  →  [운영 영향 Agent]

         payload.json ─┐                  infra_context.json ─┐
                       ↓                                      ↓
            (CVE × 자산 매칭)                    (자산 컨텍스트 기반 위험도 산정)
                                                              │
                                                              └─ 추가 질의 ─→ query 모드 응답
```

---

## 인프라 구성 (3-Tier)

```text
                        Internet
                           │
              ┌────────────▼────────────┐
              │   Public Subnet         │
              │   Web-01, Web-02        │  (nginx 1.20.0)
              └────────────┬────────────┘
                           │ :8080
              ┌────────────▼────────────┐
              │   Private Subnet (NAT)  │
              │   App-01, App-02        │  (log4j 2.14.1 / Spring Boot)
              └────────────┬────────────┘
                           │ :3306
              ┌────────────▼────────────┐
              │   Private Subnet        │
              │   DB                    │  (MySQL/PostgreSQL)
              └─────────────────────────┘
```

티어 판정 우선순위: EC2 태그(`Tier`, `Role`) → `Name` 패턴 → `unknown`
서브넷 노출도 판정: 라우트 테이블의 `0.0.0.0/0` 대상이 IGW면 `public`, NAT면 `private`, 둘 다 없으면 `isolated`

---

## 배포 정보

- **Runtime ARN**: `arn:aws:bedrock-agentcore:ap-northeast-2:<AWS 계정 ID>:runtime/asset_matching_agent-<배포 시 자동 생성 ID>`
- **Region**: `ap-northeast-2`
- **LLM**: `global.anthropic.claude-haiku-4-5-20251001-v1:0` (Bedrock 글로벌 추론 프로파일)
- **Execution Role**: `arn:aws:iam::<AWS 계정 ID>:role/AssetMatchingAgentCoreRole`
- **배포 방식**: `direct_code_deploy` (S3 코드 zip → 관리형 Python 3.12 런타임)
- **Entrypoint**: `runtime_app.py`

---

## 실행 흐름

```text
호출자 (다른 에이전트 또는 CLI)
  └─ bedrock-agentcore:InvokeAgentRuntime  (JSON payload)
        │
   ┌────▼─────────────────────────────────────────────┐
   │  AgentCore Runtime (asset_matching_agent)        │
   │    └─ runtime_app.py invoke(payload)             │
   │         ├─ mode=collect       → 단일 EC2 자산 수집
   │         ├─ mode=auto_discover → VPC 전체 자동 탐색
   │         └─ mode=query         → 자산 정보 추가 질의
   └────┬─────────────────────────────────────────────┘
        │
        ├─ Bedrock Converse (Claude Haiku 4.5, tool use 루프)
        │
        ├─ EC2 API     : Describe* (VPC 토폴로지 / SG / 라우트 테이블)
        │
        └─ SSM         : send-command (각 인스턴스 진입)
              └─ shell 명령 실행 → 결과 회신 → LLM 다음 턴
```

---

## 호출 방법

### 호출 페이로드 공통 스키마

```json
{
  "mode": "collect | query | auto_discover",
  "region": "ap-northeast-2",
  "instance_id": "i-...",
  "cve_payload": { "records": [ ... ] },
  "vpc_id": "vpc-...",
  "asset_info": { ... },
  "question": "...",
  "metadata": {
    "environment": "production",
    "network_exposure": "public",
    "business_criticality": "high"
  }
}
```

각 필드의 사용 모드:

| 필드          | collect | auto_discover | query |
| ------------- | :-----: | :-----------: | :---: |
| `cve_payload` |  필수   |     필수      |   —   |
| `vpc_id`      |    —    |     필수      |   —   |
| `instance_id` |  선택   |       —       | 선택  |
| `asset_info`  |    —    |       —       | 필수  |
| `question`    |    —    |       —       | 필수  |
| `metadata`    |  선택   |     선택      |   —   |

`instance_id` 미지정 시 collect 모드는 AgentCore 컨테이너 자체를 조사합니다 (개발용). 실무에서는 항상 instance_id 지정.

### 모드 1 — `auto_discover` (권장, 데모용 메인 진입점)

VPC 내 모든 running EC2 자동 탐색 + 티어 판정 + 자산 수집 + reachability 계산.

```bash
agentcore invoke "$(python3 -c "
import json
payload = json.load(open('payload.json'))
print(json.dumps({
  'mode': 'auto_discover',
  'cve_payload': payload,
  'vpc_id': '<대상 VPC ID>',
  'metadata': {'environment': 'production', 'business_criticality': 'high'}
}))")"
```

응답: `{"infra_context": {...}}` — 그대로 위험도 평가 에이전트에 전달.

### 모드 2 — `collect` (단일 인스턴스)

특정 EC2 1대만 조사할 때.

```bash
agentcore invoke '{
  "mode": "collect",
  "cve_payload": {"records": [...]},
  "instance_id": "<EC2 인스턴스 ID>",
  "metadata": {"environment": "production", "network_exposure": "private", "business_criticality": "high"}
}'
```

응답: `{"asset_info": {...}}`

### 모드 3 — `query` (Swarm 연동, 위험도 평가 에이전트용)

위험도 평가 에이전트가 `infra_context.json` 만으로 부족한 추가 정보가 필요할 때 호출.

```bash
agentcore invoke '{
  "mode": "query",
  "asset_info": { ... 단일 asset 객체 ... },
  "instance_id": "<EC2 인스턴스 ID>",
  "question": "log4j 2.14.1 에 Log4Shell mitigation 이 적용되어 있는가?"
}'
```

응답:

```json
{
  "answer": "Log4Shell mitigation이 적용되지 않음. (1) JVM 옵션 미설정 (2) 환경변수 미설정 (3) JndiLookup.class 존재.",
  "evidence": [
    "ps aux 결과: -Dlog4j2.formatMsgNoLookups=true 옵션 없음",
    "env | grep -i log4j: LOG4J_FORMAT_MSG_NO_LOOKUPS 환경변수 없음",
    "jar -tf /app/lib/log4j-core-2.14.1.jar: JndiLookup.class 존재 확인"
  ],
  "confidence": "high"
}
```

---

## `payload.json` 스키마 (입력 — 취약점 수집 에이전트 출력)

```json
{
  "agent": "asset_matching",
  "source_dataset": "focused_selected_raw_cves.json",
  "record_count": 2,
  "records": [
    {
      "cve_id": "CVE-2021-23017",
      "product_name": "nginx",
      "affected_version_range": [">=0.6.18 <1.20.1"],
      "fixed_version": "1.20.1",
      "product_status": "affected",
      "cpe_criteria": ["cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"]
    },
    {
      "cve_id": "CVE-2021-44228",
      "product_name": "apache-log4j",
      "affected_version_range": [">=2.0.1 <2.3.1", ">=2.13.0 <2.15.0"],
      "fixed_version": "2.15.0",
      "product_status": "affected",
      "cpe_criteria": ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"]
    }
  ]
}
```

`records[].cpe_criteria` 의 vendor/product 를 LLM 이 직접 추출해 탐지 대상으로 사용합니다.

---

## `infra_context.json` 출력 스키마 (위험도 평가 에이전트로 전달)

```json
{
  "vpc_id": "<대상 VPC ID>",
  "region": "ap-northeast-2",
  "collected_at": "2026-04-29T14:23:21.182306+00:00",
  "assets": [
    {
      "asset_id": "<EC2 인스턴스 ID>",
      "hostname": "<EC2 호스트네임>",
      "tier": "app",
      "availability_zone": "ap-northeast-2a",
      "subnet_id": "<서브넷 ID>",
      "private_ip": "<인스턴스 사설 IP>",
      "public_ip": "",
      "security_groups": ["<보안 그룹 ID>"],
      "iam_instance_profile": "<EC2 인스턴스 프로파일>",
      "metadata": {
        "environment": "production",
        "network_exposure": "private",
        "business_criticality": "high",
        "data_classification": "Internal"
      },
      "network_context": {
        "public_ip": "",
        "listening_ports": [22, 8080],
        "is_internet_facing": false
      },
      "security_context": {
        "attached_iam_role": "<EC2 인스턴스 IAM 역할>",
        "running_as_root": ["java"],
        "imds_v2_enforced": false,
        "selinux_enforced": false
      },
      "os_info": { "vendor": "amzn", "version": "2023" },
      "installed_software": [
        {
          "vendor": "apache",
          "product": "log4j",
          "version": "2.14.1",
          "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
          "source_path": "/app/lib/log4j-core-2.14.1.jar"
        }
      ]
    }
  ],
  "reachability": [
    { "from": "web", "to": "app", "ports": [8080] },
    { "from": "app", "to": "db", "ports": [3306] }
  ]
}
```

### 각 섹션의 용도

| 섹션                 | 위험도 평가 시 사용처                   | 수집 방법                                   |
| -------------------- | --------------------------------------- | ------------------------------------------- |
| `metadata`           | 환경·중요도·데이터 민감도 (점수 가중치) | payload metadata + 티어 기반 자동           |
| `network_context`    | 외부 공격 가능성 (`is_internet_facing`) | IMDS + `ss -tuln`                           |
| `security_context`   | 폭발 반경(IAM) + 권한 + 방어 기제       | IMDS + `ps -eo user,comm` + `getenforce`    |
| `os_info`            | OS 단위 패치 매칭                       | `/etc/os-release`                           |
| `installed_software` | CVE 버전 매칭의 핵심 입력               | LLM 자율 탐지 (vendor/product/version 동시) |
| `reachability`       | lateral movement 시뮬레이션             | Security Group 인바운드 규칙 분석           |

---

## AI Agent 내부 동작

### 수집 Phase (LLM이 자율 결정)

| Phase | 수집 내용            | 대표 명령어                                                                      |
| ----- | -------------------- | -------------------------------------------------------------------------------- |
| 1     | 취약 소프트웨어 버전 | `nginx -v` 또는 `<경로> -v`, `ps aux \| grep java`, `find / -name "log4j*.jar"`  |
| 2     | 네트워크 컨텍스트    | IMDS `/public-ipv4`, `ss -tuln`                                                  |
| 3     | 보안 컨텍스트        | IMDSv2 토큰 발급 → `iam/security-credentials/`, `ps -eo user,comm`, `getenforce` |
| 4     | 데이터 분류          | IMDS `/tags/instance/` 조회                                                      |

LLM 에게 명령 레시피를 주지 않습니다. 목표·결과물 스키마·실패 패턴만 시스템 프롬프트로 주고, 어떤 명령을 쓸지는 모델이 직접 결정합니다.

> **실제 탐지 사례**: nginx 가 PATH 에 없어 `nginx -v` 가 실패하자, 에이전트가 `ps aux | grep nginx` 로 프로세스를 찾아 실행 경로(`/usr/local/nginx/sbin/nginx`)에서 직접 버전을 조회. log4j 는 Java 프로세스의 classpath 에서 `log4j-core-2.14.1.jar` 파일명을 파싱해 탐지.

### Agent Tools (Bedrock toolSpec)

- **`run_command`** — 읽기/조회 shell 명령 실행. `instance_id` 가 있으면 SSM 으로 원격, 없으면 컨테이너 로컬. 파괴적 명령은 정규식 차단.
- **`read_file`** — 파일 내용 읽기 (SSM 또는 로컬).
- **`save_result`** — 수집 모드 종료 시 호출. `installed_software` / `network_context` / `security_context` / `data_classification` 제출.
- **`answer_query`** — 질의 응답 모드 종료 시 호출. `answer` + `evidence` + `confidence` 반환.

### 안전 장치

- **파괴적 명령 차단**: `rm`, `rmdir`, `mv`, `dd`, `mkfs`, `fdisk`, `kill`, `killall`, `reboot`, `shutdown`, `halt`
- **출력 길이 제한**: tool 응답 2000자로 truncation
- **HTML/XML 응답 마커화**: 비활성 엔드포인트 응답을 짧은 마커로 치환해 LLM 컨텍스트 절약
- **최대 턴 제한**: 40턴
- **빈 응답 복구**: 응답이 비면 1회 한정 "지금까지 정보로 save_result" 유도
- **Throttling 재시도**: Bedrock `ThrottlingException` 등은 지수 백오프 재시도

---

## VPC 자동 탐색 로직

```text
discover_vpc_instances(vpc_id, region)
  └─ ec2:DescribeInstances (vpc-id 필터, running 상태)
        └─ classify_subnet(subnet_id)
              └─ ec2:DescribeRouteTables (subnet 연결 또는 main)
                    → routes 에 IGW 있음   → public
                    → routes 에 NAT 있음   → private
                    → 둘 다 없음           → isolated

build_reachability(instances, region)
  └─ ec2:DescribeSecurityGroups
        └─ 인바운드 규칙에서 소스 SG → 대상 SG 매핑
              └─ tier-to-tier 포트 집합 산출
              └─ 0.0.0.0/0 소스는 'internet' tier 로 표기
```

티어 기반 `data_classification` 기본값: `db → PII`, `app → Confidential`, `web → Internal`

---

## 파일 구성

| 파일                      | 설명                                                                   |
| ------------------------- | ---------------------------------------------------------------------- |
| `agent_extract_asset.py`  | 자산 매칭 에이전트 본체. boto3 + Bedrock Converse API.                 |
| `runtime_app.py`          | AgentCore Runtime entrypoint (`BedrockAgentCoreApp`). 페이로드 라우팅. |
| `requirements.txt`        | `bedrock-agentcore`, `boto3`                                           |
| `.bedrock_agentcore.yaml` | AgentCore 배포 설정 (deployment_type, runtime_type, IAM role 등).      |
| `payload.json`            | 취약점 수집 에이전트로부터 받는 CVE 타겟 입력 샘플.                    |
| `infra_context.json`      | 수집 결과 출력 (VPC 전체 자산 + reachability) 샘플.                    |
| `asset_info.json`         | 단일 인스턴스 수집 결과 샘플.                                          |
| `.gitignore`              | `.venv`, `dependencies.zip`, `dependencies.hash` 등 제외.              |

---

## IAM 권한

### Runtime Execution Role (`AssetMatchingAgentCoreRole`)

Trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "bedrock-agentcore.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Permissions policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BedrockInvoke",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:Converse",
        "bedrock:ConverseStream"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SSMRunCommand",
      "Effect": "Allow",
      "Action": [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:ListCommandInvocations"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2Describe",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRouteTables"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Logs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:<AWS 계정 ID>:*"
    }
  ]
}
```

### EC2 인스턴스 측 IAM 권한

각 EC2 에 `AmazonSSMManagedInstanceCore` 정책이 연결된 Instance Profile 이 필요합니다.
(데모 인프라는 `<EC2 인스턴스 프로파일>` 사용)

---

## 배포 가이드

### 사전 준비

```bash
# 1) Python venv + 의존성
python3 -m venv .venv
source .venv/bin/activate
pip install bedrock-agentcore-starter-toolkit bedrock-agentcore boto3

# 2) uv 설치 (Docker 없이 direct_code_deploy 하려면 필요)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 3) AWS 자격증명 확인
aws sts get-caller-identity
```

### 재배포 (코드 수정 후)

```bash
source .venv/bin/activate
source $HOME/.local/bin/env   # uv 경로
agentcore deploy
```

`.bedrock_agentcore.yaml` 의 `agent_arn` 이 유지되므로 같은 Runtime 을 in-place 업데이트합니다.

### 신규 배포 (다른 계정/리전)

1. `AssetMatchingAgentCoreRole` IAM 역할을 위 정책으로 생성
2. `.bedrock_agentcore.yaml` 의 `account`, `region`, `execution_role` 갱신
3. `agentcore deploy`

### 상태 확인 / 호출 / 로그

```bash
agentcore status
agentcore invoke '{...}'
aws logs tail /aws/bedrock-agentcore/runtimes/asset_matching_agent-<배포 시 자동 생성 ID>-DEFAULT --since 1h
```

---

## Swarm 연동 (다른 에이전트가 호출하는 법)

다른 에이전트가 Python 에서 호출:

```python
import boto3, json

client = boto3.client("bedrock-agentcore", region_name="ap-northeast-2")
resp = client.invoke_agent_runtime(
    agentRuntimeArn="arn:aws:bedrock-agentcore:ap-northeast-2:<AWS 계정 ID>:runtime/asset_matching_agent-<배포 시 자동 생성 ID>",
    payload=json.dumps({
        "mode": "auto_discover",
        "cve_payload": {...},
        "vpc_id": "vpc-...",
    }).encode(),
)
result = json.loads(resp["response"].read())
```

호출자 IAM 에 `bedrock-agentcore:InvokeAgentRuntime` 액션 권한이 필요합니다.

---

## 데모 시나리오 (검증된 4단계 흐름)

1. **payload.json** (취약점 수집 에이전트 출력 가정) — nginx / log4j CVE 2건
2. **`auto_discover` 호출** — VPC 내 5개 EC2 자동 탐색 → 각 인스턴스 SSM 진입 → 자산 수집
3. **`infra_context.json` 출력** — 5개 자산 + reachability 2건
   - Web-01/02: nginx 1.20.0 (CVE-2021-23017 취약)
   - App-01/02: log4j 2.14.1 (CVE-2021-44228 취약)
   - DB: 취약점 없음
   - reachability: `web → app:8080`, `app → db:3306`
4. **`query` 후속 질의** (위험도 평가 에이전트가 위험도 보정 위해 추가 질의)
   - "log4j mitigation 적용 여부?" → mitigation 없음 (high confidence)
   - "RCE 시 IAM 폭발 반경?" → `ssm:GetParameter` 만 가능 (Low Blast Radius)

---

## 주의사항

- AgentCore Runtime 은 in-flight invocation 단위로 과금됩니다. idle 비용은 없음.
- 코드 변경 후 `agentcore deploy` 를 다시 실행해야 반영됩니다.
- IAM 정책 변경은 즉시 반영되지 않습니다. 새 정책이 필요한 호출은 재배포로 credential 갱신을 강제하세요.
- `run_command` 도구는 `rm`, `kill`, `reboot` 등 파괴적 명령어를 정규식으로 차단하지만, **read-only 동작 가정** 하에 설계되어 있으므로 SSM 권한을 좁혀 두는 것이 안전합니다.
- IMDSv2 강제 환경에서는 에이전트가 스스로 토큰을 발급하여 IMDS 를 호출합니다.
- `.env`, `.venv/`, `dependencies.zip` 은 git 커밋 금지.
