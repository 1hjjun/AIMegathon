# 자산 매칭 에이전트

취약점 자동 위험도 판단 시스템의 **자산 매칭 에이전트**입니다.
VPC 내 3-Tier 아키텍처(web/app/db)에서 EC2 인스턴스를 자동 탐색하고,
각 인스턴스의 소프트웨어·네트워크·보안 컨텍스트를 수집해 `infra_context.json`으로 저장합니다.
로컬 PC에서 AWS SSM을 통해 원격으로 실행되며, PEM 키 없이 동작합니다.

---

## 전체 팀 아키텍처

```text
[취약점 수집 Agent]  →  [자산 매칭 Agent]  →  [위험도 평가 Agent]  →  [운영 영향 Agent]
    (재민)                (형준, 본 repo)          (수환)                   (수환)

         payload.json ─┐           infra_context.json ─┐
                       ↓                               ↓
            (CVE × 자산 매칭)             (자산 컨텍스트 기반 위험도 산정)
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

---

## 실행 흐름 (로컬 → SSM → EC2)

```text
로컬 PC
  └─ agent_extract_asset.py --auto-discover --vpc-id vpc-xxx
        │
        ├─ AWS EC2 API  : VPC 내 running 인스턴스 목록 조회
        ├─ AWS EC2 API  : 서브넷 라우트 테이블로 public/private/isolated 판정
        ├─ AWS EC2 API  : Security Group 분석 → tier-to-tier reachability
        │
        └─ (인스턴스마다) SSM send-command
               └─ Gemini Agent (Function Calling 루프)
                     ├─ run_command  : shell 명령 원격 실행
                     ├─ read_file   : 파일 읽기
                     └─ save_result : 수집 완료 → asset_info 반환

최종 저장: infra_context.json  (assets[] + reachability[])
```

---

## 실행 모드

### 모드 1 — VPC 자동 탐색 (권장)

```bash
export GEMINI_API_KEY="your-api-key"
python3 agent_extract_asset.py \
    --auto-discover \
    --vpc-id vpc-095126a9a0924a7e2 \
    --output infra_context.json \
    --region ap-northeast-2
```

- VPC 내 모든 running EC2를 자동 탐색
- 서브넷 라우트 테이블 기반으로 network_exposure 자동 판정
- Security Group 분석으로 tier간 reachability 자동 산출
- 각 인스턴스에 SSM으로 원격 접속하여 에이전트 실행

### 모드 2 — 단일 인스턴스 수집

```bash
python3 agent_extract_asset.py \
    --payload payload.json \
    --output  asset_info.json \
    --instance-id i-0xxxxxxxxxxxxxxxxx \
    --env production --exposure public --criticality high
```

### 모드 3 — 질의 응답 (Swarm 연동)

위험도 평가 에이전트 등 다른 에이전트가 자산 정보를 추가로 질의할 때 사용합니다.

```bash
python3 agent_extract_asset.py \
    --query "nginx 가 root 권한으로 실행 중인가? 80 포트가 외부에 열려 있는가?" \
    --asset-info asset_info.json
```

출력 예시:

```json
{
  "answer": "nginx 마스터 프로세스는 root로 실행 중이며 80 포트는 LISTEN 상태입니다.",
  "evidence": [
    "ps -eo user,comm | grep nginx → root  nginx",
    "ss -tuln → LISTEN 0.0.0.0:80"
  ],
  "confidence": "high"
}
```

---

## CLI 인자 전체 목록

| 인자              | 설명                                     | 기본값               |
| ----------------- | ---------------------------------------- | -------------------- |
| `--auto-discover` | VPC 내 EC2 전체 자동 탐색 모드           | —                    |
| `--vpc-id`        | 탐색할 VPC ID                            | —                    |
| `--payload`       | CVE 타겟 JSON 파일 경로                  | —                    |
| `--output`        | 결과 저장 경로                           | `infra_context.json` |
| `--instance-id`   | 단일 인스턴스 지정                       | —                    |
| `--query`         | 질의 응답 모드 질문 문자열               | —                    |
| `--asset-info`    | 질의 응답 모드에서 참조할 기존 결과 JSON | —                    |
| `--region`        | AWS 리전                                 | `ap-northeast-2`     |
| `--env`           | 환경 레이블 (production/staging/dev)     | `production`         |
| `--exposure`      | 네트워크 노출 (public/private/isolated)  | 자동 판정            |
| `--criticality`   | 비즈니스 중요도 (high/medium/low)        | 티어 기반 자동       |

---

## 출력 스키마 — `infra_context.json`

```json
{
  "vpc_id": "vpc-095126a9a0924a7e2",
  "region": "ap-northeast-2",
  "collected_at": "2026-04-24T04:14:00+00:00",
  "assets": [
    {
      "asset_id": "i-0xxxxxxxxxxxxxxxxx",
      "hostname": "ip-10-0-1-10.ap-northeast-2.compute.internal",
      "tier": "web",
      "availability_zone": "ap-northeast-2a",
      "subnet_id": "subnet-xxxxxxxxxxxxxxxxx",
      "private_ip": "10.0.1.10",
      "public_ip": "3.34.xx.xx",
      "security_groups": ["sg-xxxxxxxxxxxxxxxxx"],
      "iam_instance_profile": "megathon-SSMRole-xxxxxxxx",
      "metadata": {
        "environment": "production",
        "network_exposure": "public",
        "business_criticality": "high",
        "data_classification": "Internal"
      },
      "network_context": {
        "public_ip": "3.34.xx.xx",
        "listening_ports": [22, 80],
        "is_internet_facing": true
      },
      "security_context": {
        "attached_iam_role": "megathon-SSMRole-xxxxxxxx",
        "running_as_root": ["nginx"],
        "imds_v2_enforced": true,
        "selinux_enforced": false
      },
      "os_info": {
        "vendor": "amzn",
        "version": "2023"
      },
      "installed_software": [
        {
          "vendor": "f5",
          "product": "nginx",
          "version": "1.20.0",
          "cpe": "cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*"
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

### 각 섹션의 목적

| 섹션                 | 용도                                   | 수집 방법                                     |
| -------------------- | -------------------------------------- | --------------------------------------------- |
| `metadata`           | 환경·중요도·데이터 민감도 분류         | CLI 인자 + EC2 태그 + 티어 기반 기본값        |
| `network_context`    | 외부 공격 가능성 판단                  | IMDS + `ss -tuln`                             |
| `security_context`   | 폭발 반경(IAM) + 실행 권한 + 방어 기제 | IMDS(iam) + `ps -eo user,comm` + `getenforce` |
| `os_info`            | OS 단위 취약점 매칭                    | `/etc/os-release`                             |
| `installed_software` | CVE 버전 매칭                          | payload 기반 동적 탐지                        |
| `reachability`       | 티어간 실제 통신 가능 포트             | Security Group 인바운드 규칙 분석             |

---

## `payload.json` 스키마

취약점 수집 에이전트(재민)가 생성하는 입력입니다.

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

---

## AI Agent 내부 동작

### 수집 모드 Phase

Gemini Agent가 아래 4단계를 자율적으로 판단하며 수행합니다.

| Phase | 수집 내용            | 대표 명령어                                                                      |
| ----- | -------------------- | -------------------------------------------------------------------------------- |
| 1     | 취약 소프트웨어 버전 | `nginx -v` 또는 `<경로> -v`, `ps aux \| grep java`, `find / -name "log4j*.jar"`  |
| 2     | 네트워크 컨텍스트    | `curl IMDS/public-ipv4`, `ss -tuln`                                              |
| 3     | 보안 컨텍스트        | IMDSv2 토큰 발급 → `iam/security-credentials/`, `ps -eo user,comm`, `getenforce` |
| 4     | 데이터 분류          | IMDS `/tags/instance/` 조회                                                      |

에이전트에게 명령어 레시피를 주지 않습니다. 목표와 결과물 스키마만 제시하고, 탐지 방법은 AI가 자율적으로 결정합니다.

> **실제 탐지 사례**: nginx가 PATH에 없어 `nginx -v`가 실패하자, 에이전트가 `ps aux | grep nginx`로 프로세스를 찾고 실행 경로(`/usr/local/nginx/sbin/nginx`)에서 직접 버전을 조회했습니다. log4j는 Java 프로세스의 classpath에서 `log4j-core-2.14.1.jar` 파일명을 파싱해 탐지했습니다.

### Agent 도구 (Function Calling)

| 도구           | 설명                                                                                                |
| -------------- | --------------------------------------------------------------------------------------------------- |
| `run_command`  | 읽기/조회 shell 명령 실행 (rm, kill 등 파괴적 명령은 정규식으로 차단)                               |
| `read_file`    | 임의 파일 읽기                                                                                      |
| `save_result`  | 수집 완료 시 호출 — installed_software, network_context, security_context, data_classification 제출 |
| `answer_query` | 질의 응답 모드 종료 — answer + evidence + confidence 반환                                           |

### 사용 모델 및 Fallback

| 우선순위 | 모델                    | 비고                      |
| -------- | ----------------------- | ------------------------- |
| 1        | `gemini-2.5-pro`        | 기본 (가장 안정적)        |
| 2        | `gemini-2.5-flash`      | 503 또는 404 시 자동 전환 |
| 3        | `gemini-2.5-flash-lite` | 최후 fallback             |

- 세션 내 첫 성공 모델을 캐시하여 이후 모든 인스턴스에서 재사용
- 503은 10초 후 재시도, 404는 즉시 다음 모델로 전환
- Gemini 응답에 HTML/XML이 섞이면 자동으로 짧은 마커로 치환 (`MALFORMED_FUNCTION_CALL` 방지)

---

## VPC 자동 탐색 로직

```text
discover_vpc_instances(vpc_id, region)
  └─ describe-instances (VPC 필터)
        └─ classify_subnet(subnet_id)
              └─ describe-route-tables
                    → 0.0.0.0/0 → IGW?  → public
                    → 0.0.0.0/0 → NAT?  → private
                    → 기본 경로 없음     → isolated

build_reachability(instances, region)
  └─ describe-security-groups
        └─ 인바운드 규칙에서 소스 SG → 대상 SG 매핑
              └─ tier-to-tier 포트 집합 산출
```

티어 기반 `data_classification` 기본값: `db → PII`, `app → Confidential`, `web → Internal`

---

## 파일 설명

| 파일                     | 설명                                                        |
| ------------------------ | ----------------------------------------------------------- |
| `agent_extract_asset.py` | 자산 매칭 에이전트 본체. 수집/질의/auto-discover 모드 지원. |
| `payload.json`           | 취약점 수집 에이전트로부터 받는 CVE 타겟 입력.              |
| `infra_context.json`     | 수집 결과 출력 (VPC 전체 자산 + reachability).              |
| `.env`                   | `GEMINI_API_KEY` 저장 (절대 git 커밋 금지).                 |

---

## 환경 요구사항

| 항목          | 내용                                                                                                                                                   |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Python        | 3.9 이상                                                                                                                                               |
| 필수 패키지   | `google-genai`                                                                                                                                         |
| API 키        | `GEMINI_API_KEY` 환경변수                                                                                                                              |
| AWS 자격증명  | `~/.aws/credentials` 또는 환경변수 (`AWS_ACCESS_KEY_ID` 등)                                                                                            |
| EC2 IAM 권한  | `AmazonSSMManagedInstanceCore` (EC2 역할에 연결)                                                                                                       |
| 로컬 IAM 권한 | `ssm:SendCommand`, `ssm:GetCommandInvocation`, `ec2:DescribeInstances`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables`, `ec2:DescribeSecurityGroups` |

---

## 실행 가이드

### 사전 준비

```bash
# 패키지 설치
pip3 install google-genai

# API 키 설정
export GEMINI_API_KEY="your-gemini-api-key"

# AWS 자격증명 확인
aws sts get-caller-identity
```

### VPC 전체 자동 수집

```bash
python3 agent_extract_asset.py \
    --auto-discover \
    --vpc-id vpc-095126a9a0924a7e2 \
    --output infra_context.json
```

### 실행 결과 예시

```
[DISCOVER] VPC vpc-095126a9a0924a7e2 에서 EC2 탐색 중...
[DISCOVER] 5개 인스턴스 발견: web/web/app/app/db
[REACHABILITY] web→app:8080, app→db:3306
[AGENT] i-xxx (Web-01) 수집 시작...
[AGENT] i-xxx (Web-01) nginx 1.20.0 탐지
[AGENT] i-xxx (App-01) log4j 2.14.1 탐지
...
[SUMMARY] assets=5, reachability=2
[SAVE] infra_context.json 저장 완료
```

---

## Swarm 연동 (위험도 평가 에이전트 → 자산 매칭 에이전트)

현재는 CLI 호출 방식입니다. 위험도 평가 에이전트가 추가 정보를 필요로 할 때 아래와 같이 호출합니다.

```bash
python3 agent_extract_asset.py \
    --query "payload 대상 서비스가 0.0.0.0에 바인딩되어 있는가?" \
    --asset-info infra_context.json
```

추후 HTTP 엔드포인트 / gRPC로 감싸면 에이전트간 메시지 라우팅이 가능한 Swarm 토폴로지로 확장할 수 있습니다.

---

## 주의사항

- `.env` 파일은 절대 git 커밋 금지 (`.gitignore` 필수).
- EC2 인스턴스에 `AmazonSSMManagedInstanceCore` IAM 역할이 연결되어 있어야 SSM으로 원격 실행이 가능합니다.
- IMDSv2 강제 환경에서는 에이전트가 스스로 토큰을 발급하여 IMDS를 호출합니다.
- Gemini 503/404 오류는 자동 재시도 + 모델 fallback 로직으로 처리됩니다.
- `run_command` 도구는 `rm`, `kill`, `reboot` 등 파괴적 명령어를 정규식으로 차단합니다.
