# Week 1 — 자산 매칭 에이전트

취약점 자동 위험도 판단 시스템의 **자산 매칭 에이전트**입니다.
취약점 수집 에이전트로부터 CVE 타겟을 받아, EC2 인스턴스에서 실제 자산 컨텍스트를 수집하고,
이후 위험도 평가 에이전트 등 다른 에이전트의 질의에도 응답할 수 있도록 설계되었습니다.

---

## 전체 에이전트 아키텍처 (팀 전체)

```text
[취약점 수집 Agent]  →  [자산 매칭 Agent]  →  [위험도 평가 Agent]  →  [운영 영향 Agent]
    (재민)                (형준, 본 repo)          (수환)                   (수환)

         payload.json ─┐           asset_info.json ─┐
                       ↓                            ↓
            (CVE × 자산 매칭)             (자산 컨텍스트 기반 위험도 산정)
```

본 에이전트의 책임 범위는:

1. **수집 모드** — `payload.json`을 받아 EC2 내부를 조사해 `asset_info.json` 생성
2. **질의 응답 모드** — 다른 에이전트가 자산 내부 정보를 물어오면 추가 조사 후 답변 (swarm 대비)

---

## 실행 모드

### 모드 1 — 수집 모드 (`--payload`)

EC2 인스턴스에서 실행. CVE 타겟 소프트웨어뿐 아니라 **위험도 평가에 필요한 네트워크/보안/프로세스/비즈니스 컨텍스트**까지 한 번에 수집합니다.

```bash
export GEMINI_API_KEY="your-api-key"
python3 agent_extract_asset.py \
    --payload payload.json \
    --output  asset_info.json \
    --env production --exposure public --criticality high
```

### 모드 2 — 질의 응답 모드 (`--query`)

위험도 평가 에이전트 등이 자산 내부의 구체적 정보를 물어올 때 사용합니다.
먼저 생성된 `asset_info.json`을 참조하고, 부족하면 EC2에서 추가 shell 조사를 수행합니다.

```bash
python3 agent_extract_asset.py \
    --query "nginx 가 root 권한으로 실행 중인가? 그리고 80 포트가 외부에 열려 있는가?" \
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

## 파일 설명

### 핵심 스크립트

| 파일 | 설명 |
|------|------|
| `agent_extract_asset.py` | 자산 매칭 에이전트 본체. 수집/질의 이중 모드 지원. |
| `run_agent.sh` | EC2에서 환경변수 로드 + 패키지 설치 + 실행까지 원스텝으로 처리. |

### 입력 데이터

| 파일 | 설명 |
|------|------|
| `payload.json` | 취약점 수집 에이전트로부터 받는 CVE 타겟 (CVE ID, 영향 버전 범위, CPE 조건). |
| `nginx_selected_raw_cves.json` | OpenCVE API 기반 CVE 원본 데이터 (참고용, 현재 버전에서는 직접 사용하지 않음). |
| `nginx_selected_raw_cves_keys_ko.txt` | 위 CVE JSON의 키 의미 한국어 설명서. |
| `.env` | `GEMINI_API_KEY` 저장 (절대 git 커밋 금지). |

### 출력 데이터

| 파일 | 생성 스크립트 | 설명 |
|------|--------------|------|
| `asset_info.json` | `agent_extract_asset.py` (수집 모드) | EC2 자산 컨텍스트 (소프트웨어·네트워크·보안·메타데이터). |

---

## `asset_info.json` 스키마 (확장)

위험도 평가 에이전트가 필요로 하는 전체 컨텍스트를 한 파일에 담습니다.

```json
{
  "asset_id": "i-0650b9a9d47b6e820",
  "hostname": "ip-10-0-6-106.ap-northeast-2.compute.internal",
  "metadata": {
    "environment": "production",
    "network_exposure": "public",
    "business_criticality": "high",
    "data_classification": "PII"
  },
  "network_context": {
    "public_ip": "3.33.xx.xx",
    "listening_ports": [22, 80, 443, 8080],
    "is_internet_facing": true
  },
  "security_context": {
    "attached_iam_role": "WebServer-S3-Read-Role",
    "running_as_root": ["nginx", "java"],
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
      "version": "1.18.0",
      "cpe": "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
    },
    {
      "vendor": "apache",
      "product": "log4j",
      "version": "2.14.1",
      "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
      "source_path": "pid:2142 /app/spring-boot-application.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar"
    }
  ]
}
```

### 각 섹션의 목적

| 섹션 | 용도 | 수집 방법 |
|------|------|----------|
| `metadata` | 환경 / 중요도 / 데이터 민감도 분류 | CLI 인자 + EC2 태그 (`/latest/meta-data/tags/instance/`) |
| `network_context` | 외부 공격 가능성 판단 | IMDS + `ss -tuln` |
| `security_context` | 폭발 반경(IAM) + 실행 권한 + 방어 기제 | IMDS (iam/security-credentials) + `ps -eo user,comm` + `getenforce` |
| `os_info` | OS 단위 취약점 매칭 | `/etc/os-release` |
| `installed_software` | CVE 버전 매칭 | payload 기반 동적 탐지 (nginx·log4j·Java fat JAR 등) |

---

## `payload.json` 스키마

취약점 수집 에이전트가 생성하는 입력입니다.

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
    }
  ]
}
```

---

## AI Agent 내부 동작

### 수집 모드 Phase

Gemini 에이전트가 아래 4단계를 순차적으로 수행합니다 (실제 순서는 LLM이 판단).

| Phase | 수집 내용 | 대표 명령어 |
|-------|----------|-------------|
| 1 | 취약 소프트웨어 버전 | `nginx -v`, `ps aux | grep java`, `unzip -l <jar>` |
| 2 | 네트워크 컨텍스트 | `curl IMDS/public-ipv4`, `ss -tuln` |
| 3 | 보안 컨텍스트 | IMDSv2 토큰 발급 → `iam/security-credentials/`, `ps -eo user,comm`, `getenforce` |
| 4 | 데이터 분류 (태그) | IMDS `/tags/instance/` 조회 |

### Agent 도구 (Function Calling)

- `run_command` — 읽기/조회 shell 명령 실행 (파괴적 명령은 차단)
- `read_file` — 임의 파일 읽기
- `save_result` (수집 모드) — 위 4개 섹션을 한 번에 제출하고 종료
- `answer_query` (질의 응답 모드) — answer + evidence + confidence로 종료

### 사용 모델

- 기본: `gemini-2.5-flash`
- 503 Fallback: `gemini-2.0-flash-001` → `gemini-2.5-flash-lite` → `gemini-2.0-flash`

---

## EC2 실행 가이드 (SSM 환경)

PEM 키 없이 AWS SSM Session Manager로 접근하는 환경을 가정합니다.

```bash
# 1) EC2 접속
aws ssm start-session --target <인스턴스-ID>

# 2) 필수 패키지 설치 (최초 1회)
pip3 install --user google-genai

# 3) 스크립트 업로드 (로컬 cat → EC2 heredoc 방식)
#    agent_extract_asset.py 와 payload.json 을 /tmp 에 저장

# 4) API 키 환경변수 주입 (.env 를 EC2에 올리지 않음)
export GEMINI_API_KEY="<키>"

# 5) 실행
cd /tmp && python3 agent_extract_asset.py \
    --payload payload.json \
    --output  asset_info.json \
    --env production --exposure public --criticality high
```

---

## Swarm 연동 (다른 에이전트에서 호출)

위험도 평가 에이전트가 추가 정보를 필요로 할 때, **질의 응답 모드**를 호출하면 됩니다.
EC2 인스턴스 위에서 다음과 같이 실행합니다.

```bash
python3 agent_extract_asset.py \
    --query "payload 대상 서비스가 0.0.0.0 에 바인딩되어 있는가?" \
    --asset-info asset_info.json
```

현재는 CLI 호출 방식이지만, 추후 HTTP 엔드포인트 / gRPC 로 감싸면
에이전트간 메시지 라우팅이 가능한 Swarm 토폴로지로 확장할 수 있습니다.

---

## 환경 요구사항

| 항목 | 내용 |
|------|------|
| Python | 3.9 이상 (EC2 Amazon Linux 2023 기본) |
| 필수 패키지 | `google-genai` |
| API 키 | Gemini API Key (`GEMINI_API_KEY`) |
| EC2 권한 | IMDS 접근, EC2 태그 조회 (`ec2:DescribeTags` 또는 IMDS 태그 활성화) |
| EC2 접근 | AWS SSM Session Manager |

---

## 주의사항

- `.env` 파일은 절대 git 커밋 금지 (`.gitignore` 필수).
- 수집 모드는 반드시 **EC2 인스턴스 위에서** 실행해야 합니다 (shell 명령 대상이 EC2 내부).
- 질의 응답 모드는 `asset_info.json`이 이미 있어야 동작합니다.
- IMDSv2 강제 환경에서는 agent가 스스로 토큰을 발급하여 호출합니다.
- Gemini 503 오류는 자동 재시도 + 모델 fallback 로직으로 처리됩니다.
