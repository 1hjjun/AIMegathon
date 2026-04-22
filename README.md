# Week 1 — 자산 매칭 파이프라인

AWS EC2 인스턴스에서 실행 중인 소프트웨어를 탐지하고,
CVE 취약점 데이터와 자동으로 매칭하는 파이프라인입니다.

---

## 전체 아키텍처

```
[취약점 수집 Agent]          [자산 수집 Agent]              [매칭 Agent]
nginx_selected_raw_cves.json  →  asset_info.json  →  asset_matching_result.json
      (OpenCVE API)                (EC2 탐지)            (CVE × 자산 비교)
         ↑
     payload.json
   (테스트 대상 CVE)
```

---

## 파이프라인 실행 순서

### Step 1 — 테스트 대상 CVE 선정 (`payload.json`)

팀원이 수동으로 작성하는 파일입니다.
테스트할 CVE와 그 CPE 조건을 정의합니다.

```bash
# 별도 실행 없음 — 파일을 직접 편집
```

### Step 2 — 자산 정보 수집 (`agent_extract_asset.py`)

EC2 인스턴스에서 실행합니다.
Gemini AI Agent가 shell 명령을 스스로 판단·실행하여 소프트웨어를 탐지합니다.

```bash
# EC2에서 실행
export GEMINI_API_KEY="your-api-key"
python3 agent_extract_asset.py \
    --payload payload.json \
    --output  asset_info.json \
    --env production --exposure public --criticality high
```

### Step 3 — CVE 자산 매칭 (`asset_matching_agent.py`)

로컬 또는 EC2에서 실행합니다.
Step 2의 `asset_info.json`과 CVE 데이터를 비교해 취약 여부를 판별합니다.

```bash
python3 asset_matching_agent.py \
    --asset asset_info.json \
    --cves  nginx_selected_raw_cves.json \
    --output asset_matching_result.json
```

---

## 파일 설명

### 입력 데이터

| 파일                                  | 설명                                                                                |
| ------------------------------------- | ----------------------------------------------------------------------------------- |
| `payload.json`                        | 테스트할 CVE 2개의 대상 소프트웨어·버전 범위·CPE 조건 정의. 팀원이 수동 작성.       |
| `nginx_selected_raw_cves.json`        | OpenCVE API로 수집한 nginx 관련 CVE 원본 데이터 (48개). 취약점 수집 Agent의 출력물. |
| `nginx_selected_raw_cves_keys_ko.txt` | `nginx_selected_raw_cves.json`의 각 키(key) 의미 설명서 (한국어).                   |

### 핵심 스크립트

#### `extract_asset.py` — 규칙 기반 자산 탐지기

- **역할**: EC2 인스턴스의 소프트웨어 종류와 버전을 탐지해 `asset_info.json`으로 저장
- **방식**: `payload.json`의 `cpe_criteria`를 파싱 → 탐지 대상 결정 → 탐지 함수 실행
- **탐지 가능 소프트웨어**: nginx (직접 명령어), log4j (패키지 매니저 → JAR 탐색 → Fat JAR 내부 → /proc 분석)
- **신규 소프트웨어 추가 방법**: `DETECTOR_REGISTRY` 딕셔너리에 `"vendor:product": 탐지함수` 추가
- **한계**: 탐지 로직을 코드로 미리 작성해야 함. Fat JAR처럼 비표준 설치 방식에 취약.

```bash
python3 extract_asset.py --payload payload.json --env production --exposure public
```

#### `agent_extract_asset.py` — AI Agent 기반 자산 탐지기 (권장)

- **역할**: Gemini AI Agent가 직접 shell 명령을 판단·실행해 소프트웨어를 탐지
- **방식**: `payload.json` → System Prompt 생성 → Gemini Function Calling 루프
- **장점**: 코드 수정 없이 `payload.json`만 바꾸면 새로운 소프트웨어 자동 탐지
- **실제 탐지 사례**: `ps aux`로 Java 프로세스 발견 → `/app/spring-boot-application.jar` 확인 → `unzip -l`로 내부 log4j 탐지
- **사용 모델**: `gemini-2.5-flash` (503 시 `gemini-2.0-flash-001` → `gemini-2.5-flash-lite` → `gemini-2.0-flash` 순 자동 전환)
- **필요 환경변수**: `GEMINI_API_KEY`

```bash
export GEMINI_API_KEY="your-api-key"
python3 agent_extract_asset.py --payload payload.json --output asset_info.json
```

#### `asset_matching_agent.py` — CVE 자산 매칭 Agent

- **역할**: `asset_info.json`의 소프트웨어 버전이 각 CVE의 영향 범위에 해당하는지 판별
- **매칭 로직**:
  1. CPE 기준으로 vendor·product 일치 여부 확인
  2. `versionStartIncluding/Excluding`, `versionEndIncluding/Excluding` 4가지 범위 조건 비교
  3. `nvd_cpe_configurations` 내 nodes (OR) → cpeMatch (OR) 구조 순회
- **출력**: 취약한 CVE 목록 + 미해당 CVE 목록 + 요약 통계

```bash
python3 asset_matching_agent.py \
    --asset asset_info.json \
    --cves  nginx_selected_raw_cves.json \
    --output asset_matching_result.json
```

### 출력 데이터

| 파일                         | 생성 스크립트                                    | 설명                                                           |
| ---------------------------- | ------------------------------------------------ | -------------------------------------------------------------- |
| `asset_info.json`            | `extract_asset.py` 또는 `agent_extract_asset.py` | EC2 인스턴스 자산 정보 (인스턴스 ID, OS, 설치 소프트웨어 목록) |
| `asset_matching_result.json` | `asset_matching_agent.py`                        | CVE별 취약 여부 판별 결과 및 매칭 상세                         |

---

## `asset_info.json` 스키마

```json
{
  "asset_id": "i-0xxxxxxxx",
  "hostname": "ip-172-xx-xx-xx",
  "metadata": {
    "environment": "production",
    "network_exposure": "public",
    "business_criticality": "high"
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

## `payload.json` 스키마

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

## 환경 요구사항

| 항목        | 내용                                                                     |
| ----------- | ------------------------------------------------------------------------ |
| Python      | 3.9 이상 (EC2 Amazon Linux 2023 기본 제공)                               |
| 필수 패키지 | `google-genai` (`pip3 install --user google-genai`)                      |
| API 키      | Gemini API Key (`GEMINI_API_KEY` 환경변수)                               |
| EC2 접근    | AWS SSM Session Manager (`aws ssm start-session --target <instance-id>`) |
| EC2 권한    | SSM Agent 실행 권한, 인터넷 아웃바운드 (Gemini API 호출용)               |

---

## 주의사항

- `.env` 파일은 절대 git에 커밋하지 마세요. `.gitignore`에 반드시 추가하세요.
- `agent_extract_asset.py`는 EC2 인스턴스 위에서 실행해야 합니다 (shell 명령을 로컬에서 실행하기 때문).
- `asset_matching_agent.py`는 어디서든 실행 가능합니다.
- Gemini API 503 오류는 일시적 과부하입니다. 자동 재시도 및 모델 전환 로직이 내장되어 있습니다.
