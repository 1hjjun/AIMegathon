# MultiAIagent

이 폴더는 현재 사용 중인 멀티 에이전트 파이프라인 작업본입니다.

현재 기준 핵심은 아래 4개입니다.

1. 오케스트라는 얇은 순차 파이프라인입니다.
2. 실제 실행은 보통 `run_orchestrator_runtime.py`로 합니다.
3. 결과는 `OchestraResult`에 저장됩니다.
4. `patch -> asset` follow-up 대화 로그는 `Conversationlog/PatchToAsset`에 저장됩니다.

지금 구조는 예전처럼 스웜 실험 위주가 아니라, 실제 AgentCore runtime들을 안정적으로 호출하고 디버깅하기 쉽게 정리된 상태입니다.

## 현재 파이프라인

현재 기본 흐름은 아래와 같습니다.

```text
vuln_collector -> asset_matching -> risk_evaluation -> patch_impact
```

각 단계 역할은 이렇습니다.

- `vuln_collector`
  CVE를 수집하고 다음 단계에서 바로 쓸 수 있는 payload를 만듭니다.
- `asset_matching`
  현재 스택/인프라에서 어떤 자산이 영향을 받는지 수집합니다.
- `risk_evaluation`
  취약점과 자산 컨텍스트를 합쳐 위험도를 계산합니다.
- `patch_impact`
  실제 패치 시 운영 영향, 의존성, follow-up 질문, 최종 조치 방향을 판단합니다.

현재 오케스트라는 이 단계를 순서대로 이어주는 허브입니다.
즉 지금 버전의 오케스트라는 "대화형 스웜 조율기"라기보다 "얇은 실행 파이프라인 + 테스트 실행기"에 가깝습니다.

## 폴더 구조

배포와 테스트 기준으로 자주 보는 폴더는 아래입니다.

```text
MultiAIagent/
├── README.md
├── run_orchestrator_runtime.py
├── OchestraResult/
├── Conversationlog/
│   └── PatchToAsset/
├── OchestratorAgent(AWS)/
├── VulnCollectorAgent(AWS)/
└── PatchImpactAgent(AWS)/
```

### `OchestratorAgent(AWS)`

오케스트라 runtime 소스입니다.

주요 파일:

- `main.py`
  AgentCore entrypoint
- `orchestrator_pipeline.py`
  실행 모드 분기와 전체 흐름 제어
- `pipeline_stages.py`
  vuln / asset / risk / patch 각 단계 실행 함수
- `runtime_agents.py`
  다른 AgentCore runtime ARN 호출 레이어

현재 성격:

- 얇은 순차 파이프라인
- `full`, `vuln_only`, `asset_only`, `risk_only`, `patch_only`, `test` 지원
- 앞 단계 결과를 다음 단계로 넘기는 역할 담당

### `VulnCollectorAgent(AWS)`

취약점 수집 runtime 소스입니다.

주요 파일:

- `runtime_app.py`
- `vuln_collector_agent/`

현재 역할:

- CVE raw 결과 생성
- `risk_assessment_payloads.json`
- `operational_impact_payloads.json`
- `asset_matching_payload.json`

즉 뒤 단계가 바로 쓸 수 있는 취약점 payload를 만드는 역할입니다.

### `PatchImpactAgent(AWS)`

패치 영향도 runtime 소스입니다.

중요:

- 현재 patch는 **ZIP runtime이 아니라 container runtime 기준**으로 운용합니다.
- 문서와 운영 설명도 container 기준으로 이해하면 됩니다.

주요 파일:

- `runtime_app.py`
  patch runtime 진입점
- `patch_runtime/patch_actions.py`
  patch 1차 판단
- `patch_runtime/followup_actions.py`
  patch -> asset follow-up 질문/응답 처리
- `patch_runtime/finalize_patch.py`
  최종 판단
- `container_server.py`
  AgentCore container runtime용 HTTP wrapper
- `Dockerfile`
  container 이미지 정의
- `build_and_push_container.sh`
  ECR build/push
- `deploy_container_runtime.sh`
  AgentCore container runtime update

현재 patch follow-up은 다음 구조입니다.

- patch pre가 추가 질문 필요 여부 판단
- asset runtime에 사실 확인 질문 전송
- 응답을 patch final에 반영

즉 지금 실제 "에이전트 간 대화"에 제일 가까운 구간은 `patch -> asset` 입니다.

### 왜 `asset_matching_agent` 와 `risk_evaluation_agent` 소스 폴더는 안 보이나

현재 이 `MultiAIagent` 폴더 안에서는 배포와 수정이 자주 일어나는 runtime 위주로 정리해 두었습니다.

즉 지금 이 폴더에서 직접 관리하는 쪽은 주로:

- `OchestratorAgent(AWS)`
- `VulnCollectorAgent(AWS)`
- `PatchImpactAgent(AWS)`

입니다.

반면 `asset_matching_agent`, `risk_evaluation_agent`는 현재 live runtime ARN을 호출하는 방식으로 연결되어 있고, 이 폴더 안에는 같은 형태의 `(AWS)` 배포 폴더가 따로 정리되어 있지 않습니다.

## 현재 운영 기준에서 없는 것

아래는 현재 기준으로 일부러 안 쓰는 방향입니다.

- 오케스트라 내부 Strands/Swarm orchestration
- patch ZIP runtime 운영
- patch OpenAI key pass-through 방식

현재 기준은:

- 오케스트라 = 얇은 순차 파이프라인
- patch = Bedrock 기반 container runtime

## 배포 방식 요약

현재 배포 방식은 runtime마다 다릅니다.

- `OchestratorAgent(AWS)`
  ZIP runtime
- `VulnCollectorAgent(AWS)`
  ZIP runtime
- `PatchImpactAgent(AWS)`
  container runtime

즉 patch만 따로 컨테이너로 운용하고, 오케스트라와 vuln은 ZIP 기준으로 유지하고 있습니다.

빠르게 기억하면 아래처럼 보면 됩니다.

- 오케스트라 다시 올릴 때
  `OchestratorAgent(AWS)/dist/deployment_package.zip`
- vuln 다시 올릴 때
  `VulnCollectorAgent(AWS)/dist/deployment_package.zip`
- patch 다시 올릴 때
  `PatchImpactAgent(AWS)/build_and_push_container.sh`
  -> `PatchImpactAgent(AWS)/deploy_container_runtime.sh`

## `run_orchestrator_runtime.py`

경로:

- `MultiAIagent/run_orchestrator_runtime.py`

이 스크립트는 로컬에서 오케스트라 runtime을 호출하는 실행기입니다.

역할:

- 실행 모드 선택
- 필요한 JSON 입력 자동 탐색
- 오케스트라 runtime 1차 호출
- 실행 결과를 `OchestraResult`에 저장
- patch -> asset follow-up이 있으면 `Conversationlog/PatchToAsset`에도 저장

### 실행 원리

호출 구조는 항상 아래와 같습니다.

```text
로컬 실행기
-> 오케스트라 runtime
-> 오케스트라가 하위 runtime들 호출
```

즉 `vuln_only`, `asset_only`, `risk_only`, `patch_only`, `full`, `test` 모두 기본 원리는 같습니다.

차이는 오케스트라가 내부에서 어디까지 호출하느냐입니다.

- `vuln_only`
  vuln runtime만 호출
- `asset_only`
  asset runtime만 호출
- `risk_only`
  risk runtime만 호출
- `patch_only`
  patch runtime만 호출
- `full`
  vuln -> asset -> risk -> patch 전체 호출
- `test`
  `test_inputs`와 `stop_stage` 기준으로 필요한 단계까지만 호출

### `.env` 탐색 방식

실행기는 아래 순서로 `.env`를 찾습니다.

1. `MultiAIagent/.env`
2. `PacherAgents/.env`

즉 `MultiAIagent` 폴더 안에 `.env`가 있으면 그걸 우선 사용하고, 없으면 상위 루트 `.env`를 사용합니다.

### 필요한 로컬 환경

최소 기준:

- Python 3.13 권장
- `boto3`
- `python-dotenv`

처음 세팅 예시는 아래 정도면 충분합니다.

```bash
cd /Users/jms/Desktop/project/PacherAgents
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install boto3 python-dotenv
```

### 필요한 `.env`

로컬 실행기 기준으로 가장 중요한 값은 AWS 자격증명입니다.

예:

```env
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=ap-northeast-2
```

참고:

- `OPENAI_API_KEY`는 현재 patch 기준 필수 아님
- `OPENCVE_API_KEY`는 주로 vuln runtime 환경변수 쪽에서 필요
- 로컬 실행기 자체는 AWS runtime 호출용 자격증명이 가장 중요함

### 실행 명령

예시:

```bash
"/Users/jms/Desktop/project/PacherAgents/.venv/bin/python3" \
  "/Users/jms/Desktop/project/PacherAgents/MultiAIagent/run_orchestrator_runtime.py"
```

### 사용 방법

실행 후 기본 규칙은 간단합니다.

- 대괄호 `[ ]` 안의 값은 기본값
- 기본값 그대로 쓰려면 엔터
- JSON 파일 경로도 기본 후보가 뜨면 엔터

실행기 안에서 고를 수 있는 모드는 아래입니다.

1. `full`
2. `vuln_only`
3. `asset_only`
4. `risk_only`
5. `patch_only`
6. `test`

### 모드별 입력

#### `full`

보통 추가 파일 입력 없이 시작합니다.
앞 단계 결과를 동적으로 이어받아 다음 단계로 넘깁니다.

#### `vuln_only`

별도 JSON 입력 없이 실행 가능

#### `asset_only`

필요 입력:

- `asset_matching_payload.json`

#### `risk_only`

필요 입력:

- `infra_context.json`
- `risk_assessment_payloads.json`

#### `patch_only`

필요 입력:

- `infra_context.json`
- `risk_evaluation_result.json`
- `operational_impact_payloads.json`

추가 옵션:

- follow-up 질문까지 실행할지 마지막에 한 번 더 확인

#### `test`

특정 단계까지만 확인할 때 씁니다.

예:

- `stop_stage = patch_pre`
  patch 1차 판단까지만 확인
- `stop_stage = patch_followup`
  follow-up 응답까지 확인
- `stop_stage = patch_final`
  patch 최종 판단까지 확인

중요:

- `test_inputs`로 직접 넣은 값은 우선 사용
- 부족한 값은 필요한 앞단 결과로 보충

## `OchestraResult`

경로:

- `MultiAIagent/OchestraResult`

이 폴더는 최근 실행 결과 저장소입니다.

기본 구조:

```text
OchestraResult/
├── orchestrator_agent/
├── vuln_collector_agent/
├── asset_matching_agent/
├── risk_evaluation_agent/
└── patch_impact_agent/
```

각 에이전트 아래에는 보통 아래 구조가 생깁니다.

- `<run_tag>/`
  실행 1회분 결과
- `latest/`
  가장 최근 결과 복사본

예를 들면:

- `OchestraResult/orchestrator_agent/<run_tag>/response.json`
- `OchestraResult/patch_impact_agent/<run_tag>/patch_impact_prejudge_result.json`
- `OchestraResult/patch_impact_agent/<run_tag>/additional_asset_response.json`
- `OchestraResult/patch_impact_agent/<run_tag>/patch_impact_final_result.json`

### 왜 중요하나

`run_orchestrator_runtime.py`는 다음 실행 때 이 폴더에서 기본 입력 후보를 자동으로 찾습니다.

즉:

- `asset_only` 후 생성된 `infra_context.json`
- `risk_only` 후 생성된 `risk_evaluation_result.json`
- `patch_only` 후 생성된 patch 결과

이런 것들이 다음 테스트 때 자동 기본값으로 재사용됩니다.

## `Conversationlog/PatchToAsset`

경로:

- `MultiAIagent/Conversationlog/PatchToAsset`

이 폴더는 patch -> asset follow-up 대화 로그 저장소입니다.

생성 조건:

- `patch_only` 또는 `full` 실행 중
- patch pre가 추가 질문을 생성하고
- 실제 follow-up이 발생한 경우

저장 구조:

```text
Conversationlog/PatchToAsset/
├── latest.json
└── <run_tag>/
    ├── conversation_log.json
    ├── followup-xxxx.json
    ├── followup-yyyy.json
    └── ...
```

`conversation_log.json`에는 전체 묶음이 들어가고, 개별 `followup-*.json`에는 request 단위 대화가 저장됩니다.

주요 필드 예시:

- `request_id`
- `cve_id`
- `instance_id`
- `source_agent`
- `target_agent`
- `question_bundle`
- `transcript`
- `final_answer`

## `hyungjun` 버전과 비교

비교 기준:

- `MultiAIagent_hyungjun/orchestrator_agent/main.py`

### 공통점

- 큰 흐름은 동일
  - `vuln -> asset -> risk`
- AgentCore runtime ARN을 호출하는 구조
- 각 단계 결과를 다음 단계 입력으로 넘기는 구조

### 현재 버전에서 달라진 점

1. patch 단계가 추가됨

- 현재 버전은 `patch_impact`까지 포함

2. 실행 모드가 늘어남

- `full`
- `vuln_only`
- `asset_only`
- `risk_only`
- `patch_only`
- `test`

3. 결과 저장 체계가 강화됨

- `OchestraResult/<agent>/<run_tag>`
- `latest`
- `Conversationlog/PatchToAsset`

4. 로컬 실행기 추가

- `run_orchestrator_runtime.py`로
- runtime 호출, 결과 저장, 최신 결과 재사용까지 한 번에 가능

한 줄로 요약하면:

- `hyungjun` 버전은 핵심 파이프라인 뼈대에 가깝고
- 현재 버전은 patch 단계, 실행 모드, 결과 저장, 로컬 실행기까지 붙은 운영형 작업본에 가깝습니다.

## 현재 기준으로 기억하면 좋은 것

- 오케스트라는 현재 얇은 순차 파이프라인이다.
- patch는 container runtime 기준으로 본다.
- 실행은 보통 `run_orchestrator_runtime.py`로 한다.
- 최근 결과는 `OchestraResult`를 본다.
- patch -> asset 대화는 `Conversationlog/PatchToAsset`를 본다.
