# Megaton

Megaton은 여러 AI 에이전트가 협업해 취약점 데이터를 수집하고, 이후에는 실제 인프라 코드까지 점검 대상으로 확장할 수 있도록 구성한 저장소입니다.

현재는 취약점 수집용 에이전트 하나가 먼저 들어와 있고, 저장소 구조는 이후 에이전트 추가와 점검 대상 인프라 코드 적재를 염두에 두고 정리되어 있습니다.

## 저장소 구조

```text
Megaton/
  MultiAIagent/
    vuln_collector_agent/
  InfraSubjectTo Vulnerability Inspection/
  README.md
```

### `MultiAIagent/`

여기는 여러 역할을 가진 AI 에이전트들을 모아두는 상위 폴더입니다.

- 현재 포함된 에이전트:
  - `vuln_collector_agent/`
- 앞으로 추가될 수 있는 예시:
  - 취약점 정규화 에이전트
  - 자산 매칭 에이전트
  - 위험도 평가 에이전트
  - 운영 영향 분석 에이전트
  - 인프라 코드 점검 에이전트

즉, `MultiAIagent/`는 "에이전트 구현체들이 들어가는 영역"이라고 보면 됩니다.

### `InfraSubjectTo Vulnerability Inspection/`

여기는 취약점 점검 대상이 되는 인프라 코드들을 올려두는 폴더입니다.

예를 들면 아래와 같은 코드가 들어올 수 있습니다.

- Terraform 코드
- Kubernetes manifests
- Helm chart
- Dockerfile / Compose 파일
- 배포 스크립트
- 운영 설정 파일

즉, 이 폴더는 "분석 대상 인프라 자산이 들어가는 영역"입니다.

## 현재 구현된 에이전트

현재는 `MultiAIagent/vuln_collector_agent/`가 먼저 구현되어 있습니다.

이 에이전트는 소수의 고정된 CVE를 수집하고, 후속 분석에 바로 사용할 수 있는 JSON payload를 생성합니다.

상세 설명은 [`MultiAIagent/vuln_collector_agent/README.md`](MultiAIagent/vuln_collector_agent/README.md)에서 볼 수 있습니다.

기본 대상 CVE:

- `CVE-2021-23017`
- `CVE-2021-44228`

생성 결과물:

- `focused_selected_raw_cves.json`
- `asset_matching_payloads.json`
- `risk_assessment_payloads.json`
- `operational_impact_payloads.json`

## 의도한 운영 방식

Megaton은 크게 아래 두 축으로 확장되는 것을 전제로 합니다.

1. `MultiAIagent/` 아래에 역할별 에이전트를 계속 추가한다.
2. `InfraSubjectTo Vulnerability Inspection/` 아래에 실제 점검 대상 인프라 코드들을 쌓는다.

이 구조를 기준으로 보면, 앞으로는 "에이전트가 생성한 취약점/위험도 정보"와 "실제 인프라 코드"를 연결하는 흐름으로 발전시키기 쉽습니다.

예를 들면 아래 같은 흐름입니다.

1. 취약점 수집 에이전트가 CVE 기반 데이터셋을 만든다.
2. 자산 매칭 또는 점검 에이전트가 인프라 코드에서 관련 컴포넌트를 찾는다.
3. 위험도 평가 에이전트가 우선순위를 정한다.
4. 운영 영향 분석 에이전트가 패치 시 주의점을 정리한다.

## 빠른 시작

프로젝트 루트 `.env` 파일에 OpenCVE 인증 정보를 넣습니다.

```env
OPENCVE_API_KEY=your_key_here
```

또는

```env
OPENCVE_API_TOKEN=your_token_here
```

현재 구현된 취약점 수집 에이전트는 아래처럼 실행할 수 있습니다.

```bash
python3 MultiAIagent/vuln_collector_agent/main.py
```

실행 후 아래 경로에 JSON 결과물이 생성됩니다.

```text
MultiAIagent/vuln_collector_agent/data/
```

## 협업 기준

저장소를 확장할 때는 아래 기준을 유지하면 구조가 덜 흔들립니다.

- 새 에이전트는 `MultiAIagent/` 아래에 독립 폴더로 추가
- 점검 대상 코드와 에이전트 코드는 분리 유지
- 에이전트별 입구 문서는 각 폴더 내부 `README.md`에 작성
- 루트 `README.md`는 저장소 전체 구조와 역할 설명 중심으로 유지

## 현재 상태 메모

- 루트는 멀티 에이전트 저장소의 입구 역할을 합니다.
- 실제 구현은 현재 `vuln_collector_agent`부터 시작되어 있습니다.
- 인프라 점검 대상 폴더는 앞으로 실제 IaC 및 운영 코드가 채워질 예정입니다.
