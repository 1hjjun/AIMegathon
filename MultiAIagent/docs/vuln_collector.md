# CLAUDE.md — VulnCollectorAgent

## 역할

OpenCVE API로 최신 CVE를 수집하고, 하위 에이전트들이 소비할 4종 페이로드를 생성한다.

## 주요 파일

- [runtime_app.py](runtime_app.py) — AgentCore 진입점. 환경변수 오버라이드 후 `run_vulnerability_collection()` 호출
- `vuln_collector_agent/main.py` — 실제 수집 로직 (OpenCVE API 호출, CWE 조회, 페이로드 변환)

## 입출력

**입력 (페이로드 키, 모두 선택)**

| 키 | 설명 |
|---|---|
| `OPENCVE_API_KEY` | 페이로드로 전달 시 환경변수 덮어쓰기 |
| `BEDROCK_MODEL_ID` | 모델 오버라이드 |

**출력**

| 키 | 설명 |
|---|---|
| `raw_dataset` | OpenCVE 원시 CVE 데이터 |
| `risk_assessment_payload` | RiskEvaluationAgent 입력용 |
| `operational_impact_payload` | PatchImpactAgent 입력용 |
| `asset_matching_payload` | InfraMatchingAgent 입력용 (`records` 배열 포함) |

## 환경변수

| 변수 | 필수 | 설명 |
|---|---|---|
| `OPENCVE_API_KEY` | 필수 | OpenCVE API 인증키 |
| `BEDROCK_MODEL_ID` | 선택 | 기본값은 에이전트 내부 설정 |

## 배포

```bash
./build_package.sh   # deployment_package.zip 생성 후 AgentCore ZIP 런타임 업로드
```

런타임: Python 3.13, 메모리 2048 MB (`VulnCollectorAgent(AWS)/.bedrock_agentcore.yaml` 참고)
