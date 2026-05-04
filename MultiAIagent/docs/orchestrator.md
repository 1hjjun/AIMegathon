# CLAUDE.md — OchestratorAgent

## 역할

전체 파이프라인을 순차 실행하는 얇은 오케스트레이터. 각 단계를 AgentCore Runtime으로 호출하고 결과를 `OchestraResult/`에 저장한다.

## 주요 파일

- [orchestrator_pipeline.py](orchestrator_pipeline.py) — 핵심 로직. `invoke(payload)` → 모드 분기 → 각 단계 실행
- [pipeline_stages.py](pipeline_stages.py) — 단계별 AgentCore 호출 함수 및 결과 경로 상수 정의
- [runtime_agents.py](runtime_agents.py) — AgentCore Runtime 호출 래퍼 (`run_agent`)
- [main.py](main.py) — AgentCore ZIP 런타임 진입점

## 실행 모드 및 분기

`mode` 값에 따라 `invoke()`가 분기한다.

| 모드 | 실행 함수 | 필수 입력 |
|---|---|---|
| `full` / `test` | `run_orchestrator()` | 없음 (전 단계 자동 실행) |
| `vuln_only` | `run_vuln_only()` | 없음 |
| `asset_only` | `run_asset_only()` | `asset_matching_payload` |
| `risk_only` | `run_risk_only()` | `infra_context`, `risk_assessment_payload` |
| `patch_only` | `run_patch_only()` | `infra_context`, `risk_result`, `operational_payload` |

`test` 모드에서는 `test_inputs` 키로 중간 결과를 주입해 특정 단계만 검증할 수 있다.

## 단계 간 데이터 핸드오프

```
vuln_stage.asset_matching_payload  → asset 단계 입력
vuln_stage.risk_assessment_payload → risk 단계 입력
asset_stage.result (infra_context)  → risk / patch 단계 입력
vuln_stage.operational_impact_payload → patch 단계 입력
risk_stage.result                   → patch 단계 입력
```

## 결과 파일 경로 (`pipeline_stages.py` 상수)

`MULTIAI_RUNTIME_ROOT` (기본 `/tmp/multiai`) 하위에 생성된다.

| 상수 | 경로 |
|---|---|
| `PIPELINE_RESULT_PATH` | `OutputResult/SwarmAgent/pipeline_result.json` |
| `PATCH_PRE_RESULT_PATH` | `OutputResult/PatchImAgent/stage1_prejudge/...` |
| `PATCH_FOLLOWUP_REQUEST_PATH` | `OutputResult/PatchImAgent/stage2_followup/...` |
| `PATCH_FINAL_RESULT_PATH` | `OutputResult/PatchImAgent/stage3_final/...` |

## 배포

```bash
./build_package.sh   # deployment_package.zip 생성
```

ZIP 파일을 AWS Lambda 또는 AgentCore ZIP 런타임에 업로드한다.
