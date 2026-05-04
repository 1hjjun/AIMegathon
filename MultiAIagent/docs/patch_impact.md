# CLAUDE.md — PatchImpactAgent (패치 영향도 에이전트)

## 역할

리스크 평가 결과를 바탕으로 패치 적용 여부를 결정하고 운영 영향도와 조치 권고를 생성한다.
컨테이너 기반으로 ECR에 배포되며 HTTP 서버로 동작한다.

## 주요 파일

- [container_server.py](container_server.py) — `ThreadingHTTPServer` (포트 8080). `/ping` 헬스체크, `POST /invocations` 처리
- [runtime_app.py](runtime_app.py) — `invoke()` 진입점. `patch_runtime.patch_actions.invoke`로 위임
- [Dockerfile](Dockerfile) — `python:3.13-slim` 기반, 진입점 `container_server.py`

## 3단계 실행 흐름

오케스트레이터가 `action` 키로 단계를 제어한다.

| action | 단계 | 설명 |
|---|---|---|
| `evaluate_patch_impact` | patch_pre | 초기 패치 영향도 예비 판단 |
| `run_followup_conversation` | patch_followup | 자산 에이전트에 추가 질의 후 보완 |
| `finalize_patch_impact` | patch_final | 최종 패치 결정 및 권고 생성 |

## 입력 페이로드 (단계별 필수 키)

**patch_pre**
```json
{
  "action": "evaluate_patch_impact",
  "infra_context": {...},
  "risk_result": [...],
  "operational_payload": {...}
}
```

**patch_followup**
```json
{
  "action": "run_followup_conversation",
  "prejudge_result": {...},
  "infra_context": {...},
  "requests": [{"instance_id": "i-xxx", "question": "..."}]
}
```

**patch_final**
```json
{
  "action": "finalize_patch_impact",
  "prejudge_result": {...},
  "additional_asset_context": {...}
}
```

## 출력

최종 결과(`patch_final`)는 다음을 포함한다.
- 패치 결정: `patch` | `delay` | `monitor`
- 운영 영향도 분석
- 의존성 분석
- 권고 조치 및 근거

## HTTP API

| 경로 | 메서드 | 설명 |
|---|---|---|
| `/ping` | GET | 헬스체크, `{"status": "Healthy"}` 반환 |
| `/invocations` | POST | JSON 페이로드로 에이전트 호출 |

## 배포

```bash
./build_and_push_container.sh    # Docker 이미지 빌드 후 ECR 푸시
./deploy_container_runtime.sh    # AgentCore 컨테이너 런타임 배포
```

IAM 정책 파일:
- [agentcore_ecr_pull_policy.json](agentcore_ecr_pull_policy.json) — ECR 이미지 풀 권한
- [agentcore_invoke_asset_runtime_policy.json](agentcore_invoke_asset_runtime_policy.json) — 자산 에이전트 호출 권한
