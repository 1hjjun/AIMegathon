# CLAUDE.md — risk_evaluation_agent (위험도 평가 에이전트)

## 역할

CVE 목록과 자산 인벤토리를 분석해 각 CVE-자산 조합에 대한 CVSS 기반 위험도 점수를 산출한다.
`strands-agents`의 `Agent`를 사용하며, 필요 시 `query_asset_details` 도구로 자산 매칭 에이전트를 실시간 호출한다.

## 주요 파일

- [main.py](main.py) — AgentCore 진입점, 프롬프트 구성, Agent 실행, 결과 파싱
- [risk_assessment_refiner.py](risk_assessment_refiner.py) — 취약점 페이로드 정제
- [infra_context_refiner.py](infra_context_refiner.py) — 자산 컨텍스트 정제

## 호출 페이로드 스키마

```json
{
  "vulnerability_payload": { "records": [...] },
  "infra_context": { "assets": [...] },
  "asset_matching_arn": "arn:aws:bedrock-agentcore:...",
  "region": "ap-northeast-2"
}
```

`infra_context`는 오케스트레이터가 asset 단계 결과를 직접 전달해야 하며, 없으면 에러 반환.

## 에이전트 도구

| 도구 | 설명 |
|---|---|
| `query_asset_details(instance_id, question)` | 자산 매칭 에이전트에 추가 조사 요청 |
| `finalize_report(report: FinalReport)` | 최종 리포트를 `risk_evaluation_result.json`에 저장 |

## 사전 증거 수집 (`_prefetch_evidence`)

LLM 추론을 줄이기 위해 Python이 직접 tier 대표 인스턴스당 1회 combined query를 실행한다.
- 취약 소프트웨어 없는 tier는 스킵
- 질문 항목: mitigation 적용 여부 / root 실행 여부 / public IP 여부

## 위험도 조정 규칙

| 조건 | 조정 |
|---|---|
| mitigation 적용 | -2단계 |
| non-root 실행 | -1단계 |
| 내부망(Internal) | -1단계 |

단계 순서: `CRITICAL → HIGH → MEDIUM → LOW`

## 출력

```json
{
  "risk_report": [
    {
      "cve_id": "CVE-XXXX-XXXXX",
      "title": "...",
      "impacted_assets": [
        {
          "instance_id": "i-xxx",
          "base_cvss": 10.0,
          "calculated_risk": "CRITICAL",
          "exposure_level": "Public",
          "mitigations_found": [],
          "risk_adjustment_reason": "...",
          "remediation": "..."
        }
      ]
    }
  ],
  "swarm_queries": [...]
}
```

## 환경변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `BEDROCK_MODEL_ID` | `global.anthropic.claude-sonnet-4-6` | LLM 모델 |
| `DEFAULT_REGION` | `ap-northeast-2` | AWS 리전 |
| `ASSET_MATCHING_ARN` | 없음 | 자산 매칭 에이전트 ARN (페이로드로도 전달 가능) |

## 배포

```bash
agentcore deploy   # .bedrock_agentcore.yaml 기준 Direct Code Deploy
```

- 런타임: Python 3.12, 무상태(`NO_MEMORY`), observability 활성화
- Agent ARN: `arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/risk_evaluation_agent-A2PkRd5CzC`
