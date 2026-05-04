# CLAUDE.md — Infra_matchingAgent (자산 매칭 에이전트)

## 역할

EC2 API + SSM으로 VPC 내 인프라를 탐색하고, CVE와 연관된 자산 인벤토리를 구성한다.
모델: **Claude Haiku 4.5**

## 주요 파일

- [runtime_app.py](runtime_app.py) — AgentCore 진입점. 모드 분기 및 VPC 자동 탐색
- [agent_extract_asset.py](agent_extract_asset.py) — `collect_single_asset`, `run_auto_discover`, `run_query_agent` 구현

## 호출 페이로드 스키마

```json
{
  "mode": "collect | query | auto_discover",
  "region": "ap-northeast-2",
  "instance_id": "i-0123abcd",
  "cve_payload": { "records": [...] },
  "vpc_id": "vpc-0abcd1234",
  "stack_name": "megathon",
  "asset_info": {...},
  "question": "...",
  "metadata": {
    "environment": "production",
    "network_exposure": "public",
    "business_criticality": "high"
  }
}
```

## 모드별 동작

| 모드 | 필수 입력 | 출력 |
|---|---|---|
| `auto_discover` | `cve_payload` + (`vpc_id` 또는 `stack_name`) | `{"infra_context": {...}}` |
| `collect` | `cve_payload` | `{"asset_info": {...}}` |
| `query` | `asset_info` + `question` | `{"answer": "...", "evidence": [...], "confidence": "high"}` |

`auto_discover`에서 `stack_name` 지정 시 CloudFormation 태그로 VPC ID를 자동 탐색한다.

## infra_context 구조 (출력)

```json
{
  "assets": [
    {
      "asset_id": "i-xxx",
      "tier": "web | app | db",
      "installed_software": [{"name": "nginx", "version": "1.x"}],
      "network": {"public_ip": "...", "subnet": "public | private"},
      "os": {...},
      "security_context": {"iam_role": "...", "imds_v2": true, "selinux": "enforcing"}
    }
  ]
}
```

## 안전 장치

- SSM `run_command` 실행 시 파괴적 명령(rm, shutdown, reboot 등) 차단
- SSM 출력 자동 truncation

## 배포

```bash
agentcore deploy   # .bedrock_agentcore.yaml 기준 Direct Code Deploy
```

런타임: Python 3.12, IAM Role: `AssetMatchingAgentCoreRole`
