#!/usr/bin/env python3
"""AgentCore Runtime 진입점 — 자산 매칭 에이전트 (Bedrock + Claude Haiku 4.5).

로컬 개발:
    python runtime_app.py
    # → localhost:8080/invocations 에서 대기

배포:
    agentcore configure --entrypoint runtime_app.py --name asset-matching-agent
    agentcore deploy
    agentcore invoke '{"mode":"query", "asset_info":{...}, "question":"..."}'

호출 페이로드 스키마:
    {
      "mode": "collect" | "query" | "auto_discover",
      "region": "ap-northeast-2",          # 선택, 기본 DEFAULT_REGION
      "instance_id": "i-0123abcd",         # collect / query 모드 — 선택
      "cve_payload": { "records": [...] }, # collect / auto_discover 모드 — 필수
      "vpc_id": "vpc-0abcd1234",           # auto_discover 모드 — 필수
      "asset_info": {...},                 # query 모드 — 필수 (기존 수집 결과)
      "question": "...",                   # query 모드 — 필수
      "metadata": {                        # collect / auto_discover — 선택
          "environment": "production",
          "network_exposure": "public",
          "business_criticality": "high"
      }
    }

응답:
    - collect       → {"asset_info": {...}}
    - auto_discover → {"infra_context": {...}}
    - query         → {"answer": "...", "evidence": [...], "confidence": "high"}
    - 에러          → {"error": "..."}

Bedrock 인증은 Runtime IAM Role 로 처리되므로 별도 시크릿/환경변수 불필요.
"""
from __future__ import annotations

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from agent_extract_asset import (
    DEFAULT_REGION,
    collect_single_asset,
    run_auto_discover,
    run_query_agent,
)

app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload: dict) -> dict:
    payload = payload or {}
    mode = (payload.get("mode") or "").strip()
    region = payload.get("region") or DEFAULT_REGION

    if not mode:
        return {"error": "mode is required (collect | query | auto_discover)"}

    if mode == "query":
        asset_info = payload.get("asset_info")
        question = payload.get("question")
        if not asset_info or not question:
            return {"error": "query mode requires 'asset_info' and 'question'"}
        return run_query_agent(
            asset_info, question,
            instance_id=payload.get("instance_id"),
            region=region,
        )

    if mode == "collect":
        cve_payload = payload.get("cve_payload")
        if not cve_payload:
            return {"error": "collect mode requires 'cve_payload'"}
        meta = payload.get("metadata") or {}
        return {"asset_info": collect_single_asset(
            cve_payload,
            instance_id=payload.get("instance_id"),
            region=region,
            environment=meta.get("environment", "production"),
            network_exposure=meta.get("network_exposure", "public"),
            business_criticality=meta.get("business_criticality", "high"),
        )}

    if mode == "auto_discover":
        cve_payload = payload.get("cve_payload")
        vpc_id = payload.get("vpc_id")
        if not cve_payload or not vpc_id:
            return {"error": "auto_discover mode requires 'cve_payload' and 'vpc_id'"}
        meta = payload.get("metadata") or {}
        try:
            return {"infra_context": run_auto_discover(
                cve_payload, vpc_id,
                region=region,
                environment=meta.get("environment", "production"),
                business_criticality=meta.get("business_criticality", "high"),
            )}
        except RuntimeError as e:
            return {"error": str(e)}

    return {"error": f"unknown mode: {mode}"}


if __name__ == "__main__":
    app.run()
