from __future__ import annotations

import os

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from vuln_collector_agent.main import run_vulnerability_collection

app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload: dict | None) -> dict:
    payload = payload or {}

    opencve_api_key = str(payload.get("OPENCVE_API_KEY") or "").strip()
    bedrock_model_id = str(payload.get("BEDROCK_MODEL_ID") or "").strip()

    if opencve_api_key:
        os.environ["OPENCVE_API_KEY"] = opencve_api_key
    if bedrock_model_id:
        os.environ["BEDROCK_MODEL_ID"] = bedrock_model_id

    result = run_vulnerability_collection(
        save_outputs=False,
    )

    return {
        "raw_dataset": result.get("raw_dataset", {}),
        "risk_assessment_payload": result.get("risk_assessment_payload", {}),
        "operational_impact_payload": result.get("operational_impact_payload", {}),
        "asset_matching_payload": result.get("asset_matching_payload", {}),
    }


if __name__ == "__main__":
    app.run()
