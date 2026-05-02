from __future__ import annotations

from bedrock_agentcore import BedrockAgentCoreApp

from orchestrator_pipeline import invoke as orchestrator_invoke


app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload: dict | None) -> dict:
    return orchestrator_invoke(payload or {})


if __name__ == "__main__":
    app.run()
