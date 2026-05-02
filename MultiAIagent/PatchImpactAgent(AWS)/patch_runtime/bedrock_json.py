from __future__ import annotations

import os
import time
from typing import Any


DEFAULT_BEDROCK_MODEL = (
    os.environ.get("PATCH_IMPACT_BEDROCK_MODEL")
    or os.environ.get("BEDROCK_MODEL_ID")
    or "global.anthropic.claude-haiku-4-5-20251001-v1:0"
)
DEFAULT_BEDROCK_REGION = (
    os.environ.get("BEDROCK_REGION")
    or os.environ.get("AWS_REGION")
    or "ap-northeast-2"
)


_BEDROCK_CLIENT: Any | None = None


def _bedrock_runtime_client() -> Any:
    global _BEDROCK_CLIENT
    if _BEDROCK_CLIENT is None:
        import boto3
        from botocore.config import Config

        _BEDROCK_CLIENT = boto3.client(
            "bedrock-runtime",
            region_name=DEFAULT_BEDROCK_REGION,
            config=Config(read_timeout=600, connect_timeout=10),
        )
    return _BEDROCK_CLIENT


def _extract_bedrock_text(response: dict[str, Any]) -> str:
    message = response.get("output", {}).get("message", {})
    contents = message.get("content", []) if isinstance(message, dict) else []
    chunks: list[str] = []
    for item in contents:
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        if isinstance(text, str) and text.strip():
            chunks.append(text.strip())
    return "\n".join(chunks).strip()


def call_bedrock_text(
    *,
    instructions: str,
    prompt: str,
    model_name: str | None = None,
    max_retries: int = 3,
    retry_delay: int = 5,
) -> str:
    resolved_model = str(model_name or "").strip() or DEFAULT_BEDROCK_MODEL
    last_exc: Exception | None = None

    for attempt in range(max_retries):
        try:
            response = _bedrock_runtime_client().converse(
                modelId=resolved_model,
                system=[{"text": instructions}],
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": prompt}],
                    }
                ],
                inferenceConfig={"temperature": 0},
            )
            output_text = _extract_bedrock_text(response)
            if not output_text:
                raise RuntimeError("Bedrock 응답 텍스트가 비어 있습니다.")
            return output_text
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            message = str(exc)
            is_transient = any(
                token in message
                for token in ("429", "500", "502", "503", "timeout", "Timeout", "Throttling")
            )
            if is_transient and attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            raise

    raise RuntimeError(f"{resolved_model} 호출 실패: {last_exc}")
