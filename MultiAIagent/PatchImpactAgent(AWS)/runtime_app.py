from __future__ import annotations

def invoke(payload: dict | None) -> dict:
    from patch_runtime.patch_actions import invoke as patch_impact_invoke

    return patch_impact_invoke(payload or {})
