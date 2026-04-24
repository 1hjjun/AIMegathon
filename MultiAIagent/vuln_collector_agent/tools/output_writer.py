# tools/output_writer.py
import json
from pathlib import Path

from tools.tooling import tool

_BASE_DIR = Path(__file__).parent.parent


@tool
def save_vulnerability_result(result: dict, output_path: str = "data/focused_selected_raw_cves.json") -> str:
    """
    Save normalized vulnerability result as JSON.
    """
    path = _BASE_DIR / output_path
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return f"Saved vulnerability result to {output_path}"
