# main.py
import argparse
import sys
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

from tools.cve_fetcher import fetch_selected_raw_cve_record
from tools.cwe_fetcher import fetch_cwe_weakness_summary
from tools.output_writer import save_vulnerability_result
from tools.payload_builder import (
    build_asset_matching_payloads,
    build_operational_impact_payloads,
    build_risk_assessment_payloads,
)

AGENT_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = AGENT_ROOT.parent.parent
FOCUSED_CVE_OUTPUT_PATH = "data/focused_selected_raw_cves.json"
ASSET_PAYLOAD_OUTPUT_PATH = "data/asset_matching_payloads.json"
RISK_PAYLOAD_OUTPUT_PATH = "data/risk_assessment_payloads.json"
OPERATIONAL_PAYLOAD_OUTPUT_PATH = "data/operational_impact_payloads.json"
DEFAULT_CVE_IDS = [
    "CVE-2021-23017",
    "CVE-2021-44228",
]
load_dotenv(PROJECT_ROOT / ".env")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Fetch the selected CVE records and generate all agent payload JSON files."
    )
    parser.add_argument(
        "--cve-id",
        action="append",
        dest="cve_ids",
        help="CVE ID to fetch. Repeat the option to fetch multiple CVEs.",
    )
    parser.add_argument(
        "--output",
        default=FOCUSED_CVE_OUTPUT_PATH,
        help=f"Output JSON path under MultiAIagent/vuln_collector_agent. Defaults to {FOCUSED_CVE_OUTPUT_PATH}.",
    )
    return parser.parse_args()


def load_raw_cve(cve_id: str) -> dict:
    raw_cve = fetch_selected_raw_cve_record(cve_id=cve_id)
    if raw_cve.get("error"):
        raise RuntimeError(raw_cve["error"])

    return raw_cve


def attach_cwe_details(raw_cve: dict, cwe_cache: Optional[dict] = None) -> dict:
    if cwe_cache is None:
        cwe_cache = {}

    cwe_details = []

    for cwe_id in raw_cve.get("weaknesses", []):
        if not isinstance(cwe_id, str) or not cwe_id.startswith("CWE-"):
            continue

        if cwe_id not in cwe_cache:
            cwe_cache[cwe_id] = fetch_cwe_weakness_summary(cwe_id)

        cwe_detail = cwe_cache[cwe_id]
        if cwe_detail.get("error"):
            cwe_details.append({
                "cwe_id": cwe_id,
                "error": cwe_detail["error"],
            })
        else:
            cwe_details.append(cwe_detail)

    raw_cve["cwe_details"] = cwe_details
    return raw_cve


def collect_selected_cve_details(cve_ids: list[str]) -> dict:
    records = []
    errors = []
    cwe_cache = {}

    for cve_id in cve_ids:
        raw_cve = fetch_selected_raw_cve_record(cve_id)
        if raw_cve.get("error"):
            errors.append({
                "cve_id": cve_id,
                "error": raw_cve["error"],
            })
            continue

        raw_cve = attach_cwe_details(raw_cve, cwe_cache=cwe_cache)
        records.append(raw_cve)

    return {
        "target": "selected_cves",
        "cve_ids": cve_ids,
        "fetched_details": len(records),
        "failed_details": len(errors),
        "errors": errors,
        "records": records,
    }


def generate_agent_payloads(dataset: dict) -> dict[str, dict]:
    return {
        ASSET_PAYLOAD_OUTPUT_PATH: build_asset_matching_payloads(dataset),
        RISK_PAYLOAD_OUTPUT_PATH: build_risk_assessment_payloads(dataset),
        OPERATIONAL_PAYLOAD_OUTPUT_PATH: build_operational_impact_payloads(dataset),
    }


def save_generated_outputs(dataset: dict, output_path: str) -> None:
    save_vulnerability_result(dataset, output_path=output_path)
    print(f"Saved JSON to {AGENT_ROOT / output_path}")

    for payload_path, payload in generate_agent_payloads(dataset).items():
        save_vulnerability_result(payload, output_path=payload_path)
        print(f"Saved JSON to {AGENT_ROOT / payload_path}")


if __name__ == "__main__":
    args = parse_args()
    cve_ids = args.cve_ids or DEFAULT_CVE_IDS
    try:
        dataset = collect_selected_cve_details(cve_ids)
        save_generated_outputs(dataset, output_path=args.output)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print(
            "Hint: this command requires network access to OpenCVE. "
            "Check your internet connection, DNS, VPN/proxy settings, and OPENCVE_API_KEY. "
            "You can test DNS with: nslookup app.opencve.io",
            file=sys.stderr,
        )
        sys.exit(1)
