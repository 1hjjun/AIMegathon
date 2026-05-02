# main.py
import argparse
import os
import sys
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

try:
    from .tools.cve_fetcher import fetch_selected_raw_cve_record
    from .tools.cwe_fetcher import fetch_cwe_weakness_summary
    from .tools.evidence_fetcher import fetch_operational_evidence, fetch_vendor_followup_evidence
    from .tools.output_writer import save_vulnerability_result
    from .tools.payload_builder import (
        build_operational_impact_payloads,
        build_risk_assessment_payloads,
        decide_operational_evidence_requirement,
        decide_vendor_followup_requirement,
    )
except ImportError:
    from tools.cve_fetcher import fetch_selected_raw_cve_record
    from tools.cwe_fetcher import fetch_cwe_weakness_summary
    from tools.evidence_fetcher import fetch_operational_evidence, fetch_vendor_followup_evidence
    from tools.output_writer import save_vulnerability_result
    from tools.payload_builder import (
        build_operational_impact_payloads,
        build_risk_assessment_payloads,
        decide_operational_evidence_requirement,
        decide_vendor_followup_requirement,
    )

AGENT_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = AGENT_ROOT.parent
ENV_PATHS = [
    PROJECT_ROOT / ".env",
    PROJECT_ROOT.parent / ".env",
]


def _resolve_output_dir() -> Path:
    explicit_dir = str(os.environ.get("VULN_AGENT_OUTPUT_DIR") or "").strip()
    if explicit_dir:
        return Path(explicit_dir)

    output_root = str(os.environ.get("MULTIAI_OUTPUT_ROOT") or "").strip()
    if output_root:
        return Path(output_root) / "VulAgent"

    return AGENT_ROOT / "result"


OUTPUT_DIR = _resolve_output_dir()
FOCUSED_CVE_OUTPUT_PATH = str(OUTPUT_DIR / "focused_selected_raw_cves.json")
RISK_PAYLOAD_OUTPUT_PATH = str(OUTPUT_DIR / "risk_assessment_payloads.json")
OPERATIONAL_PAYLOAD_OUTPUT_PATH = str(OUTPUT_DIR / "operational_impact_payloads.json")
ASSET_MATCHING_PAYLOAD_OUTPUT_PATH = str(OUTPUT_DIR / "asset_matching_payload.json")
DEFAULT_CVE_IDS = [
    "CVE-2021-23017",
    "CVE-2021-44228",
]
for env_path in ENV_PATHS:
    if env_path.exists():
        load_dotenv(env_path)


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
        help=f"Output JSON path. Defaults to {FOCUSED_CVE_OUTPUT_PATH}.",
    )
    parser.add_argument(
        "--evidence-mode",
        choices=("off", "auto", "on"),
        default="auto",
        help="Control operational evidence collection: off disables it, auto lets the LLM decide, on always collects it.",
    )
    parser.add_argument(
        "--with-evidence",
        action="store_true",
        help="Alias for --evidence-mode on.",
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


def attach_operational_evidence(raw_cve: dict, evidence_cache: Optional[dict] = None) -> dict:
    if evidence_cache is None:
        evidence_cache = {}

    cve_id = raw_cve.get("cve_id") or "unknown"
    if cve_id not in evidence_cache:
        evidence_cache[cve_id] = fetch_operational_evidence(cve_id)

    raw_cve["operational_evidence"] = evidence_cache[cve_id]
    return raw_cve


def attach_operational_evidence_decision(raw_cve: dict, decision_cache: Optional[dict] = None) -> dict:
    if decision_cache is None:
        decision_cache = {}

    cve_id = raw_cve.get("cve_id") or "unknown"
    if cve_id not in decision_cache:
        decision_cache[cve_id] = decide_operational_evidence_requirement(raw_cve)

    raw_cve["operational_evidence_decision"] = decision_cache[cve_id]
    return raw_cve


def attach_vendor_followup_decision(raw_cve: dict, decision_cache: Optional[dict] = None) -> dict:
    if decision_cache is None:
        decision_cache = {}

    cve_id = raw_cve.get("cve_id") or "unknown"
    if cve_id not in decision_cache:
        decision_cache[cve_id] = decide_vendor_followup_requirement(raw_cve)

    raw_cve["vendor_followup_decision"] = decision_cache[cve_id]
    return raw_cve


def attach_vendor_followup_evidence(raw_cve: dict, evidence_cache: Optional[dict] = None) -> dict:
    if evidence_cache is None:
        evidence_cache = {}

    cve_id = raw_cve.get("cve_id") or "unknown"
    decision = raw_cve.get("vendor_followup_decision") or {}
    selected_urls = decision.get("vendor_urls") or []
    cache_key = (cve_id, tuple(selected_urls))
    if cache_key not in evidence_cache:
        evidence_cache[cache_key] = fetch_vendor_followup_evidence(
            raw_cve.get("operational_evidence") or {},
            selected_urls=selected_urls,
        )

    raw_cve["vendor_followup_evidence"] = evidence_cache[cache_key]
    return raw_cve


def collect_selected_cve_details(cve_ids: list[str], evidence_mode: str = "auto") -> dict:
    records = []
    errors = []
    cwe_cache = {}
    evidence_cache = {}
    decision_cache = {}
    vendor_followup_decision_cache = {}
    vendor_followup_evidence_cache = {}

    for cve_id in cve_ids:
        raw_cve = fetch_selected_raw_cve_record(cve_id)
        if raw_cve.get("error"):
            errors.append({
                "cve_id": cve_id,
                "error": raw_cve["error"],
            })
            continue

        raw_cve = attach_cwe_details(raw_cve, cwe_cache=cwe_cache)

        if evidence_mode == "auto":
            raw_cve = attach_operational_evidence_decision(raw_cve, decision_cache=decision_cache)
            if (raw_cve.get("operational_evidence_decision") or {}).get("collect_operational_evidence"):
                raw_cve = attach_operational_evidence(raw_cve, evidence_cache=evidence_cache)
                raw_cve = attach_vendor_followup_decision(raw_cve, decision_cache=vendor_followup_decision_cache)
                if (raw_cve.get("vendor_followup_decision") or {}).get("investigate_vendor_context"):
                    raw_cve = attach_vendor_followup_evidence(raw_cve, evidence_cache=vendor_followup_evidence_cache)
        elif evidence_mode == "on":
            raw_cve = attach_operational_evidence(raw_cve, evidence_cache=evidence_cache)
            raw_cve = attach_vendor_followup_decision(raw_cve, decision_cache=vendor_followup_decision_cache)
            if (raw_cve.get("vendor_followup_decision") or {}).get("investigate_vendor_context"):
                raw_cve = attach_vendor_followup_evidence(raw_cve, evidence_cache=vendor_followup_evidence_cache)

        records.append(raw_cve)

    return {
        "target": "selected_cves",
        "cve_ids": cve_ids,
        "fetched_details": len(records),
        "failed_details": len(errors),
        "errors": errors,
        "records": records,
    }


def _collect_cpe_criteria(raw_cve: dict) -> list[str]:
    criteria: list[str] = []
    for config in raw_cve.get("nvd_cpe_configurations", []) if isinstance(raw_cve.get("nvd_cpe_configurations"), list) else []:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes", []) if isinstance(config.get("nodes"), list) else []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch", []) if isinstance(node.get("cpeMatch"), list) else []:
                if not isinstance(match, dict):
                    continue
                if match.get("vulnerable") is False:
                    continue
                value = str(match.get("criteria") or "").strip()
                if value and value not in criteria:
                    criteria.append(value)
    return criteria



def _version_clause(match: dict) -> str:
    clauses: list[str] = []
    start_including = str(match.get("versionStartIncluding") or "").strip()
    start_excluding = str(match.get("versionStartExcluding") or "").strip()
    end_including = str(match.get("versionEndIncluding") or "").strip()
    end_excluding = str(match.get("versionEndExcluding") or "").strip()
    if start_including:
        clauses.append(f">={start_including}")
    if start_excluding:
        clauses.append(f">{start_excluding}")
    if end_including:
        clauses.append(f"<={end_including}")
    if end_excluding:
        clauses.append(f"<{end_excluding}")
    return " ".join(clauses)



def _affected_version_ranges(raw_cve: dict) -> list[str]:
    ranges: list[str] = []
    for config in raw_cve.get("nvd_cpe_configurations", []) if isinstance(raw_cve.get("nvd_cpe_configurations"), list) else []:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes", []) if isinstance(config.get("nodes"), list) else []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch", []) if isinstance(node.get("cpeMatch"), list) else []:
                if not isinstance(match, dict):
                    continue
                if match.get("vulnerable") is False:
                    continue
                clause = _version_clause(match)
                if clause and clause not in ranges:
                    ranges.append(clause)
    return ranges



def build_asset_matching_payloads(dataset: dict, operational_payload: dict | None = None) -> dict:
    op_by_cve = {}
    if isinstance(operational_payload, dict):
        for record in operational_payload.get("records", []) if isinstance(operational_payload.get("records"), list) else []:
            if isinstance(record, dict) and record.get("cve_id"):
                op_by_cve[str(record.get("cve_id"))] = record

    records = []
    for raw_cve in dataset.get("records", []) if isinstance(dataset.get("records"), list) else []:
        if not isinstance(raw_cve, dict):
            continue
        cve_id = str(raw_cve.get("cve_id") or "").strip()
        op_record = op_by_cve.get(cve_id, {})
        product_name = str(op_record.get("product_name") or "").strip() or "unknown"
        fixed_version = str(op_record.get("fixed_version") or "").strip() or "unknown"
        records.append({
            "cve_id": cve_id,
            "product_name": product_name,
            "affected_version_range": _affected_version_ranges(raw_cve),
            "fixed_version": fixed_version,
            "product_status": "affected",
            "cpe_criteria": _collect_cpe_criteria(raw_cve),
        })

    return {
        "agent": "asset_matching",
        "source_dataset": "focused_selected_raw_cves.json",
        "record_count": len(records),
        "records": records,
    }



def generate_agent_payloads(dataset: dict) -> dict[str, dict]:
    operational_payload = build_operational_impact_payloads(dataset)
    return {
        RISK_PAYLOAD_OUTPUT_PATH: build_risk_assessment_payloads(dataset),
        OPERATIONAL_PAYLOAD_OUTPUT_PATH: operational_payload,
        ASSET_MATCHING_PAYLOAD_OUTPUT_PATH: build_asset_matching_payloads(dataset, operational_payload),
    }


def run_vulnerability_collection(
    cve_ids: Optional[list[str]] = None,
    *,
    evidence_mode: str = "auto",
    save_outputs: bool = False,
    output_path: str = FOCUSED_CVE_OUTPUT_PATH,
) -> dict[str, dict]:
    selected_cve_ids = cve_ids or DEFAULT_CVE_IDS
    dataset = collect_selected_cve_details(selected_cve_ids, evidence_mode=evidence_mode)
    payloads = generate_agent_payloads(dataset)

    risk_payload = payloads[RISK_PAYLOAD_OUTPUT_PATH]
    operational_payload = payloads[OPERATIONAL_PAYLOAD_OUTPUT_PATH]
    asset_matching_payload = payloads[ASSET_MATCHING_PAYLOAD_OUTPUT_PATH]

    if save_outputs:
        save_vulnerability_result(dataset, output_path=output_path)
        for payload_path, payload in payloads.items():
            save_vulnerability_result(payload, output_path=payload_path)

    return {
        "raw_dataset": dataset,
        "risk_assessment_payload": risk_payload,
        "operational_impact_payload": operational_payload,
        "asset_matching_payload": asset_matching_payload,
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
    evidence_mode = "on" if args.with_evidence else args.evidence_mode
    try:
        result = run_vulnerability_collection(
            cve_ids,
            evidence_mode=evidence_mode,
            save_outputs=True,
            output_path=args.output,
        )
        print(
            f"Generated payloads: risk={len((result['risk_assessment_payload'] or {}).get('records', []))}, "
            f"operational={len((result['operational_impact_payload'] or {}).get('records', []))}, "
            f"asset_matching={len((result['asset_matching_payload'] or {}).get('records', []))}"
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print(
            "Hint: run this with your Python 3.13 virtual environment that has Strands installed. "
            "This command requires network access to OpenCVE, the MITRE CWE API, and Amazon Bedrock Runtime. "
            "Check your internet connection, DNS, VPN/proxy settings, OPENCVE_API_KEY, AWS credentials, and Bedrock model access. "
            "You can test DNS with: nslookup app.opencve.io",
            file=sys.stderr,
        )
        sys.exit(1)
