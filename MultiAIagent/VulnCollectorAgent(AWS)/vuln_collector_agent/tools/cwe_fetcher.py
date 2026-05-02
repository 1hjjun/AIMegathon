import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from .tooling import tool
except ImportError:
    from tools.tooling import tool

CWE_API_BASE_URL = "https://cwe-api.mitre.org/api/v1"


def _cwe_number(cwe_id: str) -> str:
    match = re.search(r"\d+", cwe_id or "")
    return match.group(0) if match else ""


def _fetch_json(url: str) -> dict:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "VulnerabilityCollectorAgent/0.1",
        },
    )

    with urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


@tool
def fetch_cwe_weakness(cwe_id: str) -> dict:
    """
    Fetch one CWE weakness record from the MITRE CWE REST API.
    """
    cwe_number = _cwe_number(cwe_id)
    if not cwe_number:
        return {
            "error": f"Invalid CWE ID: {cwe_id}"
        }

    url = f"{CWE_API_BASE_URL}/cwe/weakness/{cwe_number}"

    try:
        return _fetch_json(url)
    except HTTPError as exc:
        return {
            "error": f"CWE API returned HTTP {exc.code} for CWE-{cwe_number}"
        }
    except URLError as exc:
        return {
            "error": f"Failed to reach CWE API for CWE-{cwe_number}: {exc.reason}"
        }
    except TimeoutError:
        return {
            "error": f"Timed out fetching CWE-{cwe_number} from CWE API"
        }
    except json.JSONDecodeError:
        return {
            "error": f"CWE API returned invalid JSON for CWE-{cwe_number}"
        }


def _summarize_related_weaknesses(weakness: dict) -> list[dict]:
    related = []

    for item in weakness.get("RelatedWeaknesses", []):
        cwe_id = item.get("CweID")
        nature = item.get("Nature")

        if cwe_id and nature:
            related.append({
                "nature": nature,
                "cwe_id": f"CWE-{cwe_id}",
            })

    return related


def _summarize_common_consequences(weakness: dict) -> list[dict]:
    consequences = []

    for item in weakness.get("CommonConsequences", []):
        consequences.append({
            "scope": item.get("Scope", []),
            "impact": item.get("Impact", []),
            "note": item.get("Note", ""),
        })

    return consequences


def _summarize_potential_mitigations(weakness: dict) -> list[dict]:
    mitigations = []

    for item in weakness.get("PotentialMitigations", []):
        mitigations.append({
            "phase": item.get("Phase", []),
            "description": item.get("Description", ""),
        })

    return mitigations


@tool
def summarize_cwe_weakness(cwe_id: str, cwe_record: dict) -> dict:
    """
    Keep only CWE fields that are useful for this project's vulnerability analysis.
    """
    weaknesses = cwe_record.get("Weaknesses", [])
    if not weaknesses:
        return {
            "cwe_id": cwe_id,
            "error": "CWE response did not include Weaknesses"
        }

    weakness = weaknesses[0]
    resolved_id = weakness.get("ID") or _cwe_number(cwe_id)

    return {
        "cwe_id": f"CWE-{resolved_id}",
        "name": weakness.get("Name", "unknown"),
        "abstraction": weakness.get("Abstraction", "unknown"),
        "structure": weakness.get("Structure", "unknown"),
        "status": weakness.get("Status", "unknown"),
        "description": weakness.get("Description", "unknown"),
        "related_weaknesses": _summarize_related_weaknesses(weakness),
        "common_consequences": _summarize_common_consequences(weakness),
        "potential_mitigations": _summarize_potential_mitigations(weakness),
    }


@tool
def fetch_cwe_weakness_summary(cwe_id: str) -> dict:
    """
    Fetch and reduce one CWE weakness record to the fields this project needs.
    """
    cwe_record = fetch_cwe_weakness(cwe_id)
    if cwe_record.get("error"):
        return {
            "cwe_id": cwe_id,
            "error": cwe_record["error"],
        }

    return summarize_cwe_weakness(cwe_id, cwe_record)
