import os
import re
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from tools.tooling import tool

OPENCVE_BASE_URL = "https://app.opencve.io/api"


def _api_token() -> str:
    return os.getenv("OPENCVE_API_TOKEN") or os.getenv("OPENCVE_API_KEY") or ""


def _fetch_json(url: str) -> dict:
    token = _api_token()
    if not token:
        raise RuntimeError("OPENCVE_API_KEY or OPENCVE_API_TOKEN is required")

    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "VulnerabilityCollectorAgent/0.1",
        },
    )

    with urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def _opencve_cve_url(cve_id: str) -> str:
    query = urlencode({"include": "nvd_cpe_configurations"})
    return f"{OPENCVE_BASE_URL}/cve/{cve_id}?{query}"


@tool
def fetch_raw_cve_record(cve_id: str) -> dict:
    """
    Fetch the raw OpenCVE CVE detail response without additional normalization.
    """
    if not cve_id:
        return {
            "error": "cve_id is required"
        }

    try:
        return _fetch_json(_opencve_cve_url(cve_id))
    except HTTPError as exc:
        if exc.code == 401:
            return {
                "error": "OpenCVE authentication failed. Check OPENCVE_API_KEY or OPENCVE_API_TOKEN."
            }

        return {
            "error": f"OpenCVE returned HTTP {exc.code} for {cve_id}"
        }
    except URLError as exc:
        return {
            "error": f"Failed to reach OpenCVE for {cve_id}: {exc.reason}"
        }
    except TimeoutError:
        return {
            "error": f"Timed out fetching {cve_id} from OpenCVE"
        }
    except json.JSONDecodeError:
        return {
            "error": f"OpenCVE returned invalid JSON for {cve_id}"
        }
    except RuntimeError as exc:
        return {
            "error": str(exc)
        }


def _extract_cwes(record: dict) -> list[str]:
    weaknesses = record.get("weaknesses") or []
    cwes = []

    def add_from_text(value: str) -> None:
        for cwe in re.findall(r"CWE-\d+", value):
            if cwe not in cwes:
                cwes.append(cwe)

    for weakness in weaknesses:
        if isinstance(weakness, str):
            add_from_text(weakness)
        elif isinstance(weakness, dict):
            for key in ("cwe_id", "cweId", "id", "name", "description"):
                value = weakness.get(key)
                if isinstance(value, str):
                    add_from_text(value)

    if not cwes:
        add_from_text(json.dumps(weaknesses))

    return cwes or ["unknown"]


def _extract_cvss(record: dict) -> dict:
    metrics = record.get("metrics") or {}

    for metric_key in ("cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"):
        metric = metrics.get(metric_key) or {}
        data = metric.get("data") or {}
        score = data.get("score")
        vector = data.get("vector")

        if score is not None or vector:
            return {
                "score": score if score is not None else "unknown",
                "vector": vector or "unknown",
                "provider": metric.get("provider") or "unknown",
                "vector_details": _parse_cvss_vector(vector or ""),
            }

    return {
        "score": "unknown",
        "vector": "unknown",
        "provider": "unknown",
        "vector_details": {},
    }


def _parse_cvss_vector(vector: str) -> dict:
    if not vector:
        return {}

    metric_labels = {
        "AV": {
            "key": "attack_vector",
            "values": {
                "N": "network",
                "A": "adjacent",
                "L": "local",
                "P": "physical",
            },
        },
        "AC": {
            "key": "attack_complexity",
            "values": {
                "L": "low",
                "H": "high",
            },
        },
        "PR": {
            "key": "privileges_required",
            "values": {
                "N": "none",
                "L": "low",
                "H": "high",
            },
        },
        "UI": {
            "key": "user_interaction",
            "values": {
                "N": "none",
                "R": "required",
            },
        },
        "S": {
            "key": "scope",
            "values": {
                "U": "unchanged",
                "C": "changed",
            },
        },
        "C": {
            "key": "confidentiality_impact",
            "values": {
                "H": "high",
                "L": "low",
                "N": "none",
            },
        },
        "I": {
            "key": "integrity_impact",
            "values": {
                "H": "high",
                "L": "low",
                "N": "none",
            },
        },
        "A": {
            "key": "availability_impact",
            "values": {
                "H": "high",
                "L": "low",
                "N": "none",
            },
        },
    }

    details = {}
    parts = vector.split("/")

    if parts and parts[0].startswith("CVSS:"):
        details["version"] = parts[0].split(":", 1)[1]

    for part in parts[1:]:
        if ":" not in part:
            continue

        metric, value = part.split(":", 1)
        label = metric_labels.get(metric)
        if not label:
            continue

        details[label["key"]] = label["values"].get(value, value.lower())

    return details


def _clean_cpe_part(value: str) -> str:
    if not value or value in {"*", "-"}:
        return ""

    return value.replace("\\:", ":").replace("_", "-").lower()


def _parse_cpe(criteria: str) -> dict:
    parts = criteria.split(":")
    if len(parts) < 6:
        return {}

    return {
        "vendor": _clean_cpe_part(parts[3]),
        "product": _clean_cpe_part(parts[4]),
        "version": _clean_cpe_part(parts[5]),
    }


def _walk_cpe_matches(value) -> list[dict]:
    matches = []

    if isinstance(value, dict):
        for key in ("cpeMatch", "cpe_match"):
            cpe_matches = value.get(key)
            if isinstance(cpe_matches, list):
                matches.extend(item for item in cpe_matches if isinstance(item, dict))

        for child in value.values():
            matches.extend(_walk_cpe_matches(child))

    elif isinstance(value, list):
        for item in value:
            matches.extend(_walk_cpe_matches(item))

    return matches


def _product_from_vendor_entry(value: str) -> str:
    if "$PRODUCT$" not in value:
        return ""

    return _clean_cpe_part(value.split("$PRODUCT$", 1)[1])


def _product_hints(record: dict) -> list[str]:
    hints = []
    title_description = f"{record.get('title') or ''} {record.get('description') or ''}".lower()

    vendors = record.get("vendors") or []
    if isinstance(vendors, list):
        for vendor in vendors:
            if not isinstance(vendor, str):
                continue

            product = _product_from_vendor_entry(vendor)
            if product and product in title_description and product not in hints:
                hints.append(product)

    for token in re.findall(r"[a-z0-9][a-z0-9._-]{1,}", title_description):
        if token not in hints:
            hints.append(_clean_cpe_part(token))

    return hints


def _configuration_matches_product(configuration: dict, product_hints: list[str]) -> bool:
    matches = _walk_cpe_matches(configuration)

    for match in matches:
        criteria = match.get("criteria") or match.get("cpe23Uri") or ""
        cpe = _parse_cpe(criteria)
        product = cpe.get("product")

        if product and product in product_hints:
            return True

    return False


def _extract_relevant_cpe_configurations(record: dict) -> list[dict]:
    configurations = record.get("nvd_cpe_configurations") or []
    product_hints = _product_hints(record)

    if not product_hints:
        return configurations

    relevant = [
        configuration for configuration in configurations
        if isinstance(configuration, dict) and _configuration_matches_product(configuration, product_hints)
    ]

    return relevant or configurations


def _version_range_from_cpe_match(match: dict) -> str:
    start_including = match.get("versionStartIncluding")
    start_excluding = match.get("versionStartExcluding")
    end_including = match.get("versionEndIncluding")
    end_excluding = match.get("versionEndExcluding")

    parts = []
    if start_including:
        parts.append(f">={start_including}")
    if start_excluding:
        parts.append(f">{start_excluding}")
    if end_including:
        parts.append(f"<={end_including}")
    if end_excluding:
        parts.append(f"<{end_excluding}")

    if parts:
        return " ".join(parts)

    criteria = match.get("criteria") or match.get("cpe23Uri") or ""
    cpe = _parse_cpe(criteria)
    return cpe.get("version") or "unknown"


def _fixed_version_from_text(text: str) -> str:
    match = re.search(r"\bbefore\s+([A-Za-z0-9][A-Za-z0-9._+-]*)", text)
    if match:
        return match.group(1).rstrip(".,;")

    return ""


def _fixed_version_from_cpe_matches(matches: list[dict], description: str) -> str:
    for match in matches:
        end_excluding = match.get("versionEndExcluding")
        if end_excluding:
            return end_excluding

    return _fixed_version_from_text(description) or "unknown"


def _extract_product_from_vendors(vendors) -> str:
    if isinstance(vendors, dict):
        for vendor, value in vendors.items():
            products = value.get("products") if isinstance(value, dict) else None
            if isinstance(products, list) and products:
                first = products[0]
                if isinstance(first, str):
                    return _clean_cpe_part(first)

            if isinstance(vendor, str):
                return _clean_cpe_part(vendor)

    if isinstance(vendors, list):
        for item in vendors:
            if isinstance(item, str):
                return _clean_cpe_part(item)

            if isinstance(item, dict):
                for key in ("product", "name", "vendor"):
                    value = item.get(key)
                    if isinstance(value, str):
                        return _clean_cpe_part(value)

    return "unknown"


def _extract_product_status(record: dict) -> dict:
    configurations = record.get("nvd_cpe_configurations") or []
    cpe_matches = [
        match for match in _walk_cpe_matches(configurations)
        if match.get("vulnerable") is not False
    ]

    products = []
    affected_versions = []

    for match in cpe_matches:
        criteria = match.get("criteria") or match.get("cpe23Uri") or ""
        cpe = _parse_cpe(criteria)

        if cpe.get("product"):
            products.append(cpe["product"])

        version_range = _version_range_from_cpe_match(match)
        if version_range != "unknown" and version_range not in affected_versions:
            affected_versions.append(version_range)

    product_hints = _product_hints(record)
    if product_hints:
        product_name = product_hints[0]
    elif products:
        product_name = products[0]
    else:
        product_name = _extract_product_from_vendors(record.get("vendors"))

    return {
        "product_name": product_name,
        "affected_versions": affected_versions or ["unknown"],
        "fixed_version": _fixed_version_from_cpe_matches(cpe_matches, record.get("description") or ""),
        "status": "affected" if affected_versions or product_name != "unknown" else "unknown",
    }


def _to_legacy_raw_record(record: dict) -> dict:
    return {
        "cve_id": record.get("cve_id") or record.get("id") or "unknown",
        "description": record.get("description") or "unknown",
        "cwe": _extract_cwes(record),
        "product_status": _extract_product_status(record),
        "metrics": record.get("metrics") or {},
    }


@tool
def extract_selected_raw_cve_record(record: dict) -> dict:
    """
    Reduce the OpenCVE response to the raw fields this project currently needs.
    """
    return {
        "cve_id": record.get("cve_id") or record.get("id") or "unknown",
        "title": record.get("title") or "unknown",
        "description": record.get("description") or "unknown",
        "cvss": _extract_cvss(record),
        "weaknesses": _extract_cwes(record),
        "nvd_cpe_configurations": _extract_relevant_cpe_configurations(record),
    }


@tool
def fetch_selected_raw_cve_record(cve_id: str) -> dict:
    """
    Fetch an OpenCVE record and keep only the selected raw fields.
    """
    record = fetch_raw_cve_record(cve_id)
    if record.get("error"):
        return record

    return extract_selected_raw_cve_record(record)


@tool
def fetch_cve_record(cve_id: str) -> dict:
    """
    Fetch a CVE record from OpenCVE and reduce it to the legacy raw CVE shape.
    """
    if not cve_id:
        return {
            "error": "cve_id is required"
        }

    record = fetch_raw_cve_record(cve_id)
    if record.get("error"):
        return record

    return _to_legacy_raw_record(record)
