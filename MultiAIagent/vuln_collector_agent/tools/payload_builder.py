import json
import re
from pathlib import Path

from tools.tooling import tool

_BASE_DIR = Path(__file__).parent.parent

_RISK_ASSESSMENT_FIELD_DESCRIPTIONS = {
    "agent": "Payload owner. risk_assessment is responsible for security severity and exploitability judgment.",
    "source_dataset": "Input dataset used to generate this payload.",
    "record_count": "Number of CVE records in records.",
    "records": "List of CVE risk assessment records.",
    "cve_id": "CVE identifier.",
    "title": "Short vulnerability title.",
    "description": "Source vulnerability description.",
    "cvss": "CVSS score, vector, provider, and parsed vector details.",
    "severity": "Severity bucket derived from CVSS score.",
    "security_domain": "Normalized vulnerability category such as remote-code-execution, memory-corruption, or denial-of-service.",
    "weaknesses": "CWE identifiers associated with the CVE.",
    "cwe_names": "Human-readable CWE names.",
    "risk_signals": "Exploitability signals extracted from CVSS, such as network exposure and privilege requirements.",
    "common_consequences": "CWE-derived attacker/security outcomes. This is not patch rollout risk.",
}

_OPERATIONAL_IMPACT_FIELD_DESCRIPTIONS = {
    "agent": "Payload owner. operational_impact is responsible for patch, dependency, rollout, and validation judgment.",
    "source_dataset": "Input dataset used to generate this payload.",
    "record_count": "Number of CVE records in records.",
    "records": "List of CVE operational impact records.",
    "cve_id": "CVE identifier.",
    "title": "Short vulnerability title.",
    "product_name": "Affected product or library name.",
    "affected_components": "Product and subcomponents that influence patch scope.",
    "affected_version_range": "Affected version ranges derived from CPE data.",
    "fixed_version": "First known fixed version inferred from version range or description.",
    "patch_type": "Patch action class, such as service_upgrade or library_upgrade.",
    "security_domain": "Security category carried over for context, not the main operational judgment.",
    "operational_impacts": "Ways a careless patch can interrupt or degrade production.",
    "dependency_touchpoints": "Dependencies, packaging points, configs, or platform surfaces to inspect before patching.",
    "code_connectivity_risks": "Indirect code paths or runtime linkage risks that can widen patch blast radius.",
    "rollout_considerations": "Deployment steps that reduce outage risk and preserve rollback options.",
    "validation_focus": "Checks to prioritize before and after patch deployment.",
    "mitigation_summaries": "Short action-oriented patch/remediation summary for the operations agent.",
    "notes": "Original source description retained as context.",
}

@tool
def load_collected_records(input_path: str = "data/focused_selected_raw_cves.json") -> dict:
    path = _BASE_DIR / input_path
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _clean_cpe_part(value: str) -> str:
    if not value or value in {"*", "-"}:
        return ""

    return value.replace("\\:", ":").replace("_", "-").lower()


def _parse_cpe(criteria: str) -> dict:
    parts = criteria.split(":")
    if len(parts) < 6:
        return {}

    return {
        "part": _clean_cpe_part(parts[2]),
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


def _version_range_from_match(match: dict) -> str:
    parts = []

    if match.get("versionStartIncluding"):
        parts.append(f">={match['versionStartIncluding']}")
    if match.get("versionStartExcluding"):
        parts.append(f">{match['versionStartExcluding']}")
    if match.get("versionEndIncluding"):
        parts.append(f"<={match['versionEndIncluding']}")
    if match.get("versionEndExcluding"):
        parts.append(f"<{match['versionEndExcluding']}")

    if parts:
        return " ".join(parts)

    criteria = match.get("criteria") or ""
    cpe = _parse_cpe(criteria)
    return cpe.get("version") or "unknown"


def _cpe_products(record: dict) -> list[str]:
    products = []
    for match in _walk_cpe_matches(record.get("nvd_cpe_configurations") or []):
        cpe = _parse_cpe(match.get("criteria") or "")
        product = cpe.get("product")
        if product and product not in products:
            products.append(product)
    return products


def _primary_product(record: dict) -> str:
    cpe_products = _cpe_products(record)
    if cpe_products:
        product = cpe_products[0]
        if product == "log4j":
            return "apache-log4j"
        return product

    text = f"{record.get('title', '')} {record.get('description', '')}".lower()
    for keyword in ("apache-log4j", "log4j", "nginx"):
        if keyword in text:
            return keyword

    return "unknown"


def _product_components(record: dict) -> list[str]:
    text = f"{record.get('title', '')} {record.get('description', '')}".lower()
    components = []
    primary_product = _primary_product(record)

    if primary_product != "unknown":
        components.append(primary_product)

    keyword_map = {
        "resolver": "dns-resolver",
        "jndi": "jndi",
        "lookup": "message-lookup",
        "ldap": "ldap-endpoints",
        "log-messages": "log-messages",
        "parameters": "log-parameters",
    }
    for keyword, component in keyword_map.items():
        if keyword in text and component not in components:
            components.append(component)

    for product in _cpe_products(record):
        normalized = "apache-log4j" if product == "log4j" else product
        if normalized not in components:
            components.append(normalized)

    return components


def _affected_version_ranges(record: dict) -> list[str]:
    ranges = []
    for match in _walk_cpe_matches(record.get("nvd_cpe_configurations") or []):
        if match.get("vulnerable") is False:
            continue

        version_range = _version_range_from_match(match)
        if version_range not in ranges:
            ranges.append(version_range)

    return ranges or ["unknown"]


def _fixed_version(record: dict) -> str:
    candidates = []
    for match in _walk_cpe_matches(record.get("nvd_cpe_configurations") or []):
        if match.get("versionEndExcluding"):
            candidates.append(match["versionEndExcluding"])
        if match.get("versionEndIncluding"):
            candidates.append(match["versionEndIncluding"])

    if candidates:
        def _version_key(value: str):
            parts = re.findall(r"[A-Za-z]+|\d+", value)
            key = []
            for part in parts:
                if part.isdigit():
                    key.append((0, int(part)))
                else:
                    key.append((1, part.lower()))
            return key

        return max(candidates, key=_version_key)

    description = record.get("description", "")
    match = re.search(r"\b(?:from version|before versions?|before version|before)\s+([A-Za-z0-9][A-Za-z0-9._+-]*)", description)
    if match:
        return match.group(1)

    return "unknown"


def _security_domain(record: dict) -> str:
    text = f"{record.get('title', '')} {record.get('description', '')}".lower()
    weakness_names = " ".join(item.get("name", "") for item in record.get("cwe_details", []))
    consequence_text = json.dumps(record.get("cwe_details", []), ensure_ascii=False).lower()

    if any(keyword in text for keyword in ("execute arbitrary code", "remote code", "code execution")):
        return "remote-code-execution"
    if any(keyword in weakness_names.lower() for keyword in ("deserialization",)):
        return "deserialization"
    if any(keyword in text for keyword in ("memory overwrite", "buffer overflow", "off-by-one", "memory disclosure")):
        return "memory-corruption"
    if "crash" in text or "denial of service" in text:
        return "denial-of-service"
    if "bypass" in text or "authentication" in text:
        return "authentication"
    if "authorization" in text:
        return "authorization"
    if "path" in text and "travers" in text:
        return "path-traversal"
    if "http header" in text:
        return "http-header"
    if "modify memory" in consequence_text:
        return "memory-corruption"

    return "unknown"


def _severity_bucket(score) -> str:
    if not isinstance(score, (int, float)):
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _risk_signals(record: dict) -> dict:
    details = (record.get("cvss") or {}).get("vector_details") or {}
    return {
        "network_exploitable": details.get("attack_vector") == "network",
        "no_privileges_required": details.get("privileges_required") == "none",
        "no_user_interaction": details.get("user_interaction") == "none",
        "attack_complexity": details.get("attack_complexity", "unknown"),
        "scope": details.get("scope", "unknown"),
    }


def _patch_type(record: dict) -> str:
    product = _primary_product(record)
    if product == "nginx":
        return "service_upgrade"
    if product == "apache-log4j":
        return "library_upgrade"
    return "unknown"


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _operational_impacts(record: dict) -> list[str]:
    impacts = []
    patch_type = _patch_type(record)
    components = set(_product_components(record))

    if patch_type == "service_upgrade":
        _append_unique(impacts, "Service restart or reload can interrupt active traffic if rollout is not drained.")
        _append_unique(impacts, "Runtime configuration compatibility must be checked before upgrading the service binary.")
        _append_unique(impacts, "Modules compiled or packaged with the current service version can become incompatible.")
    elif patch_type == "library_upgrade":
        _append_unique(impacts, "Application rebuild and redeploy are required for services that package the vulnerable library.")
        _append_unique(impacts, "Transitive dependency conflicts can break startup or runtime class loading.")
        _append_unique(impacts, "Multiple bundled or shaded copies can leave some execution paths unpatched.")
    else:
        _append_unique(impacts, "Patch deployment can affect dependent services and should be staged before production rollout.")

    if "dns-resolver" in components:
        _append_unique(impacts, "DNS resolver behavior changes can affect upstream discovery and request routing.")
    if {"jndi", "message-lookup", "ldap-endpoints", "log-parameters"} & components:
        _append_unique(impacts, "Logging configuration or lookup behavior changes can affect code paths across many modules.")

    return impacts


def _dependency_touchpoints(record: dict) -> list[str]:
    product = _primary_product(record)
    components = set(_product_components(record))

    if product == "nginx":
        touchpoints = [
            "reverse proxy routes and upstream pools",
            "nginx configuration files and included snippets",
            "dynamic modules and OS packages",
            "load balancer health checks",
        ]
        if "dns-resolver" in components:
            touchpoints.append("DNS resolver configuration and upstream service discovery")
        return touchpoints

    if product == "apache-log4j":
        return [
            "direct and transitive Java dependencies",
            "application packaging such as JAR, WAR, container image, or shared app-server library",
            "logging configuration files and custom appenders/layouts",
            "SLF4J, Log4j bridge, and framework logging adapters",
            "shaded or duplicated log4j-core copies",
        ]

    return [
        "dependent services",
        "runtime configuration",
        "build and deployment pipeline",
    ]


def _code_connectivity_risks(record: dict) -> list[str]:
    product = _primary_product(record)

    if product == "nginx":
        return [
            "Ingress, proxy, and routing changes can affect downstream applications even when their code is unchanged.",
            "Connection draining, worker reload behavior, and health checks determine whether the upgrade is user-visible.",
        ]

    if product == "apache-log4j":
        return [
            "The library is commonly called through shared logging abstractions, so many services and modules can depend on it indirectly.",
            "Classpath ordering, framework adapters, or shaded dependencies can cause different code paths to load different Log4j versions.",
        ]

    return [
        "Indirect callers and runtime dependency resolution can widen the blast radius beyond the owning component.",
    ]


def _rollout_considerations(record: dict) -> list[str]:
    patch_type = _patch_type(record)
    fixed_version = _fixed_version(record)
    version_note = f"Target fixed version: {fixed_version} or later." if fixed_version != "unknown" else "Target fixed version is unknown; confirm before rollout."

    if patch_type == "service_upgrade":
        return [
            version_note,
            "Use rolling upgrade or blue/green deployment where possible.",
            "Drain traffic and verify health checks before removing old instances.",
            "Keep a rollback package and previous configuration available.",
        ]

    if patch_type == "library_upgrade":
        return [
            version_note,
            "Regenerate lockfiles or dependency manifests and rebuild the artifact.",
            "Scan the final artifact or container image for duplicate vulnerable library copies.",
            "Canary the redeploy and keep the previous artifact available for rollback.",
        ]

    return [
        version_note,
        "Stage the patch in a non-production environment first.",
        "Prepare rollback steps before production deployment.",
    ]


def _validation_focus(record: dict) -> list[str]:
    product = _primary_product(record)

    if product == "nginx":
        return [
            "configuration syntax test",
            "startup/reload test",
            "proxy routing and upstream DNS resolution",
            "health check and connection draining behavior",
        ]

    if product == "apache-log4j":
        return [
            "dependency tree and packaged artifact verification",
            "application startup",
            "logging configuration compatibility",
            "critical request flows that emit logs",
        ]

    return [
        "dependency compatibility",
        "application startup",
        "critical user flows",
    ]


def _mitigation_summaries(record: dict) -> list[str]:
    summaries = []
    fixed_version = _fixed_version(record)
    patch_type = _patch_type(record)

    if fixed_version != "unknown":
        summaries.append(f"Upgrade to {fixed_version} or later.")

    if patch_type == "service_upgrade":
        summaries.append("Validate configuration compatibility, drain traffic, then roll the service upgrade gradually.")
    elif patch_type == "library_upgrade":
        summaries.append("Update dependency manifests, rebuild the deployable artifact, and verify the packaged runtime version.")
    else:
        summaries.append("Stage the patch, validate dependent components, and prepare rollback before production rollout.")

    return summaries


@tool
def build_asset_matching_payloads(dataset: dict) -> dict:
    records = []

    for record in dataset.get("records", []):
        records.append({
            "cve_id": record.get("cve_id"),
            "product_name": _primary_product(record),
            "affected_version_range": _affected_version_ranges(record),
            "fixed_version": _fixed_version(record),
            "product_status": "affected",
            "cpe_criteria": [
                match.get("criteria")
                for match in _walk_cpe_matches(record.get("nvd_cpe_configurations") or [])
                if match.get("criteria")
            ],
        })

    return {
        "agent": "asset_matching",
        "source_dataset": "focused_selected_raw_cves.json",
        "record_count": len(records),
        "records": records,
    }


@tool
def build_risk_assessment_payloads(dataset: dict) -> dict:
    records = []

    for record in dataset.get("records", []):
        cvss = record.get("cvss") or {}
        records.append({
            "cve_id": record.get("cve_id"),
            "title": record.get("title"),
            "description": record.get("description"),
            "cvss": cvss,
            "severity": _severity_bucket(cvss.get("score")),
            "security_domain": _security_domain(record),
            "weaknesses": record.get("weaknesses", []),
            "cwe_names": [item.get("name", "unknown") for item in record.get("cwe_details", [])],
            "risk_signals": _risk_signals(record),
            "common_consequences": [
                consequence
                for cwe in record.get("cwe_details", [])
                for consequence in cwe.get("common_consequences", [])
            ],
        })

    return {
        "agent": "risk_assessment",
        "source_dataset": "focused_selected_raw_cves.json",
        "field_descriptions": _RISK_ASSESSMENT_FIELD_DESCRIPTIONS,
        "record_count": len(records),
        "records": records,
    }


@tool
def build_operational_impact_payloads(dataset: dict) -> dict:
    records = []

    for record in dataset.get("records", []):
        records.append({
            "cve_id": record.get("cve_id"),
            "title": record.get("title"),
            "product_name": _primary_product(record),
            "affected_components": _product_components(record),
            "affected_version_range": _affected_version_ranges(record),
            "fixed_version": _fixed_version(record),
            "patch_type": _patch_type(record),
            "security_domain": _security_domain(record),
            "operational_impacts": _operational_impacts(record),
            "dependency_touchpoints": _dependency_touchpoints(record),
            "code_connectivity_risks": _code_connectivity_risks(record),
            "rollout_considerations": _rollout_considerations(record),
            "validation_focus": _validation_focus(record),
            "mitigation_summaries": _mitigation_summaries(record),
            "notes": record.get("description"),
        })

    return {
        "agent": "operational_impact",
        "source_dataset": "focused_selected_raw_cves.json",
        "field_descriptions": _OPERATIONAL_IMPACT_FIELD_DESCRIPTIONS,
        "record_count": len(records),
        "records": records,
    }
