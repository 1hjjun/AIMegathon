import json
import os
import re
import time
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlparse

from openai import OpenAI
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

try:
    from .tooling import tool
except ImportError:
    from tools.tooling import tool

_BASE_DIR = Path(__file__).parent.parent
_PROMPTS_DIR = _BASE_DIR / "prompts"
_NORMALIZER_PROMPT_PATH = _PROMPTS_DIR / "normalizer_system_prompt.txt"
_EVIDENCE_GATE_PROMPT_PATH = _PROMPTS_DIR / "evidence_gate_system_prompt.txt"
_VENDOR_FOLLOWUP_PROMPT_PATH = _PROMPTS_DIR / "vendor_followup_system_prompt.txt"
_DEFAULT_OPENAI_MODEL = "gpt-4o"

_RISK_ASSESSMENT_FIELD_DESCRIPTIONS = {
    "agent": "Payload owner. risk_assessment is responsible for security severity and exploitability judgment.",
    "source_dataset": "Input dataset used to generate this payload.",
    "record_count": "Number of CVE records in records.",
    "records": "List of CVE risk assessment records.",
    "cve_id": "CVE identifier.",
    "title": "Short vulnerability title.",
    "description": "Source vulnerability description.",
    "cvss": "Source CVSS score, vector, provider, and parsed vector details.",
    "severity": "AI-generated severity bucket derived from the overall evidence.",
    "security_domain": "AI-normalized vulnerability category.",
    "weaknesses": "CWE identifiers associated with the CVE.",
    "cwe_names": "Human-readable CWE names.",
    "risk_signals": "AI assessment of exploitability conditions and attack path.",
    "common_consequences": "AI summary of likely attacker or security outcomes.",
    "analyst_summary": "Short security summary for triage.",
    "sources_used": "Evidence sources that informed the final synthesis, including baseline CVE/CWE data and any optional enrichment.",
    "evidence_summary": "Short summary of whether extra evidence was collected, why it was or was not collected, and the most relevant enrichment highlights.",
}

_OPERATIONAL_IMPACT_FIELD_DESCRIPTIONS = {
    "agent": "Payload owner. operational_impact is responsible for patch, dependency, rollout, and validation judgment.",
    "source_dataset": "Input dataset used to generate this payload.",
    "record_count": "Number of CVE records in records.",
    "records": "List of CVE operational impact records.",
    "cve_id": "CVE identifier.",
    "title": "Short vulnerability title.",
    "product_name": "Affected product or library name.",
    "affected_components": "Components and subcomponents that influence patch scope.",
    "affected_version_range": "Affected version ranges derived from the evidence.",
    "fixed_version": "First known fixed version inferred from the evidence.",
    "patch_type": "Patch action class such as service_upgrade or library_upgrade.",
    "security_domain": "Security category carried over for context.",
    "operational_impacts": "AI-generated ways a careless patch can interrupt or degrade production.",
    "dependency_touchpoints": "Dependencies, packaging points, configs, or platform surfaces to inspect before patching.",
    "code_connectivity_risks": "Indirect code paths or runtime linkage risks that can widen patch blast radius.",
    "rollout_considerations": "Deployment steps that reduce outage risk and preserve rollback options.",
    "validation_focus": "Checks to prioritize before and after patch deployment.",
    "mitigation_summaries": "Short action-oriented patch or remediation summary.",
    "vendor_specific_guidance": "Short vendor-aware operational guidance synthesized from vendor follow-up evidence when available.",
    "notes": "Operationally relevant context only.",
    "sources_used": "Evidence sources that informed the final synthesis, including baseline CVE/CWE data and any optional enrichment.",
    "evidence_summary": "Short summary of whether extra evidence was collected, why it was or was not collected, and the most relevant enrichment highlights.",
}


class RiskSignals(BaseModel):
    network_exploitable: bool = False
    no_privileges_required: bool = False
    no_user_interaction: bool = False
    attack_complexity: str = "unknown"
    scope: str = "unknown"
    exploit_path_summary: str = "unknown"

    @model_validator(mode="before")
    @classmethod
    def _coerce_input(cls, value: Any) -> Any:
        if isinstance(value, list):
            summary = " ".join(str(item).strip() for item in value if str(item).strip())
            return {"exploit_path_summary": summary or "unknown"}
        if isinstance(value, str):
            return {"exploit_path_summary": value.strip() or "unknown"}
        return value


class RiskPayload(BaseModel):
    severity: str = "unknown"
    security_domain: str = "unknown"
    risk_signals: RiskSignals = Field(default_factory=RiskSignals)
    common_consequences: list[str] = Field(default_factory=list)
    analyst_summary: str = "unknown"

    @field_validator("common_consequences", mode="before")
    @classmethod
    def _coerce_common_consequences(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            text = value.strip()
            return [text] if text else []
        return value


class OperationalPayload(BaseModel):
    product_name: str = "unknown"
    affected_components: list[str] = Field(default_factory=list)
    affected_version_range: list[str] = Field(default_factory=list)
    fixed_version: str = "unknown"
    patch_type: str = "unknown"
    security_domain: str = "unknown"
    operational_impacts: list[str] = Field(default_factory=list)
    dependency_touchpoints: list[str] = Field(default_factory=list)
    code_connectivity_risks: list[str] = Field(default_factory=list)
    rollout_considerations: list[str] = Field(default_factory=list)
    validation_focus: list[str] = Field(default_factory=list)
    mitigation_summaries: list[str] = Field(default_factory=list)
    vendor_specific_guidance: list[str] = Field(default_factory=list)
    notes: str = "unknown"

    @field_validator("notes", mode="before")
    @classmethod
    def _coerce_notes(cls, value: Any) -> Any:
        if value is None:
            return "unknown"
        if isinstance(value, list):
            parts = [str(item).strip() for item in value if str(item).strip()]
            return " ".join(parts) if parts else "unknown"
        return value

    @field_validator(
        "affected_components",
        "affected_version_range",
        "operational_impacts",
        "dependency_touchpoints",
        "code_connectivity_risks",
        "rollout_considerations",
        "validation_focus",
        "mitigation_summaries",
        "vendor_specific_guidance",
        mode="before",
    )
    @classmethod
    def _coerce_list_fields(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            text = value.strip()
            return [text] if text else []
        return value


class VulnerabilityPayloadBundle(BaseModel):
    risk_payload: RiskPayload = Field(validation_alias="risk_assessment")
    operational_payload: OperationalPayload = Field(validation_alias="operational_impact")


class OperationalEvidenceDecision(BaseModel):
    collect_operational_evidence: bool = False
    confidence: str = "unknown"
    rationale: str = "unknown"
    evidence_targets: list[str] = Field(default_factory=list)


class VendorFollowupDecision(BaseModel):
    investigate_vendor_context: bool = False
    confidence: str = "unknown"
    rationale: str = "unknown"
    vendor_domains: list[str] = Field(default_factory=list)
    vendor_urls: list[str] = Field(default_factory=list)


_ANALYSIS_CACHE: dict[str, VulnerabilityPayloadBundle] = {}
_EVIDENCE_DECISION_CACHE: dict[str, OperationalEvidenceDecision] = {}
_VENDOR_FOLLOWUP_DECISION_CACHE: dict[str, VendorFollowupDecision] = {}

TModel = TypeVar("TModel", bound=BaseModel)


@tool
def load_collected_records(input_path: str = "data/focused_selected_raw_cves.json") -> dict:
    path = _BASE_DIR / input_path
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


MAX_RETRIES = 3
RETRY_DELAY = 5


def _require_openai_api_key() -> str:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required for AI-based payload generation")
    return api_key


def _openai_model_id() -> str:
    return (os.getenv("OPENAI_MODEL") or _DEFAULT_OPENAI_MODEL).strip()


def _load_normalizer_prompt() -> str:
    return _NORMALIZER_PROMPT_PATH.read_text(encoding="utf-8").strip()


def _load_evidence_gate_prompt() -> str:
    return _EVIDENCE_GATE_PROMPT_PATH.read_text(encoding="utf-8").strip()


def _load_vendor_followup_prompt() -> str:
    return _VENDOR_FOLLOWUP_PROMPT_PATH.read_text(encoding="utf-8").strip()


def _extract_json_blob(text: str) -> Any:
    text = text.strip()
    if not text:
        raise ValueError("LLM response was empty")

    fence_match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for idx, ch in enumerate(text):
        if ch not in '[{':
            continue
        try:
            parsed, _ = decoder.raw_decode(text[idx:])
            return parsed
        except json.JSONDecodeError:
            continue
    raise ValueError("LLM JSON response could not be parsed")


def _generate_with_fallback(client: OpenAI, instructions: str, prompt: str) -> Any:
    last_exc: Exception | None = None
    candidates = [_openai_model_id()]
    for model_name in candidates:
        for attempt in range(MAX_RETRIES):
            try:
                return client.responses.create(
                    model=model_name,
                    instructions=instructions,
                    input=[{"role": "user", "content": prompt}],
                )
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                message = str(exc)
                transient = any(token in message for token in ("429", "500", "502", "503", "timeout", "Timeout"))
                if transient and attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                    continue
                if transient:
                    break
                raise
    raise RuntimeError(f"All model attempts failed: {last_exc}")


def _call_llm_model(system_prompt: str, prompt: str, model_type: type[TModel]) -> TModel:
    client = OpenAI(api_key=_require_openai_api_key())
    response = _generate_with_fallback(client, system_prompt, prompt)
    output_text = getattr(response, "output_text", "") or ""
    payload = _extract_json_blob(output_text)
    try:
        return model_type.model_validate(payload)
    except ValidationError as exc:
        raise RuntimeError(f"Structured output validation failed for {model_type.__name__}: {exc}") from exc


def _cpe_criteria(record: dict) -> list[str]:
    collected = []

    def walk(value) -> None:
        if isinstance(value, dict):
            for key in ("cpeMatch", "cpe_match"):
                items = value.get(key)
                if isinstance(items, list):
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        criteria = item.get("criteria") or item.get("cpe23Uri")
                        if isinstance(criteria, str) and criteria not in collected:
                            collected.append(criteria)

            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(record.get("nvd_cpe_configurations") or [])
    return collected


def _cwe_names(record: dict) -> list[str]:
    names = []
    for item in record.get("cwe_details", []):
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str) and name and name not in names:
            names.append(name)
    return names


def _upstream_identity_tokens(record: dict) -> list[str]:
    title = (record.get("title") or "").split(":", 1)[0]
    raw_tokens = [token.lower() for token in title.replace("/", " ").replace("-", " ").split()]
    tokens = []
    ignored = {"and", "the", "for", "with", "does", "not", "when", "used", "features"}

    for token in raw_tokens:
        normalized = "".join(ch for ch in token if ch.isalnum())
        if len(normalized) < 3 or normalized in ignored:
            continue
        if normalized not in tokens:
            tokens.append(normalized)

    if tokens:
        return tokens

    for criteria in _cpe_criteria(record):
        parts = criteria.split(":")
        for index in (3, 4):
            if len(parts) <= index:
                continue
            token = "".join(ch for ch in parts[index].lower() if ch.isalnum())
            if len(token) >= 3 and token not in tokens:
                tokens.append(token)

    return tokens


def _upstream_vendor_previews(record: dict) -> list[dict]:
    operational_evidence = record.get("operational_evidence") or {}
    nvd_context = operational_evidence.get("nvd_context") or {}
    previews = [
        preview for preview in (nvd_context.get("vendor_advisories") or [])
        if isinstance(preview, dict)
    ]
    if not previews:
        return []

    tokens = _upstream_identity_tokens(record)
    if not tokens:
        return previews

    matched = []
    for preview in previews:
        domain = urlparse(preview.get("url") or "").netloc.lower()
        if any(token in domain for token in tokens):
            matched.append(preview)

    return matched or previews


def _enforce_upstream_vendor_followup(record: dict, decision: VendorFollowupDecision) -> VendorFollowupDecision:
    if not decision.investigate_vendor_context:
        return decision

    upstream_previews = _upstream_vendor_previews(record)
    upstream_urls: list[str] = []
    for preview in upstream_previews:
        url = preview.get("url")
        if isinstance(url, str) and url:
            upstream_urls.append(url)

    if not upstream_urls:
        return decision

    filtered_urls: list[str] = [url for url in decision.vendor_urls if url in upstream_urls]
    if not filtered_urls:
        filtered_urls = upstream_urls[:2]

    filtered_domains: list[str] = []
    for url in filtered_urls:
        domain = urlparse(url).netloc
        if domain and domain not in filtered_domains:
            filtered_domains.append(domain)

    rationale = decision.rationale
    if filtered_urls != decision.vendor_urls:
        rationale = f"{decision.rationale} Upstream maintainer guidance was prioritized over downstream ecosystem pages."

    return VendorFollowupDecision(
        investigate_vendor_context=True,
        confidence=decision.confidence,
        rationale=rationale,
        vendor_domains=filtered_domains,
        vendor_urls=filtered_urls,
    )


def _sources_used(record: dict) -> list[str]:
    sources = ["opencve_record"]

    if record.get("cwe_details"):
        sources.append("mitre_cwe_details")
    if _cpe_criteria(record):
        sources.append("nvd_cpe_configurations")

    operational_evidence = record.get("operational_evidence") or record.get("external_evidence") or {}
    nvd_context = operational_evidence.get("nvd_context") or {}

    if nvd_context:
        sources.append("nvd_context")
        if nvd_context.get("vendor_advisories"):
            sources.append("vendor_advisory_preview")
        if nvd_context.get("patch_references"):
            sources.append("patch_references")
        kev = nvd_context.get("kev") or {}
        if kev.get("required_action") not in (None, "", "unknown"):
            sources.append("kev_required_action")

    vendor_followup_evidence = record.get("vendor_followup_evidence") or {}
    if vendor_followup_evidence.get("details"):
        sources.append("vendor_followup_pages")

    return sources


def _evidence_summary(record: dict) -> dict:
    decision = record.get("operational_evidence_decision") or record.get("evidence_decision") or {}
    operational_evidence = record.get("operational_evidence") or record.get("external_evidence") or {}
    source_summary = operational_evidence.get("source_summary") or []
    vendor_followup_decision = record.get("vendor_followup_decision") or {}
    vendor_followup_evidence = record.get("vendor_followup_evidence") or {}
    vendor_followup_summary = vendor_followup_evidence.get("source_summary") or []

    return {
        "collected_operational_evidence": bool(operational_evidence),
        "gate_decision": bool(
            decision.get("collect_operational_evidence", decision.get("collect_external_evidence"))
        ),
        "gate_confidence": decision.get("confidence", "unknown"),
        "gate_rationale": decision.get("rationale", "No evidence gate rationale was recorded."),
        "collected_vendor_followup": bool(vendor_followup_evidence),
        "vendor_followup_decision": bool(vendor_followup_decision.get("investigate_vendor_context")),
        "vendor_followup_rationale": vendor_followup_decision.get("rationale", "No vendor follow-up rationale was recorded."),
        "highlights": (source_summary + vendor_followup_summary)[:6],
    }


def _record_prompt(record: dict) -> str:
    pretty_record = json.dumps(record, ensure_ascii=False, indent=2)
    return (
        "Analyze the following collected CVE record and return the structured vulnerability payload bundle.\n\n"
        f"{pretty_record}"
    )


def _evidence_gate_prompt(record: dict) -> str:
    pretty_record = json.dumps(record, ensure_ascii=False, indent=2)
    return (
        "Decide whether the following collected CVE record needs extra operational remediation evidence before final synthesis.\n\n"
        f"{pretty_record}"
    )


def _vendor_followup_prompt(record: dict) -> str:
    pretty_record = json.dumps(record, ensure_ascii=False, indent=2)
    return (
        "Decide whether the following collected CVE record needs deeper vendor-specific downstream investigation. "
        "If yes, choose only vendor advisory URLs already present in the record.\n\n"
        f"{pretty_record}"
    )


@tool
def decide_operational_evidence_requirement(record: dict) -> dict:
    cve_id = record.get("cve_id") or "unknown"
    cached = _EVIDENCE_DECISION_CACHE.get(cve_id)
    if cached is not None:
        return cached.model_dump()

    structured_output = _call_llm_model(
        _load_evidence_gate_prompt(),
        _evidence_gate_prompt(record),
        OperationalEvidenceDecision,
    )

    _EVIDENCE_DECISION_CACHE[cve_id] = structured_output
    return structured_output.model_dump()


@tool
def decide_vendor_followup_requirement(record: dict) -> dict:
    cve_id = record.get("cve_id") or "unknown"
    cached = _VENDOR_FOLLOWUP_DECISION_CACHE.get(cve_id)
    if cached is not None:
        return cached.model_dump()

    operational_evidence = record.get("operational_evidence") or {}
    nvd_context = operational_evidence.get("nvd_context") or {}
    if not nvd_context.get("vendor_advisories"):
        result = VendorFollowupDecision(
            investigate_vendor_context=False,
            confidence="high",
            rationale="No vendor advisory previews are available to support controlled downstream follow-up.",
            vendor_domains=[],
            vendor_urls=[],
        )
        _VENDOR_FOLLOWUP_DECISION_CACHE[cve_id] = result
        return result.model_dump()

    structured_output = _call_llm_model(
        _load_vendor_followup_prompt(),
        _vendor_followup_prompt(record),
        VendorFollowupDecision,
    )

    structured_output = _enforce_upstream_vendor_followup(record, structured_output)
    _VENDOR_FOLLOWUP_DECISION_CACHE[cve_id] = structured_output
    return structured_output.model_dump()


def _normalize_record_with_agent(record: dict) -> VulnerabilityPayloadBundle:
    cve_id = record.get("cve_id") or "unknown"
    cached = _ANALYSIS_CACHE.get(cve_id)
    if cached is not None:
        return cached

    structured_output = _call_llm_model(
        _load_normalizer_prompt(),
        _record_prompt(record),
        VulnerabilityPayloadBundle,
    )

    bundle = structured_output
    _ANALYSIS_CACHE[cve_id] = bundle
    return bundle


def _normalized_records(dataset: dict) -> list[VulnerabilityPayloadBundle]:
    return [
        _normalize_record_with_agent(record)
        for record in dataset.get("records", [])
        if isinstance(record, dict)
    ]


@tool
def build_risk_assessment_payloads(dataset: dict) -> dict:
    normalized_records = _normalized_records(dataset)
    records = []

    for record, normalized in zip(dataset.get("records", []), normalized_records):
        risk = normalized.risk_payload
        records.append({
            "cve_id": record.get("cve_id"),
            "title": record.get("title"),
            "description": record.get("description"),
            "cvss": record.get("cvss") or {},
            "severity": risk.severity,
            "security_domain": risk.security_domain,
            "weaknesses": record.get("weaknesses", []),
            "cwe_names": _cwe_names(record),
            "risk_signals": risk.risk_signals.model_dump(),
            "common_consequences": risk.common_consequences,
            "analyst_summary": risk.analyst_summary,
            "sources_used": _sources_used(record),
            "evidence_summary": _evidence_summary(record),
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
    normalized_records = _normalized_records(dataset)
    records = []

    for record, normalized in zip(dataset.get("records", []), normalized_records):
        operational = normalized.operational_payload
        records.append({
            "cve_id": record.get("cve_id"),
            "title": record.get("title"),
            "product_name": operational.product_name,
            "affected_components": operational.affected_components,
            "affected_version_range": operational.affected_version_range,
            "fixed_version": operational.fixed_version,
            "patch_type": operational.patch_type,
            "security_domain": operational.security_domain,
            "operational_impacts": operational.operational_impacts,
            "dependency_touchpoints": operational.dependency_touchpoints,
            "code_connectivity_risks": operational.code_connectivity_risks,
            "rollout_considerations": operational.rollout_considerations,
            "validation_focus": operational.validation_focus,
            "mitigation_summaries": operational.mitigation_summaries,
            "vendor_specific_guidance": operational.vendor_specific_guidance,
            "notes": operational.notes,
            "sources_used": _sources_used(record),
            "evidence_summary": _evidence_summary(record),
        })

    return {
        "agent": "operational_impact",
        "source_dataset": "focused_selected_raw_cves.json",
        "field_descriptions": _OPERATIONAL_IMPACT_FIELD_DESCRIPTIONS,
        "record_count": len(records),
        "records": records,
    }
