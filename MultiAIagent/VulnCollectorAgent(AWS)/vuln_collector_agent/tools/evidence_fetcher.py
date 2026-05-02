import json
import re
from html import unescape
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

try:
    from .tooling import tool
except ImportError:
    from tools.tooling import tool

NVD_CVE_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE_URL = "https://api.first.org/data/v1/epss"
MAX_VENDOR_ADVISORY_PREVIEWS = 2
MAX_PATCH_REFS = 5
MAX_VENDOR_FOLLOWUP_PAGES = 2


def _fetch_json(url: str, headers: Optional[dict] = None, timeout: float = 20.0) -> dict:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "VulnerabilityCollectorAgent/0.3",
            **(headers or {}),
        },
    )
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _fetch_text(url: str, timeout: float = 12.0) -> tuple[str, str]:
    request = Request(
        url,
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
            "User-Agent": "VulnerabilityCollectorAgent/0.3",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        content_type = response.headers.get_content_type()
        body = response.read(200_000)
        charset = response.headers.get_content_charset() or "utf-8"
        return body.decode(charset, errors="replace"), content_type


def _nvd_cve_url(cve_id: str) -> str:
    return f"{NVD_CVE_API_BASE_URL}?{urlencode({'cveId': cve_id})}"


def _epss_url(cve_id: str) -> str:
    return f"{EPSS_API_BASE_URL}?{urlencode({'cve': cve_id})}"


def _reference_tags(reference: dict) -> list[str]:
    tags = reference.get("tags") or []
    return [tag for tag in tags if isinstance(tag, str)]


def _has_any_tag(reference: dict, expected_tags: tuple[str, ...]) -> bool:
    tags = set(_reference_tags(reference))
    return any(tag in tags for tag in expected_tags)


def _html_title(document: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", document, re.IGNORECASE | re.DOTALL)
    if not match:
        return "unknown"
    title = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
    return title or "unknown"


def _meta_description(document: str) -> str:
    patterns = [
        r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']',
        r'<meta\s+content=["\'](.*?)["\']\s+name=["\']description["\']',
        r'<meta\s+property=["\']og:description["\']\s+content=["\'](.*?)["\']',
        r'<meta\s+content=["\'](.*?)["\']\s+property=["\']og:description["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, document, re.IGNORECASE | re.DOTALL)
        if match:
            description = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
            if description:
                return description
    return "unknown"


def _document_excerpt(document: str, max_chars: int = 1200) -> str:
    cleaned = re.sub(r"(?is)<script.*?>.*?</script>", " ", document)
    cleaned = re.sub(r"(?is)<style.*?>.*?</style>", " ", cleaned)
    cleaned = re.sub(r"(?is)<[^>]+>", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", unescape(cleaned)).strip()
    if not cleaned:
        return "unknown"
    return cleaned[:max_chars]


def _preview_vendor_advisory(reference: dict) -> dict:
    url = reference.get("url") or ""
    parsed = urlparse(url)
    preview = {
        "url": url,
        "domain": parsed.netloc or "unknown",
        "source": reference.get("source") or "unknown",
        "tags": _reference_tags(reference),
        "title": "unknown",
        "summary": "unknown",
        "content_type": "unknown",
        "preview_status": "not_fetched",
    }

    if not url:
        preview["preview_status"] = "missing_url"
        return preview

    try:
        document, content_type = _fetch_text(url)
        preview["content_type"] = content_type
        if content_type != "text/html":
            preview["preview_status"] = f"skipped_non_html:{content_type}"
            return preview

        preview["title"] = _html_title(document)
        preview["summary"] = _meta_description(document)
        preview["preview_status"] = "ok"
        return preview
    except HTTPError as exc:
        preview["preview_status"] = f"http_error:{exc.code}"
        return preview
    except URLError as exc:
        preview["preview_status"] = f"url_error:{exc.reason}"
        return preview
    except TimeoutError:
        preview["preview_status"] = "timeout"
        return preview
    except Exception as exc:
        preview["preview_status"] = f"error:{type(exc).__name__}"
        return preview


def _vendor_followup_detail(preview: dict) -> dict:
    detail = {
        "url": preview.get("url") or "unknown",
        "domain": preview.get("domain") or "unknown",
        "title": preview.get("title") or "unknown",
        "summary": preview.get("summary") or "unknown",
        "detail_status": "not_fetched",
        "content_excerpt": "unknown",
    }

    url = detail["url"]
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        detail["detail_status"] = "missing_url"
        return detail

    try:
        document, content_type = _fetch_text(url)
        if content_type != "text/html":
            detail["detail_status"] = f"skipped_non_html:{content_type}"
            return detail
        detail["detail_status"] = "ok"
        detail["content_excerpt"] = _document_excerpt(document)
        if detail["title"] == "unknown":
            detail["title"] = _html_title(document)
        if detail["summary"] == "unknown":
            detail["summary"] = _meta_description(document)
        return detail
    except HTTPError as exc:
        detail["detail_status"] = f"http_error:{exc.code}"
        return detail
    except URLError as exc:
        detail["detail_status"] = f"url_error:{exc.reason}"
        return detail
    except TimeoutError:
        detail["detail_status"] = "timeout"
        return detail
    except Exception as exc:
        detail["detail_status"] = f"error:{type(exc).__name__}"
        return detail


@tool
def fetch_nvd_context(cve_id: str) -> dict:
    if not cve_id:
        return {"error": "cve_id is required"}

    try:
        payload = _fetch_json(_nvd_cve_url(cve_id))
    except HTTPError as exc:
        return {"error": f"NVD returned HTTP {exc.code} for {cve_id}"}
    except URLError as exc:
        return {"error": f"Failed to reach NVD for {cve_id}: {exc.reason}"}
    except TimeoutError:
        return {"error": f"Timed out fetching {cve_id} from NVD"}
    except json.JSONDecodeError:
        return {"error": f"NVD returned invalid JSON for {cve_id}"}

    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return {"error": f"NVD returned no vulnerability entries for {cve_id}"}

    cve = (vulnerabilities[0] or {}).get("cve") or {}
    references = cve.get("references") or []
    vendor_advisory_refs = [
        reference for reference in references
        if isinstance(reference, dict) and "Vendor Advisory" in _reference_tags(reference)
    ]

    vendor_advisories = [
        _preview_vendor_advisory(reference)
        for reference in vendor_advisory_refs[:MAX_VENDOR_ADVISORY_PREVIEWS]
    ]
    patch_like_refs = [
        reference for reference in references
        if isinstance(reference, dict) and _has_any_tag(reference, ("Patch", "Vendor Advisory", "Release Notes"))
    ]

    kev = {
        "listed": bool(cve.get("cisaExploitAdd")),
        "date_added": cve.get("cisaExploitAdd") or "unknown",
        "action_due": cve.get("cisaActionDue") or "unknown",
        "required_action": cve.get("cisaRequiredAction") or "unknown",
        "vulnerability_name": cve.get("cisaVulnerabilityName") or "unknown",
    }

    return {
        "cve_id": cve_id,
        "vuln_status": cve.get("vulnStatus") or "unknown",
        "published": cve.get("published") or "unknown",
        "last_modified": cve.get("lastModified") or "unknown",
        "kev": kev,
        "references": [
            {
                "url": reference.get("url") or "unknown",
                "source": reference.get("source") or "unknown",
                "tags": _reference_tags(reference),
            }
            for reference in references
            if isinstance(reference, dict)
        ],
        "vendor_advisories": vendor_advisories,
        "patch_references": [
            {
                "url": reference.get("url") or "unknown",
                "source": reference.get("source") or "unknown",
                "tags": _reference_tags(reference),
            }
            for reference in patch_like_refs[:MAX_PATCH_REFS]
        ],
    }


@tool
def fetch_epss_context(cve_id: str) -> dict:
    if not cve_id:
        return {"error": "cve_id is required"}

    try:
        payload = _fetch_json(_epss_url(cve_id))
    except HTTPError as exc:
        return {"error": f"EPSS returned HTTP {exc.code} for {cve_id}"}
    except URLError as exc:
        return {"error": f"Failed to reach EPSS for {cve_id}: {exc.reason}"}
    except TimeoutError:
        return {"error": f"Timed out fetching {cve_id} from EPSS"}
    except json.JSONDecodeError:
        return {"error": f"EPSS returned invalid JSON for {cve_id}"}

    data = payload.get("data") or []
    if not data:
        return {
            "cve_id": cve_id,
            "epss": "unknown",
            "percentile": "unknown",
            "date": "unknown",
        }

    item = data[0] or {}
    return {
        "cve_id": cve_id,
        "epss": item.get("epss") or "unknown",
        "percentile": item.get("percentile") or "unknown",
        "date": item.get("date") or item.get("created") or "unknown",
    }


@tool
def fetch_operational_evidence(cve_id: str) -> dict:
    nvd_context = fetch_nvd_context(cve_id)

    evidence = {
        "cve_id": cve_id,
        "nvd_context": nvd_context,
        "source_summary": [],
    }

    if not nvd_context.get("error"):
        vendor_advisories = nvd_context.get("vendor_advisories") or []
        patch_references = nvd_context.get("patch_references") or []
        if vendor_advisories:
            evidence["source_summary"].append(
                f"Collected {len(vendor_advisories)} vendor advisory preview(s) from NVD references."
            )
        if patch_references:
            evidence["source_summary"].append(
                f"Collected {len(patch_references)} patch or release-note reference(s) relevant to remediation."
            )
        kev = nvd_context.get("kev") or {}
        if kev.get("required_action") not in (None, "", "unknown"):
            evidence["source_summary"].append("NVD includes a remediation-oriented KEV required action entry.")

    return evidence


@tool
def fetch_vendor_followup_evidence(operational_evidence: dict, selected_urls: Optional[list[str]] = None) -> dict:
    nvd_context = (operational_evidence or {}).get("nvd_context") or {}
    vendor_advisories = nvd_context.get("vendor_advisories") or []
    chosen_urls = {url for url in (selected_urls or []) if isinstance(url, str) and url}

    selected_previews = []
    for preview in vendor_advisories:
        if not isinstance(preview, dict):
            continue
        url = preview.get("url") or ""
        if chosen_urls and url not in chosen_urls:
            continue
        selected_previews.append(preview)

    if not selected_previews:
        selected_previews = [
            preview for preview in vendor_advisories
            if isinstance(preview, dict)
        ][:MAX_VENDOR_FOLLOWUP_PAGES]

    details = [
        _vendor_followup_detail(preview)
        for preview in selected_previews[:MAX_VENDOR_FOLLOWUP_PAGES]
    ]

    domains = []
    for detail in details:
        domain = detail.get("domain")
        if isinstance(domain, str) and domain and domain not in domains:
            domains.append(domain)

    source_summary = []
    if details:
        source_summary.append(
            f"Collected deeper vendor follow-up content from {len(details)} advisory page(s)."
        )
    if domains:
        source_summary.append(
            f"Vendor follow-up domains: {', '.join(domains)}."
        )

    return {
        "details": details,
        "source_summary": source_summary,
    }
