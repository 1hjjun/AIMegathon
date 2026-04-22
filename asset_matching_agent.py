#!/usr/bin/env python3
"""
자산 매칭 Agent.

asset_info.json (extract_asset.py 출력)과
nginx_selected_raw_cves.json (취약점 수집 Agent 출력)을 입력받아,
설치된 소프트웨어에 영향을 미치는 CVE를 판별한 뒤
asset_matching_result.json 으로 저장한다.
"""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# 버전 비교 유틸 (외부 의존성 없음)
# ---------------------------------------------------------------------------

def _parse_version(version_str: str) -> tuple[int, ...]:
    """
    "1.18.0" → (1, 18, 0) 형태로 변환한다.
    숫자가 아닌 접미사(rc1, beta 등)는 제거 후 파싱한다.
    """
    # 숫자와 점으로만 구성된 앞부분 추출
    clean = re.match(r"[\d.]+", version_str)
    if not clean:
        return (0,)
    parts = clean.group(0).rstrip(".").split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return (0,)


def _version_in_range(
    installed: str,
    start_including: str | None,
    start_excluding: str | None,
    end_including: str | None,
    end_excluding: str | None,
) -> bool:
    """
    설치된 버전이 지정된 범위 안에 있는지 확인한다.
    모든 범위 필드가 None 이면 True (버전 무관 취약점).
    """
    v = _parse_version(installed)

    if start_including:
        if v < _parse_version(start_including):
            return False

    if start_excluding:
        if v <= _parse_version(start_excluding):
            return False

    if end_including:
        if v > _parse_version(end_including):
            return False

    if end_excluding:
        if v >= _parse_version(end_excluding):
            return False

    return True


def _range_description(
    start_including: str | None,
    start_excluding: str | None,
    end_including: str | None,
    end_excluding: str | None,
) -> str:
    """사람이 읽기 쉬운 버전 범위 문자열을 생성한다."""
    left = f"[{start_including}" if start_including else (f"({start_excluding}" if start_excluding else "(-∞")
    right = f"{end_including}]" if end_including else (f"{end_excluding})" if end_excluding else "+∞)")
    return f"{left}, {right}"


# ---------------------------------------------------------------------------
# CPE 파싱
# ---------------------------------------------------------------------------

def _parse_cpe(criteria: str) -> tuple[str, str]:
    """
    "cpe:2.3:a:f5:nginx:*:..." → ("f5", "nginx") 반환.
    파싱 실패 시 ("", "") 반환.
    """
    parts = criteria.split(":")
    # cpe:2.3:type:vendor:product:...
    if len(parts) >= 5:
        return parts[3].lower(), parts[4].lower()
    return "", ""


# ---------------------------------------------------------------------------
# 매칭 코어
# ---------------------------------------------------------------------------

def _match_software_to_cpe_node(software: dict, cpe_match: dict) -> dict | None:
    """
    소프트웨어 하나와 CPE 매치 항목 하나를 비교한다.
    취약하다고 판단되면 매치 상세를 반환하고, 아니면 None 을 반환한다.
    """
    if not cpe_match.get("vulnerable", False):
        return None

    criteria = cpe_match.get("criteria", "")
    cpe_vendor, cpe_product = _parse_cpe(criteria)

    sw_vendor = software.get("vendor", "").lower()
    sw_product = software.get("product", "").lower()

    # 벤더·제품명 일치 확인
    if cpe_vendor != sw_vendor or cpe_product != sw_product:
        return None

    installed_version = software.get("version", "")
    start_inc = cpe_match.get("versionStartIncluding")
    start_exc = cpe_match.get("versionStartExcluding")
    end_inc = cpe_match.get("versionEndIncluding")
    end_exc = cpe_match.get("versionEndExcluding")

    # 버전 범위 필드가 모두 없으면 와일드카드 취약점 (버전 무관)
    has_range = any([start_inc, start_exc, end_inc, end_exc])

    if has_range and not _version_in_range(
        installed_version, start_inc, start_exc, end_inc, end_exc
    ):
        return None

    return {
        "matched_cpe": criteria,
        "version_range": _range_description(start_inc, start_exc, end_inc, end_exc),
        "wildcard_match": not has_range,
    }


def match_cve_to_asset(cve: dict, asset: dict) -> dict | None:
    """
    CVE 하나와 자산을 비교한다.
    취약점이 확인되면 매치 결과 dict 를 반환하고, 아니면 None 을 반환한다.

    NVD CPE 구성 논리:
      - configurations 내부 nodes 는 OR 관계
      - 각 node 내 cpeMatch 항목들은 OR 관계
      - negate=True 인 node 는 제외 조건 (현재 스펙에서는 단순화하여 무시)
    """
    installed_list: list[dict] = asset.get("installed_software", [])
    configurations: list[dict] = cve.get("nvd_cpe_configurations", [])

    if not configurations:
        return None

    for config in configurations:
        for node in config.get("nodes", []):
            if node.get("negate", False):
                continue  # 제외 조건 노드는 스킵

            for cpe_match in node.get("cpeMatch", []):
                for software in installed_list:
                    detail = _match_software_to_cpe_node(software, cpe_match)
                    if detail:
                        return {
                            "cve_id": cve["cve_id"],
                            "title": cve.get("title", ""),
                            "description": cve.get("description", ""),
                            "matched_software": {
                                "vendor": software.get("vendor"),
                                "product": software.get("product"),
                                "installed_version": software.get("version"),
                            },
                            "match_detail": detail,
                            "cvss": cve.get("cvss", {}),
                            "weaknesses": cve.get("weaknesses", []),
                            "is_vulnerable": True,
                        }
    return None


# ---------------------------------------------------------------------------
# 메인 파이프라인
# ---------------------------------------------------------------------------

def run_matching(asset_path: Path, cves_path: Path) -> dict:
    asset: dict = json.loads(asset_path.read_text())
    cve_data: dict = json.loads(cves_path.read_text())
    records: list[dict] = cve_data.get("records", [])

    matched: list[dict] = []
    unmatched: list[dict] = []

    for cve in records:
        result = match_cve_to_asset(cve, asset)
        if result:
            matched.append(result)
        else:
            unmatched.append({
                "cve_id": cve["cve_id"],
                "title": cve.get("title", ""),
                "is_vulnerable": False,
            })

    return {
        "asset_id": asset.get("asset_id"),
        "hostname": asset.get("hostname"),
        "metadata": asset.get("metadata", {}),
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_cves_evaluated": len(records),
            "vulnerable_count": len(matched),
            "not_vulnerable_count": len(unmatched),
        },
        "matched_cves": matched,
        "unmatched_cves": unmatched,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="자산 정보와 CVE 데이터를 비교하여 영향 여부를 판별합니다."
    )
    parser.add_argument(
        "--asset",
        default="asset_info.json",
        help="자산 정보 JSON 파일 경로 (default: asset_info.json)",
    )
    parser.add_argument(
        "--cves",
        default="nginx_selected_raw_cves.json",
        help="CVE 데이터 JSON 파일 경로 (default: nginx_selected_raw_cves.json)",
    )
    parser.add_argument(
        "--output",
        default="asset_matching_result.json",
        help="출력 파일 경로 (default: asset_matching_result.json)",
    )
    args = parser.parse_args()

    asset_path = Path(args.asset)
    cves_path = Path(args.cves)

    if not asset_path.exists():
        print(f"[ERROR] 자산 파일을 찾을 수 없습니다: {asset_path}")
        raise SystemExit(1)
    if not cves_path.exists():
        print(f"[ERROR] CVE 파일을 찾을 수 없습니다: {cves_path}")
        raise SystemExit(1)

    result = run_matching(asset_path, cves_path)

    output_path = Path(args.output)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2))

    matched_count = result["summary"]["vulnerable_count"]
    total = result["summary"]["total_cves_evaluated"]
    print(f"[OK] 매칭 완료: {total}개 CVE 중 {matched_count}개 취약점 발견")
    print(f"[OK] 결과 저장: {output_path.resolve()}")

    if result["matched_cves"]:
        print("\n--- 취약한 CVE 목록 ---")
        for m in result["matched_cves"]:
            score = m["cvss"].get("score", "N/A")
            version_range = m["match_detail"]["version_range"]
            print(
                f"  {m['cve_id']} | CVSS {score} | "
                f"{m['matched_software']['product']} {m['matched_software']['installed_version']} "
                f"→ 범위 {version_range}"
            )


if __name__ == "__main__":
    main()
