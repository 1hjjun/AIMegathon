import json
from typing import Optional, Union

DEFAULT_INPUT_PATH = "risk_assessment_payloads.json"


def get_refined_vulnerability(payload: Optional[Union[dict, str]] = None):
    """risk_assessment 페이로드에서 핵심 보안 지표만 추출.

    payload:
        - dict 직접 전달 (AgentCore Runtime 호출 시 권장)
        - str 경로 전달 (로컬 테스트용)
        - None — 기본 경로 'risk_assessment_payloads.json' 읽음
    """
    if payload is None:
        payload = DEFAULT_INPUT_PATH

    if isinstance(payload, str):
        try:
            with open(payload, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            print("파일을 찾을 수 없습니다.")
            return []
        except json.JSONDecodeError:
            print("JSON 파싱 에러가 발생했습니다.")
            return []
    elif isinstance(payload, dict):
        data = payload
    else:
        print(f"지원하지 않는 payload 타입: {type(payload)}")
        return []

    refined_records = []
    for record in data.get("records", []):
        cvss_details = record.get("cvss", {}).get("vector_details", {})
        refined_records.append({
            "cve_id": record.get("cve_id"),
            "severity": record.get("severity"),
            "score": record.get("cvss", {}).get("score"),
            "attack_vector": cvss_details.get("attack_vector"),
            "attack_complexity": cvss_details.get("attack_complexity"),
            "privileges_required": cvss_details.get("privileges_required"),
            "domain": record.get("security_domain"),
            "summary": record.get("title"),
        })
    return refined_records


if __name__ == "__main__":
    result = get_refined_vulnerability()
    print(json.dumps(result, indent=2, ensure_ascii=False))
