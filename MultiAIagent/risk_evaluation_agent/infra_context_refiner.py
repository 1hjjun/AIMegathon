import json
import os
from typing import List, Dict, Optional, Union

DEFAULT_INPUT_PATH = "infra_context.json"


class AssetRiskAnalyzer:
    def __init__(self, asset_data: Dict):
        self.data = asset_data
        self.assets = asset_data.get("assets", [])

    def extract_critical_assets(self) -> List[Dict]:
        """자산 데이터를 분석하여 SOC 관점 위험 가중치를 계산하고 정렬된 리스트 반환."""
        refined_assets = []

        for asset in self.assets:
            metadata = asset.get("metadata", {})
            sec_context = asset.get("security_context", {})

            risk_score = 0
            risk_factors = []

            # 1. 인터넷 노출 점수 (40점)
            is_public = asset.get("public_ip") or metadata.get("network_exposure") == "public"
            if is_public:
                risk_score += 40
                risk_factors.append("Internet Facing (Public)")

            # 2. 권한 남용 위험 점수 (30점)
            root_procs = sec_context.get("running_as_root", [])
            if root_procs:
                risk_score += 30
                risk_factors.append(f"Root Process: {', '.join(root_procs)}")

            # 3. 비즈니스 중요도 점수 (20점)
            if metadata.get("business_criticality") == "high":
                risk_score += 20
                risk_factors.append("Business Criticality: High")

            # 4. 소프트웨어 취약성 점수 (10점)
            software_list = [
                {
                    "product": sw.get("product"),
                    "version": sw.get("version"),
                    "cpe": sw.get("cpe"),
                }
                for sw in asset.get("installed_software", [])
            ]
            if software_list:
                risk_score += 10

            refined_assets.append({
                "asset_id": asset.get("asset_id"),
                "hostname": asset.get("hostname"),
                "tier": asset.get("tier"),
                "private_ip": asset.get("private_ip"),
                "public_ip": asset.get("public_ip"),
                "risk_score": risk_score,
                "risk_factors": risk_factors,
                "vulnerable_software": software_list,
                "os_info": asset.get("os_info", {}),
                "is_public": is_public,
            })

        return sorted(refined_assets, key=lambda x: x["risk_score"], reverse=True)


def get_refined_asset_report(source: Optional[Union[dict, str]] = None):
    """infra_context 정제.

    source:
        - dict 직접 전달 (AgentCore Runtime 호출 시 권장)
        - str 경로 전달 (로컬 테스트용)
        - None — 기본 경로 'infra_context.json' 읽음
    """
    if source is None:
        source = DEFAULT_INPUT_PATH

    if isinstance(source, str):
        if not os.path.exists(source):
            print(f"경고: {source} 파일을 찾을 수 없습니다.")
            return []
        try:
            with open(source, "r", encoding="utf-8") as f:
                asset_json = json.load(f)
        except Exception as e:
            print(f"파일 로드 실패: {e}")
            return []
    elif isinstance(source, dict):
        asset_json = source
    else:
        print(f"지원하지 않는 source 타입: {type(source)}")
        return []

    try:
        analyzer = AssetRiskAnalyzer(asset_json)
        return analyzer.extract_critical_assets()
    except Exception as e:
        print(f"데이터 정제 중 예외 발생: {e}")
        return []


if __name__ == "__main__":
    print("--- 인프라 데이터 정제 테스트 시작 ---")
    test_results = get_refined_asset_report()
    for res in test_results[:2]:
        print(f"ID: {res['asset_id']} | Score: {res['risk_score']} | Factors: {res['risk_factors']}")
