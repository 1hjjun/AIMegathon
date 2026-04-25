import json
import os
from typing import List, Dict

class AssetRiskAnalyzer:
    def __init__(self, asset_data: Dict):
        self.data = asset_data
        self.assets = asset_data.get("assets", [])

    def extract_critical_assets(self) -> List[Dict]:
        """
        자산 데이터를 분석하여 SOC 관점의 위험 가중치를 계산하고 정렬된 리스트를 반환합니다.
        """
        refined_assets = []
        
        for asset in self.assets:
            asset_id = asset.get("asset_id")
            metadata = asset.get("metadata", {})
            sec_context = asset.get("security_context", {})
            net_context = asset.get("network_context", {}) # 네트워크 정보 추가
            
            # 위험 가중치 계산 로직
            risk_score = 0
            risk_factors = []

            # 1. 인터넷 노출 점수 (40점) - Public IP가 있거나 exposure가 public인 경우
            is_public = asset.get("public_ip") or metadata.get("network_exposure") == "public"
            if is_public:
                risk_score += 40
                risk_factors.append("Internet Facing (Public)")

            # 2. 권한 남용 위험 점수 (30점) - Root 권한으로 실행 중인 프로세스가 있는 경우
            root_procs = sec_context.get("running_as_root", [])
            if root_procs:
                risk_score += 30
                risk_factors.append(f"Root Process: {', '.join(root_procs)}")

            # 3. 비즈니스 중요도 점수 (20점) - High Criticality 자산인 경우
            if metadata.get("business_criticality") == "high":
                risk_score += 20
                risk_factors.append("Business Criticality: High")

            # 4. 소프트웨어 취약성 점수 (10점) - 설치된 소프트웨어가 식별된 경우
            software_list = [
                {
                    "product": sw.get("product"), 
                    "version": sw.get("version"), 
                    "cpe": sw.get("cpe")
                }
                for sw in asset.get("installed_software", [])
            ]
            if software_list:
                risk_score += 10

            # 5. 정제된 데이터 조립
            refined_assets.append({
                "asset_id": asset_id,
                "hostname": asset.get("hostname"),
                "tier": asset.get("tier"),
                "private_ip": asset.get("private_ip"),
                "public_ip": asset.get("public_ip"),
                "risk_score": risk_score,
                "risk_factors": risk_factors,
                "vulnerable_software": software_list,
                "os_info": asset.get("os_info", {}),
                "is_public": is_public
            })

        # 위험 점수가 높은 순(내림차순)으로 정렬
        return sorted(refined_assets, key=lambda x: x['risk_score'], reverse=True)

def get_refined_asset_report(file_path: str = 'infra_context.json'):
    """
    외부(main.py)에서 호출하는 인터페이스 함수입니다.
    """
    if not os.path.exists(file_path):
        print(f"경고: {file_path} 파일을 찾을 수 없습니다.")
        return []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            asset_json = json.load(f)
        
        analyzer = AssetRiskAnalyzer(asset_json)
        return analyzer.extract_critical_assets()
    except Exception as e:
        print(f"데이터 정제 중 예외 발생: {e}")
        return []

if __name__ == "__main__":
    # 단독 테스트용
    print("--- 인프라 데이터 정제 테스트 시작 ---")
    test_results = get_refined_asset_report()
    for res in test_results[:2]: # 상위 2개만 출력
        print(f"ID: {res['asset_id']} | Score: {res['risk_score']} | Factors: {res['risk_factors']}")