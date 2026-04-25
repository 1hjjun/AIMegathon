import json

def get_refined_asset_report():
    """
    asset_matching_result.json에서 위험도 평가에 꼭 필요한 
    자산 보안 설정 및 취약점 요약 정보만 추출
    """
    input_path = 'asset_matching_result.json'
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 1. 자산 기본 보안 컨텍스트 추출
        metadata = data.get("metadata", {})
        refined_asset = {
            "asset_id": data.get("asset_id"),
            "hostname": data.get("hostname"),
            "security_context": {
                "env": metadata.get("environment"),
                "exposure": metadata.get("network_exposure"), # public 여부 확인 핵심
                "criticality": metadata.get("business_criticality")
            },
            "vulnerability_summary": []
        }

        # 2. 매칭된 취약점(matched_cves) 중 핵심 지표만 추출
        for cve in data.get("matched_cves", []):
            cvss_details = cve.get("cvss", {}).get("vector_details", {})
            
            # AI가 판단하기 좋게 다이어트된 취약점 정보
            refined_vuln = {
                "cve_id": cve.get("cve_id"),
                "severity_score": cve.get("cvss", {}).get("score"),
                "attack_vector": cvss_details.get("attack_vector"), # network vs local
                "attack_complexity": cvss_details.get("attack_complexity"),
                "software": cve.get("matched_software", {}).get("product"),
                "version": cve.get("matched_software", {}).get("installed_version")
            }
            refined_asset["vulnerability_summary"].append(refined_vuln)

        return refined_asset

    except FileNotFoundError:
        return {"error": "asset_matching_result.json 파일을 찾을 수 없습니다."}

if __name__ == "__main__":
    # 테스트 출력
    result = get_refined_asset_report()
    print(json.dumps(result, indent=2, ensure_ascii=False))