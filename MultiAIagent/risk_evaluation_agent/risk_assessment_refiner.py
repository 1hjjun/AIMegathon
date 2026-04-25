import json

def get_refined_vulnerability():
    """
    risk_assessment_payloads.json에서 핵심 보안 지표만 추출
    """
    input_path = 'risk_assessment_payloads.json'
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        refined_records = []
        
        # 'records' 리스트 순회
        for record in data.get('records', []):
            # CVSS 상세 정보 추출 (판단 근거의 핵심)
            cvss_details = record.get('cvss', {}).get('vector_details', {})
            
            refined_item = {
                "cve_id": record.get("cve_id"),
                "severity": record.get("severity"),
                "score": record.get("cvss", {}).get("score"),
                # AI가 공격 가능성을 판단할 핵심 매트릭스
                "attack_vector": cvss_details.get("attack_vector"),
                "attack_complexity": cvss_details.get("attack_complexity"),
                "privileges_required": cvss_details.get("privileges_required"),
                # 어떤 도메인의 취약점인지 (RCE, Memory 등)
                "domain": record.get("security_domain"),
                # 요약된 설명 (너무 길면 핵심만)
                "summary": record.get("title")
            }
            refined_records.append(refined_item)
            
        return refined_records

    except FileNotFoundError:
        print("파일을 찾을 수 없습니다.")
        return []
    except json.JSONDecodeError:
        print("JSON 파싱 에러가 발생했습니다.")
        return []

if __name__ == "__main__":
    # 테스트 실행
    result = get_refined_vulnerability()
    print(json.dumps(result, indent=2))