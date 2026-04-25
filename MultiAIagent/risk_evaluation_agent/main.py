import json
import datetime
import os
import risk_assessment_refiner
# import asset_matching_refiner
import infra_context_refiner
from pydantic import BaseModel, Field  
from typing import List                
from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent, tool

app = BedrockAgentCoreApp()
agent = Agent(model="anthropic.claude-3-haiku-20240307-v1:0")

# --- [Step 1: 데이터 규격 정의 (프롬프트 밖에서 관리)] ---

class ImpactedAsset(BaseModel):
    instance_id: str = Field(description="AWS EC2 인스턴스 ID")
    calculated_risk: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW 중 하나를 선택")
    reasoning: str = Field(description="해당 자산의 위험도가 산출된 보안 논리적 근거")
    remediation: str = Field(description="보안 권고 조치 사항")

class FinalReport(BaseModel):
    cve_id: str = Field(description="분석 대상 취약점 번호")
    title: str = Field(description="취약점 명칭")
    impacted_assets: List[ImpactedAsset] = Field(description="영향을 받는 자산 리스트")
    summary: str = Field(description="보안 분석가 관점의 전체 종합 의견")

# --- [Step 2: 도구 정의 (Pydantic 모델을 인자로 받음)] ---

@tool
def finalize_report(report: FinalReport):
    """
    위험도 평가가 완전히 끝났을 때 정규화된 최종 리포트를 저장합니다.
    AI는 FinalReport 구조에 맞춰 데이터를 생성하여 호출해야 합니다.
    """
    # report는 이미 Pydantic에 의해 검증된 객체입니다.
    with open("risk_evaluation_result.json", "w", encoding="utf-8") as f:
        # dict로 변환 후 저장
        json.dump(report.dict(), f, ensure_ascii=False, indent=2)
    return "FINAL_COMPLETE"

@tool
def request_additional_assets(request_list: List[str]):
    """
    판단 근거 부족 시 자산 수집 Agent에게 보낼 추가 조사 항목 리스트를 저장합니다.
    """
    with open("additional_asset_request.json", "w", encoding="utf-8") as f:
        json.dump(request_list, f, ensure_ascii=False, indent=2)
    return "REQUEST_PENDING"

@app.entrypoint
def invoke(payload):
    # 1. 기존 데이터들 로드 (매 실행마다 업데이트된 정보를 읽음)
    vuln_list = risk_assessment_refiner.get_refined_vulnerability()
    asset_info = infra_context_refiner.get_refined_asset_report()
    
    # 2. 에이전트 미션: 판단하거나, 요청하거나
    user_message = payload.get("prompt", "현재 수집된 자산과 취약점을 비교하여 위험도를 평가해줘.")

    user_message = f"""
    {user_message}

    제공된 모든 취약점과 자산의 교집합을 분석하여 '누락 없이' 전수 리포트를 작성하십시오.
    
    [참조 데이터]
    - 취약점 : {json.dumps(vuln_list)}
    - 현재 자산 상태 : {json.dumps(asset_info)}
    
    # ANALYSIS LOGIC
    - 단계 1: 각 취약점(CVE)을 순회합니다.
    - 단계 2: 해당 취약점의 영향을 받는 모든 EC2 인스턴스를 식별합니다.
    - 단계 3: 취약점 1개당 영향을 받는 자산이 여러 개일 경우, 'impacted_assets' 리스트에 모두 포함하십시오.
    - 단계 4: 모든 취약점에 대해 위 과정을 반복하여 하나의 JSON 배열로 응답하십시오.

    # OUTPUT FORMAT (STRICT)
    응답은 반드시 아래 형태의 json 구조여야 합니다:
    
    [
        {{
        "cve_id": "첫 번째 CVE 번호",
        "title": "첫 번째 취약점 명칭",
        "impacted_assets": [
            {{
                "instance_id": "string",
                "calculated_risk": "CRITICAL | HIGH | MEDIUM | LOW",
                "exploit_available": "Yes | No"(공격 코드의 공개되어 있는지 여부),
                "asset_criticality": "Prod | Dev" (해당 서버가 운영 환경인지 테스트 환경인지 구분 ),
                "exposure_level": "Public | Internal" (인터넷 노출인지 내부망에서 사용되는지 여부),
                "potential_impact": "공격 성공 시 예상되는 직접적인 피해 내용",
                "summary": "자산별 위험도 요약"
            }}
        ]
        }},
        {{
        "cve_id": "두 번째 CVE 번호",
        "title": "두 번째 취약점 명칭",
        "impacted_assets": [
            {{
                "instance_id": "string",
                "calculated_risk": "CRITICAL | HIGH | MEDIUM | LOW",
                "exploit_available": "Yes | No"(공격 코드의 공개되어 있는지 여부),
                "asset_criticality": "Prod | Dev" (해당 서버가 운영 환경인지 테스트 환경인지 구분 ),
                "exposure_level": "Public | Internal" (인터넷 노출인지 내부망에서 사용되는지 여부),
                "potential_impact": "공격 성공 시 예상되는 직접적인 피해 내용",
                "summary": "자산별 위험도 요약"
            }}
        ]
        }}
    ]
    

    # CRITICAL CONSTRAINT
        - 입력된 데이터 중 어느 하나라도 분석에서 누락되면 안 됩니다.
        - 텍스트 설명 없이 오직 JSON 배열만 출력하십시오.
        - 모든 설명 및 Json의 Value값은 15자 이내의 핵심 키워드로만 작성하십시오.
        - 줄바꿈을 절대 사용하지 마십시오.

    "RESPONSE MUST BE A SINGLE JSON OBJECT ONLY. DO NOT INCLUDE ANY TEXT OUTSIDE THE JSON."
    """
    
    result = agent(user_message, tools=[finalize_report, request_additional_assets])
    
    # 4. 결과 정제 및 완전한 JSON 포맷팅
    raw_text = result.message['content'][0]['text'].strip()

    # 마크다운 태그(```json)가 섞여 들어올 경우를 대비한 세척
    if "```" in raw_text:
        raw_text = raw_text.split("```")[-1].replace("json", "").strip()

    try:
        # 텍스트를 파이썬 객체로 변환
        final_data = json.loads(raw_text)
        
        # [핵심 수정] 객체를 다시 '들여쓰기(indent=4)'가 적용된 예쁜 JSON 문자열로 변환
        # 이렇게 리턴해야 파일에 넣었을 때 빨간 줄이 안 생기고 탭이 정리됩니다.
        formatted_json = json.dumps(final_data, indent=4, ensure_ascii=False)
        return formatted_json

    except Exception as e:
        # 에러 발생 시 줄바꿈 기호를 세척하고 재시도
        import re
        try:
            clean_text = re.sub(r'\s+', ' ', raw_text)
            fixed_data = json.loads(clean_text)
            return json.dumps(fixed_data, indent=4, ensure_ascii=False)
        except:
            return f"JSON 파싱 실패. 원본 데이터: {raw_text[:200]}"

#    if os.path.exists("risk_evaluation_result.json"):
#        with open("risk_evaluation_result.json", "r", encoding="utf-8") as f:
#            return json.load(f)
    
    return {"status": result.message}

if __name__ == "__main__":
    app.run()

