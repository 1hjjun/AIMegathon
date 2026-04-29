import json
import datetime
import os
import risk_assessment_refiner
import boto3
import infra_context_refiner
from pydantic import BaseModel, Field  
from typing import List                
from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent, tool

app = BedrockAgentCoreApp()
agent = Agent(model="anthropic.claude-3-haiku-20240307-v1:0")
client = boto3.client("bedrock-agent-runtime")

@tool
def ask_asset_agent(missing_queries: List[str]):
    """
    분석에 필요한 자산 정보가 부족할 때, 자산 수집 에이전트(다른 런타임)에게 
    실시간으로 추가 정보를 요청하고 그 결과를 반환받습니다.
    """
    ASSET_AGENT_ID = "ASSET_COLLECTOR_ID" 
    ASSET_AGENT_ALIAS_ID = "TSTALIASID"

    # AI가 넘겨준 리스트를 하나의 질문 문장으로 합칩니다.
    combined_query = ", ".join(missing_queries)

    try:
        # 다른 런타임 에이전트 호출
        response = client.invoke_agent(
            agentId=ASSET_AGENT_ID,
            agentAliasId=ASSET_AGENT_ALIAS_ID,
            sessionId="security-swarm-session",
            inputText=f"다음 항목들에 대해 추가 조사가 필요합니다: {combined_query}"
        )
        
        # 호출 결과를 텍스트로 변환하여 현재 에이전트에게 리턴
        # 이를 통해 현재 에이전트는 바로 분석을 재개합니다.
        return response['completion']
        
    except Exception as e:
        return f"자산 에이전트 호출 중 오류 발생: {str(e)}"

@tool
def handoff_to_impact_analyzer(risk_result: str):
    """
    위험도 평가 완료 후, 영향도 평가 에이전트(다른 런타임)에게 결과를 전달합니다.
    """
    IMPACT_AGENT_ID = "IMPACT_ANALYZER_ID"
    IMPACT_AGENT_ALIAS_ID = "TSTALIASID"

    # 다른 런타임 에이전트 호출
    response = client.invoke_agent(
        agentId=IMPACT_AGENT_ID,
        agentAliasId=IMPACT_AGENT_ALIAS_ID,
        sessionId="security-swarm-session",
        inputText=f"평가 완료된 위험도 데이터입니다. 영향도 분석 시작해줘: {risk_result}"
    )
    
    # 전달 성공 메시지 혹은 에이전트의 답변 반환
    return response['completion']

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
    - 단계 1: 각 취약점의 'summary(title)'와 'description'을 정밀 분석하여, 공격 성공에 필요한 핵심 키워드와 서버 전제 조건(Prerequisites)을 파악하십시오.
    - 단계 2: 해당 취약점의 영향을 받는 EC2 인스턴스를 식별하고, 자산의 포트, 보안 그룹 상태 등 필수 데이터를 대조하십시오.
    - 단계 3: 자산 정보에 해당 전제 조건(예: 특정 설정, 포트 활성화 여부)을 확인할 수 있는 데이터가 부족하다면, 즉시 `ask_asset_agent` 도구를 호출하여 구체적으로 조사하십시오.
    - 단계 4: 모든 데이터가 확보되어 위험도 평가가 완료되었다면, 최종 JSON 결과를 생성하여 `handoff_to_impact_analyzer` 도구의 인자로 전달하십시오.

    # OUTPUT FORMAT (STRICT)
    응답은 반드시 아래 형태의 json 구조여야 합니다:
    
    [
        {{
        "cve_id": "첫 번째 CVE 번호",
        "title": "원문을 그대로 복사하지 말고, 5단어 이내로 직관적으로 요약한 명칭",
        "impacted_assets": [
            {{
                // [필수 고정 필드: 반드시 아래 Key를 유지할 것]
                "instance_id": "string",
                "calculated_risk": "CRITICAL | HIGH | MEDIUM | LOW",
                "exploit_available": "Yes | No"(공격 코드의 공개되어 있는지 여부),
                "asset_criticality": "Prod | Dev" (해당 서버가 운영 환경인지 테스트 환경인지 구분 ),
                "exposure_level": "Public | Private" (인터넷 노출인지 내부망에서 사용되는지 여부),
                "potential_impact": "공격 성공 시 예상되는 직접적인 피해 내용",
                "inbound_open_ports": "실제 허용된 인바운드 포트들을 나열 (예: 80, 443, 22)",
                "outbound_allow_rules": "실제 허용된 아웃바운드 규칙 (예: All Traffic 또는 0.0.0.0/0:443)",
                "security_group_status": "보안 그룹 개방 수준 (예: Full-Open, Restricted, Internal-Only)"

                // [에이전트의 사고 강제 필드: 깊게 분석하되 출력은 짧게]
                "attack_prerequisites_reasoning": "Description을 분석하여 단순 포트 개방이나 데몬 실행 여부가 아닌, 취약점 발현을 위한 '특수 기능/모듈'과 '특수 통신 조건'을 파악한 뒤, 콤마(,)로 구분된 짧은 단답형 키워드로만 요약하십시오 (줄바꿈 절대 금지).",

                // [수정: 예시 단어 제거 및 다중 키 강제]
                "cve_specific_findings": {{
                    "Required_Condition_1_Name": "상태값 (예: Yes / No / Unknown)",
                    "Required_Condition_2_Name": "상태값",
                    "Required_Condition_3_Name": "상태값 (필요시 계속 추가)"
                }}
            }}
        ]
        }},
        {{
        "cve_id": "두 번째 CVE 번호",
        "title": "두 번째 취약점 명칭",
        "impacted_assets": [
            {{
                // [필수 고정 필드: 반드시 아래 Key를 유지할 것]
                "instance_id": "string",
                "calculated_risk": "CRITICAL | HIGH | MEDIUM | LOW",
                "exploit_available": "Yes | No"(공격 코드의 공개되어 있는지 여부),
                "asset_criticality": "Prod | Dev" (해당 서버가 운영 환경인지 테스트 환경인지 구분 ),
                "exposure_level": "Public | Private" (인터넷 노출인지 내부망에서 사용되는지 여부),
                "potential_impact": "공격 성공 시 예상되는 직접적인 피해 내용",
                "inbound_open_ports": "실제 허용된 인바운드 포트들을 나열 (예: 80, 443, 22)",
                "outbound_allow_rules": "실제 허용된 아웃바운드 규칙 (예: All Traffic 또는 0.0.0.0/0:443)",
                "security_group_status": "보안 그룹 개방 수준 (예: Full-Open, Restricted, Internal-Only)"

                // [에이전트의 사고 강제 필드: 깊게 분석하되 출력은 짧게]
                "attack_prerequisites_reasoning": "Description을 분석하여 단순 포트 개방이나 데몬 실행 여부가 아닌, 취약점 발현을 위한 '특수 기능/모듈'과 '특수 통신 조건'을 파악한 뒤, 콤마(,)로 구분된 짧은 단답형 키워드로만 요약하십시오 (줄바꿈 절대 금지).",

                // [수정: 예시 단어 제거 및 다중 키 강제]
                "cve_specific_findings": {{
                    "Required_Condition_1_Name": "상태값 (예: Yes / No / Unknown)",
                    "Required_Condition_2_Name": "상태값",
                    "Required_Condition_3_Name": "상태값 (필요시 계속 추가)"
                }}
            }}
        ]
        }}
    ]
    
    # CRITICAL CONSTRAINT
    1. [문법 엄수] 텍스트 설명 없이 오직 JSON 배열만 출력하십시오. JSON 내부에는 어떠한 주석(//)도 포함하지 마십시오.
    2. [무결성] 제공된 자산 및 취약점 데이터 중 어느 하나라도 분석에서 누락되면 안 됩니다.
    3. [도구 호출 및 빈칸 무관용 - 매우 중요] 자산 데이터에 `inbound_open_ports` 등 필수 고정 필드 값이 없거나, `cve_specific_findings`를 확정할 정보가 부족하다면 **절대 임의로 "Yes/No"를 추측하거나 빈칸("")으로 비워두지 마십시오.** 비어있는 값이 발생할 상황이라면 즉시 JSON 출력을 멈추고 `ask_asset_agent` 도구를 호출하여 사실을 확인하십시오. (최종 분석 완료 시에만 `handoff_to_impact_analyzer` 호출)
    4. [가변 필드 규칙] `cve_specific_findings`에는 일반적인 데몬 실행 여부나 뻔한 포트/버전 정보(예: Nginx_Version, Open_Port_80)를 적지 마십시오. 오직 Description을 분석하여 **공격 발현을 위한 특수한 기능/설정(예: DNS Resolver, JNDI 기능)이나 공격자의 조작 조건(예: UDP 패킷 위조 가능 여부)**만을 도출해 Key로 만드십시오.
    5. [조건 다각화 강제] 단 하나의 조건만 도출하고 멈추지 마십시오. 공격자가 거쳐야 하는 네트워크 흐름(In/Outbound), 필수 데몬 활성화 여부 등 **최소 2개 이상의 서로 다른 필수 전제 조건**을 쪼개어 `cve_specific_findings`의 Key로 생성하십시오.
    6. [파싱 오류 방지 - 줄바꿈 절대 금지] JSON Value 안에 실제 줄바꿈(Enter)이나 '\n' 문자가 포함되면 시스템이 붕괴됩니다. 모든 Value 값은 아무리 길어지더라도 절대 줄바꿈을 하지 말고, 반드시 한 줄(Single line)로 이어서 작성하십시오.
    7. [길이 제한 및 요약 강제] 
       - `title` 필드는 원문을 복사하지 말고 5단어 이내로 짧게 요약하십시오.
       - `attack_prerequisites_reasoning` 필드는 긴 문장이 아닌, 콤마(,)로 구분된 짧은 키워드(예: UDP 패킷 위조, Nginx Resolver 활성화)로만 작성하십시오.
       - `cve_specific_findings`의 Value는 분석된 상태를 15자 이내의 단답형(Yes, No, Unknown 등)으로만 간결하게 작성하십시오.

    "RESPONSE MUST BE A SINGLE JSON OBJECT ONLY. DO NOT INCLUDE ANY TEXT OUTSIDE THE JSON."
    
    """
    
    result = agent(user_message, tools=[ask_asset_agent, handoff_to_impact_analyzer])

    # 1. 에이전트가 도구를 정상적으로 호출한 경우, 도구에 담은 JSON 알맹이만 빼옵니다.
    if hasattr(result, 'tool_calls') and result.tool_calls:
        for call in result.tool_calls:
            if call.function.name == "handoff_to_impact_analyzer":
                return call.function.arguments.get("risk_result", "도구는 호출했으나 risk_result 값이 없습니다.")

    # 2. 도구를 호출하지 않고 그냥 텍스트로 답한 경우 (예외 상황)
    try:
        return result.message['content'][0]['text']
    except Exception as e:
        return f"분석 실패 또는 결과 추출 오류: {str(e)}"

if __name__ == "__main__":
    app.run()

