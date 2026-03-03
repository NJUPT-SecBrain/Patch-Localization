"""
Decision Maker Agent - 整合CVE和Commit分析结果，做出最终判断
"""
import json
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage


class DecisionMakerAgent:
    """整合CVE和Commit分析结果，做出最终判断"""
    
    def __init__(self, llm: ChatOpenAI, verbose: bool = False):
        self.llm = llm
        self.verbose = verbose
    
    def decide(self, cve_id: str, cve_analysis: dict, commit_analysis: dict) -> dict:
        """基于两个专家的分析结果，做出最终判断"""
        
        system_prompt = """You are a security fix verification expert.

Your task: Based on CVE analysis and Commit analysis, determine if the commit fixes the specific CVE.

**Analysis Approach**:
Read both analyses carefully. The CVE analysis tells you what vulnerability exists and what kind of 
fix is expected. The Commit analysis tells you what actually changed in the code and why.

Ask yourself:
1. Do the code changes address the vulnerability described in the CVE?
2. Do the modified components match the affected components in the CVE?
3. Does the nature of the fix align with what's expected for this vulnerability type?
4. Is this a genuine security fix or just a refactoring/feature addition?

**Decision Criteria**:
- YES: High confidence (>=70%) this commit fixes the CVE
- NO: This commit does not fix this specific CVE (<40% confidence)
- UNCERTAIN: Partial match, unclear (40-69% confidence)

**Output Format**:
{
  "decision": "YES" or "NO",
  "confidence": 0-100,
  "reasoning": "detailed explanation of your decision",
  "component_match": true/false,
  "fix_pattern_match": true/false,
  "vulnerability_match": true/false
}

Be thorough in your reasoning. Explain why you reached your decision."""
        
        user_prompt = f"""CVE ID: {cve_id}

=== CVE Analysis (by CVE Expert) ===
{json.dumps(cve_analysis, indent=2, ensure_ascii=False)}

=== Commit Analysis (by Commit Expert) ===
{json.dumps(commit_analysis, indent=2, ensure_ascii=False)}

Based on these analyses, determine if this commit fixes CVE {cve_id}.
Output your decision in JSON format."""
        
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ]
        
        try:
            response = self.llm.invoke(messages)
            content = response.content
            
            if self.verbose:
                print(f"\n[Decision Maker] Raw output:\n{content[:300]}...")
            
            # 解析JSON
            if "{" in content and "}" in content:
                json_start = content.find("{")
                json_end = content.rfind("}") + 1
                json_str = content[json_start:json_end]
                result = json.loads(json_str)
                
                # 确保必需字段存在
                if "decision" not in result:
                    result["decision"] = "NO"
                if "confidence" not in result:
                    result["confidence"] = 0
                if "reasoning" not in result:
                    result["reasoning"] = "unknown"
                
                return result
            else:
                raise ValueError("No JSON found in response")
        
        except Exception as e:
            if self.verbose:
                print(f"[Decision Maker] Error: {e}")
            
            return {
                "decision": "NO",
                "confidence": 0,
                "reasoning": f"Decision failed: {str(e)}",
                "component_match": False,
                "fix_pattern_match": False,
                "vulnerability_match": False,
                "error": str(e)
            }
