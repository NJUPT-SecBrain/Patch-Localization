"""
CVE Analyst Agent - 专门分析CVE描述的专家
"""
import json
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage


class CVEAnalystAgent:
    """专门分析CVE描述的专家Agent"""
    
    def __init__(self, llm: ChatOpenAI, verbose: bool = False):
        self.llm = llm
        self.verbose = verbose
    
    def analyze(self, cve_id: str, cve_description: str) -> dict:
        """分析CVE描述，提取关键信息"""
        
        system_prompt = """You are a CVE security analysis expert. Your task is to analyze CVE descriptions 
and extract key vulnerability information.

Analyze the following aspects:

1. Vulnerability Type: Identify the type of vulnerability (e.g., XSS, SQL Injection, RCE, CSRF, etc.)
2. Affected Components: Extract the specific modules, components, or file paths affected
3. Root Cause: Explain the underlying technical flaw that causes the vulnerability
4. Expected Fix Patterns: List the likely code changes or security patterns that would fix this vulnerability

Output as JSON with these fields:
{
  "vulnerability_type": "string",
  "affected_components": ["string"],
  "root_cause": "string",
  "expected_fix_patterns": ["string"]
}

Be concise and factual. Extract only information explicitly stated or clearly inferable from the CVE description."""
        
        user_prompt = f"""CVE ID: {cve_id}

Description:
{cve_description}

Analyze this CVE and output structured information in JSON format."""
        
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ]
        
        try:
            response = self.llm.invoke(messages)
            content = response.content
            
            if self.verbose:
                print(f"\n[CVE Analyst] Raw output:\n{content[:300]}...")
            
            # 解析JSON
            if "{" in content and "}" in content:
                json_start = content.find("{")
                json_end = content.rfind("}") + 1
                json_str = content[json_start:json_end]
                result = json.loads(json_str)
                
                # 确保所有字段都存在
                required_fields = [
                    "vulnerability_type", "affected_components", "root_cause",
                    "expected_fix_patterns"
                ]
                for field in required_fields:
                    if field not in result:
                        result[field] = [] if field != "vulnerability_type" and field != "root_cause" else "unknown"
                
                return result
            else:
                raise ValueError("No JSON found in response")
        
        except Exception as e:
            if self.verbose:
                print(f"[CVE Analyst] Error: {e}")
            
            return {
                "vulnerability_type": "unknown",
                "affected_components": [],
                "root_cause": "analysis failed",
                "expected_fix_patterns": [],
                "error": str(e)
            }
