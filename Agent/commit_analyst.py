"""
Commit Analyst Agent - 专门分析Commit和代码diff的专家
"""
import json
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage


class CommitAnalystAgent:
    """专门分析Commit和代码diff的专家Agent（暂不使用工具）"""
    
    def __init__(self, llm: ChatOpenAI, verbose: bool = False):
        self.llm = llm
        self.verbose = verbose
    
    def analyze(self, commit_hash: str, commit_message: str, commit_diff: str) -> dict:
        """分析commit和diff，提取改动信息（暂不使用工具）"""
        
        system_prompt = """You are a Code Change Analysis Expert. Analyze Git commits and code diffs to understand 
what changed and why.

**Your Analysis Should Cover:**
1. **What changed** - Describe the modifications in the code
2. **Why it changed** - Infer the intent from the commit message and code changes
3. **Your observations** - Add any additional insights about the changes, potential issues, 
   or patterns you notice

Be concise and technical. Focus on understanding the change holistically.

**Output Format** (JSON for downstream processing):
{
  "what_changed": "string - describe modifications",
  "why_changed": "string - infer intent",
  "observations": "string - additional insights"
}

Note: Be natural and insightful in your descriptions. Don't just list facts mechanically."""
        
        user_prompt = f"""Commit: {commit_hash}
Message: {commit_message}

Diff:
{commit_diff}

Analyze this commit and output structured information in JSON format."""
        
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ]
        
        try:
            # 直接调用 LLM（不使用工具）
            response = self.llm.invoke(messages)
            content = response.content
            
            if self.verbose:
                print(f"\n[Commit Analyst] Output:\n{content[:300]}...")
            
            # 解析JSON
            if "{" in content and "}" in content:
                json_start = content.find("{")
                json_end = content.rfind("}") + 1
                json_str = content[json_start:json_end]
                result = json.loads(json_str)
                
                # 添加工具使用信息（暂时为空）
                result["tools_used"] = []
                
                # 确保必需字段存在
                required_fields = ["what_changed", "why_changed", "observations"]
                for field in required_fields:
                    if field not in result:
                        result[field] = "unknown"
                
                return result
            else:
                raise ValueError("No JSON found in response")
        
        except Exception as e:
            if self.verbose:
                print(f"[Commit Analyst] Error: {e}")
            
            return {
                "what_changed": "analysis failed",
                "why_changed": "unknown",
                "observations": "error occurred",
                "tools_used": [],
                "error": str(e)
            }
