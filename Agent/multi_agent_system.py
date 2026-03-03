"""
Multi-Agent Security Fix Detection System
协调三个专家Agent：CVE分析专家 → Commit分析专家 → 决策专家
"""
import subprocess
from typing import TypedDict, Optional
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END

from cve_analyst import CVEAnalystAgent
from commit_analyst import CommitAnalystAgent
from decision_maker import DecisionMakerAgent


# ==================== 状态定义 ====================
class MultiAgentState(TypedDict):
    """多Agent共享状态"""
    # 输入信息
    cve_id: str
    cve_description: str
    commit_hash: str
    commit_message: str
    commit_diff: str
    
    # Agent 1 输出 (CVE分析专家)
    cve_analysis: Optional[dict]
    
    # Agent 2 输出 (Commit分析专家)
    commit_analysis: Optional[dict]
    
    # Agent 3 输出 (决策专家)
    final_decision: Optional[dict]
    
    # 元数据
    tool_calls_count: int
    error: Optional[str]


# ==================== 主系统：多Agent协作 ====================
class MultiAgentSecuritySystem:
    """三Agent串行协作系统"""
    
    def __init__(
        self,
        repo_path: str,
        api_key: str,
        base_url: Optional[str] = None,
        model: str = "gpt-4o-mini",
        temperature: float = 0.1,
        verbose: bool = False
    ):
        self.verbose = verbose
        self.repo_path = repo_path
        
        # 初始化LLM
        llm_kwargs = {"model": model, "temperature": temperature, "api_key": api_key}
        if base_url:
            llm_kwargs["base_url"] = base_url
        
        # 为每个Agent创建独立的LLM实例（可以用不同配置）
        self.cve_llm = ChatOpenAI(**llm_kwargs)
        self.commit_llm = ChatOpenAI(**llm_kwargs)
        self.decision_llm = ChatOpenAI(**llm_kwargs)
        
        # 初始化三个Agent
        self.cve_analyst = CVEAnalystAgent(self.cve_llm, verbose=verbose)
        self.commit_analyst = CommitAnalystAgent(self.commit_llm, verbose=verbose)
        self.decision_maker = DecisionMakerAgent(self.decision_llm, verbose=verbose)
        
        # 构建LangGraph工作流
        self.app = self._build_graph()
    
    def _build_graph(self):
        """构建并行三Agent工作流"""
        
        def cve_analysis_node(state: MultiAgentState) -> dict:
            """节点1: CVE分析（并行）"""
            if self.verbose:
                print("\n" + "="*60)
                print("STAGE 1a: CVE Analysis (Parallel)")
                print("="*60)
            
            result = self.cve_analyst.analyze(
                cve_id=state["cve_id"],
                cve_description=state["cve_description"]
            )
            
            return {"cve_analysis": result}
        
        def commit_analysis_node(state: MultiAgentState) -> dict:
            """节点2: Commit分析（并行）"""
            if self.verbose:
                print("\n" + "="*60)
                print("STAGE 1b: Commit Analysis (Parallel)")
                print("="*60)
            
            result = self.commit_analyst.analyze(
                commit_hash=state["commit_hash"],
                commit_message=state["commit_message"],
                commit_diff=state["commit_diff"]
            )
            
            # 暂时不使用工具，tool_calls_count保持为0
            return {
                "commit_analysis": result,
                "tool_calls_count": 0
            }
        
        def aggregation_node(state: MultiAgentState) -> dict:
            """汇总节点：等待并行任务完成"""
            if self.verbose:
                print("\n" + "="*60)
                print("STAGE 2: Aggregating Results")
                print("="*60)
                print(f"CVE Analysis: {'✓' if state['cve_analysis'] else '✗'}")
                print(f"Commit Analysis: {'✓' if state['commit_analysis'] else '✗'}")
            
            # 不做任何修改，只是一个同步点
            return {}
        
        def decision_node(state: MultiAgentState) -> dict:
            """节点3: 最终决策"""
            if self.verbose:
                print("\n" + "="*60)
                print("STAGE 3: Final Decision")
                print("="*60)
            
            result = self.decision_maker.decide(
                cve_id=state["cve_id"],
                cve_analysis=state["cve_analysis"],
                commit_analysis=state["commit_analysis"]
            )
            
            return {"final_decision": result}
        
        # 构建图
        workflow = StateGraph(MultiAgentState)
        
        # 添加节点
        workflow.add_node("cve_analyst", cve_analysis_node)
        workflow.add_node("commit_analyst", commit_analysis_node)
        workflow.add_node("aggregation", aggregation_node)
        workflow.add_node("decision_maker", decision_node)
        
        # 设置并行流程
        # START -> CVE Analyst (并行分支1)
        workflow.add_edge("__start__", "cve_analyst")
        # START -> Commit Analyst (并行分支2)
        workflow.add_edge("__start__", "commit_analyst")
        
        # 两个并行任务都汇总到 aggregation 节点
        workflow.add_edge("cve_analyst", "aggregation")
        workflow.add_edge("commit_analyst", "aggregation")
        
        # aggregation -> decision_maker -> END
        workflow.add_edge("aggregation", "decision_maker")
        workflow.add_edge("decision_maker", END)
        
        return workflow.compile()
    
    def _get_commit_diff(self, commit_hash: str, context_lines: int = 8) -> str:
        """获取commit的diff"""
        try:
            result = subprocess.run(
                ['git', 'show', f'--unified={context_lines}', commit_hash],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                errors='ignore'
            )
            return result.stdout if result.returncode == 0 else ""
        except:
            return ""
    
    def analyze_commit(
        self,
        cve_id: str,
        cve_desc: str,
        commit_hash: str,
        commit_message: str,
        repo_name: Optional[str] = None
    ) -> dict:
        """
        分析commit是否为CVE修复（三Agent协作）
        
        Returns:
            包含完整分析过程和最终决策的字典
        """
        # 获取diff
        diff = self._get_commit_diff(commit_hash, context_lines=8)
        if len(diff) > 4000:
            diff = diff[:4000] + "\n[... truncated ...]"
        
        # 初始状态
        initial_state = {
            "cve_id": cve_id,
            "cve_description": cve_desc,
            "commit_hash": commit_hash,
            "commit_message": commit_message,
            "commit_diff": diff,
            "cve_analysis": None,
            "commit_analysis": None,
            "final_decision": None,
            "tool_calls_count": 0,
            "error": None
        }
        
        try:
            # 执行工作流
            final_state = self.app.invoke(initial_state)
            
            # 提取结果
            decision = final_state["final_decision"]
            
            return {
                'is_security_fix': decision.get("decision", "NO") == "YES",
                'reasoning': decision.get("reasoning", ""),
                'tool_calls': final_state["tool_calls_count"],
                # 附加完整的三个Agent输出
                'cve_analysis': final_state["cve_analysis"],
                'commit_analysis': final_state["commit_analysis"],
                'decision_details': decision,
                'agent_steps': []  # 兼容旧接口
            }
        
        except Exception as e:
            return {
                'is_security_fix': False,
                'reasoning': f"Multi-agent system error: {str(e)}",
                'tool_calls': 0,
                'cve_analysis': None,
                'commit_analysis': None,
                'decision_details': None,
                'agent_steps': [],
                'error': str(e)
            }
