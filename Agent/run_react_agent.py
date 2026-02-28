import sys
import os
import pandas as pd
import time
from pathlib import Path

# 添加当前脚本所在目录到Python路径（修复模块导入问题）
SCRIPT_DIR = Path(__file__).parent.absolute()
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from langgraph_react_agent import SecurityFixReActAgent


# ==================== 配置 ====================
API_KEY = "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"
BASE_URL = None  # 或中转站URL
MODEL = "gpt-4o-mini"
TEMPERATURE = 0.1
MAX_ITERATIONS = 5  # ReAct最大推理轮数

# 路径配置
REPO_ROOT = r"E:\ptrhon project\project2\vcmatch_repro\gitrepo1"
INPUT_CSV = r"E:\ptrhon project\project2\vcmatch_repro\dataset\test_cve_2012_0850_hard.csv"
OUTPUT_CSV = r"E:\ptrhon project\project2\vcmatch_repro\dataset\agent_results.csv"
LOG_FILE = r"E:\ptrhon project\project2\vcmatch_repro\dataset\agent_react_log.txt"

DEFAULT_CVE_DESC = "The sbr_qmf_synthesis function in libavcodec/aacsbr.c in FFmpeg before 0.9.1 allows remote attackers to cause a denial of service (application crash) via a crafted mpg file that triggers memory corruption involving the v_off variable, probably a buffer underflow."


class DetailedLogger:
    """Detailed logger for Agent reasoning process"""
    
    def __init__(self, filename):
        self.log = open(filename, 'w', encoding='utf-8')
    
    def section(self, title):
        self.log.write("\n" + "="*80 + "\n")
        self.log.write(f"{title}\n")
        self.log.write("="*80 + "\n\n")
    
    def subsection(self, title):
        self.log.write("\n" + "-"*80 + "\n")
        self.log.write(f"{title}\n")
        self.log.write("-"*80 + "\n")
    
    def write(self, content):
        self.log.write(content + "\n")
    
    def code_block(self, title, content):
        self.log.write(f"\n{title}:\n")
        self.log.write("-" * 40 + "\n")
        self.log.write(content[:2000] if len(content) > 2000 else content)
        if len(content) > 2000:
            self.log.write("\n... [truncated] ...")
        self.log.write("\n" + "-" * 40 + "\n")
    
    def final_decision(self, decision, confidence, reasoning):
        self.log.write("\n" + "="*80 + "\n")
        self.log.write(f"FINAL DECISION: {decision}\n")
        self.log.write(f"Confidence: {confidence}%\n")
        self.log.write(f"Reasoning: {reasoning}\n")
        self.log.write("="*80 + "\n")
    
    def flush(self):
        self.log.flush()
    
    def close(self):
        self.log.close()


def format_agent_steps(steps):
    """格式化Agent的推理步骤（从intermediate_steps提取）"""
    formatted = []
    for i, (action, observation) in enumerate(steps, 1):
        formatted.append({
            'round': i,
            'tool': action.tool,
            'input': str(action.tool_input),
            'observation': observation[:200] + "..." if len(observation) > 200 else observation
        })
    return formatted


def main():
    # Check configuration
    if not API_KEY or "your-api-key" in API_KEY.lower():
        print("[ERROR] Please set API_KEY in script")
        return
    
    # Load data
    print("="*80)
    print("Loading test data...")
    print("="*80)
    
    df = pd.read_csv(INPUT_CSV, encoding='utf-8-sig')
    print(f"Loaded {len(df)} commits")
    print(f"  - Label=1 (True Fix): {len(df[df['label']==1])}")
    print(f"  - Label=0 (Candidate): {len(df[df['label']==0])}")
    
    # Get repository path
    first_repo = df.iloc[0]['repo']
    repo_path = Path(REPO_ROOT) / first_repo
    if not repo_path.exists():
        print(f"[ERROR] Repository not found: {repo_path}")
        return
    
    # Initialize Agent
    print("\n" + "="*80)
    print("Initializing LangChain ReAct Agent...")
    print("="*80)
    
    try:
        agent = SecurityFixReActAgent(
            repo_path=str(repo_path),
            api_key=API_KEY,
            base_url=BASE_URL,
            model=MODEL,
            temperature=TEMPERATURE,
            max_iterations=MAX_ITERATIONS,
            verbose=False
        )
        print(f"[OK] Agent initialized (Model: {MODEL})")
    except Exception as e:
        print(f"[ERROR] Initialization failed: {e}")
        return
    
    # Initialize logger
    logger = DetailedLogger(LOG_FILE)
    logger.section("LangChain ReAct Agent - Complete Reasoning Log")
    logger.write(f"Test Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.write(f"Model: {MODEL}")
    logger.write(f"Total Commits: {len(df)}")
    logger.write(f"CVE: {df.iloc[0]['cve']}")
    
    print("\n" + "="*80)
    print("Starting batch analysis...")
    print("="*80)
    print(f"Log File: {LOG_FILE}")
    print(f"Result File: {OUTPUT_CSV}\n")
    
    results = []
    start_time = time.time()
    
    for idx, row in df.iterrows():
        cve_id = str(row['cve'])
        repo_name = str(row['repo'])
        commit_hash = str(row['commit'])
        true_label = int(row['label'])
        commit_msg = str(row.get('message', 'Fix'))
        cve_desc = str(row.get('description', DEFAULT_CVE_DESC))
        
        # Console output
        print(f"[{idx+1}/{len(df)}] {commit_hash[:12]} (Label: {true_label}) ", end='', flush=True)
        
        # Log - New commit section
        logger.section(f"[{idx+1}/{len(df)}] Commit: {commit_hash[:12]}")
        logger.write(f"CVE: {cve_id}")
        logger.write(f"Repository: {repo_name}")
        logger.write(f"Commit: {commit_hash}")
        logger.write(f"True Label: {true_label} ({'Fix' if true_label == 1 else 'Candidate'})")
        logger.write(f"Commit Message: {commit_msg}")
        logger.write(f"CVE Description: {cve_desc}")
        
        try:
            # Record initial input
            logger.subsection("Agent Initial Input")
            
            # 获取初始diff（与Agent看到的一致）
            initial_diff = agent.code_tools.get_commit_diff(commit_hash, context_lines=8)
            if len(initial_diff) > 4000:
                initial_diff_preview = initial_diff[:4000] + "\n\n[... truncated ...]"
            else:
                initial_diff_preview = initial_diff
            
            logger.code_block("Initial Diff", initial_diff_preview)
            
            # Call Agent analysis
            logger.subsection("Agent Analysis - ReAct Process")
            
            result = agent.analyze_commit(
                cve_id=cve_id,
                cve_desc=cve_desc,
                commit_hash=commit_hash,
                commit_message=commit_msg,
                repo_name=repo_name
            )
            
            # Record reasoning process
            agent_steps = result.get('agent_steps', [])
            
            if agent_steps:
                logger.write("\nComplete Reasoning Process:\n")
                for i, (action, observation) in enumerate(agent_steps, 1):
                    tool_name = action.tool if hasattr(action, 'tool') else str(action)
                    tool_input = action.tool_input if hasattr(action, 'tool_input') else {}
                    
                    logger.write(f"Round {i}:")
                    logger.write(f"  Action: {tool_name}")
                    logger.write(f"  Input: {tool_input}")
                    logger.write(f"  Observation:")
                    
                    obs_preview = observation[:800] if len(observation) > 800 else observation
                    for line in obs_preview.split('\n'):
                        logger.write(f"     {line}")
                    if len(observation) > 800:
                        logger.write(f"     ... [+{len(observation)-800} chars]")
                    logger.write("")
            else:
                logger.write("\nAgent made decision in Round 1 (no tools needed)\n")
            
            # Final decision
            predicted = 1 if result['is_security_fix'] else 0
            is_correct = (predicted == true_label)
            
            logger.final_decision(
                decision="YES - Security Fix" if predicted == 1 else "NO - Not a Fix",
                confidence=result['confidence'],
                reasoning=result['reasoning']
            )
            
            # Validation
            logger.write(f"\n[{'CORRECT' if is_correct else 'WRONG'}] Predicted: {predicted}, True: {true_label}")
            logger.write(f"Tool Calls: {result['tool_calls']}")
            logger.write(f"Component Match: {result.get('component_match', 'N/A')}")
            logger.write(f"Vulnerability Match: {result.get('vulnerability_match', 'N/A')}")
            
            # Save result
            results.append({
                'commit': commit_hash,
                'true_label': true_label,
                'predicted': predicted,
                'correct': is_correct,
                'confidence': result['confidence'],
                'reasoning': result['reasoning'],
                'tool_calls': result['tool_calls'],
                'component_match': result.get('component_match', False),
                'vulnerability_match': result.get('vulnerability_match', False)
            })
            
            # Console output
            status = "[OK]" if is_correct else "[FAIL]"
            print(f"-> {status} {'YES' if predicted==1 else 'NO'} ({result['confidence']}%)")
            
            logger.flush()
            
        except KeyboardInterrupt:
            print("\n\n[INTERRUPTED] User stopped")
            break
        
        except Exception as e:
            print(f"-> [ERROR] {e}")
            logger.write(f"\n[ERROR] {e}\n")
            results.append({
                'commit': commit_hash,
                'true_label': true_label,
                'predicted': 0,
                'correct': False,
                'confidence': 0,
                'reasoning': f'Error: {e}',
                'tool_calls': 0,
                'component_match': False,
                'vulnerability_match': False
            })
            logger.flush()
    
    # Save results
    if results:
        df_results = pd.DataFrame(results)
        df_results.to_csv(OUTPUT_CSV, index=False, encoding='utf-8-sig')
        
        # Simple statistics
        total = len(df_results)
        correct = len(df_results[df_results['correct']])
        accuracy = correct / total * 100 if total > 0 else 0
        
        elapsed = time.time() - start_time
        
        print("\n" + "="*80)
        print("Completed")
        print("="*80)
        print(f"Total Commits: {total}")
        print(f"Correct: {correct}")
        print(f"Accuracy: {accuracy:.1f}%")
        print(f"Time: {elapsed/60:.1f} minutes")
        print(f"\nResults CSV: {OUTPUT_CSV}")
        print(f"Detailed Log: {LOG_FILE}")
        
        # Log summary
        logger.section("Test Summary")
        logger.write(f"Total Commits: {total}")
        logger.write(f"Correct: {correct} ({accuracy:.1f}%)")
        logger.write(f"Total Time: {elapsed/60:.1f} minutes")
        logger.write(f"Average Time: {elapsed/total:.1f} seconds/commit")
    
    logger.close()
    print(f"\nCheck detailed reasoning: {LOG_FILE}")


if __name__ == "__main__":
    main()
