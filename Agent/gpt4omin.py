import pandas as pd
import subprocess
import os
import csv
import concurrent.futures
from openai import OpenAI, APIConnectionError, RateLimitError, APIError
from tqdm import tqdm
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# ================= 配置区域 =================
API_KEY = "sk-4ieetjUybqH2tQW9BVoWFlifUEndHZtOBGbxyhDtixCijv9o"
# 修正：大多数中转 API 必须添加 /v1 后缀
BASE_URL = "https://chatapi.onechats.ai/v1"

# 路径配置
REPO_ROOT = r"E:\ptrhon project\project2\vcmatch_repro\gitrepo1"
INPUT_CSV = r"E:\ptrhon project\project2\vcmatch_repro\dataset\filtered_label1_reduced.csv"
CVE_DESC_CSV = r"E:\ptrhon project\project2\vcmatch_repro\dataset\cve_desc.csv"
OUTPUT_CSV = r"E:\ptrhon project\project2\vcmatch_repro\dataset\gpt4o_analysis_results.csv"

# 并发配置
MAX_WORKERS = 8

client = OpenAI(api_key=API_KEY, base_url=BASE_URL)


def get_repo_path(repo_name):
    name_map = {
        'ffmpeg': 'FFmpeg', 'linux': 'linux', 'openssl': 'openssl',
        'wireshark': 'wireshark', 'php-src': 'php-src', 'qemu': 'qemu',
        'moodle': 'moodle', 'jenkins': 'jenkins', 'imagemagick': 'ImageMagick',
        'phpmyadmin': 'phpMyAdmin'
    }
    key = str(repo_name).lower().strip()
    if 'imagemagick' in key:
        path1 = os.path.join(REPO_ROOT, 'ImageMagick')
        path2 = os.path.join(REPO_ROOT, 'ImageMagick6')
        return path1 if os.path.exists(path1) else path2
    mapped_name = name_map.get(key, repo_name)
    return os.path.join(REPO_ROOT, mapped_name)


def get_git_data(repo_path, commit):
    try:
        cmd = ["git", "show", "--stat", "--format=COMMIT:%H%nMSG:%s%nDESC:%b%nDIFF:", commit]
        res = subprocess.run(
            cmd, cwd=repo_path, capture_output=True,
            text=True, errors='replace', encoding='utf-8', timeout=30
        )
        output = res.stdout
        limit = 25000
        if len(output) > limit:
            output = output[:limit] + "\n\n...[Diff Truncated]"
        return output
    except Exception as e:
        return f"Git Error: {str(e)}"


# === 增强重试机制，增加调试打印 ===
@retry(
    retry=retry_if_exception_type((RateLimitError, APIConnectionError, APIError)),
    wait=wait_exponential(multiplier=1, min=2, max=20),
    stop=stop_after_attempt(3)  # 减少重试次数，快速暴露错误
)
def call_openai_with_retry(git_content, cve_desc):
    prompt = f"""You are a Security Auditor.
Task: Determine if the Git Commit describes the **SECURITY FIX** for the Target CVE.
[Target CVE] {cve_desc}
[Git Commit] {git_content}
[Instructions]
1. Analyze if file paths match the component in CVE.
2. Does the code fix the specific vulnerability?
3. Output "VERDICT: YES" or "VERDICT: NO" on the last line.
"""
    try:
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a security researcher."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1
        )

        # === 核心调试修复 ===
        # 你的报错是因为 res 是字符串。这里我们做检查。
        if isinstance(res, str):
            # 如果是字符串，说明 API 返回了错误文本而不是 JSON 对象
            raise ValueError(f"API Returned String Error: {res}")

        # 兼容字典模式（防止旧版本库或某些包装器返回 dict）
        if hasattr(res, 'choices'):
            return res.choices[0].message.content.strip()
        elif isinstance(res, dict) and 'choices' in res:
            return res['choices'][0]['message']['content'].strip()
        else:
            raise ValueError(f"Unknown Response Format: {type(res)}")

    except Exception as e:
        # 这里的 raise 会触发 tenacity 的重试
        raise e


def analyze_with_cot(git_content, cve_desc):
    try:
        content = call_openai_with_retry(git_content, cve_desc)
        lines = content.strip().split('\n')
        decision = "NO"
        check_range = lines[-10:] if len(lines) >= 10 else lines

        for line in reversed(check_range):
            clean = line.upper().strip()
            if "VERDICT: YES" in clean or "VERDICT:YES" in clean:
                decision = "YES";
                break
            elif "VERDICT: NO" in clean or "VERDICT:NO" in clean:
                decision = "NO";
                break

        return {"final_decision": decision, "reasoning": content}
    except Exception as e:
        # 捕获最终失败的异常，写入 CSV 方便查看
        return {"final_decision": "NO", "reasoning": f"API Fail: {str(e)}"}


def process_single_item(row, cve_desc_map):
    cve = str(row['cve']).strip().upper()
    repo = row['repo']
    commit = str(row['commit']).strip()

    if cve not in cve_desc_map: return None
    repo_path = get_repo_path(repo)
    if not os.path.exists(repo_path): return None

    git_content = get_git_data(repo_path, commit)
    if "Error" in git_content or not git_content.strip():
        return {
            "cve": cve, "repo": repo, "commit": commit, "commit_type": row.get('commit_type', ''),
            "ground_truth": row['label'], "ai_pred": -1, "is_correct": False,
            "reasoning": f"Git Error: {git_content[:100]}"
        }

    ai_result = analyze_with_cot(git_content, cve_desc_map[cve])
    ai_pred_int = 1 if ai_result.get("final_decision") == "YES" else 0

    return {
        "cve": cve, "repo": repo, "commit": commit, "commit_type": row.get('commit_type', ''),
        "ground_truth": row['label'], "ai_pred": ai_pred_int,
        "is_correct": (row['label'] == ai_pred_int),
        "reasoning": ai_result.get("reasoning")
    }


def load_cve_descriptions(path):
    for enc in ['utf-8-sig', 'gbk', 'latin1']:
        try:
            df = pd.read_csv(path, encoding=enc)
            df.columns = df.columns.str.strip().str.lower()
            cve_col = next((c for c in df.columns if 'cve' in c), None)
            desc_col = next((c for c in df.columns if 'desc' in c), None)

            cve_map = {}
            for _, row in df.iterrows():
                if pd.notna(row[cve_col]) and pd.notna(row[desc_col]):
                    cve_map[str(row[cve_col]).strip().upper()] = str(row[desc_col]).strip()
            return cve_map
        except:
            continue
    return {}


def main():
    print("=== 开始运行 (修复版) ===")

    # 1. 加载数据
    try:
        df_input = pd.read_csv(INPUT_CSV, encoding='utf-8-sig')
        df_valid = df_input[df_input['filter_status'].isna() | (
                    df_input['filter_status'] == '')] if 'filter_status' in df_input.columns else df_input
        print(f"待处理任务数: {len(df_valid)}")
    except Exception as e:
        print(f"输入文件错误: {e}");
        return

    cve_desc_map = load_cve_descriptions(CVE_DESC_CSV)
    if not cve_desc_map: print("CVE 描述加载失败"); return

    # 2. 检查断点
    processed_keys = set()
    file_exists = os.path.exists(OUTPUT_CSV)
    if file_exists:
        try:
            # 兼容读取可能存在的空行或错误
            try:
                df_done = pd.read_csv(OUTPUT_CSV, encoding='utf-8-sig', on_bad_lines='skip')
            except:
                df_done = pd.read_csv(OUTPUT_CSV, encoding='gbk', on_bad_lines='skip')
            for _, row in df_done.iterrows():
                processed_keys.add(f"{str(row['cve']).strip().upper()}_{str(row['commit']).strip()}")
            print(f"跳过已完成: {len(processed_keys)}")
        except:
            pass

    # 3. 筛选任务
    tasks = []
    for _, row in df_valid.iterrows():
        key = f"{str(row['cve']).strip().upper()}_{str(row['commit']).strip()}"
        if key not in processed_keys and str(row['cve']).strip().upper() in cve_desc_map:
            tasks.append(row)

    print(f"实际执行任务: {len(tasks)}")
    if not tasks: return

    # 4. 执行
    fieldnames = ["cve", "repo", "commit", "commit_type", "ground_truth", "ai_pred", "is_correct", "reasoning"]

    with open(OUTPUT_CSV, 'a' if file_exists else 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists or os.stat(OUTPUT_CSV).st_size == 0: writer.writeheader()

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_row = {executor.submit(process_single_item, row, cve_desc_map): row for row in tasks}

            for future in tqdm(concurrent.futures.as_completed(future_to_row), total=len(tasks), desc="API Requesting"):
                try:
                    res = future.result()
                    if res:
                        writer.writerow(res)
                        f.flush()
                except Exception as e:
                    print(f"Thread Error: {e}")


if __name__ == "__main__":
    main()
