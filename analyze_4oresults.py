import pandas as pd

# 你的结果文件路径
RESULT_CSV = r"E:\ptrhon project\project2\vcmatch_repro\dataset\gpt4o_analysis_results.csv"


def get_simple_stats():
    # 读取数据并排除报错跳过的数据 (ai_pred != -1)
    df = pd.read_csv(RESULT_CSV, encoding='utf-8-sig', on_bad_lines='skip')
    df = df[df['ai_pred'] != -1]

    total = len(df)
    wrong_count = len(df[df['is_correct'] == False])
    success_rate = ((total - wrong_count) / total) * 100 if total > 0 else 0

    total_cves = df['cve'].nunique()
    wrong_cves = df[df['is_correct'] == False]['cve'].nunique()

    print(f"有效测试总条数: {total}")
    print(f"1. 判断成功率: {success_rate:.2f}%")
    print(f"2. 误判的总数量: {wrong_count} 条")
    print(f"3. 涉及判断错误的CVE: {wrong_cves} 个 (总共 {total_cves} 个CVE)")


if __name__ == "__main__":
    get_simple_stats()
