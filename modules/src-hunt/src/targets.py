# -*- coding: utf-8 -*-
"""
目标清单（模板）。

本文件只放**示例占位**，真实目标由使用者自己填 —— 开源仓库里不应沉淀任何
具体厂商的资产清单，那既过时又容易把别人拖进未授权测试。

分档思路（跟主流 SRC 的奖励梯度对齐，方便排优先级）：

  T1 = 互联网大厂 / 高权重站点   → 中高危单价最高，防护成熟，通用路径爆破基本无效
  T2 = 中大型厂商 / 垂直行业      → 单价次之，系统类子域多，未授权类问题更容易出
  T3 = 中小企业 / 官网门户        → 单价低，但防护弱，适合练手和跑通链路

补天规则里明确排除的两类，别浪费时间：
  - gov / edu（有单独权重与提交要求）
  - 裸 IP 资产（"IP 漏洞暂不收取"），必须先跟自有域名绑定

用法：
    python targets.py                      # 打印本文件的示例清单
    python targets.py --csv my_scope.csv   # 从 CSV 读：domain,tier,owner
"""
import csv
import sys

# ---- 换成你自己的授权目标 ----
TARGETS = [
    # ---------- T1 ----------
    ("example-corp.com",      "T1", "示例大厂"),
    ("example-cdn.net",       "T1", "示例大厂-备用域"),
    # ---------- T2 ----------
    ("example-group.com.cn",  "T2", "示例集团"),
    ("example-telecom.cn",    "T2", "示例运营商"),
    # ---------- T3 ----------
    ("example-sme.com",       "T3", "示例中小企业"),
]


def load_csv(path):
    """CSV 三列：domain,tier,owner；缺省 tier=T3。"""
    out = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.reader(f):
            row = [c.strip() for c in row]
            if not row or row[0].startswith("#") or not row[0]:
                continue
            if row[0].lower() == "domain":          # 跳过表头
                continue
            out.append((row[0], (row[1] if len(row) > 1 and row[1] else "T3"),
                        row[2] if len(row) > 2 else ""))
    return out


def main():
    argv = sys.argv[1:]
    if "--csv" in argv:
        targets = load_csv(argv[argv.index("--csv") + 1])
    else:
        targets = TARGETS
    by_tier = {}
    for d, t, o in targets:
        by_tier.setdefault(t, []).append((d, o))
    for tier in sorted(by_tier):
        print(f"[{tier}] {len(by_tier[tier])} 个")
        for d, o in by_tier[tier]:
            print(f"  {d:<32} {o}")
    print(f"\n合计 {len(targets)} 个主域")


if __name__ == "__main__":
    main()
