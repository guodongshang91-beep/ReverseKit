#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rkhunt —— src-hunt 全链路编排器

七个阶段一条命令跑完，产物落在统一的 workdir 里，中断可续、每阶段计数可查。
底层还是那几个独立脚本，本文件只负责「按顺序、带正确参数、把产物接起来」。

    python rkhunt.py list                                   # 看阶段定义
    python rkhunt.py run --scope ../../examples/scope.csv   # 全跑
    python rkhunt.py run --scope scope.csv --dry-run        # 只打印命令
    python rkhunt.py run --scope scope.csv --only recon,probe
    python rkhunt.py run --workdir loot --skip oss,param
    python rkhunt.py status --workdir loot                  # 看跑过什么、出了多少条

产物布局（workdir 默认 ./loot）：

    loot/
    ├── run.json            # 每阶段：命令、耗时、退出码、条数
    ├── subs.json           # 1 recon
    ├── alive.json          # 2 probe（带 stack，全链路的依据）
    ├── unauth-hits.json    # 3 unauth
    ├── oss-hits.json       # 4 oss
    ├── js-hits.json        # 5 js
    ├── param-hits.json     # 6 param
    └── targeted-hits.json  # 7 targeted
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")          # 各阶段脚本所在目录（也是子进程的 cwd）
PY = sys.executable

# name, 说明, 需要的前置产物, 参数模板, 本条产物里的列表字段（用于计数）
STAGES = [
    ("recon", "子域枚举（crt.sh + 被动源 + 前缀爆破）", None,
     ["recon.py", "--csv", "{scope}", "--out", "{subs}"], None),
    ("probe", "存活 + 指纹（全链路依据，必须先跑）", "subs",
     ["probe.py", "--subs", "{subs}", "--out", "{alive}", "--workers", "{workers}"], None),
    ("unauth", "未授权 / 敏感路径（含五道防线）", "alive",
     ["unauth_scan.py", "--alive", "{alive}", "--out", "{unauth}", "--workers", "{workers2}"], None),
    ("oss", "对象存储公开桶", "subs",
     ["oss_scan.py", "--subs", "{subs}", "--out", "{oss}"], None),
    ("js", "前端 bundle 逆向（地址 / 接口 / 密钥 / mock 后门）", "alive",
     ["js_harvest.py", "--alive", "{alive}", "--out", "{js}"], None),
    ("param", "参数注入探测", "alive",
     ["param_probe.py", "--alive", "{alive}", "--out", "{param}", "--workers", "{workers2}"], None),
    ("targeted", "按指纹栈深度探测", "alive",
     ["targeted.py", "--targets", "{alive}", "--out", "{hit_targeted}"], None),
]

ORDER = [s[0] for s in STAGES]
STATE = "run.json"


def state_path(w):
    return os.path.join(w, STATE)


def load_state(w):
    p = state_path(w)
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_state(w, st):
    os.makedirs(w, exist_ok=True)
    json.dump(st, open(state_path(w), "w", encoding="utf-8"), ensure_ascii=False, indent=1)


def count_json(path):
    """数一条产物里有多少条记录。

    兼容三种形状：
      - list                       → 元素个数
      - {domain: {subs: [...]}}    → subs 总数（recon.py 的产物）
      - {k: [...]}                 → 最大的那个列表
    """
    try:
        d = json.load(open(path, encoding="utf-8"))
    except Exception:
        return None
    if isinstance(d, list):
        return len(d)
    if isinstance(d, dict):
        subs = sum(len(v["subs"]) for v in d.values()
                   if isinstance(v, dict) and isinstance(v.get("subs"), list))
        if subs:
            return subs
        if isinstance(d.get("subs"), list):
            return len(d["subs"])
        lists = [v for v in d.values() if isinstance(v, list)]
        if lists:
            return max(len(v) for v in lists)
        return len(d)
    return None


def paths(workdir):
    j = lambda n: os.path.join(workdir, n)
    return {"subs": j("subs.json"), "alive": j("alive.json"),
            "unauth": j("unauth-hits.json"), "oss": j("oss-hits.json"),
            "js": j("js-hits.json"), "param": j("param-hits.json"),
            "hit_targeted": j("targeted-hits.json")}


def build(stage, scope, workdir, workers, workers2):
    name, desc, needs, tmpl, _ = stage
    mapping = paths(workdir)
    mapping.update({"scope": scope, "w": workdir,
                    "workers": str(workers), "workers2": str(workers2)})
    return [t.format(**mapping) for t in tmpl]


def artifact_of(name):
    files = {"recon": "subs.json", "probe": "alive.json", "unauth": "unauth-hits.json",
             "oss": "oss-hits.json", "js": "js-hits.json", "param": "param-hits.json",
             "targeted": "targeted-hits.json"}
    return files.get(name)


# 依赖关键字 -> 需要的产物文件名
DEP_FILE = {"subs": "subs.json", "alive": "alive.json"}


def cmd_list(a):
    print("%-10s %-6s %s" % ("stage", "needs", "说明"))
    for name, desc, needs, _, _ in STAGES:
        print("%-10s %-6s %s" % (name, needs or "-", desc))
    print("\n依赖关系：recon → subs → probe → alive → {unauth, js, param, targeted}；oss 只依赖 subs")
    return 0


def cmd_run(a):
    workdir = os.path.normpath(os.path.abspath(a.workdir))
    os.makedirs(workdir, exist_ok=True)
    only = [s.strip() for s in a.only.split(",") if s.strip()] if a.only else ORDER
    skip = {s.strip() for s in a.skip.split(",") if s.strip()} if a.skip else set()

    bad = [s for s in only if s not in ORDER]
    if bad:
        raise SystemExit("未知阶段：%s（可选：%s）" % (", ".join(bad), ", ".join(ORDER)))

    # 前置检查
    if not os.path.exists(a.scope) and ("recon" in only):
        raise SystemExit("找不到 scope 文件：%s（示例见 examples/scope.csv）" % a.scope)

    st = load_state(workdir)
    todo = [s for s in STAGES if s[0] in only and s[0] not in skip]

    print("workdir : %s" % workdir)
    print("阶段    : %s" % ", ".join(s[0] for s in todo))
    print()

    failed = []
    for stage in todo:
        name, desc, needs, _, _ = stage
        need_file = DEP_FILE.get(needs) if needs else None
        if needs and not a.dry_run and not os.path.exists(os.path.join(workdir, need_file)):
            print("[skip] %-9s 缺少前置产物 %s（先把 %s 跑完）" % (name, need_file, needs))
            failed.append((name, "missing:" + need_file))
            if not a.keep_going:
                break
            continue

        argv = build(stage, os.path.abspath(a.scope), workdir, a.workers, a.workers2)
        printable = " ".join([os.path.basename(argv[0])] + argv[1:])
        print("[%s] %-9s %s" % ("dry" if a.dry_run else "run", name, desc))
        print("      %s" % printable)
        if a.dry_run:
            continue

        t0 = time.time()
        r = subprocess.run([PY] + argv, cwd=SRC)
        dt = time.time() - t0
        art = os.path.join(workdir, artifact_of(name))
        exists = os.path.exists(art)
        n = count_json(art) if exists else None
        st[name] = {"argv": argv, "exit": r.returncode, "seconds": round(dt, 1),
                    "artifact": os.path.basename(art) if exists else "-（未产出）",
                    "count": n, "at": time.strftime("%Y-%m-%d %H:%M:%S")}
        save_state(workdir, st)
        print("      -> exit=%d  %.1fs  %s%s" % (
            r.returncode, dt, os.path.basename(art) if exists else "(无产物)",
            "" if n is None else "  %d 条" % n))
        if r.returncode != 0:
            failed.append((name, "exit=%d" % r.returncode))
            if not a.keep_going:
                print("\n中止：%s 失败（--keep-going 可继续跑后面的）" % name)
                break
        print()

    if a.dry_run:
        print("dry-run 结束，什么都没执行。")
        return 0

    print("=" * 64)
    for name in ORDER:
        rec = st.get(name)
        if not rec:
            continue
        print("%-9s exit=%-3d %6.1fs  %-20s %s" % (
            name, rec["exit"], rec["seconds"], rec["artifact"],
            "" if rec["count"] is None else "%d 条" % rec["count"]))
    if failed:
        print("\n失败/跳过：%s" % ", ".join("%s(%s)" % (n, w) for n, w in failed))
        return 1
    print("\n下一步：把 unauth-hits / js-hits / param-hits / targeted-hits 里的候选逐条复现，")
    print("        用 tools/evidkit.py 建证据包（docs/05-playbooks.md 有判定五问）。")
    return 0


def cmd_status(a):
    w = os.path.abspath(a.workdir)
    st = load_state(w)
    if not st:
        print("%s 里没有 run.json，还没跑过。" % w)
        return 1
    print("workdir: %s\n" % w)
    print("%-9s %-6s %-8s %-8s %-20s %s" % ("stage", "exit", "耗时", "条数", "产物", "时间"))
    for name, rec in st.items():
        print("%-9s %-6d %-8.1f %-8s %-20s %s" % (
            name, rec["exit"], rec["seconds"],
            "-" if rec["count"] is None else rec["count"],
            rec["artifact"], rec["at"]))
    return 0


def main():
    ap = argparse.ArgumentParser(description="src-hunt 全链路编排器")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="列出阶段与依赖")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("run", help="按顺序跑阶段")
    p.add_argument("--scope", default=os.path.join(HERE, "..", "..", "examples", "scope.csv"),
                   help="目标清单 CSV（domain,tier,owner）")
    p.add_argument("--workdir", default="loot")
    p.add_argument("--only", default="", help="只跑这些阶段，逗号分隔")
    p.add_argument("--skip", default="", help="跳过这些阶段")
    p.add_argument("--workers", type=int, default=24)
    p.add_argument("--workers2", type=int, default=8, help="未授权/参数探测的并发（别开太大）")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--keep-going", action="store_true", help="某阶段失败也继续")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("status", help="看已跑阶段与产物计数")
    p.add_argument("--workdir", default="loot")
    p.set_defaults(fn=cmd_status)

    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
