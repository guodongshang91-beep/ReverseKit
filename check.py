#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check.py —— 本地自检（等价于 CI，不依赖 GitHub Actions）

    python check.py            # 全部检查
    python check.py --quick    # 只做编译 + 域名守卫

四道检查：
  1. 编译   python -m compileall 全量字节编译（阻断）
  2. 冒烟   每个命令行工具 -h 能正常退出（阻断）
  3. 守卫   仓库里不得出现真实厂商域名 / 内网地址 / 凭据（阻断）
  4. 静态   pyflakes（装了才跑，只提示不阻断）

退出码：0 全过，1 有阻断项失败。
"""
import argparse
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

# 必须有 -h 且退出 0 的入口
CLI = [
    "modules/src-hunt/rkhunt.py",
    "tools/evidkit.py",
    "modules/binary-re/tools/elfkit.py",
    "modules/pe-patch/tools/peck.py",
    "modules/android/tools/aar_extract.py",
    "modules/src-hunt/src/recon.py",
    "modules/src-hunt/src/probe.py",
    "modules/src-hunt/src/unauth_scan.py",
    "modules/src-hunt/src/oss_scan.py",
    "modules/src-hunt/src/js_harvest.py",
    "modules/src-hunt/src/param_probe.py",
    "modules/src-hunt/src/targeted.py",
]

# 守卫：这些出现在仓库里说明脱敏没做干净
VENDOR = re.compile(
    r"\b[a-z0-9][a-z0-9-]*\.(?:163|126|netease|jd|baidu|bytedance|toutiao|douyin|"
    r"kuaishou|meituan|sina|weibo|pinduoduo|ctrip|qunar|didiglobal|360|so|qihoo|"
    r"xiaomi|mi|huawei|alipay|taobao|tmall|youku|iqiyi|bilibili|zhihu|91)\.(?:com|cn|net)\b",
    re.I,
)
PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
SECRET = re.compile(r"\b(?:LTAI[0-9A-Za-z]{12,}|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{30,})\b")
SKIP_EXT = {".svg", ".png", ".jpg", ".ico", ".zip", ".pcap"}
SKIP_DIR = {".git", "__pycache__", "out", "recon", "evidence"}

ok = True


def sh(args, cwd=ROOT):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def step_compile():
    print("[1/4] compileall ...")
    r = sh([PY, "-m", "compileall", "-q", "modules"])
    if r.returncode != 0:
        print((r.stdout + r.stderr)[-1500:])
        return False
    print("      ok")
    return True


def step_cli():
    print("[2/4] CLI 冒烟 ...")
    bad = []
    for rel in CLI:
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            bad.append((rel, "missing"))
            continue
        r = sh([PY, p, "-h"])
        if r.returncode != 0:
            bad.append((rel, (r.stderr or r.stdout).strip().splitlines()[-1:][0] if (r.stderr or r.stdout).strip() else "exit %d" % r.returncode))
        else:
            print("      ok  %s" % rel)
    for rel, why in bad:
        print("      FAIL %s -> %s" % (rel, why))
    return not bad


def step_guard():
    print("[3/4] 真实资产 / 凭据守卫 ...")
    hits = []
    for dirpath, dirnames, files in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR]
        for f in files:
            if os.path.splitext(f)[1].lower() in SKIP_EXT:
                continue
            p = os.path.join(dirpath, f)
            try:
                text = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            rel = os.path.relpath(p, ROOT)
            for name, rx in (("vendor-domain", VENDOR), ("private-ip", PRIVATE_IP), ("secret", SECRET)):
                for m in rx.finditer(text):
                    line = text[:m.start()].count("\n") + 1
                    hits.append("%s:%d  %s  (%s)" % (rel, line, m.group(0), name))
    if hits:
        print("      发现 %d 处，需要脱敏：" % len(hits))
        for h in hits[:40]:
            print("      - " + h)
        return False
    print("      ok")
    return True


def step_pyflakes():
    print("[4/4] pyflakes（可选）...")
    if not shutil.which("pyflakes") and sh([PY, "-c", "import pyflakes"]).returncode != 0:
        print("      跳过（pip install pyflakes 后生效）")
        return True
    r = sh([PY, "-m", "pyflakes", "modules"])
    out = (r.stdout + r.stderr).strip()
    if out:
        print("      提示（不阻断）：")
        for line in out.splitlines()[:40]:
            print("      " + line)
    else:
        print("      ok")
    return True


def main():
    ap = argparse.ArgumentParser(description="ReverseKit 本地自检")
    ap.add_argument("--quick", action="store_true", help="只跑编译 + 守卫")
    a = ap.parse_args()

    global ok
    ok &= step_compile()
    if not a.quick:
        ok &= step_cli()
    ok &= step_guard()
    if not a.quick:
        step_pyflakes()

    print()
    print("结果：" + ("全部通过" if ok else "有阻断项失败，见上面 FAIL / 发现 行"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
