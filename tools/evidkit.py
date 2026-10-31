#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evidkit —— 证据包与报告生成

「目录里没有这些，就不算发现。」这个工具负责把这句话变成可执行的操作：
每个发现一个目录，原始报文按序编号、清单带哈希、报告从数据生成而不是手写。

    python tools/evidkit.py new    --id VULN-001 --host api.example.com \
                                   --path /actuator/env --level 中危 --type 未授权访问
    python tools/evidkit.py add    --id VULN-001 --request req.txt --response resp.txt
    python tools/evidkit.py seal   --id VULN-001
    python tools/evidkit.py verify --id VULN-001
    python tools/evidkit.py report --id VULN-001 --out report.md

产物结构：

    evidence/VULN-001/
    ├── meta.json           # 元信息 + 每次抓包的 sha256/长度/时间
    ├── verify-notes.md     # 复现步骤、影响、假阳性排除记录（人工填）
    ├── request-01.txt      # 原始请求
    ├── response-01.txt     # 原始响应
    ├── request-02.txt      # 第二次独立会话
    ├── response-02.txt
    ├── hash.txt            # sha256 清单（seal 生成）
    └── report.md           # 由 meta.json + notes 渲染（report 生成）

时间戳统一取系统本地时间，不手写——手写的日期是报告里最容易出错的部分。
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time

ROOT = "evidence"

NOTES_TEMPLATE = """# {id} 验证记录

## 基本信息

| 项 | 值 |
| --- | --- |
| 目标 | `{host}` |
| 路径 | `{path}` |
| 类型 | {vtype} |
| 初判等级 | {level} |
| 发现时间 | {ts} |

## 复现步骤

1. （填：第一个请求怎么发的，带哪些 header）
2. （填：响应是什么，关键字段在哪）
3. （填：与随机路径基线对比结果）
4. （填：换会话/换出口再测一次的结果）

## 影响

（填：能读到什么、能做什么、影响范围。敏感数据必须脱敏后再写。）

## 假阳性排除记录（五问，逐条回答）

| # | 检查项 | 结论 | 依据 |
| --- | --- | --- | --- |
| 1 | catch-all 基线 | 待填 | 比 `/__rk-probe-xxxx` 的 status/md5/长度 |
| 2 | 响应去重 | 待填 | 同 md5 在这台主机出现过几次 |
| 3 | WAF 拦截页 | 待填 | 正文前 4KB 有没有 `waf_block` / `访问被拒绝` |
| 4 | 404 路径回显 | 待填 | 正文里是否出现请求路径末段 |
| 5 | 换会话复现 | 待填 | 第二次抓包的 md5 是否一致 |

## 修复建议

1. （填）

## 备注

- 证据清单见 `hash.txt`，用 `python tools/evidkit.py verify --id {id}` 复核。
"""


def hx_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def evdir(a, eid=None):
    eid = eid or a.id
    return os.path.join(a.dir if hasattr(a, "dir") else ROOT, eid)


def load_meta(d):
    p = os.path.join(d, "meta.json")
    if not os.path.exists(p):
        raise SystemExit("不是证据目录（缺 meta.json）：%s\n先运行 new 子命令" % d)
    return json.load(open(p, encoding="utf-8"))


def save_meta(d, m):
    json.dump(m, open(os.path.join(d, "meta.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)


def cmd_new(a):
    d = evdir(a)
    if os.path.exists(d) and not a.force:
        raise SystemExit("%s 已存在（--force 覆盖元信息，不会删已有报文）" % d)
    os.makedirs(d, exist_ok=True)
    ts = time.strftime("%Y-%m-%d %H:%M:%S %z")
    meta = {"id": a.id, "host": a.host, "path": a.path, "type": a.vtype,
            "level": a.level, "created": ts, "status": "待验证", "captures": []}
    save_meta(d, meta)
    notes = os.path.join(d, "verify-notes.md")
    if not os.path.exists(notes) or a.force:
        open(notes, "w", encoding="utf-8").write(NOTES_TEMPLATE.format(
            id=meta["id"], host=meta["host"], path=meta["path"],
            vtype=meta["type"], level=meta["level"], ts=ts))
    print("created  %s" % d)
    print("         meta.json / verify-notes.md")
    print("下一步：  evidkit add --id %s --request ... --response ..." % a.id)
    return 0


def _next_index(d):
    n = 1
    while os.path.exists(os.path.join(d, "request-%02d.txt" % n)):
        n += 1
    return n


def cmd_add(a):
    d = evdir(a)
    meta = load_meta(d)
    idx = _next_index(d)
    rec = {"index": idx, "at": time.strftime("%Y-%m-%d %H:%M:%S %z"), "note": a.note}
    for kind, src in (("request", a.request), ("response", a.response)):
        if not src:
            continue
        if not os.path.exists(src):
            raise SystemExit("文件不存在：%s" % src)
        dst = os.path.join(d, "%s-%02d.txt" % (kind, idx))
        shutil.copyfile(src, dst)
        rec[kind] = {"file": os.path.basename(dst), "bytes": os.path.getsize(dst),
                     "sha256": hx_sha(dst)}
    if "request" not in rec and "response" not in rec:
        raise SystemExit("至少给一个 --request 或 --response")
    meta["captures"].append(rec)
    save_meta(d, meta)
    print("added    #%02d  %s" % (idx, ", ".join(
        "%s=%s" % (k, rec[k]["bytes"]) for k in ("request", "response") if k in rec)))
    return 0


def cmd_seal(a):
    d = evdir(a)
    meta = load_meta(d)
    # 先把 sealed 时间写进 meta.json，再算哈希——否则 meta.json 自己每次都会对不上
    meta["sealed"] = time.strftime("%Y-%m-%d %H:%M:%S %z")
    save_meta(d, meta)
    files = sorted(f for f in os.listdir(d) if f != "hash.txt" and os.path.isfile(os.path.join(d, f)))
    lines = []
    for f in files:
        p = os.path.join(d, f)
        lines.append("%s  %8d  %s" % (hx_sha(p), os.path.getsize(p), f))
    open(os.path.join(d, "hash.txt"), "w", encoding="utf-8").write(
        "# sha256  size  file\n" + "\n".join(lines) + "\n")
    print("sealed   %d 个文件 -> hash.txt" % len(files))
    for line in lines:
        print("         " + line.split("  ", 1)[-1])
    if len(meta.get("captures", [])) < 2:
        print("\n⚠ 只有 %d 次抓包。至少两次独立会话才算验证过（playbook 五问第 5 条）。"
              % len(meta.get("captures", [])))
    return 0


def cmd_verify(a):
    d = evdir(a)
    p = os.path.join(d, "hash.txt")
    if not os.path.exists(p):
        raise SystemExit("没有 hash.txt，先运行 seal")
    bad, ok = [], 0
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("  ")
        want, fname = parts[0], parts[-1].strip()
        fp = os.path.join(d, fname)
        if not os.path.exists(fp):
            bad.append("%s  缺失" % fname)
            continue
        got = hx_sha(fp)
        if got != want:
            bad.append("%s  哈希不符\n     期望 %s\n     实际 %s" % (fname, want, got))
        else:
            ok += 1
    print("verify   %d 个文件一致" % ok)
    if bad:
        print("         %d 个有问题：" % len(bad))
        for b in bad:
            print("         - " + b)
        return 1
    print("         OK")
    return 0


def _read(path, limit=4000):
    if not os.path.exists(path):
        return "（缺）"
    with open(path, encoding="utf-8", errors="replace") as f:
        s = f.read(limit + 1)
    if len(s) > limit:
        s = s[:limit] + "\n... （截断，原文见文件，总长度 %d 字节）" % os.path.getsize(path)
    return s


def cmd_report(a):
    d = evdir(a)
    meta = load_meta(d)
    caps = meta.get("captures", [])
    out = ["""# {id} — {vtype}

| 项 | 值 |
| --- | --- |
| 目标 | `{host}` |
| 路径 | `{path}` |
| 类型 | {vtype} |
| 等级 | {level} |
| 状态 | {status} |
| 首次发现 | {created} |
| 抓包次数 | {n} |
| 清单封存 | {sealed} |
""".format(n=len(caps), sealed=meta.get("sealed", "未封存"),
           id=meta["id"], vtype=meta["type"], host=meta["host"], path=meta["path"],
           level=meta["level"], status=meta.get("status", "-"),
           created=meta.get("created", "-"))]

    if caps:
        out.append("\n## 证据\n")
        out.append("| # | 时间 | 请求 | 响应 | sha256（响应） |")
        out.append("| --- | --- | --- | --- | --- |")
        for c in caps:
            req = c.get("request", {})
            resp = c.get("response", {})
            out.append("| %d | %s | %s (%s B) | %s (%s B) | `%s` |" % (
                c["index"], c.get("at", ""),
                req.get("file", "-"), req.get("bytes", "-"),
                resp.get("file", "-"), resp.get("bytes", "-"),
                (resp.get("sha256") or "-")[:16]))
        last = caps[-1]
        if "request" in last:
            out.append("\n### 原始请求（第 %d 次）\n\n```http\n%s\n```"
                       % (last["index"], _read(os.path.join(d, last["request"]["file"]), 2000)))
        if "response" in last:
            out.append("\n### 原始响应（第 %d 次，前 4KB）\n\n```http\n%s\n```"
                       % (last["index"], _read(os.path.join(d, last["response"]["file"]))))

    notes = os.path.join(d, "verify-notes.md")
    if os.path.exists(notes):
        body = open(notes, encoding="utf-8").read()
        # 去掉自己的标题，避免报告里出现两级同名标题
        body = re.sub(r"^#\s+.*?\n", "", body, count=1)
        out.append("\n## 验证记录\n" + body)

    text = "\n".join(out)
    dst = a.out or os.path.join(d, "report.md")
    open(dst, "w", encoding="utf-8").write(text)
    print("report   %s  (%d 字符, %d 次抓包)" % (dst, len(text), len(caps)))
    if len(caps) < 2:
        print("         ⚠ 抓包不足两次，报告里应标注「未完成独立复现」")
    return 0


def main():
    ap = argparse.ArgumentParser(description="证据包与报告生成")
    ap.add_argument("--dir", default=ROOT, help="证据根目录（默认 evidence）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("new"); p.add_argument("--id", required=True)
    p.add_argument("--host", required=True); p.add_argument("--path", default="/")
    p.add_argument("--type", dest="vtype", default="未授权访问")
    p.add_argument("--level", default="中危"); p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_new)

    p = sub.add_parser("add"); p.add_argument("--id", required=True)
    p.add_argument("--request", default=""); p.add_argument("--response", default="")
    p.add_argument("--note", default=""); p.set_defaults(fn=cmd_add)

    p = sub.add_parser("seal"); p.add_argument("--id", required=True); p.set_defaults(fn=cmd_seal)

    p = sub.add_parser("verify"); p.add_argument("--id", required=True); p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("report"); p.add_argument("--id", required=True)
    p.add_argument("--out", default=""); p.set_defaults(fn=cmd_report)

    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
