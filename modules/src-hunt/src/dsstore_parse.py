# -*- coding: utf-8 -*-
"""
.DS_Store 泄露解析 —— 把泄露的目录/文件名还原成可读清单。

.DS_Store 是 macOS Finder 在目录里生成的隐藏文件，被一起发布到 Web 根目录时，
任何匿名访问者都能还原该目录的完整文件名清单 —— 常暴露后台路径、备份包、
临时脚本、未上线页面。补天归类「信息泄露」；若清单里含备份包/后台/数据库导出，
危害上抬（可进一步验证是否可下载）。

只读：只下载 .DS_Store 本身并本地解析；后续是否请求清单里的文件由下一步决定。
"""
import sys
if hasattr(sys.stdout, "reconfigure"):   # Windows 控制台默认 cp1252，中文输出会直接崩
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import re
import sys
import json
import argparse

import requests
import urllib3
try:
    import ds_store
except ImportError:
    raise SystemExit("需要 ds-store：pip install ds-store")

urllib3.disable_warnings()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"
# 泄露文件名里值得追的敏感词
SENSITIVE = [
    (r"(?i)\.(sql|bak|backup|zip|rar|7z|tar|gz|tgz)$", "备份/归档文件"),
    (r"(?i)(admin|manage|manager|backend|houtai|console|system)", "后台入口"),
    (r"(?i)(test|demo|tmp|temp|old|new|dev|debug|v1|v2)", "测试/旧版入口"),
    (r"(?i)(\.git|\.svn|\.env|config|conf|properties|yml|yaml|xml)$", "配置类文件"),
    (r"(?i)(log|logs|error|trace)", "日志文件"),
    (r"(?i)(user|member|customer|order|pay|finance|salary|hr|employee)", "业务敏感模块"),
    (r"(?i)(upload|uploads|attachment|files|download)", "上传/下载目录"),
    (r"(?i)(key|secret|token|pwd|password|credential)", "凭据相关"),
    (r"(?i)(db|database|data|mysql|redis|mongo)", "数据相关"),
    (r"(?i)\.(xls|xlsx|csv|doc|docx|pdf)$", "文档表格导出"),
]


def fetch(host, path="/.DS_Store", max_bytes=8 * 1024 * 1024):
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}{path}", timeout=25, verify=False,
                             headers={"User-Agent": UA}, stream=True)
            if r.status_code != 200:
                continue
            buf = b""
            for c in r.iter_content(65536):
                buf += c
                if len(buf) >= max_bytes:
                    break
            return r.url, buf
        except Exception:
            continue
    return None, None


def parse(buf):
    names = []
    try:
        with ds_store.DSStore.open(buf, b"rb" if False else None) as d:
            pass
    except Exception:
        pass
    # ds_store 库需要文件路径，落盘再用
    return names


def parse_file(path):
    names = []
    try:
        with ds_store.DSStore.open(path, "r") as d:
            for f in d:
                try:
                    names.append(str(f.filename))
                except Exception:
                    pass
    except Exception as e:
        print(f"[!] 解析失败 {path}: {type(e).__name__}: {e}", file=sys.stderr)
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True, help="逗号分隔主机名")
    ap.add_argument("--out", default="../recon/dsstore.json")
    a = ap.parse_args()

    result = {}
    for host in [h.strip() for h in a.hosts.split(",") if h.strip()]:
        url, buf = fetch(host)
        if not buf:
            print(f"[x] {host} 未取到 .DS_Store")
            continue
        tmp = f"../recon/_ds_{host.replace('.', '_')}.bin"
        open(tmp, "wb").write(buf)
        names = parse_file(tmp)
        result[host] = {"url": url, "size": len(buf), "count": len(names), "names": names}
        print(f"\n=== {host}  {url}  {len(buf)} 字节，解析出 {len(names)} 个条目")

        hits = {}
        for n in names:
            for pat, label in SENSITIVE:
                if re.search(pat, n):
                    hits.setdefault(label, []).append(n)
                    break
        for label, items in sorted(hits.items(), key=lambda x: -len(x[1])):
            print(f"  [{label}] {len(items)} 个，例：{items[:6]}")
        print(f"  全部条目示例：{names[:25]}")

    json.dump(result, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"\n[✓] → {a.out}")


if __name__ == "__main__":
    main()
