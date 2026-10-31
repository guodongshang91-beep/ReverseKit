# -*- coding: utf-8 -*-
"""
阶段 2c：前端 JS bundle 逆向 —— 挖硬编码密钥与内部接口。

为什么值得做：现代前端把配置打进 bundle，常带云 AK/SK、内部域名、未上线 API、
数据库连接串。这类"硬编码凭据泄露"在补天属「信息泄露」，可定中危~高危
（若凭据可实际接管资源，按 §4 高危第 2 条"严重敏感信息泄露"）。

只读：仅下载目标自己的静态 JS，解析文本，不调用任何拿到的凭据去访问资源
（调用=使用凭据，超出最小影响原则；验证阶段如需证明危害再做，且只做只读列举）。
"""
import sys
if hasattr(sys.stdout, "reconfigure"):   # Windows 控制台默认 cp1252，中文输出会直接崩
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import re
import json
import sys
import time
import argparse
import concurrent.futures as cf
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings()
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
TIMEOUT = 10
MAX_JS = 3 * 1024 * 1024

# (名称, 正则, 建议等级, 说明)
RULES = [
    ("阿里云 AccessKey", r"\bLTAI[A-Za-z0-9]{12,24}\b", "高危", "阿里云 RAM 公钥 ID"),
    ("腾讯云 SecretId", r"\bAKID[A-Za-z0-9]{32,40}\b", "高危", "腾讯云 CAM 公钥"),
    ("AWS AccessKey", r"\bAKIA[0-9A-Z]{16}\b", "高危", "AWS IAM 公钥"),
    ("AWS SecretKey", r"(?i)aws.{0,20}secret.{0,10}['\"]([A-Za-z0-9/+=]{40})['\"]", "高危", "AWS 私钥"),
    ("华为云 AK", r"\b[A-Z]{4}[A-Za-z0-9]{20,}\b(?=.*huawei)", "info", "疑似华为云 AK（需人工确认）"),
    ("私钥 PEM", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "高危", "私钥硬编码"),
    ("JWT 硬编码", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "中危", "JWT 令牌硬编码"),
    ("数据库连接串", r"\bjdbc:[a-z0-9]+://[^\s\"'）)]{6,}", "高危", "含主机库名，可能含账号口令"),
    ("Redis 连接串", r"\bredis://[^\s\"']*:[^\s@\"']+@[^\s\"']+", "高危", "Redis 地址+口令"),
    ("MongoDB 连接串", r"\bmongodb(?:\+srv)?://[^\s\"']+", "高危", "Mongo 地址+可能的账号口令"),
    ("阿里云 OSS 端点", r"[a-z0-9-]+\.oss-[a-z0-9-]+\.aliyuncs\.com", "info", "对象存储端点（配合 oss_scan 用）"),
    ("腾讯云 COS 端点", r"[a-z0-9-]+\.cos\.[a-z0-9-]+\.myqcloud\.com", "info", "对象存储端点"),
    ("内网 IP", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", "低危", "内网地址泄露"),
    ("内网域名", r"\b[a-z0-9-]+\.(?:internal|intranet|corp|local|lan)\b", "低危", "内网域名泄露"),
    ("通用密钥赋值", r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?key|app[_-]?secret|client[_-]?secret|password|passwd|token)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{8,64})['\"]", "中危", "硬编码密钥/口令"),
    ("微信 AppSecret", r"(?i)appsecret\s*[:=]\s*['\"]([0-9a-f]{32})['\"]", "中危", "微信公众平台密钥"),
    ("支付宝私钥", r"(?i)(?:alipay|rsa)[^\n]{0,30}private[_-]?key['\"]?\s*[:=]", "中危", "支付宝商户私钥引用"),
    ("内部 API 路径", r"['\"]/(?:api|internal|admin|manage|ops|v1|v2|v3)/[A-Za-z0-9_\-/{}.]{3,60}['\"]", "info", "接口路径线索（阶段 2d 参数测试用）"),
    ("调试/测试开关", r"(?i)\b(?:debug|devMode|isTest|enableDebug|mock)\s*[:=]\s*['\"]?(?:true|1)['\"]?", "info", "调试开关开启线索"),
]

JS_RE = re.compile(r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""", re.I)
SRC_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+\.map)", re.I)


def fetch_js_list(host):
    """从首页抽取 JS 链接"""
    sess = requests.Session()
    for scheme in ("https", "http"):
        try:
            r = sess.get(f"{scheme}://{host}", timeout=TIMEOUT, verify=False, headers={"User-Agent": UA})
            if r.status_code == 200:
                urls = []
                for m in JS_RE.finditer(r.text[:400000]):
                    urls.append(urljoin(r.url, m.group(1)))
                for m in SRC_MAP_RE.finditer(r.text[:400000]):
                    urls.append(urljoin(r.url, m.group(1)))
                return host, sorted(set(urls))
        except Exception:
            continue
    return host, []


def fetch_text(url):
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False, headers={"User-Agent": UA},
                         stream=True)
        if r.status_code != 200:
            return None
        ct = r.headers.get("Content-Type", "")
        n = 0
        buf = b""
        for chunk in r.iter_content(65536):
            buf += chunk
            n += len(chunk)
            if n >= MAX_JS:
                break
        return buf.decode("utf-8", "ignore")
    except Exception:
        return None


def scan_host(host, max_js=8):
    _, urls = fetch_js_list(host)
    if not urls:
        return []
    hits = []
    urls = urls[:max_js]
    for u in urls:
        txt = fetch_text(u)
        if not txt:
            continue
        for name, pat, level, desc in RULES:
            for m in re.finditer(pat, txt):
                val = m.group(0)
                if len(val) > 300:
                    continue
                # 明显是占位符/示例的跳过
                if re.search(r"(?i)(your|example|placeholder|xxxx|\*{3,}|\.\.\.|demo|test123|foo|bar)", val):
                    continue
                hits.append({
                    "host": host, "js": u, "rule": name, "level": level,
                    "desc": desc, "match": val[:200],
                })
                break  # 同一规则在同一 JS 只记一次
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alive", default="../recon/alive.json")
    ap.add_argument("--out", default="../recon/js-hits.json")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-js", type=int, default=8)
    a = ap.parse_args()

    data = json.load(open(a.alive, encoding="utf-8"))
    meta = {d["host"]: (d.get("tier", ""), d.get("vendor", ""), d.get("root", "")) for d in data}
    hosts = [d["host"] for d in data]
    if a.limit:
        hosts = hosts[:a.limit]
    print(f"[*] JS 逆向 {len(hosts)} 主机（每站最多 {a.max_js} 个 JS）", file=sys.stderr)

    out = []
    t0 = time.time()
    done = 0
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(scan_host, h, a.max_js): h for h in hosts}
        for f in cf.as_completed(futs):
            h = futs[f]
            done += 1
            try:
                hits = f.result()
            except Exception:
                hits = []
            for x in hits:
                x["tier"], x["vendor"], x["root"] = meta.get(h, ("", "", ""))
                out.append(x)
            if done % 25 == 0:
                print(f"    {done}/{len(hosts)} hits={len(out)} ({time.time()-t0:.0f}s)", file=sys.stderr)

    json.dump(out, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[✓] JS 命中 {len(out)} 条 → {a.out}")
    from collections import Counter
    for k, v in Counter(x["rule"] for x in out).most_common():
        print(f"    {k}: {v}")


if __name__ == "__main__":
    main()
