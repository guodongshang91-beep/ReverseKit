# -*- coding: utf-8 -*-
"""
阶段 2b：云存储桶（OSS/COS/S3/Qiniu）公开可读 / 可列举 检测。

原理：子域 CNAME 常指向对象存储域名（*.oss-cn-*.aliyuncs.com、*.cos.*.myqcloud.com、
*.s3.amazonaws.com、*.qiniudn.com …）。桶名若开了「公共读 + 允许列举」，
GET /?max-keys=N 会返回 ListBucketResult XML —— 这是可直接提交的
「敏感信息泄露 / 未授权访问」（补天中危第 6 条：比较严重的信息泄露）。

只读：仅列举对象 key 名，最多取 20 条，绝不下载对象内容。
"""
import json
import re
import sys
import argparse
import concurrent.futures as cf

import requests
try:
    import dns.resolver
except ImportError:          # 没装 dnspython 时跳过 CNAME 归属判定，其余功能照常
    dns = None
import urllib3

urllib3.disable_warnings()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"
TIMEOUT = 10

# (云厂商, CNAME 正则, 桶访问 URL 构造器)
PROVIDERS = [
    ("阿里云OSS", r"([^.]+)\.oss(?:-cn-|-|\.)([a-z0-9-]+)\.aliyuncs\.com",
     lambda b, r: f"https://{b}.oss-{r}.aliyuncs.com/?max-keys=20"),
    ("阿里云OSS(内网式)", r"([^.]+)\.oss\.aliyuncs\.com",
     lambda b, r: f"https://{b}.oss.aliyuncs.com/?max-keys=20"),
    ("腾讯云COS", r"([^.]+)\.cos\.([a-z0-9-]+)\.myqcloud\.com",
     lambda b, r: f"https://{b}.cos.{r}.myqcloud.com/?max-keys=20&prefix="),
    ("AWS S3", r"([^.]+)\.s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com",
     lambda b, r: f"https://{b}.s3.{r or 'us-east-1'}.amazonaws.com/?max-keys=20"),
    ("七牛云", r"([^.]+)\.(?:qiniudn|qbox\.me|clouddn)\.com",
     lambda b, r: f"https://{b}.qiniudn.com/?max-keys=20"),
    ("华为云OBS", r"([^.]+)\.obs\.([a-z0-9-]+)\.mycloud\.com",
     lambda b, r: f"https://{b}.obs.{r}.mycloud.com/?max-keys=20"),
    ("UCloud", r"([^.]+)\.ufile\.cn-([a-z0-9-]+)\.ufileos\.com",
     lambda b, r: f"https://{b}.ufile.cn-{r}.ufileos.com/?max-keys=20"),
]


def cname_of(host):
    try:
        res = dns.resolver.Resolver()
        res.lifetime = 5
        res.timeout = 4
        for rdtype in ("CNAME",):
            try:
                ans = res.resolve(host, rdtype)
                return str(ans[0].target).rstrip(".").lower()
            except Exception:
                continue
    except Exception:
        pass
    return None


def bucket_from_host(host):
    """从子域名本身猜测桶名（很多站点直接把 bucket 当子域）"""
    cn = cname_of(host)
    if not cn:
        return None, None, None
    for name, pat, builder in PROVIDERS:
        m = re.search(pat, cn, re.I)
        if m:
            return name, builder(m.group(1), m.group(2) if m.lastindex >= 2 else ""), cn
    return None, None, cn


def test_bucket(url):
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False, headers={"User-Agent": UA})
    except Exception:
        return None
    if r.status_code != 200:
        return None
    body = r.text[:8000]
    if "ListBucketResult" not in body:
        return None
    keys = re.findall(r"<Key>(.*?)</Key>", body, re.S)[:20]
    return {"url": url, "count": len(keys), "keys": keys,
            "snippet": body[:300].replace("\n", " ")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subs", default="../recon/subs.json")
    ap.add_argument("--out", default="../recon/oss-hits.json")
    ap.add_argument("--workers", type=int, default=30)
    a = ap.parse_args()
    data = json.load(open(a.subs, encoding="utf-8"))
    hosts = sorted({s for v in data.values() for s in v["subs"]})
    print(f"[*] 解析 {len(hosts)} 主机 CNAME ...", file=sys.stderr)

    cands = []
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for host, (name, url, cn) in zip(hosts, ex.map(bucket_from_host, hosts)):
            if name and url:
                cands.append((host, name, url, cn))
    print(f"[*] 发现 {len(cands)} 个疑似对象存储桶", file=sys.stderr)

    out = []
    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        for (host, name, url, cn), res in zip(cands, ex.map(test_bucket, [c[2] for c in cands])):
            if res:
                res.update({"host": host, "provider": name, "cname": cn})
                out.append(res)
    json.dump(out, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[✓] 可公开列举的桶 {len(out)} 个 → {a.out}")
    for x in out[:20]:
        print(f"    [{x['provider']}] {x['host']} -> {x['url']} ({x['count']} keys)")
        for k in x["keys"][:5]:
            print(f"        - {k[:100]}")


if __name__ == "__main__":
    main()
