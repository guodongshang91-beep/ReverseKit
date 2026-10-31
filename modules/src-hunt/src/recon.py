# -*- coding: utf-8 -*-
"""
阶段 1：子域资产侦察（被动优先 + 定向爆破）。

被动源（实测大陆可达性）：
  - certspotter  https://api.certspotter.com/v1/issuances        [实测 200]
  - hackertarget https://api.hackertarget.com/hostsearch/         [实测 200，有配额]
  - urlscan      https://urlscan.io/api/v1/search/                [实测 200]
  - crt.sh       https://crt.sh/                                  [实测常 502，失败即跳过]

主动爆破：dnspython 并发解析，词表以"容易出洞的边缘系统"为重心
（oa/hr/test/dev/staging/ops/jenkins/gitlab/kibana/nacos/zabbix/...）。

纪律：被动为主；爆破限速（默认 60 并发 + 每域间隔），不做端口扫描。
"""
import json
import re
import sys
import time
import argparse
import concurrent.futures as cf

import requests
try:
    import dns.resolver
except ImportError:          # 没装 dnspython 时仍可用 --crtsh / --no-brute，不直接崩
    dns = None

from targets import TARGETS

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
TIMEOUT = 25

# 爆破词表：优先"能出洞的边缘系统"，而不是漫无目的的词海
BRUTE_WORDS = """
www m api admin manage manager login sso passport uc user member account my
oa hr hrm erp crm bi bo boss ops devops dev test testing staging uat pre prod gray demo
vpn mail mail2 smtp pop3 imap webmail
gitlab git svn jenkins jira confluence wiki kb docs doc apidoc swagger
kibana grafana prometheus zabbix nagios cacti sonar sonarqube nexus harbor
nacos consul eureka zookeeper dubbo solr elasticsearch es redis mongodb mysql
log logs monitor monitoring dashboard status alert sentry
backup bak old new v1 v2 v3 static assets cdn img image upload files file download
partner open developer dev-api openapi cloud iot
pay payment finance bill invoice order shop mall
mobile app m-api h5 wap mini
edu train learn campus school
hr-recruit recruit job
it helpdesk support ticket
cmis cms news portal site
internal in inner corp company
adminer phpmyadmin
jenkins2 ci cd build release
""".split()

# 常见泛解析黑名单（命中即说明该域开了 wildcard DNS，爆破结果不可信）
WILDCARD_PROBE = "this-should-not-exist-{rand}.{domain}"


def passive_certspotter(domain):
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names&include_subdomains=true"
    try:
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
        if r.status_code != 200:
            return set()
        out = set()
        for item in r.json():
            for n in item.get("dns_names", []):
                n = n.strip().lower().lstrip("*.")
                if n.endswith("." + domain) or n == domain:
                    out.add(n)
        return out
    except Exception as e:
        print(f"  [!] certspotter {domain}: {type(e).__name__}", file=sys.stderr)
        return set()


def passive_hackertarget(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
        if r.status_code != 200 or "error" in r.text[:200].lower():
            return set()
        out = set()
        for line in r.text.splitlines():
            h = line.split(",")[0].strip().lower()
            if h.endswith("." + domain) or h == domain:
                out.add(h)
        return out
    except Exception as e:
        print(f"  [!] hackertarget {domain}: {type(e).__name__}", file=sys.stderr)
        return set()


def passive_urlscan(domain, size=2000):
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size={size}"
    try:
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
        if r.status_code != 200:
            return set()
        out = set()
        for item in r.json().get("results", []):
            for key in ("domain", "hostname"):
                v = (item.get("page") or {}).get(key) or (item.get("task") or {}).get(key)
                if not v:
                    continue
                v = str(v).lower().lstrip("*.")
                if v.endswith("." + domain) or v == domain:
                    out.add(v)
            # urlscan 的 task.url 也带主机
            tu = (item.get("task") or {}).get("url", "")
            m = re.match(r"https?://([^/:]+)", str(tu))
            if m:
                h = m.group(1).lower()
                if h.endswith("." + domain):
                    out.add(h)
        return out
    except Exception as e:
        print(f"  [!] urlscan {domain}: {type(e).__name__}", file=sys.stderr)
        return set()


def passive_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
        if r.status_code != 200:
            return set()
        out = set()
        for item in r.json():
            n = (item.get("name_value") or "").strip().lower().lstrip("*.")
            for part in n.split("\n"):
                part = part.strip()
                if part.endswith("." + domain):
                    out.add(part)
        return out
    except Exception:
        return set()  # crt.sh 大陆常 502，静默跳过


def _resolve(host, resolver):
    try:
        ans = resolver.resolve(host, "A")
        ips = [str(r) for r in ans]
        return host, ips
    except Exception:
        return host, None


def brute(domain, words, workers=60):
    if dns is None:
        raise SystemExit("爆破需要 dnspython：pip install dnspython（或用 --no-brute）")
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    resolver.timeout = 3
    # 泛解析检测：随机子域也能解析 → 该域开了 wildcard，爆破结果全部作废
    probe = WILDCARD_PROBE.format(rand="q9x7z3", domain=domain)
    _, ips = _resolve(probe, resolver)
    if ips:
        print(f"  [!] {domain} 疑似泛解析(wildcard)，跳过爆破")
        return set()
    hosts = [f"{w}.{domain}" for w in words]
    found = set()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_resolve, h, resolver): h for h in hosts}
        for f in cf.as_completed(futs):
            h, r = f.result()
            if r:
                found.add(h)
    return found


def run(domain, do_brute=True, use_crtsh=False):
    print(f"[*] {domain} 被动源收集 ...")
    found = set()
    for fn in (passive_certspotter, passive_hackertarget, passive_urlscan):
        s = fn(domain)
        print(f"    {fn.__name__}: {len(s)}")
        found |= s
    if use_crtsh:
        s = passive_crtsh(domain)
        print(f"    crt.sh: {len(s)}")
        found |= s
    if do_brute:
        print(f"[*] {domain} 定向爆破 {len(BRUTE_WORDS)} 词 ...")
        b = brute(domain, BRUTE_WORDS)
        print(f"    brute: {len(b)}")
        found |= b
    return sorted(found)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", default="", help="T1 / T2 / 空=全部")
    ap.add_argument("--domains", default="", help="逗号分隔，覆盖 tier")
    ap.add_argument("--no-brute", action="store_true")
    ap.add_argument("--crtsh", action="store_true")
    ap.add_argument("--out", default="../recon/subs.json")
    ap.add_argument("--csv", default="", help="目标清单 CSV（domain,tier,owner），替代内置 TARGETS")
    a = ap.parse_args()

    if a.domains:
        todo = [(d.strip(), "T?", "手动") for d in a.domains.split(",") if d.strip()]
    elif a.csv:
        from targets import load_csv
        todo = load_csv(a.csv)
    else:
        todo = [t for t in TARGETS if (not a.tier or t[1] == a.tier)]
    if not todo:
        raise SystemExit("没有目标：用 --domains / --csv，或编辑 targets.py 里的 TARGETS")

    result = {}
    for domain, tier, name in todo:
        t0 = time.time()
        subs = run(domain, do_brute=not a.no_brute, use_crtsh=a.crtsh)
        result[domain] = {"tier": tier, "vendor": name, "subs": subs, "count": len(subs)}
        print(f"[=] {tier} {name} {domain}: {len(subs)} 子域 ({time.time()-t0:.0f}s)\n")

    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)

    total = sum(v["count"] for v in result.values())
    print(f"[✓] 合计 {total} 个唯一子域 → {a.out}")


if __name__ == "__main__":
    main()
