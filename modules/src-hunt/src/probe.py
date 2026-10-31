# -*- coding: utf-8 -*-
"""
阶段 1b：HTTP 存活探测 + 指纹识别（httpx 的自研替代）。

对每个主机做 http/https 探测，抽取：
  状态码 / 跳转链 / 标题 / Server / X-Powered-By / 框架特征 / WAF 特征 / 证书 CN

指纹规则集中在 FINGERPRINTS，命中即输出组件名（后续关联已知 CVE 与未授权风险面）。
限速：默认 32 并发 + 每主机 8s 超时，不压测。
"""
import json
import re
import sys
import time
import argparse
import concurrent.futures as cf

import requests
import urllib3

urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
TIMEOUT = 8

# (组件名, 匹配来源, 正则)  来源: body / header / title / url
FINGERPRINTS = [
    ("Spring Boot", "body", r"Whitelabel Error Page|org\.springframework|Spring Boot"),
    ("Spring Actuator", "body", r'_links.\s*:\s*\{|/actuator/health'),
    ("Swagger", "body", r"swagger-ui|swagger\.json|api-docs|Swagger UI"),
    ("Druid", "body", r"Druid Stat Index|druid/index\.html|StatViewServlet"),
    ("Jenkins", "header", r"X-Jenkins|JENKINS_HOME"),
    ("Jenkins", "body", r"Jenkins|jenkins"),
    ("GitLab", "body", r"GitLab|gitlab"),
    ("Jira", "body", r"atlassian\.jira|JIRA"),
    ("Confluence", "body", r"Confluence|atlassian"),
    ("Kibana", "body", r"kibana|Kibana"),
    ("Grafana", "body", r"Grafana|grafana"),
    ("Nacos", "body", r"nacos|Nacos"),
    ("Zabbix", "body", r"Zabbix|zbx_session"),
    ("Elasticsearch", "body", r'"cluster_name"|"tagline"\s*:\s*"You Know'),
    ("Solr", "body", r"Solr Admin|solr"),
    ("Tomcat", "body", r"Apache Tomcat|Tomcat"),
    ("Weblogic", "body", r"WebLogic|Oracle WebLogic"),
    ("Nexus", "body", r"Sonatype Nexus|Nexus Repository"),
    ("SonarQube", "body", r"SonarQube|sonarqube"),
    ("phpMyAdmin", "body", r"phpMyAdmin"),
    ("ThinkPHP", "body", r"ThinkPHP|thinkphp"),
    ("Shiro", "header", r"rememberMe=deleteMe|set-cookie:.*rememberMe"),
    ("Fastjson", "body", r"fastjson"),
    ("WordPress", "body", r"wp-content|wp-includes|WordPress"),
    ("Discuz", "body", r"Discuz|discuz"),
    ("Ruoyi", "body", r"RuoYi|ruoyi"),
    ("Vue", "body", r"__VUE|vue\.js|id=\"app\""),
    ("React", "body", r"react|__NEXT_DATA__"),
    ("Nginx", "header", r"nginx"),
    ("Apache", "header", r"Apache"),
    ("IIS", "header", r"Microsoft-IIS"),
    ("OpenResty", "header", r"openresty"),
    ("Tengine", "header", r"Tengine"),
    ("Kong", "header", r"kong"),
    ("PHP", "header", r"PHP/"),
    ("ASP.NET", "header", r"ASP\.NET|X-AspNet"),
    ("Java", "header", r"Servlet|JSP"),
    ("ColdFusion", "header", r"ColdFusion"),
    ("Laravel", "body", r"Laravel|laravel_session"),
    ("Django", "body", r"csrfmiddlewaretoken|Django"),
    ("Flask/Jinja", "body", r"Werkzeug|Flask"),
    ("Express", "header", r"Express"),
    ("Go", "body", r"net/http"),
]

WAF_SIGNS = [
    ("Cloudflare", r"cloudflare|cf-ray|__cf_bm"),
    ("Akamai", r"akamai|AkamaiGHost"),
    ("Alibaba WAF", r"AliyunWaf|aliyun|Yundun"),
    ("Tencent WAF", r"WAF|tencentwaf|qcloud"),
    ("Huawei WAF", r"Huawei|huaweicloudwaf"),
    ("F5 BIG-IP", r"BigIP|BIGipServer|f5"),
    ("Imperva", r"Imperva|incapsula"),
    ("ModSecurity", r"ModSecurity|mod_security"),
    ("Safedog", r"safedog|SafeDog"),
    ("Chaitin", r"Chaitin|chaitin|SafeLine"),
    ("360", r"360wzws|360waf"),
    ("Baidu Yunjiasu", r"yunjiasu|Yundun"),
]

# 高风险暴露面：命中后直接进入阶段 2 候选
HIGH_VALUE_PATH = [
    "actuator", "swagger", "druid", "jenkins", "kibana", "grafana", "nacos",
    "zabbix", "solr", "elastic", "sonar", "nexus", "gitlab", "jira", "confluence",
    "admin", "manage", "login", "test", "dev", "uat", "staging", "ops", "monitor",
    "backup", "old", "api", "open", "internal", "bi", "erp", "crm", "hr", "oa",
]


def probe(host):
    rec = {"host": host, "alive": False}
    sess = requests.Session()
    last_exc = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = sess.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False,
                         headers={"User-Agent": UA})
            body = r.text[:200000]
            hdr = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
            comps = set()
            for name, src, pat in FINGERPRINTS:
                tgt = {"body": body, "header": hdr, "title": title}.get(src, "")
                if tgt and re.search(pat, tgt, re.I):
                    comps.add(name)
            wafs = set()
            for name, pat in WAF_SIGNS:
                if re.search(pat, hdr, re.I) or re.search(pat, body[:5000], re.I):
                    wafs.add(name)
            rec.update({
                "alive": True, "url": r.url, "status": r.status_code, "title": title,
                "server": r.headers.get("Server", "")[:60],
                "xpowered": r.headers.get("X-Powered-By", "")[:60],
                "components": sorted(comps), "waf": sorted(wafs),
                "len": len(r.content),
                "high_value": [p for p in HIGH_VALUE_PATH if re.search(p, host, re.I)],
            })
            return rec
        except Exception as e:
            last_exc = e
            continue
    rec["err"] = type(last_exc).__name__ if last_exc else "unknown"
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subs", default="../recon/subs.json")
    ap.add_argument("--out", default="../recon/alive.json")
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--domains", default="")
    a = ap.parse_args()

    data = json.load(open(a.subs, encoding="utf-8"))
    hosts = []
    meta = {}
    for dom, v in data.items():
        if a.domains and dom not in a.domains.split(","):
            continue
        for s in v["subs"]:
            hosts.append(s)
            meta[s] = (v["tier"], v["vendor"], dom)
    hosts = sorted(set(hosts))
    print(f"[*] 待探测 {len(hosts)} 主机", file=sys.stderr)

    out = []
    t0 = time.time()
    done = 0
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for rec in ex.map(probe, hosts):
            done += 1
            if rec.get("alive"):
                rec["tier"], rec["vendor"], rec["root"] = meta[rec["host"]]
                out.append(rec)
            if done % 100 == 0:
                print(f"    {done}/{len(hosts)} alive={len(out)} ({time.time()-t0:.0f}s)",
                      file=sys.stderr)

    json.dump(out, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[✓] 存活 {len(out)}/{len(hosts)} → {a.out}")


if __name__ == "__main__":
    main()
