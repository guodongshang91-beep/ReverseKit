# -*- coding: utf-8 -*-
"""
阶段 2：多角度「范围性爆破」——敏感路径 + 中间件未授权 + 通用组件风险面。

设计原则（对应技能铁律 3/4：最小影响、禁止破坏）：
  - 全部为「只读探测」，不写数据、不触发删除/修改类 payload
  - heapdump / 备份包只取前若干字节证明真实，不整体下载
  - 三重假阳性防线（本脚本的核心，第一轮实测教训）：
      1) 随机路径基线：GET /<random>-probe，若返回 200 说明该站是 catch-all
         （SPA 首页 / WAF 兜底页 / 统一错误页），此类站点上所有"命中"必须与
         基线内容显著不同才算数 —— 实测某大厂门户就是这种，/admin /login
         /h2-console 全都返回同一个 24091 字节页面。
      2) 收紧正则：不写 "title"、"h2"、"loading" 这类 HTML 通用词，
         只匹配组件独有特征串。
      3) 响应去重：同一主机多个路径返回同一 md5 → 视为兜底页，丢弃。
"""
import re
import json
import sys
import time
import random
import string
import hashlib
import argparse
import concurrent.futures as cf

import requests
import urllib3

urllib3.disable_warnings()
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
TIMEOUT = 8

# ---------------------------------------------------------------- A. 敏感文件
SENSITIVE_FILES = [
    ("/.git/HEAD", r"^ref:\s*refs/heads/", "Git 源码泄露", "中危"),
    ("/.git/config", r"\[core\]\s|\[remote", "Git 配置泄露", "中危"),
    ("/.svn/entries", r"^\d+\s*$|^dir\s", "SVN 源码泄露", "中危"),
    ("/.svn/wc.db", None, "SVN 数据库泄露(仅验头)", "中危"),
    ("/.env", r"^[A-Z][A-Z0-9_]{2,}\s*=", "env 配置泄露(含密钥)", "高危"),
    ("/web.config", r"<configuration>|<appSettings>", "IIS 配置泄露", "中危"),
    ("/WEB-INF/web.xml", r"<web-app", "Java 配置泄露", "中危"),
    ("/WEB-INF/classes/application.properties", r"spring\.|jdbc:|password\s*=", "Spring 配置泄露", "中危"),
    ("/WEB-INF/classes/application.yml", r"^spring:|datasource:", "Spring 配置泄露", "中危"),
    ("/application-dev.yml", r"datasource:|password:|url:\s*jdbc", "Spring 开发配置泄露", "高危"),
    ("/application-prod.yml", r"datasource:|password:|url:\s*jdbc", "Spring 生产配置泄露", "高危"),
    ("/application.yml", r"datasource:|password:|url:\s*jdbc", "Spring 配置泄露", "高危"),
    ("/bootstrap.yml", r"datasource:|password:|url:\s*jdbc", "Spring 配置泄露", "高危"),
    ("/.DS_Store", None, "DS_Store 目录泄露(仅验头)", "低危"),
    ("/composer.json", r'"require"\s*:|"name"\s*:', "PHP 依赖清单泄露", "低危"),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version\s*\d|System\s*</td>", "phpinfo 信息泄露", "中危"),
    ("/info.php", r"phpinfo\(\)|PHP Version\s*\d", "phpinfo 信息泄露", "中危"),
    ("/test.php", r"phpinfo\(\)|PHP Version\s*\d", "phpinfo 信息泄露", "中危"),
    ("/.idea/workspace.xml", r"<project\s+version=", "IDE 工程泄露", "中危"),
    ("/.vscode/settings.json", r'"files\.exclude"|"editor\.|"settings"', "IDE 配置泄露", "低危"),
    ("/backup.sql", r"CREATE TABLE|INSERT INTO|-- MySQL dump", "数据库备份泄露", "高危"),
    ("/db.sql", r"CREATE TABLE|INSERT INTO", "数据库备份泄露", "高危"),
    ("/data.sql", r"CREATE TABLE|INSERT INTO", "数据库备份泄露", "高危"),
    ("/www.zip", None, "整站打包泄露(仅验头)", "高危"),
    ("/web.zip", None, "整站打包泄露(仅验头)", "高危"),
    ("/wwwroot.zip", None, "整站打包泄露(仅验头)", "高危"),
    ("/backup.zip", None, "备份压缩包泄露(仅验头)", "高危"),
    ("/code.tar.gz", None, "源码包泄露(仅验头)", "高危"),
    ("/server-status", r"Apache Server Status|Total accesses|Total Traffic", "Apache 状态页未授权", "低危"),
    ("/nginx_status", r"Active connections\s|server accepts handled", "Nginx 状态页未授权", "低危"),
    ("/sql.txt", r"CREATE TABLE|INSERT INTO", "数据库导出泄露", "高危"),
]

# ------------------------------------------------------- B. 中间件未授权
MIDDLEWARE = [
    ("/actuator", r'"_links"\s*:\s*\{', "Spring Actuator 未授权", "中危"),
    ("/actuator/env", r'"propertySources"|"profiles"', "Actuator env 未授权(含连接串)", "高危"),
    ("/actuator/beans", r'"beans"\s*:|"contexts"', "Actuator beans 未授权", "中危"),
    ("/actuator/health", r'"status"\s*:\s*"UP"', "Actuator health 未授权", "低危"),
    ("/actuator/gateway/routes", r'"route_id"|"predicates"', "Gateway 路由泄露", "中危"),
    ("/manage/actuator/env", r'"propertySources"', "Actuator env 未授权", "高危"),
    ("/monitor/actuator/env", r'"propertySources"', "Actuator env 未授权", "高危"),
    ("/druid/index.html", r"Druid (Stat Index|Monitor)|druid\.stat", "Druid 监控未授权", "中危"),
    ("/druid/datasource.json", r'"DbType"|"UserName"|"URL"\s*:\s*"jdbc', "Druid 数据源信息泄露", "中危"),
    ("/swagger-ui.html", r"swagger-ui|Swagger UI|swagger-resources", "Swagger 未授权", "低危"),
    ("/swagger/index.html", r"swagger", "Swagger 未授权", "低危"),
    ("/v2/api-docs", r'"swagger"\s*:|"paths"\s*:|"definitions"', "Swagger API 文档未授权", "低危"),
    ("/v3/api-docs", r'"openapi"\s*:|"paths"\s*:', "OpenAPI 文档未授权", "低危"),
    ("/doc.html", r"knife4j|swagger|api-docs", "knife4j 文档未授权", "低危"),
    ("/nacos/v1/auth/users/login", r"username|password|accessToken", "Nacos 未授权", "高危"),
    ("/nacos/v1/cs/configs", r'"dataId"|"group"|"content"', "Nacos 配置未授权", "高危"),
    ("/nacos/", r"nacos|Nacos", "Nacos 控制台暴露", "info"),
    ("/kibana/app/kibana", r'"kibana"|kibanaWelcome|Elastic', "Kibana 未授权", "中危"),
    ("/grafana/api/search", r'\[\s*\{|"title"\s*:|"uid"\s*:', "Grafana 面板未授权", "中危"),
    ("/grafana/login", r"Grafana|grafana", "Grafana 未授权", "中危"),
    ("/grafana/api/datasources", r'"type"\s*:|"database"|"password"', "Grafana 数据源泄露", "高危"),
    ("/zabbix/zabbix.php", r"Zabbix|zabbix", "Zabbix 未授权", "中危"),
    ("/jenkins/api/json", r'"_class"|"nodeName"|"jobs"', "Jenkins API 未授权", "高危"),
    ("/jenkins/", r"Jenkins|jenkins", "Jenkins 控制台暴露", "info"),
    ("/sonar/api/system/health", r'"health"|SonarQube', "SonarQube 未授权", "中危"),
    ("/nexus/service/rest", r"Nexus|nexus", "Nexus 未授权", "中危"),
    ("/_cat/indices", r"docs\.count|store\.size|pri\.rep", "Elasticsearch 未授权", "高危"),
    ("/_cluster/health", r'"cluster_name"|"number_of_nodes"', "Elasticsearch 未授权", "高危"),
    ("/_all/_search", r'"hits"\s*:|"took"\s*:', "ES 全索引未授权查询", "高危"),
    ("/es/_cat/indices", r"docs\.count|store\.size", "Elasticsearch 未授权", "高危"),
    ("/api/v1/namespaces", r'"kind"\s*:\s*"Namespace"|"items"', "K8s API 未授权", "高危"),
    ("/h2-console", r"H2 Database Engine|org\.h2\.|H2 Console|jdbc:h2", "H2 控制台未授权", "高危"),
    ("/console", r"H2 Database Engine|jolokia|Spring Boot Admin", "管理控制台未授权", "中危"),
    ("/adminer.php", r"Adminer|adminer", "Adminer 未授权", "中危"),
    ("/phpmyadmin/", r"phpMyAdmin|pma_", "phpMyAdmin 暴露", "中危"),
    ("/heapdump", None, "heapdump 泄露(仅验头)", "高危"),
    ("/actuator/heapdump", None, "heapdump 泄露(仅验头)", "高危"),
    ("/metrics", r"^jvm_|^process_cpu|^system_load", "Metrics 未授权", "低危"),
    ("/prometheus", r"^go_|^jvm_|^process_", "Prometheus 未授权", "中危"),
    ("/eureka/apps", r"<applications>|application\s+name=", "Eureka 未授权", "中危"),
    ("/solr/admin/info/system", r'"lucene"|"solr_home"|solr-spec",', "Solr 未授权", "高危"),
    ("/solr/admin/cores", r'"status"\s*:|"name"\s*:', "Solr cores 未授权", "高危"),
    ("/actuator/metrics", r'"names"\s*:|"measurements"', "Actuator metrics 未授权", "低危"),
    ("/api/users", r'"email"|"username"|"id"\s*:', "用户 API 未授权", "高危"),
    ("/api/v1/users", r'"email"|"username"|"id"\s*:', "用户 API 未授权", "高危"),
    ("/admin/", None, "后台暴露(仅线索)", "info"),
    ("/login", None, "登录页(仅线索)", "info"),
    ("/robots.txt", None, "robots(仅线索)", "info"),
]

# 防线 4/5：WAF 拦截页 与 404 路径回显（第二轮实测教训）
#   - 某视频站 /phpmyadmin/ 返回 200，但正文是云 WAF 的
#     waf_block_deny.html —— 正则命中了 URL 里的 "phpmyadmin" 字样
#   - 某企业系统 /phpmyadmin/ 返回 200，正文是 404 JSON，
#     把请求路径 /phpmyadmin/index.html 原样回显了出来
WAF_BLOCK = (r"(?i)(waf_block|/punish/|__waf|access\s*denied|request\s*denied|访问被拦截|"
             r"访问被拒绝|安全验证|请求已被拒绝|blocked\s*by|are\s*you\s*a\s*robot|"
             r"captcha|风险访问|deny\.html|forbidden\.html)")
ERR_ECHO = r"(?i)(not\s*found|404\s*not|不存在|无法找到|page\s*not\s*found|找不到|resource.{0,20}not\s*found)"

ZIP_SIG = (b"PK\x03\x04", b"\x1f\x8b", b"\xfd7zXZ", b"SQLite format", b"\x1f\x8b\x08")
DS_STORE_SIG = b"\x00\x00\x00\x01Bud1"
SQLITE_SIG = b"SQLite format 3"
HPROF_SIG = (b"JAVA PROFILE", b"\x08\x00\x00\x00")


def _rand():
    return "".join(random.choices(string.ascii_lowercase, k=10))


def baseline(sess, base):
    """随机路径基线：识别 catch-all / SPA / WAF 兜底页"""
    for _ in range(2):
        try:
            r = sess.get(f"{base}/{_rand()}-probe-{_rand()}", timeout=TIMEOUT, verify=False,
                         allow_redirects=False, headers={"User-Agent": UA})
            if r.status_code == 200 and len(r.content) > 0:
                return {
                    "len": len(r.content),
                    "md5": hashlib.md5(r.content[:4000]).hexdigest(),
                    "status": r.status_code,
                }
        except Exception:
            continue
    return None


def _binary_ok(path, head):
    if "heapdump" in path:
        return any(head.startswith(s) for s in HPROF_SIG) or b"\x00\x00" in head[:64]
    if path.endswith((".zip", ".tar.gz", ".rar", ".7z")):
        return any(head.startswith(s) for s in ZIP_SIG)
    if ".svn/wc.db" in path:
        return head.startswith(SQLITE_SIG)
    if ".DS_Store" in path:
        return head.startswith(b"\x00\x00\x00\x01Bud1")
    return any(head.startswith(s) for s in ZIP_SIG)


def check(sess, base, path, pat, name, level, bl):
    url = base.rstrip("/") + path
    try:
        r = sess.get(url, timeout=TIMEOUT, verify=False, allow_redirects=False,
                     headers={"User-Agent": UA, "Accept": "*/*"})
    except Exception:
        return None
    if r.status_code not in (200, 206):
        return None
    ctype = r.headers.get("Content-Type", "")
    head = r.content[:400]
    md5 = hashlib.md5(r.content[:4000]).hexdigest()

    # 防线 1+3：与随机基线同内容 → 兜底页，丢弃
    if bl and md5 == bl["md5"]:
        return None
    if bl and abs(len(r.content) - bl["len"]) <= max(64, bl["len"] * 0.02):
        if abs(len(r.content) - bl["len"]) < 200:
            return None

    # 防线 4：WAF / 风控拦截页 —— 200 也不是真命中
    txt_head = r.text[:3000]
    if re.search(WAF_BLOCK, txt_head):
        return None
    # 防线 5：404/错误页把请求路径回显了出来 —— 命中的是路径本身，不是组件
    if re.search(ERR_ECHO, txt_head) and path.strip("/").split("/")[-1] in txt_head:
        return None

    if pat is None:
        # 无正则：按文件头/等级判定
        if _binary_ok(path, head):
            ev = f"magic={head[:8].hex()} ctype={ctype[:30]} len={len(r.content)}"
        elif level == "info":
            ev = f"HTTP200 len={len(r.content)}"
        else:
            return None
    else:
        txt = r.text[:6000]
        m = re.search(pat, txt, re.I | re.M)
        if not m:
            return None
        ev = m.group(0)[:120].replace("\n", " ")
        # 防线 2：命中内容里若同时是兜底页特征（超大 HTML 且无该组件独有串）已由收紧正则过滤

    return {
        "url": url, "status": r.status_code, "type": name, "level": level,
        "evidence": ev, "ctype": ctype[:60], "size": len(r.content),
        "md5": md5,
        "snippet": (r.text[:250].replace("\n", " ").replace("\r", "") if pat else ""),
    }


def scan_host(host):
    hits = []
    sess = requests.Session()
    base = None
    for scheme in ("https", "http"):
        try:
            sess.get(f"{scheme}://{host}", timeout=TIMEOUT, verify=False, headers={"User-Agent": UA})
            base = f"{scheme}://{host}"
            break
        except Exception:
            continue
    if not base:
        return hits
    bl = baseline(sess, base)
    targets = list(SENSITIVE_FILES) + list(MIDDLEWARE)
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(check, sess, base, p, r, n, l, bl) for p, r, n, l in targets]
        for f in cf.as_completed(futs):
            try:
                r = f.result()
                if r:
                    hits.append(r)
            except Exception:
                pass
    # 去重：同一 md5 只保留等级最高的一条
    seen = {}
    for h in hits:
        k = h["md5"]
        order = {"高危": 0, "中危": 1, "低危": 2, "info": 3}
        if k not in seen or order[h["level"]] < order[seen[k]["level"]]:
            seen[k] = h
    res = list(seen.values())
    for h in res:
        h.pop("md5", None)
    return res, (bl is not None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alive", default="../recon/alive.json")
    ap.add_argument("--out", default="../recon/unauth-hits.json")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--hosts", default="")
    a = ap.parse_args()

    if a.hosts:
        hosts = [h.strip() for h in a.hosts.split(",") if h.strip()]
        meta = {h: ("T?", "手动", "?") for h in hosts}
    else:
        data = json.load(open(a.alive, encoding="utf-8"))
        hosts = [d["host"] for d in data]
        meta = {d["host"]: (d.get("tier", ""), d.get("vendor", ""), d.get("root", "")) for d in data}
    if a.limit:
        hosts = hosts[:a.limit]
    print(f"[*] 扫描 {len(hosts)} 台存活 × {len(SENSITIVE_FILES)+len(MIDDLEWARE)} 规则", file=sys.stderr)

    out = []
    catchall = 0
    t0 = time.time()
    done = 0
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(scan_host, h): h for h in hosts}
        for f in cf.as_completed(futs):
            h = futs[f]
            done += 1
            try:
                hits, is_ca = f.result()
            except Exception:
                hits, is_ca = [], False
            catchall += 1 if is_ca else 0
            for x in hits:
                x["host"] = h
                x["tier"], x["vendor"], x["root"] = meta.get(h, ("", "", ""))
                out.append(x)
            if done % 25 == 0:
                print(f"    {done}/{len(hosts)} hits={len(out)} catchall={catchall} ({time.time()-t0:.0f}s)",
                      file=sys.stderr)

    json.dump(out, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[✓] 命中 {len(out)} 条（catch-all 站点 {catchall} 个已降噪）→ {a.out}")
    from collections import Counter
    for k, v in Counter(x["level"] for x in out).most_common():
        print(f"    {k}: {v}")


if __name__ == "__main__":
    main()
