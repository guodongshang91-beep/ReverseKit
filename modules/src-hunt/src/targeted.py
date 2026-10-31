# -*- coding: utf-8 -*-
"""
阶段 2e：针对性深度探测 —— 对指纹识别出的具体技术栈，打该栈独有的风险面。

区别于 2b 的通用路径爆破，这里按栈下药：
  Spring Boot → actuator / env / heapdump
  GitLab      → 开放注册、匿名可见项目、API 未授权
  Sentry      → 匿名可读组织/项目/事件（事件里常有堆栈与敏感参数）
  Django      → DEBUG 模式、admin 暴露、DRF 未授权
  Discuz      → uc_server、config、已知历史接口
  WordPress   → REST 用户枚举、配置备份、xmlrpc
  ASP.NET/IIS → 常见后台、web.config、trace.axd
只读探测，不爆破口令、不改数据。
"""
import re
import json
import sys
import argparse
import concurrent.futures as cf

import requests
import urllib3

urllib3.disable_warnings()
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
TIMEOUT = 10

# (栈, [(路径, 判定正则, 名称, 等级)])
PLAYBOOK = {
    "spring": [
        ("/actuator", r'"_links"\s*:\s*\{', "Actuator 未授权", "中危"),
        ("/actuator/env", r'"propertySources"', "Actuator env 未授权", "高危"),
        ("/actuator/beans", r'"beans"|"contexts"', "Actuator beans 未授权", "中危"),
        ("/actuator/heapdump", None, "heapdump 未授权", "高危"),
        ("/actuator/threaddump", r'"threads"|"threadName"', "threaddump 未授权", "中危"),
        ("/actuator/mappings", r'"mappings"|"handler"', "路由信息泄露", "中危"),
        ("/actuator/configprops", r'"configurationProperties"|"contexts"', "配置属性泄露", "中危"),
        ("/actuator/loggers", r'"loggers"|"configuredLevel"', "日志配置未授权", "低危"),
        ("/actuator/scheduledtasks", r'"scheduledTasks"|"cron"', "定时任务泄露", "中危"),
        ("/actuator/caches", r'"caches"|"cacheManagers"', "缓存信息泄露", "低危"),
        ("/actuator/httptrace", r'"traces"|"timestamp"', "HTTP 请求追踪泄露", "中危"),
        ("/v2/api-docs", r'"swagger"|"paths"', "Swagger 文档未授权", "低危"),
    ],
    "gitlab": [
        ("/users/sign_in", r'GitLab|Sign in', "GitLab 登录页可达", "info"),
        ("/api/v4/projects", r'\[\s*\{|"id":\s*\d+', "GitLab 项目 API 未授权", "高危"),
        ("/api/v4/users", r'"username"|"id":\s*\d+', "GitLab 用户 API 未授权", "中危"),
        ("/api/v4/version", r'"version"|"revision"', "GitLab 版本泄露", "低危"),
        ("/explore", r"Explore|projects", "GitLab 公开项目浏览", "info"),
        ("/-/metrics", r"^gitlab_|http_requests", "GitLab 指标未授权", "低危"),
        ("/admin", r"Admin Area|GitLab", "GitLab 管理区暴露", "info"),
    ],
    "sentry": [
        ("/auth/login/", r"Sentry|Sign in|CSRF", "Sentry 登录页可达", "info"),
        ("/api/0/organizations/", r'\[|"slug"|"name"', "Sentry 组织 API 未授权", "高危"),
        ("/api/0/projects/", r'\[|"slug"|"name"', "Sentry 项目 API 未授权", "高危"),
        ("/api/0/", r'\{|"version"', "Sentry API 根可达", "info"),
        ("/manage/", r"Sentry|Manage", "Sentry 管理后台暴露", "info"),
    ],
    "django": [
        ("/", r"DisallowedHost|DEBUG\s*=\s*True|Traceback", "Django 调试信息泄露", "中危"),
        ("/admin/", r"Django administration|django", "Django Admin 暴露", "info"),
        ("/admin/login/", r"Django administration|username", "Django Admin 登录页", "info"),
        ("/api/", r'\{|\[|"count"|"results"', "API 根可达", "info"),
        ("/api/v1/", r'\{|\[|"count"|"results"', "API v1 根可达", "info"),
        ("/static/rest_framework/css/bootstrap.css", r"css", "DRF 框架确认", "info"),
        ("/.env", r"^[A-Z][A-Z0-9_]{2,}\s*=", "env 泄露", "高危"),
        ("/debug/", r"DEBUG|Traceback|settings", "调试页泄露", "中危"),
    ],
    "discuz": [
        ("/forum.php", r"Discuz|forum", "Discuz 确认", "info"),
        ("/uc_server/", r"UCenter|uc_server", "UCenter 目录可达", "info"),
        ("/config/config_global.php", r"\$_config|dbhost", "Discuz 全局配置泄露", "高危"),
        ("/config/config_ucenter.php", r"UC_|dbhost", "UCenter 配置泄露", "高危"),
        ("/data/", r"Index of|Parent Directory", "data 目录可列目录", "中危"),
        ("/source/plugin/", r"Index of|Parent Directory", "插件目录可列目录", "低危"),
        ("/robots.txt", None, "robots", "info"),
    ],
    "wordpress": [
        ("/wp-json/wp/v2/users", r'"slug"|"name"|"id":\s*\d', "WP REST 用户枚举未授权", "中危"),
        ("/wp-json/wp/v2/posts", r'"slug"|"title"', "WP REST 文章 API", "info"),
        ("/xmlrpc.php", r"XML-RPC server accepts", "xmlrpc 开启", "info"),
        ("/wp-config.php.bak", r"DB_NAME|DB_PASSWORD", "wp-config 备份泄露", "高危"),
        ("/wp-config.php~", r"DB_NAME|DB_PASSWORD", "wp-config 备份泄露", "高危"),
        ("/wp-content/debug.log", r"\[\d{2}-|PHP (Warning|Notice|Fatal)", "WP 调试日志泄露", "中危"),
        ("/?author=1", r"author|Archive", "作者枚举", "info"),
    ],
    "aspnet": [
        ("/web.config", r"<configuration>|<appSettings>", "web.config 泄露", "中危"),
        ("/trace.axd", r"Trace|Request Details", "ASP.NET Trace 未授权", "中危"),
        ("/elmah.axd", r"ELMAH|Error Log", "ELMAH 错误日志未授权", "中危"),
        ("/api/", r'\{|\[|"value"', "API 根可达", "info"),
        ("/swagger", r"swagger", "Swagger 未授权", "低危"),
        ("/.git/config", r"\[core\]|\[remote", "Git 泄露", "中危"),
    ],
}

# 主机 -> 栈（来自 probe.py 的指纹命中）
# 真实目标不要写进仓库：用 --targets hits.json 从文件读，格式 [{"host":..,"stack":..,"owner":..}]
TARGETS = [
    ("example-corp.com", "spring", "示例大厂"),
    ("dev.example-group.com", "gitlab", "示例集团"),
]


def load_targets(path):
    """从 probe.py 产出的 JSON 里挑出「已知栈」的主机。"""
    import json as _json
    with open(path, encoding="utf-8") as f:
        rows = _json.load(f)
    out = []
    for r in rows if isinstance(rows, list) else rows.get("alive", []):
        host = r.get("host") or r.get("url", "").split("//")[-1].split("/")[0]
        stack = r.get("stack") or "generic"
        if host:
            out.append((host, stack, r.get("owner", "")))
    return out


def probe_one(host, stack, path, pat, name, level):
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}{path}"
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True,
                             headers={"User-Agent": UA, "Accept": "*/*"})
        except Exception:
            continue
        if r.status_code != 200:
            continue
        txt = r.text[:8000]
        if pat is None:
            ev = f"HTTP200 len={len(r.content)}"
        else:
            m = re.search(pat, txt, re.I | re.M)
            if not m:
                continue
            ev = m.group(0)[:120].replace("\n", " ")
        return {"host": host, "stack": stack, "url": r.url, "status": r.status_code,
                "name": name, "level": level, "evidence": ev,
                "size": len(r.content), "snippet": txt[:220].replace("\n", " ")}
    return None


def run(host, stack, vendor):
    out = []
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(probe_one, host, stack, p, r, n, l) for p, r, n, l in PLAYBOOK[stack]]
        for f in cf.as_completed(futs):
            try:
                r = f.result()
                if r:
                    r["vendor"] = vendor
                    out.append(r)
            except Exception:
                pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../recon/targeted-hits.json")
    ap.add_argument("--extra", default="", help="host:stack:vendor,host:stack:vendor")
    a = ap.parse_args()
    todo = list(TARGETS)
    for item in a.extra.split(","):
        if item.strip():
            h, s, v = (item.split(":") + ["?", "?"])[:3]
            todo.append((h.strip(), s.strip(), v.strip()))
    out = []
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(run, h, s, v): h for h, s, v in todo}
        for f in cf.as_completed(futs):
            h = futs[f]
            try:
                res = f.result()
            except Exception as e:
                print(f"[!] {h}: {type(e).__name__}", file=sys.stderr)
                res = []
            out.extend(res)
    json.dump(out, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    order = {"高危": 0, "中危": 1, "低危": 2, "info": 3}
    for x in sorted(out, key=lambda a: order.get(a["level"], 9)):
        print(f"[{x['level']}] {x['vendor']} {x['host']} ({x['stack']})")
        print(f"    {x['url']}")
        print(f"    证据: {x['evidence'][:110]}")
    print(f"\n[✓] {len(out)} 条 → {a.out}")


if __name__ == "__main__":
    main()
