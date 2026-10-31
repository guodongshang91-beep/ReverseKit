# -*- coding: utf-8 -*-
"""HTTP 方法 / CORS / 安全响应头 / Cookie 属性 实测

usage: python headers_check.py <host> [path] [--out out/headers_check.json]
"""
import sys, json, os
sys.stdout.reconfigure(encoding="utf-8", errors="ignore")
from probe import raw

argv = sys.argv[1:]
OUT = "out/headers_check.json"
if "--out" in argv:
    i = argv.index("--out")
    OUT = argv[i + 1]
    del argv[i:i + 2]
if not argv:
    print(__doc__.strip())
    sys.exit(2)
HOST = argv[0]
P = argv[1] if len(argv) > 1 else "/"
if os.path.dirname(OUT):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
out = {}

print("=== 1. HTTP 方法 ===")
for m in ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH", "PROPFIND", "DEBUG"]:
    st, h, b = raw(HOST, P, m, body=("x=1" if m in ("POST", "PUT", "PATCH") else None), timeout=12)
    allow = h.get("allow", "")
    echo = "ECHO-DANGER" if (m == "TRACE" and st == 200 and len(b) > 0) else ""
    print("%-9s st=%-4d len=%-7d allow=%-30s %s" % (m, st, len(b), allow, echo))
    out.setdefault("methods", []).append({"m": m, "st": st, "len": len(b), "allow": allow})

print("\n=== 2. CORS ===")
for orig in ["https://evil.example.com", "null", "https://%s" % HOST]:
    st, h, b = raw(HOST, P, "GET",
                   headers={"Origin": orig}, timeout=12)
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    flag = "  <<< REFLECTED-ORIGIN" if orig in acao and acao != "*" else ""
    print("Origin=%-28s ACAO=%-32s ACAC=%-6s%s" % (orig, acao or "-", acac or "-", flag))
    out.setdefault("cors", []).append({"orig": orig, "acao": acao, "acac": acac})

print("\n=== 3. 安全响应头 ===")
st, h, b = raw(HOST, P, timeout=12)
sec = {
    "Strict-Transport-Security": h.get("strict-transport-security", ""),
    "X-Frame-Options": h.get("x-frame-options", ""),
    "X-Content-Type-Options": h.get("x-content-type-options", ""),
    "Content-Security-Policy": h.get("content-security-policy", ""),
    "Content-Security-Policy-Report-Only": h.get("content-security-policy-report-only", ""),
    "Referrer-Policy": h.get("referrer-policy", ""),
    "Permissions-Policy": h.get("permissions-policy", ""),
    "X-XSS-Protection": h.get("x-xss-protection", ""),
    "Cross-Origin-Opener-Policy": h.get("cross-origin-opener-policy", ""),
}
for k, v in sec.items():
    status = "OK" if v else "MISSING"
    if k == "Strict-Transport-Security" and v and "includeSubDomains" not in v:
        status = "WEAK(no includeSubDomains)"
    if k == "Content-Security-Policy-Report-Only" and v:
        status = "REPORT-ONLY(不阻断)"
    print("%-38s %-26s %s" % (k, status, v[:80]))
out["security_headers"] = sec

print("\n=== 4. Cookie 属性 ===")
for k, v in h.items():
    if k == "set-cookie":
        low = v.lower()
        print("Set-Cookie:", v)
        print("   Secure=%s HttpOnly=%s SameSite=%s" % (
            "Secure" in v, "HttpOnly" in v, "SameSite" in v))
        out["cookie"] = {"raw": v, "secure": "Secure" in v,
                         "httponly": "HttpOnly" in v, "samesite": "SameSite" in v}

print("\n=== 5. 点击劫持 PoC 可行性 ===")
print("X-Frame-Options 缺失 -> 页面可被 iframe 嵌入")
print("CSP 为 Report-Only -> 不阻断 frame-ancestors")
out["clickjacking"] = {"xfo_missing": not bool(sec["X-Frame-Options"]),
                       "csp_enforcing": bool(sec["Content-Security-Policy"])}

json.dump(out, open(OUT, "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)
print("\n[+] saved %s" % OUT)
