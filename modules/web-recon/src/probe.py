# -*- coding: utf-8 -*-
"""
黑盒存活探测 + 软 404 基线。
纯标准库，Windows 可用。只做只读探测 + 记录，不做破坏性动作。

同时作为 headers_check / jsonp_fuzz 的底层 raw() 提供者。
"""
import http.client, ssl, socket, json, sys, re, urllib.parse, gzip, io
from concurrent.futures import ThreadPoolExecutor

UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def raw(host, path="/", method="GET", body=None, headers=None, timeout=12, port=443, tls=True):
    """返回 (status, headers_dict, body_bytes)"""
    h = {"Host": host, "User-Agent": UA, "Accept": "*/*", "Connection": "close"}
    if headers:
        h.update(headers)
    if body is not None and isinstance(body, str):
        body = body.encode("utf-8", "ignore")
    try:
        if tls:
            c = http.client.HTTPSConnection(host, port, context=CTX, timeout=timeout)
        else:
            c = http.client.HTTPConnection(host, port, timeout=timeout)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        hdrs = dict((k.lower(), v) for k, v in r.getheaders())
        st = r.status
        c.close()
        return st, hdrs, data
    except Exception as e:
        return 0, {"_err": str(e)}, b""


def txt(b):
    if b"Content-Encoding" == b"":
        pass
    try:
        return b.decode("utf-8", "ignore")
    except Exception:
        return str(b)


if __name__ == "__main__":
    print("module ready")
