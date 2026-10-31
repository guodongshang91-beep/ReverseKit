# web-recon — 黑盒 Web 快速侦察

> 目标只有一个：在你开始爆破之前，先搞清楚**哪些响应值得信**。

## 工具

| 脚本 | 作用 | 依赖 |
| --- | --- | --- |
| `src/dnsx.py` | 自己发 DNS 包，查 A / AAAA / CNAME / NS / MX / TXT / SOA，展平输出 | 纯标准库 |
| `src/probe.py` | 底层 `raw()`：裸 `http.client` + 关闭证书校验，返回 `(status, headers, body)`；被另外两个脚本复用 | 纯标准库 |
| `src/jsonp_fuzz.py` | 回调参数注入探测 + WAF 指纹（空响应 / 延迟） | 纯标准库 |
| `src/headers_check.py` | HTTP 方法矩阵 / CORS / 安全响应头 / Cookie 属性审计 | 纯标准库 |

> 四个脚本都是**零第三方依赖**（`probe.py` 用 `http.client` 而不是 `requests`，
> 为的是在任何机器上都能跑，包括 pip 装不上东西的环境）。

## 用法

```bash
# DNS：一条命令看全所有记录
python src/dnsx.py example.com api.example.com

# 回调参数注入（host + 一个带查询参数的接口路径）
python src/jsonp_fuzz.py example.com "/api/hot?bid=1" --param callback

# 响应头 / CORS / 方法矩阵审计
python src/headers_check.py example.com / --out out/headers.json
```

写成脚本互相调用时，`probe.raw()` 是唯一的底层出口：

```python
from probe import raw
st, hdrs, body = raw("example.com", "/api/ping")   # 默认 443、关闭证书校验
```

## DNS 里要看什么

| 记录 | 危险信号 | 含义 |
| --- | --- | --- |
| A = `10.x` / `172.16-31.x` / `192.168.x` | 内网 IP 公网泄露 | 内网拓扑暴露，SSRF 的落点 |
| A = `127.0.0.1` | 环回泄露 | 辅助 DNS Rebinding |
| SOA / NS 与主域不同 | 子域被单独委派 | 遗留资产，重点查子域接管 |
| CNAME 指向第三方或已下线服务 | 接管面 | 核对目标是否仍在使用该服务 |

## 软 404：四个必须先记住的模式

| 现象 | 其实是 | 别当成 |
| --- | --- | --- |
| `302` + 0 字节 | WAF / 网关兜底 | 重定向到后台 |
| `200` + 与首页同尺寸 | 伪装 200 的兜底页 | `/admin` 可访问 |
| `200` + 0 字节 | 静态资源缺失 | 空接口 |
| `404` + 正文回显请求路径 | 错误页模板 | 目录遍历 |

`probe.raw()` 让你能拿到**未经跟随跳转的原始响应**（`http.client` 不自动跟随 302），
这正是判定需要的。软 404 基线在 [`src-hunt/unauth_scan.py`](../src-hunt/src/unauth_scan.py)
的 `baseline()` 里实现：先 `GET /<random>-probe`，把 status/md5/长度记下来，
后续所有命中都跟它比。**跳过这一步的扫描结果，当作噪声处理。**

## 输出

`jsonp_fuzz.py` / `headers_check.py` 默认写 `out/*.json`（`--out` 可改），
字段统一保留 `status / length / headers / body 片段`，
方便脚本之间串起来，也方便报告里直接贴。
