# 假阳性：为什么你的扫描器一直在骗你

> 这是本仓库最重要的一篇。工具换掉无所谓，这套判定逻辑不能丢。

## 先说结论

在防护成熟的目标上，**未经校准的扫描命中，假阳性率可以到 100%**。

真实数据（同一天、同一套脚本、同一批目标）：

| 场景 | 原始"命中" | 校准后 | 假阳性率 |
| --- | --- | --- | --- |
| 某大厂门户敏感路径 | 5 条"中高危" | 0 | 100% |
| 某视频站 + 本地生活站点 | 5 条 | 0 | 100% |
| 全量路径扫描（多站点） | 识别 **232 个** catch-all 站点 | — | — |
| 50 个中小企业主域 + 304 个参数化接口 | 若干低危 | 0 中高危 | — |

换一条链路（子域 + 前端 bundle）后，同一天在 72 个业务系统子域里拿到 **2 个真实高危**。
差别不在扫描量，在**判定方式**。

---

## 防线 1：随机路径基线

### 症状

某个站点的 `/admin`、`/login`、`/h2-console`、`/.env` **全部返回 200**，
长度还都一样（比如都是 24091 字节）。你兴冲冲写了三条高危。

其实它们返回的是同一个 SPA 首页。

### 判定

```python
def baseline(base_url):
    """先问一个肯定不存在的路径，看站点怎么回答"""
    probe = f"{base_url}/{random_token()}-probe"
    r = requests.get(probe, timeout=8, verify=False, allow_redirects=False)
    return {"status": r.status_code, "md5": md5(r.content), "len": len(r.content)}
```

规则：**命中响应必须与基线在 md5 或长度上显著不同**，否则一律丢弃。

```python
base = baseline(url)
r = requests.get(url + path, ...)
if r.status_code == base["status"] and md5(r.content) == base["md5"]:
    return None          # catch-all，扔掉
if abs(len(r.content) - base["len"]) < 64:
    return None          # 长度几乎一致，多半也是兜底页
```

---

## 防线 2：收紧正则

### 症状

`/h2-console` 被判"H2 数据库控制台暴露（高危）"。
原因：正则里写了 `h2`，而页面正文里有 `<h2>` 标签。

同类灾难词：`title`、`loading`、`welcome`、`error`、`admin`、
`username`、`password`（登录页全有）。

### 判定

只匹配**组件独有**的特征串：

| 别用 | 用这个 |
| --- | --- |
| `h2` | `H2 Console` / `org.h2.server.web` / `h2-console/login.jsp` |
| `actuator` | `"_links"` + `"self"` + `"health"` 同时出现 |
| `druid` | `Druid Stat Index` / `druid/index.html` |
| `swagger` | `swagger-ui.css` / `"swagger":"2.0"` |
| `nacos` | `nacos/v1/auth` / `Nacos Login` |

---

## 防线 3：响应去重

### 症状

同一台主机上 40 个路径全是"命中"，因为全返回同一个兜底页（只是 URL 变了）。

### 判定

一个主机扫完，按 `md5(content)` 分组，每组只保留等级最高的一条。
一个 md5 出 3 条以上，整组降级为"疑似兜底页"。

```python
seen = {}
for hit in hits:
    seen.setdefault(hit["md5"], []).append(hit)
for m, group in seen.items():
    if len(group) >= 3:
        continue            # 兜底页，全丢
    keep_best(group)
```

---

## 防线 4：WAF 拦截页

### 症状

返回 200，正则命中了——因为**正文是 WAF 的拦截页**，
而拦截页里恰好包含你请求的路径（`/phpmyadmin/` 被"回显"在提示里）。

### 判定

```python
WAF_BLOCK = (
    r"(?i)(waf_block|/punish/|__waf|access\s*denied|request\s*denied|"
    r"访问被拦截|访问被拒绝|安全验证|请求已被拒绝|blocked\s*by|"
    r"are\s*you\s*a\s*robot|deny\.html|拦截页面)"
)
if re.search(WAF_BLOCK, text[:4096]):
    return None
```

注意只取正文前 4KB —— 有些站点正文里带一整段 WAF 脚本，全局匹配会误杀真命中。

---

## 防线 5：404 路径回显

### 症状

404 页的 JSON 长这样：

```json
{"code": 404, "message": "resource /phpmyadmin/index.html not found"}
```

你的正则匹配到了 `phpmyadmin`，判定"phpMyAdmin 暴露"。

### 判定

```python
ERR_ECHO = r"(?i)(not\s*found|不存在|no\s*such|404|cannot\s*find)"
tail = path.strip("/").split("/")[-1]           # 例如 index.html
if re.search(ERR_ECHO, text[:2048]) and tail and tail in text[:2048]:
    return None
```

---

## 附带的坑：`allow_redirects` 把 URL 参数也算命中

### 症状

目标 `/debug/` 返回 302 到 OIDC 登录页，URL 里带
`redirect_uri=https%3A%2F%2Fbi.example.com%2Fdebug%2F`。
你请求 `/debug/`，跟随跳转后正文里出现了 `debug` —— 命中"调试接口暴露"。

### 判定

针对性探测必须：

```python
r = requests.get(url, allow_redirects=False, ...)
if 300 <= r.status_code < 400:
    return None          # 别跟；也别拿 Location 当证据
```

**跟随跳转后得到的正文，不能作为原始路径的证据。** 这是最基本的一条，
但用 `requests` 的默认参数就会踩。

---

## 前端 bundle 逆向的假阳性

### 私钥：51 个命中，全是假的

`-----BEGIN RSA PRIVATE KEY-----` 在 bundle 里出现 51 次，
几乎全部来自 `jsencrypt.min.js` / `umd.js` / `login.js` —— 登录页**前端加密库的公钥**。
公钥本来就是公开的，不是泄露。

判定：先排除库文件（`jsencrypt|crypto-js|forge|vendor|chunk-vendors|polyfill`），
再看剩下的里面有没有真的 `AK/SK`、`jdbc:` 串、可用的私钥。

### 云 AK：宽正则必然误报

`\b[A-Z]{4}[A-Za-z0-9]{20,}\b` 会匹配一堆普通随机串。
真 AK 的特征是**前缀 + 固定长度**（如阿里云 `LTAI` 开头的 20~24 位、AWS `AKIA` 开头的 20 位）。
写死前缀，别用宽泛的大写字母组合。

### 内网地址：价值判断，不是技术判断

内网域名 / 内网 IP 泄露，在多数 SRC 里属"降低或忽略奖励"的低价值项。
它们真正的用途是**当 SSRF 的落点**——单独报价值低，串起来才有价值。

### 判定真凭据的四条标准

1. 排除已知前端加密库文件；
2. 前缀符合厂商规范（`LTAI` / `AKIA` / `AKID` / `SK-`）；
3. 附近有对应 secret（单有 AK 没 SK 基本没法用）；
4. 能用一个**只读**请求证明有效（如 OSS `ListBuckets`），且**只请求一次**。

---

## 一条经验：命中数量本身就是信号

| 现象 | 含义 |
| --- | --- |
| 单站命中 > 20 条 | 99% 是 catch-all，先看基线 |
| 命中率 > 30% | 路径字典不适配这个站，或全站兜底 |
| 同一 md5 反复出现 | 兜底页 |
| 全是低危（`.DS_Store` / `web.config` / `.htaccess`） | 目标防护中等，该换链路了——去子域和 bundle 里找 |

**最后这条很关键**：中小企业官网上自动化扫描只能出低危信息泄露。
真正的中高危在**子域里的企业系统**和**前端 JS 硬编码的内部地址**后面。
50 个 SME 主域 + 304 个参数化接口 = 0 中高危；换到 72 个业务子域 = 2 个高危。
链路选错，努力白费。
