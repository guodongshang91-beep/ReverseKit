# src-hunt — 广撒网挖掘 + 假阳性过滤

> 本模块解决的是「扫描器命中一大堆，但全是假的」。
> 五道防线内建在脚本里，不是文档里的口号。

## 一键跑（推荐）

```bash
python rkhunt.py list                                    # 看阶段定义与依赖
python rkhunt.py run --scope ../../examples/scope.csv --dry-run   # 只打印命令，不发包
python rkhunt.py run --scope scope.csv --workdir loot    # 全跑
python rkhunt.py run --workdir loot --only recon,probe   # 只跑前两段
python rkhunt.py run --workdir loot --skip oss,param     # 跳过耗时的
python rkhunt.py status --workdir loot                   # 每阶段 exit / 耗时 / 条数
```

产物统一落在 `--workdir`（默认 `loot/`），每阶段结束就把 `exit / 耗时 / 条数` 写进
`loot/run.json`，断了重跑会自动跳过已有前置产物的判断，不会重复轰炸目标。

`--keep-going` 让某段失败后继续跑后面的；默认一失败就停（省得在错的输入上继续）。

## 手动串（想知道每一步在干什么时用）

```bash
cd src

python recon.py        --out ../recon/subs.json                                   # 1. 子域（被动源 + 定向爆破）
python probe.py        --subs ../recon/subs.json --out ../recon/alive.json --workers 28   # 2. 存活 + 指纹
python unauth_scan.py  --alive ../recon/alive.json --out ../recon/unauth.json --workers 10 # 3. 未授权 / 敏感路径
python oss_scan.py     --subs ../recon/subs.json --out ../recon/oss.json         # 4. 对象存储桶
python js_harvest.py   --alive ../recon/alive.json --out ../recon/js.json        # 5. 前端 bundle 逆向
python param_probe.py  --alive ../recon/alive.json --out ../recon/param.json --workers 20  # 6. 参数注入
python targeted.py     --targets ../recon/alive.json                             # 7. 按指纹栈深度探测
```

产能参考（单机、普通宽带）：37 主域 → 2,099 子域（约 12 min）→ 1,440 存活（约 9 min）→ 全量路径爆破（约 10 min）。

## 脚本职责

| 脚本 | 做什么 | 关键参数 |
| --- | --- | --- |
| `recon.py` | 证书透明 / 被动源 / 前缀爆破 | `--out` `--threads` |
| `probe.py` | 存活判定 + 40 余种系统指纹 | `--workers` |
| `unauth_scan.py` | 敏感路径与中间件未授权（nacos / actuator / druid / swagger / jenkins / minio…） | `--workers` |
| `oss_scan.py` | 阿里 OSS / 腾讯 COS / S3 / 七牛 / UFile 公开桶 | `--subs` |
| `js_harvest.py` | bundle 里抽绝对地址、API 路径、硬编码密钥、mock 后门接口 | `--alive` |
| `param_probe.py` | 参数级注入探测（错误型 / 时间型 / 回显型） | `--workers` |
| `targeted.py` | 按已知栈跑专属 payload（spring / gitlab / django / discuz / wordpress / aspnet / sentry） | `--targets` |
| `dsstore_parse.py` | `.DS_Store` 解析出目录结构 | 位置参数 |
| `targets.py` | 目标清单模板（T1/T2/T3 分档），支持 CSV | `--csv` |

## 五道防线在代码里的位置

| # | 防线 | 函数 |
| --- | --- | --- |
| 1 | 随机路径基线 | `unauth_scan.py: baseline()` |
| 2 | 收紧正则（不用 HTML 通用词） | `unauth_scan.py` 的 `SIGS` |
| 3 | 同主机响应 md5 去重 | `unauth_scan.py: scan_host()` 末尾 |
| 4 | WAF 拦截页识别 | `unauth_scan.py: WAF_BLOCK` |
| 5 | 404 路径回显识别 | `unauth_scan.py: ERR_ECHO` |

原理与实测数据见 [docs/04-false-positive.md](../../docs/04-false-positive.md)。

## 目标清单

`targets.py` 只放占位示例。真实目标自己维护成 CSV：

```csv
domain,tier,owner
your-scope.example.com,T2,客户A
another-scope.example.net,T3,客户B
```

```bash
python targets.py --csv my_scope.csv
```

**不要把别人的资产清单提交进仓库。**

## 输出约定

```text
recon/subs.json      [{"domain": "...", "source": "crt|brute", ...}]
recon/alive.json     [{"host": "...", "status": 200, "server": "...", "stack": "spring", ...}]
recon/unauth.json    [{"host": "...", "path": "/actuator/env", "level": "高危", "evidence_md5": "..."}]
```

`level` 只是**候选等级**，不是结论。要写进报告，必须回到原始响应逐条复现。
