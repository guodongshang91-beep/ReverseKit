# 模块手册

逐个模块的参数、输出格式、退出码。每个模块目录下还有更细的 README。

---

## web-recon

| 脚本 | 参数 | 说明 |
| --- | --- | --- |
| `dnsx.py` | `<domain...>` | 必填。查 A/AAAA/CNAME/NS/MX/TXT/SOA，用 223.5.5.5 / 119.29.29.29 / 8.8.8.8 轮询 |
| `probe.py` | 无 CLI | 底层库：`raw(host, path, method, body, headers, timeout)` → `(status, headers, body)`，不跟随跳转、不校验证书 |
| `jsonp_fuzz.py` | `<host> <path>` `[--param callback]` `[--out]` | 往 `<path>` 追加 `<param>=<payload>`，同时跑 WAF 指纹组 |
| `headers_check.py` | `<host> [path]` `[--out]` | HTTP 方法矩阵 / CORS 三来源 / 9 项安全头 / Cookie 属性 |

四个脚本**零第三方依赖**。无参数运行会打印 usage 并以 `2` 退出。

退出码统一 `0` 成功、`1` 参数或网络错误。

---

## src-hunt

| 脚本 | 必需参数 | 主要输出字段 |
| --- | --- | --- |
| `recon.py` | `--out` | `domain` `source` |
| `probe.py` | `--subs` `--out` | `host` `status` `server` `stack` `baseline_md5` |
| `unauth_scan.py` | `--alive` `--out` | `host` `path` `level` `evidence_md5` `baseline_diff` |
| `oss_scan.py` | `--subs` `--out` | `bucket` `provider` `listable` |
| `js_harvest.py` | `--alive` `--out` | `host` `url` `kind`(`url|api|secret|mock`) `match` |
| `param_probe.py` | `--alive` `--out` | `host` `path` `param` `signal`(`error|time|echo`) |
| `targeted.py` | `--targets <json|none>` | `host` `stack` `path` `name` `level` |
| `dsstore_parse.py` | `<file.ds_store>` | 目录树 |
| `targets.py` | `--csv` | 打印分档清单 |

`--workers` 默认值不高（8~28）。**别开太大**：目标侧看到的是流量，你只是自己图快。

### 编排器 rkhunt

```text
rkhunt list                                   # 阶段与依赖
rkhunt run --scope scope.csv [--workdir loot] # 全跑
rkhunt run ... --only recon,probe             # 只跑指定阶段
rkhunt run ... --skip oss,param               # 跳过指定阶段
rkhunt run ... --dry-run                      # 只打印命令
rkhunt run ... --keep-going                   # 失败也继续
rkhunt status --workdir loot                  # 每阶段 exit/耗时/条数
```

阶段依赖：`recon → subs → probe → alive → {unauth, js, param, targeted}`，`oss` 只依赖 `subs`。
每阶段状态写进 `<workdir>/run.json`。

---

## tools/evidkit（证据包与报告）

```text
evidkit new    --id VULN-001 --host api.example.com --path /actuator/env --level 中危 --type 未授权访问
evidkit add    --id VULN-001 --request req.txt --response resp.txt [--note 换出口]
evidkit seal   --id VULN-001          # 生成 hash.txt（sha256 + 字节数）
evidkit verify --id VULN-001          # 复核，被改过就 exit 1
evidkit report --id VULN-001 [--out report.md]
```

全局参数 `--dir` 指定证据根目录（默认 `evidence/`）。
`report` 从 `meta.json` + 最后一次抓包 + `verify-notes.md` 渲染，
抓包不足两次会提示「未完成独立复现」。

## binary-re / elfkit

```text
elfkit info    <file>                       [-l N] [-q]
elfkit strings <file>                       [-m MIN] [-f FILTER]
elfkit xref    <file> <hex-vaddr>
elfkit dis     <file> <hex-vaddr>           [-n COUNT]
elfkit patch   <file> (--off|--vaddr) <hex> [--dry-run]
```

| 输出字段 | 含义 |
| --- | --- |
| `off=` | 文件偏移 |
| `vaddr=` | 虚拟地址（按节/段映射换算） |
| `ptr32` / `ptr64` | 命中的是 4 字节还是 8 字节字面量 |
| `adrp+add` | AArch64 指令对拼出的地址引用 |
| `verify` | 补丁回读结果，`OK` / `FAILED` |

---

## pe-patch / peck

```text
peck info    <file>
peck strings <file> [-m MIN] [-f FILTER] [--utf16]
peck hunt    <file>
peck xref    <file> <hex-rva>
peck dis     <file> <hex-rva>               [-n COUNT]
peck patch   <file> (--rva|--off) <hex>     [--dry-run]
```

`info` 输出里的 `mitigations` 很有用：目标有 `CFG`（控制流保护）时，
把中间指令改成 `jmp` 可能触发崩溃，优先考虑整块 `nop` 或改条件跳转的方向。

---

## wifi

```text
capture.py     --ssid <SSID>            # 需 Npcap
capture_mon.py --ssid <SSID> --bssid <MAC>   # 需 Npcap + 管理员
analyze.py     <pcap> [--ssid <SSID>] [--self-test]
gen_dict.py                              # 读 RK_SSID / RK_DICT_OUT
```

`analyze.py` 输出 hashcat 22000 行：

```text
WPA*02*<MIC>*<MAC_AP>*<MAC_STA>*<SSID_HEX>*<ANONCE>*<EAPOL>*<MP>
```

`--self-test` 用已知密码的合成握手验证 PBKDF2→PMK→PTK→MIC 全链路，**先跑这个再跑真实抓包**。

---

## android

```text
aar_extract.py  list  <aars...>
aar_extract.py  jar   <aars...> -o <out.jar>
aar_extract.py  so    <aars...> [--abi arm64-v8a] -o <dir>
res_check.py    [工程目录]
syntax_check.py [工程目录]
```

`res_check.py` / `syntax_check.py` 有非零退出码即代表发现问题，
可以直接挂到 CI 或 pre-commit。
