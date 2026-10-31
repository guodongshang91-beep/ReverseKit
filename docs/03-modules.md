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

---

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
