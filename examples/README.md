# 示例与输入格式

仓库里**不放真实目标**。这里的文件都是占位样例，照着改。

## 文件

| 文件 | 用途 | 对应脚本 |
| --- | --- | --- |
| `scope.csv` | 目标清单（domain,tier,owner） | `src-hunt/src/targets.py --csv` |
| `urls.txt` | 待探测 URL 列表，一行一个 | `web-recon/src/probe.py --urls` |
| `alive.sample.json` | `probe.py` 输出格式样例 | `unauth_scan.py --alive` / `js_harvest.py --alive` |
| `evidence-template/` | 证据包目录模板 | 人工归档 |

## scope.csv

```csv
domain,tier,owner
example.com,T1,示例大厂
example-group.com.cn,T2,示例集团
example-sme.com,T3,示例中小企业
```

`tier` 只影响排序优先级（T1 先跑），不影响扫描行为。

## alive.sample.json

```json
[
  {
    "host": "api.example.com",
    "url": "https://api.example.com",
    "status": 200,
    "server": "nginx",
    "title": "Example API",
    "stack": "spring",
    "baseline_md5": "d41d8cd98f00b204e9800998ecf8427e",
    "baseline_len": 0
  }
]
```

`baseline_md5` / `baseline_len` 由 `probe.py --baseline` 写入，
是后续所有假阳性判定的依据。**缺了这两个字段，`unauth_scan` 会拒绝把结果标为"可信"。**

## 证据包模板

```text
evidence-template/
├── request-01.txt      原始请求（含全部 header）
├── response-01.txt     原始响应（大文件截前 4KB + 总长度）
├── verify-notes.md     时间、会话、复现步骤、影响面、修复建议
└── hash.txt            sha256 清单
```

复制成 `evidence/<VULN-ID>/` 再填。判断标准见
[docs/00-quickstart.md](../docs/00-quickstart.md) 第 5 节。

## 需要二进制样本？

别往仓库里塞。自己造或就地取材：

```bash
# Linux：系统里到处都是 ELF
python modules/binary-re/tools/elfkit.py info /usr/lib/x86_64-linux-gnu/libc.so.6

# Windows：随便一个自带 exe
python modules/pe-patch/tools/peck.py info C:\Windows\System32\notepad.exe

# 自己编一个最小 ELF
echo 'int main(){return 0;}' > t.c && gcc t.c -o t && python modules/binary-re/tools/elfkit.py info t
```
