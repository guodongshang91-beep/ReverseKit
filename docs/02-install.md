# 安装与环境

## 依赖矩阵

| 模块 | 必需 | 可选 | 系统级 |
| --- | --- | --- | --- |
| `web-recon` | `requests` | — | — |
| `src-hunt` | `requests` `dnspython` `ds-store` | — | — |
| `binary-re` | —（纯标准库） | `capstone`（`dis` 子命令） | — |
| `pe-patch` | `pefile` | `capstone`（`dis` 子命令） | — |
| `wifi` | —（纯标准库） | — | **Npcap** |
| `android` | —（纯标准库） | — | 建 APK 才需要 aapt2/d8/apksigner |

```bash
pip install -r requirements.txt
```

## Windows 上会踩的四个坑

### 1. 中文输出乱码 / 直接抛 `UnicodeEncodeError`

控制台默认 GBK，脚本 `print` 中文就炸。两种解法：

```bash
# 单次
set PYTHONIOENCODING=utf-8 && python script.py
# 或 PowerShell
$env:PYTHONIOENCODING="utf-8"
```

脚本内部也已经写了 `sys.stdout.reconfigure(encoding="utf-8", errors="ignore")`，
但只有 Python 3.7+ 的 stdout 是 `TextIOWrapper` 时才生效（重定向到管道时可能不生效）。

### 2. MSYS / Git Bash 传路径给 Windows Python

```bash
# 不行：Python 收到的是 /e/repos/x.so，找不到
python elfkit.py info /e/repos/x.so
# 行：用 Windows 原生路径
python elfkit.py info E:/repos/x.so
```

### 3. Npcap 不支持静默安装

`npcap-x.y.z.exe /S` 无效，必须 GUI 走一遍并过 UAC。
装完检查 `C:\Windows\System32\Npcap\wpcap.dll` 是否存在（兼容模式还会复制一份到 `System32`）。

### 4. 递归删除大目录会被安全策略掐掉

`Remove-Item -Recurse`、`del /s /q` 在某些沙箱/EDR 环境会**静默杀进程**。
批量清理用 Python：

```python
import shutil
shutil.rmtree(r"E:\path\to\dir", ignore_errors=True)
```

## Linux / macOS

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

`binary-re` 在 Linux 上开箱可用（`/usr/lib` 下有大量 `.so` 可以练手）。
`pe-patch` 也能跑（只是分析对象是 PE 文件，不需要 Windows）。
`wifi` 模块请用 `aircrack-ng` 生态，本仓库的 Windows 路线不适用。

## 最小可用子集

只想做侦察，不想装东西：

```bash
pip install requests
python modules/web-recon/src/dnsx.py example.com    # 零依赖
python modules/web-recon/src/probe.py --urls u.txt  # 只要 requests
```

只想做二进制：

```bash
pip install capstone pefile
```

## 版本

已在以下环境实测跑通：

- Python 3.12.10 / 3.13.12
- Windows 11（`peck` / `elfkit` / `wifi` 全链路）
- `capstone` 5.0.7、`pefile` 2024.8.26
