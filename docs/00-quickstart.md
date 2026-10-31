# 快速开始（5 分钟跑通）

## 0. 前置

- Python **3.9+**（3.11/3.12/3.13 都实测过）
- Windows / Linux / macOS 均可；`wifi` 模块只在 Windows 上完整可用
- 一个**你自己有权测试**的目标

## 1. 安装

```bash
git clone https://github.com/guodongshang91-beep/ReverseKit.git
cd ReverseKit
pip install -r requirements.txt
```

只要核心侦察能力的话，`requests` 一个包就够：

```bash
pip install requests
```

## 2. 三条命令验证装好了

```bash
# ELF 工具自检（拿系统里任意 .so 或自己编一个）
python modules/binary-re/tools/elfkit.py info /usr/lib/x86_64-linux-gnu/libc.so.6

# PE 工具自检（Windows）
python modules/pe-patch/tools/peck.py info C:\Windows\System32\notepad.exe

# DNS 侦察
python modules/web-recon/src/dnsx.py example.com
```

三个都出结构化的表，说明环境没问题。

## 3. 第一次完整链路（授权目标）

```bash
cd modules/src-hunt/src

python recon.py       --out ../recon/subs.json
python probe.py       --subs ../recon/subs.json --out ../recon/alive.json --workers 20
python unauth_scan.py --alive ../recon/alive.json --out ../recon/unauth.json --workers 8
```

看 `recon/unauth.json` 里的 `level` 字段——**那只是候选等级**。

## 4. 关键一步：把候选变成结论

对每一条 `level >= 中危` 的命中，回到原始响应手工确认：

```bash
curl -sS -o body.txt -D head.txt "https://<host>/<path>" && wc -c body.txt && head -20 body.txt
```

判定标准：

| 条件 | 结论 |
| --- | --- |
| 返回内容与 `/random-probe` 基线明显不同，且含组件独有特征 | 可能是真的，继续 |
| 与基线 md5 相同 / 是 WAF 页 / 是 404 回显 | 假阳性，丢弃 |
| 需要认证才能看到的东西被直接返回了 | 记下，这是结论 |

## 5. 存证据

每次确认都留三样东西：

```text
evidence/<VULN-ID>/
├── request-01.txt     完整请求（含 header）
├── response-01.txt    完整响应（或前 4KB + 长度）
└── verify-notes.md    时间、会话、复现步骤、影响面
```

**没有这三样的东西，不算发现。** 这是本仓库所有模块共同的纪律。

## 下一步

- 想知道为什么这么多假阳性 → [04-false-positive.md](04-false-positive.md)
- 想按场景抄作业 → [05-playbooks.md](05-playbooks.md)
- 想确认自己有没有越界 → [06-legal.md](06-legal.md)
