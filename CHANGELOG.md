# 变更记录

遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-10-31

首个公开版本：六个模块、统一 CLI 风格、完整文档。

### 新增

- **web-recon**：`dnsx`（自实现 DNS 报文解析，零依赖）、`probe`（存活 + 软 404 基线）、
  `jsonp_fuzz`（回调参数注入）、`headers_check`（响应头审计）。
- **src-hunt**：`recon` / `probe` / `unauth_scan` / `oss_scan` / `js_harvest` /
  `param_probe` / `targeted` / `dsstore_parse` / `targets` 九个脚本，
  五道假阳性防线内建于 `unauth_scan`。
- **binary-re**：`elfkit` —— `info` / `strings` / `xref` / `dis` / `patch` 五子命令，
  含 AArch64 `adrp`+`add` 指令对解码。
- **pe-patch**：`peck` —— `info` / `strings` / `hunt` / `xref` / `dis` / `patch` 六子命令，
  UTF-16LE 字符串支持，补丁自动备份 + 回读校验。
- **wifi**：`capture`（错误密钥触发握手，无需监听模式）、`capture_mon`（监听模式 + deauth）、
  `analyze`（22000 格式 + 合成自检）、`gen_dict`。
- **android**：`aar_extract`（list/jar/so 三子命令）、`res_check`、`syntax_check`。

### 文档

- `docs/04-false-positive.md`：五道防线的完整判定逻辑与实测数据。
- `docs/05-playbooks.md`：四套可照抄的流程（SRC / 漏洞判定 / PE / ELF）。
- `docs/06-legal.md`：授权边界、法律依据、常见误区。
- `docs/07-faq.md`：22 个高频问题。

### 安全

- 全部脚本移除硬编码的目标网络、厂商资产与本地绝对路径，改为运行时参数
  （`--ssid` / `--bssid` / `--csv` / `--targets` 或环境变量 `RK_*`）。
- 仓库不含任何真实目标、凭据、抓包与漏洞证据。

### 已知限制

- `wifi` 模块只在 Windows + Npcap 上完整可用。
- `pdf`/`dis` 子命令需要 `capstone`。
- 未实现证据包自动归档与报告生成（见路线图）。
