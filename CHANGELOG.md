# 变更记录

遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.1.0] - 2026-10-31

把「跑完一条链路」和「交出一份能复核的证据」补上。

### 新增

- **`src-hunt/rkhunt.py`** —— 全链路编排器：`run` / `status` / `list` 三个子命令。
  七阶段依赖图（`recon → subs → probe → alive → {unauth, js, param, targeted}`，`oss` 只依赖 `subs`），
  状态写 `<workdir>/run.json`，支持 `--only` / `--skip` / `--dry-run` / `--keep-going`。
  实测：`probe` 段在 example.com 上 exit=0、2 条；`js` / `targeted` 空任务也落空产物并 exit=0。
- **`tools/evidkit.py`** —— 证据包与报告：`new` / `add` / `seal` / `verify` / `report`。
  每次抓包记 sha256 + 字节数；`seal` 之后任何改动都会被 `verify` 检出
  （实测篡改 `response-02.txt` → 哈希不符 → exit 1）。
  `report` 从 `meta.json` + 最新抓包 + `verify-notes.md` 渲染 Markdown。
- **`check.py`** —— 本地自检（编译 / CLI 冒烟 / 真实资产守卫 / pyflakes），
  替代暂不可用的 GitHub Actions；守卫会拦下真实厂商域名、内网 IP、云 AK、GitHub token。

### 变更

- 栈指纹 43 → **57** 条，新增 Nacos 2.x Console / MinIO / K8s Dashboard / Harbor / Consul /
  Eureka / SkyWalking / YApi / XXL-JOB / Apollo Config / RabbitMQ / Portainer / ShardingSphere / Seata。
- 收紧 6 条噪声指纹（Jenkins / Nacos / Vue / React / Solr / Go）——不再用 `id="app"`、`react`、
  `net/http` 这类通用词，否则任何页面都能命中（已用 `id="app"`、`<h2>title</h2>` 做反向验证）。
- `targeted.py` 新增 `--targets`，可直接吃 `probe.py` 的 `alive.json`；
  无带栈主机时输出空数组并以 `0` 退出（空任务不等于失败）。
- `docs/05-playbooks.md` 的 Playbook 1 与证据包章节改用 `rkhunt` / `evidkit`。

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
