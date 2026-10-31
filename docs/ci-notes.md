# 为什么这里没有 ci.yml

推送 GitHub Actions 工作流文件，Personal Access Token 必须带 `workflow` 权限。
本仓库首次发布所用的 token 只有 `repo` 权限，GitHub 直接拒收了 `ci.yml`（`refusing to
allow a Personal Access Token to create or update workflow ... without workflow scope`）。

**启用 CI 的方法**：把 [`ci-template.yml`](ci-template.yml) 复制成
`.github/workflows/ci.yml` 再提交——用带 `workflow` 权限的 token，或在网页端
「Add file → Create new file」直接粘贴。

模板内容：

1. `python -m compileall -q modules` —— 全量字节编译（阻断项）
2. `python -m pyflakes modules` —— 静态检查（非阻断，先当提示用）
3. 每个命令行工具的 `-h` 冒烟测试
4. Windows runner 上跑一次真实的 PE 分析（`peck info notepad.exe`）
5. 守卫：仓库里出现真实厂商域名直接 fail

矩阵：Ubuntu + Windows × Python 3.9 / 3.12。
