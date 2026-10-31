# 关于 CI：为什么这里没有 ci.yml，以及现在怎么办

## 现状

推送 GitHub Actions 工作流文件时，Personal Access Token **必须带 `workflow` 权限**。
本仓库发布时用过的两个 token 权限集完全相同，都**没有** `workflow`
（`X-OAuth-Scopes` 里有 `repo`、`admin:org`、`delete_repo` 等，就是没有 `workflow`），
GitHub 直接拒收：

```text
! [remote rejected] main -> main (refusing to allow a Personal Access Token to
  create or update workflow `.github/workflows/ci.yml` without `workflow` scope)
```

注意：这个限制覆盖 `.github/workflows/` 下**所有文件**，连一个 README.md 都算 workflow。

## 所以：自检搬到了本地

[`check.py`](../check.py) 把 CI 要干的事在本地做完了，不依赖 Actions：

```bash
python check.py            # 全跑
python check.py --quick    # 只跑编译 + 守卫
```

1. `compileall` 全量字节编译（阻断）
2. 每个命令行工具 `-h` 冒烟（阻断）
3. 真实厂商域名 / 内网 IP / 凭据守卫（阻断）
4. `pyflakes` 静态检查（非阻断，装了才跑）

## 想要真正的 Actions

两种办法，任选：

**A. 网页端建文件（最快，1 分钟）**
仓库页 → Add file → Create new file → 路径填 `.github/workflows/ci.yml`
→ 把 [`ci-template.yml`](ci-template.yml) 的内容粘进去 → Commit。

**B. 换一个带 `workflow` 权限的 token**
Classic PAT：Settings → Developer settings → Tokens (classic) → 勾 `repo` + **`workflow`**。
Fine-grained PAT：仓库权限里把 **Workflows** 设为 *Read and write*。
拿到后正常 `git push` 即可，不需要改任何文件。

## 模板内容

1. `compileall`（阻断）
2. `pyflakes`（提示）
3. 各工具 `-h` 冒烟
4. Windows runner 上跑一次真实 PE 分析（`peck info notepad.exe`）
5. 守卫：仓库里出现真实厂商域名直接 fail

矩阵：Ubuntu + Windows × Python 3.9 / 3.12。
