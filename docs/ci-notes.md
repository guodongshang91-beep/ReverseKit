# CI：现在跑什么，以及踩过的两个坑

## 现状：CI 已启用

工作流文件：[`.github/workflows/ci.yml`](../.github/workflows/ci.yml)（本目录的
[`ci-template.yml`](ci-template.yml) 是它的副本，留作引用）。

矩阵 **Ubuntu + Windows × Python 3.9 / 3.12**，跑的是 `python check.py`——
和本地自检**完全同一套标准**，避免「CI 说行、本地不行」：

1. `compileall` 全量字节编译（阻断）
2. 12 个命令行工具 `-h` 冒烟（阻断）
3. 真实资产 / 凭据守卫：厂商域名、内网 IP、云 AK、`ghp_` token（阻断）
4. `pyflakes`（装了才跑，非阻断）

Windows 格外跑一次真实 PE 分析（`peck info notepad.exe`），验证 pefile 链路能用。

---

## 坑 1：Windows runner 上 `-h` 直接崩

第一次跑 CI 时 Windows 两个格全挂，Ubuntu 全过：

```text
UnicodeEncodeError: 'charmap' codec can't encode characters in position 52-58
```

原因是 **Windows 的 Python stdout 默认 `cp1252`**，而工具的 help 文本是中文，
`argparse.print_help()` 一写就炸。开发机控制台是 UTF-8，所以本地永远复现不出来。

这不是 CI 配置问题，是工具的跨平台缺陷。修法（已落到每个工具的开头）：

```python
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
```

CI 里再加一道 `env: PYTHONIOENCODING: utf-8` 双保险。
本地想复现这个 bug：`PYTHONIOENCODING=cp1252 python <tool>.py -h`。

## 坑 2：token 缺 `workflow` 权限时推不上去

GitHub 对 `.github/workflows/` 下**任何文件**都做保护，连 `README.md` 都算 workflow：

```text
! [remote rejected] main -> main (refusing to allow a Personal Access Token to
  create or update workflow `.github/workflows/ci.yml` without `workflow` scope)
```

当时发布用的 token 没有 `workflow`，所以 CI 一度只能写成模板放着。
后来换成带 `workflow` 的 token（classic PAT 勾 `repo` + `workflow`，
或 fine-grained 把 **Workflows** 设为 *Read and write*）后正常推送。

判断当前 token 有没有这个权限：

```bash
curl -s -D - -o /dev/null -H "Authorization: token $T" https://api.github.com/user \
  | tr -d '\r' | grep -i x-oauth-scopes
```

输出里有 `workflow` 才行。

---

想改检查项？改 [`check.py`](../check.py) 一个文件就够，CI 和本地同步生效。
