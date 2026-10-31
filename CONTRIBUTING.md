# 贡献指南

先读这三条，能省掉一轮 review：

1. **只加检测不叫贡献，加了防线才算。** 任何新增的"命中"规则必须同时给出对应的
   假阳性判定（基线比对 / 收紧正则 / 去重 / WAF 页 / 回显识别）。
2. **不放真实目标。** 域名、IP、厂商名、凭据、样本、漏洞证据一律用占位符。
   PR 里出现真实资产会被直接关闭。
3. **脚本要能 `-h` 自解释。** 参数、输出字段、退出码写清楚，别让人读源码猜。

---

## 提交前自检

```bash
# 语法
python -m compileall -q modules && echo OK

# 静态检查（可选但推荐）
pip install pyflakes && python -m pyflakes modules

# 自己跑一遍改动的脚本
python modules/<mod>/<tool>.py -h
```

CI 会跑 `compileall`（阻断）与 `pyflakes`（提示）。仓库当前**未启用** Actions——
启用方法见 [docs/ci-notes.md](docs/ci-notes.md)。
没开 CI 时请自己跑上面两条命令。

---

## 代码风格

- Python 3.9+ 语法；**只用标准库 + requirements.txt 里已有的包**，不要新增重依赖。
- 单个脚本保持可独立运行（不依赖包内 import 路径）。
- `--dry-run` 模式的写操作工具必须有；备份命名统一 `<file>.bak`。
- 中文注释写"为什么"，不写"这行在做什么"。
- 日志/输出用 `print` 到 stdout，诊断信息用 `file=sys.stderr`，方便管道处理。

## 新增探测规则的模板

```python
# 1) 特征串只挑组件独有词，不用 HTML 通用词
SIG = r"(?i)(H2\s*Console|org\.h2\.server\.web)"

# 2) 必须经过三重过滤才允许进入结果
def judge(r, base, path):
    if r.status_code == base["status"] and md5(r.content) == base["md5"]:
        return None                       # 防线 1：catch-all
    if re.search(WAF_BLOCK, r.text[:4096]):
        return None                       # 防线 4：WAF 页
    tail = path.strip("/").split("/")[-1]
    if re.search(ERR_ECHO, r.text[:2048]) and tail in r.text[:2048]:
        return None                       # 防线 5：404 回显
    m = re.search(SIG, r.text[:8192])
    return m.group(0) if m else None
```

## 提交流程

```bash
git checkout -b feat/your-thing
# 改代码 + 补文档
python -m compileall -q modules
git commit -m "feat(src-hunt): 新增 X 组件未授权探测（含假阳性防线）"
git push origin feat/your-thing
```

PR 描述里请写清：

- 新增/修改了什么，为什么；
- 对应的假阳性防线是什么；
- 你在什么目标类型上验证过（**只说类型，不说具体目标**）；
- 有没有已知限制。

## 文档改动

`docs/` 下每篇都有明确职责，别混着写：

| 文件 | 只放什么 |
| --- | --- |
| `00-quickstart.md` | 5 分钟能跑通的最短路径 |
| `01-architecture.md` | 分层、数据流、扩展点 |
| `02-install.md` | 依赖矩阵、平台坑 |
| `03-modules.md` | 参数手册（查表用） |
| `04-false-positive.md` | 判定方法论（最重要，改动需谨慎） |
| `05-playbooks.md` | 可照抄的流程 |
| `06-legal.md` | 授权边界 |
| `07-faq.md` | 高频疑问 |

## 行为准则

对事不对人。技术分歧拿数据说话——"我这里复现不出来"比"你这个是错的"有用得多。
人身攻击、炫技式贬低、公开他人未修复漏洞，一次即移除协作资格。

## 许可

提交即表示你同意以 [MIT](LICENSE) 许可发布你的贡献。
