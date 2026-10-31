# binary-re — ELF / `.so` 静态分析

`tools/elfkit.py`：不依赖 IDA / Ghidra，用标准库 + capstone 把
「查结构 → 找字符串 → 找引用 → 反汇编 → 打补丁」脚本化。

## 子命令

| 子命令 | 作用 | 依赖 |
| --- | --- | --- |
| `info` | 节表 / 程序头 / 动态符号（导入导出）/ sha256 | 标准库 |
| `strings` | 提取可打印字符串并标注虚拟地址 | 标准库 |
| `xref` | 扫描指向某虚拟地址的引用（指针字面量 + AArch64 `adrp`+`add`） | 标准库 |
| `dis` | 从虚拟地址反汇编，标注跳转目标与字符串引用 | `capstone` |
| `patch` | 按文件偏移或虚拟地址写字节，自动备份 + 回读校验 | 标准库 |

## 用法

```bash
# 结构总览
python tools/elfkit.py info libfoo.so

# 找授权相关字符串
python tools/elfkit.py strings libfoo.so -m 6 -f licen
python tools/elfkit.py strings libfoo.so -m 6 -f 试用

# 谁引用了这个字符串（AArch64 会走 adrp+add 解析）
python tools/elfkit.py xref libfoo.so 0x2a1c0

# 判定点反汇编
python tools/elfkit.py dis libfoo.so 0x2ad50 -n 60

# 补丁（先 dry-run）
python tools/elfkit.py patch libfoo.so --vaddr 0x2ad74 --hex 1f2003d5 --dry-run
python tools/elfkit.py patch libfoo.so --vaddr 0x2ad74 --hex 1f2003d5
```

## 为什么 `xref` 要单独实现 `adrp`+`add`

ARM64 位置无关代码**不会**把地址写成完整字面量。取一个字符串的地址长这样：

```asm
0x9cc74  adrp x0, #0x54000      ; 先取 4KB 页基址
0x9cc78  add  x0, x0, #0x760    ; 再加页内偏移
```

所以「搜 8 字节地址」在 ARM64 上基本永远搜不到。`elfkit` 会解码
`adrp` 的 `immlo/immhi`（21 位有符号立即数，左移 12 位）加上 `add` 的 `imm12`
（注意 `sh` 位可能再左移 12），拼出目标地址再比对。

在 `libc++_shared.so` 上实测：目标 `0x54760` 命中 3 处 `adrp+add`，地址精确对齐。

## `patch` 的安全设计

1. 先打印 `before` / `after`，`--dry-run` 可只看不写；
2. 首次写入前自动备份成 `<file>.bak`（已存在则不复盖，避免把好备份冲掉）；
3. 写完**回读**并比对，输出 `OK` / `FAILED`；
4. 补丁长度超出 EOF 时直接拒绝，不做部分写入。

## 常见坑

- **`.dynstr` 里的字符串不等于 `.rodata` 里的**：动态符号表的字符串只被重定位引用，
  `xref` 查不到是正常的，别以为工具坏了。
- **节 addr = 0 的段**（如某些 `.rela` 后段）要跳过，否则 `v2o` 会算错；`elfkit` 里已过滤 `type != 8`。
- **strip 过的库没有 `.symtab`**，只能靠 `.dynsym` + `strings` + 反汇编硬找，属正常流程。
