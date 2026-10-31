# pe-patch — Windows PE 授权校验分析

`tools/peck.py`：不需要 IDA，不需要调试器（目标带反调试时这点很关键）。
pefile + capstone 五步走：**找路标 → 找引用 → 看判定 → 最小补丁 → 验证启动**。

## 子命令

| 子命令 | 作用 | 关键点 |
| --- | --- | --- |
| `info` | 节表 / 入口 / 导入表 / ASLR·DEP·CFG / 签名目录 | 先确认是否 32/64 位、是否加壳 |
| `strings` | ASCII + UTF-16LE 双编码提取，带 RVA 与文件偏移 | 中文软件必须看 UTF-16LE |
| `hunt` | 按试用/授权/注册/序列号/license/trial 等关键词筛字符串 | 路标一次列全 |
| `xref` | 扫 `.text` 里指向某 RVA 的指针字面量 | 32 位扫 4 字节，64 位加扫 8 字节 |
| `dis` | 从 RVA 反汇编，标注跳转目标与字符串引用 | `call`/`jz` 后面跟的提示串最有用 |
| `patch` | 按 RVA 或偏移写字节 | 自动备份 + 回读校验 |

## 标准工作流

```bash
# 1) 摸清目标
python tools/peck.py info app.exe

# 2) 找授权检查的路标字符串
python tools/peck.py hunt app.exe
python tools/peck.py strings app.exe --utf16 -f 试用

# 3) 谁引用了这个字符串
python tools/peck.py xref app.exe 0x2f3a0

# 4) 看判定逻辑
python tools/peck.py dis app.exe 0x401220 -n 40

# 5) 最小补丁：先 dry-run 确认偏移
python tools/peck.py patch app.exe --rva 0x401234 --hex 90909090 --dry-run
python tools/peck.py patch app.exe --rva 0x401234 --hex 90909090
```

## 判定点常见的三种形态

| 形态 | 汇编特征 | 最小补丁 |
| --- | --- | --- |
| 条件跳转决定成败 | `test eax,eax` / `jz 0x...` | `jz` → `jmp`（`74 xx` → `EB xx`）或整条 `nop` |
| 早期返回 | `xor eax,eax` / `ret` | `xor eax,eax` → `mov eax,1`（`33 C0` → `B0 01`） |
| 提示串分支 | `push offset "试用期已到期"`，随后 `jmp` | 把跳转目标改到正常流程 |

> 改之前先确认这段代码**没被完整性校验覆盖**——`hunt` 里出现"文件被非法修改"
> 这类字符串，通常说明有 CRC/签名自检，直接改字节会触发。这种目标要用
> 内存补丁或先定位校验函数。

## `patch` 的安全设计

- `before` / `after` 先打印，`--dry-run` 只看不写；
- 首次写入前备份 `<file>.bak`；
- 写完回读比对并输出 `OK` / `FAILED`；
- 超出 EOF 直接拒绝。

## 边界

只对自己拥有或**书面授权**的软件使用。商业软件逆向的合法性因辖区而异，
拿不准就先问法律意见，别拿"我只是研究"当免责符。见 [DISCLAIMER.md](../../DISCLAIMER.md)。
