#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
peck —— Windows PE 授权校验的静态侦察与定点补丁

不需要 IDA / Ghidra / 调试器。用 pefile + capstone 把「找字符串 → 找引用 → 反汇编
→ 判定点 → 最小补丁 → 启动验证」这条链子脚本化，每一步都能复现。

子命令：
    info     节表 / 入口点 / 导入表 / 安全相关属性（ASLR、DEP、签名目录）
    strings  提取 ASCII 与 UTF-16LE 字符串，带 RVA 与文件偏移
    hunt     按关键词（试用/授权/注册/序列号/license/trial）筛候选字符串
    xref     扫描 .text 中指向某个 RVA 的指针字面量（x86/x64）
    dis      从指定 RVA 反汇编并标注跳转/字符串引用
    patch    按 RVA 或文件偏移写字节（自动备份 + 回读校验）

示例：
    python peck.py info app.exe
    python peck.py hunt app.exe
    python peck.py xref app.exe 0x41a2c
    python peck.py dis  app.exe 0x401220 -n 40
    python peck.py patch app.exe --rva 0x401234 --hex 90909090 --dry-run

⚠ 仅用于你自己拥有或获授权分析的软件。
"""
import argparse
import os
import shutil
import sys

try:
    import pefile
except ImportError:
    raise SystemExit("pefile required: pip install pefile")

KEYWORDS = ["试用", "授权", "注册", "序列号", "加密狗", "未找到", "非法修改", "到期",
            "剩余", "购买", "license", "licence", "trial", "expire", "activate",
            "serial", "dongle", "unregistered", "invalid key"]


def load(path):
    try:
        pe = pefile.PE(path, fast_load=False)
    except pefile.PEFormatError as e:
        raise SystemExit("not a PE file: %s" % e)
    return pe


def hx(n):
    return "0x%x" % n if n is not None else "-"


# ---------------------------------------------------------------- info
def cmd_info(a):
    pe = load(a.file)
    oh = pe.OPTIONAL_HEADER
    chars = oh.DllCharacteristics
    print("file        : %s" % a.file)
    print("size        : %d bytes" % os.path.getsize(a.file))
    print("machine     : %s  %s" % (pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "?"),
                                    "PE32+" if oh.Magic == 0x20B else "PE32"))
    print("timestamp   : 0x%08x" % pe.FILE_HEADER.TimeDateStamp)
    print("entry (RVA) : %s   imagebase=%s" % (hx(oh.AddressOfEntryPoint), hx(oh.ImageBase)))
    flags = [("ASLR", 0x40), ("DEP", 0x100), ("CFG", 0x4000), ("HIGH_ENTROPY_VA", 0x20)]
    print("mitigations : %s" % ", ".join(n for n, b in flags if chars & b) or "none")
    sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    print("signed      : %s" % ("yes (%d bytes)" % sec.Size if sec.Size else "no"))
    print("\n%-10s %-12s %-12s %-12s %s" % ("section", "vaddr", "vsize", "raw_off", "chars"))
    for s in pe.sections:
        print("%-10s %-12s %-12s %-12s %s"
              % (s.Name.decode("utf-8", "replace").rstrip("\x00"),
                 hx(s.VirtualAddress), hx(s.Misc_VirtualSize),
                 hx(s.PointerToRawData), hx(s.Characteristics)))
    try:
        imports = [(e.dll.decode(), [i.name.decode() if i.name else "ord%d" % i.ordinal
                                     for i in e.imports]) for e in pe.DIRECTORY_ENTRY_IMPORT]
        print("\n[IMPORTS] %d dll" % len(imports))
        for dll, names in imports:
            print("  %-28s %d funcs: %s" % (dll, len(names), ", ".join(names[:8])))
    except AttributeError:
        print("\n[IMPORTS] none")


# ---------------------------------------------------------------- strings
def iter_pe_strings(data, minlen=5):
    """ASCII"""
    cur, start = [], 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                yield start, bytes(cur).decode("ascii", "replace")
            cur = []


def iter_utf16_strings(data, minlen=5):
    """UTF-16LE：中文软件的主战场（每个 ASCII 字符后跟 \x00，汉字为双字节）"""
    i, n = 0, len(data)
    while i + 1 < n:
        start = i
        chars = []
        while i + 1 < n and (0x20 <= data[i] < 0x7F and data[i + 1] == 0):
            chars.append(chr(data[i]))
            i += 2
        if len(chars) >= minlen:
            yield start, "".join(chars)
            continue
        i = start + 1


def cmd_strings(a):
    pe = load(a.file)
    with open(a.file, "rb") as f:
        data = f.read()
    base = pe.OPTIONAL_HEADER.ImageBase
    gen = iter_pe_strings(data, a.min)
    for off, s in gen:
        if a.filter and a.filter.lower() not in s.lower():
            continue
        print("%-10s off=0x%-8x %s" % (hx(rva(pe, off)), off, s))
    if a.utf16:
        for off, s in iter_utf16_strings(data, a.min):
            if a.filter and a.filter.lower() not in s.lower():
                continue
            print("%-10s off=0x%-8x %s  [utf16]" % (hx(rva(pe, off)), off, s))


def rva(pe, off):
    try:
        return pe.get_rva_from_offset(off)
    except Exception:
        return None


def off_of(pe, rva_):
    try:
        return pe.get_offset_from_rva(rva_)
    except Exception:
        return None


def cmd_hunt(a):
    """关键词命中 = 授权校验的最好路标"""
    pe = load(a.file)
    with open(a.file, "rb") as f:
        data = f.read()
    hits = 0
    for enc, gen in (("ascii", iter_pe_strings(data, 4)), ("utf16", iter_utf16_strings(data, 3))):
        for off, s in gen:
            low = s.lower()
            if any(k.lower() in low for k in KEYWORDS):
                print("%-10s off=0x%-8x [%s] %s" % (hx(rva(pe, off)), off, enc, s[:90]))
                hits += 1
    print("\n%d candidate string(s) — 下一步用 xref 找谁引用了它们" % hits, file=sys.stderr)


# ---------------------------------------------------------------- xref
def cmd_xref(a):
    pe = load(a.file)
    target = int(a.target, 16)
    with open(a.file, "rb") as f:
        data = f.read()
    text = next((s for s in pe.sections if b".text" in s.Name), None)
    if not text:
        raise SystemExit("no .text section")
    lo = text.PointerToRawData
    hi = lo + text.SizeOfRawData
    is64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    hits = 0
    for width in ((8, 4) if is64 else (4,)):
        pat = target.to_bytes(width, "little")
        i = lo
        while True:
            i = data.find(pat, i, hi)
            if i < 0:
                break
            print("  ptr%d  off=0x%-8x rva=%s" % (width * 8, i, hx(rva(pe, i))))
            hits += 1
            i += 1
    print("\n%d reference(s) to RVA %s" % (hits, hx(target)), file=sys.stderr)


# ---------------------------------------------------------------- dis
def cmd_dis(a):
    try:
        import capstone
    except ImportError:
        raise SystemExit("capstone required: pip install capstone")
    pe = load(a.file)
    is64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
    md.detail = True
    base = pe.OPTIONAL_HEADER.ImageBase
    rva_ = int(a.rva, 16)
    off = off_of(pe, rva_)
    if off is None:
        raise SystemExit("rva not mapped")
    with open(a.file, "rb") as f:
        f.seek(off)
        code = f.read(a.count * 15 + 32)
    for ins in md.disasm(code, base + rva_):
        note = ""
        for op in ins.operands:
            if op.type == capstone.CS_OP_IMM and op.imm > base:
                t_rva = op.imm - base
                note += "  ; -> rva %s" % hx(t_rva)
                t_off = off_of(pe, t_rva)
                if t_off is not None:
                    with open(a.file, "rb") as f2:
                        f2.seek(t_off)
                        head = f2.read(48).split(b"\x00")[0]
                    if len(head) >= 4 and all(0x20 <= c < 0x7F for c in head):
                        note += ' "%s"' % head.decode("ascii", "replace")
        print("%s  %-8s %-30s %s" % (hx(ins.address), ins.mnemonic, ins.op_str, note))
        if ins.address - (base + rva_) >= a.count * 15:
            break


# ---------------------------------------------------------------- patch
def cmd_patch(a):
    pe = load(a.file)
    if a.rva:
        off = off_of(pe, int(a.rva, 16))
        if off is None:
            raise SystemExit("rva not mapped")
    else:
        off = int(a.off, 16)
    new = bytes.fromhex(a.hex.replace(" ", "").replace("0x", ""))
    with open(a.file, "rb") as f:
        f.seek(off)
        old = f.read(len(new))
    if len(old) != len(new):
        raise SystemExit("patch runs past EOF")
    print("file     : %s" % a.file)
    print("offset   : 0x%x  (rva %s)" % (off, hx(rva(pe, off))))
    print("before   : %s" % old.hex())
    print("after    : %s" % new.hex())
    if a.dry_run:
        print("\n[dry-run] nothing written")
        return
    bak = a.file + ".bak"
    if not os.path.exists(bak):
        shutil.copy2(a.file, bak)
        print("backup   : %s" % bak)
    with open(a.file, "r+b") as f:
        f.seek(off)
        f.write(new)
    with open(a.file, "rb") as f:
        f.seek(off)
        got = f.read(len(new))
    print("verify   : %s  %s" % (got.hex(), "OK" if got == new else "FAILED"))


def main():
    p = argparse.ArgumentParser(description="PE license-check recon / patch toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("info"); q.add_argument("file"); q.set_defaults(fn=cmd_info)

    q = sub.add_parser("strings"); q.add_argument("file")
    q.add_argument("-m", "--min", type=int, default=5)
    q.add_argument("-f", "--filter", default="")
    q.add_argument("--utf16", action="store_true"); q.set_defaults(fn=cmd_strings)

    q = sub.add_parser("hunt"); q.add_argument("file"); q.set_defaults(fn=cmd_hunt)

    q = sub.add_parser("xref"); q.add_argument("file"); q.add_argument("target")
    q.set_defaults(fn=cmd_xref)

    q = sub.add_parser("dis"); q.add_argument("file"); q.add_argument("rva")
    q.add_argument("-n", "--count", type=int, default=40); q.set_defaults(fn=cmd_dis)

    q = sub.add_parser("patch"); q.add_argument("file")
    g = q.add_mutually_exclusive_group(required=True)
    g.add_argument("--rva"); g.add_argument("--off")
    q.add_argument("--hex", required=True)
    q.add_argument("--dry-run", action="store_true"); q.set_defaults(fn=cmd_patch)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
