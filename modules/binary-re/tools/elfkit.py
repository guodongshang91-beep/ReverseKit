#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
elfkit —— ELF 二进制侦察 / 反汇编 / 定点打补丁（Linux / Android .so 通用）

只依赖标准库；`dis` 子命令额外需要 capstone（pip install capstone）。

子命令：
    info    节表 / 程序头 / 动态符号（导入导出）
    strings 提取可打印字符串并标注虚拟地址
    xref    在 .text 里扫描指向某个虚拟地址的引用（指针字面量 + AArch64 adrp/add）
    dis     从指定虚拟地址开始反汇编，自动标注跳转目标与字符串引用
    patch   按文件偏移或虚拟地址写入字节（自动备份 + 校验）

示例：
    python elfkit.py info   libfoo.so
    python elfkit.py strings libfoo.so --min 6 | grep -i -E 'licen|trial'
    python elfkit.py xref   libfoo.so 0x3a1c0
    python elfkit.py dis    libfoo.so 0x2ad50 -n 60
    python elfkit.py patch  libfoo.so --vaddr 0x2ad74 --hex 1f2003d5
"""
import argparse
import hashlib
import os
import shutil
import struct
import sys

EM = {3: "x86", 8: "MIPS", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}


class ELF:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise SystemExit("not an ELF file: %s" % path)
        self.is64 = d[4] == 2
        self.e = "<" if d[5] == 1 else ">"
        if self.is64:
            vals = struct.unpack_from(self.e + "HHIQQQIHHHHHH", d, 16)
        else:
            vals = struct.unpack_from(self.e + "HHIIIIIHHHHHH", d, 16)
        (self.e_type, self.e_machine, _v, self.e_entry, self.e_phoff, self.e_shoff,
         self.e_flags, _eh, self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, self.e_shstrndx) = vals

        # ---- sections ----
        self.secs = []
        fmt = self.e + ("IIQQQQIIQQ" if self.is64 else "IIIIIIIIII")
        for i in range(self.e_shnum):
            o = self.e_shoff + i * self.e_shentsize
            v = struct.unpack_from(fmt, d, o)
            self.secs.append(dict(name_off=v[0], type=v[1], flags=v[2], addr=v[3],
                                  off=v[4], size=v[5], link=v[6], info=v[7],
                                  align=v[8], entsize=v[9]))
        shstr = self.secs[self.e_shstrndx] if self.secs else None
        for s in self.secs:
            s["name"] = self._cstr(shstr["off"] + s["name_off"]) if shstr else ""
        self.by_name = {s["name"]: s for s in self.secs}

        # ---- segments ----
        self.loads = []
        fmt = self.e + ("IIQQQQQQ" if self.is64 else "IIIIIIII")
        for i in range(self.e_phnum):
            o = self.e_phoff + i * self.e_phentsize
            v = struct.unpack_from(fmt, d, o)
            if v[0] == 1:  # PT_LOAD
                self.loads.append(dict(off=v[2], vaddr=v[3], filesz=v[5], memsz=v[6]))

    def _cstr(self, off):
        end = self.data.index(b"\x00", off)
        return self.data[off:end].decode("utf-8", "replace")

    def v2o(self, va):
        """虚拟地址 -> 文件偏移"""
        for s in self.secs:
            if s["addr"] and s["addr"] <= va < s["addr"] + s["size"] and s["type"] != 8:
                return s["off"] + (va - s["addr"])
        for L in self.loads:
            if L["vaddr"] <= va < L["vaddr"] + L["filesz"]:
                return L["off"] + (va - L["vaddr"])
        return None

    def o2v(self, off):
        for s in self.secs:
            if s["off"] and s["off"] <= off < s["off"] + s["size"] and s["type"] != 8:
                return s["addr"] + (off - s["off"])
        for L in self.loads:
            if L["off"] <= off < L["off"] + L["filesz"]:
                return L["vaddr"] + (off - L["off"])
        return None

    def text_range(self):
        """可执行段的 (文件起始, 文件结束, 虚拟地址)"""
        t = self.by_name.get(".text")
        if t:
            return t["off"], t["off"] + t["size"], t["addr"]
        for L in self.loads:
            return L["off"], L["off"] + L["filesz"], L["vaddr"]
        return 0, len(self.data), 0

    def dynsyms(self):
        """返回 (imports, exports)，符号名 + 相对地址"""
        out = []
        dynsym = self.by_name.get(".dynsym")
        dynstr = self.by_name.get(".dynstr")
        if not dynsym or not dynstr:
            return out
        step = 24 if self.is64 else 16
        fmt = self.e + ("IBBHQQ" if self.is64 else "IIIBBH")
        n = dynsym["size"] // step
        for i in range(n):
            v = struct.unpack_from(fmt, self.data, dynsym["off"] + i * step)
            if self.is64:
                name_off, info, _other, shndx, value, size = v
            else:
                name_off, value, size, info, _other, shndx = v
            if not name_off:
                continue
            name = self._cstr(dynstr["off"] + name_off)
            kind = "IMPORT" if shndx == 0 else "EXPORT"
            out.append((kind, name, value, size))
        return out


def hx(n):
    return "unknown" if n is None else "0x%x" % n


# ---------------------------------------------------------------- info
def cmd_info(a):
    d = ELF(a.file)
    print("file      : %s" % d.path)
    print("size      : %d bytes  sha256=%s" % (len(d.data), hashlib.sha256(d.data).hexdigest()[:16]))
    print("class     : %s  %s  %s" %
          ("ELF64" if d.is64 else "ELF32", "LSB" if d.e == "<" else "MSB",
           EM.get(d.e_machine, "machine=%d" % d.e_machine)))
    print("type      : %d   entry=%s" % (d.e_type, hx(d.e_entry)))
    print("sections  : %d   program headers: %d" % (len(d.secs), d.e_phnum))
    print("\n[LOAD]")
    for L in d.loads:
        print("  vaddr=%-12s filesz=%-8s memsz=%-8s off=%s"
              % (hx(L["vaddr"]), hx(L["filesz"]), hx(L["memsz"]), hx(L["off"])))
    print("\n[SECTIONS]")
    print("  %-18s %-10s %-12s %-12s %-8s %s" % ("name", "type", "addr", "off", "size", "flags"))
    for s in d.secs:
        if not s["name"]:
            continue
        print("  %-18s %-10d %-12s %-12s %-8s %s"
              % (s["name"][:18], s["type"], hx(s["addr"]), hx(s["off"]),
                 hx(s["size"]), "W" if s["flags"] & 1 else "-"))
    syms = d.dynsyms()
    if syms and not a.quiet:
        imp = [s for s in syms if s[0] == "IMPORT"]
        exp = [s for s in syms if s[0] == "EXPORT"]
        print("\n[DYNSYM] imports=%d exports=%d" % (len(imp), len(exp)))
        for kind, name, val, size in imp[:a.limit]:
            print("  IMPORT  %-40s (undef)" % name)
        for kind, name, val, size in exp[:a.limit]:
            print("  EXPORT  %-40s %s  size=%s" % (name, hx(val), hx(size)))


# ---------------------------------------------------------------- strings
def iter_strings(data, minlen):
    cur, start = [], 0
    printable = set(range(0x20, 0x7F)) | {9}
    for i, b in enumerate(data):
        if b in printable:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                yield start, bytes(cur).decode("ascii", "replace")
            cur = []


def cmd_strings(a):
    d = ELF(a.file)
    for off, s in iter_strings(d.data, a.min):
        if a.filter and a.filter.lower() not in s.lower():
            continue
        print("%s  off=0x%-8x %s" % (hx(d.o2v(off)), off, s))


# ---------------------------------------------------------------- xref
def cmd_xref(a):
    d = ELF(a.file)
    target = int(a.target, 16) if not a.target.lower().startswith("0x") else int(a.target, 16)
    lo, hi, _tva = d.text_range()
    hits = 0
    for width in (8, 4):
        pat = struct.pack(d.e + ("Q" if width == 8 else "I"), target)
        i = lo
        while True:
            i = d.data.find(pat, i, hi)
            if i < 0:
                break
            print("  ptr%d  file_off=0x%-8x vaddr=%s" % (width * 8, i, hx(d.o2v(i))))
            hits += 1
            i += 1
    if d.e_machine == 183:
        hits += aarch64_adrp_add(d, target, lo, hi)
    print("\n%d reference(s) to %s" % (hits, hx(target)), file=sys.stderr)


def aarch64_adrp_add(d, target, lo, hi):
    """识别 adrp Xn, #page 紧跟 add Xn, Xn, #lo12 的指令对 -> 页内偏移组合出目标地址"""
    hits = 0
    for off in range(lo, hi - 8, 4):
        w1 = struct.unpack_from("<I", d.data, off)[0]
        if (w1 & 0x9F000000) != 0x90000000:      # ADRP
            continue
        va = d.o2v(off)
        if va is None:
            continue
        immlo = (w1 >> 29) & 3
        immhi = (w1 >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (va & ~0xFFF) + (imm << 12)
        w2 = struct.unpack_from("<I", d.data, off + 4)[0]
        if (w2 & 0xFF800000) == 0x91000000:      # ADD (immediate)
            imm12 = (w2 >> 10) & 0xFFF
            sh = (w2 >> 22) & 1
            if sh:
                imm12 <<= 12
            if page + imm12 == target:
                print("  adrp+add  file_off=0x%-8x vaddr=%s  -> %s"
                      % (off, hx(va), hx(target)))
                hits += 1
    return hits


# ---------------------------------------------------------------- dis
def cmd_dis(a):
    try:
        import capstone
    except ImportError:
        raise SystemExit("capstone required: pip install capstone")
    d = ELF(a.file)
    arch = {62: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            3: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            183: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            40: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            8: (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32)}.get(d.e_machine)
    if not arch:
        raise SystemExit("unsupported machine %d" % d.e_machine)
    md = capstone.Cs(*arch)
    md.detail = True
    va = int(a.vaddr, 16)
    off = d.v2o(va)
    if off is None:
        raise SystemExit("vaddr %s not mapped in file" % a.vaddr)
    code = d.data[off:off + a.count * 4 + 16]
    for ins in md.disasm(code, va):
        note = ""
        for op in ins.operands:
            if op.type == capstone.CS_OP_IMM:
                note += "  ; -> %s" % hx(op.imm)
                s = d.v2o(op.imm)
                if s is not None and s < len(d.data):
                    head = d.data[s:s + 42].split(b"\x00")[0]
                    if head and all(0x20 <= c < 0x7F for c in head) and len(head) >= 4:
                        note += ' "%s"' % head.decode("ascii", "replace")
        print("%s  %-8s %-28s %s" % (hx(ins.address), ins.mnemonic, ins.op_str, note))
        if ins.address - va >= a.count * 4:
            break


# ---------------------------------------------------------------- patch
def cmd_patch(a):
    d = ELF(a.file)
    if a.vaddr:
        off = d.v2o(int(a.vaddr, 16))
        if off is None:
            raise SystemExit("vaddr not mapped: %s" % a.vaddr)
    else:
        off = int(a.off, 16)
    new = bytes.fromhex(a.hex.replace(" ", "").replace("0x", ""))
    old = d.data[off:off + len(new)]
    if len(old) != len(new):
        raise SystemExit("patch runs past EOF")
    print("file     : %s" % a.file)
    print("offset   : 0x%x  (vaddr %s)" % (off, hx(d.o2v(off))))
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
    d2 = ELF(a.file)
    check = d2.data[off:off + len(new)]
    print("verify   : %s  %s" % (check.hex(), "OK" if check == new else "FAILED"))


def main():
    p = argparse.ArgumentParser(description="ELF recon / disasm / patch toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("info"); q.add_argument("file")
    q.add_argument("-l", "--limit", type=int, default=25)
    q.add_argument("-q", "--quiet", action="store_true"); q.set_defaults(fn=cmd_info)

    q = sub.add_parser("strings"); q.add_argument("file")
    q.add_argument("-m", "--min", type=int, default=5)
    q.add_argument("-f", "--filter", default=""); q.set_defaults(fn=cmd_strings)

    q = sub.add_parser("xref"); q.add_argument("file"); q.add_argument("target")
    q.set_defaults(fn=cmd_xref)

    q = sub.add_parser("dis"); q.add_argument("file"); q.add_argument("vaddr")
    q.add_argument("-n", "--count", type=int, default=80); q.set_defaults(fn=cmd_dis)

    q = sub.add_parser("patch"); q.add_argument("file")
    g = q.add_mutually_exclusive_group(required=True)
    g.add_argument("--off"); g.add_argument("--vaddr")
    q.add_argument("--hex", required=True)
    q.add_argument("--dry-run", action="store_true"); q.set_defaults(fn=cmd_patch)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
