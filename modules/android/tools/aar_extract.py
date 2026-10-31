# -*- coding: utf-8 -*-
"""从 AAR 里抽出能用于**手工构建 APK** 的两样东西：Java 类 + 原生库。

为什么需要它：
    没有 Gradle 时（Gradle 在部分机器上初始化 native 库会失败），AAR 没人帮你解。
    但 AAR 就是个 zip，自己拆完全可行 —— 手工路线照样能用第三方库。

用法：
    # 1) 合并多个 aar 的 classes.jar → 一个 jar（javac/d8 直接用）
    python aar_extract.py jar libs/aar/*.aar -o build/libs.jar

    # 2) 抽出指定 ABI 的原生库，并按 APK 内的路径命名
    python aar_extract.py so libs/aar/*.aar --abi arm64-v8a -o build/jni

    # 3) 只看看里面有什么（不确定该抽什么的时候先跑这个）
    python aar_extract.py list libs/aar/*.aar

依赖链提醒：
    一个库的 Maven 坐标常不止一个 artifact，缺一个就连编译都过不去。
    典型例子（TFLite 2.14）：tensorflow-lite 的 classes.jar 只有 12 个类，
    Tensor / DataType / Delegate / InterpreterApi 全在 tensorflow-lite-api 里；
    GpuDelegate 的构造签名依赖 GpuDelegateFactory，而它在 tensorflow-lite-gpu-api 里。
    漏了哪个，javac 会报「找不到符号」，那时回头看 .pom 的 <dependencies> 最快。
"""
import sys
if hasattr(sys.stdout, "reconfigure"):   # Windows 控制台默认 cp1252，中文输出会直接崩
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


import argparse
import io
import os
import sys
import zipfile
from pathlib import Path

# 合并进最终 jar 时要跳过的东西：签名/清单会和最终 APK 的冲突，
# 而且多个 jar 的 MANIFEST 同名会让 d8 报 duplicate class。
SKIP_PREFIX = ("META-INF/",)


def cmd_list(args):
    for a in args.aars:
        if not Path(a).exists():
            print("缺文件：%s" % a)
            continue
        print("=== %s (%.1f KB)" % (a, os.path.getsize(a) / 1024))
        with zipfile.ZipFile(a) as z:
            names = z.namelist()
            # ★ 内层 jar 的类必须**从内层 jar 里读**，不能拿 AAR 自己的条目去数 ——
            # AAR 的 namelist 里只有 "classes.jar" 这一个条目，数出来永远是 0 个 class。
            inner = {}
            for n in names:
                if n.endswith(".jar"):
                    inner[n] = z.read(n)
        sos = [n for n in names if n.endswith(".so")]
        hdrs = [n for n in names if n.endswith(".h")]

        for n, data in sorted(inner.items()):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as iz:
                    cls = [x for x in iz.namelist() if x.endswith(".class")]
                    pkgs = sorted({x.rsplit("/", 1)[0].replace("/", ".") for x in cls if "/" in x})
            except zipfile.BadZipFile:
                print("    jar  %-34s （不是合法的 jar）" % n)
                continue
            print("    jar  %-34s %3d 个 .class   %s"
                  % (n, len(cls), ", ".join(pkgs[:6]) + (" ..." if len(pkgs) > 6 else "")))

        d = {}
        for s in sos:
            abi = s.split("/")[1] if s.count("/") >= 2 else "?"
            d.setdefault(abi, []).append(os.path.basename(s))
        for abi, fs in sorted(d.items()):
            print("    so   %-12s %s" % (abi, ", ".join(fs)))
        if hdrs:
            print("    头文件 %d 个（手工构建用不上）" % len(hdrs))
        other = [n for n in names if not n.endswith(("/", ".jar", ".so", ".h"))]
        if other:
            print("    其他 %s" % ", ".join(other[:8]))


def cmd_jar(args):
    if not args.out:
        print("-o 必填")
        return 2
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    seen = {}
    skipped_dup = 0
    for a in args.aars:
        if not Path(a).exists():
            print("缺文件：%s" % a)
            return 2
        with zipfile.ZipFile(a) as z:
            try:
                data = z.read("classes.jar")
            except KeyError:
                print("跳过 %s（里面没有 classes.jar）" % a)
                continue
            tmp = out.parent / ("__inner_%s" % Path(a).stem)
            tmp.write_bytes(data)
            with zipfile.ZipFile(tmp) as iz:
                for name in iz.namelist():
                    if name.endswith("/") or name.startswith(SKIP_PREFIX):
                        continue
                    if name in seen:
                        skipped_dup += 1
                        continue
                    seen[name] = iz.read(name)
            try:
                tmp.unlink()
            except OSError:
                pass

    if out.exists():
        out.unlink()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(seen.items()):
            z.writestr(name, data)

    print("合并 %d 个 aar → %s" % (len(args.aars), out))
    print("  %d 个 class，跳过重复 %d 个，体积 %.1f KB"
          % (len(seen), skipped_dup, out.stat().st_size / 1024))
    tf = [n for n in seen if n.startswith("org/tensorflow/")]
    if tf:
        print("  其中 tensorflow 包 %d 个类" % len(tf))
    return 0


def cmd_so(args):
    if not args.out:
        print("-o 必填")
        return 2
    dest = Path(args.out)
    dest.mkdir(parents=True, exist_ok=True)
    want = "jni/%s/" % args.abi
    n = 0
    for a in args.aars:
        if not Path(a).exists():
            print("缺文件：%s" % a)
            return 2
        with zipfile.ZipFile(a) as z:
            for name in z.namelist():
                if not name.startswith(want) or not name.endswith(".so"):
                    continue
                fn = os.path.basename(name)
                p = dest / fn
                p.write_bytes(z.read(name))
                print("  %-40s %8.1f KB" % ("lib/%s/%s" % (args.abi, fn), p.stat().st_size / 1024))
                n += 1
    if n == 0:
        print("!! 没抽到任何 %s 的 .so —— 确认这些 aar 里带不带这个 ABI" % args.abi)
        return 1
    print("共 %d 个，放在 %s" % (n, dest))
    print("打包时按 lib/%s/<文件名> 写进 APK" % args.abi)
    return 0


def main():
    ap = argparse.ArgumentParser(description="AAR 拆包（手工构建 APK 用）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="看看 aar 里有什么")
    p.add_argument("aars", nargs="+")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("jar", help="合并 classes.jar")
    p.add_argument("aars", nargs="+")
    p.add_argument("-o", "--out", required=True)
    p.set_defaults(fn=cmd_jar)

    p = sub.add_parser("so", help="抽出某个 ABI 的原生库")
    p.add_argument("aars", nargs="+")
    p.add_argument("--abi", default="arm64-v8a")
    p.add_argument("-o", "--out", required=True)
    p.set_defaults(fn=cmd_so)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
