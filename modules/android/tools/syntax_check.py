# -*- coding: utf-8 -*-
"""用 javalang 对所有 .java 做语法解析。

作用边界：只能查语法错误、括号/关键字/结构问题。
查不出类型错误、方法是否存在、API 等级是否够 —— 那些必须靠真机 Gradle 编译。

用法： python syntax_check.py <工程根目录>
依赖： pip install javalang
"""
import sys
if hasattr(sys.stdout, "reconfigure"):   # Windows 控制台默认 cp1252，中文输出会直接崩
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import sys
import pathlib

import javalang


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    files = sorted(root.rglob("*.java"))
    bad = 0
    for f in files:
        src = f.read_text(encoding="utf-8")
        try:
            javalang.parse.parse(src)
            print("OK    %s (%d 行)" % (f.relative_to(root), len(src.splitlines())))
        except Exception as e:
            bad += 1
            print("FAIL  %s -> %s: %s" % (f.relative_to(root), type(e).__name__, e))
    print("\n共 %d 个文件，失败 %d 个" % (len(files), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
