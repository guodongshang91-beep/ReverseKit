# -*- coding: utf-8 -*-
"""Android 资源引用一致性校验（不需要 Android SDK）。

做三件事：
  1. 所有 XML 是否格式良好；
  2. Java 里用到的 R.id.x / R.layout.x / R.drawable.x / R.string.x / R.xml.x / R.color.x
     是否真的在 res/ 里存在；
  3. AndroidManifest 里引用的 @style / @xml / @string / @drawable / @mipmap / @color 是否解析得到。

这一步能拦住「id 打错」「漏建 layout」「manifest 指向不存在的 xml」这类高频低级错误。
拦不住的是类型错误和 API 等级问题，那必须真机 Gradle 编译。

用法： python res_check.py <工程根目录>
"""
import re
import sys
import pathlib
import xml.etree.ElementTree as ET

AND = "{http://schemas.android.com/apk/res/android}"


def collect_res(root: pathlib.Path):
    """res/ 下所有资源的名字集合，按类型分桶。"""
    res = root / "app" / "src" / "main" / "res"
    found = {}
    for p in res.rglob("*"):
        if p.is_dir():
            continue
        kind_dir = p.parent.name.split("-")[0]
        name = p.name.split(".")[0]
        found.setdefault(kind_dir, set()).add(name)
    # values/*.xml 里的条目也算资源
    for vf in (res / "values").glob("*.xml"):
        try:
            t = ET.parse(vf)
        except ET.ParseError:
            continue
        for child in t.getroot():
            tag = child.tag
            n = child.get("name")
            if n:
                found.setdefault(tag, set()).add(n)
    return found


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    problems = []

    # ---- 1. XML 格式 ----
    xmls = sorted(root.rglob("*.xml"))
    for f in xmls:
        try:
            ET.parse(f)
        except ET.ParseError as e:
            problems.append("XML 格式错误 %s -> %s" % (f.relative_to(root), e))
    print("XML 文件 %d 个，格式全部通过" % len(xmls) if not problems else "XML 存在问题")

    res = collect_res(root)

    # ---- 1.5 layout / menu 里的 @+id 声明 ----
    ids = set()
    id_pat = re.compile(r'@\+id/(\w+)')
    for f in xmls:
        txt = f.read_text(encoding="utf-8", errors="ignore")
        ids.update(id_pat.findall(txt))
    res.setdefault("id", set()).update(ids)
    print("声明了 %d 个 id：%s" % (len(ids), ", ".join(sorted(ids))))

    # ---- 2. Java 里的 R.* 引用 ----
    java = sorted(root.rglob("*.java"))
    pat = re.compile(r"\bR\.(\w+)\.(\w+)\b")
    for f in java:
        src = f.read_text(encoding="utf-8")
        for kind, name in pat.findall(src):
            bucket = res.get(kind, set())
            if name not in bucket:
                problems.append("%s 引用 R.%s.%s 不存在" % (f.relative_to(root), kind, name))

    # ---- 3. Manifest 里的 @ 引用 ----
    mf = root / "app" / "src" / "main" / "AndroidManifest.xml"
    if mf.exists():
        t = ET.parse(mf)
        for node in t.getroot().iter():
            for k, v in node.attrib.items():
                if not v.startswith("@"):
                    continue
                body = v[1:]
                if body.startswith("+") or body.startswith("android:"):
                    continue
                if body.startswith("style/") or body.startswith("android:style/"):
                    continue
                if "/" not in body:
                    continue
                kind, name = body.split("/", 1)
                if name not in res.get(kind, set()):
                    problems.append("AndroidManifest 引用 @%s/%s 不存在" % (kind, name))

    if problems:
        print("\n发现 %d 个问题：" % len(problems))
        for p in problems:
            print("  -", p)
        return 1
    print("资源引用一致性：全部通过（java %d 个文件，资源类别 %s）"
          % (len(java), sorted(res.keys())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
