# android — 免 root 触摸注入与工程自检

> 面向**自有应用**的自动化与辅助功能研究。核心价值是一张选型表和几个静态校验工具。

## 六条路线

### 免 root（本模块主体）

| 路线 | 权限入口 | 注入层 | 暴露面 |
| --- | --- | --- | --- |
| **A** | `AccessibilityService.dispatchGesture()` | 应用层 | 服务可被枚举；`MotionEvent` 带 `FLAG_IS_ACCESSIBILITY_EVENT` |
| **B** | ESP32-S2/S3 USB HID 触摸屏 | **内核输入层** | 应用层无特征，只有内核知道是 HID |

要求"不 root"且目标是**别的应用** ⇒ 只能是 A 或 B，没有第三条。

实践顺序：先用 A 把检测逻辑和参数调通（半小时），要更干净再上 B。
两条路线的控制律、轨迹算法可以完全复用。

### 需要 root / 内核权限（反检测强度递增）

| 路线 | 手段 | 原理 | 为什么更难被检测 |
| --- | --- | --- | --- |
| **C** | `INJECT_EVENTS` / `injectInputEvent` | 系统服务层 | 需要 `signature\|privileged`，靠 root / Shizuku / 常驻 adb |
| **D** | 陀螺仪注入 | 不产生触摸事件，改注入设备转动 | 触摸事件流里完全看不到痕迹；受游戏是否启用陀螺仪限制 |
| **E** | `uinput` 设备伪装 | 自建 `/dev/uinput` 并伪装成真实触摸屏（`BUS_I2C` + OEM 厂商名） | 内核看到的是"新接上一块触摸屏" |
| **F** | 内核驱动直调 `input_handle_event` | 绕开 uinput，直接进输入子系统 | 连设备枚举都没有，事件像内生的 |

选型建议：**D 最省事的"干净"路线**（不用建设备，一行数据就转视角）；
E 要做设备伪装（总线类型和名称都得对）；F 可移植性最差但最隐蔽。

## 工具

| 脚本 | 作用 |
| --- | --- |
| `tools/aar_extract.py` | 拆 AAR：解出 `classes.jar`、`AndroidManifest.xml`、`res/`、`jni/` |
| `tools/res_check.py` | 工程静态自检：资源引用、`AndroidManifest` 权限与组件、`uses-sdk` 一致性 |
| `tools/syntax_check.py` | 不装 Android SDK 也能做的语法级校验（XML 合法性、Java 括号/import 粗检） |

```bash
# AAR 拆包：先看内容，再按需合并 jar / 抽 native 库
python tools/aar_extract.py list libs/foo.aar libs/bar.aar
python tools/aar_extract.py jar  libs/*.aar -o out/classes.jar
python tools/aar_extract.py so   libs/*.aar --abi arm64-v8a -o out/jniLibs

# 工程静态自检（直接指向工程目录，无参数则用当前目录）
python tools/res_check.py    app/src/main
python tools/syntax_check.py app/src/main
```

## 手工构建要点（不依赖 Gradle）

Gradle 在沙箱/老机器上经常死在 native 服务初始化。手工链路：

```text
aapt2 compile → aapt2 link（出 base APK + R.java）
→ javac（android.jar + 所有 jar）→ d8（dex）
→ zipalign → apksigner（自有 keystore 签名）
```

三个硬约束：

1. **`classes.dex` 必须在 APK 根目录**，且未压缩存储（`zip -0`）可选但推荐；
2. **改过 `.so` 后必须重新签名**，否则安装失败（`INSTALL_FAILED_INVALID_APK`）；
3. **Android 14 抓屏**要先 `MediaProjection` 授权再建 `VirtualDisplay`，顺序错了黑屏。

## 边界

给**自己的应用**做自动化、辅助功能、可访问性研究，是正常工程需求。
把它用在别人的游戏或应用上，通常同时违反服务条款与当地法律。见 [DISCLAIMER.md](../../DISCLAIMER.md)。
