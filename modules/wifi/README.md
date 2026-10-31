# wifi — WPA2 握手抓取与校验

> 在自己的网络上做无线安全自查。不依赖监听模式、不需要第二块网卡、不用 Linux。

## 核心思路：用错误密码主动触发握手

绝大多数教程要走「Linux + 监听模式 + `aireplay-ng` 去认证」。Windows 上有一条更省事的路：

用**错误密码**主动去连目标 AP。AP 并不知道密码对不对，它照样发起四次握手：

1. AP → 本机：EAPOL **M1**（含 ANonce，很多 AP 还附赠 PMKID）
2. 本机 → AP：EAPOL **M2**（含 SNonce + 用错误密钥算出的 MIC）

802.1X 的受控端口对 EAPOL 是放行的，所以这两帧**会经 NDIS 上送**，
Npcap 的过滤驱动能看到副本——即使链路最终因 MIC 校验失败而断开。

于是：**不需要监听模式、不需要注入、不需要 deauth、不需要第二块网卡。**

判据：`netsh wlan show interfaces` 显示「正在验证」并持续十几秒 ⇒ 握手正在跑，路子通。

## 脚本

| 脚本 | 作用 | 依赖 |
| --- | --- | --- |
| `src/capture.py` | 用 wpcap（ctypes）抓 M1/M2，无需监听模式 | Npcap |
| `src/capture_mon.py` | 监听模式抓包 + 可选 deauth 强制重连 | Npcap + 管理员 |
| `src/analyze.py` | 从 pcap 提取握手，输出 hashcat `-m 22000` 行；自带合成自检 | 标准库 |
| `src/gen_dict.py` | 生成场景字典（通用弱口令 + SSID 衍生） | 标准库 |

## 用法

```bash
# 0) 唯一硬门槛：装 Npcap（不支持 /S 静默安装，必须 GUI 走一遍并过 UAC）
#    https://npcap.com/dist/

# 1) 抓包（参数必须显式给，脚本里没有任何真实网络）
python src/capture.py --ssid <你的SSID>

# 2) 提取握手 → 22000 格式
python src/analyze.py handshake.pcap --ssid <你的SSID>

# 3) 校验管线是否正确（合成握手，密码已知）
python src/analyze.py --self-test

# 4) 生成字典
RK_SSID=<你的SSID> python src/gen_dict.py
```

`analyze.py --self-test` 是刻意的设计：先用一个**密码已知**的合成握手跑通
PBKDF2 → PMK → PTK → MIC 全链路，证明代码没写错，再去处理真实抓包。
不然抓包失败和算法写错会混在一起，很难排。

## 运行时参数

| 环境变量 | 参数 | 含义 |
| --- | --- | --- |
| `RK_SSID` | `--ssid` | 目标 AP 名称（必填） |
| `RK_BSSID` | `--bssid` | AP MAC（监听模式需要） |
| `RK_IFACE` | — | 网卡 GUID 片段，默认取第一块 802.11 网卡 |
| `RK_PCAP` | — | 输出 pcap 路径 |
| `RK_SECONDS` | — | 抓包时长，默认 75 秒 |

## 常见失败原因

| 现象 | 原因 |
| --- | --- |
| `wpcap.dll not found` | Npcap 没装，或装的时候没勾"兼容 WinPcap 模式" |
| 抓到 0 帧 EAPOL | 用错了配置文件（必须是一份**密码错误**的 profile，否则不会触发握手） |
| 只有 M1 没有 M2 | Windows supplicant 被别的网络管理器抢了；或 AP 开了 802.11w（PMF） |
| hashcat 报 `no hashes loaded` | 22000 行里 SSID 与实际不符，或 MIC 字段没清零就参与计算 |

## 边界

**只对自己的 AP 做。** 蹭网、破解他人 WiFi 在几乎所有辖区都是违法行为，
且不在本项目的授权范围内。见 [DISCLAIMER.md](../../DISCLAIMER.md)。
