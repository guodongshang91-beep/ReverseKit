# 实战 Playbook

四套可以直接照抄的流程。**每一套都假设你已经拿到了授权。**

---

## Playbook 1：SRC — 从 0 到中高危

### 为什么不能一上来就扫路径

中小企业官网（静态门户 / CMS）的自动化扫描结果长这样：

```text
web.config 泄露（低危）
.htaccess 泄露（低危）
.DS_Store 泄露（低危）
```

50 个主域 + 304 个参数化接口 + sqlmap 复测 = **0 中高危**。

真正的中高危在这两个地方：

1. **子域里的企业系统**（OA / ERP / 门禁 / 日志 / 对象存储）
2. **前端 JS 里硬编码的内部地址**（尤其是 `http://<公网IP>:<端口>/` 这种）

同样一天，换到 72 个业务系统子域 → **2 个高危**（公开 OSS 录音桶、nginx 目录遍历日志服务）。

### 步骤

一条命令先跑通全链（详细分步见下）：

```bash
python modules/src-hunt/rkhunt.py run --scope scope.csv --workdir loot
python modules/src-hunt/rkhunt.py status --workdir loot
```

手动分步：

```bash
cd modules/src-hunt/src

# 1. 子域（被动 + 定向）
python recon.py --out ../recon/subs.json

# 2. 存活 + 指纹
python probe.py --subs ../recon/subs.json --out ../recon/alive.json --workers 28

# 3. 只挑"系统类"前缀深挖
grep -E '"(oa|erp|crm|sso|api|admin|manage|portal|gateway|wms|boss|vpn|jenkins|gitlab|nacos|minio|monitor|log|bi|data|files|oss)"' \
     ../recon/alive.json > ../recon/sys.json

# 4. 未授权路径（只在这批系统上跑）
python unauth_scan.py --alive ../recon/sys.json --out ../recon/unauth.json --workers 10

# 5. ★ 前端 bundle 逆向：这一步最容易出活
python js_harvest.py --alive ../recon/sys.json --out ../recon/js.json
```

### 第 5 步为什么关键

SPA 的 bundle 里出现 `http://<公网IP>:<端口>/xxx/` 时，**大概率是没做访问控制的
运维 / 日志 / 文件服务**。上一轮的高危目录遍历就是这么挖到的。

`js_harvest.py` 抽四类东西：

| 类型 | 正则要点 | 价值 |
| --- | --- | --- |
| 绝对地址 | `oss-*.aliyuncs.com`、`*.cos.*.myqcloud.com`、`http://<IP>:<port>` | 未授权服务 / 公开桶 |
| API 路径 | `/api/v4/user/query`、`/auth/login` | 后续参数探测的入口 |
| 硬编码密钥 | `AKID`/`LTAI`/`AKIA`、`secretKey`、`appKey`、32 位 map key | 直读数据 |
| mock 后门 | `pwmini/mock`、`loginFromMock`、`devLogin`、`skipAuth` | 绕过认证 |

### 收尾：归属绑定

IP / 对象存储桶在多数 SRC 属"IP 漏洞暂不收取"。必须用
「**该厂商自有域名下的前端 JS 引用了这个地址**」的截图把目标与厂商绑定，
否则会被当无主资产忽略。

### 纪律

- 只取证明所需的数据量：OSS 只列举 + 取文件头 64 字节，**不下载完整文件**；
  目录遍历只取一个文件头。
- 手机号（前 3 后 4）、身份证、IMEI、内网 IP 一律打码。
- 独立会话重复 ≥ 2 次。

---

## Playbook 2：判定一条漏洞是不是真的

拿到一条"命中"之后，按这个顺序问五个问题：

1. **基线对了吗？** `/random-probe` 返回什么？命中响应和它差在哪？
2. **是兜底页吗？** 同一 md5 在这台主机上出现过几次？
3. **跳转过吗？** `allow_redirects=False` 再发一次，看原始响应。
4. **回显还是真实内容？** 命中的字符串是不是就是我自己请求的路径？
5. **换会话还能复现吗？** 换 UA、换出口 IP、等 5 分钟再来一次。

五问全过，才能写"已验证"。任何一问过不了，写"未验证，疑似假阳性"。

```bash
# 五问的工具化
curl -sS -o /tmp/base.txt "https://$H/$(head -c8 /dev/urandom|base64|tr -dc a-z)-probe"
curl -sS -o /tmp/hit.txt -D /tmp/hit.head --max-redirs 0 "https://$H$PATH"
md5sum /tmp/base.txt /tmp/hit.txt && wc -c /tmp/base.txt /tmp/hit.txt
head -c 400 /tmp/hit.txt
```

---

## Playbook 3：PE 授权校验 —— 从字符串到补丁

```bash
cd modules/pe-patch

# 1. 先看目标长什么样
python tools/peck.py info app.exe
#    → 64 位？有 CFG？加壳了吗（节名/熵）？

# 2. 找路标
python tools/peck.py hunt app.exe
#    → 0x2f3a0  [utf16] 授权文件未找到，程序将以试用模式运行
#    → 0x2f420  [utf16] 试用期已到期，请输入序列号

# 3. 谁引用了它
python tools/peck.py xref app.exe 0x2f3a0
#    → ptr64  off=0x2e1a4  rva=0x2e5a4

# 4. 反汇编那片区域
python tools/peck.py dis app.exe 0x2e560 -n 60
#    找 test/cmp + jz/jnz 的组合

# 5. 最小补丁：先 dry-run
python tools/peck.py patch app.exe --rva 0x2e5a8 --hex 9090 --dry-run
python tools/peck.py patch app.exe --rva 0x2e5a8 --hex 9090
```

### 判定点的三种形态

| 形态 | 汇编 | 补丁 |
| --- | --- | --- |
| 条件跳转 | `test eax,eax` + `jz` | `74 xx` → `EB xx`，或 `90 90` |
| 早期返回 | `xor eax,eax` + `ret` | `33 C0` → `B0 01` |
| 提示串分支 | `push offset "到期"` + `jmp` | 改跳转目标到正常流程 |

### 先确认没有完整性自检

`hunt` 里出现"文件被非法修改"/"程序已被篡改"这类字符串，
说明有 CRC 或签名自检，直接改字节会触发。这种情况要么定位校验函数一起改，
要么改内存（运行期补丁）。

---

## Playbook 4：ELF `.so` 里的授权逻辑

```bash
cd modules/binary-re

# 1. 结构
python tools/elfkit.py info liblicense.so

# 2. 路标字符串（中文用 -f 试用 / 授权）
python tools/elfkit.py strings liblicense.so -m 5 -f licen
python tools/elfkit.py strings liblicense.so -m 5 -f 试用

# 3. 交叉引用（ARM64 会走 adrp+add 解析）
python tools/elfkit.py xref liblicense.so 0x2a1c0

# 4. 反汇编
python tools/elfkit.py dis liblicense.so 0x2ad50 -n 60

# 5. 补丁：ARM64 上「无条件返回 true」常见写法
#    mov w0, #1 ; ret   →   20 00 80 52  c0 03 5f d6
python tools/elfkit.py patch liblicense.so --vaddr 0x2ad74 --hex "20008052c0035fd6" --dry-run
```

### ARM64 常见指令速查

| 语义 | 编码 | 字节（小端） |
| --- | --- | --- |
| `nop` | `0xD503201F` | `1f 20 03 d5` |
| `ret` | `0xD65F03C0` | `c0 03 5f d6` |
| `mov w0, #1` | `0x52800020` | `20 00 80 52` |
| `mov w0, #0` | `0x52800000` | `00 00 80 52` |
| `cbz w0, +8` → `b +8` | — | `60 00 00 34` → `02 00 00 14` |

### 改完记得回 APK

```bash
# 替换 .so → 重新对齐 → 用自有 keystore 重签，否则装不上
zipalign -f 4 base.apk aligned.apk
apksigner sign --ks my.jks aligned.apk
```

---

## 通用收尾：证据包

```text
evidence/<VULN-ID>/
├── meta.json             元信息 + 每次抓包的 sha256/长度/时间
├── request-01.txt        原始请求（方法/路径/全部 header）
├── response-01.txt       原始响应（状态码/header/正文；大文件截前 4KB + 总长度）
├── request-02.txt        第二次独立会话（换 UA / 换出口）
├── response-02.txt
├── verify-notes.md       复现步骤、影响面、五问排除记录
├── hash.txt              sha256 清单（seal 生成）
└── report.md             由 meta.json + notes 渲染（report 生成）
```

别手动建这套目录，用工具：

```bash
E="python tools/evidkit.py"
$E new --id VULN-001 --host api.example.com --path /actuator/env --type 未授权访问 --level 中危
$E add --id VULN-001 --request req1.txt --response resp1.txt --note 第一次
$E add --id VULN-001 --request req2.txt --response resp2.txt --note 换出口
$E seal   --id VULN-001        # 封存清单
$E verify --id VULN-001        # 事后复核，文件被动过就 exit 1
$E report --id VULN-001        # 出 Markdown 报告
```

`add` 只往目录里拷文件并记哈希，**不改你的原始报文**；`seal` 之后再改任何文件，
`verify` 都会指出来。

**目录里没有这些，就不算发现。** 这条纪律比任何工具都重要。
