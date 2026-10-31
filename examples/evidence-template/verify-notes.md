# VULN-XXX 验证记录

## 基本信息

| 项 | 值 |
| --- | --- |
| 发现时间 | 2026-01-01 12:00 (+08:00) |
| 目标 | `api.example.com`（授权编号：XXXX） |
| 类型 | 未授权访问 / actuator 环境信息泄露 |
| 初判等级 | 中危 |
| 状态 | **已验证**（两次独立会话复现） |

## 复现步骤

1. 直接访问 `https://api.example.com/actuator/env`，无需任何认证；
2. 响应 200，正文含 `_links.self` 与 `propertySources` 结构；
3. 与随机路径基线对比：`/a8f3k2-probe` 返回 404 / 空，md5 不同 → 非兜底页；
4. 换出口 IP、换 UA 后重复一次，结果一致。

## 证据

- `request-01.txt` / `response-01.txt`（第一次）
- `request-02.txt` / `response-02.txt`（第二次，不同会话）
- `hash.txt`

## 影响

actuator/env 暴露了数据源连接串配置（密码字段已脱敏）。
可进一步读取 `/actuator/heapdump` 获取内存中的明文凭据。
**本次未下载 heapdump**（只取了前 64 字节证明可访问）。

## 假阳性排除记录

| 检查项 | 结果 |
| --- | --- |
| catch-all 基线 | 不同（404 vs 200，md5 不同） |
| WAF 拦截页 | 否（无 `waf_block` / `访问被拒绝`） |
| 404 路径回显 | 否（正文不含请求路径末段） |
| 跳转跟随 | 未跳转（302 不存在） |
| 同 md5 复现次数 | 1（无兜底页嫌疑） |

## 修复建议

1. actuator 端点限制为内网访问或加认证；
2. 升级 Spring Boot Actuator 至默认关闭 `env` / `heapdump` 的版本；
3. 轮换已暴露的数据源凭据。
