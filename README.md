# Web 安全靶场 Write-up

面向 **渗透测试 / 安全服务** 方向的 Web 漏洞手动复现记录。

在本地 DVWA、Pikachu 靶场和 PortSwigger Web Security Academy 上逐个复现漏洞，每篇都按 **源码定位 → 手工复现 → 绕过对比 → 成因分析 → 修复建议** 五步写，不贴完 payload 就结束。

- **25 篇文档**：DVWA 14 篇、Pikachu 2 篇、PortSwigger 25 个 Lab 的 9 篇复盘
- **全程手工**：Burp Suite 拦截改包，payload 自己构造，不用 sqlmap 一键出结果
- **对照 Low / Medium**：同一漏洞的两个难度并排放，说明"过滤做了什么、为什么能被绕过"
- **给出修复代码**：每篇结尾落到参数化查询、白名单、`escapeshellarg()` 这类具体写法

## 内容概览

| 靶场 | 主题 | 文档 | 关卡 |
|------|------|------|------|
| [DVWA](dvwa/) | SQL 注入 / XSS / CSRF / 文件包含 / 文件上传 / 命令注入 / 暴力破解 | 14 | 16 |
| [Pikachu](pikachu/) | SSRF / PHP 反序列化 / 文件包含 | 2 | — |
| [PortSwigger](portswigger/) | CSRF 8 个 + SQL 注入 17 个 Lab 的通关复盘 | 9 | 25 |

## 目录结构

```text
.
├── dvwa/                    # DVWA 靶场，按漏洞类型命名
├── pikachu/                 # Pikachu 靶场
├── portswigger/             # PortSwigger Academy 7 天通关复盘 + 速查表
└── README.md
```

文件命名统一为 `漏洞-难度.md`（如 `sqli-blind-low.md`），按文件名排序即按漏洞类型分组，同类漏洞的 Low / Medium 会挨在一起。

## DVWA

| # | 漏洞 | 难度 | 文档 | 关键点 |
|---|------|------|------|--------|
| 1 | SQL 注入 | Low | [sqli-low.md](dvwa/sqli-low.md) | `ORDER BY` 数列、`UNION` 回显、`information_schema` 拖表拖字段 |
| 2 | SQL 注入 | Medium | [sqli-medium.md](dvwa/sqli-medium.md) | 前端下拉框只是摆设，Burp 改包 + 十六进制绕过引号过滤 |
| 3 | SQL 盲注 | Low | [sqli-blind-low.md](dvwa/sqli-blind-low.md) | 布尔盲注逐字符猜解、二分查找把 36 次压到 6 次、Python 脚本 |
| 4 | XSS 反射型 | Low | [xss-reflected-low.md](dvwa/xss-reflected-low.md) | 输出点定位、`<script>` 被拦后换事件属性、Cookie 窃取链路 |
| 5 | XSS 存储型 | Low | [xss-stored-low.md](dvwa/xss-stored-low.md) | 留言板两处注入点、`maxlength` 用 Burp 绕过、自建接收端验证 |
| 6 | XSS DOM 型 | Low | [xss-dom-low.md](dvwa/xss-dom-low.md) | `document.write` 型 DOM XSS，服务端日志里看不到 payload |
| 7 | XSS DOM 型 | Medium | [xss-dom-medium.md](dvwa/xss-dom-medium.md) | 服务端只过滤 `<script`，DOM 层用 `<img onerror>` 或大小写绕过 |
| 8 | CSRF | Low | [csrf-low.md](dvwa/csrf-low.md) | 无 token 的改密请求，构造自动提交表单 |
| 9 | CSRF | Medium | [csrf-medium.md](dvwa/csrf-medium.md) | `stripos(Referer, SERVER_NAME)` 子串校验，用文件名带上目标 IP 绕过 |
| 10 | 文件包含 | Low | [file-inclusion-low.md](dvwa/file-inclusion-low.md) | LFI 读 `/etc/passwd`、`php://filter` 读源码、RFI + `data://` GetShell |
| 11 | 文件包含 | Medium | [file-inclusion-medium.md](dvwa/file-inclusion-medium.md) | `str_replace` 删 `../`，双写 / `..././` / 绝对路径三种绕过 |
| 12 | 文件上传 | Low + Medium | [file-upload-low-medium.md](dvwa/file-upload-low-medium.md) | 一句话木马、Content-Type 伪造、`.php.jpg` 与 `%00` 截断 |
| 13 | 命令注入 | Low + Medium | [command-injection-low-medium.md](dvwa/command-injection-low-medium.md) | 分号 / `&&` / 管道符、`str_replace` 黑名单不全、`escapeshellarg()` 修复 |
| 14 | 暴力破解 | Low | [brute-force-low.md](dvwa/brute-force-low.md) | Burp Intruder Sniper 模式、按响应长度差异定位正确口令 |

## Pikachu

| 模块 | 文档 | 关键点 |
|------|------|--------|
| SSRF | [ssrf.md](pikachu/ssrf.md) | `curl_exec` 与 `file_get_contents` 两个入口、内网端口探测、`gopher://` 构造 POST、`php://filter` 读源码 |
| 反序列化 / 文件包含 | [deserialization-and-file-inclusion.md](pikachu/deserialization-and-file-inclusion.md) | PHP 魔术方法触发链、`__destruct` 写 shell、`php://input` 与伪协议包含 |

## PortSwigger Web Security Academy

7 天、25 个 Lab 的完整复盘，每日一篇：

| 天 | 主题 | Lab | 文档 |
|----|------|-----|------|
| 1 | CSRF 原理与三个经典缺陷 | 1–4 | [day1.md](portswigger/day1.md) |
| 2 | 令牌绑定缺陷与 Referer 绕过 | 5–8 | [day2.md](portswigger/day2.md) |
| 3 | SQLi 原理、隐藏数据、登录绕过、指纹 | 9–12 | [day3.md](portswigger/day3.md) |
| 4 | UNION 起步与库表枚举 | 13–16 | [day4.md](portswigger/day4.md) |
| 5 | UNION 取数与布尔盲注 | 17–20 | [day5.md](portswigger/day5.md) |
| 6 | 时间盲注与带外（OAST） | 21–24 | [day6.md](portswigger/day6.md) |
| 7 | XML 编码绕 WAF + 全局复盘 | 25 | [day7.md](portswigger/day7.md) |

另外还有一份跨 DBMS 的语法速查表（MySQL / MSSQL / Oracle / PostgreSQL 的注释、版本、拼接、延迟、报错注入写法对照）：[cheatsheet.md](portswigger/cheatsheet.md)。总目录见 [portswigger/README.md](portswigger/README.md)。

## 单篇文档的写法

每个漏洞固定五段，方便当 checklist 复用：

1. **漏洞概述** —— 这个漏洞是什么，触发条件是什么
2. **源码分析** —— 贴出后端关键代码，指出哪一行把用户输入当成了代码/命令
3. **手工复现** —— 每一步的输入、返回、为什么这么试，含 Burp 原始请求
4. **绕过与对比** —— Low 与 Medium 的过滤差异，以及绕过为什么成立
5. **成因与修复** —— 落到具体代码的修复方案，不是"加强过滤"这种空话

## 环境

- **靶场**：DVWA（PHP + MySQL）、Pikachu
- **代理与抓包**：Burp Suite Community Edition + Chrome + FoxyProxy
- **系统**：Kali Linux / Windows + 本地虚拟机
- **辅助**：sqlmap（仅用于验证手工结论）、Python（盲注与爆破脚本）

## 进度

- [x] DVWA：SQL 注入 / XSS / CSRF / 文件包含 / 文件上传 / 命令注入 / 暴力破解（Low、Medium）
- [x] Pikachu：SSRF、反序列化、文件包含
- [x] PortSwigger：CSRF + SQL 注入 25 个 Lab
- [ ] DVWA High 与 Impossible 级别对照（重点补 SQL 注入与 XSS 的防御代码）
- [ ] 内网渗透：VulnHub 靶机、域内信息收集与横向
- [ ] 一篇完整的渗透测试报告样例（发现 → 验证 → 影响 → 修复 → 复测）

## 免责声明

本仓库所有内容仅用于个人学习与**已获授权的测试环境**。请勿将其中任何技术用于未授权的真实目标，否则后果自负。

## 关于

目前求职方向：**渗透测试 / 安全服务工程师**（实习 · 校招）。

如果这些记录对你有帮助，欢迎 Star；发现问题也欢迎开 Issue 指正。
