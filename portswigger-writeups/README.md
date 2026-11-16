# PortSwigger Web Security Academy · CSRF + SQL Injection 通关复盘

> 记录方式：每天 3 小时（180 min），连续 7 天，共 21 h，覆盖 25 个 lab。
> CSRF 8 个（4 Apprentice / 4 Practitioner）+ SQLi 17 个（2 Apprentice / 15 Practitioner）。
> 写作视角：通关后回溯整理，时间轴是"那一天大概怎么花的"，不是精确计时。

---

## 一、总排期

| Day | 主题 | 覆盖 Lab | 数量 | 时长 |
|-----|------|----------|------|------|
| 1 | CSRF 原理 + 三个"经典缺陷" | Lab 1–4 | 4 | 3 h |
| 2 | CSRF 令牌绑定缺陷与 Referer 绕过 | Lab 5–8 | 4 | 3 h |
| 3 | SQLi 原理 + 隐藏数据 / 登录绕过 / 指纹 | Lab 9–12 | 4 | 3 h |
| 4 | UNION 起步 + 库表结构枚举 | Lab 13–16 | 4 | 3 h |
| 5 | UNION 取数据 + 布尔盲注两种信号 | Lab 17–20 | 4 | 3 h |
| 6 | 时间盲注 + 带外（OAST） | Lab 21–24 | 4 | 3 h |
| 7 | WAF/XML 编码绕过 + 全局复盘 | Lab 25 + 复盘 | 1 | 3 h |

时间分配原则：**原理 40–50 min → 动手 120–130 min → 写笔记 20–30 min**。
宁可少打一个 lab，也不要跳过写笔记那 20 分钟——第 7 天能把 25 个 lab 串成一张表，靠的就是这 7 段笔记。

## 二、每日文档

| 文件 | 内容 |
|------|------|
| [day1.md](day1.md) | CSRF 是什么、三要素、exploit server 工作流；4 个 Apprentice |
| [day2.md](day2.md) | 令牌不绑 session / 绑非 session cookie / 双提交；Referer 两种绕过 |
| [day3.md](day3.md) | SQL 注入点定位、注释符与 DBMS 指纹；4 个基础 lab |
| [day4.md](day4.md) | ORDER BY 数列、找字符列、information_schema / all_tables 枚举 |
| [day5.md](day5.md) | UNION 取账号密码、单列拼接、条件响应盲注、条件错误盲注 |
| [day6.md](day6.md) | pg_sleep 时间盲注、CASE 逐字符、Oracle OAST 出网与外带 |
| [day7.md](day7.md) | XML 实体编码绕 WAF、总复盘、能力自评、下一步 |
| [cheatsheet.md](cheatsheet.md) | 两张速查表：CSRF 绕过矩阵 + SQLi 跨 DBMS 语法差异 |

## 三、环境与前置

- **Burp Suite**：Community 够用；Pro 多了 CSRF PoC 生成器、Collaborator、Intruder 无限速。
  - Community 没有 CSRF PoC 生成器 → 手写 HTML（本套笔记里全是手写版本，可直接抄）。
  - Community 没有内置 Collaborator → 用 `interactsh`（`interactsh-client`）替代，DNS/HTTP 回连一样能收到。
- **浏览器**：Chrome + FoxyProxy（只代理 `*.web-security-academy.net` 与 `*.exploit-server.net`）。
- **两个特殊域名**，每次都容易混：
  - `LAB-ID.web-security-academy.net` = 靶场本身（受害者登录在这里）。
  - `exploit-ID.exploit-server.net` = 攻击者服务器（放 PoC，然后 Deliver to victim）。
- **Deliver 只能成功一次**：改完 PoC 必须重新 **Store**，再 Deliver，否则投递的是旧页面。这是前两天最容易浪费时间的坑。
- **每个 lab 独立实例**，实例过期（约 30–60 min 无操作）会重置，登录态和改过的邮箱全部回滚。

## 四、进度表（自己填实际用时）

| # | Lab | 难度 | 预计 | 实际 | 状态 |
|---|-----|------|------|------|------|
| 1 | CSRF vulnerability with no defenses | Apprentice | 20 min | | ☐ |
| 2 | CSRF where token validation depends on request method | Apprentice | 20 min | | ☐ |
| 3 | CSRF where token validation depends on token being present | Apprentice | 20 min | | ☐ |
| 4 | CSRF where token is not tied to user session | Apprentice | 30 min | | ☐ |
| 5 | CSRF where token is tied to a non-session cookie | Practitioner | 45 min | | ☐ |
| 6 | CSRF where token is duplicated in cookie | Practitioner | 40 min | | ☐ |
| 7 | CSRF where Referer validation depends on header being present | Practitioner | 35 min | | ☐ |
| 8 | CSRF with broken Referer validation | Practitioner | 40 min | | ☐ |
| 9 | SQLi in WHERE clause allowing retrieval of hidden data | Apprentice | 20 min | | ☐ |
| 10 | SQLi allowing login bypass | Apprentice | 15 min | | ☐ |
| 11 | Querying the database type and version on Oracle | Practitioner | 30 min | | ☐ |
| 12 | Querying the database type and version on MySQL and MSSQL | Practitioner | 25 min | | ☐ |
| 13 | UNION attack, determining the number of columns | Practitioner | 30 min | | ☐ |
| 14 | UNION attack, finding a column containing text | Practitioner | 30 min | | ☐ |
| 15 | Listing database contents on non-Oracle databases | Practitioner | 40 min | | ☐ |
| 16 | Listing database contents on Oracle | Practitioner | 40 min | | ☐ |
| 17 | UNION attack, retrieving data from other tables | Practitioner | 35 min | | ☐ |
| 18 | UNION attack, retrieving multiple values in a single column | Practitioner | 30 min | | ☐ |
| 19 | Blind SQLi with conditional responses | Practitioner | 45 min | | ☐ |
| 20 | Blind SQLi with conditional errors | Practitioner | 45 min | | ☐ |
| 21 | Blind SQLi with time delays | Practitioner | 35 min | | ☐ |
| 22 | Blind SQLi with time delays and information retrieval | Practitioner | 45 min | | ☐ |
| 23 | Blind SQLi with out-of-band interaction | Practitioner | 40 min | | ☐ |
| 24 | Blind SQLi with out-of-band data exfiltration | Practitioner | 45 min | | ☐ |
| 25 | SQLi with filter bypass via XML encoding | Practitioner | 60 min | | ☐ |

## 五、这套笔记的写法约定

每个 lab 固定六段，方便以后当 checklist 用：

1. **一句话结论** —— 这个 lab 想让你学会的唯一一件事。
2. **观察** —— 进 lab 先看什么（请求、Cookie、响应差异、报错）。
3. **攻击** —— 可直接复制的 payload / HTML，含原始 HTTP。
4. **为什么有效** —— 落到代码逻辑上，而不是"试出来的"。
5. **坑** —— 我实际卡住的地方。
6. **带走** —— 迁移到真实目标的判断句。

> 编号说明：本文档的 Lab 1–25 按**学习顺序**编号（先 CSRF 后 SQLi），与 PortSwigger 站点上的排列顺序不完全一致；按标题对照即可。
>
> 说明：时间轴按"3 h/天、25 个 lab"回溯估算；如果你的通关节奏不是 7 天（比如集中两天打完），把每天的文件当成"章节"而不是"日历"来读即可，内容顺序仍然是正确的学习顺序。
