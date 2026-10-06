# DVWA XSS (DOM) Medium 通关 WriteUp

## 一、Medium 难度概述

DVWA 的 **XSS (DOM)** 模块在 Medium 级别引入了一个服务端过滤：使用 `str_replace` 移除 `<script` 字符串。但 DOM 型 XSS 的数据流完全发生在客户端，服务端的过滤能否生效，取决于前端 JavaScript 是否使用了被过滤后的变量。

将 DVWA 安全级别设置为 **Medium**，进入 **XSS (DOM)** 模块。

## 二、源码分析

查看 Medium 级别源码：

```php
<?php
if (array_key_exists("default", $_GET) && !is_null($_GET['default'])) {
    $default = $_GET['default'];
    // Do some filtering
    $default = str_replace("<script", "", $default);
} else {
    $default = "English";
}
?>
```

前端 JavaScript 代码与 Low 级别基本相同：

```javascript
if (document.location.href.indexOf("default=") >= 0) {
    var lang = document.location.href.substring(document.location.href.indexOf("default=") + 8);
    document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
    document.write("<option value='' disabled='disabled'>----</option>");
}
// ...
```

## 三、过滤机制分析

Medium 在 PHP 端使用了 `str_replace("<script", "", $default)` 来过滤 `<script` 字符串。但问题在于：

- **PHP 端的 `$default` 变量并没有被前端 JavaScript 使用。**
- 前端 JavaScript 仍然直接从 `document.location.href` 中读取 `default` 参数。
- 因此 PHP 的过滤完全影响不到 JavaScript 的数据流。

这意味着 **Medium 的过滤是无效的**，DOM 型 XSS 依然存在。但为了演示更通用的绕过思路，我们仍然可以使用不包含 `<script` 的 Payload。

## 四、绕过方法

### 方法一：直接使用 `<script>`（因为 PHP 过滤不影响 JS）

Payload：

```text
?default=<script>alert(1)</script>
```

在 Medium 下依然会弹窗，因为 PHP 的 `str_replace` 只修改了 PHP 变量，而 JavaScript 从 URL 读取原始值。

### 方法二：使用不需要 `<script` 的标签

如果某些情况下过滤真的作用到了前端（例如修改了 JavaScript 代码），可以使用其他标签绕过：

```html
<img src=x onerror=alert(1)>
```

`str_replace` 只过滤了 `<script`，没有过滤 `<img`，因此这个 Payload 可以正常工作。

其他可用标签：

```html
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
```

### 方法三：大小写混合

如果过滤是大小写敏感的，可以尝试：

```html
<ScRiPt>alert(1)</ScRiPt>
```

但 `str_replace` 是区分大小写的，所以 `<ScRiPt` 不会被过滤。不过由于 PHP 过滤本身无效，这个技巧不是必须的。

## 五、验证

访问：

```text
http://靶机IP/dvwa/vulnerabilities/xss_d/?default=<img src=x onerror=alert(1)>
```

页面弹窗，Medium 难度绕过成功。

也可以直接使用 `<script>`：

```text
http://靶机IP/dvwa/vulnerabilities/xss_d/?default=<script>alert(1)</script>
```

同样会弹窗，证明 PHP 端过滤未生效。

## 六、Low 与 Medium 对比

| 对比项                  | Low                      | Medium                                            |
| --- | --- | --- |
| PHP 端过滤              | 无                       | `str_replace("<script", "", $default)`            |
| 前端 JavaScript 数据源  | `document.location.href` | 同 Low                                            |
| 过滤是否生效            | 不适用                   | **不生效**，因为 JS 未使用 PHP 变量               |
| 直接 `<script>` Payload | 有效                     | 仍然有效（PHP 过滤无效）                          |
| 绕过思路                | 无需绕过                 | 使用 `<img>`、`<svg>` 等标签，或直接忽略 PHP 过滤 |
| 根本问题                | 客户端未编码输出         | 客户端未编码输出 + 服务端过滤错位                 |

Medium 是一个典型的“防御错位”案例：开发者在服务器端做了过滤，但 DOM 型 XSS 的数据流完全在客户端，导致过滤形同虚设。

## 七、防御措施

针对 DOM 型 XSS，防御必须落在客户端：

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

## 八、总结

Medium 级别虽然引入了 `str_replace` 过滤，但由于前端 JavaScript 直接从 URL 读取数据，PHP 端的过滤并未生效。直接使用 `<script>` 或改用 `<img src=x onerror=alert(1)>` 均可成功绕过。核心教训是：DOM 型 XSS 的防御必须在客户端进行输出编码，服务端过滤无法覆盖客户端的数据流。