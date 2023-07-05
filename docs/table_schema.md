# Table Schema

Since Maat 4.0，The range of item_id(group_id, compile_id) is 0～2^63，which is 8 bytes.

## Item Table

Each item table must has the following columns

- item_id: In a maat instance, the item ID is globally unique, meaning that the item IDs of different tables must not be duplicate.
- group_id: Indicate the group to which the item belongs, an item belongs to only one group.
- is_valid: In incremental updates, 1(valid means add) 0(invalid means del)

Different types of tables also have different fields defined according to their respective needs.

### 1. String item table
Describe matching rules for strings.

#### table schema
| **FieldName**    | **type**       | **NULL** | **constraint** |
| ---------------- | -------------- | -------- | ------- |
| **item_id**      | LONG LONG      | N        | primary key |
| **group_id**     | LONG LONG      | N        | group2group or group2compile table's group_id |
| **keywords**     | VARCHAR2(1024) | N        | field to match during scanning |
| **expr_type**    | INT            | N        | 0(keywords), 1(AND expr), 2(regular expr), 3(substring with offset)
| **match_method** | INT            | N        | only useful when expr_type is 0 |
| **is_hexbin**    | INT            | N        | 0(not HEX & case insensitive, this is default value)  1(HEX & case sensitive)  2(not HEX & case sensitive) |
| **is_valid**     | INT            | N        | 0(invalid), 1(valid) |

Matching rules for string，expr_type column represents the expression type.

1. keywords matching(0), match_method column as follows
    - substring matching (0)
    - suffix matching    (1)
    - prefix matching    (2)
    - exactly matching   (3)
2. AND expression(1), supports up to 8 substrings.
3. Regular expression(2)
4. substring matching with offset(3)
  - offset start with 0, [offset_start, offset_end] closed interval
  - multiple substrings with offset are logical AND

Since Maat4.0，only support UTF-8，no more encoding conversion。For binary format configurations, the keyword is hexadecimal, such as the keyword "hello" is represented as "68656C6C6F". A keyword can't contain invisible characters such as spaces, tabs, and CR, which are ASCII codes 0x00 to 0x1F and 0x7F.
If these characters need to be used, they must be escaped, refer to the "keywords escape table".
Characters led by backslashes outside this table are processed as ordinary strings, such as '\t' will be processed as the string "\t".

The symbol '&' means conjunction operation in AND expression. So if the keywords has '&', it must be escaped by '\&'.

**keywords escape table**

| **symbol** | **ASCII code** | **symbol after escape** |
| ---------- | -------------- | ----------------------- |
| \          | 0x5c           | \\\                     |
| &          | 0x26           | \\&                     |
| blank space| 0x20           | \b                      |

Length constraint：

- Single substring no less than 3 bytes；
- No less than 3 bytes for a single substring in AND expression；
- Support up to 8 substrings in one AND expression, expr = substr1 & substr2 & substr3 & substr4 & substr5 & substr6 & substr7 & substr8
- The length of one AND expression should not exceed 1024 bytes(including '&')


### 2. IP item table

Describe matching rules for IP address. Both the address and port are represented by string, IPv4 is dotted decimal and IPv6 is colon separated hexadecimal.

#### table schema

| **FieldName** | **type**     | **NULL** | **constraint** |
| ------------- | ------------ | -------- | -------------- |
| item_id       | LONG LONG    | N        | primary key |
| group_id      | LONG LONG    | N        | group2group or group2compile table's group_id |
| addr_type     | INT          | N        | Ipv4 = 4 Ipv6 = 6 |
| addr_format   | VARCHAR2(40) | N        | ip addr format, single/range/CIDR/mask |
| ip1           | VARCHAR2(40) | N        | start ip |
| ip2           | VARCHAR2(40) | N        | end ip |
| port_format   | VARCHAR2(40) | N        | port format, single/range |
| port1         | VARCHAR2(6)  | N        | start port number |
| port2         | VARCHAR2(6)  | N        | end port number |
| protocol      | INT          | N        | default(-1) TCP(6) UDP(17), user define field |
| is_valid      | INT          | N        | 0(invalid), 1(valid) |

### 3. Numeric item table

Determine whether an integer is within a certain numerical range.

#### table schema

| **FieldName** | **type** | **NULL** | **constraint** |
| ------------- | -------- | -------- | -------------- |
| item_id      | INT      | N        | primary key |
| group_id     | INT      | N        | group2group or group2compile table's group_id |
| low_boundary | INT      | N        | lower bound of the numerical range(including lb), 0 ~ (2^32 - 1)|
| up_boundary  | INT      | N        | upper bound of the numerical range(including ub), 0 ~ (2^32 - 1)|
| is_valid     | INT      | N        | 0(invalid), 1(valid) |


### 4. Group2group table

Describe the relationship between groups.

#### table schema

| **FieldName**     | **type**  | **NULL** | **constraint** |
| ----------------- | --------- | -------- | ---------------|
| group_id          | LONG LONG | N        | reference from xx_item table's group_id |
| superior_group_id | LONG LONG | N        | group_id include or exclude specified super_group_id |
| is_exlude         | Bool      | N        | 0(include) 1(exclude) |
| is_valid          | Bool      | N        | 0(invalid), 1(valid) |

### 5. Group2compile table

Describe the relationship between group and compile.

#### table schema

| **FieldName** | **type**      | **NULL** | **constraint** |
| ------------- | ------------- | -------- | ------- |
| group_id      | LONG LONG     | N        | reference from xx_item table's group_id|
| compile_id    | LONG LONG     | N        | compile ID |
| is_valid      | INT           | N        | 0(invalid), 1(valid) |
| not_flag      | INT           | N        | logical 'NOT', identify a NOT clause, 0(no) 1(yes) |
| virtual_table | VARCHAR2(256) | N        | virtual table name, default:”null” |
| Nth_clause    | INT           | N        | the clause seq in (conjunctive normal form)CNF, from 0 to 7. groups with the same clause ID are logical 'OR' |

NOTE: If group_id is invalid in xx_item table, it must be marked as invalid in this table.

### 6. Compile table

Describe the specific policy, One maat instance can has multiple compile tables with different names.

#### table schema

| **FieldName**    | **type**       | **NULL** | **constraint** |
| ---------------- | -------------- | -------- | --------------- |
| compile_id       | LONG LONG      | N        | primary key, policy ID |
| service          | INT            | N        | such as URL keywords or User Agent etc. |
| action           | VARCHAR(1)     | N        | recommended definitions: 0(Blocking) 1(Monitoring) 2(whitelist) |
| do_blacklist     | VARCHAR(1)     | N        | 0(no)，1(yes)  transparent to maat |
| do_log           | VARCHAR(1)     | N        | 0(no)，1(yes)，default 1 transparent to maat |
| tags             | VARCHAR2(1024) | N        | default 0，means no tag |
| user_region      | VARCHAR2(8192) | N        | default 0  transparent to maat |
| is_valid         | INT            | N        | 0(invalid)，1(valid)  |
| clause_num       | INT            | N        | no more than 8 clauses |
| evaluation_order | DOUBLE | N     |          | default 0 |


### 7. Plugin table

There is no fixed format for configuration of the plugin table, which is determined by business side. The plugin table support three types of keys: pointer, integer and ip_addr.

**pointer key(compatible with maat3)**

(1) schema
```
{
    "table_id":1,
    "table_name":"TEST_PLUGIN_POINTER_KEY_TYPE",
    "table_type":"plugin",
    "valid_column":4,
    "custom": {
        "key_type":"pointer",
        "key":2,
        "tag":5
    }
}
```

(2) plugin table configuration
```
{
    "table_name": "TEST_PLUGIN_POINTER_KEY_TYPE",
    "table_content": [
        "1\tHeBei\tShijiazhuang\t1\t0",
        "2\tHeNan\tZhengzhou\t1\t0",
        "3\tShanDong\tJinan\t1\t0",
        "4\tShanXi\tTaiyuan\t1\t0"
    ]
}
```

(3) get_ex_data
```
const char *key1 = "HeBei";
const char *table_name = "TEST_PLUGIN_POINTER_KEY_TYPE";

int table_id = maat_get_table_id(maat_instance, table_name);
maat_plugin_table_get_ex_data(maat_instance, table_id, key1, strlen(key1));
```

**integer key**

support integers of different lengths, such as int(4 bytes), long long(8 bytes).

(1) schema
```
{
    "table_id":1,
    "table_name":"TEST_PLUGIN_INT_KEY_TYPE",
    "table_type":"plugin",
    "valid_column":4,
    "custom": {
        "key_type":"integer",
        "key_len":4
        "key":2,
        "tag":5
    }
}

{
    "table_id":2,
    "table_name":"TEST_PLUGIN_LONG_KEY_TYPE",
    "table_type":"plugin",
    "valid_column":4,
    "custom": {
        "key_type":"integer",
        "key_len":8
        "key":2,
        "tag":5
    }
}
```

(2) plugin table configuration
```
{
    "table_name": "TEST_PLUGIN_INT_KEY_TYPE",
    "table_content": [
        "1\t101\tChina\t1\t0",
        "2\t102\tAmerica\t1\t0",
        "3\t103\tRussia\t1\t0",
        "4\t104\tJapan\t1\t0"
    ]
}

{
    "table_name": "TEST_PLUGIN_LONG_KEY_TYPE",
    "table_content": [
        "1\t11111111\tShijiazhuang\t1\t0",
        "2\t22222222\tZhengzhou\t1\t0",
        "3\t33333333\tJinan\t1\t0",
        "4\t44444444\tTaiyuan\t1\t0"
    ]
}
```

(3) get_ex_data
```
//int
int key1 = 101;
const char *table_name = "TEST_PLUGIN_INT_KEY_TYPE";

int table_id = maat_get_table_id(maat_instance, table_name);
maat_plugin_table_get_ex_data(maat_instance, table_id, key1, sizeof(key1));

//long long
long long key2 = 11111111;
const char *table_name = "TEST_PLUGIN_LONG_KEY_TYPE";

table_id = maat_get_table_id(maat_instance, table_name);
maat_plugin_table_get_ex_data(maat_instance, table_id, key2, sizeof(key2));
```

**ip_addr key**

support ip address(ipv4 or ipv6) as key.

(1) schema
```
{
    "table_id":1,
    "table_name":"TEST_PLUGIN_IP_KEY_TYPE",
    "table_type":"plugin",
    "valid_column":4,
    "custom": {
        "key_type":"ip_addr",
        "addr_type":1,
        "key":2
    }
}
```
The addr_type column indicates whether the key is a v4 or v6 address.

(2) plugin table configuration
```
{
    "table_name": "TEST_PLUGIN_IP_KEY_TYPE",
    "table_content": [
        "4\t100.64.1.1\tXiZang\t1\t0",
        "4\t100.64.1.2\tXinJiang\t1\t0",
        "6\t2001:da8:205:1::101\tGuiZhou\t1\t0",
        "6\t1001:da8:205:1::101\tSiChuan\t1\t0"
    ]
}
```

(3) get_ex_data
```
uint32_t ipv4_addr;
inet_pton(AF_INET, "100.64.1.1", &ipv4_addr);
const char *table_name = "TEST_PLUGIN_IP_KEY_TYPE";

table_id = maat_get_table_id(maat_instance, table_name);
maat_plugin_table_get_ex_data(maat_instance, table_id, (char *)&ipv4_addr, sizeof(ipv4_addr));
```


### 8. IP Plugin table

Similar to plugin table but the key of maat_ip_plugin_table_get_ex_data is ip address.

### 9. FQDN Plugin table

Scan the input string according to the domain name hierarchy '.'

Return results order:
1. sort by decreasing the length of the hit rule

2. 

For example:
1. example.com.cn
2. com.cn
3. example.com.cn
4. cn
5. ample.com.cn

 If the input string is example.com.cn，则返回结果顺序为：3，1，2，4。规则5中的ample不是域名层级的一部分，不返回。

### 10. BoolPlugin table

按照布尔表达式扫描输入的整数数组，如[100,1000,2,3]。

布尔表达式规则为“&”分隔的数字，例如“1&2&1000”。

### 11. Virtual Table

虚拟一个配置表，其内容为特定物理域配置表的视图。实践中，通常采用网络流量的属性作为虚拟表名，如HTTP_HOST、SSL_SNI等。一个虚拟表可以建立在多个不同类型的物理表之上，但不允许建立在其它虚拟表上。

虚拟表以分组为单位引用实体表中的域配置，引用关系在分组关系表中描述。一个分组可被同一个编译配置的不同虚拟表引用。例如下表，一个关键字的分组keyword_group_1，被一条compile_1的Request Body和Response Body两个虚拟表引用。

| **分组ID**          | **父ID**  | **有效标志** | **非运算标志位** | **父节点类型** | **分组所属虚拟表** |
| ------------------- | --------- | ------------ | ---------------- | -------------- | ------------------ |
| **keyword_group_1** | compile_1 | 1            | 0                | 0              | REQUEST_BODY       |
| **keyword_group_1** | compile_1 | 1            | 0                | 0              | RESPONSE_BODY      |

### 12. Conjunction Table

表名不同，但table id相同的表。旨在数据库表文件和MAAT API之间提供一个虚拟层，通过API调用一次扫描，即可扫描多张同类配置表。

使用方法：

1. 在配置表描述文件中，将需要连接的多个表共用一个table_id；
2. 通过Maat_table_register注册被连接表中的任意一个表名，使用该id进行扫描。

被连接的配置表的各项属性以在配置表描述文件（table_info.conf）中第一个出现的同ID描述行为准，同一table_id下最多支持8个配置表。

支持所有类型表的连接，包括各类域配置、回调类配置。配置分组和配置编译的连接没有意义。

## Foreign Files

回调类配置中，特定字段可以指向一个外部内容，目前支持指向Redis中的一个key。

回调表的外键列，必须具备”redis://”前缀。存放在Redis中的外键内容，其Key必须具备”__FILE_”前缀。当Key为“null”时，表示该文件为空。

例如，原始文件为./testdata/mesa_logo.jpg，计算其MD5值后，得到redis的外键__FILE_795700c2e31f7de71a01e8350cf18525，写入回调表后的格式如下：

```
14	./testdata/digest_test.data	redis://__FILE_795700c2e31f7de71a01e8350cf18525 1
```

​    回调表中的一行最多允许8个外键，外键内容可以通过Maat_cmd_set_file函数设置。

​    Maat在通知回调表前会将外键拉取到本地文件，并将外键列替换为本地文件路径。

​    内容外键的声明方法，参见本文档-配置表描述文件一节。

## Tags

通过将Maat接受标签与配置标签的匹配，实现有选择的配置加载。其中配置标签是一个标签数组的集合，记为”tag_sets”，Maat接受标签是标签数组，记为”tags”。

配置标签是指存放在编译配置或分组配置上的标签，标识着该配置在那些Maat实例中生效。由多个tag_set构成，1个set内的多个tag是与的关系，1个tag的多个值是或的关系，值内部用”/”表示层次结构。

格式为一个不含回车、空格的JSON，结构为:

若干tag集合（数组）->tag集合（数组）->若干tag（数组）->{tag名称，tag值（数组）}

例如：

```json
{"tag_sets":[[{"tag":"location","value":["北京/朝阳/华严北里","上海/浦东/陆家嘴"]},{"tag":"isp","value":["电信","移动"]}],[{"tag":"location","value":["北京"]},{"tag":"isp","value":["联通"]}]]}
```

上例有2个tag分组：

- 分组1：（"北京/朝阳/华严北里"∨"上海/浦东/陆家嘴"）∧("电信"∨"移动")
- 分组2：（"北京"∧"联通"）
- 分组1∨分组2

Maat实例初始化时，可以设置自身的标签信息，称为接受标签。格式为同样要求的JSON，内有多个标签，加载配置时匹配实例标签和配置的生效范围标签。例如：

```json
{"tags":[{"tag":"location","value":"北京/朝阳/华严北里/甲22号”},{"tag":"isp","value":"电信"}]}
```

该Maat实例在加载以下标签时：

1.  {"tag_sets":[[{"tag":"location","value":["北京/朝阳"]},{"tag":"isp","value":["联通","移动"]}]}，不被接受，因为isp tag不匹配。
2. {"tag_sets":[[{"tag":"location","value":["北京"]}]]}，接受，空tag在任意tag上生效。

对于Maat实例接受标签和配置标签name不匹配的异常情况，Maat遵循不违背即接受的原则，全部接受。

- Maat实例的接受标签是配置标签的真子集时，即tags 属于tag_set，Maat会接受该配置。
  - 例如：接受标签为：{"tags":[{"tag":"location","value":"北京”}]} ，配置标签为：{"tags":[{"tag":"location","value":"北京/朝阳”},{"tag":"isp","value":"电信"}]} ，Maat会接受该配置，因为实例仅要求”location”满足“北京”，未对“isp”标签的值作出要求。
-  配置标签是Maat实例接受标签的真子集时，即tag_sets属于tags，Maat会接受该配置。
  - 例如：接受标签为：{"tags":[{"tag":"location","value":"北京/朝阳”},{"tag":"isp","value":"电信"}]}，配置标签为：{"tags":[{"tag":"location","value":"北京”}]}，Maat会接受该配置。配置没有“isp”标签，并未违背Maat接受条件。
- Maat实例的接受标签和配置标签的交集为空时，Maat会接受该配置。

当配置标签为“0”或“{}”时，无论Maat实例的接受标签是什么都会接受，这一特性用于向前兼容未设置标签的配置。  