# Maat table

The maat table consists of two parts: `schema` and `runtime`, which is the core skeleton of maat. In a production environment, maat periodically loads the configurations from redis and parses it according to the schema, building a table-based runtime for use by the scanning interface.

* [table schema](#1-table-schema)
* [table runtime](#2-table-runtime)

## 1. Table schema

Maat tables are divided into two categories: physical tables that actually exist in the database and virtual tables that reference physical tables.

The types of physical tables are as follows:
- [item table](#11-item-table)
- [compile table](#12-compile-table)
- [group2compile table](#13-group2compile-table)
- [group2group table](#14-group2group-table)
- [plugin table](#15-plugin-table)
- [ip_plugin table](#16-ip_plugin-table)
- [fqdn_plugin table](#17-fqdn_plugin-table)
- [bool_plugin table](#18-bool_plugin-table)
- [ipport_plugin table](#19-ipport_plugin-table)

Different physical tables can be combined into one table, see [conjunction table](#110-conjunction-table)

A virtual table can only reference one physical table or conjuntion table, see [virtual table](#111-virtual-table)

### 1.1 <a name='Itemtable'></a> Item table

Item tables are further subdivided into different types of subtables as follows:
- [expr item table](#111-expr-item-table)
- [expr_plus item table](#112-expr_plus-item-table)
- [ip item table](#113-ip-item-table)
- [interval item table](#114-interval-item-table)
- [interval_plus item table](#115-interval_plus-item-table)
- [flag item table](#116-flag-item-table)
- [flag_plus item table](#117-flag_plus-item-table)

Each item table must has the following columns:

- item_id: In a maat instance, the item id is globally unique, meaning that the item id of different tables must not be duplicate.

- group_id: Indicate the group to which the item belongs, an item belongs to only one group.

- is_valid: In incremental updates, 1(valid means add) 0(invalid means del)

The range of item_id(group_id, compile_id) is 0～2^63，which is 8 bytes.

#### 1.1.1 <a name='exprtable'></a> expr item table

Describe matching rules for strings.

| **FieldName**    | **type**       | **constraint** |
| ---------------- | -------------- | ------- |
| **item_id**      | LONG LONG      | primary key |
| **group_id**     | LONG LONG      | leaf group id, can be referenced by group2group & group2compile table |
| **keywords**     | VARCHAR2(1024) | field to match during scanning |
| **expr_type**    | INT            | 0(keywords), 1(AND expr), 2(regular expr), 3(substring with offset)
| **match_method** | INT            | only useful when expr_type is 0. 0(sub), 1(suffix), 2(prefix), 3(exactly) |
| **is_hexbin**    | INT            | 0(not HEX & case insensitive, this is default value)  1(HEX & case sensitive)  2(not HEX & case sensitive) |
| **is_valid**     | INT            | 0(invalid), 1(valid) |

The table schema is stored in table_info.conf.
```c
{
    "table_id":3,  //[0 ~ 1023], don't allow duplicate
    "table_name":"HTTP_URL", //db table's name
    "table_type":"expr",
    "valid_column":7,    //7th column(is_valid field)
    "custom": {
        "item_id":1,     //1st column(item_id field)
        "group_id":2,    //2nd column(group_id field)
        "keywords":3,    //3rd column(keywords field)
        "expr_type":4,   //4th column(expr_type field)
        "match_method":5,//5th column(match_method field)
        "is_hexbin":6    //6th column(is_hexbin field)
    }
}

/* If you want to combine multiple physical tables into one table, db_tables should be added as follows.
   The value of table_name can be a user-defined string, the value of db_tables is the table name that actually exists in database. */
{
    "table_id":3,  //[0 ~ 1023], don't allow duplicate
    "table_name":"HTTP_REGION", //user-defined string
    "db_tables":["HTTP_URL", "HTTP_HOST"],
    "table_type":"expr",
    "valid_column":7,
    "custom": {
        "item_id":1,
        "group_id":2,
        "keywords":3,
        "expr_type":4,
        "match_method":5,
        "is_hexbin":6
    }
}
```

`expr_type` column represents the expression type:

1. keywords matching(0), match_method column as follows
    - substring matching (0)
        
        For example: substring: "China", scan_data: "Hello China" will hit, "Hello World" will not hit

    - suffix matching (1)
    
        For example: suffix: ".baidu.com", scan_data: "www.baidu.com" will hit, "www.google.com" will not hit

    - prefix matching (2)
        
        For example: prefix: "^abc", scan_data: "abcdef" will hit, "1abcdef" will not hit

    - exactly matching (3)
    
        For example: string: "World", scan_data: "World" will hit, "Hello World" will not hit

2. AND expression(1), supports up to 8 substrings. 

    For example: AND expr: "yesterday&today", scan_data: "Goodbye yesterday, Hello today!" will hit, "Goodbye yesterday, Hello tomorrow!" will not hit.

3. Regular expression(2)

    For example: Regex expr: "[W|world]", scan_data: "Hello world" will hit, "Hello World" will hit too.

4. substring matching with offset(3)
  - offset start with 0, [offset_start, offset_end] closed interval

  - multiple substrings with offset are logical AND

    For example: substring expr: "1-1:48&3-4:4C4C", scan_data: "HELLO" will hit, "HLLO" will not hit.
    **Note**: 48('H') 4C('L')

Since Maat4.0, only UTF-8 is supported, and encoding conversion is no longer supported. For binary format rules, keywords are represented in hexadecimal, such as the keyword "hello" being represented as "68656C6C6F". Keywords cannot contain invisible characters such as spaces, tabs, and carriage returns, which have ASCII codes from 0x00 to 0x1F and 0x7F. If these characters need to be used, they must be escaped, referring to the "keyword escape table". Characters led by backslashes outside this table are processed as ordinary strings, such as '\t' being processed as the string "\t".

The symbol '&' represents the conjunction operation in an AND expression. Therefore, if a keyword contains '&', it must be escaped as '\&'.

**keywords escape table**

| **symbol** | **ASCII code** | **symbol after escape** |
| ---------- | -------------- | ----------------------- |
| \          | 0x5c           | \\\                     |
| &          | 0x26           | \\&                     |
| blank space| 0x20           | \b                      |

Length constraint：

- Single substring no less than 3 bytes

- No less than 3 bytes for a single substring in AND expression

- Support up to 8 substrings in one AND expression, expr = substr1 & substr2 & substr3 & substr4 & substr5 & substr6 & substr7 & substr8

- The length of one AND expression should not exceed 1024 bytes(including '&')

#### 1.1.2 <a name='ExprPlusItemTable'></a> expr_plus item table
Describe extended matching rules for strings by adding the district column.

| **FieldName**    | **type**       | **constraint** |
| ---------------- | -------------- | ------- |
| **item_id**      | LONG LONG      | primary key |
| **group_id**     | LONG LONG      | leaf group id, can be referenced by group2group & group2compile table |
| **district**     | VARCHAR2(1024) | describe the effective position of the keywords |
| **keywords**     | VARCHAR2(1024) | field to match during scanning |
| **expr_type**    | INT            | 0(keywords), 1(AND expr), 2(regular expr), 3(substring with offset)
| **match_method** | INT            | only useful when expr_type is 0 |
| **is_hexbin**    | INT            | 0(not HEX & case insensitive, this is default value)  1(HEX & case sensitive)  2(not HEX & case sensitive) |
| **is_valid**     | INT            | 0(invalid), 1(valid) |


For example, if the district is User-Agent and keywords is Chrome, scanning in the following way will hit.
```c
    const char *scan_data = "Chrome is fast";
    const char *district = "User-Agent";

    maat_state_set_scan_district(..., district, ...);
    maat_scan_string(..., scan_data, ...)
```

#### 1.1.3 <a name='IPItemTable'></a> ip item table

Describe matching rules for IP address. Both the address and port are represented by string, IPv4 is dotted decimal and IPv6 is colon separated hexadecimal.

| **FieldName**  | **type**     | **constraint** |
| -------------- | ------------ | -------------- |
| **item_id**    | LONG LONG    | primary key |
| **group_id**   | LONG LONG    | leaf group id, can be referenced by group2group & group2compile table |
| **addr_type**  | INT          | Ipv4 = 4 Ipv6 = 6 |
| **addr_format**| VARCHAR2(40) | ip addr format, single/range/CIDR/mask |
| **ip1**        | VARCHAR2(40) | start ip |
| **ip2**        | VARCHAR2(40) | end ip |
| **is_valid**   | INT          | 0(invalid), 1(valid) |

#### 1.1.4 <a name='IntervalItemTable'></a> interval item table

Determine whether an integer is within a certain numerical range.

| **FieldName**    | **type** | **constraint** |
| ---------------- | -------- | -------------- |
| **item_id**      | INT      | primary key |
| **group_id**     | INT      | leaf group id, can be referenced by group2group & group2compile table |
| **low_boundary** | INT      | lower bound of the numerical range(including lb), 0 ~ (2^32 - 1)|
| **up_boundary**  | INT      | upper bound of the numerical range(including ub), 0 ~ (2^32 - 1)|
| **is_valid**     | INT      | 0(invalid), 1(valid) |

#### 1.1.5 <a name='IntervalPlusItemTable'></a> interval_plus item table

Describe extended matching rules for integer by adding the district column.

| **FieldName**    | **type** | **constraint** |
| ---------------- | -------- | -------------- |
| **item_id**      | INT      | primary key |
| **group_id**     | INT      | leaf group id, can be referenced by group2group & group2compile table |
| **district**     | VARCHAR2(1024)| describe the effective position of the keywords |
| **low_boundary** | INT      | lower bound of the numerical range(including lb), 0 ~ (2^32 - 1)|
| **up_boundary**  | INT      | upper bound of the numerical range(including ub), 0 ~ (2^32 - 1)|
| **is_valid**     | INT      | 0(invalid), 1(valid) |

#### 1.1.6 <a name="FlagItemTable"></a> flag item table

| **FieldName** | **type** | **constraint** |
| ------------- | -------- | -------------- |
| **item_id**   | INT      | primary key |
| **group_id**  | INT      | leaf group id, can be referenced by group2group & group2compile table |
| **flag**      | INT      | flag, 0 ~ (2^32 - 1)|
| **flag_mask** | INT      | flag_mask, 0 ~ (2^32 - 1)|
| **is_valid**  | INT      | 0(invalid), 1(valid) |

#### 1.1.7 <a name="FlagPlusItemTable"></a> flag_plus item table

| **FieldName** | **type** | **constraint** |
| ------------- | -------- | -------------- |
| **item_id**   | INT      | primary key |
| **group_id**  | INT      | leaf group id, can be referenced by group2group & group2compile table |
| **district**  | INT      | describe the effective position of the flag |
| **flag**      | INT      | flag, 0 ~ (2^32 - 1)|
| **flag_mask** | INT      | flag_mask, 0 ~ (2^32 - 1)|
| **is_valid**  | INT      | 0(invalid), 1(valid) |

### 1.2 <a name='CompileTable'></a> compile table

Describe the specific policy, one maat instance can has multiple compile tables with different names.

| **FieldName**  | **type**       | **constraint**  |
| -------------- | -------------- | --------------- |
| **compile_id** | LONG LONG      | primary key, compile id |
| **tags**       | VARCHAR2(1024) | default 0，means no tag |
| **is_valid**   | INT            | 0(invalid)，1(valid)  |
| **clause_num** | INT            | no more than 8 clauses |

### 1.3 <a name='Group2CompileTable'></a> group2compile table

Describe the relationship between group and compile.

| **FieldName**     | **type**      | **constraint** |
| ----------------- | ------------- | -------------- |
| **group_ids**     | VARCHAR(256)  | group ids are separated by commas(g1,g2,g3) |
| **compile_id**    | LONG LONG     | compile id |
| **is_valid**      | INT           | 0(invalid), 1(valid) |
| **not_flag**      | INT           | logical 'NOT', identify a NOT clause, 0(no) 1(yes) |
| **virtual_table** | VARCHAR2(256) | virtual table name, NOT NULL |
| **Nth_clause**    | INT           | the clause seq in (conjunctive normal form)CNF, from 0 to 7. groups with the same clause ID are logical 'OR' |

NOTE: If group_id is invalid in xx_item table, it must be marked as invalid in this table.

### 1.4 <a name='Group2GroupTable'></a> group2group table 

Describe the relationship between groups.

| **FieldName**          | **type**     | **constraint** |
| ---------------------- | ------------ | ---------------|
| **group_id**           | LONG LONG    | reference from xx_item table's group_id |
| **incl_sub_group_ids** | VARCHAR(256) | included sub group ids are separated by commas(g1,g2,g3)|
| **excl_sub_group_ids** | VARCHAR(256) | excluded sub group ids are separated by commas(g4,g5)|
| **is_valid**           | Bool         | (invalid), 1(valid) |


### 1.5 <a name='PluginTable'></a> plugin table

There is no fixed rule format of the plugin table, which is determined by business side. The plugin table supports two sets of callback functions, registered with **maat_table_callback_register** and **maat_plugin_table_ex_schema_register** respectively.

```c
int maat_table_callback_register(struct maat *instance, int table_id,
								 maat_start_callback_t *start_cb,
								 maat_update_callback_t *update_cb,
								 maat_finish_callback_t *finish_cb,
								 void *u_para);
```

When the plugin table rules are updated, `start_cb` will be called first and only once, then `update_cb` will be called by each rule item, and `finish_cb` will be called last and only once.

If rules have been loaded but maat_table_callback_register has not yet been called, maat will cache the loaded rules and perform the callbacks(start, update, finish) when registration is complete.

This set of callbacks is concerned with changes to the table, including when the table starts to change (start_cb), the type of change (full or incremental), when the change ends (finish_cb), and the specific content of each change (update_cb).

```c
int maat_plugin_table_ex_schema_register(struct maat *instance, const char *table_name,
                                         maat_ex_new_func_t *new_func,
                                         maat_ex_free_func_t *free_func,
                                         maat_ex_dup_func_t *dup_func,
                                         long argl, void *argp);
```

This interface registers a set of callback functions for the xx_plugin table. Unlike the callbacks registered with `maat_table_callback_register`, when adding a configuration, the `new_func` is called immediately, and when deleting a configuration, the `free_func` is not called immediately due to the introduction of a garbage collection mechanism. Instead, the free_func is called when the garbage collection queue starts the collection process.

this set of callbacks is concerned with the specific configuration changes line by line, which configuration is added (new_func), which configuration is deleted (free_func), and which configuration can be queried for ex_data (dup_func).

```c
void *maat_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                    const char *key, size_t key_len);
```

Plugin table supports three types of keys to query ex_data.

1. Pointer key(compatible with maat3)
2. Integer key
3. Ipv4 or ipv6 address as key.

### 1.6 <a name='IpPluginTable'></a> ip_plugin table

Similar to plugin table but the key of maat_ip_plugin_table_get_ex_data is ip address.

### 1.7 <a name='FQDNPlugintable'></a> fqdn_plugin table

Scan the input string according to the domain name hierarchy '.'

Return results order: sort by decreasing the length of the hit rule

For example:
1. example.com.cn
2. com.cn
3. example.com.cn
4. cn
5. ample.com.cn

If the input string is example.com.cn, the expected result order would be: 3, 1, 2, 4. The 'ample' in rule 5 is not part of the domain hierarchy and should not be returned.

### 1.8 <a name='BoolPluginTable'></a> bool_plugin table

Scan the input integer array based on a boolean expression, such as [100, 1000, 2, 3].

The boolean expression rule is numbers separated by "&", for example, "1&2&1000".

### 1.9 <a name='IpPortPluginTable'></a>ipport_plugin table

Different from IPPlugin table, which uses ip as the key, IPPortPlugin table uses ip+port as the key, which can meet users' more refined ex_data query requirements. For example, by building a mapping from ip+port to subscriber ID, network traffic can be distributed based on subscriber ID.

### 1.10 <a name='ConjunctionTable'></a> conjunction table

By default, maat builds a separate runtime for each physical table, which can be used for rule matching by specifying the table ID during scanning. If the user wants to combine multiple physical tables of the same type into a single table for runtime build and scan, it means conjunction of multiple tables. 

For example: HTTP_REGION is the conjunction of HTTP_URL and HTTP_HOST.

```json
{
    "table_id":1,
    "table_name":"HTTP_REGION",
    "db_tables":["HTTP_URL", "HTTP_HOST"],
    "table_type":"expr",
    "valid_column":7,
    "custom": {
        "item_id":1,
        "group_id":2, 
        "keywords":3,
        "expr_type":4,
        "match_method":5,
        "is_hexbin":6
    }
}
```

`Note`: Only physical tables support conjunction.

### 1.11 <a name='VirtualTable'></a> virtual table

A physical table refers to a table that physically exists in the database. In contrast, there are no virtual tables in the database. Virtual tables are merely references to physical tables, where one virtual table can only reference one physical table. If you want to reference multiple physical tables of the same type, you need to first combine these physical tables into a conjunction table, and then have the virtual table reference it. A physical table can be referenced by multiple virtual tables.

Virtual tables are often used for different traffic attributes, where different virtual tables represent different traffic attributes, such as HTTP_HOST, HTTP_URL, and so on.

### 1.12 <a name='ForeignFiles'></a>Foreign Files

In callback configurations, specific fields can point to external content, currently supporting pointing to a key in Redis.

The foreign key column in the callback table must have the prefix "redis://". The content stored in Redis as a foreign key must have the prefix "__FILE_". When the key is "null", it indicates that the file is empty.

For example, if the original file is ./testdata/mesa_logo.jpg, and after calculating its MD5 value, we get the Redis foreign key __FILE_795700c2e31f7de71a01e8350cf18525, the format written in the callback table would be as follows:

```
14	./testdata/digest_test.data	redis://__FILE_795700c2e31f7de71a01e8350cf18525 1
```

Each row in the callback table can have a maximum of 8 foreign keys, and the foreign key content can be set using the Maat_cmd_set_file function.

Before notifying the callback table, Maat fetches the foreign keys to local files and replaces the foreign key column with the local file path.

### 1.13 <a name='Tags'></a>Tags

By matching the tags accepted by Maat with the configuration tags, selective configuration loading is achieved. Configuration tags are a collection of tag arrays, denoted as "tag_sets", while Maat accepts tags are tag arrays denoted as "tags".

Configuration tags are tags stored on compilation configurations or group configurations, identifying where the configuration is effective in which Maat instances. It consists of multiple tag sets, where multiple tags within a set are ANDed, and multiple values of a tag are ORed.

## 2. Table runtime

Maat loads the configuration of different types of tables into memory to form the corresponding runtime for each table. We can see all table types from the table schema, and the runtime for the item table is similar, as it is an abstraction of the scanning engine. When we provide the data to be scanned and call the corresponding scanning interface, we can return whether the item is hit or not, and if it is hit, we can return the corresponding item’s group_id.

From the [configuration relationship](./overview.md#12-configuration-relationship) diagram, we can see how the hit group is referenced by other groups or compiles. If a hit group is referenced by other groups or compiles, there will be one or more hit paths that follow the `item_id -> group_id` {-> super group_id} `-> compile_id`. This requires two special runtimes: group2group_runtime and compile_runtime. 

Based on this, we can divide the runtime into the following three categories:

1. item table runtime
    * expr_runtime
    * ip_runtime
    * flag_runtime
    * interval_runtime

2. group & compile table runtime
    * group2group_runtime
    * compile_runtime

3. xx_plugin table runtime
    * plugin_runtime
    * ip_plugin_runtime
    * fqdn_plugin_runtime
    * bool_plugin_runtime
    * ipport_plugin_runtime

### 2.1 item table runtime

<img src="./imgs/expr-runtime.png" width="300" height="300" > 

Among the four types of runtimes mentioned above, `expr_runtime` is relatively unique. Its expr_matcher supports two types of scanning engines: `hyperscan` and `rulescan`. Other xx_runtime directly calls the corresponding xx_matcher to obtain scanning results.

**Note**: Due to the inability to unify the native rulescan usage with hyperscan, a partial refactoring has been done on rulescan. The refactored rulescan follows the same interface and usage as hyperscan, making it compatible with the design of the expr_matcher abstraction layer.

### 2.2 group & compile table runtime

#### 2.2.1 group2group runtime

The `group2group_runtime` is a runtime that is built based on the reference relationships between groups, which are stored in the [group2group table](#14-group2group-table). From the [group hierarchy](./group_hierarchy.md), we can understand that if a hit occurs in a leaf group that is referenced by other groups, there may be certain super groups that are also hit. This is exactly the functionality provided by this runtime.

#### 2.2.2 compile runtime

In addition to the compile table, there is also the group2compile table in the table schema. However, from a runtime perspective, the configurations of these two tables together constitute compile_runtime. This means that there is no standalone group2compile_runtime. Compile_runtime is the most complex among all runtime types because it serves multiple functions.

**Note:** This will involve the terminology of [clause](./terminology.md#clause).

1. For expressions without NOT-clauses, returning the matched compile_id:

    * compile1 = clause1 & clause2 = {vtable1, g1} & {vtable2, g2}

    * compile2 = clause1 & clause2 = {vtable1, g2} & {vtable2, g3}

    Given the matched vtable_id and group_id, all matching compile_ids can be provided. For example, if scanning vtable1 matches g2 and vtable2 matches g3, compile_runtime will return the matched compile_id 2.

2. For expressions with NOT-clauses, returning the matched compile_id:

    * compile3 = clause1 & !clause2 = {vtable1, g1} & !{vtable2, g2}

    * compile4 = !clause1 & clause2 = !{vtable1, g2} & {vtable2, g3}

    If scanning vtable1 matches g1 and vtable2 matches g3, compile_runtime will return the matched compile_id 4.

3. If a compile_id is matched, the full hit path can be obtained: **item_id -> group_id ->** {super_group_id} -> clause{**vtable_id, not_flag, clause_index} -> compile_id**. If the matched group is not referenced by a compile, a half hit path can be obtained: **item_id -> group_id** -> {super_group_id}.

4. Getting the matched group_ids and the count of hit groups.

The internal structure of compile_runtime is as follows, including the control plane for configuration loading and the data plane for external calls.

![compile runtime](./imgs/compile-runtime.png)

* **Control plane**

Compile runtime loads the compile table and group2compile table configurations into memory, assigning a unique clause_id to all clauses of each compile. The following three parts are constructed based on the clause_id:

1. All clause_ids under the same compile are used to construct AND expressions, and all compile AND expressions are used to build a bool_matcher.

2. For not_flag=0 (clauses), a `clause_id hash` is built, key:{group_id, vtable_id, not_flag}, value:clause_id.

3. For not_flag=1 (NOT-clauses), a `NOT_clause_id hash` is built, key:{group_id, vtable_id, not_flag}, value:clause_id.

* **Data Plane**

On the data plane, services are provided externally through the maat API, primarily with the following three types of interfaces:

1. **maat_scan_xx**: This interface dynamically generates the hit {item_id, group_id}.

* The hit item_id and group_id form a half-hit path.

* The group_id that is hit and the scanned `vtable_id` form the key {group_id, vtable_id, 0}. This key is used to find the `hit clause_ids` in the clause_id hash.

* Use the key {group_id, vtable_id, 1} to search for NOT_clause_ids in the NOT_clause_id hash and cache them as `exclude clause_ids`. These clause_ids need to be removed from all clause_ids that are eventually hit. This is because the scan hit {group_id, vtable_id, 0} => clause_id, leading to the deduction that {group_id, vtable_id, 1} => NOT_clause_id does not hit.

* Identify the group_ids in vtable_id table that appear in the NOT_clause and add them to the `NOT_clause_group` set. Ensure that this set does not contain any group_id that was hit during scanning. If any such group_id is present, remove it from the set to form the final `NOT_clause_group` for the vtable_id table.

* Use the hit clause_ids to determine if there are any hit compile_ids. If there are, populate the half-hit path which will become full-hit path.

2. **maat_scan_not_logic**: This interface is used to activate NOT-clause logic.

* Traverse the `NOT_clause_group` of `vtable_id`. For each `group_id`, form a key `{group_id, vtable_id, 1}` to obtain the `NOT_clause_id`. If it is in the `exclude clause_ids` set, ignore it; otherwise, add it to the `all hit clause_ids` set as a hit `NOT_clause_id`, and record the half-hit path of the NOT-clause.

* Use the `all hit clause_ids` to calculate if there are any newly hit compile_ids. If there are, populate the half-hit path of the NOT-clause which will become full-hit path.

3. **xx_get_hit_path**: This interface is used to retrieve the hit path.