# Table Schema

Maat tables are divided into two categories: physical tables that actually exist in the database and virtual tables that reference physical tables.

The types of physical tables are as follows:
- [item table](#1-item-table)
- [compile table](#4-compile-table)
- [group2compile table](#3-group2compile-table)
- [group2group table](#2-group2group-table)
- [plugin table](#5-plugin-table)
- [ip_plugin table](#6-ip_plugin-table)
- [fqdn_plugin table](#7-fqdn_plugin-table)
- [bool_plugin table](#8-bool_plugin-table)

Different physical tables can be combined into one table, see [conjunction table](#112-12-conjunction-table)

A virtual table can only reference one physical table or conjuntion table, see [virtual table](#111-11-virtual-table)

## 1. <a name='Itemtable'></a> Item table

Item tables are further subdivided into different types of subtables as follows:
- [expr item table](#11-expr-item-table)
- [expr_plus item table](#12-expr_plus-item-table)
- [ip_plus item table](#13-ip_plus-item-table)
- [intval item table](#14-numeric-range-item-table)
- [intval_plus item table](#14-numeric-range-item-table)
- [flag item table](#15-flag-item-table)
- [flag_plus item table](#16-flag_plus-item-table)

Each item table must has the following columns:

- item_id: In a maat instance, the item id is globally unique, meaning that the item IDs of different tables must not be duplicate.

- group_id: Indicate the group to which the item belongs, an item belongs to only one group.

- is_valid: In incremental updates, 1(valid means add) 0(invalid means del)

The range of item_id(group_id, compile_id) is 0～2^63，which is 8 bytes.

### 1.1 <a name='exprtable'></a> expr item table
Describe matching rules for strings.

- table format

| **FieldName**    | **type**       | **NULL** | **constraint** |
| ---------------- | -------------- | -------- | ------- |
| **item_id**      | LONG LONG      | N        | primary key |
| **group_id**     | LONG LONG      | N        | group2group or group2compile table's group_id |
| **keywords**     | VARCHAR2(1024) | N        | field to match during scanning |
| **expr_type**    | INT            | N        | 0(keywords), 1(AND expr), 2(regular expr), 3(substring with offset)
| **match_method** | INT            | N        | only useful when expr_type is 0 |
| **is_hexbin**    | INT            | N        | 0(not HEX & case insensitive, this is default value)  1(HEX & case sensitive)  2(not HEX & case sensitive) |
| **is_valid**     | INT            | N        | 0(invalid), 1(valid) |

- table schema(stored in table_info.conf)
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

**expr_type** column represents the expression type:

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

&ensp;&ensp;Since Maat4.0，only support UTF-8，no more encoding conversion。For binary format configurations, the keyword is hexadecimal, such as the keyword "hello" is represented as "68656C6C6F". A keyword can't contain invisible characters such as spaces, tabs, and CR, which are ASCII codes 0x00 to 0x1F and 0x7F. If these characters need to be used, they must be escaped, refer to the "keywords escape table". Characters led by backslashes outside this table are processed as ordinary strings, such as '\t' will be processed as the string "\t".

The symbol '&' means conjunction operation in AND expression. So if the keywords has '&', it must be escaped by '\&'.

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

Sample
- table schema
- rule
- scanning

table schema stored in table_info.conf
```json
[
    {
        "table_id":0,
        "table_name":"COMPILE",
        "table_type":"compile",
        "valid_column":8,
        "custom": {
            "compile_id":1,
            "tags":6,
            "clause_num":9
        }
    },
    {
        "table_id":1,
        "table_name":"GROUP2COMPILE",
        "table_type":"group2compile",
        "associated_compile_table_id":0,
        "valid_column":3,
        "custom": {
            "group_id":1,
            "compile_id":2,
            "not_flag":4,
            "virtual_table_name":5,
            "clause_index":6
        }
    },
    {
        "table_id":2,
        "table_name":"GROUP2GROUP",
        "table_type":"group2group",
        "valid_column":4,
        "custom": {
            "group_id":1,
            "super_group_id":2,
            "is_exclude":3
        }
    },
    {
        "table_id":3,
        "table_name":"HTTP_URL",
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
 ]
```

rule stored in maat_json.json
```json
{
    "compile_table": "COMPILE",
    "group2compile_table": "GROUP2COMPILE",
    "group2group_table": "GROUP2GROUP",
    "rules": [
        {
            "compile_id": 123,
            "service": 1,
            "action": 1,
            "do_blacklist": 1,
            "do_log": 1,
            "user_region": "anything",
            "is_valid": "yes",
            "groups": [
                {
                    "group_name": "Untitled",
                    "regions": [
                        {
                            "table_name": "HTTP_URL",
                            "table_type": "expr",
                            "table_content": 
                            {
                                "keywords": "multiple disciplines",
                                "expr_type": "none",
                                "match_method": "exact",
                                "format": "uncase plain"
                            }
                        }
                    ]
                }
            ]
        },
        {
            "compile_id": 124,
            "service": 1,
            "action": 1,
            "do_blacklist": 1,
            "do_log": 1,
            "user_region": "anything",
            "is_valid": "yes",
            "groups": [
                {
                    "group_name": "Untitled",
                    "regions": [
                        {
                            "table_name": "HTTP_URL",
                            "table_type": "expr",
                            "table_content": 
                            {
                                "keywords": "baidu.com",
                                "expr_type": "none",
                                "match_method": "suffix",
                                "format": "uncase plain"
                            }
                        }
                    ]
                }
            ]
        },
        {
            "compile_id": 125,
            "service": 1,
            "action": 1,
            "do_blacklist": 1,
            "do_log": 1,
            "user_region": "anything",
            "is_valid": "yes",
            "groups": [
                {
                    "group_name": "Untitled",
                    "regions": [
                        {
                            "table_name": "HTTP_URL",
                            "table_type": "expr",
                            "table_content": 
                            {
                                "keywords": "www",
                                "expr_type": "none",
                                "match_method": "prefix",
                                "format": "uncase plain"
                            }
                        }
                    ]
                }
            ]
        },
        {
            "compile_id": 126,
            "service": 1,
            "action": 1,
            "do_blacklist": 1,
            "do_log": 1,
            "user_region": "anything",
            "is_valid": "yes",
            "groups": [
                {
                    "group_name": "Untitled",
                    "regions": [
                        {
                            "table_name": "HTTP_URL",
                            "table_type": "expr",
                            "table_content": 
                            {
                                "keywords": "abc&123",
                                "expr_type": "and",
                                "match_method": "sub",
                                "format": "uncase plain"
                            }
                        }
                    ]
                }
            ]
        },
        {
            "compile_id": 127,
            "service": 1,
            "action": 1,
            "do_blacklist": 1,
            "do_log": 1,
            "user_region": "anything",
            "is_valid": "yes",
            "groups": [
                {
                    "group_name": "Untitled",
                    "regions": [
                        {
                            "table_name": "HTTP_URL",
                            "table_type": "expr",
                            "table_content": 
                            {
                                "keywords": "action=search\\&query=(.*)",
                                "expr_type": "regex",
                                "match_method": "sub",
                                "format": "uncase plain"
                            }
                        }
                    ]
                }
            ]
        },
        {
            "compile_id": 128,
            "service": 1,
            "action": 1,
            "do_blacklist": 1,
            "do_log": 1,
            "user_region": "anything",
            "is_valid": "yes",
            "groups": [
                {
                    "group_name": "Untitled",
                    "regions": [
                        {
                            "table_name": "HTTP_URL",
                            "table_type": "expr",
                            "table_content": 
                            {
                                "keywords": "1-1:48&3-4:4C4C",
                                "expr_type": "offset",
                                "match_method": "sub",
                                "format": "uncase plain"
                            }
                        }
                    ]
                }
            ]
        }
    ]
}
```

scanning
```c
#include <assert.h>

#include "maat.h"

#define ARRAY_SIZE 16

const char *json_filename = "./maat_json.json";
const char *table_info_path = "./table_info.conf";

int main()
{
    // initialize maat options which will be used by maat_new()
    struct maat_options *opts = maat_options_new();
    maat_options_set_json_file(opts, json_filename);
    maat_options_set_logger(opts, "./sample_test.log", LOG_LEVEL_INFO);

    // create maat instance, rules in table_info.conf will be loaded.
    struct maat *maat_instance = maat_new(opts, table_info_path);
    assert(maat_instance != NULL);
    maat_options_free(opts);

    const char *table_name = "HTTP_URL"; //maat_json.json has HTTP_URL rule
    int table_id = maat_get_table_id(maat_instance, table_name);
    assert(table_id == 3); // defined in table_info.conf

    int thread_id = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    assert(state != NULL);

    const char *scan_data1 = "There are multiple disciplines";
    int ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    assert(ret == MAAT_SCAN_HIT);
    assert(n_hit_result == 1);
    assert(results[0] == 123);

    maat_state_reset(state);
    const char *scan_data2 = "www.baidu.com";
    ret = maat_scan_string(maat_instance, table_id, scan_data2, strlen(scan_data2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    assert(ret == MAAT_SCAN_HIT);
    assert(n_hit_result == 1);
    assert(results[0] == 124);

    maat_state_reset(state);
    const char *scan_data3 = "www.google.com";
    ret = maat_scan_string(maat_instance, table_id, scan_data3, strlen(scan_data3),
                           results, ARRAY_SIZE, &n_hit_result, state);
    assert(ret == MAAT_SCAN_HIT);
    assert(n_hit_result == 1);
    assert(results[0] == 125);

    maat_state_reset(state);
    const char *scan_data4 = "alphabet abc, digit 123";
    ret = maat_scan_string(maat_instance, table_id, scan_data4, strlen(scan_data4),
                           results, ARRAY_SIZE, &n_hit_result, state);
    assert(ret == MAAT_SCAN_HIT);
    assert(n_hit_result == 1);
    assert(results[0] == 126);

    maat_state_reset(state);
    const char *scan_data5 = "http://www.cyberessays.com/search_results.php?action=search&query=username,abckkk,1234567";
    ret = maat_scan_string(maat_instance, table_id, scan_data5, strlen(scan_data5),
                           results, ARRAY_SIZE, &n_hit_result, state);
    assert(ret == MAAT_SCAN_HIT);
    assert(n_hit_result == 1);
    assert(results[0] == 127);

    maat_state_reset(state);
    const char *scan_data6 = "HELLO WORLD";
    ret = maat_scan_string(maat_instance, table_id, scan_data6, strlen(scan_data6),
                           results, ARRAY_SIZE, &n_hit_result, state);
    assert(ret == MAAT_SCAN_HIT);
    assert(n_hit_result == 1);
    assert(results[0] == 128);

    maat_state_free(state);

    return 0;
}
```

### 1.2 <a name='ExprPlusItemTable'></a> expr_plus item table
Describe extended matching rules for strings by adding the district column.

- table format

| **FieldName**    | **type**       | **NULL** | **constraint** |
| ---------------- | -------------- | -------- | ------- |
| **item_id**      | LONG LONG      | N        | primary key |
| **group_id**     | LONG LONG      | N        | group2group or group2compile table's group_id |
| **district**     | VARCHAR2(1024) | N        | describe the effective position of the keywords |
| **keywords**     | VARCHAR2(1024) | N        | field to match during scanning |
| **expr_type**    | INT            | N        | 0(keywords), 1(AND expr), 2(regular expr), 3(substring with offset)
| **match_method** | INT            | N        | only useful when expr_type is 0 |
| **is_hexbin**    | INT            | N        | 0(not HEX & case insensitive, this is default value)  1(HEX & case sensitive)  2(not HEX & case sensitive) |
| **is_valid**     | INT            | N        | 0(invalid), 1(valid) |


For example, if the district is User-Agent and keywords is Chrome, scanning in the following way will hit.
```c
    const char *scan_data = "Chrome is fast";
    const char *district = "User-Agent";

    maat_state_set_scan_district(..., district, ...);
    maat_scan_string(..., scan_data, ...)
```

### 1.3 <a name='IPPlusItemTable'></a> ip_plus item table

Describe matching rules for IP address. Both the address and port are represented by string, IPv4 is dotted decimal and IPv6 is colon separated hexadecimal.

- table format

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

### 1.4 <a name='NumericItemTable'></a> numeric range item table

Determine whether an integer is within a certain numerical range.

- table format

| **FieldName** | **type** | **NULL** | **constraint** |
| ------------- | -------- | -------- | -------------- |
| item_id       | INT      | N        | primary key |
| group_id      | INT      | N        | group2group or group2compile table's group_id |
| low_boundary  | INT      | N        | lower bound of the numerical range(including lb), 0 ~ (2^32 - 1)|
| up_boundary   | INT      | N        | upper bound of the numerical range(including ub), 0 ~ (2^32 - 1)|
| is_valid      | INT      | N        | 0(invalid), 1(valid) |

### 1.5 <a name="FlagItemTable"></a> flag item table

- table format

| **FieldName** | **type** | **NULL** | **constraint** |
| ------------- | -------- | -------- | -------------- |
| item_id       | INT      | N        | primary key |
| group_id      | INT      | N        | group2group or group2compile table's group_id |
| flag          | INT      | N        | flag, 0 ~ (2^32 - 1)|
| flag_mask     | INT      | N        | flag_mask, 0 ~ (2^32 - 1)|
| is_valid      | INT      | N        | 0(invalid), 1(valid) |

### 1.6 <a name="FlagPlusItemTable"></a> flag_plus item table

- table format

| **FieldName** | **type** | **NULL** | **constraint** |
| ------------- | -------- | -------- | -------------- |
| item_id       | INT      | N        | primary key |
| group_id      | INT      | N        | group2group or group2compile table's group_id |
| district      | INT      | N        | describe the effective position of the flag |
| flag          | INT      | N        | flag, 0 ~ (2^32 - 1)|
| flag_mask     | INT      | N        | flag_mask, 0 ~ (2^32 - 1)|
| is_valid      | INT      | N        | 0(invalid), 1(valid) |

### 2. <a name='group2grouptable'></a> group2group table 

Describe the relationship between groups.

- table format

| **FieldName**     | **type**  | **NULL** | **constraint** |
| ----------------- | --------- | -------- | ---------------|
| group_id          | LONG LONG | N        | reference from xx_item table's group_id |
| superior_group_id | LONG LONG | N        | group_id include or exclude specified super_group_id |
| is_exlude         | Bool      | N        | 0(include) 1(exclude) |
| is_valid          | Bool      | N        | 0(invalid), 1(valid) |

### 3. <a name='group2compiletable'></a> group2compile table

Describe the relationship between group and compile.

- table format

| **FieldName** | **type**      | **NULL** | **constraint** |
| ------------- | ------------- | -------- | ------- |
| group_id      | LONG LONG     | N        | reference from xx_item table's group_id|
| compile_id    | LONG LONG     | N        | compile ID |
| is_valid      | INT           | N        | 0(invalid), 1(valid) |
| not_flag      | INT           | N        | logical 'NOT', identify a NOT clause, 0(no) 1(yes) |
| virtual_table | VARCHAR2(256) | N        | virtual table name, default:”null” |
| Nth_clause    | INT           | N        | the clause seq in (conjunctive normal form)CNF, from 0 to 7. groups with the same clause ID are logical 'OR' |

NOTE: If group_id is invalid in xx_item table, it must be marked as invalid in this table.

### 4. <a name='compiletable'></a> compile table

Describe the specific policy, One maat instance can has multiple compile tables with different names.

- table format

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


### 5. <a name='plugintable'></a> plugin table

There is no fixed format for configuration of the plugin table, which is determined by business side. The plugin table supports two sets of callback functions, registered with **maat_table_callback_register** and **maat_plugin_table_ex_schema_register** respectively.

maat_table_callback_register
```c
/*
    When the plugin table configurations are updated, start will be called first and only once, then update will be called by each configuration item, and finish will be called last and only once.

    If configurations have been loaded but maat_table_callback_register has not yet been called, maat will cache the loaded configurations and perform the callbacks(start, update, finish) when registration is complete.
*/

typedef void maat_start_callback_t(int update_type, ...);
//table_line points to one complete configuration line, such as: "1\tHeBei\tShijiazhuang\t1\t0"
typedef void maat_update_callback_t(..., const char *table_line, ...);
typedef void maat_finish_callback_t(...);

int maat_table_callback_register(...,
                                 maat_start_callback_t *start,
                                 maat_update_callback_t *update,
                                 maat_finish_callback_t *finish,
                                 ...);
```

maat_plugin_table_ex_schema_register

```c
/*

*/

typedef void maat_ex_new_func_t(..., const char *key, const char *table_line, ...);
typedef void maat_ex_free_func_t(...);
typedef void maat_ex_dup_func_t(...);

int maat_plugin_table_ex_schema_register(...,
                                         maat_ex_new_func_t *new_func,
                                         maat_ex_free_func_t *free_func,
                                         maat_ex_dup_func_t *dup_func,
                                         ...);
```

three types of keys(pointer, integer and ip_addr) for ex_data callback.

**pointer key(compatible with maat3)**

(1) schema
```json
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
```json
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

(3) register callback
```c

```

(4) get ex_data
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

(3) get ex_data
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

(3) get ex_data
```
uint32_t ipv4_addr;
inet_pton(AF_INET, "100.64.1.1", &ipv4_addr);
const char *table_name = "TEST_PLUGIN_IP_KEY_TYPE";

table_id = maat_get_table_id(maat_instance, table_name);
maat_plugin_table_get_ex_data(maat_instance, table_id, (char *)&ipv4_addr, sizeof(ipv4_addr));
```


### 6. <a name='ip_plugintable'></a> ip_plugin table

Similar to plugin table but the key of maat_ip_plugin_table_get_ex_data is ip address.

### 7. <a name='FQDNPlugintable'></a> fqdn_plugin table

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

### 8. <a name='boolplugintable'></a> bool_plugin table

按照布尔表达式扫描输入的整数数组，如[100,1000,2,3]。

布尔表达式规则为“&”分隔的数字，例如“1&2&1000”。

### 1.11 <a name='virtualtable'></a> virtual table

虚拟一个配置表，其内容为特定物理域配置表的视图。实践中，通常采用网络流量的属性作为虚拟表名，如HTTP_HOST、SSL_SNI等。一个虚拟表可以建立在多个不同类型的物理表之上，但不允许建立在其它虚拟表上。

虚拟表以分组为单位引用实体表中的域配置，引用关系在分组关系表中描述。一个分组可被同一个编译配置的不同虚拟表引用。例如下表，一个关键字的分组keyword_group_1，被一条compile_1的Request Body和Response Body两个虚拟表引用。

| **分组ID**          | **父ID**  | **有效标志** | **非运算标志位** | **父节点类型** | **分组所属虚拟表** |
| ------------------- | --------- | ------------ | ---------------- | -------------- | ------------------ |
| **keyword_group_1** | compile_1 | 1            | 0                | 0              | REQUEST_BODY       |
| **keyword_group_1** | compile_1 | 1            | 0                | 0              | RESPONSE_BODY      |

### 1.12 <a name='conjunctiontable'></a> conjunction table

表名不同，但table id相同的表。旨在数据库表文件和MAAT API之间提供一个虚拟层，通过API调用一次扫描，即可扫描多张同类配置表。

使用方法：

1. 在配置表描述文件中，将需要连接的多个表共用一个table_id；
2. 通过Maat_table_register注册被连接表中的任意一个表名，使用该id进行扫描。

被连接的配置表的各项属性以在配置表描述文件（table_info.conf）中第一个出现的同ID描述行为准，同一table_id下最多支持8个配置表。

支持所有类型表的连接，包括各类域配置、回调类配置。配置分组和配置编译的连接没有意义。

##  2. <a name='ForeignFiles'></a>Foreign Files

回调类配置中，特定字段可以指向一个外部内容，目前支持指向Redis中的一个key。

回调表的外键列，必须具备”redis://”前缀。存放在Redis中的外键内容，其Key必须具备”__FILE_”前缀。当Key为“null”时，表示该文件为空。

例如，原始文件为./testdata/mesa_logo.jpg，计算其MD5值后，得到redis的外键__FILE_795700c2e31f7de71a01e8350cf18525，写入回调表后的格式如下：

```
14	./testdata/digest_test.data	redis://__FILE_795700c2e31f7de71a01e8350cf18525 1
```

​    回调表中的一行最多允许8个外键，外键内容可以通过Maat_cmd_set_file函数设置。

​    Maat在通知回调表前会将外键拉取到本地文件，并将外键列替换为本地文件路径。

​    内容外键的声明方法，参见本文档-配置表描述文件一节。

##  3. <a name='Tags'></a>Tags

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