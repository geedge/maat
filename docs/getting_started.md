# Getting started

## Build

```shell
$ mkdir build && cd build
$ cmake ..
$ make
$ make install
```

## Run test

```shell
$ cd build/test
$ ./maat_framework_gtest  #Functional test set
$ ./maat_framework_perf_gtest #Performance test set
```

Maat is used as a dynamic library by applications and its API is defined in the header file(maat.h).

## Use case

A complete use case consists of three parts:

* `table schema`: Define how to parse configuration in different types of tables, that is, specify what each column in the table represents.

* `configuration`: Different types of configurations are stored in tables of the corresponding type.

* `maat_scan_xx/xx_plugin_get_ex_data`: In the scanning scenario, the caller uses the maat_scan_xx api to determine whether the traffic hits effective rules; In the callback scenario, the caller uses the xx_plugin_get_ex_data api to query the ex_data of the specified key. 

### Case1

In the scanning scenario, it is necessary to configure the schema of multiple tables, including the item table, object2rule table, and rule table. If there is also object nesting involved, the schema of the object_group table needs to be configured.

**(1) table schema**

Table schema is stored in a json file(such as table_info.json), which is loaded when maat instance is created.

```json
 [
    {
        "table_id":0,
        "table_name":"RULE",
        "table_type":"rule",
        "default_rule_table":0, /* key:indicate this is the default rule table, value:can be anything(not care) */
        "valid_column":8,
        "custom": {
            "rule_id":1,
            "tags":6,
            "condition_num":9
        }
    },
    {
        "table_id":1,
        "table_name":"OBJECT2RULE",
        "table_type":"object2rule",
        "associated_rule_table_id":0, /* associate rule table_id, object2rule table shares the same runtime with the corresponding rule table, so it needs to be mapped to the corresponding rule table. */
        "valid_column":3,
        "custom": {
            "object_id":1,
            "rule_id":2,
            "negate_option":4,
            "field_name":5,
            "condition_index":6
        }
    },
    {
        "table_id":2,
        "table_name":"OBJECT_GROUP",
        "table_type":"object_group",
        "valid_column":4,
        "custom": {
            "object_id":1,
            "included_sub_object_ids":2,
            "excluded_sub_object_ids":3
        }
    },
    {
        "table_id":3,
        "table_name":"HTTP_URL",
        "table_type":"expr",
        "valid_column":7,
        "custom": {
            "item_id":1,
            "object_id":2,
            "keywords":3,
            "expr_type":4,
            "match_method":5,
            "is_hexbin":6
        }
    }
 ]
```

**(2) configuration**

Configurations are stored in a json file(such as maat_json.json), which is loaded when maat instance is created.
```json
{
    "rule_table": "RULE",
    "object2rule_table": "OBJECT2RULE",
    "object_group_table": "OBJECT_GROUP",
    "rules": [
        {
            "rule_id": 123,
            "service": 1,
            "action": 1,
            "do_blacklist": 1,
            "do_log": 1,
            "user_region": "anything",
            "is_valid": "yes",
            "objects": [
                {
                    "object_name": "Untitled",
                    "regions": [
                        {
                            "table_name": "HTTP_URL",
                            "table_type": "expr",
                            "table_content": {
                                "keywords": "Hello Maat",
                                "expr_type": "none",
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

**(3) scanning**

```C
#include <assert.h>

#include "maat.h"

#define ARRAY_SIZE 16

const char *json_filename = "./maat_json.json";
const char *table_info_path = "./table_info.json";

int main()
{
    /* initialize maat options which will be used by maat_new() */
    struct maat_options *opts = maat_options_new();
    maat_options_set_json_file(opts, json_filename);
    maat_options_set_logger(opts, "./sample_test.log", LOG_LEVEL_INFO);

    /* create maat instance, rules in table_info.json will be loaded. */
    struct maat *maat_instance = maat_new(opts, table_info_path);
    assert(maat_instance != NULL);
    maat_options_free(opts);

    const char *table_name = "HTTP_URL"; /* maat_json.json has HTTP_URL rule */
    int table_id = maat_get_table_id(maat_instance, table_name);
    assert(table_id == 3); /* defined in table_info.json */

    int thread_id = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    
    /* store scanning intermediate state */
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    assert(state != NULL);

    const char *scan_data = "Hello Maat, nice to meet you";

    /**
     * Becase maat instance has loaded rule in table_info.json which keywords is "Hello Maat",
       so maat_scan_string should return hit flag and rule's rule_id stored in results array.
    */
    int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    assert(ret == MAAT_SCAN_HIT);
    assert(n_hit_result == 1);
    assert(results[0] == 123);

    maat_state_free(state);

    return 0;
}

```

### Case2

In the callback scenario, only the schema of the corresponding table needs to be configured.

**(1) table schema**

```json
 [
    {
        "table_id":1,
        "table_name":"TEST_IP_PLUGIN_WITH_EXDATA",
        "table_type":"ip_plugin",
        "valid_column":6,
        "custom": {
            "gc_timeout_s": 3,
            "item_id":1,
            "ip_type":2,
            "start_ip":3,
            "end_ip":4
        }
    }
 ]
```

**(2) configuration**

```json
{
    "rule_table": "RULE",
    "object2rule_table": "OBJECT2RULE",
    "object_group_table": "OBJECT_GROUP",
    "plugin_table": {
        "table_name": "TEST_IP_PLUGIN_WITH_EXDATA",
        "table_content": [
            "101\t4\t192.168.30.99\t192.168.30.101\tSomething-like-json\t1",
            "102\t4\t192.168.30.90\t192.168.30.128\tBigger-range-should-in-the-back\t1",
            "103\t6\t2001:db8:1234::\t2001:db8:1235::\tBigger-range-should-in-the-back\t1",
            "104\t6\t2001:db8:1234::1\t2001:db8:1234::5210\tSomething-like-json\t1",
            ]
        },
}
```

**(3) xx_plugin_get_ex_data**

```C
#include <assert.h>

#include "maat.h"
#include "maat_utils.h"

#define ARRAY_SIZE 16

const char *json_filename = "./maat_json.json";
const char *table_info_path = "./table_info.json";

struct ip_plugin_ud {
	long long rule_id;
	char *buffer;
    size_t buf_len;
};
void ip_plugin_ex_new_cb(const char *table_name, int table_id, const char *key, 
                         const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	size_t column_offset=0, column_len=0;
	struct ip_plugin_ud *ud = ALLOC(struct ip_plugin_ud, 1);

	int ret = get_column_pos(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);

	ud->rule_id = atoll(table_line + column_offset);

	ret = get_column_pos(table_line, 5, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	ud->buffer = ALLOC(char, column_len + 1);
	strncpy(ud->buffer, table_line + column_offset, column_len);

    ud->buf_len = column_len + 1;
	*ad = ud;
	(*counter)++;
}

void ip_plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct ip_plugin_ud *ud = (struct ip_plugin_ud *)(*ad);

    ud->rule_id = 0;
    memset(ud->buffer, 0, ud->buf_len);
    ud->buf_len = 0;

	free(ud->buffer);
	free(ud);
	*ad = NULL;
}

void ip_plugin_ex_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct ip_plugin_ud *ud = (struct ip_plugin_ud *)(*from);
	
	*to = ud;
}

int main()
{
    /* initialize maat options which will be used by maat_new() */
    struct maat_options *opts = maat_options_new();
    maat_options_set_json_file(opts, json_filename);
    maat_options_set_logger(opts, "./sample_test.log", LOG_LEVEL_INFO);

    /* create maat instance, rules in table_info.json will be loaded. */
    struct maat *maat_instance = maat_new(opts, table_info_path);
    assert(maat_instance != NULL);
    maat_options_free(opts);

    const char *table_name = "TEST_IP_PLUGIN_WITH_EXDATA"; /* maat_json.json has TEST_IP_PLUGIN_WITH_EXDATA rule */
    int table_id = maat_get_table_id(maat_instance, table_name);
    assert(table_id == 1); /* defined in table_info.json */

    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                   ip_plugin_ex_new_cb,
                                                   ip_plugin_ex_free_cb,
                                                   ip_plugin_ex_dup_cb,
                                                   0, &ip_plugin_ex_data_counter);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(ip_plugin_ex_data_counter, 4);

    struct ip_addr ipv4;
    ipv4.ip_type = IPv4;
    ret = inet_pton(AF_INET, "192.168.30.100", &ipv4.ipv4);
    EXPECT_EQ(ret, 1);

    /* get ex_data */
    struct ip_plugin_ud *results[ARRAY_SIZE];
    ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_id, &ipv4, 
                                           (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(results[0]->rule_id, 101);
    EXPECT_EQ(results[1]->rule_id, 102);

    struct ip_addr ipv6;
    ipv6.ip_type = IPv6;
    inet_pton(AF_INET6, "2001:db8:1234::5210", &(ipv6.ipv6));
    memset(results, 0, sizeof(results));

	ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_id, &ipv6, 
                                           (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 2);
	EXPECT_EQ(results[0]->rule_id, 104);
	EXPECT_EQ(results[1]->rule_id, 103);

    maat_state_free(state);

    return 0;
}

```