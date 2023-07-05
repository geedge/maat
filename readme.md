<h1 align="left">
  <img src="./docs/imgs/maat_logo.png" height="40px" alt="swarmkv logo"/>
</h1>

**Unified description framework for network flow processing configuration**

## Origin

Maat was the goddness of harmony, justice, and truth in ancient Egyptian. Her feather was the measure that determined whether the souls of the departed would reach the paradise of the afterlife successfully. We use this meaning to metaphorically indicate whether scannning has hit or not.

The Maat framework abstracts the configuration in network flow processing. It supports dynamic loading and multi-machine synchronization of configurations. The core function of Maat is to determine whether a loaded rule has been hit through scanning.

Maat supports three configuration loading modes.

* **Redis mode**(for production): the data source is usually a relational database, such as Oracle, MySQL.
* **JSON File mode**(for production and debugging)
* **IRIS File mode**(for troubleshooting)

**Note**: Redis mode and JSON File mode support configuration dynamic loading

Maat is used as a dynamic library by applications and it's API is defined in the header file(maat.h).

## Building
```shell
mkdir build && cd build
cmake ..
make
make install
```

## Sample
A complete use case consists of three parts
* **table schema**: define how to parse rule in different table, that is specify what each column in a table represents.
* **rule**: different types of rules are stored in tables of the corresponding type.
* **scanning API**: used by application to find whether scan data has hit loaded rules.


### 1. table schema
Table schema is stored in a json file(such as table_info.conf), which is loaded when maat instance is created.

```shell
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

### 2. rule
Rules are stored in a json file(such as maat_json.json), which is loaded when maat instance is created.
```shell
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

### 3. scanning API
Given an example for how to use maat API (JSON File mode)
```C
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

    const char *scan_data = "Hello Maat, nice to meet you";

    /**
     * Becase maat instance has loaded rule in table_info.conf which keywords is "Hello Maat",
       so maat_scan_string should return hit flag and rule's compile_id stored in results array.
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
## More details

* [Introduction](./docs/introduction.md)

* [Table schema](./docs/table_schema.md)

* [Rules](./docs/table_data.md)

* [Scan API](./docs/scan_api.md)

* [Thread mode](./docs/thread_mode.md)

* [Tools](./docs/tools.md)