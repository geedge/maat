# API reference

When using libmaatframe, you need to first call maat_options_new to create a maat_options structure, maat_options_set_xx is used to tell libmaatframe how to behave. Select one of the following interfaces to set the configuration loading mode. Select other maat_options interfaces as required.

* maat_options_set_iris
* maat_options_set_redis
* maat_options_set_json_file

After that, call maat_new to create a maat instance. Next, for the two main usage scenarios, call different interfaces.

`Note`: Both scenarios support multi-threaded calls.

* Scan Scenario

    * Call maat_state_new to create a maat_state structure to save the intermediate state of the scan.

    * Call the maat_scan_xx interface to perform the scan task and return the hit rule_id.

    * If you are interested in the hit item, group, or path information, you can call the maat_state_get_xx interface as needed.

* Callback Scenario

    * Each thread call maat_register_thread initially, then maat will internally maintain the thread_id.

    * Call maat_plugin_table_ex_schema_register to register the callback function.

    * Call xx_plugin_table_get_ex_data to query the ex_data for the specified key.

## common

* [maat_register_thread](#maat_register_thread)
* [maat_reload_log_level](#maat_reload_log_level)
* [maat_get_table_id](#maat_get_table_id)
* [maat_get_table_schema_tag](#maat_get_table_schema_tag)

## maat options

* [maat_options_new](#maat_options_new)
* [maat_options_free](#maat_options_free)
* [maat_options_set_instance_name](#maat_options_set_instance_name)
* [maat_options_set_iris](#maat_options_set_iris)
* [maat_options_set_redis](#maat_options_set_redis)
* [maat_options_set_json_file](#maat_options_set_json_file)
* [maat_options_set_caller_thread_number](#maat_options_set_caller_thread_number)
* [maat_options_set_accept_tags](#maat_options_set_accept_tags)
* [maat_options_set_rule_update_checking_interval_ms](#maat_options_set_rule_update_checking_interval_ms)
* [maat_options_set_gc_timeout_ms](#maat_options_set_gc_timeout_ms)
* [maat_options_set_deferred_load_on](#maat_options_set_deferred_load_on)
* [maat_options_set_stat_on](#maat_options_set_stat_on)
* [maat_options_set_perf_on](#maat_options_set_perf_on)
* [maat_options_set_stat_file](#maat_options_set_stat_file)
* [maat_options_set_foreign_cont_dir](#maat_options_set_foreign_cont_dir)
* [maat_options_set_logger](#maat_options_set_logger)
* [maat_options_set_json_file_gzip_flag](#maat_options_set_json_file_gzip_flag)
* [maat_options_set_json_file_decrypt_key](#maat_options_set_json_file_decrypt_key)
* [maat_options_set_expr_engine](#maat_options_set_expr_engine)
* [maat_options_set_hit_path_enabled](#maat_options_set_hit_path_enabled)
* [maat_options_set_hit_group_enabled](#maat_options_set_hit_group_enabled)

## maat instance

* [maat_new](#maat_new)
* [maat_free](#maat_free)

## maat state

* [maat_state_new](#maat_state_new)
* [maat_state_reset](#maat_state_reset)
* [maat_state_free](#maat_state_free)
* [maat_state_set_scan_district](#maat_state_set_scan_district)
* [maat_state_set_scan_rule_table](#maat_state_set_scan_rule_table)
* [maat_state_get_hit_paths](#maat_state_get_hit_paths)
* [maat_state_get_rule_table_ids](#maat_state_get_rule_table_ids)
* [maat_state_get_scan_count](#maat_state_get_scan_count)
* [maat_state_get_direct_hit_groups](#maat_state_get_direct_hit_groups)
* [maat_state_get_direct_hit_group_cnt](#maat_state_get_direct_hit_group_cnt)
* [maat_state_get_indirect_hit_groups](#maat_state_get_indirect_hit_groups)
* [maat_state_get_indirect_hit_group_cnt](#maat_state_get_indirect_hit_group_cnt)
* [maat_state_get_last_hit_groups](#maat_state_get_last_hit_groups)
* [maat_state_get_last_hit_group_cnt](#maat_state_get_last_hit_group_cnt)

## maat scan

* [maat_scan_flag](#maat_scan_flag)
* [maat_scan_integer](#maat_scan_integer)
* [maat_scan_ipv4](#maat_scan_ipv4)
* [maat_scan_ipv6](#maat_scan_ipv6)
* [maat_scan_string](#maat_scan_string)
* [maat_scan_group](#maat_scan_group)
* [maat_scan_not_logic](#maat_scan_not_logic)

## maat stream

* [maat_stream_new](#maat_stream_new)
* [maat_stream_scan](#maat_stream_scan)
* [maat_stream_free](#maat_stream_free)

## maat plugin

* [maat_table_callback_register](#maat_table_callback_register)
* [maat_plugin_table_ex_schema_register](#maat_plugin_table_ex_schema_register)
* [maat_plugin_table_get_ex_data](#maat_plugin_table_get_ex_data)
* [maat_ip_plugin_table_get_ex_data](#maat_ip_plugin_table_get_ex_data)
* [maat_ipport_plugin_table_get_ex_data](#maat_ipport_plugin_table_get_ex_data)
* [maat_fqdn_plugin_table_get_ex_data](#maat_fqdn_plugin_table_get_ex_data)
* [maat_bool_plugin_table_get_ex_data](#maat_bool_plugin_table_get_ex_data)

# maat command

* [maat_cmd_set_line](#maat_cmd_set_line)
* [maat_cmd_set_file](#maat_cmd_set_file)
* [maat_cmd_incrby](#maat_cmd_incrby)
* [maat_cmd_flushDB](#maat_cmd_flushdb)

## maat helper

* [maat_helper_read_column](#maat_helper_read_column)
* [maat_helper_verify_regex_expression](#maat_helper_verify_regex_expression)

### maat_register_thread

```c
void maat_register_thread(struct maat *instance);
```

Each thread can call this function initially, maat will maintain the thread_id internally, So it's no need to pass thread_id by maat_state_new and xx_plugin_get_ex_data API.

**Parameters**: 
* instance - Maat instance created by maat_new().

**Returns**: no returns


### maat_reload_log_level

```c
void maat_reload_log_level(struct maat *instance, enum log_level level);
```

Update maat log level dynamically(at runtime).

**Parameters**:
* instance - Maat instance created by maat_new().

* level - Log output level
    * LOG_LEVEL_TRACE
    * LOG_LEVEL_DEBUG
    * LOG_LEVEL_INFO
    * LOG_LEVEL_WARN
    * LOG_LEVEL_ERROR
    * LOG_LEVEL_FATAL

**Returns**: no returns


### maat_get_table_id

```c
int maat_get_table_id(struct maat *instance, const char *table_name);
```

Gets the ID of the specified table.

**Parameters**:
* instance - Maat instance created by maat_new().
* table_name - The name of table.

**Returns**: success(>=0), failure(-1)


### maat_get_table_schema_tag

```c
const char *maat_get_table_schema_tag(struct maat *instance, int table_id);
```

Gets the value of the tag field in the specified table's schema, and returns NULL if there is no tag field.

**Parameters**:
* instance - Maat instance created by maat_new().
* table_name - The table ID.

**Returns**: The value of tag field on success and NULL on failure.


### maat_options_new

```c
struct maat_options *maat_options_new(void);
```

Create the maat_options structure which will be set on the maat instance.

**Parameters**:
* instance - Maat instance created by maat_new().

**Returns**: The maat_options pointer on success and NULL on failure.


### maat_options_free

```c
void maat_options_free(struct maat_options *opts);
```

Destroy a maat_options structure.

**Parameters**:
* opts - The pointer of maat_options structure.

**Returns**: no returns


### maat_options_set_instance_name

```c
int maat_options_set_instance_name(struct maat_options *opts, const char *instance_name);
```

Set the name of the maat instance, which will be used as the output log file name and the monitor_loop thread name.

**Parameters**:
* opts - The pointer of maat_options structure.
* instance_name - The name of maat instance.

**Returns**: success(0), failure(-1)


### maat_options_set_iris

```c
int maat_options_set_iris(struct maat_options *opts, const char *full_directory, 
                          const char *increment_directory);
```

Set maat to use iris file mode for configuration loading, and set the file path for full and incremental configuration.

**Parameters**:
* opts - The pointer of maat_options structure.
* full_directory - Full configuration file path.
* increment_directory - Increment configuration file path.

**Returns**: success(0), failure(-1)


### maat_options_set_redis

```c
int maat_options_set_redis(struct maat_options *opts, const char *redis_ip, 
                           uint16_t redis_port, int redis_db);
```

Set maat to use redis mode for configuration loading, and set the redis_ip,redis_port and redis_db.

**Parameters**:
* opts - The pointer of maat_options structure.
* redis_ip - Redis ip address to connect to
* redis_port - Redis port number to connect to.
* redis_db - Redis db index to connect to.

**Returns**: success(0), failure(-1)


### maat_options_set_json_file

```c
int maat_options_set_json_file(struct maat_options *opts,
                               const char *json_filename);
```

Set maat to use json file mode for configuration loading, and set the path of the json file.

**Parameters**:
* opts - The pointer of maat_options structure.
* json_filename - The path of the json file.

**Returns**: success(0), failure(-1)


### maat_options_set_accept_tags

```c
int maat_options_set_accept_tags(struct maat_options *opts,
                                 const char *accept_tags);
```

Set the `accept tags` of the maat instance. If it matches the tags in the configuration, the configuration will be loaded by the maat. Otherwise, the configuration will not be loaded. That is, to implement the selective loading of the configuration.

**Parameters**:
* opts - The pointer of maat_options structure.
* accept_tags - The string of accept tags.

**Returns**: success(0), failure(-1)


### maat_options_set_caller_thread_number

```c
int maat_options_set_caller_thread_number(struct maat_options *opts,
                                          size_t n_thread);
```

Sets the number of threads that the caller will use to execute maat_scan_xx or xx_plugin_table_get_ex_data.

**Parameters**:
* opts - The pointer of maat_options structure.
* n_thread - The number of threads.

**Returns**: success(0), failure(-1)


### maat_options_set_rule_update_checking_interval_ms

```c
int maat_options_set_rule_update_checking_interval_ms(struct maat_options *opts,
                                                      int interval_ms);
```

The background update thread (monitor_loop) of maat will periodically check for configuration updates, and this interface is used to set this time interval.

**Parameters**:
* opts - The pointer of maat_options structure.
* interval_ms - Time interval, unit: milliseconds.

**Returns**: success(0), failure(-1)


### maat_options_set_gc_timeout_ms

```c
int maat_options_set_gc_timeout_ms(struct maat_options *opts, int interval_ms);
```

Maat uses the RCU mechanism to build the runtime. When the new runtime takes effect, the old runtime is put into the garbage collection queue for periodic collection. This interface is used to set the collection period of the garbage collection queue.

**Parameters**:
* opts - The pointer of maat_options structure.
* interval_ms - Time interval, unit: milliseconds.

**Returns**: success(0), failure(-1)


### maat_options_set_deferred_load_on

```c
int maat_options_set_deferred_load_on(struct maat_options *opts);
```

By default, when the `maat_new` interface is called, maat synchronously loads all configurations. The maat instance pointer is returned after the configurations are successfully loaded. The more configurations there are, the longer the function's return time. If the above interface is called, it will immediately return the maat instance pointer without blocking the caller, and the deferred loading of configurations is implemented internally by maat.

**Parameters**:
* opts - The pointer of maat_options structure.

**Returns**: success(0), failure(-1)


### maat_options_set_stat_on

```c
int maat_options_set_stat_on(struct maat_options *opts);
```

By default, maat does not output runtime statistics, which can be done if the interface is called.

**Parameters**:
* opts - The pointer of maat_options structure.

**Returns**: success(0), failure(-1)


### maat_options_set_stat_file

```c
int maat_options_set_stat_file(struct maat_options *opts,
                               const char *stat_filename);
```

Specifies the file name and path to output maat runtime statistics.

**Parameters**:
* opts - The pointer of maat_options structure.

**Returns**: success(0), failure(-1)


### maat_options_set_perf_on

```c
int maat_options_set_perf_on(struct maat_options *opts);
```

By default, maat does not collect statistics on the cpu consumption during the runtime scanning process, which reduces the scanning performance. This interface indicates that the maat needs to output statistics on the cpu consumption.

**Parameters**:
* opts - The pointer of maat_options structure.

**Returns**: success(0), failure(-1)


### maat_options_set_foreign_cont_dir

```c
int maat_options_set_foreign_cont_dir(struct maat_options *opts, const char *dir);
```

The maat can not only pull configurations from redis line by line, but also read files from redis. This interface specifies the file storage path.

**Parameters**:
* opts - The pointer of maat_options structure.
* dir - The storage path of the file.

**Returns**: success(0), failure(-1)


### maat_options_set_logger

```c
int maat_options_set_logger(struct maat_options *opts, const char *log_path,
                            enum log_level level);
```

Set the path and level of the maat instance output log.

**Parameters**:
* opts - The pointer of maat_options structure.
* log_path - The path for storing log files.
* level - Log output level.
    * LOG_LEVEL_TRACE
    * LOG_LEVEL_DEBUG
    * LOG_LEVEL_INFO
    * LOG_LEVEL_WARN
    * LOG_LEVEL_ERROR
    * LOG_LEVEL_FATAL

**Returns**: success(0), failure(-1)


### maat_options_set_json_file_gzip_flag

```c
int maat_options_set_json_file_gzip_flag(struct maat_options *opts, int flag);
```

By default, if you choose json file mode to load the configuration, maat reads the configuration file directly to build the runtime. If the json file is gzip compressed, call this interface to indicate that maat needs to decompress it first.


**Parameters**:
* opts - The pointer of maat_options structure.
* flag - 1(compressed) 0(uncompressed)

**Returns**: success(0), failure(-1)


### maat_options_set_json_file_decrypt_key

```c
int maat_options_set_json_file_decrypt_key(struct maat_options *opts,
                                           const char *decrypt_key);
```

By default, if you choose json file mode to load the configuration, maat reads the configuration file directly to build the runtime. If the json file is already encrypted by openssl (see openssl encryption/decryption), call this interface to indicate that maat needs to decrypt it first. Of course, the json file can also be compressed using gzip and then encrypted using openssl. In this case, the above two interfaces need to be set at the same time. maat will decrypt and decompress the json file.

**Parameters**:
* opts - The pointer of maat_options structure.
* decrypt_key - Decryption key.

**Returns**: success(0), failure(-1)


### maat_options_set_expr_engine

```c
int maat_options_set_expr_engine(struct maat_options *opts,
                                 enum maat_expr_engine engine);
```

Set the scan engine used by all expr tables.

**Parameters**:
* opts - The pointer of maat_options structure.
* engine - default(MAAT_EXPR_ENGINE_AUTO)
    * MAAT_EXPR_ENGINE_HS 
    * MAAT_EXPR_ENGINE_RS
    * MAAT_EXPR_ENGINE_AUTO

**Returns**: success(0), failure(-1)


### maat_options_set_hit_path_enabled

```c
int maat_options_set_hit_path_enabled(struct maat_options *opts);
```

By default, maat does not store the hit path, and you can call this interface if you need to get this information.

**Parameters**:
* opts - The pointer of maat_options structure.

**Returns**: success(0), failure(-1)


### maat_options_set_hit_group_enabled

```c
int maat_options_set_hit_group_enabled(struct maat_options *opts);
```

By default, maat does not store the hit groups, and you can call this interface if you need to get this information.

**Parameters**:
* opts - The pointer of maat_options structure.

**Returns**: success(0), failure(-1)


### maat_new

```c
struct maat *maat_new(struct maat_options *opts, const char *table_info_path);
```

Create a maat instance based on maat options and table schema.

**Parameters**:
* opts - Maat options is used to tell libmaatframe how to behave.
* table_info_path - File path to store table schema information.

**Returns**: The maat instance pointer on success and NULL on failure.

### maat_free

```c
void maat_free(struct maat *instance);
```

Destroy a maat instance.

**Parameters**:
* instance - Maat instance created by maat_new().

**Returns**: no returns


### maat_state_new

```c
struct maat_state *maat_state_new(struct maat *instance, int thread_id);
```

Before performing the actual scanning task, you need to call this interface to create a per-thread maat_state structure, which will be used as an input parameter when calling the maat_scan_xx interface to store the intermediate scanning state. This is especially useful in composite scanning scenarios to accurately provide all hit results from multiple scans. Additionally, hit paths, group_id of hits, and other information generated by the scanning are temporarily stored in it, and can be retrieved through the maat_state_get_xx interface.

**Parameters**:
* instance - Maat instance created by maat_new().
* thread_id - Thread id of the caller.

**Returns**: return NULL if an error occurs.


### maat_state_reset
```c
void maat_state_reset(struct maat_state *state);
```

Reset a maat_state to an initial state. Conceptually, this is equivalent to performing maat_state_free() followed by a maat_state_new(). This interface can avoid unnecessary memory allocation and deallocation operations for maat_state.

**Parameters**:
* state - Pointer to the maat state structure to be reset.

**Returns**: no returns


### maat_state_free

```c
void maat_state_free(struct maat_state *state);
```

Destroy a maat_state structure.

**Parameters**:
* state - Pointer to the maat state structure to be reset.

**Returns**: no returns


### maat_state_set_scan_district

```c
int maat_state_set_scan_district(struct maat_state *state, int table_id, 
                                 const char *district, size_t district_len);
```

To set the field to be matched in the next scan, for example: if you want to match traffic where the User-Agent field is Chrome, you need to call this interface and pass in the User-Agent string (case-sensitive) for setting.

**Parameters**:
* state - Pointer to the maat state structure.
* table_id - The table ID.
* district - The string of the field to be matched.
* district_len - The length of string.

**Returns**: success(0) failure(-1)


### maat_state_set_scan_rule_table

```c
int maat_state_set_scan_rule_table(struct maat_state *state,
                                      int rule_table_id);
```

Maat supports loading multiple rule tables and building their respective runtime. Within the table schema, there is a rule table that has a `default_rule_table` field, indicating that maat will use the runtime of this table to calculate which rule_id will be hit by the hit group_id. If the caller wants to use another rule table runtime for the above calculation, this interface can be invoked to set it up.

**Parameters**:
* state - Pointer to the maat state structure.
* rule_table_id - The rule table ID.

**Returns**: success(0) failure(-1)


### maat_state_get_hit_paths

```c
int maat_state_get_hit_paths(struct maat_state *state,
                             struct maat_hit_path *path_array, 
                             size_t array_size);
```

Gets all hit paths since maat state was created.

**Parameters**:
* state - Pointer to the maat state structure.
* path_array - Array for storing hit paths
* array_size - Size of the array.

**Returns**: The number of hit paths is returned on success, and -1 is returned on failure.


### maat_state_get_rule_table_ids

```c
int maat_state_get_rule_table_ids(struct maat_state *state,
                                     long long *rule_ids,
                                     size_t n_rule_ids,
                                     int *rule_table_ids);
```

Get the ID of the table that rule_id belongs to.

**Parameters**:
* state - Pointer to the maat state structure.
* rule_ids - Array of rule_ids.
* n_compild_ids - The number of rule_ids.
* rule_table_ids - The array of id of the tables to which each rule id belongs.

**Returns**: The number of rule table ids is return on success, and -1 is returned on failure.


### maat_state_get_scan_count

```c
size_t maat_state_get_scan_count(struct maat_state *state)
```

Gets the number of scans since maat state was created.

**Parameters**:
* state - Pointer to the maat state structure.

**Returns**: The number of scans.


### maat_state_get_direct_hit_groups

```c
int maat_state_get_direct_hit_groups(struct maat_state *state,
                                     struct maat_hit_group *group_array,
                                     size_t array_size);
```

Get the direct hit_groups, including the table_id from the scan input, the item_id and its group_id in the corresponding item table.

`Note`: hit_groups may be duplicated.

**Parameters**:
* state - Pointer to the maat state structure.
* group_array - Array to store the maat_hit_groups.
* array_size - Size of the array.

**Returns**: The number of direct hit_groups on success, and -1 is returned on failure.


### maat_state_get_direct_hit_group_cnt

```c
size_t maat_state_get_direct_hit_group_cnt(struct maat_state *state);
```

Get the number of direct hit_groups.

**Parameters**:
* state - Pointer to the maat state structure.

**Returns**: The number of direct hit_groups.


### maat_state_get_indirect_hit_groups

```c
int maat_state_get_indirect_hit_groups(struct maat_state *state,
                                       struct maat_hit_group *group_array,
                                       size_t array_size);
```

Gets the indirect hit_groups, including the table_id from the scan input, the id of the super groups referencing the hit items.

`Note`: hit_groups may be duplicated.

**Parameters**:
* state - Pointer to the maat state structure.
* group_array - Array to store the maat_hit_groups.
* array_size - Size of the array.

**Returns**: The number of indirect hit_groups on success, and -1 is returned on failure.


### maat_state_get_indirect_hit_group_cnt

```c
size_t maat_state_get_indirect_hit_group_cnt(struct maat_state *state);
```

Get the number of indirect hit_groups.

**Parameters**:
* state - Pointer to the maat state structure.

**Returns**: The number of indirect hit_groups.


### maat_state_get_last_hit_groups

```c
int maat_state_get_last_hit_groups(struct maat_state *state,
                                   struct maat_hit_group *group_array,
                                   size_t array_size);
```

Get all hit_groups in the latest scan, including the table_id from the scan input, the item_id and its group_id in the corresponding item table, the id of the super groups referencing the hit items.

`Note`: hit_groups is not duplicated.

**Parameters**:
* state - Pointer to the maat state structure.
* group_array - Array to store the maat_hit_groups.
* array_size - Size of the array.

**Returns**: The number of all hit_groups in the latest scan on success, and -1 is returned on failure.


### maat_state_get_last_hit_group_cnt

```c
size_t maat_state_get_last_hit_group_cnt(struct maat_state *state);
```

Get the number of all hit_groups in the latest scan.

**Parameters**:
* state - Pointer to the maat state structure.

**Returns**: The number of all hit_groups in the latest scan.


### maat_scan_flag

```c
int maat_scan_flag(struct maat *instance, int table_id, long long flag,
                   long long *results, size_t n_result, size_t *n_hit_result,
                   struct maat_state *state);
```

Check if the `flag` in the scan input hits the rules in the effective rule table. If there is a hit, put the rule_id of the rules into the results array and put the number of hit rule_ids into n_hit_result.

**Parameters**:
* instance - Maat instance created by maat_new().
* table_id - ID of the table to be scanned.
* flag - Data to be scanned.
* results - Array to store hit rule_ids.
* n_result - Size of the results array.
* n_hit_result - The number of hit rule_ids.
* state - Used to store the intermediate state of the scan.

**Returns**: 
* MAAT_SCAN_ERR - An error occurred with the scan.
* MAAT_SCAN_OK - Scan without error and without any hits.
* MAAT_SCAN_HALF_HIT - Half hit.
* MAAT_SCAN_HIT - Full hit.


### maat_scan_integer

```c
int maat_scan_integer(struct maat *instance, int table_id, long long integer,
                      long long *results, size_t n_result, size_t *n_hit_result,
                      struct maat_state *state);
```

Same as above, the difference is that the data to be scanned is an integer.


### maat_scan_ipv4

```c
int maat_scan_ipv4(struct maat *instance, int table_id, uint32_t ip_addr,
                   long long *results, size_t n_result, size_t *n_hit_result,
                   struct maat_state *state);
```

Same as above, the difference is that the data to be scanned is an ipv4 address.

### maat_scan_ipv6

```c
int maat_scan_ipv6(struct maat *instance, int table_id, uint8_t *ip_addr,
                   long long *results, size_t n_result, size_t *n_hit_result,
                   struct maat_state *state);
```

Same as above, the difference is that the data to be scanned is an ipv6 address.


### maat_scan_string

```c
int maat_scan_string(struct maat *instance, int table_id,
                     const char *data, size_t data_len,
                     long long *results, size_t n_result,
                     size_t *n_hit_result, struct maat_state *state);
```

Same as above, the difference is that the data to be scanned is a string.

### maat_scan_group

```c
int maat_scan_group(struct maat *instance, int table_id,
                    struct maat_hit_group *groups, size_t n_group,
                    long long *results, size_t n_result,
                    size_t *n_hit_result, struct maat_state *state);
```

Different from the above interface, the input to this interface is the hit item_id and group_id. Therefore, there is no need to execute the underlying scanning engine. It only needs to calculate the hit rule_id based on the hit group_id.


### maat_scan_not_logic

```c
int maat_scan_not_logic(struct maat *instance, int table_id,
                        long long *results, size_t n_result,
                        size_t *n_hit_result, struct maat_state *state);
```

If the rule configuration contains negate-conditions, this interface needs to be called to activate the calculation of rule_id involving negate-conditions. This means that other scanning interfaces will not activate negate-conditions except for calling this interface. When to call this interface is determined by the caller. For example, on a session, four packets were scanned with maat_scan_string and three rule_id were hit. The negate-condition was expected to be activated, so this interface was called and two new rule_id were hit.

Since this interface only activates non-conditions and does not call the underlying scanning engine to perform actual scanning tasks, there is no data to be scanned.


### maat_stream_new

```c
struct maat_stream *maat_stream_new(struct maat *instance, int table_id,
                                    struct maat_state *state);

```

Before executing streaming scanning tasks, this interface needs to be called to create a maat_stream handle and pass it as an input parameter to `maat_stream_scan`. 

`Note`: It is usually called once at the beginning of a session.

**Parameters**:
* instance - Maat instance created by maat_new().
* table_id - ID of the table to be scanned.
* state - Used to store the intermediate state of the scan.

**Returns**: The maat stream handle on success, NULL on failure.


### maat_stream_scan

```c
int maat_stream_scan(struct maat_stream *stream, const char *data, int data_len, 
                     long long *results, size_t n_result, size_t *n_hit_result,
                     struct maat_state *state);
```

This interface is used to perform streaming scanning tasks, for example: in a session, consecutively scanning multiple packets and providing the hit rule_ids.

**Parameters**:
* stream - Maat_stream handle created by maat_stream_new().
* data - Data to be scanned.
* data_len - The length of the data.
* results - Array to store hit rule_ids.
* n_result - Size of the results array.
* n_hit_result - The number of hit rule_ids.
* state - Used to store the intermediate state of the scan.

**Returns**:
* MAAT_SCAN_ERR - An error occurred with the scan.
* MAAT_SCAN_OK - Scan without error and without any hits.
* MAAT_SCAN_HALF_HIT - Half hit.
* MAAT_SCAN_HIT - Full hit.

### maat_stream_free

```c
void maat_stream_free(struct maat_stream *stream);
```

Destroy a maat_stream handle.

**Parameters**:
* stream - Maat_stream handle created by maat_stream_new().

**Returns**: no returns


### maat_table_callback_register

```c
int maat_table_callback_register(struct maat *instance, int table_id,
								 maat_start_callback_t *start_cb,
								 maat_update_callback_t *update_cb,
								 maat_finish_callback_t *finish_cb,
								 void *u_para);
```

This interface registers a set of callback functions for a plugin table. When a round of updates for the specified table begins, the start_cb will be called once with information about whether it is a full or incremental update passed as its input parameter. The update_cb will be called for each update configuration, and the finish_cb will be called once when a round of updates ends. If there is user-defined data, it can be placed in the u_para position and will be passed as an input parameter in start_cb, update_cb, and finish_cb.

From the above, it is evident that this set of callbacks is concerned with changes to the table, including when the table starts to change (start_cb), the type of change (full or incremental), when the change ends (finish_cb), and the specific content of each change (update_cb).

**Parameters**:
* instance - Maat instance created by maat_new().
* table_id - ID of the table to be registered.
* start_cb - Called once before a round of configuration updates begins.
* update_cb - Called for each update configuration.
* finish_cb - Called once after a round of configuration updates ends.
* u_para -  User-defined data.

**Returns**: success(0), failure(-1)


### maat_plugin_table_ex_schema_register

```c
int maat_plugin_table_ex_schema_register(struct maat *instance,
                                         const char *table_name,
                                         maat_ex_new_func_t *new_func,
                                         maat_ex_free_func_t *free_func,
                                         maat_ex_dup_func_t *dup_func,
                                         long argl, void *argp);
```

This interface registers a set of callback functions for the xx_plugin table. Unlike the callbacks registered with `maat_table_callback_register`, when adding a configuration, the new_func is called immediately, and when deleting a configuration, the free_func is not called immediately due to the introduction of a garbage collection mechanism. Instead, the free_func is called when the garbage collection queue starts the collection process. If there is a sequence of configuration additions and deletions as follows:

1. add rule1 - new_func(rule1)
2. del rule1 - free_func(rule1)
3. add rule2 - new_func(rule2)

Step 3 usually occurs before Step 2.

The dup_func is only called when the user invokes `xx_plugin_table_get_ex_data`.

From the above, it is evident that this set of callbacks is concerned with the specific configuration changes line by line, which configuration is added (new_func), which configuration is deleted (free_func), and which configuration can be queried for ex_data (dup_func).

**Parameters**:
* instance - Maat instance created by maat_new().
* table_name - Name of the table to be registered.
* new_func - The function called when adding a configuration.
* free_func - The function called when deleting a configuration.
* dup_func - The function called when quering a configuration.
* argl - User-defined data.
* argp - User-defined data.

**Returns**: success(0), failure(-1)


### maat_plugin_table_get_ex_data

```c
void *maat_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                    const char *key, size_t key_len);
```

Get ex_data for the specified key in the plugin table. This interface supports three types of keys to query ex_data.

1. Pointer key(compatible with maat3)
2. Integer key
3. Ipv4 or ipv6 address as key.

**Parameters**:
* instance - Maat instance created by maat_new().
* table_id - ID of the table to be queried.
* key - The key to be queried.
* key_len - The length of the key.

**Returns**: Return NULL if no ex data is queried.


### maat_ip_plugin_table_get_ex_data

```c
int maat_ip_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                     const struct ip_addr *ip_addr,
                                     void **ex_data_array, size_t array_size);
```

Same as above, the difference is that the key is the ip address.


### maat_ipport_plugin_table_get_ex_data

```c
int maat_ipport_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                         const struct ip_addr *ip_addr, uint16_t port,
                                         void **ex_data_array, size_t array_size);
```

Same as above, the difference is that the key is the ip address + port.


### maat_fqdn_plugin_table_get_ex_data

```c
int maat_fqdn_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                       const char *fqdn, void **ex_data_array, 
                                       size_t array_size);
```

Same as above, the difference is that the key is the fqdn string.


### maat_bool_plugin_table_get_ex_data

```c
int maat_bool_plugin_table_get_ex_data(struct maat *instance, int table_id,
                                       unsigned long long *item_ids, size_t n_item,
                                       void **ex_data_array, size_t array_size);
```

Same as above, the difference is that the key is the array of integer.


### maat_cmd_set_line

```c
int maat_cmd_set_line(struct maat *maat_instance,
                      const struct maat_cmd_line *line_rule);
```

This interface supports writing a configuration line into redis.

**Parameters**:
* instance - Maat instance created by maat_new().
* line_rule - The configuration to be written.

**Returns**: success(1), failure(-1)


### maat_cmd_set_file

```c
int maat_cmd_set_file(struct maat *maat_instance, const char *key,
                      const char *value, size_t size, enum maat_operation op);
```

This interface supports writing a configuration file into redis.

**Parameters**:
* instance - Maat instance created by maat_new().
* key - The string of the key.
* value - The string of the value.
* size - The length of the value.
* op - add or del.

**Returns**: success(1), failure(-1)


### maat_cmd_incrby

```c
long long maat_cmd_incrby(struct maat *maat_instance, const char *key,
                          int increment);
```

Increments the number stored on the key in redis.

**Parameters**:
* instance - Maat instance created by maat_new().
* key - The string of the key.
* increment - Numbers to add up.

**Returns**: success(>=0), failure(-1)


### maat_cmd_flushDB

```c
int maat_cmd_flushDB(struct maat *maat_instance);
```

Delete all the keys of the currently selected DB. 

**Parameters**:
* instance - Maat instance created by maat_new().

**Returns**: success(0), failure(-1)


### maat_helper_read_column

```c
int maat_helper_read_column(const char *table_line, int Nth_column, 
                            size_t *column_offset, size_t *column_len);
```

This interface is used to parse the offset and length of a column in a configuration line. Each column in a configuration line is separated by a tab.

For example: hello\t123\tworld
If you want to parse the second column, then Nth_column = 2, column_offset = 123, and column_len = 3.

**Parameters**:
* table_line - Configuration to be parsed.
* Nth_column - Column index.
* column_offset - The offset of the column.
* column_len - The length of the column.

**Returns**: success(0), failure(-1)

### maat_helper_verify_regex_expression

```c
int maat_helper_verify_regex_expression(const char *expression);
```

This interface is used to determine if the given string is a regular expression.

**Parameters**:
* expression - The string to be checked.

**Returns**: success(0), failure(-1)