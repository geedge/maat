# logic AND OR NOT

- [logic AND](#logic-and)
- [logic OR](#logic-or)
- [logic NOT](#logic-not)
- [group exclude](#group-exclude)

## logic AND

rule = China & USA

```json
{
    "compile_id": 123,
    "service": 1,
    "action": 1,
    "do_blacklist": 1,
    "do_log": 1,
    "user_region": "null",
    "is_valid": "yes",
    "groups": [
        {
            "clause_index": 0,
            "regions": [
                {
                    "table_name": "HTTP_URL",
                    "table_type": "expr",
                    "table_content": {
                        "keywords": "China",
                        "expr_type": "none",
                        "match_method": "sub",
                        "format": "uncase plain"
                    }
                }
            ]
        },
        {
            "clause_index": 1,
            "regions": [
                {
                    "table_name": "HTTP_URL",
                    "table_type": "expr",
                    "table_content": {
                        "keywords": "USA",
                        "expr_type": "none",
                        "match_method": "sub",
                        "format": "uncase plain"
                    }
                }
            ]
        }
    ]
}
```

scan sample
```c
    const char *string1 = "China";
	const char *string2 = "USA";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "HTTP_URL";
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_inst, table_id, string1, strlen(string1), 
						       results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, table_id, string2, strlen(string2), 
						       results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 123);
    maat_state_free(state);
```

## logic OR
rule = China | USA

```json
{
    "compile_id": 124,
    "service": 0,
    "action": 0,
    "do_blacklist": 0,
    "do_log": 0,
    "user_region": "null",
    "is_valid": "yes",
    "groups": [
        {
            "regions": [
                {
                    "table_type": "expr",
                    "table_name": "HTTP_URL",
                    "table_content": {
                        "keywords": "China",
                        "expr_type": "none",
                        "format": "uncase plain",
                        "match_method": "prefix"
                    }
                },
                {
                    "table_type": "expr",
                    "table_name": "HTTP_URL",
                    "table_content": {
                        "keywords": "USA",
                        "expr_type": "none",
                        "format": "uncase plain",
                        "match_method": "prefix"
                    }
                }
            ]
        }
    ]
}
```
scan sample
```c
    const char *string1 = "China";
	const char *string2 = "USA";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "HTTP_URL";
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
   
    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_inst, table_id, string1, strlen(string1), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 124);
    maat_state_reset(state);

    ret = maat_scan_string(maat_inst, table_id, string2, strlen(string2), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 124);

    maat_state_free(state);
```

## logic NOT

rule = China & !USA
```json
{
    "compile_id": 125,
    "service": 1,
    "action": 1,
    "do_blacklist": 1,
    "do_log": 1,
    "user_region": "null",
    "is_valid": "yes",
    "groups": [
        {
            "clause_index": 0,
            "not_flag": 0,
            "regions": [
                {
                    "table_name": "HTTP_URL",
                    "table_type": "expr",
                    "table_content": {
                        "keywords": "China",
                        "expr_type": "none",
                        "match_method": "sub",
                        "format": "uncase plain"
                    }
                }
            ]
        },
        {
            "clause_index": 1,
            "not_flag": 1,
            "regions": [
                {
                    "table_name": "HTTP_URL",
                    "table_type": "expr",
                    "table_content": {
                        "keywords": "USA",
                        "expr_type": "none",
                        "match_method": "sub",
                        "format": "uncase plain"
                    }
                }
            ]
        }
    ]
}
```

scan sample
```c
    const char *string1 = "China";
	const char *string2 = "England";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "HTTP_URL";
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_inst, table_id, string1, strlen(string1), 
						       results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

	maat_state_set_last_scan(state);
    ret = maat_scan_string(maat_inst, table_id, string2, strlen(string2), 
						       results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 125);
    maat_state_free(state);
```

## group exclude

```json
 {
    "compile_id": 126,
    "service": 1,
    "action": 1,
    "do_blacklist": 1,
    "do_log": 1,
    "user_region": "null",
    "is_valid": "yes",
    "groups": [
        {
            "group_name": "ExcludeGroup199",
            "sub_groups":[
                {
                    "group_name": "ExcludeGroup199_1",
                    "is_exclude": 0,
                    "clause_index": 0,
                    "regions": [
                        {
                            "table_name": "HTTP_URL",
                             "table_type": "expr",
                            "table_content": {
                                "keywords": "baidu.com",
                                "expr_type": "none",
                                "match_method": "suffix",
                                "format": "uncase plain"
                            }
                        }
                    ]
                },
                {
                    "group_name": "ExcludeGroup199_2",
                    "is_exclude": 1,
                    "clause_index": 0,
                    "regions": [
                        {
                            "table_name": "HTTP_URL",
                            "table_type": "expr",
                            "table_content": {
                                "keywords": "www.baidu.com",
                                "expr_type": "none",
                                "match_method": "exact",
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

scan sample
```c
    const char *string_not_hit = "www.baidu.com";
	const char *string_hit = "mail.baidu.com";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "HTTP_URL";
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(not_hit_table_id, 0);

    int ret = maat_scan_string(maat_inst, table_id, string_not_hit, strlen(string_not_hit), 
						       results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, table_id, string_hit, strlen(string_hit), 
						   results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 126);

    maat_state_free(state);
```