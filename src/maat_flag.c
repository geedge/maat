/*
**********************************************************************************************
*	File: maat_flag.cpp
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "maat_flag.h"
#include "flag_matcher.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "log/log.h"
#include "uthash/uthash.h"
#include "rcu_hash.h"
#include "maat_table.h"
#include "alignment.h"
#include "maat_compile.h"
#include "maat_garbage_collection.h"

#define MODULE_FLAG	 module_name_str("maat.flag")

struct flag_schema {
    int item_id_column;
    int group_id_column;
    int district_column;
    int flag_column;
    int flag_mask_column;
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

struct flag_item {
    long long item_id;
    long long group_id;
    long long district_id;
    long long flag;
    long long flag_mask;
};

struct flag_runtime {
    struct flag_matcher *matcher;
    struct rcu_hash_table *htable;       //store flag rule for rebuild flag_matcher instance
    struct rcu_hash_table *item_htable;  //store this flag table's all maat_item which will be used in flag_runtime_scan
    uint32_t rule_num;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
    int district_num;
    struct maat_kv_store *district_map;
    struct maat_kv_store *tmp_district_map;

    long long *scan_cnt;
    long long *hit_cnt;
};

void *flag_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                      const char *table_name, struct log_handle *logger)
{
    struct flag_schema *schema = ALLOC(struct flag_schema, 1);

    char table_type[NAME_MAX] = {0};
    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
    } else {
        log_error(logger, MODULE_FLAG, 
                  "[%s:%d] table %s has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    /* table_type already validate in maat_table_new() */
    item = cJSON_GetObjectItem(json, "table_type");
    memcpy(table_type, item->valuestring, strlen(item->valuestring));

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_FLAG, 
                  "[%s:%d] table %s has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->item_id_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_FLAG, 
                  "[%s:%d] table %s has no item_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->group_id_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_FLAG, 
                  "[%s:%d] table %s has no group_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    /* flag_plus has district */
    if (strcmp(table_type, "flag_plus") == 0) {
        custom_item = cJSON_GetObjectItem(item, "district");
        if (custom_item != NULL && custom_item->type == cJSON_Number) {
            schema->district_column = custom_item->valueint;
        } else {
            log_error(logger, MODULE_FLAG, 
                  "[%s:%d] flag_plus table %s has no district column", 
                  __FUNCTION__, __LINE__, table_name);
            goto error;
        }
    }

    custom_item = cJSON_GetObjectItem(item, "flag");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->flag_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_FLAG, 
                  "[%s:%d] table %s has no flag column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "flag_mask");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->flag_mask_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_FLAG, 
                  "[%s:%d] table %s has no flag_mask column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    schema->ref_tbl_mgr = tbl_mgr;
    return schema;
error:
    FREE(schema);
    return NULL;
}

void flag_schema_free(void *flag_schema)
{
    FREE(flag_schema);
}

void flag_ex_data_free(void *user_ctx, void *data)
{
    struct flag_item *flag_item = (struct flag_item *)data;
    FREE(flag_item);
}

void flag_maat_item_free(void *user_ctx, void *data)
{
    struct maat_item *item = (struct maat_item *)data;
    maat_item_free(item);
}

void *flag_runtime_new(void *flag_schema, int max_thread_num, 
                       struct maat_garbage_bin *garbage_bin,
                       struct log_handle *logger)
{
    if (NULL == flag_schema) {
        return NULL;
    }

    struct flag_runtime *flag_rt = ALLOC(struct flag_runtime, 1);

    flag_rt->htable = rcu_hash_new(flag_ex_data_free, NULL);
    flag_rt->item_htable = rcu_hash_new(flag_maat_item_free, NULL);
    flag_rt->ref_garbage_bin = garbage_bin;
    flag_rt->logger = logger;
    flag_rt->district_map = maat_kv_store_new();

    flag_rt->hit_cnt = alignment_int64_array_alloc(max_thread_num);
    flag_rt->scan_cnt = alignment_int64_array_alloc(max_thread_num);

    return flag_rt;
}

void flag_runtime_free(void *flag_runtime)
{
    if (NULL == flag_runtime) {
        return;
    }

    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;
    if (flag_rt->htable != NULL) {
        rcu_hash_free(flag_rt->htable);
        flag_rt->htable = NULL;
    }

    if (flag_rt->item_htable != NULL) {
        rcu_hash_free(flag_rt->item_htable);
        flag_rt->item_htable = NULL;
    }

    if (flag_rt->matcher != NULL) {
        flag_matcher_free(flag_rt->matcher);
        flag_rt->matcher = NULL;
    }

    assert(flag_rt->tmp_district_map == NULL);

    if (flag_rt->district_map != NULL) {
        maat_kv_store_free(flag_rt->district_map);
        flag_rt->district_map = NULL;
    }

    if (flag_rt->hit_cnt != NULL) {
        alignment_int64_array_free(flag_rt->hit_cnt);
        flag_rt->hit_cnt = NULL;
    }

    if (flag_rt->scan_cnt != NULL) {
        alignment_int64_array_free(flag_rt->scan_cnt);
        flag_rt->scan_cnt = NULL;
    }

    FREE(flag_rt);
}

int flag_runtime_update_row(struct flag_runtime *flag_rt, char *key, size_t key_len,
                            long long item_id, struct flag_rule *rule, int is_valid)
{
    int ret = -1;

    if (0 == is_valid) {
        //delete
        rcu_hash_del(flag_rt->htable, key, key_len);
    } else {
        //add
        ret = rcu_hash_add(flag_rt->htable, key, key_len, (void *)rule);
        if (ret < 0) {
            log_error(flag_rt->logger, MODULE_FLAG,
                      "[%s:%d] flag rule(rule_id:%lld) add to flag runtime htable failed", 
                      __FUNCTION__, __LINE__, item_id);
            return -1;
        }
    }
    
    return 0;
}

long long flag_runtime_get_district_id(struct flag_runtime *flag_rt, const char *district)
{
    long long district_id = DISTRICT_ANY;

	int map_ret = maat_kv_read(flag_rt->district_map, district, &district_id);
	if (map_ret < 0) {
        if (NULL == flag_rt->tmp_district_map) {
            flag_rt->tmp_district_map = maat_kv_store_duplicate(flag_rt->district_map);
        }
        
        map_ret = maat_kv_read(flag_rt->tmp_district_map, district, &district_id);
        if (map_ret < 0) {
            district_id = flag_rt->district_num;
		    maat_kv_register(flag_rt->tmp_district_map, district, district_id);
		    flag_rt->district_num++;
        }
	}

	return district_id;
}

int flag_runtime_set_scan_district(struct flag_runtime *flag_rt, const char *district, 
                                    size_t district_len, long long *district_id)
{
    if (NULL == flag_rt || NULL == district || 0 == district_len) {
        return -1;
    }
    
    return maat_kv_read_unNull(flag_rt->district_map, district, district_len, district_id);
}

struct flag_item *flag_item_new(const char *line, struct flag_schema *schema,
                                struct flag_runtime *flag_rt)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    enum table_type table_type = TABLE_TYPE_INVALID;
    struct flag_item *item = ALLOC(struct flag_item, 1);

    int ret = get_column_pos(line, schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(flag_rt->logger, MODULE_FLAG, 
                  "[%s:%d] flag table(table_id:%d) line:%s has no item_id",
                  __FUNCTION__, __LINE__, schema->table_id, line);
        goto error;
    }
    item->item_id = atoll(line + column_offset);

    ret = get_column_pos(line, schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(flag_rt->logger, MODULE_FLAG, 
                  "[%s:%d] flag table(table_id:%d) line:%s has no group_id",
                  __FUNCTION__, __LINE__, schema->table_id, line);
        goto error;
    }
    item->group_id = atoll(line + column_offset);

    table_type = table_manager_get_table_type(schema->ref_tbl_mgr, schema->table_id);
    if (table_type == TABLE_TYPE_INTERVAL_PLUS) {
        ret = get_column_pos(line, schema->district_column, &column_offset, &column_len);
        if (ret < 0) {
            goto error;
        }

        if (column_len >= MAX_DISTRICT_STR) {
            log_error(flag_rt->logger, MODULE_FLAG, 
                      "[%s:%d] flag_plus table(table_id:%d) line:%s district length too long",
                      __FUNCTION__, __LINE__, schema->table_id, line);
            goto error;
        }

        char district[MAX_DISTRICT_STR] = {0};
        memcpy(district, (line + column_offset), column_len);
        assert(strlen(district) > 0);
        str_unescape(district);
        item->district_id = flag_runtime_get_district_id(flag_rt, district);
    } else {
        item->district_id = DISTRICT_ANY;
    }

    ret = get_column_pos(line, schema->flag_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(flag_rt->logger, MODULE_FLAG, 
                  "[%s:%d] flag table(table_id:%d) line:%s has no flag",
                  __FUNCTION__, __LINE__, schema->table_id, line);
        goto error;
    }

    item->flag = strtoull(line + column_offset, NULL, 0);

     ret = get_column_pos(line, schema->flag_mask_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(flag_rt->logger, MODULE_FLAG, 
                  "[%s:%d] flag table(table_id:%d) line:%s has no flag_mask",
                  __FUNCTION__, __LINE__, schema->table_id, line);
        goto error;
    }
    item->flag_mask = strtoull(line + column_offset, NULL, 0);

    return item;
error:
    FREE(item);
    return NULL;
}

void flag_item_free(struct flag_item *item)
{
    FREE(item);
}

struct flag_rule *flag_item_to_flag_rule(struct flag_item *item, void *user_data)
{
    struct flag_rule *rule = ALLOC(struct flag_rule, 1);

    rule->rule_id = item->item_id;
    rule->flag = item->flag;
    rule->mask = item->flag_mask;
    rule->user_tag = user_data;

    return rule;
}

void flag_rule_free(struct flag_rule *rule)
{
    FREE(rule);
}

int flag_runtime_update(void *flag_runtime, void *flag_schema, 
                        const char *table_name, const char *line, 
                        int valid_column)
{
    if (NULL == flag_runtime || NULL == flag_schema ||
        NULL == line) {
        return -1;
    }

    int ret = -1;
    struct maat_item_inner *u_para = NULL;
    struct maat_item *item = NULL;
    struct flag_rule *flag_rule = NULL;
    struct flag_schema *schema = (struct flag_schema *)flag_schema;
    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;

    long long item_id = get_column_value(line, schema->item_id_column);
    if (item_id < 0) {
        return -1;
    }

    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    } else if (0 == is_valid) {
        //delete
       rcu_hash_del(flag_rt->item_htable, (char *)&item_id, sizeof(item_id));
    } else {
        //add
        struct flag_item *flag_item = flag_item_new(line, schema, flag_rt);
        if (NULL == flag_item) {
            return -1;
        }

        u_para = maat_item_inner_new(flag_item->group_id, item_id, flag_item->district_id);
        item = maat_item_new(item_id, flag_item->group_id, u_para, maat_item_inner_free);
        ret = rcu_hash_add(flag_rt->item_htable, (char *)&(item_id), sizeof(item_id), item);
        if (ret < 0) {
            log_error(flag_rt->logger, MODULE_FLAG, 
                      "[%s:%d] [table:%s] flag runtime add item(item_id:%lld) failed", 
                      __FUNCTION__, __LINE__, table_name, item_id);
            flag_item_free(flag_item);
            maat_item_free(item);
            return -1;
        }

        flag_rule = flag_item_to_flag_rule(flag_item, u_para);
        flag_item_free(flag_item);
        if (NULL == flag_rule) {
            log_error(flag_rt->logger, MODULE_FLAG, 
                      "[%s:%d] [table:%s] transform flag_item(item_id:%lld) to flag_rule failed",
                      __FUNCTION__, __LINE__, table_name, item_id);
            return -1;
        }
    }

    char *key = (char *)&item_id;
    ret = flag_runtime_update_row(flag_rt, key, sizeof(long long), item_id, flag_rule, is_valid);
    if (ret < 0) {
        if (flag_rule != NULL) {
            flag_rule_free(flag_rule);
            flag_rule = NULL;
        }
        return -1;
    }

    return 0;
}

void garbage_flag_matcher_free(void *flag_matcher, void *arg)
{
    struct flag_matcher *matcher = (struct flag_matcher *)flag_matcher;
    flag_matcher_free(matcher);
}

int flag_runtime_commit(void *flag_runtime, const char *table_name)
{
    if (NULL == flag_runtime) {
        return -1;
    }

    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;

    int updating_flag = rcu_hash_is_updating(flag_rt->htable);
    if (0 == updating_flag) {
        return 0;
    }

    rcu_hash_commit(flag_rt->htable);

    if (flag_rt->tmp_district_map != NULL) {
        struct maat_kv_store *tmp_map = flag_rt->district_map;
        flag_rt->district_map = flag_rt->tmp_district_map;
        flag_rt->tmp_district_map = NULL;
        maat_garbage_bagging(flag_rt->ref_garbage_bin, tmp_map, NULL, 
                             garbage_maat_kv_store_free);
    }

    struct flag_rule *rules = NULL;
    void **ex_data_array = NULL;
    size_t rule_cnt = rcu_hash_list(flag_rt->htable, &ex_data_array);
    if (rule_cnt > 0) {
        rules = ALLOC(struct flag_rule, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            rules[i] = *(struct flag_rule *)ex_data_array[i];
        }
    }

    log_info(flag_rt->logger, MODULE_FLAG,
             "table[%s] committing %zu flag rules for rebuilding flag_matcher engine", 
             table_name, rule_cnt);

    int ret = 0;
    struct flag_matcher *new_flag_matcher = NULL;
    struct flag_matcher *old_flag_matcher = NULL;

    if (rule_cnt > 0) {
        new_flag_matcher = flag_matcher_new(rules, rule_cnt);
        if (NULL == new_flag_matcher) {
            log_error(flag_rt->logger, MODULE_FLAG,
                      "[%s:%d] table[%s] rebuild flag_matcher engine failed when update %zu flag rules",
                      __FUNCTION__, __LINE__, table_name, rule_cnt);
            ret = -1;
        }
    }

    old_flag_matcher = flag_rt->matcher;
    flag_rt->matcher = new_flag_matcher;
    if (old_flag_matcher != NULL) {
        maat_garbage_bagging(flag_rt->ref_garbage_bin, old_flag_matcher, NULL,
                             garbage_flag_matcher_free);
    }
    rcu_hash_commit(flag_rt->item_htable);
    flag_rt->rule_num = rule_cnt;

    if (rules != NULL) {
        FREE(rules);
    }
    
    if (ex_data_array != NULL) {
        FREE(ex_data_array);
    }

    return ret;
}

int flag_runtime_scan(struct flag_runtime *flag_rt, int thread_id, 
                      long long flag, int vtable_id, struct maat_state *state)
{
    if (0 == flag_rt->rule_num) {
        //empty flag table
        return 0;
    }

    struct flag_result hit_results[MAX_SCANNER_HIT_ITEM_NUM];
    memset(hit_results, 0, sizeof(hit_results));
    
    int n_hit_item = flag_matcher_match(flag_rt->matcher, flag, 
                                        hit_results, MAX_SCANNER_HIT_ITEM_NUM);
    if (n_hit_item <= 0) {
        return n_hit_item;
    }

    if (n_hit_item > MAX_SCANNER_HIT_ITEM_NUM) {
        log_info(flag_rt->logger, MODULE_FLAG, 
                 "hit flag item count:%d exceed maxium:%d", 
                 n_hit_item, MAX_SCANNER_HIT_ITEM_NUM);
        n_hit_item = MAX_SCANNER_HIT_ITEM_NUM;
    }
    
    long long hit_item_ids[MAX_SCANNER_HIT_ITEM_NUM];
    struct maat_item_inner *item = NULL;
    int real_hit_item_cnt = 0;
    long long district_id = state->district_id;

    memset(hit_item_ids, -1, sizeof(hit_item_ids));
    
    for (int i = 0; i < n_hit_item; i++) {
        item = (struct maat_item_inner *)(hit_results[i].user_tag);
        if (item->district_id == district_id || item->district_id == DISTRICT_ANY) {
            hit_item_ids[real_hit_item_cnt++] = hit_results[i].rule_id;
        }
    }

    size_t group_hit_cnt = 0;
    int ret = maat_compile_state_update(flag_rt->item_htable, vtable_id, hit_item_ids, 
                                        n_hit_item, &group_hit_cnt, state);
    if (ret < 0) {
        return -1;
    }

    return group_hit_cnt;
}

void flag_runtime_scan_hit_inc(struct flag_runtime *flag_rt, int thread_id)
{
    alignment_int64_array_add(flag_rt->hit_cnt, thread_id, 1);
}

long long flag_runtime_scan_hit_sum(struct flag_runtime *flag_rt, int n_thread)
{
    return alignment_int64_array_sum(flag_rt->hit_cnt, n_thread);
}
