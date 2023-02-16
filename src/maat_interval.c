/*
**********************************************************************************************
*	File: maat_interval.cpp
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "maat_utils.h"
#include "log/log.h"
#include "maat_interval.h"
#include "maat_rule.h"
#include "rcu_hash.h"
#include "alignment.h"
#include "uthash/uthash.h"
#include "maat_garbage_collection.h"
#include "maat_compile.h"
#include "interval_matcher.h"

#define MODULE_INTERVAL	 module_name_str("maat.interval")

struct interval_schema {
    int item_id_column;
    int group_id_column;
    int district_column;
    int low_bound_column;
    int up_bound_column;
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

struct interval_item {
    int item_id;
    int group_id;
    int district_id;
    int low_bound;
    int up_bound;
};

struct interval_runtime {
    struct interval_matcher *matcher;
    struct rcu_hash_table *htable;

    uint32_t rule_num;
    uint32_t updating_rule_num;
    struct maat_item *item_hash;
    void (*item_user_data_free)(void *);

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;

    long long *scan_cnt;
    long long *hit_cnt;
};

void *interval_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                          const char *table_name, struct log_handle *logger)
{
    int read_cnt = 0;
    struct interval_schema *schema = ALLOC(struct interval_schema, 1);

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_INTERVAL, 
                  "table %s has no custom column", table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->item_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->group_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "district");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->district_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "low_bound");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->low_bound_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "up_bound");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->up_bound_column = custom_item->valueint;
        read_cnt++;
    }

    schema->ref_tbl_mgr = tbl_mgr;

    if (read_cnt < 5) {
        goto error;
    }

    return schema;
error:
    FREE(schema);
    return NULL;
}

void interval_schema_free(void *interval_schema)
{
    FREE(interval_schema);
}

void interval_ex_data_free(void *user_ctx, void *data)
{
    struct interval_item *item = (struct interval_item *)data;
    FREE(item);
}

void *interval_runtime_new(void *interval_schema, int max_thread_num, 
                           struct maat_garbage_bin *garbage_bin,
                           struct log_handle *logger)
{
    if (NULL == interval_schema) {
        return NULL;
    }

    struct interval_runtime *interval_rt = ALLOC(struct interval_runtime, 1);

    interval_rt->htable = rcu_hash_new(interval_ex_data_free);
    interval_rt->item_user_data_free = maat_item_inner_free;
    interval_rt->ref_garbage_bin = garbage_bin;
    interval_rt->logger = logger;

    interval_rt->hit_cnt = alignment_int64_array_alloc(max_thread_num);
    interval_rt->scan_cnt = alignment_int64_array_alloc(max_thread_num);

    return interval_rt;
}

void interval_runtime_free(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return;
    }

    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;
    if (interval_rt->htable != NULL) {
        rcu_hash_free(interval_rt->htable);
        interval_rt->htable = NULL;
    }

    struct maat_item *item = NULL, *tmp = NULL;
    HASH_ITER(hh, interval_rt->item_hash, item, tmp) {
        HASH_DELETE(hh, interval_rt->item_hash, item);
        maat_item_free(item, interval_rt->item_user_data_free);
    }

    if (interval_rt->hit_cnt != NULL) {
        alignment_int64_array_free(interval_rt->hit_cnt);
        interval_rt->hit_cnt = NULL;
    }

    if (interval_rt->scan_cnt != NULL) {
        alignment_int64_array_free(interval_rt->scan_cnt);
        interval_rt->scan_cnt = NULL;
    }

    FREE(interval_rt);
}

struct interval_item *interval_item_new(const char *line, struct interval_schema *schema,
                                        struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    enum table_type table_type = TABLE_TYPE_INVALID;
    struct interval_item *item = ALLOC(struct interval_item, 1);

    int ret = get_column_pos(line, schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_INTERVAL, 
                  "interval table(table_id:%d) line:%s has no item_id",
                  schema->table_id, line);
        goto error;
    }
    item->item_id = atoi(line + column_offset);

    ret = get_column_pos(line, schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_INTERVAL, 
                  "interval table(table_id:%d) line:%s has no group_id",
                  schema->table_id, line);
        goto error;
    }
    item->group_id = atoi(line + column_offset);

    table_type = table_manager_get_table_type(schema->ref_tbl_mgr, schema->table_id);
    if (table_type == TABLE_TYPE_INTERVAL_PLUS) {
        ret = get_column_pos(line, schema->district_column, &column_offset, &column_len);
        if (ret < 0) {
            goto error;
        }

        if (column_len >= MAX_DISTRICT_STR) {
            log_error(logger, MODULE_INTERVAL, 
                      "interval table(table_id:%d) line:%s district length too long",
                      schema->table_id, line);
            goto error;
        }

        char district[MAX_DISTRICT_STR] = {0};
        memcpy(district, (line + column_offset), column_len);
        assert(strlen(district) > 0);
        str_unescape(district);
        item->district_id = table_manager_get_district_id(schema->ref_tbl_mgr, district);
    }

    ret = get_column_pos(line, schema->low_bound_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_INTERVAL, 
                  "interval table(table_id:%d) line:%s has no low_bound",
                  schema->table_id, line);
        goto error;
    }
    item->low_bound = atoi(line + column_offset);

    ret = get_column_pos(line, schema->up_bound_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_INTERVAL, 
                  "interval table(table_id:%d) line:%s has no up_bound",
                  schema->table_id, line);
        goto error;
    }
    item->up_bound = atoi(line + column_offset);

    return item;
error:
    FREE(item);
    return NULL;
}

void interval_item_free(void *interval_item)
{
    FREE(interval_item);
}

struct interval_rule *interval_item_to_interval_rule(struct interval_item *item, void *user_data)
{
    struct interval_rule *rule = ALLOC(struct interval_rule, 1);

    rule->start = item->low_bound;
    rule->end = item->up_bound;
    rule->result.rule_id = item->item_id;
    rule->result.user_tag = user_data;

    return rule;
}

void interval_rule_free(struct interval_rule *rule)
{
    FREE(rule);
}

int interval_runtime_update_row(struct interval_runtime *interval_rt, char *key, size_t key_len,
                                int item_id, struct interval_rule *rule, int is_valid)
{
    void *data = NULL;

    if (0 == is_valid) {
        //delete
        data = rcu_hash_find(interval_rt->htable, key, key_len);
        if (NULL == data) {
            log_error(interval_rt->logger, MODULE_INTERVAL, 
                      "the key of interval rule not exist, can't be deleted, item_id:%d",
                      item_id);
            return -1;
        }
        rcu_hash_del(interval_rt->htable, key, key_len);
    } else {
        //add
        data = rcu_hash_find(interval_rt->htable, key, key_len);
        if (data != NULL) {
            log_error(interval_rt->logger, MODULE_INTERVAL,
                      "the key of interval rule already exist, can't be added, item_id:%d", 
                      item_id);
            return -1;
        }
        rcu_hash_add(interval_rt->htable, key, key_len, (void *)rule);
    }
    
    return 0;
}

int interval_runtime_update(void *interval_runtime, void *interval_schema, 
                            const char *line, int valid_column)
{
    if (NULL == interval_runtime || NULL == interval_schema ||
        NULL == line) {
        return -1;
    }

    struct maat_item_inner *u_para = NULL;
    struct maat_item *item = NULL;
    struct interval_rule *interval_rule = NULL;
    struct interval_schema *schema = (struct interval_schema *)interval_schema;
    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;

    int item_id = get_column_value(line, schema->item_id_column);
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    } else if (0 == is_valid) {
        //delete
        HASH_FIND_INT(interval_rt->item_hash, &item_id, item);
        if (NULL == item) {
            return -1;
        }

        u_para = (struct maat_item_inner *)item->user_data;
        item->user_data = NULL;
        
	    if (NULL == u_para) {
		    return -1;
	    }

        HASH_DELETE(hh, interval_rt->item_hash, item);
        maat_garbage_bagging(interval_rt->ref_garbage_bin, u_para, maat_item_inner_free);
    } else {
        //add
        HASH_FIND_INT(interval_rt->item_hash, &item_id, item);
        if (item) {
            log_error(interval_rt->logger, MODULE_INTERVAL, 
                      "interval runtime add item %d to item_hash failed, already exist", 
                      item_id);
            return -1;
        }

        struct interval_item *interval_item = interval_item_new(line, schema, interval_rt->logger);
        if (NULL == interval_item) {
            return -1;
        }

        u_para = maat_item_inner_new(interval_item->group_id, item_id, interval_item->district_id);
        item = maat_item_new(item_id, interval_item->group_id, u_para);
        HASH_ADD_INT(interval_rt->item_hash, item_id, item);

        interval_rule = interval_item_to_interval_rule(interval_item, u_para);
        interval_item_free(interval_item);
        if (NULL == interval_rule) {
            log_error(interval_rt->logger, MODULE_INTERVAL, 
                      "transform interval table(table_id:%d) item to interval_rule failed, item_id:%d",
                      schema->table_id, item_id);
            return -1;
        }
    }

    char *key = (char *)&item_id;
    int ret = interval_runtime_update_row(interval_rt, key, sizeof(int), item_id, interval_rule, is_valid);
    if (ret < 0) {
        if (interval_rule != NULL) {
            interval_rule_free(interval_rule);
            interval_rule = NULL;
        }
        return -1;
    } else {
        if (0 == is_valid) {
            interval_rt->rule_num--;
        } else {
            interval_rt->rule_num++;
        }
    }

    return 0;
}

int interval_runtime_commit(void *interval_runtime, const char *table_name)
{
    if (NULL == interval_runtime) {
        return -1;
    }

    int ret = 0;
    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;
    void **ex_data_array = NULL;

    size_t rule_cnt = rcu_hash_list_updating_data(interval_rt->htable, &ex_data_array);
    if (0 == rule_cnt) {
        FREE(ex_data_array);
        return 0;
    }

    struct interval_rule *rules = ALLOC(struct interval_rule, rule_cnt);

    for (size_t i = 0; i < rule_cnt; i++) {
        rules[i] = *(struct interval_rule *)ex_data_array[i];
    }

    struct interval_matcher *new_interval_matcher = NULL;
    struct interval_matcher *old_interval_matcher = NULL;

    log_info(interval_rt->logger, MODULE_INTERVAL,
             "table[%s] committing %zu interval rules for rebuilding interval_matcher engine", 
             table_name, rule_cnt);

    new_interval_matcher = interval_matcher_new(rules, rule_cnt);
    if (NULL == new_interval_matcher) {
        log_error(interval_rt->logger, MODULE_INTERVAL,
                  "table[%s]rebuild interval_matcher engine failed when update %zu interval rules", 
                  table_name, rule_cnt);
        ret = -1;
    }

    old_interval_matcher = interval_rt->matcher;
    interval_rt->matcher = new_interval_matcher;

    maat_garbage_bagging(interval_rt->ref_garbage_bin, old_interval_matcher, 
                         (void (*)(void*))interval_matcher_free);
    rcu_hash_commit(interval_rt->htable);
    rule_cnt = rcu_hash_updating_count(interval_rt->htable);
    assert(rule_cnt == 0);
    
    FREE(rules);
    FREE(ex_data_array);

    return ret;
}

int interval_runtime_scan(struct interval_runtime *interval_rt, int thread_id, 
                                 uint64_t integer, 
                                 int *group_ids, size_t group_ids_size, 
                                 int vtable_id, struct maat_state *state)
{
    struct interval_result hit_results[MAX_SCANNER_HIT_ITEM_NUM] = {0};
    
    int n_hit_item = interval_matcher_match(interval_rt->matcher, integer, 
                                            hit_results, MAX_SCANNER_HIT_ITEM_NUM);
    if (n_hit_item <= 0) {
        return n_hit_item;
    }

    if (n_hit_item > MAX_SCANNER_HIT_ITEM_NUM) {
        log_info(interval_rt->logger, MODULE_INTERVAL, 
                 "hit interval item count:%d exceed maxium:%d", 
                 n_hit_item, MAX_SCANNER_HIT_ITEM_NUM);
        n_hit_item = MAX_SCANNER_HIT_ITEM_NUM;
    }
    
    int hit_item_ids[MAX_SCANNER_HIT_ITEM_NUM];
    struct maat_item_inner *item = NULL;
    int real_hit_item_cnt = 0;
    int district_id = state->district_id;

    memset(hit_item_ids, -1, sizeof(hit_item_ids));

    for (int i = 0; i < n_hit_item; i++) {
        item = (struct maat_item_inner *)(hit_results[i].user_tag);
        if (item->district_id == district_id || district_id == DISTRICT_ANY) {
            hit_item_ids[real_hit_item_cnt++] = hit_results[i].rule_id;
        }
    }

    size_t group_hit_cnt = 0;
    int ret = maat_compile_state_update(interval_rt->item_hash, vtable_id, hit_item_ids, 
                                        n_hit_item, group_ids, group_ids_size, 
                                        &group_hit_cnt, state);
    if (ret < 0) {
        return -1;
    }

    return group_hit_cnt;
}

void interval_runtime_scan_hit_inc(struct interval_runtime *interval_rt, int thread_id)
{
    alignment_int64_array_add(interval_rt->hit_cnt, thread_id, 1);
}

long long interval_runtime_scan_hit_sum(struct interval_runtime *interval_rt, int n_thread)
{
    return alignment_int64_array_sum(interval_rt->hit_cnt, n_thread);
}