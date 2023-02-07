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
    int flag_column;
    int flag_mask_column;
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

struct flag_item {
    int item_id;
    int group_id;
    uint64_t flag;
    uint64_t flag_mask;
};

struct flag_runtime {
    struct flag_matcher *matcher;
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

void *flag_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                      const char *table_name, struct log_handle *logger)
{
    int read_cnt = 0;
    struct flag_schema *schema = ALLOC(struct flag_schema, 1);

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_FLAG, 
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

    custom_item = cJSON_GetObjectItem(item, "flag");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->flag_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "flag_mask");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->flag_mask_column = custom_item->valueint;
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

void flag_schema_free(void *flag_schema)
{
    FREE(flag_schema);
}

void flag_ex_data_free(void *user_ctx, void *data)
{
    struct flag_item *flag_item = (struct flag_item *)data;
    FREE(flag_item);
}

void *flag_runtime_new(void *flag_schema, int max_thread_num, 
                       struct maat_garbage_bin *garbage_bin,
                       struct log_handle *logger)
{
    if (NULL == flag_schema) {
        return NULL;
    }

    struct flag_runtime *flag_rt = ALLOC(struct flag_runtime, 1);

    flag_rt->htable = rcu_hash_new(flag_ex_data_free);
    flag_rt->item_user_data_free = maat_item_inner_free;
    flag_rt->ref_garbage_bin = garbage_bin;
    flag_rt->logger = logger;

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

    struct maat_item *item = NULL, *tmp = NULL;
    HASH_ITER(hh, flag_rt->item_hash, item, tmp) {
        HASH_DELETE(hh, flag_rt->item_hash, item);
        maat_item_free(item, flag_rt->item_user_data_free);
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
                            int item_id, struct flag_rule *rule, int is_valid)
{
    void *data = NULL;

    if (0 == is_valid) {
        //delete
        data = rcu_hash_find(flag_rt->htable, key, key_len);
        if (NULL == data) {
            log_error(flag_rt->logger, MODULE_FLAG, 
                      "the key of flag rule not exist, can't be deleted, item_id:%d",
                      item_id);
            return -1;
        }
        rcu_hash_del(flag_rt->htable, key, key_len);
    } else {
        //add
        data = rcu_hash_find(flag_rt->htable, key, key_len);
        if (data != NULL) {
            log_error(flag_rt->logger, MODULE_FLAG,
                      "the key of flag rule already exist, can't be added, item_id:%d", 
                      item_id);
            return -1;
        }
        rcu_hash_add(flag_rt->htable, key, key_len, (void *)rule);
    }
    
    return 0;
}

struct flag_item *flag_item_new(const char *line, struct flag_schema *flag_schema,
                                struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    struct flag_item *flag_item = ALLOC(struct flag_item, 1);

    int ret = get_column_pos(line, flag_schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_FLAG, 
                  "flag table(table_id:%d) line:%s has no item_id",
                  flag_schema->table_id, line);
        goto error;
    }
    flag_item->item_id = atoi(line + column_offset);

    ret = get_column_pos(line, flag_schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_FLAG, 
                  "flag table(table_id:%d) line:%s has no group_id",
                  flag_schema->table_id, line);
        goto error;
    }
    flag_item->group_id = atoi(line + column_offset);

    ret = get_column_pos(line, flag_schema->flag_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_FLAG, 
                  "flag table(table_id:%d) line:%s has no flag",
                  flag_schema->table_id, line);
        goto error;
    }

    flag_item->flag = strtoull(line + column_offset, NULL, 0);

     ret = get_column_pos(line, flag_schema->flag_mask_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_FLAG, 
                  "flag table(table_id:%d) line:%s has no flag_mask",
                  flag_schema->table_id, line);
        goto error;
    }
    flag_item->flag_mask = strtoull(line + column_offset, NULL, 0);

    return flag_item;
error:
    FREE(flag_item);
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
                        const char *line, int valid_column)
{
    if (NULL == flag_runtime || NULL == flag_schema ||
        NULL == line) {
        return -1;
    }

    struct maat_item_inner *u_para = NULL;
    struct maat_item *item = NULL;
    struct flag_rule *flag_rule = NULL;
    struct flag_schema *schema = (struct flag_schema *)flag_schema;
    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;

    int item_id = get_column_value(line, schema->item_id_column);
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    } else if (0 == is_valid) {
        //delete
        HASH_FIND_INT(flag_rt->item_hash, &item_id, item);
        if (NULL == item) {
            return -1;
        }

        u_para = (struct maat_item_inner *)item->user_data;
        item->user_data = NULL;
        
	    if (NULL == u_para) {
		    return -1;
	    }

        HASH_DELETE(hh, flag_rt->item_hash, item);
        maat_garbage_bagging(flag_rt->ref_garbage_bin, u_para, maat_item_inner_free);
    } else {
        //add
        HASH_FIND_INT(flag_rt->item_hash, &item_id, item);
        if (item) {
            log_error(flag_rt->logger, MODULE_FLAG, 
                      "flag runtime add item %d to item_hash failed, already exist", 
                      item_id);
            return -1;
        }

        struct flag_item *flag_item = flag_item_new(line, schema, flag_rt->logger);
        if (NULL == flag_item) {
            return -1;
        }

        u_para = maat_item_inner_new(flag_item->group_id, item_id, 0);
        item = maat_item_new(item_id, flag_item->group_id, u_para);
        HASH_ADD_INT(flag_rt->item_hash, item_id, item);

        flag_rule = flag_item_to_flag_rule(flag_item, u_para);
        flag_item_free(flag_item);
        if (NULL == flag_rule) {
            log_error(flag_rt->logger, MODULE_FLAG, 
                      "transform flag table(table_id:%d) item to flag_rule failed, item_id:%d",
                      schema->table_id, item_id);
            return -1;
        }
    }

    char *key = (char *)&item_id;
    int ret = flag_runtime_update_row(flag_rt, key, sizeof(int), item_id, flag_rule, is_valid);
    if (ret < 0) {
        if (flag_rule != NULL) {
            flag_rule_free(flag_rule);
            flag_rule = NULL;
        }
        return -1;
    } else {
        if (0 == is_valid) {
            flag_rt->rule_num--;
        } else {
            flag_rt->rule_num++;
        }
    }

    return 0;
}

int flag_runtime_commit(void *flag_runtime)
{
    if (NULL == flag_runtime) {
        return -1;
    }

    int ret = 0;
    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;
    void **ex_data_array = NULL;

    size_t rule_cnt = rcu_hash_list_updating_data(flag_rt->htable, &ex_data_array);
    if (0 == rule_cnt) {
        FREE(ex_data_array);
        return 0;
    }

    struct flag_rule *rules = ALLOC(struct flag_rule, rule_cnt);

    for (size_t i = 0; i < rule_cnt; i++) {
        rules[i] = *(struct flag_rule *)ex_data_array[i];
    }

    struct flag_matcher *new_flag_matcher = NULL;
    struct flag_matcher *old_flag_matcher = NULL;

    log_info(flag_rt->logger, MODULE_FLAG,
             "committing %zu flag rules for rebuilding flag_matcher engine", 
             rule_cnt);
    new_flag_matcher = flag_matcher_new(rules, rule_cnt);
    if (NULL == new_flag_matcher) {
        log_error(flag_rt->logger, MODULE_FLAG,
                  "rebuild flag_matcher engine failed when update %zu flag rules", 
                  rule_cnt);
        ret = -1;
    }

    old_flag_matcher = flag_rt->matcher;
    flag_rt->matcher = new_flag_matcher;

    maat_garbage_bagging(flag_rt->ref_garbage_bin, old_flag_matcher, 
                         (void (*)(void*))flag_matcher_free);
    rcu_hash_commit(flag_rt->htable);
    rule_cnt = rcu_hash_updating_count(flag_rt->htable);
    assert(rule_cnt == 0);
    
    FREE(rules);
    FREE(ex_data_array);

    return ret;
}

int flag_runtime_scan_flag(struct flag_runtime *flag_rt, int thread_id, 
                           uint64_t flag, int *group_ids, size_t group_ids_size, 
                           int vtable_id, struct maat_state *state)
{
    struct flag_result hit_results[MAX_SCANNER_HIT_ITEM_NUM] = {0};
    
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
    
    int hit_item_ids[MAX_SCANNER_HIT_ITEM_NUM] = {-1};
    for (int i = 0; i < n_hit_item; i++) {
        hit_item_ids[i] = hit_results[i].rule_id;
    }

    size_t group_hit_cnt = 0;
    int ret = maat_compile_state_update(flag_rt->item_hash, vtable_id, hit_item_ids, 
                                        n_hit_item, group_ids, group_ids_size, 
                                        &group_hit_cnt, state);
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