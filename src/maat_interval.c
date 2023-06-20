/*
**********************************************************************************************
*	File: maat_interval.c
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "maat_rule.h"
#include "maat_utils.h"
#include "rcu_hash.h"
#include "alignment.h"
#include "maat_garbage_collection.h"
#include "maat_compile.h"
#include "interval_matcher.h"
#include "maat_interval.h"

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
    long long item_id;
    long long group_id;
    int low_bound;
    int up_bound;
    void *user_data;
    void (*user_data_free)(void *data);
    int district_id;
};

struct interval_runtime {
    struct interval_matcher *matcher;
    struct rcu_hash_table *item_hash;  // <item_id, struct interval_item>

    long long rule_num;
    size_t n_worker_thread;
    struct log_handle *logger;
    struct maat_garbage_bin *ref_garbage_bin;

    int district_num;
    struct maat_kv_store *district_map;
    struct maat_kv_store *tmp_district_map;

    long long update_err_cnt;
    long long *scan_cnt;
    long long *scan_cpu_time;
    long long *hit_cnt;
};

void *interval_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                          const char *table_name, struct log_handle *logger)
{
    struct interval_schema *schema = ALLOC(struct interval_schema, 1);

    char table_type[NAME_MAX] = {0};
    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
    } else {
        log_error(logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    /* table_type already validate in maat_table_new() */
    item = cJSON_GetObjectItem(json, "table_type");
    memcpy(table_type, item->valuestring, strlen(item->valuestring));

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->item_id_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> schema has no item_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->group_id_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> schema has no group_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    /* interval_plus has district */
    if (strcmp(table_type, "intval_plus") == 0) {
        custom_item = cJSON_GetObjectItem(item, "district");
        if (custom_item != NULL && custom_item->type == cJSON_Number) {
            schema->district_column = custom_item->valueint;
        } else {
            log_error(logger, MODULE_INTERVAL, 
                  "[%s:%d] interval_plus table:<%s> schema has no district column", 
                  __FUNCTION__, __LINE__, table_name);
            goto error;
        }
    }

    custom_item = cJSON_GetObjectItem(item, "low_bound");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->low_bound_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> schema has no low_bound column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "up_bound");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->up_bound_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> schema has no up_bound column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    schema->ref_tbl_mgr = tbl_mgr;
    return schema;
error:
    FREE(schema);
    return NULL;
}

void interval_schema_free(void *interval_schema)
{
    FREE(interval_schema);
}

static void interval_item_free(struct interval_item *item)
{
    if (NULL == item) {
        return;
    }

    if (item->user_data != NULL && item->user_data_free != NULL) {
        item->user_data_free(item->user_data);
        item->user_data = NULL;
    }

    FREE(item);
}

static void interval_item_free_cb(void *user_ctx, void *data)
{
    struct interval_item *item = (struct interval_item *)data;
    interval_item_free(item);
}

void *interval_runtime_new(void *interval_schema, size_t max_thread_num,
                           struct maat_garbage_bin *garbage_bin, 
                           struct log_handle *logger)
{
    if (NULL == interval_schema) {
        return NULL;
    }

    struct interval_runtime *interval_rt = ALLOC(struct interval_runtime, 1);

    interval_rt->item_hash = rcu_hash_new(interval_item_free_cb, NULL, 0);
    interval_rt->n_worker_thread = max_thread_num;
    interval_rt->ref_garbage_bin = garbage_bin;
    interval_rt->logger = logger;
    interval_rt->district_map = maat_kv_store_new();

    interval_rt->hit_cnt = alignment_int64_array_alloc(max_thread_num);
    interval_rt->scan_cnt = alignment_int64_array_alloc(max_thread_num);
    interval_rt->scan_cpu_time = alignment_int64_array_alloc(max_thread_num);

    return interval_rt;
}

void interval_runtime_free(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return;
    }

    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;
    if (interval_rt->item_hash != NULL) {
        rcu_hash_free(interval_rt->item_hash);
        interval_rt->item_hash = NULL;
    }

    if (interval_rt->matcher != NULL) {
        interval_matcher_free(interval_rt->matcher);
        interval_rt->matcher = NULL;
    }

    assert(interval_rt->tmp_district_map == NULL);

    if (interval_rt->district_map != NULL) {
        maat_kv_store_free(interval_rt->district_map);
        interval_rt->district_map = NULL;
    }

    if (interval_rt->hit_cnt != NULL) {
        alignment_int64_array_free(interval_rt->hit_cnt);
        interval_rt->hit_cnt = NULL;
    }

    if (interval_rt->scan_cnt != NULL) {
        alignment_int64_array_free(interval_rt->scan_cnt);
        interval_rt->scan_cnt = NULL;
    }

    if (interval_rt->scan_cpu_time != NULL) {
        alignment_int64_array_free(interval_rt->scan_cpu_time);
        interval_rt->scan_cpu_time = NULL;
    }

    FREE(interval_rt);
}

static int interval_runtime_get_district_id(struct interval_runtime *interval_rt,
                                            const char *district)
{
    long long district_id = DISTRICT_ANY;

	int map_ret = maat_kv_read(interval_rt->district_map, district, &district_id);
	if (map_ret < 0) {
        if (NULL == interval_rt->tmp_district_map) {
            interval_rt->tmp_district_map = maat_kv_store_duplicate(interval_rt->district_map);
        }
        
        map_ret = maat_kv_read(interval_rt->tmp_district_map, district, &district_id);
        if (map_ret < 0) {
            district_id = interval_rt->district_num;
		    maat_kv_register(interval_rt->tmp_district_map, district, district_id);
		    interval_rt->district_num++;
        }
	}

	return (int)district_id;
}

int interval_runtime_set_scan_district(struct interval_runtime *interval_rt,
                                       const char *district, size_t district_len,
                                       long long *district_id)
{
    if (NULL == interval_rt || NULL == district || 0 == district_len) {
        return -1;
    }

    return maat_kv_read_unNull(interval_rt->district_map, district,
                               district_len, district_id);
}

static struct interval_item *
interval_item_new(struct interval_schema *schema, const char *table_name,
                  const char *line, struct interval_runtime *interval_rt)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    enum table_type table_type = TABLE_TYPE_INVALID;
    struct interval_item *item = ALLOC(struct interval_item, 1);

    int ret = get_column_pos(line, schema->item_id_column, &column_offset,
                             &column_len);
    if (ret < 0) {
        log_error(interval_rt->logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> has no item_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    item->item_id = atoll(line + column_offset);

    ret = get_column_pos(line, schema->group_id_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_error(interval_rt->logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> has no group_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    item->group_id = atoll(line + column_offset);

    table_type = table_manager_get_table_type(schema->ref_tbl_mgr, schema->table_id);
    if (table_type == TABLE_TYPE_INTERVAL_PLUS) {
        ret = get_column_pos(line, schema->district_column, &column_offset,
                             &column_len);
        if (ret < 0) {
            goto error;
        }

        if (column_len >= MAX_DISTRICT_STR) {
            log_error(interval_rt->logger, MODULE_INTERVAL, 
                      "[%s:%d] interval_plus table:<%s> district length exceed "
                      "maxium:%d in line:%s", __FUNCTION__, __LINE__, table_name,
                      MAX_DISTRICT_STR, line);
            goto error;
        }

        char district[MAX_DISTRICT_STR] = {0};
        memcpy(district, (line + column_offset), column_len);
        assert(strlen(district) > 0);
        str_unescape(district);
        item->district_id = interval_runtime_get_district_id(interval_rt, district);
    } else {
        item->district_id = DISTRICT_ANY;
    }

    ret = get_column_pos(line, schema->low_bound_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(interval_rt->logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> has no low_bound in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    item->low_bound = atoi(line + column_offset);

    ret = get_column_pos(line, schema->up_bound_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(interval_rt->logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> has no up_bound in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    item->up_bound = atoi(line + column_offset);

    return item;
error:
    FREE(item);
    return NULL;
}

static struct interval_rule
interval_item_to_interval_rule(struct interval_item *item)
{
    struct interval_rule rule;

    rule.start = item->low_bound;
    rule.end = item->up_bound;
    rule.result.rule_id = item->item_id;
    rule.result.user_tag = item->user_data;

    return rule;
}

static int interval_runtime_update_row(struct interval_runtime *interval_rt,
                                       char *key, size_t key_len,
                                       struct interval_item *item, int is_valid)
{
    int ret = -1;

    if (0 == is_valid) {
        //delete
        rcu_hash_del(interval_rt->item_hash, key, key_len);
    } else {
        //add
        ret = rcu_hash_add(interval_rt->item_hash, key, key_len, (void *)item);
        if (ret < 0) {
            log_error(interval_rt->logger, MODULE_INTERVAL,
                      "[%s:%d] interval item(item_id:%lld) add to "
                      "interavl_item_hash failed", __FUNCTION__, __LINE__,
                      item->item_id);
            return -1;
        }
    }
    
    return 0;
}

int interval_runtime_update(void *interval_runtime, void *interval_schema, 
                            const char *table_name, const char *line, 
                            int valid_column)
{
    if (NULL == interval_runtime || NULL == interval_schema ||
        NULL == line) {
        return -1;
    }

    struct interval_schema *schema = (struct interval_schema *)interval_schema;
    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;

    long long item_id = get_column_value(line, schema->item_id_column);
    if (item_id < 0) {
        log_error(interval_rt->logger, MODULE_INTERVAL,
                  "[%s:%d] interval table:<%s> has no item_id(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  schema->item_id_column, line);
        interval_rt->update_err_cnt++;
        return -1;
    }

    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        log_error(interval_rt->logger, MODULE_INTERVAL,
                  "[%s:%d] interval table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        interval_rt->update_err_cnt++;
        return -1;
    }
    
    struct interval_item *interval_item = NULL;
    if (1 == is_valid) {
        //add
        interval_item = interval_item_new(schema, table_name, line, interval_rt);
        if (NULL == interval_item) {
            interval_rt->update_err_cnt++;
            return -1;
        }

        int *item_district_id = ALLOC(int, 1);
        *item_district_id = interval_item->district_id;

        interval_item->user_data = item_district_id;
        interval_item->user_data_free = free;
    }

    int ret = interval_runtime_update_row(interval_rt, (char *)&item_id, sizeof(long long),
                                          interval_item, is_valid);
    if (ret < 0) {
        if (interval_item != NULL) {
            interval_item_free(interval_item);
        }
        interval_rt->update_err_cnt++;
        return -1;
    }

    return 0;
}

void garbage_interval_matcher_free(void *interval_matcher, void *arg)
{
    struct interval_matcher *matcher = (struct interval_matcher *)interval_matcher;
    interval_matcher_free(matcher);
}

int interval_runtime_commit(void *interval_runtime, const char *table_name,
                            long long maat_rt_version)
{
    if (NULL == interval_runtime) {
        return -1;
    }

    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;

    int updating_flag = rcu_hash_is_updating(interval_rt->item_hash);
    if (0 == updating_flag) {
        return 0;
    }

    if (interval_rt->tmp_district_map != NULL) {
        struct maat_kv_store *tmp_map = interval_rt->district_map;
        interval_rt->district_map = interval_rt->tmp_district_map;
        interval_rt->tmp_district_map = NULL;
        maat_garbage_bagging(interval_rt->ref_garbage_bin, tmp_map, NULL, 
                             garbage_maat_kv_store_free);
    }

    void **ex_data_array = NULL;
    struct interval_rule *rules = NULL;

    size_t rule_cnt = rcu_updating_hash_list(interval_rt->item_hash, &ex_data_array);
    if (rule_cnt > 0) {
        rules = ALLOC(struct interval_rule, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            struct interval_item *interval_item = (struct interval_item *)ex_data_array[i];
            rules[i] = interval_item_to_interval_rule(interval_item);
        }
    }

    int ret = 0;
    struct interval_matcher *new_interval_matcher = NULL;
    struct interval_matcher *old_interval_matcher = NULL;

    if (rule_cnt > 0) {
        new_interval_matcher = interval_matcher_new(rules, rule_cnt);
        if (NULL == new_interval_matcher) {
            log_error(interval_rt->logger, MODULE_INTERVAL,
                      "[%s:%d] table[%s]rebuild interval_matcher engine failed "
                      "when update %zu interval rules", __FUNCTION__, __LINE__,
                      table_name, rule_cnt);
            ret = -1;
        }
    }

    old_interval_matcher = interval_rt->matcher;
    interval_rt->matcher = new_interval_matcher;
    rcu_hash_commit(interval_rt->item_hash);

    if (old_interval_matcher != NULL) {
        maat_garbage_bagging(interval_rt->ref_garbage_bin, old_interval_matcher, NULL,
                            garbage_interval_matcher_free);
    }
    
    interval_rt->rule_num = rule_cnt;
    
    log_info(interval_rt->logger, MODULE_INTERVAL,
             "table[%s] commit %zu interval rules and rebuild interval_matcher "
             "completed, version:%lld", table_name, rule_cnt, maat_rt_version);

    if (rules != NULL) {
        FREE(rules);
    }
    
    if (ex_data_array != NULL) {
        FREE(ex_data_array);
    }

    return ret;
}

long long interval_runtime_rule_count(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return 0;
    }
    
    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;
    return interval_rt->rule_num;
}

int interval_runtime_scan(struct interval_runtime *interval_rt, int thread_id, 
                          long long integer, int vtable_id, struct maat_state *state)
{
    if (0 == interval_rt->rule_num) {
        //empty interval table
        return 0;
    }

    struct interval_result hit_results[MAX_SCANNER_HIT_ITEM_NUM];
    
    int n_hit_item = interval_matcher_match(interval_rt->matcher, integer, 
                                            hit_results, MAX_SCANNER_HIT_ITEM_NUM);
    if (n_hit_item <= 0) {
        return n_hit_item;
    }

    if (n_hit_item > MAX_SCANNER_HIT_ITEM_NUM) {
        n_hit_item = MAX_SCANNER_HIT_ITEM_NUM;
    }
    
    struct maat_item hit_maat_items[n_hit_item];
    size_t real_hit_item_cnt = 0;
    
    for (int i = 0; i < n_hit_item; i++) {
        int tag_district_id = *(int *)(hit_results[i].user_tag);
        if (tag_district_id == state->district_id || tag_district_id == DISTRICT_ANY) {
            long long item_id = hit_results[i].rule_id;
            struct interval_item *int_item = (struct interval_item *)rcu_hash_find(interval_rt->item_hash, 
                                                                                  (char *)&item_id,
                                                                                  sizeof(long long));
            if (!int_item) {
                // item config has been deleted
                continue;
            }

            hit_maat_items[real_hit_item_cnt].item_id = item_id;
            hit_maat_items[real_hit_item_cnt].group_id = int_item->group_id;
            real_hit_item_cnt++;
        }
    }

    maat_compile_state_update(vtable_id, hit_maat_items, real_hit_item_cnt, state);

    return real_hit_item_cnt;
}

void interval_runtime_hit_inc(struct interval_runtime *interval_rt, int thread_id)
{
    if (NULL == interval_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(interval_rt->hit_cnt, thread_id, 1);
}

void interval_runtime_perf_stat(struct interval_runtime *interval_rt,
                                struct timespec *start, struct timespec *end,
                                int thread_id)
{
    if (NULL == interval_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(interval_rt->scan_cnt, thread_id, 1);
    
    if (start != NULL && end != NULL) {
        long long consume_time = (end->tv_sec - start->tv_sec) * 1000000000 +
                                 (end->tv_nsec - start->tv_nsec);
        alignment_int64_array_add(interval_rt->scan_cpu_time, thread_id, consume_time);
    }
}

long long interval_runtime_scan_count(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return 0;
    }

    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;
    long long sum = alignment_int64_array_sum(interval_rt->scan_cnt,
                                              interval_rt->n_worker_thread);
    alignment_int64_array_reset(interval_rt->scan_cnt, interval_rt->n_worker_thread);

    return sum;
}

long long interval_runtime_scan_cpu_time(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return 0;
    }

    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;
    long long sum = alignment_int64_array_sum(interval_rt->scan_cpu_time, 
                                              interval_rt->n_worker_thread);
    alignment_int64_array_reset(interval_rt->scan_cpu_time, interval_rt->n_worker_thread);

    return sum;
}

long long interval_runtime_hit_count(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return 0;
    }

    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;
    long long sum = alignment_int64_array_sum(interval_rt->hit_cnt,
                                              interval_rt->n_worker_thread);
    alignment_int64_array_reset(interval_rt->hit_cnt, interval_rt->n_worker_thread);

    return sum;
}

long long interval_runtime_update_err_cnt(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return 0;
    }

    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;
    return interval_rt->update_err_cnt;
}