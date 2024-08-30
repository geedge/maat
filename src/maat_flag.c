/*
**********************************************************************************************
*	File: maat_flag.c
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "maat_flag.h"
#include "flag_matcher.h"
#include "maat_utils.h"
#include "maat_core.h"
#include "log/log.h"
#include "uthash/uthash.h"
#include "rcu_hash.h"
#include "maat_table.h"
#include "alignment.h"
#include "maat_rule.h"
#include "maat_garbage_collection.h"

#define MODULE_FLAG	 module_name_str("maat.flag")

struct flag_schema {
    int item_id_column;
    int object_id_column;
    int district_column;
    int flag_column;
    int flag_mask_column;
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

struct flag_item {
    long long item_id;
    long long object_id;
    long long flag;
    long long flag_mask;
    void *user_data;
    int district_id;
};

struct flag_runtime {
    struct flag_matcher *matcher;
    struct rcu_hash_table *item_hash; // <item_id, struct flag_item>

    long long rule_num;
    size_t n_worker_thread;
    struct log_handle *logger;
    struct maat_garbage_bin *ref_garbage_bin;

    int district_num;
    struct maat_kv_store *district_map;
    struct maat_kv_store *tmp_district_map;

    long long *scan_times;
    long long *scan_cpu_time;

    long long *hit_times;
    long long *hit_item_num;

    long long update_err_cnt;
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
        log_fatal(logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    /* table_type already validate in maat_table_new() */
    item = cJSON_GetObjectItem(json, "table_type");
    memcpy(table_type, item->valuestring, strlen(item->valuestring));

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_fatal(logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->item_id_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> schema has no item_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "object_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->object_id_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> schema has no object_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    /* flag_plus has district */
    if (strcmp(table_type, "flag_plus") == 0) {
        custom_item = cJSON_GetObjectItem(item, "district");
        if (custom_item != NULL && custom_item->type == cJSON_Number) {
            schema->district_column = custom_item->valueint;
        } else {
            log_fatal(logger, MODULE_FLAG, 
                  "[%s:%d] flag_plus table:<%s> schema has no district column", 
                  __FUNCTION__, __LINE__, table_name);
            goto error;
        }
    }

    custom_item = cJSON_GetObjectItem(item, "flag");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->flag_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> schema has no flag column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "flag_mask");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->flag_mask_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> schema has no flag_mask column", 
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

static void flag_item_free(struct flag_item *item)
{
    if (NULL == item) {
        return;
    }

    if (item->user_data != NULL) {
        FREE(item->user_data);
    }

    FREE(item);
}

static void flag_item_free_cb(void *user_ctx, void *data)
{
    struct flag_item *item = (struct flag_item *)data;
    
    flag_item_free(item);
}

void *flag_runtime_new(void *flag_schema, size_t max_thread_num,
                       struct maat_garbage_bin *garbage_bin, 
                       struct log_handle *logger)
{
    if (NULL == flag_schema) {
        return NULL;
    }

    struct flag_runtime *flag_rt = ALLOC(struct flag_runtime, 1);

    flag_rt->item_hash = rcu_hash_new(flag_item_free_cb, NULL, 0);
    flag_rt->n_worker_thread = max_thread_num;
    flag_rt->ref_garbage_bin = garbage_bin;
    flag_rt->logger = logger;
    flag_rt->district_map = maat_kv_store_new();

    flag_rt->scan_times = alignment_int64_array_alloc(max_thread_num);
    flag_rt->scan_cpu_time = alignment_int64_array_alloc(max_thread_num);

    flag_rt->hit_times = alignment_int64_array_alloc(max_thread_num);
    flag_rt->hit_item_num = alignment_int64_array_alloc(max_thread_num);

    return flag_rt;
}

void flag_runtime_free(void *flag_runtime)
{
    if (NULL == flag_runtime) {
        return;
    }

    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;
    if (flag_rt->item_hash != NULL) {
        rcu_hash_free(flag_rt->item_hash);
        flag_rt->item_hash = NULL;
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

    if (flag_rt->scan_times != NULL) {
        alignment_int64_array_free(flag_rt->scan_times);
        flag_rt->scan_times = NULL;
    }

    if (flag_rt->scan_cpu_time != NULL) {
        alignment_int64_array_free(flag_rt->scan_cpu_time);
        flag_rt->scan_cpu_time = NULL;
    }

    if (flag_rt->hit_times != NULL) {
        alignment_int64_array_free(flag_rt->hit_times);
        flag_rt->hit_times = NULL;
    }

    if (flag_rt->hit_item_num != NULL) {
        alignment_int64_array_free(flag_rt->hit_item_num);
        flag_rt->hit_item_num = NULL;
    }

    FREE(flag_rt);
}

static int flag_runtime_update_row(struct flag_runtime *flag_rt, char *key,
                                   size_t key_len, struct flag_item *item,
                                   int is_valid)
{
    int ret = -1;

    if (0 == is_valid) {
        //delete
        rcu_hash_del(flag_rt->item_hash, key, key_len);
    } else {
        //add
        ret = rcu_hash_add(flag_rt->item_hash, key, key_len, (void *)item);
        if (ret < 0) {
            log_debug(flag_rt->logger, MODULE_FLAG,
                      "[%s:%d] flag item(item_id:%lld) add to item_hash failed", 
                      __FUNCTION__, __LINE__, item->item_id);
            return -1;
        }
    }
    
    return 0;
}

static int flag_runtime_get_district_id(struct flag_runtime *flag_rt,
                                        const char *district)
{
    long long district_id = DISTRICT_ANY;

	int map_ret = maat_kv_read(flag_rt->district_map, district, &district_id, 1);
	if (map_ret < 0) {
        if (NULL == flag_rt->tmp_district_map) {
            flag_rt->tmp_district_map = maat_kv_store_duplicate(flag_rt->district_map);
        }
        
        map_ret = maat_kv_read(flag_rt->tmp_district_map, district, &district_id, 1);
        if (map_ret < 0) {
            district_id = flag_rt->district_num;
		    maat_kv_register(flag_rt->tmp_district_map, district, district_id);
		    flag_rt->district_num++;
        }
	}

	return (int)district_id;
}

int flag_runtime_set_scan_district(struct flag_runtime *flag_rt, const char *district, 
                                    size_t district_len, long long *district_id)
{
    if (NULL == flag_rt || NULL == district || 0 == district_len) {
        return -1;
    }
    
    return maat_kv_read_unNull(flag_rt->district_map, district, district_len,
                               district_id, 1);
}

static struct flag_item *
flag_item_new(struct flag_schema *schema, const char *table_name,
              const char *line, struct flag_runtime *flag_rt)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    enum table_type table_type = TABLE_TYPE_INVALID;
    struct flag_item *item = ALLOC(struct flag_item, 1);

    int ret = get_column_pos(line, schema->item_id_column, &column_offset,
                             &column_len);
    if (ret < 0) {
        log_fatal(flag_rt->logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> has no item_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    item->item_id = atoll(line + column_offset);

    ret = get_column_pos(line, schema->object_id_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_fatal(flag_rt->logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> has no object_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    item->object_id = atoll(line + column_offset);

    table_type = table_manager_get_table_type(schema->ref_tbl_mgr, schema->table_id);
    if (table_type == TABLE_TYPE_INTERVAL_PLUS) {
        ret = get_column_pos(line, schema->district_column, &column_offset,
                             &column_len);
        if (ret < 0) {
            goto error;
        }

        if (column_len > MAX_DISTRICT_STR_LEN) {
            log_fatal(flag_rt->logger, MODULE_FLAG, 
                      "[%s:%d] flag_plus table:<%s> district length exceed "
                      "maximum:%d in line:%s", __FUNCTION__, __LINE__,
                      table_name, MAX_DISTRICT_STR_LEN, line);
            goto error;
        }

        char district[MAX_DISTRICT_STR_LEN + 1] = {0};
        memcpy(district, (line + column_offset), column_len);
        assert(strlen(district) > 0);
        item->district_id = flag_runtime_get_district_id(flag_rt, district);
    } else {
        item->district_id = DISTRICT_ANY;
    }

    ret = get_column_pos(line, schema->flag_column, &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(flag_rt->logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> has no flag in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }

    item->flag = strtoull(line + column_offset, NULL, 0);

    ret = get_column_pos(line, schema->flag_mask_column, &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(flag_rt->logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> has no flag_mask in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    item->flag_mask = strtoull(line + column_offset, NULL, 0);

    return item;
error:
    FREE(item);
    return NULL;
}

static struct flag_rule flag_item_to_flag_rule(struct flag_item *item)
{
    struct flag_rule rule;

    rule.rule_id = item->item_id;
    rule.flag = item->flag;
    rule.mask = item->flag_mask;
    rule.user_tag = item->user_data;

    return rule;
}

int flag_runtime_update(void *flag_runtime, void *flag_schema,
                        const char *table_name, const char *line,
                        int valid_column)
{
    if (NULL == flag_runtime || NULL == flag_schema ||
        NULL == line) {
        return -1;
    }

    struct flag_schema *schema = (struct flag_schema *)flag_schema;
    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;

    long long item_id = get_column_value(line, schema->item_id_column);
    if (item_id < 0) {
        log_fatal(flag_rt->logger, MODULE_FLAG,
                  "[%s:%d] flag table:<%s> has no item_id(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  schema->item_id_column, line);
        return -1;
    }

    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        log_fatal(flag_rt->logger, MODULE_FLAG,
                  "[%s:%d] flag table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        flag_rt->update_err_cnt++;
        return -1;
    }

    struct flag_item *flag_item = NULL;
    if (1 == is_valid) {
        flag_item = flag_item_new(schema, table_name, line, flag_rt);
        if (NULL == flag_item) {
            flag_rt->update_err_cnt++;
            return -1;
        }

        int *item_district_id = ALLOC(int, 1);
        *item_district_id = flag_item->district_id;

        flag_item->user_data = item_district_id;
    }

    int ret = flag_runtime_update_row(flag_rt, (char *)&item_id, sizeof(long long),
                                      flag_item, is_valid);
    if (ret < 0) {
        if (flag_item != NULL) {
            flag_item_free(flag_item);
        }
        //don't return failed, ignore the case of adding duplicate keys
    }

    return 0;
}

static void garbage_flag_matcher_free(void *flag_matcher, void *arg)
{
    struct flag_matcher *matcher = (struct flag_matcher *)flag_matcher;
    flag_matcher_free(matcher);
}

int flag_runtime_commit(void *flag_runtime, const char *table_name,
                        long long maat_rt_version)
{
    if (NULL == flag_runtime) {
        return -1;
    }

    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;

    int updating_flag = rcu_hash_is_updating(flag_rt->item_hash);
    if (0 == updating_flag) {
        return 0;
    }
    
    if (flag_rt->tmp_district_map != NULL) {
        struct maat_kv_store *tmp_map = flag_rt->district_map;
        flag_rt->district_map = flag_rt->tmp_district_map;
        flag_rt->tmp_district_map = NULL;
        maat_garbage_bagging(flag_rt->ref_garbage_bin, tmp_map, NULL, 
                             garbage_maat_kv_store_free);
    }

    struct flag_rule *rules = NULL;
    void **ex_data_array = NULL;

    size_t rule_cnt = rcu_updating_hash_list(flag_rt->item_hash, &ex_data_array);
    if (rule_cnt > 0) {
        rules = ALLOC(struct flag_rule, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            struct flag_item *flag_item = (struct flag_item *)ex_data_array[i];
            rules[i] = flag_item_to_flag_rule(flag_item);
        }
    }

    int ret = 0;
    struct flag_matcher *new_flag_matcher = NULL;
    struct flag_matcher *old_flag_matcher = NULL;

    if (rule_cnt > 0) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        new_flag_matcher = flag_matcher_new(rules, rule_cnt);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                                   (end.tv_nsec - start.tv_nsec) / 1000000;

        if (NULL == new_flag_matcher) {
            log_fatal(flag_rt->logger, MODULE_FLAG,
                      "[%s:%d] table[%s] rebuild flag_matcher engine failed "
                      "when update %zu flag rules", __FUNCTION__, __LINE__,
                      table_name, rule_cnt);
            ret = -1;
        } else {
            log_info(flag_rt->logger, MODULE_FLAG,
                     "table[%s] commit %zu flag rules and rebuild flag_matcher completed,"
                     " version:%lld, consume:%lldms", table_name, rule_cnt, maat_rt_version,
                     time_elapse_ms);
        }
    }

    old_flag_matcher = flag_rt->matcher;
    flag_rt->matcher = new_flag_matcher;
    rcu_hash_commit(flag_rt->item_hash);

    if (old_flag_matcher != NULL) {
        maat_garbage_bagging(flag_rt->ref_garbage_bin, old_flag_matcher, NULL,
                             garbage_flag_matcher_free);
    }
    
    flag_rt->rule_num = rule_cnt;

    if (rules != NULL) {
        FREE(rules);
    }
    
    if (ex_data_array != NULL) {
        FREE(ex_data_array);
    }

    return ret;
}

long long flag_runtime_rule_count(void *flag_runtime)
{
    if (NULL == flag_runtime) {
        return 0;
    }
    
    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;
    return flag_rt->rule_num;
}

int flag_runtime_scan(struct flag_runtime *flag_rt, int thread_id, 
                      long long flag, int attribute_id, struct maat_state *state)
{
    //clear rule_state->last_hit_object
    if (state != NULL && state->rule_compile_state != NULL) {
        rule_compile_state_clear_last_hit_object(state->rule_compile_state);
    }

    if (0 == flag_rt->rule_num) {
        //empty flag table
        return 0;
    }

    if (NULL == flag_rt->matcher) {
        return 0;
    }

    struct flag_result hit_results[MAX_HIT_ITEM_NUM];
    int n_hit_item = flag_matcher_match(flag_rt->matcher, flag, hit_results,
                                        MAX_HIT_ITEM_NUM);
    if (n_hit_item < 0) {
        return -1;
    }

    struct maat_item hit_maat_items[n_hit_item];
    size_t real_hit_item_cnt = 0;

    if (0 == n_hit_item) {
        goto next;
    }

    for (int i = 0; i < n_hit_item; i++) {
        int tag_district_id = *(int *)(hit_results[i].user_tag);
        if (tag_district_id == state->district_id ||
            tag_district_id == DISTRICT_ANY) {
            long long item_id = hit_results[i].rule_id;
            struct flag_item *flag_item =
                (struct flag_item *)rcu_hash_find(flag_rt->item_hash, 
                                                  (char *)&item_id,
                                                  sizeof(long long));
            if (!flag_item) {
                // item config has been deleted
                continue;
            }

            hit_maat_items[real_hit_item_cnt].item_id = item_id;
            hit_maat_items[real_hit_item_cnt].object_id = flag_item->object_id;
            real_hit_item_cnt++;
        }
    }

    if (real_hit_item_cnt > 0) {
        alignment_int64_array_add(flag_rt->hit_item_num, state->thread_id,
                                  real_hit_item_cnt);
    }

next:
    if (NULL == state->rule_compile_state) {
        state->rule_compile_state = rule_compile_state_new();
        alignment_int64_array_add(state->maat_inst->stat->rule_state_cnt,
                                  state->thread_id, 1);
    }

    return rule_compile_state_update(state->rule_compile_state, state->maat_inst, attribute_id,
                                state->rule_table_id, state->Nth_scan,
                                hit_maat_items, real_hit_item_cnt);
}

void flag_runtime_perf_stat(struct flag_runtime *flag_rt, struct timespec *start,
                            struct timespec *end, int thread_id)
{
    if (NULL == flag_rt || thread_id < 0) {
        return;
    }

    if (start != NULL && end != NULL) {
        long long consume_time = (end->tv_sec - start->tv_sec) * 1000000000 + 
                                 (end->tv_nsec - start->tv_nsec);
        alignment_int64_array_add(flag_rt->scan_cpu_time, thread_id, consume_time);
    }
}

void flag_runtime_hit_times_inc(struct flag_runtime *flag_rt, int thread_id)
{
    if (NULL == flag_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(flag_rt->hit_times, thread_id, 1);
}

long long flag_runtime_hit_times(void *flag_runtime)
{
    if (NULL == flag_runtime) {
        return 0;
    }

    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;
    long long sum = alignment_int64_array_sum(flag_rt->hit_times, 
                                              flag_rt->n_worker_thread);
    alignment_int64_array_reset(flag_rt->hit_times,
                                flag_rt->n_worker_thread);

    return sum;
}

long long flag_runtime_hit_item_num(void *flag_runtime)
{
    if (NULL == flag_runtime) {
        return 0;
    }

    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;
    long long sum = alignment_int64_array_sum(flag_rt->hit_item_num, 
                                              flag_rt->n_worker_thread);
    alignment_int64_array_reset(flag_rt->hit_item_num,
                                flag_rt->n_worker_thread);

    return sum;
}

void flag_runtime_scan_times_inc(struct flag_runtime *flag_rt, int thread_id)
{
    if (NULL == flag_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(flag_rt->scan_times, thread_id, 1);
}

long long flag_runtime_scan_times(void *flag_runtime)
{
    if (NULL == flag_runtime) {
        return 0;
    }

    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;
    long long sum = alignment_int64_array_sum(flag_rt->scan_times, 
                                              flag_rt->n_worker_thread);
    alignment_int64_array_reset(flag_rt->scan_times,
                                flag_rt->n_worker_thread);

    return sum;
}

long long flag_runtime_scan_cpu_time(void *flag_runtime)
{
    if (NULL == flag_runtime) {
        return 0;
    }

    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;
    long long sum = alignment_int64_array_sum(flag_rt->scan_cpu_time, 
                                              flag_rt->n_worker_thread);
    alignment_int64_array_reset(flag_rt->scan_cpu_time,
                                flag_rt->n_worker_thread);

    return sum;
}

long long flag_runtime_update_err_count(void *flag_runtime)
{
    if (NULL == flag_runtime) {
        return 0;
    }

    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;
    return flag_rt->update_err_cnt;
}  
