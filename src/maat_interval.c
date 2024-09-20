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

#include "maat_core.h"
#include "maat_utils.h"
#include "rcu_hash.h"
#include "alignment.h"
#include "maat_garbage_collection.h"
#include "maat_rule.h"
#include "interval_matcher.h"
#include "maat_interval.h"

#define MODULE_INTERVAL	 module_name_str("maat.interval")

struct interval_schema {
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

struct interval_item {
    uuid_t item_uuid;
    uuid_t object_uuid;
    int low_boundary;
    int up_boundary;
    void *user_data;
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

    long long *scan_times;
    long long *scan_cpu_time;

    long long *hit_times;
    long long *hit_item_num;

    long long update_err_cnt;
};

void *interval_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                          const char *table_name, struct log_handle *logger)
{
    struct interval_schema *schema = ALLOC(struct interval_schema, 1);

    char table_type[NAME_MAX] = {0};
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    /* table_type already validate in maat_table_new() */
    item = cJSON_GetObjectItem(json, "table_type");
    memcpy(table_type, item->valuestring, strlen(item->valuestring));

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

    if (item->user_data != NULL) {
        FREE(item->user_data);
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

    interval_rt->hit_times = alignment_int64_array_alloc(max_thread_num);
    interval_rt->scan_times = alignment_int64_array_alloc(max_thread_num);
    interval_rt->scan_cpu_time = alignment_int64_array_alloc(max_thread_num);
    interval_rt->hit_item_num = alignment_int64_array_alloc(max_thread_num);

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

    if (interval_rt->hit_times != NULL) {
        alignment_int64_array_free(interval_rt->hit_times);
        interval_rt->hit_times = NULL;
    }

    if (interval_rt->scan_times != NULL) {
        alignment_int64_array_free(interval_rt->scan_times);
        interval_rt->scan_times = NULL;
    }

    if (interval_rt->scan_cpu_time != NULL) {
        alignment_int64_array_free(interval_rt->scan_cpu_time);
        interval_rt->scan_cpu_time = NULL;
    }

    if (interval_rt->hit_item_num != NULL) {
        alignment_int64_array_free(interval_rt->hit_item_num);
        interval_rt->hit_item_num = NULL;
    }

    FREE(interval_rt);
}

static int interval_runtime_get_district_id(struct interval_runtime *interval_rt,
                                            const char *district)
{
    long long district_id = DISTRICT_ANY;

	int map_ret = maat_kv_read(interval_rt->district_map, district, &district_id, 1);
	if (map_ret < 0) {
        if (NULL == interval_rt->tmp_district_map) {
            interval_rt->tmp_district_map = maat_kv_store_duplicate(interval_rt->district_map);
        }
        
        map_ret = maat_kv_read(interval_rt->tmp_district_map, district, &district_id, 1);
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

    return maat_kv_read_unNull(interval_rt->district_map, district, district_len,
                               district_id, 1);
}

static struct interval_item *
interval_item_new(struct interval_schema *schema, const char *table_name,
                  const cJSON *json, struct interval_runtime *interval_rt, uuid_t item_uuid)
{
    enum table_type table_type = TABLE_TYPE_INVALID;
    char port_str[16] = {0};
    struct interval_item *item = ALLOC(struct interval_item, 1);
    cJSON *tmp_obj = NULL;

    uuid_copy(item->item_uuid, item_uuid);

    tmp_obj = cJSON_GetObjectItem(json, "object_uuid");
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(interval_rt->logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> has no object_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
        goto error;
    }
    uuid_parse(tmp_obj->valuestring, item->object_uuid);

    table_type = table_manager_get_table_type(schema->ref_tbl_mgr, schema->table_id);
    if (table_type == TABLE_TYPE_INTERVAL_PLUS) {
        tmp_obj = cJSON_GetObjectItem(json, "district");
        if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
            log_fatal(interval_rt->logger, MODULE_INTERVAL, 
                      "[%s:%d] interval_plus table:<%s> has no district in line:%s",
                      __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
            goto error;
        }

        size_t len = strlen(tmp_obj->valuestring);

        if (len > MAX_DISTRICT_STR_LEN) {
            log_fatal(interval_rt->logger, MODULE_INTERVAL, 
                      "[%s:%d] interval_plus table:<%s> district length exceed "
                      "maximum:%d in line:%s", __FUNCTION__, __LINE__, table_name,
                      MAX_DISTRICT_STR_LEN, cJSON_Print(json));
            goto error;
        }

        char district[MAX_DISTRICT_STR_LEN + 1] = {0};
        memcpy(district, tmp_obj->valuestring, len);
        assert(strlen(district) > 0);
        item->district_id = interval_runtime_get_district_id(interval_rt, district);
    } else {
        item->district_id = DISTRICT_ANY;
    }

    tmp_obj = cJSON_GetObjectItem(json, "interval");
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(interval_rt->logger, MODULE_INTERVAL, 
                  "[%s:%d] interval table:<%s> has no interval in line:%s",
                  __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
        goto error;
    }
    memcpy(port_str, tmp_obj->valuestring, strlen(tmp_obj->valuestring));
    if (strchr(port_str, '-') != NULL) {
        sscanf(port_str, "%d-%d", &item->low_boundary, &item->up_boundary);
    } else {
        item->low_boundary = atoi(port_str);
        item->up_boundary = item->low_boundary;
    }

    return item;
error:
    FREE(item);
    return NULL;
}

static struct interval_rule
interval_item_to_interval_rule(struct interval_item *item)
{
    struct interval_rule rule;

    rule.start = item->low_boundary;
    rule.end = item->up_boundary;
    uuid_copy(rule.result.rule_uuid, item->item_uuid);
    rule.result.user_tag = item->user_data;

    return rule;
}

static int interval_runtime_update_row(struct interval_runtime *interval_rt,
                                       char *key, size_t key_len,
                                       struct interval_item *item, enum maat_operation op)
{
    int ret = -1;

    if (MAAT_OP_DEL == op) {
        //delete
        rcu_hash_del(interval_rt->item_hash, key, key_len);
    } else {
        //add
        ret = rcu_hash_add(interval_rt->item_hash, key, key_len, (void *)item);
        if (ret < 0) {
            char uuid_str[UUID_STR_LEN] = {0};
            uuid_unparse(item->item_uuid, uuid_str);
            log_debug(interval_rt->logger, MODULE_INTERVAL,
                      "[%s:%d] interval item(item_id:%s) add to "
                      "interavl_item_hash failed", __FUNCTION__, __LINE__,
                      uuid_str);
            return -1;
        }
    }
    
    return 0;
}

int interval_runtime_update(void *interval_runtime, void *interval_schema, 
                            const char *table_name, const char *line, 
                            enum maat_operation op)
{
    if (NULL == interval_runtime || NULL == interval_schema ||
        NULL == line) {
        return -1;
    }

    struct interval_schema *schema = (struct interval_schema *)interval_schema;
    struct interval_runtime *interval_rt = (struct interval_runtime *)interval_runtime;
    cJSON *tmp_obj = NULL;
    cJSON *json = NULL;
    
    json = cJSON_Parse(line);
    if (NULL == json) {
        log_fatal(interval_rt->logger, MODULE_INTERVAL,
                  "[%s:%d] interval table:<%s> line:%s is not a valid json",
                  __FUNCTION__, __LINE__, table_name, line);
        interval_rt->update_err_cnt++;
        goto ERROR;
    }

    tmp_obj = cJSON_GetObjectItem(json, "uuid");
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(interval_rt->logger, MODULE_INTERVAL,
                  "[%s:%d] interval table:<%s> has no item_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        interval_rt->update_err_cnt++;
        goto ERROR;
    }

    uuid_t item_uuid;
    uuid_parse(tmp_obj->valuestring, item_uuid);
    if (uuid_is_null(item_uuid)) {
        log_fatal(interval_rt->logger, MODULE_INTERVAL,
                  "[%s:%d] interval table:<%s> item_id wrong"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  line);
        interval_rt->update_err_cnt++;
        goto ERROR;
    }
    
    struct interval_item *interval_item = NULL;
    if (MAAT_OP_ADD == op) {
        //add
        interval_item = interval_item_new(schema, table_name, json, interval_rt, item_uuid);
        if (NULL == interval_item) {
            interval_rt->update_err_cnt++;
            goto ERROR;
        }

        int *item_district_id = ALLOC(int, 1);
        *item_district_id = interval_item->district_id;

        interval_item->user_data = item_district_id;
    }

    int ret = interval_runtime_update_row(interval_rt, (char *)&item_uuid, sizeof(uuid_t),
                                          interval_item, op);
    if (ret < 0) {
        if (interval_item != NULL) {
            interval_item_free(interval_item);
        }
        //don't return failed, ignore the case of adding duplicate keys
    }

    cJSON_Delete(json);
    return 0;
    
ERROR:
    if (json != NULL) {
        cJSON_Delete(json);
    }
    return -1;
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

    struct interval_runtime *interval_rt =
        (struct interval_runtime *)interval_runtime;

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
            struct interval_item *interval_item =
                (struct interval_item *)ex_data_array[i];
            rules[i] = interval_item_to_interval_rule(interval_item);
        }
    }

    int ret = 0;
    struct interval_matcher *new_interval_matcher = NULL;
    struct interval_matcher *old_interval_matcher = NULL;

    if (rule_cnt > 0) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        new_interval_matcher = interval_matcher_new(rules, rule_cnt);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                                   (end.tv_nsec - start.tv_nsec) / 1000000;

        if (NULL == new_interval_matcher) {
            log_fatal(interval_rt->logger, MODULE_INTERVAL,
                      "[%s:%d] table[%s]rebuild interval_matcher engine failed "
                      "when update %zu interval rules", __FUNCTION__, __LINE__,
                      table_name, rule_cnt);
            ret = -1;
        } else {
            log_info(interval_rt->logger, MODULE_INTERVAL,
                     "table[%s] commit %zu interval rules and rebuild interval_matcher "
                     "completed, version:%lld, consume:%lldms", table_name, rule_cnt,
                     maat_rt_version, time_elapse_ms);
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
    
    struct interval_runtime *interval_rt =
        (struct interval_runtime *)interval_runtime;
    return interval_rt->rule_num;
}

int interval_runtime_scan(struct interval_runtime *interval_rt, int thread_id, 
                          long long integer, int attribute_id, struct maat_state *state)
{
    //clear rule_state->last_hit_object
    if (state != NULL && state->rule_compile_state != NULL) {
        rule_compile_state_clear_last_hit_object(state->rule_compile_state);
    }

    if (0 == interval_rt->rule_num) {
        //empty interval table
        return 0;
    }

    if (NULL == interval_rt->matcher) {
        return 0;
    }

    struct interval_result hit_results[MAX_HIT_ITEM_NUM];
    int n_hit_item = interval_matcher_match(interval_rt->matcher, integer, 
                                            hit_results, MAX_HIT_ITEM_NUM);
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
            struct interval_item *int_item =
                (struct interval_item *)rcu_hash_find(interval_rt->item_hash, 
                                                     (char *)&hit_results[i].rule_uuid,
                                                      sizeof(uuid_t));
            if (!int_item) {
                // item config has been deleted
                continue;
            }

            uuid_copy(hit_maat_items[real_hit_item_cnt].item_uuid, int_item->item_uuid);
            uuid_copy(hit_maat_items[real_hit_item_cnt].object_uuid, int_item->object_uuid);
            real_hit_item_cnt++;
        }
    }

    if (real_hit_item_cnt > 0) {
        alignment_int64_array_add(interval_rt->hit_item_num, state->thread_id,
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

void interval_runtime_perf_stat(struct interval_runtime *interval_rt,
                                struct timespec *start, struct timespec *end,
                                int thread_id)
{
    if (NULL == interval_rt || thread_id < 0) {
        return;
    }

    if (start != NULL && end != NULL) {
        long long consume_time = (end->tv_sec - start->tv_sec) * 1000000000 +
                                 (end->tv_nsec - start->tv_nsec);
        alignment_int64_array_add(interval_rt->scan_cpu_time, thread_id, consume_time);
    }
}

void interval_runtime_hit_times_inc(struct interval_runtime *interval_rt,
                                    int thread_id)
{
    if (NULL == interval_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(interval_rt->hit_times, thread_id, 1);
}

long long interval_runtime_hit_times(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return 0;
    }

    struct interval_runtime *interval_rt =
        (struct interval_runtime *)interval_runtime;

    long long sum = alignment_int64_array_sum(interval_rt->hit_times,
                                              interval_rt->n_worker_thread);
    alignment_int64_array_reset(interval_rt->hit_times,
                                interval_rt->n_worker_thread);

    return sum;
}

void interval_runtime_scan_times_inc(struct interval_runtime *interval_rt,
                                     int thread_id)
{
    if (NULL == interval_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(interval_rt->scan_times, thread_id, 1);
}

long long interval_runtime_scan_times(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return 0;
    }

    struct interval_runtime *interval_rt =
        (struct interval_runtime *)interval_runtime;

    long long sum = alignment_int64_array_sum(interval_rt->scan_times,
                                              interval_rt->n_worker_thread);
    alignment_int64_array_reset(interval_rt->scan_times,
                                interval_rt->n_worker_thread);

    return sum;
}

long long interval_runtime_scan_cpu_time(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return 0;
    }

    struct interval_runtime *interval_rt =
        (struct interval_runtime *)interval_runtime;

    long long sum = alignment_int64_array_sum(interval_rt->scan_cpu_time, 
                                              interval_rt->n_worker_thread);
    alignment_int64_array_reset(interval_rt->scan_cpu_time,
                                interval_rt->n_worker_thread);

    return sum;
}

long long interval_runtime_hit_item_num(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return 0;
    }

    struct interval_runtime *interval_rt =
        (struct interval_runtime *)interval_runtime;

    long long sum = alignment_int64_array_sum(interval_rt->hit_item_num,
                                              interval_rt->n_worker_thread);
    alignment_int64_array_reset(interval_rt->hit_item_num,
                                interval_rt->n_worker_thread);

    return sum;
}

long long interval_runtime_update_err_cnt(void *interval_runtime)
{
    if (NULL == interval_runtime) {
        return 0;
    }

    struct interval_runtime *interval_rt =
        (struct interval_runtime *)interval_runtime;

    return interval_rt->update_err_cnt;
}