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
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

struct flag_item {
    uuid_t item_uuid;
    uuid_t object_uuid;
    long long flag;
    long long flag_mask;
};

struct flag_runtime {
    struct flag_matcher *matcher;
    struct rcu_hash_table *item_hash; // <item_id, struct flag_item>

    long long rule_num;
    size_t n_worker_thread;
    struct log_handle *logger;
    struct maat_garbage_bin *ref_garbage_bin;

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
                                   enum maat_operation op)
{
    int ret = -1;

    if (MAAT_OP_DEL == op) {
        //delete
        rcu_hash_del(flag_rt->item_hash, key, key_len);
    } else {
        //add
        ret = rcu_hash_add(flag_rt->item_hash, key, key_len, (void *)item);
        if (ret < 0) {
            char uuid_str[UUID_STR_LEN] = {0};
            uuid_unparse(item->item_uuid, uuid_str);
            log_debug(flag_rt->logger, MODULE_FLAG,
                      "[%s:%d] flag item(item_uuid:%s) add to item_hash failed", 
                      __FUNCTION__, __LINE__, uuid_str);
            return -1;
        }
    }
    
    return 0;
}

static struct flag_item *
flag_item_new(struct flag_schema *schema, const char *table_name,
              const cJSON *json, struct flag_runtime *flag_rt, uuid_t item_uuid)
{
    cJSON *tmp_obj = NULL;
    struct flag_item *item = ALLOC(struct flag_item, 1);

    uuid_copy(item->item_uuid, item_uuid);

    tmp_obj = cJSON_GetObjectItem(json, "object_uuid");
    if (tmp_obj == NULL || tmp_obj->type != cJSON_String) {
        char *json_str = cJSON_Print(json);
        log_fatal(flag_rt->logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> has no object_id in json:%s",
                  __FUNCTION__, __LINE__, table_name, json_str);
        goto error;
    }
    uuid_parse(tmp_obj->valuestring, item->object_uuid);

    tmp_obj = cJSON_GetObjectItem(json, "flag");
    if (tmp_obj == NULL || tmp_obj->type != cJSON_Number) {
        char *json_str = cJSON_Print(json);
        log_fatal(flag_rt->logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> has no flag in json:%s",
                  __FUNCTION__, __LINE__, table_name, json_str);
        FREE(json_str);
        goto error;
    }

    item->flag = tmp_obj->valueint;

    tmp_obj = cJSON_GetObjectItem(json, "mask");
    if (tmp_obj == NULL || tmp_obj->type != cJSON_Number) {
        char *json_str = cJSON_Print(json);
        log_fatal(flag_rt->logger, MODULE_FLAG, 
                  "[%s:%d] flag table:<%s> has no mask in json:%s",
                  __FUNCTION__, __LINE__, table_name, json_str);
        FREE(json_str);
        goto error;
    }
    
    item->flag_mask = tmp_obj->valueint;

    return item;
error:
    FREE(item);
    return NULL;
}

static struct flag_rule flag_item_to_flag_rule(struct flag_item *item)
{
    struct flag_rule rule;

    uuid_copy(rule.rule_uuid, item->item_uuid);
    rule.flag = item->flag;
    rule.mask = item->flag_mask;

    return rule;
}

int flag_runtime_update(void *flag_runtime, void *flag_schema,
                        const char *table_name, const char *line,
                        enum maat_operation op)
{
    if (NULL == flag_runtime || NULL == flag_schema ||
        NULL == line) {
        return -1;
    }

    struct flag_schema *schema = (struct flag_schema *)flag_schema;
    struct flag_runtime *flag_rt = (struct flag_runtime *)flag_runtime;

    cJSON *json = cJSON_Parse(line);
    if (NULL == json) {
        log_fatal(flag_rt->logger, MODULE_FLAG,
                  "[%s:%d] flag table:<%s> line:%s is not a valid json",
                  __FUNCTION__, __LINE__, table_name, line);
        return -1;
    }

    cJSON *item = cJSON_GetObjectItem(json, "uuid");
    if (NULL == item || item->type != cJSON_String) {
        log_fatal(flag_rt->logger, MODULE_FLAG,
                  "[%s:%d] flag table:<%s> line:%s has no item_id",
                  __FUNCTION__, __LINE__, table_name, line);
        goto ERROR;
    }

    uuid_t item_uuid;
    uuid_parse(item->valuestring, item_uuid);

    struct flag_item *flag_item = NULL;
    if (MAAT_OP_ADD == op) {
        flag_item = flag_item_new(schema, table_name, json, flag_rt, item_uuid);
        if (NULL == flag_item) {
            flag_rt->update_err_cnt++;
            goto ERROR;
        }
    }

    int ret = flag_runtime_update_row(flag_rt, (char *)&item_uuid, sizeof(item_uuid),
                                      flag_item, op);
    if (ret < 0) {
        if (flag_item != NULL) {
            flag_item_free(flag_item);
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
                      long long flag, const char *attribute_name, struct maat_state *state)
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
        struct flag_item *flag_item =
            (struct flag_item *)rcu_hash_find(flag_rt->item_hash, 
                                                (char *)&hit_results[i].rule_uuid,
                                                sizeof(hit_results[i].rule_uuid));
        if (!flag_item) {
            // item config has been deleted
            continue;
        }

        uuid_copy(hit_maat_items[real_hit_item_cnt].item_uuid, hit_results[i].rule_uuid);
        uuid_copy(hit_maat_items[real_hit_item_cnt].object_uuid, flag_item->object_uuid);
        real_hit_item_cnt++;
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

    return rule_compile_state_update(state->rule_compile_state, state->maat_inst, attribute_name,
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
