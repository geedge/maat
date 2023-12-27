/*
**********************************************************************************************
*	File: maat_bool_plugin.c
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "alignment.h"
#include "maat_bool_plugin.h"
#include "bool_matcher.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "maat_garbage_collection.h"

#define MODULE_BOOL_PLUGIN	 module_name_str("maat.bool_plugin")

struct bool_plugin_schema {
    int item_id_column;
    int bool_expr_column;
    int rule_tag_column;
    int gc_timeout_s;
    struct ex_container_schema container_schema;
    int table_id;
    struct table_manager *ref_tbl_mgr;
    struct log_handle *logger;
};

struct bool_plugin_runtime {
    struct bool_matcher *matcher;
    struct ex_data_runtime *ex_data_rt;
    size_t n_worker_thread;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;

    long long rule_num;
    long long update_err_cnt;
    long long *scan_times;
};

/* bool plugin schema API */
void *bool_plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger)
{
    struct bool_plugin_schema *schema = ALLOC(struct bool_plugin_schema, 1);
    schema->logger = logger;

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
   if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_BOOL_PLUGIN, 
                  "[%s:%d] bool_plugin table:<%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (NULL == item || item->type != cJSON_Object) {
        log_fatal(logger, MODULE_BOOL_PLUGIN, 
                  "[%s:%d] bool_plugin table:<%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->item_id_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_BOOL_PLUGIN, 
                  "[%s:%d] bool_plugin table:<%s> schema has no item_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "bool_expr");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->bool_expr_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_BOOL_PLUGIN, 
                  "[%s:%d] bool_plugin table:<%s> schema has no bool_expr column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    // rule_tag is optional
    custom_item = cJSON_GetObjectItem(item, "rule_tag");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->rule_tag_column = custom_item->valueint;
    }

    //gc_timeout_s is optional
    custom_item = cJSON_GetObjectItem(item, "gc_timeout_s");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->gc_timeout_s = custom_item->valueint;
    }

    schema->ref_tbl_mgr = tbl_mgr;
    return schema;
error:
    FREE(schema);
    return NULL;
}

void bool_plugin_schema_free(void *bool_plugin_schema)
{
    if (NULL == bool_plugin_schema) {
        return;
    }
  
    FREE(bool_plugin_schema);
}

int bool_plugin_table_set_ex_container_schema(void *bool_plugin_schema, int table_id,
                                              maat_ex_new_func_t *new_func,
							                  maat_ex_free_func_t *free_func,
							                  maat_ex_dup_func_t *dup_func,
                                              void (*custom_data_free)(void *),
							                  long argl, void *argp)
{
    struct bool_plugin_schema *schema = (struct bool_plugin_schema *)bool_plugin_schema;

    if (1 == schema->container_schema.set_flag) {
        log_fatal(schema->logger, MODULE_BOOL_PLUGIN, 
                  "[%s:%d] bool_plugin table(table_id:%d) ex_container_schema"
                  " has been set, can't set again", __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    schema->container_schema.table_id = table_id;
    schema->container_schema.custom_data_free = custom_data_free;
    schema->container_schema.ex_schema.new_func = new_func;
    schema->container_schema.ex_schema.free_func = free_func;
    schema->container_schema.ex_schema.dup_func = dup_func;
    schema->container_schema.ex_schema.argl = argl;
    schema->container_schema.ex_schema.argp = argp;
    schema->container_schema.set_flag = 1;
    
    return 0;
}

struct ex_container_schema *
bool_plugin_table_get_ex_container_schema(void *bool_plugin_schema)
{
    struct bool_plugin_schema *schema = (struct bool_plugin_schema *)bool_plugin_schema;

    return &(schema->container_schema);
}

static int cmp_ull_p(const void *p1, const void *p2)
{
	if(* (unsigned long long*) p1 > * (unsigned long long*) p2) {
		return 1;
	} else if(* (unsigned long long*) p1 < * (unsigned long long*) p2) {
		return -1;
	} else {
		return 0;
	}
}

static size_t ull_dedup(unsigned long long item_ids[], size_t n_item)
{
    size_t index = 0;

	qsort(item_ids, n_item, sizeof(unsigned long long), cmp_ull_p);

	for (size_t i = 1; i < n_item; i++) {
		if (item_ids[i] != item_ids[index]) {
            item_ids[++index] = item_ids[i];
        }
	}

	return index + 1;
}

void *bool_plugin_runtime_new(void *bool_plugin_schema, size_t max_thread_num,
                              struct maat_garbage_bin *garbage_bin, 
                              struct log_handle *logger)
{
    if (NULL == bool_plugin_schema) {
        return NULL;
    }

    struct bool_plugin_schema *schema = (struct bool_plugin_schema *)bool_plugin_schema;
    struct bool_plugin_runtime *bool_plugin_rt = ALLOC(struct bool_plugin_runtime, 1);

    bool_plugin_rt->ex_data_rt = ex_data_runtime_new(schema->table_id, schema->gc_timeout_s,
                                                     logger);
    if (1 == schema->container_schema.set_flag) {
        ex_data_runtime_set_ex_container_schema(bool_plugin_rt->ex_data_rt,
                                                &(schema->container_schema));
    }

    bool_plugin_rt->n_worker_thread = max_thread_num;
    bool_plugin_rt->ref_garbage_bin = garbage_bin;
    bool_plugin_rt->logger = logger;
    bool_plugin_rt->scan_times = alignment_int64_array_alloc(max_thread_num);

    return bool_plugin_rt;
}

void bool_plugin_runtime_free(void *bool_plugin_runtime)
{
    if (NULL == bool_plugin_runtime) {
        return;
    }

    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;
    if (bool_plugin_rt->matcher != NULL) {
        bool_matcher_free(bool_plugin_rt->matcher);
        bool_plugin_rt->matcher = NULL;
    }

    if (bool_plugin_rt->ex_data_rt != NULL) {
        ex_data_runtime_free(bool_plugin_rt->ex_data_rt);
        bool_plugin_rt->ex_data_rt = NULL;
    }

    if (bool_plugin_rt->scan_times != NULL) {
        alignment_int64_array_free(bool_plugin_rt->scan_times);
        bool_plugin_rt->scan_times = NULL;
    }

    FREE(bool_plugin_rt);
}

static int bool_plugin_runtime_update_row(struct bool_plugin_runtime *bool_plugin_rt,
                                          const char *table_name, const char *row, 
                                          const char *key, size_t key_len, 
                                          struct bool_expr *expr, int is_valid)
{
    int ret = -1;
    struct ex_data_runtime *ex_data_rt = bool_plugin_rt->ex_data_rt;

    if (0 == is_valid) {
        // delete
        ret = ex_data_runtime_del_ex_container(ex_data_rt, key, key_len);
        if (ret < 0) {
            return -1;
        }
    } else {
        // add
        void *ex_data = ex_data_runtime_row2ex_data(ex_data_rt, table_name, row,
                                                    key, key_len);
        struct ex_container *ex_container = ex_container_new(ex_data, (void *)expr);
        ret = ex_data_runtime_add_ex_container(ex_data_rt, key, key_len, ex_container);
        if (ret < 0) {
            ex_container_free(ex_data_rt, ex_container);
            return -1;
        }
    }

    return 0;
}

static int bool_plugin_accept_tag_match(struct bool_plugin_schema *schema,
                                        const char *table_name, const char *line,
                                        struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);

    if (schema->rule_tag_column > 0 && n_tag > 0) {
        int ret = get_column_pos(line, schema->rule_tag_column, 
                                 &column_offset, &column_len);
        if (ret < 0) {
            log_fatal(logger, MODULE_BOOL_PLUGIN,
                      "[%s:%d] bool_plugin table:<%s> has no rule_tag in line:%s",
                      __FUNCTION__, __LINE__, table_name, line);
            return TAG_MATCH_ERR;
        }

        if (column_len > 2) {
            char *tag_str = ALLOC(char, column_len + 1);
            memcpy(tag_str, (line + column_offset), column_len);
            ret = table_manager_accept_tags_match(schema->ref_tbl_mgr, tag_str);
            FREE(tag_str);
            if (TAG_MATCH_ERR == ret) {
                log_fatal(logger, MODULE_BOOL_PLUGIN,
                          "[%s:%d] bool_plugin table:<%s> has invalid tag format in line:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                return TAG_MATCH_ERR;
            }

            if (TAG_MATCH_UNMATCHED == ret) {
                log_fatal(logger, MODULE_BOOL_PLUGIN,
                          "[%s:%d] bool_plugin table:<%s> has unmatched tag in line:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                return TAG_MATCH_UNMATCHED;
            }
        }
    }

    return TAG_MATCH_MATCHED;
}

static struct bool_expr *
bool_plugin_expr_new(struct bool_plugin_schema *schema, const char *table_name,
                     const char *line, struct log_handle *logger)
{
    int ret = bool_plugin_accept_tag_match(schema, table_name, line, logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        return NULL;
    }

    size_t column_offset = 0;
    size_t column_len = 0;
    size_t n_item = 0;
    char expr_buffer[BUFSIZ + 1] = {0};
    unsigned long long items[MAX_ITEMS_PER_BOOL_EXPR] = {0};
    char *token = NULL, *sub_token = NULL, *saveptr;
    struct bool_expr *bool_expr = ALLOC(struct bool_expr, 1);

    ret = get_column_pos(line, schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_BOOL_PLUGIN, 
                  "[%s:%d] bool_plugin table:<%s> has no item_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    bool_expr->expr_id = atoll(line + column_offset);

    ret = get_column_pos(line, schema->bool_expr_column, &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_BOOL_PLUGIN, 
                  "[%s:%d] bool_plugin table:<%s> has no bool_expr in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }

    memset(expr_buffer, 0, sizeof(expr_buffer));
    memcpy(expr_buffer, line + column_offset, column_len);
    for (token = expr_buffer; ; token = NULL) {
        sub_token = strtok_r(token, "&", &saveptr);
        if (NULL == sub_token) {
            break;
        }

        ret = sscanf(sub_token, "%llu", items + n_item);
        n_item++;
        if (ret != 1 || n_item > MAX_ITEMS_PER_BOOL_EXPR) {
            log_fatal(logger, MODULE_BOOL_PLUGIN, 
                      "[%s:%d] bool_plugin table:<%s> has invalid format of "
                      "bool_expr in line:%s", __FUNCTION__, __LINE__, table_name, line);
            goto error;
        }
    }

    n_item = ull_dedup(items, n_item);
    for (size_t i = 0; i < n_item; i++) {
        bool_expr->items[i].item_id = items[i];
        bool_expr->items[i].not_flag = 0;
    }

    bool_expr->item_num = n_item;

    return bool_expr;
error:
    FREE(bool_expr);
    return NULL;
}

static void bool_plugin_expr_free(struct bool_expr *expr)
{
    FREE(expr);
}

int bool_plugin_runtime_update(void *bool_plugin_runtime, void *bool_plugin_schema, 
                               const char *table_name, const char *line, int valid_column)
{
    if (NULL == bool_plugin_runtime || NULL == bool_plugin_schema || 
        NULL == line) {
        return -1;
    }

    struct bool_expr *bool_expr = NULL;
    struct bool_plugin_schema *schema = (struct bool_plugin_schema *)bool_plugin_schema;
    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;
    size_t item_id_offset = 0, item_id_len = 0;

    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        log_fatal(bool_plugin_rt->logger, MODULE_BOOL_PLUGIN,
                  "[%s:%d] bool_plugin table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        bool_plugin_rt->update_err_cnt++;
        return -1;
    }

    int ret = get_column_pos(line, schema->item_id_column, &item_id_offset, &item_id_len);
    if (ret < 0) {
        log_fatal(bool_plugin_rt->logger, MODULE_BOOL_PLUGIN,
                  "[%s:%d] bool_plugin table:<%s> has no item_id(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  schema->item_id_column, line);
        bool_plugin_rt->update_err_cnt++;
        return -1;
    }

    if (1 == schema->container_schema.set_flag) {
        if (1 == is_valid) {
            // add
            bool_expr = bool_plugin_expr_new(schema, table_name, line, bool_plugin_rt->logger);
            if (NULL == bool_expr) {
                bool_plugin_rt->update_err_cnt++;
                return -1;
            }
        }

        const char *key = line + item_id_offset;
        size_t key_len = item_id_len;
        ret = bool_plugin_runtime_update_row(bool_plugin_rt, table_name, line, key, key_len, 
                                             bool_expr, is_valid);
        if (ret < 0) {
            if (bool_expr != NULL) {
                bool_plugin_expr_free(bool_expr);
            }
            bool_plugin_rt->update_err_cnt++;
            return -1;
        }

        log_debug(bool_plugin_rt->logger, MODULE_BOOL_PLUGIN,
                  "bool_plugin table:<%s> update one line, key:%s, key_len:%zu, is_valid:%d",
                  table_name, key, key_len, is_valid);
    } else {
        //ex_schema not set
        ex_data_runtime_cache_row_put(bool_plugin_rt->ex_data_rt, line);
        bool_plugin_rt->rule_num = ex_data_runtime_cached_row_count(bool_plugin_rt->ex_data_rt);
    }

    return 0;
}

void garbage_bool_matcher_free(void *matcher, void *arg)
{
    struct bool_matcher *bm = (struct bool_matcher *)matcher;
    bool_matcher_free(bm);
}

int bool_plugin_runtime_commit(void *bool_plugin_runtime, const char *table_name,
                               long long maat_rt_version)
{
    if (NULL == bool_plugin_runtime) {
        return -1;
    }

    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;
    struct ex_data_runtime *ex_data_rt = bool_plugin_rt->ex_data_rt;
    if (NULL == ex_data_rt) {
        return -1;
    }

    int updating_flag = ex_data_runtime_is_updating(ex_data_rt);
    if (0 == updating_flag) {
        return 0;
    }

    struct bool_expr *rules = NULL;
    struct ex_container **ex_container = NULL;
    size_t rule_cnt = ex_data_runtime_list_updating_ex_container(ex_data_rt, &ex_container);
    if (rule_cnt > 0) {
        rules = ALLOC(struct bool_expr, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            rules[i] = *(struct bool_expr *)(struct bool_expr *)ex_container[i]->custom_data;
            assert(rules[i].user_tag == ex_container[i] || NULL == rules[i].user_tag);
            rules[i].user_tag = ex_container[i];
        }
    }

    int ret = 0;
    size_t mem_used = 0;
    struct bool_matcher *new_bool_matcher = NULL;
    struct bool_matcher *old_bool_matcher = NULL;

    if (rule_cnt > 0) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        new_bool_matcher = bool_matcher_new(rules, rule_cnt, &mem_used);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                                   (end.tv_nsec - start.tv_nsec) / 1000000;

        if (NULL == new_bool_matcher) {
            log_fatal(bool_plugin_rt->logger, MODULE_BOOL_PLUGIN,
                      "[%s:%d] table[%s] rebuild bool_matcher engine failed when "
                      "update %zu bool_plugin rules", __FUNCTION__, __LINE__,
                      table_name, rule_cnt);
            ret = -1;
        } else {
             log_info(bool_plugin_rt->logger, MODULE_BOOL_PLUGIN,
                      "table[%s] commit %zu bool_plugin rules and rebuild bool_matcher"
                      " completed, version:%lld, consume:%lldms", table_name, rule_cnt,
                      maat_rt_version, time_elapse_ms);
        }
    }

    old_bool_matcher = bool_plugin_rt->matcher;
    bool_plugin_rt->matcher = new_bool_matcher;
    ex_data_runtime_commit(ex_data_rt);

    if (old_bool_matcher != NULL) {
        maat_garbage_bagging(bool_plugin_rt->ref_garbage_bin, old_bool_matcher, NULL,
                             garbage_bool_matcher_free);
    }

    bool_plugin_rt->rule_num = rule_cnt;

    if (rules != NULL) {
        FREE(rules);
    }
    
    if (ex_container != NULL) {
        FREE(ex_container);
    }

    return ret;
}

long long bool_plugin_runtime_rule_count(void *bool_plugin_runtime)
{
    if (NULL == bool_plugin_runtime) {
        return 0;
    }
    
    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;
    return bool_plugin_rt->rule_num;
}

struct ex_data_runtime *bool_plugin_runtime_get_ex_data_rt(void *bool_plugin_runtime)
{
    if (NULL == bool_plugin_runtime) {
        return NULL;
    }

    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;

    return bool_plugin_rt->ex_data_rt;
}

int bool_plugin_runtime_get_ex_data(void *bool_plugin_runtime, unsigned long long *item_ids, 
                                    size_t n_item, void **ex_data_array, size_t n_ex_data)
{
    if (NULL == bool_plugin_runtime || NULL == ex_data_array ||
        NULL == item_ids || 0 == n_item || 0 == n_ex_data) {
        return -1;
    }

    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;
    if (0 == bool_plugin_rt->rule_num) {
        return 0;
    }

    if (NULL == bool_plugin_rt->matcher) {
        return 0;
    }

    struct bool_expr_match results[n_ex_data];
    n_item = ull_dedup(item_ids, n_item);
    
	int n_result = bool_matcher_match(bool_plugin_rt->matcher, item_ids, n_item, results, n_ex_data);
	for (int i = 0; i < n_result; i++) {
		ex_data_array[i] = ex_data_runtime_get_ex_data_by_container(bool_plugin_rt->ex_data_rt,
                                                                    (struct ex_container *)results[i].user_tag);
	}

	return n_result;
}

long long bool_plugin_runtime_update_err_count(void *bool_plugin_runtime)
{
    if (NULL == bool_plugin_runtime) {
        return 0;
    }

    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;
    return bool_plugin_rt->update_err_cnt;
}

void bool_plugin_runtime_scan_times_inc(void *bool_plugin_runtime, int thread_id)
{
    if (NULL == bool_plugin_runtime || thread_id < 0) {
        return;
    }

    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;
    alignment_int64_array_add(bool_plugin_rt->scan_times, thread_id, 1);
}

long long bool_plugin_runtime_scan_times(void *bool_plugin_runtime)
{
    if (NULL == bool_plugin_runtime) {
        return 0;
    }

    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;
    long long sum = alignment_int64_array_sum(bool_plugin_rt->scan_times,
                                              bool_plugin_rt->n_worker_thread);
    alignment_int64_array_reset(bool_plugin_rt->scan_times, bool_plugin_rt->n_worker_thread);

    return sum;
}