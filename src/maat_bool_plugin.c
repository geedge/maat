/*
**********************************************************************************************
*	File: maat_bool_plugin.cpp
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "maat_bool_plugin.h"
#include "bool_matcher.h"
#include "maat_ex_data.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "maat_garbage_collection.h"

#define MODULE_BOOL_PLUGIN	 module_name_str("maat.bool_plugin")

struct bool_plugin_schema {
    int item_id_column;
    int bool_expr_column;
    int rule_tag_column;
    struct ex_data_schema *ex_schema;
    int table_id;
    struct table_manager *ref_tbl_mgr;

    unsigned long long update_err_cnt;
    unsigned long long unmatch_tag_cnt;
};

struct bool_plugin_runtime {
    struct bool_matcher *matcher;
    struct ex_data_runtime *ex_data_rt;

    uint32_t rule_num;
    uint32_t updating_rule_num;

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

/* bool plugin schema API */
void *bool_plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger)
{
    size_t read_cnt = 0;
    struct bool_plugin_schema *schema = ALLOC(struct bool_plugin_schema, 1);

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
   if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (NULL == item || item->type != cJSON_Object) {
        log_error(logger, MODULE_BOOL_PLUGIN, 
                  "table %s has no custom column", table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->item_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "bool_expr");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->bool_expr_column = custom_item->valueint;
        read_cnt++;
    }

    // rule_tag is optional
    custom_item = cJSON_GetObjectItem(item, "rule_tag");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->rule_tag_column = custom_item->valueint;
    }

    schema->ref_tbl_mgr = tbl_mgr;

    if (read_cnt < 3) {
        goto error;
    }
    
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
    struct bool_plugin_schema *schema = (struct bool_plugin_schema *)bool_plugin_schema;
    if (schema->ex_schema != NULL) {
        ex_data_schema_free(schema->ex_schema);
        schema->ex_schema = NULL;
    }

    FREE(schema);
}

/* ip plugin table ex data API */
struct ex_data_schema *bool_plugin_table_get_ex_data_schema(void *bool_plugin_schema)
{
    if (NULL == bool_plugin_schema) {
        return NULL;
    }

    struct bool_plugin_schema *schema = (struct bool_plugin_schema *)bool_plugin_schema;

    return schema->ex_schema;
}

int bool_plugin_table_set_ex_data_schema(void *bool_plugin_schema, 
                                         maat_ex_new_func_t *new_func,
							             maat_ex_free_func_t *free_func,
							             maat_ex_dup_func_t *dup_func,
							             long argl, void *argp,
                                         struct log_handle *logger)
{
    if (NULL == bool_plugin_schema) {
        return -1;
    }

    struct bool_plugin_schema *schema = (struct bool_plugin_schema *)bool_plugin_schema;
    if (schema->ex_schema != NULL) {
        assert(0);
        log_error(logger, MODULE_BOOL_PLUGIN,
                  "Error: %s, EX data schema already registed", __FUNCTION__);
        return -1;
    }

    schema->ex_schema = ex_data_schema_new(new_func, free_func, dup_func, argl, argp);

    return 0;
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

size_t ull_dedup(unsigned long long item_ids[], size_t n_item)
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

void *bool_plugin_runtime_new(void *bool_plugin_schema, int max_thread_num,
                              struct maat_garbage_bin *garbage_bin,
                              struct log_handle *logger)
{
    if (NULL == bool_plugin_schema) {
        return NULL;
    }

    struct bool_plugin_schema *schema = (struct bool_plugin_schema *)bool_plugin_schema;
    struct bool_plugin_runtime *bool_plugin_rt = ALLOC(struct bool_plugin_runtime, 1);

    bool_plugin_rt->ex_data_rt = ex_data_runtime_new(schema->table_id, ex_data_container_free, 
                                                     logger);
    bool_plugin_rt->ref_garbage_bin = garbage_bin;
    bool_plugin_rt->logger = logger;

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

    FREE(bool_plugin_rt);
}

int bool_plugin_runtime_update_row(struct bool_plugin_runtime *bool_plugin_rt,
                                   const char *row, char *key, size_t key_len, 
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
        void *ex_data = ex_data_runtime_row2ex_data(ex_data_rt, row, key, key_len);
        struct ex_data_container *ex_container = ex_data_container_new(ex_data, (void *)expr);
        ret = ex_data_runtime_add_ex_container(ex_data_rt, key, key_len, ex_container);
        if (ret < 0) {
            return -1;
        }
    }

    return 0;
}

int bool_plugin_accept_tag_match(struct bool_plugin_schema *schema, const char *line,
                                 struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);

    if (schema->rule_tag_column > 0 && n_tag > 0) {
        int ret = get_column_pos(line, schema->rule_tag_column, 
                                 &column_offset, &column_len);
        if (ret < 0) {
            log_error(logger, MODULE_BOOL_PLUGIN,
                      "bool_plugin table(table_id:%d) has no rule_tag, line:%s",
                      schema->table_id, line);
            schema->update_err_cnt++;
            return TAG_MATCH_ERR;
        }

        if (column_len > 2) {
            char *tag_str = ALLOC(char, column_len + 1);
            memcpy(tag_str, (line + column_offset), column_len);
            ret = table_manager_accept_tags_match(schema->ref_tbl_mgr, tag_str);
            FREE(tag_str);
            if (TAG_MATCH_ERR == ret) {
                log_error(logger, MODULE_BOOL_PLUGIN,
                          "bool_plugin table(table_id:%d) has invalid tag format, line:%s",
                          schema->table_id, line);
                schema->update_err_cnt++;
                return TAG_MATCH_ERR;
            }

            if (TAG_MATCH_UNMATCHED == ret) {
                schema->unmatch_tag_cnt++;
                return TAG_MATCH_UNMATCHED;
            }
        }
    }

    return TAG_MATCH_MATCHED;
}

struct bool_expr *
bool_plugin_expr_new(const char *line, struct bool_plugin_schema *schema,
                     struct log_handle *logger)
{
    int ret = bool_plugin_accept_tag_match(schema, line, logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        return NULL;
    }

    size_t column_offset = 0;
    size_t column_len = 0;
    size_t n_item = 0;
    char expr_buffer[BUFSIZ] = {0};
    unsigned long long items[MAX_ITEMS_PER_BOOL_EXPR] = {0};
    char *token = NULL, *sub_token = NULL, *saveptr;
    struct bool_expr *bool_expr = ALLOC(struct bool_expr, 1);

    ret = get_column_pos(line, schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_BOOL_PLUGIN, 
                  "bool_plugin table(table_id:%d) line:%s has no item_id column",
                  schema->table_id, line);
        goto error;
    }
    bool_expr->expr_id = atoll(line + column_offset);

    ret = get_column_pos(line, schema->bool_expr_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_BOOL_PLUGIN, 
                  "bool_plugin table(table_id:%d) line:%s has no bool_expr column",
                  schema->table_id, line);
        goto error;
    }

    memcpy(expr_buffer, line + column_offset, column_len);
    for (token = expr_buffer; ; token = NULL) {
        sub_token = strtok_r(token, "&", &saveptr);
        if (NULL == sub_token) {
            break;
        }

        ret = sscanf(sub_token, "%llu", items + n_item);
        n_item++;
        if (ret != 1 || n_item > MAX_ITEMS_PER_BOOL_EXPR) {
            log_error(logger, MODULE_BOOL_PLUGIN, 
                      "bool_plugin table(table_id:%d) invalid format of bool_expr column, line:%s",
                      schema->table_id, line);
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

void bool_plugin_expr_free(struct bool_expr *expr)
{
    FREE(expr);
}

int bool_plugin_runtime_update(void *bool_plugin_runtime, void *bool_plugin_schema, 
                               const char *line, int valid_column)
{
    if (NULL == bool_plugin_runtime || NULL == bool_plugin_schema || 
        NULL == line) {
        return -1;
    }

    struct bool_expr *bool_expr = NULL;
    struct bool_plugin_schema *schema = (struct bool_plugin_schema *)bool_plugin_schema;
    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;
    long long item_id = get_column_value(line, schema->item_id_column);
    if (item_id < 0) {
        return -1;
    }

    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    }

    if (schema->ex_schema != NULL) {
        if (1 == is_valid) {
            // add
            bool_expr = bool_plugin_expr_new(line, schema, bool_plugin_rt->logger);
            if (NULL == bool_expr) {
                return -1;
            }
        }

        char *key = (char *)&item_id;
        int ret = bool_plugin_runtime_update_row(bool_plugin_rt, line, key,
                                                 sizeof(long long), bool_expr, is_valid);
        if (ret < 0) {
            if (bool_expr != NULL) {
                bool_plugin_expr_free(bool_expr);
            }
            return -1;
        } else {
            if (0 == is_valid) {
                bool_plugin_rt->rule_num--;
            } else {
                bool_plugin_rt->rule_num++;
            }
        }
    } else {
        //ex_schema not set
        ex_data_runtime_cache_row_put(bool_plugin_rt->ex_data_rt, line);
        bool_plugin_rt->rule_num = ex_data_runtime_cached_row_count(bool_plugin_rt->ex_data_rt);
    }

    return 0;
}

int bool_plugin_runtime_commit(void *bool_plugin_runtime, const char *table_name)
{
    if (NULL == bool_plugin_runtime) {
        return -1;
    }

    int ret = 0;
    struct ex_data_container **ex_container = NULL;
    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;
    struct ex_data_runtime *ex_data_rt = bool_plugin_rt->ex_data_rt;

    size_t expr_cnt = ex_data_runtime_list_updating_ex_container(ex_data_rt, &ex_container);
    if (0 == expr_cnt) {
        FREE(ex_container);
        return 0;
    }

    struct bool_expr *exprs = ALLOC(struct bool_expr, expr_cnt);

    for (size_t i = 0; i < expr_cnt; i++) {
        exprs[i] = *(struct bool_expr *)(struct bool_expr *)ex_container[i]->custom_data;
        assert(exprs[i].user_tag == ex_container[i] || NULL == exprs[i].user_tag);
        exprs[i].user_tag = ex_container[i];
    }

    struct bool_matcher *new_bool_matcher = NULL;
    struct bool_matcher *old_bool_matcher = NULL;
    size_t mem_used = 0;

    log_info(bool_plugin_rt->logger, MODULE_BOOL_PLUGIN,
             "table[%s] committing %zu bool_plugin rules for rebuilding bool_matcher engine", 
             table_name, expr_cnt);

    new_bool_matcher = bool_matcher_new(exprs, expr_cnt, &mem_used);
    if (NULL == new_bool_matcher) {
        log_error(bool_plugin_rt->logger, MODULE_BOOL_PLUGIN,
                  "table[%s] rebuild bool_matcher engine failed when update %zu bool_plugin rules",
                  table_name, expr_cnt);
        ret = -1;
    }

    old_bool_matcher = bool_plugin_rt->matcher;
    bool_plugin_rt->matcher = new_bool_matcher;
    maat_garbage_bagging(bool_plugin_rt->ref_garbage_bin, old_bool_matcher, 
                        (void (*)(void*))bool_matcher_free);
    ex_data_runtime_commit(ex_data_rt);

    FREE(exprs);
    FREE(ex_container);

    return ret;
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
    if (NULL == bool_plugin_runtime) {
        return -1;
    }

    struct bool_plugin_runtime *bool_plugin_rt = (struct bool_plugin_runtime *)bool_plugin_runtime;
    if (NULL == bool_plugin_rt->matcher) {
        log_info(bool_plugin_rt->logger, MODULE_BOOL_PLUGIN, 
                 "bool_matcher is NULL, can't get ex data");
        return 0;
    }

    struct bool_expr_match results[n_ex_data];
	memset(results, 0, sizeof(results));

    n_item = ull_dedup(item_ids, n_item);
	int n_result = bool_matcher_match(bool_plugin_rt->matcher, item_ids, n_item, results, n_ex_data);
	for (int i = 0; i < n_result; i++) {
		ex_data_array[i] = ex_data_runtime_get_ex_data_by_container(bool_plugin_rt->ex_data_rt, 
                                                                    (struct ex_data_container *)results[i].user_tag);
	}

	return n_result;
}
