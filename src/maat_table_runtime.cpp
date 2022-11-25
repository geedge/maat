/*
**********************************************************************************************
*	File: maat_table_runtime.cpp
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <hs/hs.h>

#include "utils.h"
#include "maat_utils.h"
#include "maat_table_runtime.h"
#include "uthash/uthash.h"
#include "maat_ex_data.h"
#include "adapter_hs.h"
#include "rcu_hash.h"
#include "IPMatcher.h"

#define MAAT_MAX_EXPR_ITEM_NUM	8

struct plugin_ex_data {
    void *data;
    void *user_data;
};

struct plugin_user_ctx {
    int table_id;
    struct ex_data_schema *ex_schema;
};

struct expr_runtime {
    enum scan_mode scan_mode;
    struct adapter_hs *hs;
    struct adapter_hs_stream *hs_stream;
    struct rcu_hash_table *htable;
};

struct ip_runtime {
    struct ip_matcher *ip_matcher;
    struct rcu_hash_table *htable;
};

struct plugin_runtime {
    uint64_t acc_line_num;
    struct ex_data_runtime *ex_data_rt;
};

struct ip_plugin_runtime {
	struct ip_matcher* ip_matcher;
    struct ex_data_runtime* ex_data_rt;
};

struct table_runtime {
    uint32_t rule_num;
    uint32_t updating_rule_num;
    enum table_type table_type;
    union {
        struct expr_runtime expr_rt;
        struct ip_runtime ip_rt;
        struct plugin_runtime plugin_rt;
        struct ip_plugin_runtime ip_plugin_rt;
    };

    struct maat_garbage_bin *ref_garbage_bin;
    //ex_data_rt
    //table相关指针
};

struct table_runtime_manager {
    struct table_runtime **table_rt;
    size_t n_table_rt;

    struct maat_garbage_bin *garbage_bin;
};

void plugin_ex_data_free(void *user_ctx, void *data)
{
    struct plugin_user_ctx *ctx = (struct plugin_user_ctx *)user_ctx;
    long argl = ctx->ex_schema->argl;
    void *argp = ctx->ex_schema->argp;
    ctx->ex_schema->free_func(ctx->table_id, &data, argl, argp);
}

void expr_ex_data_free(void *user_ctx, void *data)
{
    free(data);
}

struct table_runtime *table_runtime_new(struct table_schema *table_schema, int max_thread_num, struct maat_garbage_bin* bin)
{
    int table_id = table_schema_get_table_id(table_schema);
    struct table_runtime *table_rt = ALLOC(struct table_runtime, 1);
    table_rt->ref_garbage_bin = bin;
    table_rt->table_type = table_schema_get_table_type(table_schema);

    switch (table_rt->table_type) {
        case TABLE_TYPE_EXPR:
            table_rt->expr_rt.htable = rcu_hash_new(expr_ex_data_free);
            table_rt->expr_rt.scan_mode = expr_table_schema_get_scan_mode(table_schema);
            break;
        case TABLE_TYPE_PLUGIN:
            table_rt->plugin_rt.ex_data_rt = ex_data_runtime_new(table_id, plugin_ex_data_free);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            table_rt->ip_plugin_rt.ex_data_rt = ex_data_runtime_new(table_id, plugin_ex_data_free);
            break;
        default:
            break;
    }

    return table_rt;
}

void table_runtime_free(struct table_runtime * table_rt)
{
    switch (table_rt->table_type) {
        case TABLE_TYPE_EXPR:
            adapter_hs_destroy(table_rt->expr_rt.hs);
            rcu_hash_free(table_rt->expr_rt.htable);
            break;
        case TABLE_TYPE_PLUGIN:
            ex_data_runtime_free(table_rt->plugin_rt.ex_data_rt);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ip_matcher_free(table_rt->ip_plugin_rt.ip_matcher);
            ex_data_runtime_free(table_rt->ip_plugin_rt.ex_data_rt);
            break;
        default:
            break;
    }

    free(table_rt);
}

struct table_runtime_manager *
table_runtime_manager_create(struct table_schema_manager *table_schema_mgr, int max_thread_num, 
                             struct maat_garbage_bin* garbage_bin)
{
    if (NULL == table_schema_mgr) {
        return NULL;
    }

    struct table_runtime_manager *table_rt_mgr = ALLOC(struct table_runtime_manager, 1);
    table_rt_mgr->n_table_rt = table_schema_manager_get_size(table_schema_mgr);
    table_rt_mgr->table_rt = ALLOC(struct table_runtime *, table_rt_mgr->n_table_rt);

    for (size_t i = 0; i < table_rt_mgr->n_table_rt; i++) {
        struct table_schema *table_schema = table_schema_get(table_schema_mgr, i);
        if (NULL == table_schema) {
            continue;
        }
        table_rt_mgr->table_rt[i] = table_runtime_new(table_schema, max_thread_num, garbage_bin);
    }

    return table_rt_mgr;
}

void table_runtime_manager_destroy(struct table_runtime_manager *table_rt_mgr)
{
	for(size_t i = 0; i < table_rt_mgr->n_table_rt; i++) {
		table_runtime_free(table_rt_mgr->table_rt[i]);
		table_rt_mgr->table_rt[i] = NULL;
	}

	free(table_rt_mgr->table_rt);
	table_rt_mgr->table_rt = NULL;
	free(table_rt_mgr);
}

struct table_runtime *table_runtime_get(struct table_runtime_manager *table_rt_mgr, int table_id)
{
    assert(table_id < (int)table_rt_mgr->n_table_rt);
	return table_rt_mgr->table_rt[table_id];
}

size_t table_runtime_rule_count(struct table_runtime *table_rt)
{
    return table_rt->rule_num;
}

enum table_type table_runtime_get_type(struct table_runtime* table_rt)
{
    return table_rt->table_type;
}

int table_runtime_scan_string(struct table_runtime* table_rt, int thread_id, const char *data, size_t data_len, 
                              int result[], size_t *n_result)
{
    return adapter_hs_scan(table_rt->expr_rt.hs, thread_id, data, data_len, result, n_result);
}

void table_runtime_stream_open(struct table_runtime *table_rt, int thread_id)
{
    struct adapter_hs_stream *hs_stream = adapter_hs_stream_open(table_rt->expr_rt.hs, thread_id);
    table_rt->expr_rt.hs_stream = hs_stream;
}

int table_runtime_scan_stream(struct table_runtime *table_rt, const char *data, size_t data_len,
                              int result[], size_t *n_result)
{
    return adapter_hs_scan_stream(table_rt->expr_rt.hs_stream, data, data_len, result, n_result);
}

void table_runtime_stream_close(struct table_runtime *table_rt)
{
    adapter_hs_stream_close(table_rt->expr_rt.hs_stream);
    table_rt->expr_rt.hs_stream = NULL;
}

struct ip_rule *ip_plugin_item_to_ip_rule(struct ip_plugin_item *ip_plugin_item)
{
    return NULL;
}

and_expr_t *expr_item_to_expr_rule(struct expr_item *expr_item)
{
    size_t i = 0;
    size_t sub_expr_cnt = 0;
    char *pos = NULL;
    char *saveptr = NULL;
    char *sub_key_array[MAAT_MAX_EXPR_ITEM_NUM];
    and_expr_t *expr_rule = ALLOC(and_expr_t, 1);

    switch (expr_item->expr_type) {
        case EXPR_TYPE_AND:
        case EXPR_TYPE_REGEX:
            for (i = 0, pos = expr_item->keywords; ; i++, pos = NULL) {
                char *tmp = strtok_r_esc(pos, '&', &saveptr);
                if (NULL == tmp) {
                    break;
                }

                if (i >= MAAT_MAX_EXPR_ITEM_NUM) {
                    fprintf(stderr, "item_id:%d too many patterns", expr_item->item_id);
                    return NULL;
                }

                sub_key_array[i] = tmp;
                if (expr_item->expr_type == EXPR_TYPE_REGEX) {
                    sub_key_array[i] = str_unescape_and(sub_key_array[i]);
                } else {
                    sub_key_array[i] = str_unescape(sub_key_array[i]);
                }
            }
            sub_expr_cnt = i;
            break;
        case EXPR_TYPE_STRING:
            sub_expr_cnt = 1;
            sub_key_array[0] = expr_item->keywords;
            sub_key_array[0] = str_unescape(sub_key_array[0]);
            break;
        default:
            break;
    }

    for (i = 0; i < sub_expr_cnt; i++) {
        expr_rule->expr_id = expr_item->item_id;
        expr_rule->patterns[i].pat = ALLOC(char, strlen(sub_key_array[i]));
        memcpy(expr_rule->patterns[i].pat, sub_key_array[i], strlen(sub_key_array[i]));
        expr_rule->patterns[i].pat_len = strlen(sub_key_array[i]);
        expr_rule->patterns[i].type = expr_item->expr_type;
    }
    expr_rule->n_patterns = sub_expr_cnt;
    
    return expr_rule;
}

void expr_runtime_update_row(struct expr_runtime *expr_rt, char *key, size_t key_len, 
                             and_expr_t *expr_rule, int is_valid)
{
    void *data = NULL;

    if (is_valid == 0) {
        //delete
        data = rcu_hash_find(expr_rt->htable, key, key_len);
        if (NULL == data) {
            //log_error("the key:%s not exist, so can't be deleted.");
            return;
        }
        rcu_hash_del(expr_rt->htable, key, key_len);
    } else {
        //add
        data = rcu_hash_find(expr_rt->htable, key, key_len);
        if (data != NULL) {
            //log_error("the key:%s already exist, so can't be added.");
            return;
        }
        and_expr_t *data = ALLOC(and_expr_t, 1);
        memcpy(data, expr_rule, sizeof(and_expr_t));
        rcu_hash_add(expr_rt->htable, key, key_len, (void *)data);
    }
}

void plugin_runtime_update_row(struct plugin_runtime *plugin_rt, struct table_schema *table_schema, 
                               const char *row, char *key, size_t key_len, int is_valid)
{
    struct plugin_ex_data *ex_data = ALLOC(struct plugin_ex_data, 1);
    ex_data->data = ex_data_runtime_row2ex_data(plugin_rt->ex_data_rt, row, key, key_len);
    int set_flag = plugin_table_schema_ex_data_schema_flag(table_schema);
    size_t cb_count = plugin_table_schema_callback_count(table_schema);

    /* already set plugin_table_schema's ex_data_schema */
    if (1 == set_flag) {
        if (is_valid == 0) {
            // delete
            ex_data_runtime_del_ex_data(plugin_rt->ex_data_rt, key, key_len);
        } else {
            // add
            ex_data_runtime_add_ex_data(plugin_rt->ex_data_rt, key, key_len, (void *)ex_data);
        }
    }

    /* plugin table schema has callback */
    if (cb_count > 0) {
        plugin_table_schema_all_cb_update(table_schema, row);
    }
    
    if ((0 == set_flag) && (0 == cb_count)) {
        ex_data_runtime_cache_row_put(plugin_rt->ex_data_rt, row);
    }

    plugin_rt->acc_line_num++;
}

void ip_plugin_runtime_update_row(struct ip_plugin_runtime *ip_plugin_rt, struct table_schema *table_schema,
                                  const char *row, char *key, size_t key_len, 
                                  struct ip_rule *ip_rule, int is_valid)
{
    struct plugin_ex_data *ex_data = ALLOC(struct plugin_ex_data, 1);
    struct ex_data_runtime *ex_data_rt = ip_plugin_rt->ex_data_rt;
    ex_data->data = ex_data_runtime_row2ex_data(ex_data_rt, row, key, key_len);
    ex_data->user_data = ip_rule;
    int set_flag = plugin_table_schema_ex_data_schema_flag(table_schema);

    if (1 == set_flag) {
        if (0 == is_valid) {
            //delete
            ex_data_runtime_del_ex_data(ex_data_rt, key, key_len);
        } else {
            //add
            ex_data_runtime_add_ex_data(ip_plugin_rt->ex_data_rt, key, key_len, ex_data);
        }
    } else {
        ex_data_runtime_cache_row_put(ip_plugin_rt->ex_data_rt, row);
    }
    
}

void table_runtime_update(struct table_runtime *table_rt, struct table_schema *table_schema, const char *row, struct table_item *table_item)
{
    int is_valid = -1;
    char *key = NULL;
    size_t key_len = 0;
    and_expr_t *expr_rule = NULL;
    struct ip_rule *ip_rule = NULL;

    switch (table_rt->table_type) {
        case TABLE_TYPE_EXPR:
            is_valid = table_item->expr_item.is_valid;
            expr_rule = expr_item_to_expr_rule(&table_item->expr_item);
            key = (char *)&(table_item->expr_item.item_id);
            expr_runtime_update_row(&(table_rt->expr_rt), key, sizeof(int), expr_rule, is_valid);
            free(expr_rule);
            break;
        case TABLE_TYPE_PLUGIN:
            is_valid = table_item->plugin_item.is_valid;
            key = table_item->plugin_item.key;
            key_len = table_item->plugin_item.key_len;
            plugin_runtime_update_row(&(table_rt->plugin_rt), table_schema, row, key, key_len, is_valid);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            is_valid = table_item->ip_plugin_item.is_valid;
            ip_rule = ip_plugin_item_to_ip_rule(&table_item->ip_plugin_item);
            key = (char *)&(table_item->ip_plugin_item.item_id);
            ip_plugin_runtime_update_row(&(table_rt->ip_plugin_rt), table_schema, row, key, sizeof(int), ip_rule, is_valid);
            free(ip_rule);
            break;
        default:
            break;
    }

    if (is_valid == 0) {
        table_rt->rule_num--;
    } else {
        table_rt->rule_num++;
    }
}

int expr_runtime_commit(struct table_runtime *table_rt, size_t nr_worker_thread)
{
    struct expr_runtime *expr_rt = &(table_rt->expr_rt);
    void **ex_data_array = NULL;
    and_expr_t *rules = NULL;
    size_t rule_cnt = 0;
    int ret = 0;

    rule_cnt = rcu_hash_list_updating_data(expr_rt->htable, &ex_data_array);
    rules = ALLOC(and_expr_t, rule_cnt);

    for (size_t i = 0; i < rule_cnt; i++) {
        rules[i] = *(and_expr_t *)ex_data_array[i];
    }

    struct adapter_hs *new_adapter_hs = NULL;
    struct adapter_hs *old_adapter_hs = NULL;
    if (rule_cnt > 0) {
        new_adapter_hs = adapter_hs_initialize(expr_rt->scan_mode, nr_worker_thread, rules, rule_cnt);
        if (NULL == new_adapter_hs) {
            ret = -1;
        }
    }

    old_adapter_hs = expr_rt->hs;
    expr_rt->hs = new_adapter_hs;

    maat_garbage_bagging(table_rt->ref_garbage_bin, old_adapter_hs, (void (*)(void*))adapter_hs_destroy);
    rcu_hash_commit(expr_rt->htable);
    table_rt->rule_num = rcu_hash_count(expr_rt->htable);

    free(rules);
    free(ex_data_array);

    return ret;
}

int plugin_runtime_commit(struct table_runtime *table_rt)
{
    ex_data_runtime_commit(table_rt->plugin_rt.ex_data_rt);
    table_rt->rule_num = ex_data_runtime_ex_data_count(table_rt->plugin_rt.ex_data_rt);

    return 0;
}

int ip_plugin_runtime_commit(struct table_runtime *table_rt)
{
    struct plugin_ex_data **ex_data_array = NULL;
    struct ip_rule *rules = NULL;
    size_t rule_cnt = 0;
    int ret = 0;
    struct ip_plugin_runtime *ip_plugin_rt = &(table_rt->ip_plugin_rt);

    rule_cnt = ex_data_runtime_list_updating_ex_data(ip_plugin_rt->ex_data_rt, (void ***)&ex_data_array);
    rules = ALLOC(struct ip_rule, rule_cnt);

    for (size_t i = 0; i < rule_cnt; i++) {
        rules[i] = *(struct ip_rule *)ex_data_array[i]->user_data;
    }

    struct ip_matcher *new_ip_matcher = NULL;
    struct ip_matcher *old_ip_matcher = NULL;
    size_t mem_used = 0;

    if (rule_cnt > 0) {
        new_ip_matcher = ip_matcher_new(rules, rule_cnt, &mem_used);
        if (NULL == new_ip_matcher) {
            ret = -1;
        }
    }

    old_ip_matcher = ip_plugin_rt->ip_matcher;
    ip_plugin_rt->ip_matcher = new_ip_matcher;
    maat_garbage_bagging(table_rt->ref_garbage_bin, old_ip_matcher, (void (*)(void*))ip_matcher_free);
    ex_data_runtime_commit(ip_plugin_rt->ex_data_rt);
    table_rt->rule_num = ex_data_runtime_ex_data_count(ip_plugin_rt->ex_data_rt);

    free(rules);
    free(ex_data_array);

    return ret;
}

int expr_runtime_updating_flag(struct expr_runtime *expr_rt)
{
    return rcu_hash_updating_flag(expr_rt->htable);
}

int plugin_runtime_updating_flag(struct plugin_runtime *plugin_rt)
{
    return ex_data_runtime_updating_flag(plugin_rt->ex_data_rt);
}

int ip_plugin_runtime_updating_flag(struct ip_plugin_runtime *ip_plugin_rt)
{
    return ex_data_runtime_updating_flag(ip_plugin_rt->ex_data_rt);
}

int table_runtime_updating_flag(struct table_runtime *table_rt)
{
    int updating_flag = 0;

    switch (table_rt->table_type) {
    case TABLE_TYPE_EXPR:
        updating_flag = expr_runtime_updating_flag(&(table_rt->expr_rt));
        break;
    case TABLE_TYPE_PLUGIN:
        updating_flag = plugin_runtime_updating_flag(&(table_rt->plugin_rt));
        break;
    case TABLE_TYPE_IP_PLUGIN:
        updating_flag = ip_plugin_runtime_updating_flag(&(table_rt->ip_plugin_rt));
        break;
    default:
        break;
    }

    return updating_flag;
}

void table_runtime_commit(struct table_runtime *table_rt, size_t nr_worker_thread)
{
    switch (table_rt->table_type) {
        case TABLE_TYPE_EXPR:
            expr_runtime_commit(table_rt, nr_worker_thread);
            break;
        case TABLE_TYPE_PLUGIN:
            plugin_runtime_commit(table_rt);
        case TABLE_TYPE_IP_PLUGIN:
            ip_plugin_runtime_commit(table_rt);
            break;
        default:
            break;
    }
}

size_t plugin_table_runtime_cached_row_count(struct table_runtime* table_rt)
{
    size_t row_count = 0;
    struct ex_data_runtime *ex_data_rt = NULL;

    switch (table_rt->table_type) {
        case TABLE_TYPE_IP_PLUGIN:
            ex_data_rt = table_rt->ip_plugin_rt.ex_data_rt;
            break;
        default:
            break;
    }
    row_count = ex_data_runtime_cached_row_count(ex_data_rt);

    return row_count;
}

const char* plugin_table_runtime_get_cached_row(struct table_runtime* table_rt, size_t row_seq)
{
    const char *line = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    switch (table_rt->table_type) {
        case TABLE_TYPE_IP_PLUGIN:
            ex_data_rt = table_rt->ip_plugin_rt.ex_data_rt;
            break;
        default:
            break;
    }
    line = ex_data_runtime_cached_row_get(ex_data_rt, row_seq);

    return line;
}

void *plugin_table_runtime_get_ex_data(struct table_runtime *table_rt, struct table_schema *table_schema, 
                                        const char *key, size_t key_len)
{
    void *ex_data = NULL;
    int set_flag = plugin_table_schema_ex_data_schema_flag(table_schema);
    if (0 == set_flag) {
        assert(0);
		return NULL;
    }

    enum table_type table_type = table_schema_get_table_type(table_schema);
    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            ex_data = ex_data_runtime_get_ex_data(table_rt->plugin_rt.ex_data_rt, key, key_len);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            break;
        default:
            break;
    }
    
    return ex_data;
}

struct ex_data_runtime *table_runtime_get_ex_data_rt(struct table_runtime *table_rt)
{
    struct ex_data_runtime *ex_data_rt = NULL;

    switch (table_rt->table_type) {
        case TABLE_TYPE_PLUGIN:
            ex_data_rt = table_rt->plugin_rt.ex_data_rt;
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ex_data_rt = table_rt->ip_plugin_rt.ex_data_rt;
            break;
        default:
            break;
    }

    return ex_data_rt;
}

void plugin_table_runtime_commit_ex_data_schema(struct table_runtime *table_rt, struct table_schema *table_schema)
{
    struct ex_data_schema *ex_data_schema = plugin_table_schema_get_ex_data_schema(table_schema);
    struct ex_data_runtime *ex_data_rt = table_runtime_get_ex_data_rt(table_rt);
    ex_data_runtime_set_schema(ex_data_rt, ex_data_schema);
    struct plugin_user_ctx *user_ctx = ALLOC(struct plugin_user_ctx, 1);
    
    user_ctx->table_id = table_schema_get_table_id(table_schema);
    user_ctx->ex_schema = ex_data_schema;
    ex_data_runtime_set_user_ctx(ex_data_rt, user_ctx);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const char *row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        switch (table_rt->table_type) {
            case TABLE_TYPE_PLUGIN:
                plugin_runtime_update_row(&(table_rt->plugin_rt), table_schema, row, NULL, 0, 1);
                break;
            case TABLE_TYPE_IP_PLUGIN:
                ip_plugin_runtime_update_row(&(table_rt->ip_plugin_rt), table_schema, NULL, NULL, 0, NULL, 1);
                break;
            default:
                break;
        }
    }
    ex_data_runtime_clear_row_cache(ex_data_rt);

    table_runtime_commit(table_rt, 0);
}
