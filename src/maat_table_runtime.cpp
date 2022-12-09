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
#include "log/log.h"
#include "maat_utils.h"
#include "maat_table_runtime.h"
#include "uthash/uthash.h"
#include "maat_ex_data.h"
#include "adapter_hs.h"
#include "rcu_hash.h"
#include "IPMatcher.h"

#define MODULE_TABLE_RUNTIME	 module_name_str("maat.table_runtime")

#define MAAT_MAX_EXPR_ITEM_NUM	8

struct port_range {
    uint16_t min_port;
    uint16_t max_port;
};

struct ex_container_ctx {
    int table_id;
    void (*custom_data_free)(void *custom_data);
    struct ex_data_schema *ex_schema;
};

struct expr_runtime {
    enum hs_scan_mode scan_mode;
    struct adapter_hs *hs;
    struct adapter_hs_stream *hs_stream;
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
        //struct ip_plugin_runtime ip_rt;
        struct ip_plugin_runtime ip_plus_rt;
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

void ex_data_container_free(void *ctx, void *data)
{
    if (NULL == ctx || NULL == data) {
        return;
    }

    struct ex_container_ctx *container_ctx = (struct ex_container_ctx *)ctx;
    long argl = container_ctx->ex_schema->argl;
    void *argp = container_ctx->ex_schema->argp;

    struct ex_data_container *ex_container = (struct ex_data_container *)data;
    if (ex_container->ex_data != NULL && container_ctx->ex_schema->free_func != NULL) {
        container_ctx->ex_schema->free_func(container_ctx->table_id, &(ex_container->ex_data), argl, argp);
    }
    
    if (ex_container->custom_data != NULL && container_ctx->custom_data_free != NULL) {
        container_ctx->custom_data_free(ex_container->custom_data);
    }

    FREE(ex_container);
}

void expr_rule_free(and_expr_t *expr_rule)
{
    if (NULL == expr_rule) {
        return;
    }

    for (size_t i = 0; i < expr_rule->n_patterns; i++) {
        FREE(expr_rule->patterns[i].pat);
    }
}
void expr_ex_data_free(void *user_ctx, void *data)
{
    and_expr_t *expr_rule = (and_expr_t *)data;
    expr_rule_free(expr_rule);
    FREE(data);
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
        case TABLE_TYPE_IP_PLUS:
            table_rt->ip_plus_rt.ex_data_rt = ex_data_runtime_new(table_id, ex_data_container_free);
            break;
        case TABLE_TYPE_PLUGIN:
            table_rt->plugin_rt.ex_data_rt = ex_data_runtime_new(table_id, ex_data_container_free);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            table_rt->ip_plugin_rt.ex_data_rt = ex_data_runtime_new(table_id, ex_data_container_free);
            break;
        default:
            break;
    }

    return table_rt;
}

void table_runtime_free(struct table_runtime * table_rt)
{
    if (NULL == table_rt) {
        return;
    }

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

    FREE(table_rt);
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
    if (NULL == table_rt_mgr) {
        return;
    }

	for(size_t i = 0; i < table_rt_mgr->n_table_rt; i++) {
		table_runtime_free(table_rt_mgr->table_rt[i]);
		table_rt_mgr->table_rt[i] = NULL;
	}

	FREE(table_rt_mgr->table_rt);
	FREE(table_rt_mgr);
}

struct table_runtime *table_runtime_get(struct table_runtime_manager *table_rt_mgr, int table_id)
{
    if (NULL == table_rt_mgr || (table_id < 0) || (table_id >= MAX_TABLE_NUM)) {
        return NULL;
    }

    assert(table_id < (int)table_rt_mgr->n_table_rt);
	return table_rt_mgr->table_rt[table_id];
}

size_t table_runtime_rule_count(struct table_runtime *table_rt)
{
    if (NULL == table_rt) {
        return 0;
    }

    return table_rt->rule_num;
}

enum table_type table_runtime_get_type(struct table_runtime* table_rt)
{
    if (NULL == table_rt) {
        return TABLE_TYPE_MAX;
    }

    return table_rt->table_type;
}

int table_runtime_scan_string(struct table_runtime* table_rt, int thread_id, const char *data, size_t data_len, 
                              int result[], size_t *n_result)
{
    if (NULL == table_rt) {
        return -1;
    }

    return adapter_hs_scan(table_rt->expr_rt.hs, thread_id, data, data_len, result, n_result);
}

void table_runtime_stream_open(struct table_runtime *table_rt, int thread_id)
{
    if (NULL == table_rt) {
        return;
    }

    struct adapter_hs_stream *hs_stream = adapter_hs_stream_open(table_rt->expr_rt.hs, thread_id);
    table_rt->expr_rt.hs_stream = hs_stream;
}

int table_runtime_scan_stream(struct table_runtime *table_rt, const char *data, size_t data_len,
                              int result[], size_t *n_result)
{
    if (NULL == table_rt) {
        return -1;
    }

    return adapter_hs_scan_stream(table_rt->expr_rt.hs_stream, data, data_len, result, n_result);
}

void table_runtime_stream_close(struct table_runtime *table_rt)
{
    if (table_rt != NULL) {
        adapter_hs_stream_close(table_rt->expr_rt.hs_stream);
        table_rt->expr_rt.hs_stream = NULL;
    }
}

enum IP_TYPE ip_type_transform(enum ip_type type)
{
    if (type == IP_TYPE_V4) {
        return IPv4;
    } else {
        return IPv6;
    }
}

int table_runtime_scan_ip(struct table_runtime *table_rt, int thread_id, struct table_rt_2tuple *data,
                          int results[], size_t *n_result)
{
    if (NULL == table_rt) {
        return -1;
    }

    int i = 0;
    int n_hit_result = 0;
    struct scan_result scan_results[table_rt->rule_num] = {0};

    struct ip_data ip;
    ip.type = ip_type_transform(data->ip_type);
    if (ip.type == IPv4) {
        ip.ipv4 = data->ipv4;
    } else {
        memcpy(ip.ipv6, data->ipv6, sizeof(data->ipv6));
    }
  
    n_hit_result = ip_matcher_match(table_rt->ip_plus_rt.ip_matcher, &ip, scan_results, table_rt->rule_num);
    int index = 0;
    /* filter rule_id by port */
    for (i = 0; i < n_hit_result; i++) {
        struct port_range *port_range = (struct port_range *)scan_results[i].tag;
        if (data->port < port_range->min_port || data->port > port_range->max_port) {
            continue;
        }
        results[index++] = scan_results[i].rule_id;
    }
    *n_result = index;

    return 0;
}

void ip_plus_item_to_ip_rule(struct ip_plus_item *item, struct ip_rule *rule)
{
    struct port_range *sport_range = ALLOC(struct port_range, 1);
    if (4 == item->addr_type) {
        rule->type = IPv4;
        sport_range->min_port = item->ipv4.min_sport;
        sport_range->max_port = item->ipv4.max_sport;
    } else {
        rule->type = IPv6;
        sport_range->min_port = item->ipv6.min_sport;
        sport_range->max_port = item->ipv6.max_sport;
    }
    rule->rule_id = item->item_id;
    rule->user_tag = sport_range;
    rule->ipv4_rule.start_ip = item->ipv4.min_sip;
    rule->ipv4_rule.end_ip = item->ipv4.max_sip;
    memcpy(rule->ipv6_rule.start_ip, item->ipv6.min_sip, sizeof(item->ipv6.min_sip));
    memcpy(rule->ipv6_rule.end_ip, item->ipv6.max_sip, sizeof(item->ipv6.max_sip));
}

void ip_plugin_item_to_ip_rule(struct ip_plugin_item *item, struct ip_rule *rule)
{

}

enum pattern_type expr_type2pattern_type(enum expr_type expr_type)
{
    enum pattern_type pattern_type = PATTERN_TYPE_STR;

    switch (expr_type) {
        case EXPR_TYPE_STRING:
        case EXPR_TYPE_AND:
            break;
        case EXPR_TYPE_REGEX:
            pattern_type = PATTERN_TYPE_REG;
            break;
        default:
            break;
    }

    return pattern_type;
}

and_expr_t *expr_item_to_expr_rule(struct expr_item *expr_item, struct log_handle *logger)
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
                    log_error(logger, MODULE_TABLE_RUNTIME, "item_id:%d too many patterns", 
                                                            expr_item->item_id);
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
        expr_rule->patterns[i].type = expr_type2pattern_type(expr_item->expr_type);
    }
    expr_rule->n_patterns = sub_expr_cnt;
    
    return expr_rule;
}

void expr_runtime_update_row(struct expr_runtime *expr_rt, char *key, size_t key_len, 
                             and_expr_t *expr_rule, int is_valid, struct log_handle *logger)
{
    void *data = NULL;

    if (is_valid == 0) {
        //delete
        data = rcu_hash_find(expr_rt->htable, key, key_len);
        if (NULL == data) {
            log_error(logger, MODULE_TABLE_RUNTIME, "the key:%s not exist, so can't be deleted", key);
            return;
        }
        rcu_hash_del(expr_rt->htable, key, key_len);
    } else {
        //add
        data = rcu_hash_find(expr_rt->htable, key, key_len);
        if (data != NULL) {
            log_error(logger, MODULE_TABLE_RUNTIME, "the key:%s already exist, so can't be added", key);
            return;
        }
        and_expr_t *data = ALLOC(and_expr_t, 1);
        memcpy(data, expr_rule, sizeof(and_expr_t));
        for (size_t i = 0; i < expr_rule->n_patterns; i++) {
            data->patterns[i].pat = ALLOC(char, expr_rule->patterns[i].pat_len);
            memcpy(data->patterns[i].pat, expr_rule->patterns[i].pat, expr_rule->patterns[i].pat_len);
        }
        rcu_hash_add(expr_rt->htable, key, key_len, (void *)data);
    }
}

void ip_plus_runtime_update_row(struct ip_plugin_runtime *ip_plus_rt, struct table_schema *table_schema,
                           const char *row, char *key, size_t key_len, struct ip_plus_item *ip_plus_item, 
                           int is_valid, struct log_handle *logger)
{
    struct ex_data_container *ex_container = ALLOC(struct ex_data_container, 1);
    struct ex_data_runtime *ex_data_rt = ip_plus_rt->ex_data_rt;
    ex_container->ex_data = NULL;
    ex_container->custom_data = ip_plus_item;
    struct ex_container_ctx *ctx = ALLOC(struct ex_container_ctx, 1);
    ctx->custom_data_free = free;
    ex_data_runtime_set_ex_container_ctx(ex_data_rt, ctx);
    
    if (0 == is_valid) {
        // delete
        ex_data_runtime_del_ex_container(ex_data_rt, key, key_len, logger);
    } else {
        // add
        ex_data_runtime_add_ex_container(ip_plus_rt->ex_data_rt, key, key_len, ex_container);
    }
}

void plugin_runtime_update_row(struct plugin_runtime *plugin_rt, struct table_schema *table_schema, 
                               const char *row, char *key, size_t key_len, int is_valid,
                               struct log_handle *logger)
{
    struct ex_data_container *ex_container = ALLOC(struct ex_data_container, 1);
    ex_container->ex_data = ex_data_runtime_row2ex_data(plugin_rt->ex_data_rt, row, key, key_len);
    int set_flag = plugin_table_schema_ex_data_schema_flag(table_schema);
    size_t cb_count = plugin_table_schema_callback_count(table_schema);

    /* already set plugin_table_schema's ex_data_schema */
    if (1 == set_flag) {
        if (is_valid == 0) {
            // delete
            ex_data_runtime_del_ex_container(plugin_rt->ex_data_rt, key, key_len, logger);
        } else {
            // add
            ex_data_runtime_add_ex_container(plugin_rt->ex_data_rt, key, key_len, ex_container);
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
                                  const char *row, char *key, size_t key_len, struct ip_plugin_item *ip_plugin_item, 
                                  int is_valid, struct log_handle *logger)
{
    struct ex_data_container *ex_container = ALLOC(struct ex_data_container, 1);
    struct ex_data_runtime *ex_data_rt = ip_plugin_rt->ex_data_rt;
    ex_container->ex_data = ex_data_runtime_row2ex_data(ex_data_rt, row, key, key_len);
    ex_container->custom_data = ip_plugin_item;
    struct ex_container_ctx *ctx = ex_data_runtime_get_ex_container_ctx(ex_data_rt);
    ctx->custom_data_free = free;

    int set_flag = plugin_table_schema_ex_data_schema_flag(table_schema);

    if (1 == set_flag) {
        if (0 == is_valid) {
            //delete
            ex_data_runtime_del_ex_container(ex_data_rt, key, key_len, logger);
        } else {
            //add
            ex_data_runtime_add_ex_container(ip_plugin_rt->ex_data_rt, key, key_len, ex_container);
        }
    } else {
        ex_data_runtime_cache_row_put(ip_plugin_rt->ex_data_rt, row);
    }
}

void table_runtime_update(struct table_runtime *table_rt, struct table_schema *table_schema, 
                          const char *row, struct table_item *table_item, struct log_handle *logger)
{
    int is_valid = -1;
    char *key = NULL;
    size_t key_len = 0;
    and_expr_t *expr_rule = NULL;
    struct ip_plus_item *ip_plus_item = NULL;
    struct ip_plugin_item *ip_plugin_item = NULL;

    switch (table_rt->table_type) {
        case TABLE_TYPE_EXPR:
            is_valid = table_item->expr_item.is_valid;
            expr_rule = expr_item_to_expr_rule(&table_item->expr_item, logger);
            key = (char *)&(table_item->expr_item.item_id);
            expr_runtime_update_row(&(table_rt->expr_rt), key, sizeof(int), expr_rule, is_valid, logger);
            expr_rule_free(expr_rule);
            break;
        case TABLE_TYPE_IP_PLUS:
            is_valid = table_item->ip_plus_item.is_valid;
            ip_plus_item = ALLOC(struct ip_plus_item, 1);
            memcpy(ip_plus_item, &(table_item->ip_plus_item), sizeof(table_item->ip_plus_item));
            key = (char *)&(table_item->ip_plus_item.item_id);
            ip_plus_runtime_update_row(&(table_rt->ip_plus_rt), table_schema, row, key, sizeof(int), 
                                       ip_plus_item, is_valid, logger);
            break;
        case TABLE_TYPE_PLUGIN:
            is_valid = table_item->plugin_item.is_valid;
            key = table_item->plugin_item.key;
            key_len = table_item->plugin_item.key_len;
            plugin_runtime_update_row(&(table_rt->plugin_rt), table_schema, row, key, key_len, is_valid, logger);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            is_valid = table_item->ip_plugin_item.is_valid;
            ip_plugin_item = ALLOC(struct ip_plugin_item, 1);
            memcpy(ip_plugin_item, &(table_item->ip_plugin_item), sizeof(table_item->ip_plugin_item));
            key = (char *)&(table_item->ip_plugin_item.item_id);
            ip_plugin_runtime_update_row(&(table_rt->ip_plugin_rt), table_schema, row, key, sizeof(int), 
                                         ip_plugin_item, is_valid, logger);
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
    rule_cnt = rcu_hash_list_updating_data(expr_rt->htable, &ex_data_array);
    assert(rule_cnt == 0);
    
    FREE(rules);
    FREE(ex_data_array);

    return ret;
}

int ip_plus_runtime_commit(struct table_runtime *table_rt)
{
    struct ex_data_container **ex_container = NULL;
    struct ip_rule *rules = NULL;
    size_t rule_cnt = 0;
    int ret = 0;
    struct ip_plugin_runtime *ip_plus_rt = &(table_rt->ip_plus_rt);

    rule_cnt = ex_data_runtime_list_updating_ex_container(ip_plus_rt->ex_data_rt, &ex_container);
    rules = ALLOC(struct ip_rule, rule_cnt);

    for (size_t i = 0; i < rule_cnt; i++) {
        struct ip_plus_item *item = (struct ip_plus_item *)ex_container[i]->custom_data;
        ip_plus_item_to_ip_rule(item, &rules[i]);
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

    old_ip_matcher = ip_plus_rt->ip_matcher;
    ip_plus_rt->ip_matcher = new_ip_matcher;
    maat_garbage_bagging(table_rt->ref_garbage_bin, old_ip_matcher, (void (*)(void*))ip_matcher_free);
    ex_data_runtime_commit(ip_plus_rt->ex_data_rt);
    table_rt->rule_num = ex_data_runtime_ex_container_count(ip_plus_rt->ex_data_rt);

    FREE(rules);
    FREE(ex_container);

    return ret;
}

int plugin_runtime_commit(struct table_runtime *table_rt)
{
    ex_data_runtime_commit(table_rt->plugin_rt.ex_data_rt);
    table_rt->rule_num = ex_data_runtime_ex_container_count(table_rt->plugin_rt.ex_data_rt);

    return 0;
}

int ip_plugin_runtime_commit(struct table_runtime *table_rt)
{
    struct ex_data_container **ex_container = NULL;
    struct ip_rule *rules = NULL;
    size_t rule_cnt = 0;
    int ret = 0;
    struct ip_plugin_runtime *ip_plugin_rt = &(table_rt->ip_plugin_rt);

    rule_cnt = ex_data_runtime_list_updating_ex_container(ip_plugin_rt->ex_data_rt, &ex_container);
    rules = ALLOC(struct ip_rule, rule_cnt);

    for (size_t i = 0; i < rule_cnt; i++) {
        struct ip_plugin_item *item = (struct ip_plugin_item *)ex_container[i]->custom_data;
        ip_plugin_item_to_ip_rule(item, &rules[i]);
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
    table_rt->rule_num = ex_data_runtime_ex_container_count(ip_plugin_rt->ex_data_rt);

    FREE(rules);
    FREE(ex_container);

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
        case TABLE_TYPE_IP_PLUS:
            ip_plus_runtime_commit(table_rt);
            break;
        case TABLE_TYPE_PLUGIN:
            plugin_runtime_commit(table_rt);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ip_plugin_runtime_commit(table_rt);
            break;
        default:
            break;
    }
}

size_t table_runtime_cached_row_count(struct table_runtime* table_rt)
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

const char* table_runtime_get_cached_row(struct table_runtime* table_rt, size_t row_seq)
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

struct ex_data_runtime *table_runtime_get_ex_data_rt(struct table_runtime *table_rt)
{
    struct ex_data_runtime *ex_data_rt = NULL;

    switch (table_rt->table_type) {
        case TABLE_TYPE_IP_PLUS:
            ex_data_rt = table_rt->ip_plus_rt.ex_data_rt;
            break;
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

void table_runtime_commit_ex_data_schema(struct table_runtime *table_rt, struct table_schema *table_schema,
                                         struct log_handle *logger)
{
    struct ex_data_schema *ex_data_schema = plugin_table_schema_get_ex_data_schema(table_schema);
    struct ex_data_runtime *ex_data_rt = table_runtime_get_ex_data_rt(table_rt);
    ex_data_runtime_set_schema(ex_data_rt, ex_data_schema);
    struct ex_container_ctx *ctx = ALLOC(struct ex_container_ctx, 1);
    
    ctx->table_id = table_schema_get_table_id(table_schema);
    ctx->ex_schema = ex_data_schema;
    ex_data_runtime_set_ex_container_ctx(ex_data_rt, ctx);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const char *row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        switch (table_rt->table_type) {
            case TABLE_TYPE_PLUGIN:
                plugin_runtime_update_row(&(table_rt->plugin_rt), table_schema, row, NULL, 0, 1, logger);
                break;
            case TABLE_TYPE_IP_PLUGIN:
                ip_plugin_runtime_update_row(&(table_rt->ip_plugin_rt), table_schema, NULL, NULL, 0, NULL, 1, logger);
                break;
            default:
                break;
        }
    }
    ex_data_runtime_clear_row_cache(ex_data_rt);

    table_runtime_commit(table_rt, 0);
}
