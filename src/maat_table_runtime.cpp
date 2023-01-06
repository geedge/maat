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
#include "cJSON/cJSON.h"
#include "maat_utils.h"
#include "maat_table_schema.h"
#include "maat_table_runtime.h"
#include "uthash/uthash.h"
#include "maat_ex_data.h"
#include "adapter_hs.h"
#include "rcu_hash.h"
#include "IPMatcher.h"
#include "alignment.h"
#include "maat_hierarchy.h"
#include "maat_rule.h"
#include "igraph/igraph.h"
#include "maat_group.h"

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

struct compile_runtime {
    struct maat_hierarchy *hier;
};

struct group2compile_runtime {
    long long not_flag_group;
    struct compile_runtime *ref_compile_rt;
    struct group2group_runtime *ref_g2g_rt;
};

struct group2group_runtime {
    struct maat_group_topology *group_topo;
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
        struct compile_runtime compile_rt;
        struct group2compile_runtime g2c_rt;
        struct group2group_runtime g2g_rt;
        struct expr_runtime expr_rt;
        struct ip_plugin_runtime ip_plus_rt;
        struct plugin_runtime plugin_rt;
        struct ip_plugin_runtime ip_plugin_rt;
    };

    struct maat_garbage_bin *ref_garbage_bin;

    long long *scan_cnt;
    long long *hit_cnt;
    long long *stream_num;
    //ex_data_rt
    //table相关指针
};

struct table_runtime_manager {
    struct table_runtime **table_rt;
    size_t n_table_rt;

    struct maat_item *hash_item_by_id;
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

    FREE(expr_rule);
}
void expr_ex_data_free(void *user_ctx, void *data)
{
    and_expr_t *expr_rule = (and_expr_t *)data;
    expr_rule_free(expr_rule);
}

void fill_maat_rule(struct maat_rule *rule, const struct maat_rule_head *rule_head, 
                    const char *srv_def, int srv_def_len)
{
	memcpy(rule, rule_head, sizeof(struct maat_rule_head));
	memcpy(rule->service_defined, srv_def, MIN(srv_def_len, MAX_SERVICE_DEFINE_LEN));
}

void *rule_ex_data_new(const struct maat_rule_head *rule_head, const char *srv_def, const struct compile_ex_data_schema *ex_schema)
{
	void *ex_data = NULL;
	struct maat_rule rule;

	fill_maat_rule(&rule, rule_head, srv_def, strlen(srv_def)+1);
	ex_schema->new_func(ex_schema->idx, &rule, srv_def, &ex_data, ex_schema->argl, ex_schema->argp);
	
    return ex_data;
}

void rule_ex_data_free(const struct maat_rule_head *rule_head, const char *srv_def, void *ex_data, 
                       const struct compile_ex_data_schema *ex_schema)
{
	struct maat_rule rule;

    memset(&rule, 0, sizeof(rule));
	fill_maat_rule(&rule, rule_head, srv_def, strlen(srv_def)+1);
	ex_schema->free_func(ex_schema->idx, &rule, srv_def, ex_data, ex_schema->argl, ex_schema->argp);
}

void destroy_compile_rule(struct maat_compile_rule *compile_rule)
{
    size_t n_compile_ex_schema = table_schema_compile_rule_ex_data_schema_count(compile_rule->ref_table);
	assert(compile_rule->magic_num == COMPILE_RULE_MAGIC);

	for (size_t i = 0; i < n_compile_ex_schema; i++) {
        struct compile_ex_data_schema *compile_ex_schema = table_schema_get_compile_rule_ex_data_schema(compile_rule->ref_table, i);
		rule_ex_data_free(&(compile_rule->head), compile_rule->service_defined, compile_rule->ex_data+i, compile_ex_schema);
		void *ex_data = compile_rule->ex_data + 1;
        ex_data = NULL;
	}
	free(compile_rule->ex_data);

	compile_rule->is_valid = 0;
	compile_rule->declared_clause_num = -1;
	FREE(compile_rule->service_defined);
	FREE(compile_rule);
}

void maat_item_inner_free(struct maat_item_inner *item)
{
	assert(item->magic_num == ITEM_RULE_MAGIC);
	assert(item->expr_id_cnt == 0 || item->expr_id_cnt == (item->expr_id_ub - item->expr_id_lb + 1));
	item->magic_num = 0;
	FREE(item);
}

struct table_runtime *table_runtime_new(struct table_schema *table_schema, int max_thread_num, struct maat_garbage_bin *garbage_bin,
                                        struct log_handle *logger)
{
    struct ex_container_ctx *ex_container_ctx = NULL;
    int table_id = table_schema_get_table_id(table_schema);
    struct table_runtime *table_rt = ALLOC(struct table_runtime, 1);
    table_rt->ref_garbage_bin = garbage_bin;
    table_rt->table_type = table_schema_get_table_type(table_schema);

    switch (table_rt->table_type) {
        case TABLE_TYPE_COMPILE:
            table_rt->compile_rt.hier = maat_hierarchy_new(max_thread_num, garbage_bin, logger);
            maat_hierarchy_set_compile_user_data_free_func(table_rt->compile_rt.hier, (void (*)(void*))destroy_compile_rule);
	        maat_hierarchy_set_item_user_data_free_func(table_rt->compile_rt.hier, (void (*)(void*))maat_item_inner_free);
            break;
        case TABLE_TYPE_GROUP2COMPILE:
            break;
        case TABLE_TYPE_GROUP2GROUP:
            table_rt->g2g_rt.group_topo = maat_group_topology_new(logger);
            break;
        case TABLE_TYPE_EXPR:
            table_rt->expr_rt.htable = rcu_hash_new(expr_ex_data_free);
            table_rt->expr_rt.scan_mode = expr_table_schema_get_scan_mode(table_schema);
            break;
        case TABLE_TYPE_IP_PLUS:
            table_rt->ip_plus_rt.ex_data_rt = ex_data_runtime_new(table_id, ex_data_container_free);
            ex_container_ctx = ALLOC(struct ex_container_ctx, 1);
            ex_container_ctx->custom_data_free = free;
            //ex_data_runtime_set_ex_container_ctx(ex_data_rt, ex_container_ctx);
            break;
        case TABLE_TYPE_PLUGIN:
            table_rt->plugin_rt.ex_data_rt = ex_data_runtime_new(table_id, ex_data_container_free);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            table_rt->ip_plugin_rt.ex_data_rt = ex_data_runtime_new(table_id, ex_data_container_free);
            ex_container_ctx = ALLOC(struct ex_container_ctx, 1);
            ex_container_ctx->custom_data_free = free;
            //ex_data_runtime_set_ex_container_ctx(ex_data_rt, ex_container_ctx);
            break;
        default:
            break;
    }

    table_rt->scan_cnt = alignment_int64_array_alloc(max_thread_num);
    table_rt->hit_cnt = alignment_int64_array_alloc(max_thread_num);
    table_rt->stream_num = alignment_int64_array_alloc(max_thread_num);
    
    return table_rt;
}

void table_runtime_free(struct table_runtime *table_rt)
{
    if (NULL == table_rt) {
        return;
    }

    switch (table_rt->table_type) {
        case TABLE_TYPE_COMPILE:
            maat_hierarchy_free(table_rt->compile_rt.hier);
            break;
        case TABLE_TYPE_GROUP2COMPILE:
            break;
        case TABLE_TYPE_GROUP2GROUP:
            maat_group_topology_free(table_rt->group2group_rt.group_topo);
            break;
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
                             struct maat_garbage_bin *garbage_bin, struct log_handle *logger)
{
    if (NULL == table_schema_mgr) {
        return NULL;
    }

    struct table_runtime_manager *table_rt_mgr = ALLOC(struct table_runtime_manager, 1);
    table_rt_mgr->n_table_rt = table_schema_manager_get_size(table_schema_mgr);
    table_rt_mgr->table_rt = ALLOC(struct table_runtime *, table_rt_mgr->n_table_rt);

    size_t i = 0;
    for (i = 0; i < table_rt_mgr->n_table_rt; i++) {
        struct table_schema *table_schema = table_schema_get(table_schema_mgr, i);
        if (NULL == table_schema) {
            continue;
        }
        table_rt_mgr->table_rt[i] = table_runtime_new(table_schema, max_thread_num, garbage_bin, logger);
    }

    /* group2compile table_rt depends on associated compile table_rt,
       must make sure associated compile table_rt already exist */
    for (i = 0; i < table_rt_mgr->n_table_rt; i++) {
        struct table_runtime *table_rt = table_runtime_get(table_rt_mgr, i);
        if (NULL == table_rt) {
            continue;
        }

        enum table_type table_type = table_runtime_get_type(table_rt);
        if (table_type != TABLE_TYPE_GROUP2COMPILE) {
            continue;
        }

        struct table_schema *table_schema = table_schema_get(table_schema_mgr, i);
        int associated_compile_table_id = table_schema_get_associated_table_id(table_schema);
        struct table_runtime *compile_table_rt = table_runtime_get(table_rt_mgr, associated_compile_table_id);
        table_rt->group2compile_rt.ref_compile_rt = &compile_table_rt->compile_rt;
        assert(table_rt->group2compile_rt.ref_compile_rt != NULL);
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
        return TABLE_TYPE_INVALID;
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

int table_runtime_scan_ip(struct table_runtime *table_rt, int thread_id, struct ip_addr *scan_data,
                          struct scan_result *results, size_t *n_result, size_t n_result_array)
{
    if (NULL == table_rt) {
        return -1;
    }

    int i = 0;
    int n_hit_result = 0;
    struct scan_result scan_results[n_result_array] = {0};

    struct ip_data ip;
    ip.type = ip_type_transform(scan_data->ip_type);
    if (ip.type == IPv4) {
        ip.ipv4 = scan_data->ipv4;
    } else {
        memcpy(ip.ipv6, scan_data->ipv6, sizeof(scan_data->ipv6));
    }
    
    n_hit_result = ip_matcher_match(table_rt->ip_plus_rt.ip_matcher, &ip, scan_results, n_result_array);
    if (n_hit_result > (int)n_result_array) {
        n_hit_result = n_result_array;
    }

    int index = 0;
    for (i = 0; i < n_hit_result; i++) {
        results[index++].rule_id = scan_results[i].rule_id;
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
                    log_error(logger, MODULE_TABLE_RUNTIME, "expr item_id:%d too many patterns", 
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

struct maat_item_inner* maat_item_inner_new(int group_id, int item_id, int district_id)
{
	struct maat_item_inner *item = ALLOC(struct maat_item_inner, 1);
	item->magic_num = ITEM_RULE_MAGIC;
	item->item_id = item_id;
	item->group_id = group_id;
	item->district_id = district_id;

	return item;
}

void maat_item_inner_free(struct maat_item_inner *item)
{
	assert(item->magic_num == ITEM_RULE_MAGIC);
	assert(item->expr_id_cnt == 0 || item->expr_id_cnt == item->expr_id_ub - item->expr_id_lb + 1);
	item->magic_num = 0;

	free(item);
}

int compile_runtime_update_row(struct compile_runtime *compile_rt, const char *table_name, int compile_id,
                                struct maat_compile_rule *compile_rule, struct maat_garbage_bin *garbage_bin,
                                int is_valid, struct log_handle *logger)
{
    int ret = -1;
    struct maat_hierarchy *maat_hier = compile_rt->hier;

    if (0 == is_valid) {
        // delete
		struct maat_compile_rule *p_compile = (struct maat_compile_rule *)maat_hierarchy_compile_dettach_user_data(compile_rt->hier, compile_id);
		if (p_compile != NULL) {
			ret = maat_hierarchy_compile_remove(compile_rt->hier, compile_id);
			assert(ret == 0);
			maat_garbage_bagging(garbage_bin, p_compile, (void (*)(void*))destroy_compile_rule);
		}
	} else {
        // add
		ret = maat_hierarchy_compile_add(compile_rt->hier, compile_id, compile_rule->declared_clause_num, compile_rule);
		if (ret != 0) {
			log_info(logger, MODULE_TABLE_RUNTIME, "duplicate config of compile table %s compile_id %d",
							                        table_name, compile_id);
			destroy_compile_rule(compile_rule);
		}
	}

    return ret;
}

int group2compile_runtime_update_row(struct group2compile_runtime *g2c_rt,
                                      int compile_id, struct group2compile_item *g2c_item,
                                      int is_valid, struct log_handle *logger)
{
    int ret = -1;
    struct compile_runtime *compile_rt = g2c_rt->ref_compile_rt;
    struct group2group_runtime *g2g_rt = g2c_rt->ref_g2g_rt;
    struct maat_group *group = NULL;

    if (0 == is_valid) {
        /*TODO: by luis*/
        group = maat_group_topology_find_group(g2g_rt->group_topo, g2c_item->group_id);
        if (NULL == group) {
            log_error(logger, MODULE_TABLE_RUNTIME,
				      "Remove group %d from compile %d failed, group is not exisited.",
				      g2c_item->group_id, compile_id);
            return ret;
        }

		ret = maat_hierarchy_remove_group_from_compile(compile_rt->hier, g2c_item->group_id, g2c_item->virtual_table_id, 
                                                       g2c_item->not_flag, g2c_item->clause_index, g2c_item->compile_id);
		if (0 == ret) {
            group->ref_by_compile_cnt--;
			if (g2c_item->not_flag) {
				g2c_rt->not_flag_group--;
			}
		}
	} else {
        group = maat_group_topology_find_group(g2g_rt->group_topo, g2c_item->group_id);
        if (NULL == group) {
            group = maat_group_topology_add_group(g2g_rt->group_topo, g2c_item->group_id);
        }

		ret = maat_hierarchy_add_group_to_compile(compile_rt->hier, g2c_item->group_id, g2c_item->virtual_table_id, 
                                                  g2c_item->not_flag, g2c_item->clause_index, g2c_item->compile_id);
		if (0 == ret) {
            group->ref_by_compile_cnt++;
			if (g2c_item->not_flag) {
				g2c_rt->not_flag_group++;
			}
		}
	}

    return ret;
}

int group2group_runtime_update_row(struct group2group_runtime *g2g_rt, int group_id,
                                    struct group2group_item *g2g_item,
                                    int is_valid, struct log_handle *logger)
{
    int ret = -1;

    if (0 == is_valid) {
        //delete
		ret = maat_group_topology_add_group_to_group(g2g_rt->group_topo, group_id, g2g_item->superior_group_id);
	} else {
        //add
		ret = maat_group_topology_remove_group_from_group(g2g_rt->group_topo, group_id, g2g_item->superior_group_id);
	}

    return ret;
}

void expr_runtime_update_row(struct expr_runtime *expr_rt, char *key, size_t key_len, 
                             and_expr_t *expr_rule, int is_valid, struct log_handle *logger)
{
    void *data = NULL;

    if (0 == is_valid) {
        //delete
        data = rcu_hash_find(expr_rt->htable, key, key_len);
        if (NULL == data) {
            log_error(logger, MODULE_TABLE_RUNTIME, 
                      "the key of expr rule not exist, can't be deleted, expr_id:%d", expr_rule->expr_id);
            return;
        }
        rcu_hash_del(expr_rt->htable, key, key_len);
    } else {
        //add
        data = rcu_hash_find(expr_rt->htable, key, key_len);
        if (data != NULL) {
            log_error(logger, MODULE_TABLE_RUNTIME,
                      "the key of expr rule already exist, can't be added, expr_id:%d", expr_rule->expr_id);
            return;
        }
        rcu_hash_add(expr_rt->htable, key, key_len, (void *)expr_rule);
    }
}

void ip_plus_runtime_update_row(struct ip_plugin_runtime *ip_plus_rt, char *key, size_t key_len, 
                                struct ip_plus_item *ip_plus_item, int is_valid, 
                                struct log_handle *logger)
{
    struct ex_data_runtime *ex_data_rt = ip_plus_rt->ex_data_rt;
    
    if (0 == is_valid) {
        // delete
        ex_data_runtime_del_ex_container(ex_data_rt, key, key_len, logger);
    } else {
        // add
        struct ex_data_container *ex_container = ALLOC(struct ex_data_container, 1);
        ex_container->ex_data = NULL;
        ex_container->custom_data = ip_plus_item;
        ex_data_runtime_add_ex_container(ip_plus_rt->ex_data_rt, key, key_len, ex_container);
    }
}

void plugin_runtime_update_row(struct plugin_runtime *plugin_rt, struct table_schema *table_schema, 
                               const char *row, char *key, size_t key_len, int is_valid,
                               struct log_handle *logger)
{
    struct ex_data_container *ex_container = ALLOC(struct ex_data_container, 1);
    ex_container->ex_data = ex_data_runtime_row2ex_data(plugin_rt->ex_data_rt, row, key, key_len);
    int set_flag = table_schema_ex_data_schema_flag(table_schema);
    size_t cb_count = table_schema_callback_count(table_schema);

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
        table_schema_all_cb_update(table_schema, row);
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
    struct ex_data_runtime *ex_data_rt = ip_plugin_rt->ex_data_rt;
    int set_flag = table_schema_ex_data_schema_flag(table_schema);

    if (1 == set_flag) {
        if (0 == is_valid) {
            //delete
            ex_data_runtime_del_ex_container(ex_data_rt, key, key_len, logger);
        } else {
            //add
            struct ex_data_container *ex_container = ALLOC(struct ex_data_container, 1);
            ex_container->ex_data = ex_data_runtime_row2ex_data(ex_data_rt, row, key, key_len);
            ex_container->custom_data = ip_plugin_item;
            ex_data_runtime_add_ex_container(ip_plugin_rt->ex_data_rt, key, key_len, ex_container);
        }
    } else {
        ex_data_runtime_cache_row_put(ip_plugin_rt->ex_data_rt, row);
    }
}

struct maat_compile_rule *compile_item_to_compile_rule(struct compile_item *compile_item, struct table_schema *table_schema, struct log_handle *logger)
{
    struct maat_rule_head rule_head;
    rule_head.config_id = compile_item->compile_id;
    rule_head.service_id = compile_item->service_id;
    rule_head.action = compile_item->action;
    rule_head.do_blacklist = compile_item->do_blacklist;
    rule_head.do_log = compile_item->do_log;

    struct maat_compile_rule *p = ALLOC(struct maat_compile_rule, 1);
    
    p->magic_num = COMPILE_RULE_MAGIC;
    p->head = rule_head;
    p->declared_clause_num = compile_item->clause_num;
    p->ex_data = ALLOC(void *, MAX_COMPILE_EX_DATA_NUM);

    p->ref_table = table_schema;
    p->head.serv_def_len = strlen(compile_item->user_region);
    p->service_defined = ALLOC(char, p->head.serv_def_len);
    memcpy(p->service_defined, compile_item->user_region, p->head.serv_def_len);
    p->evaluation_order = compile_item->evaluation_order;

    size_t n_rule_ex_schema = table_schema_compile_rule_ex_data_schema_count(table_schema);
    for (size_t i = 0; i < n_rule_ex_schema; i++) {
        struct compile_ex_data_schema *ex_schema = table_schema_get_compile_rule_ex_data_schema(table_schema, i);
        p->ex_data[i] = rule_ex_data_new(&p->head, p->service_defined, ex_schema);
    }
    p->is_valid = 1;
    p->compile_id = compile_item->compile_id;
    pthread_rwlock_init(&p->rwlock, NULL);

    return p;
}

int compile_runtime_update(struct compile_runtime *compile_rt, struct compile_item *compile_item,
                           struct table_schema *table_schema, const char *table_name, 
                           struct maat_garbage_bin *garbage_bin, int is_valid, struct log_handle *logger)
{
    int ret = -1;

    if (NULL == compile_rt || NULL == compile_item) {
        return ret;
    }
    
    struct maat_compile_rule *compile_rule = NULL;
    if (1 == is_valid) {
        compile_rule = compile_item_to_compile_rule(compile_item, table_schema, logger);
        if (NULL == compile_rule) {
            log_error(logger, MODULE_TABLE_RUNTIME,
                      "transform compile table:%s item to compile_rule failed, compile_id:%d",
                      table_name, compile_item->compile_id);
            return ret;
        }
    }

    ret = compile_runtime_update_row(compile_rt, table_name, compile_item->compile_id, compile_rule, garbage_bin, is_valid, logger);
    return ret;
}

int group2compile_runtime_update(struct group2compile_runtime *g2c_rt, struct group2compile_item *g2c_item, 
                                  const char *table_name, int is_valid, struct log_handle *logger)
{
    int ret = -1;

    if (NULL == g2c_rt || NULL == g2c_item) {
        return ret;
    }

    ret = group2compile_runtime_update_row(g2c_rt, g2c_item->compile_id, g2c_item, is_valid, logger);
    return ret;
}

int group2group_runtime_update(struct group2group_runtime *g2g_rt, struct group2group_item *g2g_item, 
                                const char *table_name, int is_valid, struct log_handle *logger)
{
    int ret = -1;

    if (NULL == g2g_rt || NULL == g2g_item) {
        return ret;
    }

    ret = group2group_runtime_update_row(g2g_rt, g2g_item->group_id, g2g_item, is_valid, logger);
    return ret;
}

int expr_runtime_update(struct expr_runtime *expr_rt, struct expr_item *expr_item, 
                        const char *table_name, int is_valid, struct log_handle *logger)
{
    if (NULL == expr_rt || NULL == expr_item) {
        return -1;
    }

    /* add item to group */
    struct maat_item_inner *u_para = NULL;
    u_para = maat_item_inner_new(expr_item->group_id, expr_item->item_id, -1);
    int ret = maat_hierarchy_add_item_to_group(scanner->hier, expr_item->group_id, expr_item->item_id, u_para);
    if (ret != 0) {
		maat_item_inner_free(u_para);
		u_para = NULL;
		return -1;
	}

    and_expr_t *expr_rule = NULL;
    if (1 == is_valid) {
        expr_rule = expr_item_to_expr_rule(expr_item, logger);
        if (NULL == expr_rule) {
            log_error(logger, MODULE_TABLE_RUNTIME, "transform expr table:%s item to expr_rule failed, item_id:%d",
                      table_name, expr_item->item_id);
            return -1;
        }
    }

    char *key = (char *)&(expr_item->item_id);
    expr_runtime_update_row(expr_rt, key, sizeof(int), expr_rule, is_valid, logger);

    return 0;
}

int ip_plus_runtime_update(struct ip_plugin_runtime *ip_plus_rt, struct ip_plus_item *ip_plus_item, 
                            const char *table_name, int is_valid, struct log_handle *logger)
{
    if (NULL == ip_plus_rt || NULL == ip_plus_item) {
        return -1;
    }

    struct ip_plus_item *item = NULL;
    if (1 == is_valid) {
        item = ALLOC(struct ip_plus_item, 1);
        memcpy(item, ip_plus_item, sizeof(struct ip_plus_item));
    }
    
    char *key = (char *)&(ip_plus_item->item_id);
    ip_plus_runtime_update_row(ip_plus_rt, key, sizeof(int), ip_plus_item, is_valid, logger);

    return 0;
}

int plugin_runtime_update(struct plugin_runtime *plugin_rt, struct plugin_item *plugin_item,
                           struct table_schema *table_schema, const char *row, int is_valid, 
                           struct log_handle *logger)
{
    if (NULL == plugin_rt || NULL == plugin_item) {
        return -1;
    }

    char *key = plugin_item->key;
    size_t key_len = plugin_item->key_len;

    plugin_runtime_update_row(plugin_rt, table_schema, row, key, key_len, is_valid, logger);

    return 0;
}

int ip_plugin_runtime_update(struct ip_plugin_runtime *ip_plugin_rt, 
                              struct ip_plugin_item *ip_plugin_item, 
                              struct table_schema *table_schema, const char *row, 
                              int is_valid, struct log_handle *logger)
{
    if (NULL == ip_plugin_rt || NULL == ip_plugin_item) {
        return -1;
    }

    struct ip_plugin_item *item = NULL;
    if (1 == is_valid) {
        item = ALLOC(struct ip_plugin_item, 1);
        memcpy(item, ip_plugin_item, sizeof(struct ip_plugin_item));
    }

    char *key = (char *)&(ip_plugin_item->item_id);
    ip_plugin_runtime_update_row(ip_plugin_rt, table_schema, row, key, sizeof(int),
                                 item, is_valid, logger);

    return 0;
}

void table_runtime_update(struct table_runtime *table_rt, struct table_schema *table_schema, 
                          const char *row, struct table_item *table_item, struct log_handle *logger)
{
    int ret = -1;
    int is_valid = -1;
    const char *table_name = table_schema_get_updating_name(table_schema);
    int table_id = table_schema_get_table_id(table_schema);

    switch (table_rt->table_type) {
        case TABLE_TYPE_COMPILE:
            is_valid = table_item->compile_item.is_valid;
            ret = compile_runtime_update(&(table_rt->compile_rt), &(table_item->compile_item), table_schema, table_name, table_rt->ref_garbage_bin, is_valid, logger);
            break;
        case TABLE_TYPE_GROUP2COMPILE:
            is_valid = table_item->g2c_item.is_valid;
            ret = group2compile_runtime_update(&(table_rt->g2c_rt), &(table_item->g2c_item), table_name, is_valid, logger);
            break;
        case TABLE_TYPE_GROUP2GROUP:
            is_valid = table_item->g2g_item.is_valid;
            ret = group2group_runtime_update(&(table_rt->g2g_rt), &(table_item->g2g_item), table_name, is_valid, logger);
            break;
        case TABLE_TYPE_EXPR:
            is_valid = table_item->expr_item.is_valid;
            ret = expr_runtime_update(&(table_rt->expr_rt), &(table_item->expr_item), table_name, is_valid, logger);
            break;
        case TABLE_TYPE_IP_PLUS:
            is_valid = table_item->ip_plus_item.is_valid;
            ret = ip_plus_runtime_update(&(table_rt->ip_plus_rt), &(table_item->ip_plus_item), table_name, is_valid, logger);
            break;
        case TABLE_TYPE_PLUGIN:
            is_valid = table_item->plugin_item.is_valid;
            ret = plugin_runtime_update(&(table_rt->plugin_rt), &(table_item->plugin_item), table_schema, row, is_valid, logger);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            is_valid = table_item->ip_plugin_item.is_valid;
            ret = ip_plugin_runtime_update(&(table_rt->ip_plugin_rt), &(table_item->ip_plugin_item), table_schema, row, is_valid, logger);
            break;
        default:
            break;
    }

    if (ret < 0) {
        return;
    }

    if (is_valid == 0) {
        table_rt->rule_num--;
    } else {
        table_rt->rule_num++;
    }
}

int compile_runtime_commit(struct table_runtime *table_rt, long long version, struct log_handle *logger)
{
    int ret = -1;

    ret = maat_hierarchy_rebuild(table_rt->compile_rt.hier);
    if (ret != 0) {
        log_error(logger, MODULE_TABLE_RUNTIME, "version %lld hierarchy rebuild failed.",
                                                version);
        return -1;
    } else {
        log_info(logger, MODULE_TABLE_RUNTIME, "version %lld hierarchy rebuild success.",
                                                version);
        return 0;
    }
}

int expr_runtime_commit(struct table_runtime *table_rt, size_t nr_worker_thread,
                        struct log_handle *logger)
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
        log_info(logger, MODULE_TABLE_RUNTIME, 
                 "committing %zu expr rules for rebuilding adapter_hs engine", rule_cnt);
        new_adapter_hs = adapter_hs_initialize(expr_rt->scan_mode, nr_worker_thread, rules, rule_cnt);
        if (NULL == new_adapter_hs) {
            log_error(logger, MODULE_TABLE_RUNTIME, 
                      "rebuild adapter_hs engine failed when update %zu expr rules", rule_cnt);
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

int ip_plus_runtime_commit(struct table_runtime *table_rt, struct log_handle *logger)
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
        log_info(logger, MODULE_TABLE_RUNTIME, 
                 "committing %zu ip_plus rules for rebuilding ip_matcher engine", rule_cnt);
        new_ip_matcher = ip_matcher_new(rules, rule_cnt, &mem_used);
        if (NULL == new_ip_matcher) {
            log_error(logger, MODULE_TABLE_RUNTIME, 
                      "rebuild ip_matcher engine failed when update %zu ip_plus rules", rule_cnt);
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

int ip_plugin_runtime_commit(struct table_runtime *table_rt, struct log_handle *logger)
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
         log_info(logger, MODULE_TABLE_RUNTIME, 
                 "committing %zu ip_plugin rules for rebuilding ip_matcher engine", rule_cnt);
        new_ip_matcher = ip_matcher_new(rules, rule_cnt, &mem_used);
        if (NULL == new_ip_matcher) {
            log_error(logger, MODULE_TABLE_RUNTIME, 
                      "rebuild ip_matcher engine failed when update %zu ip_plugin rules", rule_cnt);
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

void table_runtime_commit(struct table_runtime *table_rt, long long version, size_t nr_worker_thread,
                          struct log_handle *logger)
{
    switch (table_rt->table_type) {
        case TABLE_TYPE_COMPILE:
        case TABLE_TYPE_GROUP2COMPILE:
        case TABLE_TYPE_GROUP2GROUP:
            compile_runtime_commit(table_rt, version, logger);
            break;
        case TABLE_TYPE_EXPR:
            expr_runtime_commit(table_rt, nr_worker_thread, logger);
            break;
        case TABLE_TYPE_IP_PLUS:
            ip_plus_runtime_commit(table_rt, logger);
            break;
        case TABLE_TYPE_PLUGIN:
            plugin_runtime_commit(table_rt);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ip_plugin_runtime_commit(table_rt, logger);
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
                                         int nr_worker_thread, long long version, struct log_handle *logger)
{
    struct ex_data_schema *ex_data_schema = table_schema_get_ex_data_schema(table_schema);
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

    table_runtime_commit(table_rt, version, nr_worker_thread, logger);
}
