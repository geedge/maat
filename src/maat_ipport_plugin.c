/*
**********************************************************************************************
*	File: maat_ipport_plugin.c
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "alignment.h"
#include "log/log.h"
#include "maat_utils.h"
#include "maat_ipport_plugin.h"
#include "ip_matcher.h"
#include "interval_matcher.h"
#include "maat_rule.h"
#include "maat_garbage_collection.h"

#define MODULE_IPPORT_PLUGIN	 module_name_str("maat.ipport_plugin")

struct ipport_plugin_schema {
    int item_id_column;
    int ip_type_column;
    int ip_addr_column;
    int port1_column;
    int port2_column;
    int gc_timeout_s;
    int table_id;
    struct ex_container_schema container_schema;
    struct table_manager *ref_tbl_mgr;
    struct log_handle *logger;
};

struct ipv4_item {
    uint32_t min_ip;
    uint32_t max_ip;
};

struct ipv6_item {
    uint32_t min_ip[4];
    uint32_t max_ip[4];
};

struct ipport_item {
    long long item_id;
    int ip_type; //IPV4 or IPV6
    union {
        struct ipv4_item ipv4;
        struct ipv6_item ipv6;
    };
    uint16_t min_port;
    uint16_t max_port;
};

struct ipport_plugin_runtime {
    struct ip_matcher *ip_matcher;
    struct interval_matcher *intval_matcher;
    struct rcu_hash_table *item_hash;  //<item_id, struct ipport_item>

    long long rule_num;
    long long update_err_cnt;
    struct ex_data_runtime *ex_data_rt;
    size_t n_worker_thread;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

void *ipport_plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                               const char *table_name, struct log_handle *logger)
{
    struct ipport_plugin_schema *schema = ALLOC(struct ipport_plugin_schema, 1);
    schema->logger = logger;

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
   if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
    } else {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table:<%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (NULL == item || item->type != cJSON_Object) {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table:<%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->item_id_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table:<%s> schema has no item_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "ip_type");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->ip_type_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table:<%s> schema has no ip_type column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "ip_addr");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->ip_addr_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table:<%s> schema has no ip_addr column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "port1");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->port1_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table:<%s> schema has no port1 column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "port2");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->port2_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table:<%s> schema has no port2 column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
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

void ipport_plugin_schema_free(void *ipport_plugin_schema)
{
    if (NULL == ipport_plugin_schema) {
        return;
    }

    FREE(ipport_plugin_schema);
}

int ipport_plugin_table_set_ex_container_schema(void *ipport_plugin_schema, int table_id,
                                                maat_ex_new_func_t *new_func,
							                    maat_ex_free_func_t *free_func,
							                    maat_ex_dup_func_t *dup_func,
                                                void (*custom_data_free)(void *),
							                    long argl, void *argp)
{
    struct ipport_plugin_schema *schema = (struct ipport_plugin_schema *)ipport_plugin_schema;

    if (1 == schema->container_schema.set_flag) {
        log_error(schema->logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table(table_id:%d) ex_container_schema has been set"
                  ", can't set again", __FUNCTION__, __LINE__, table_id);
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
ipport_plugin_table_get_ex_container_schema(void *ipport_plugin_schema)
{
    struct ipport_plugin_schema *schema = (struct ipport_plugin_schema *)ipport_plugin_schema;

    return &(schema->container_schema);
}

void *ipport_plugin_runtime_new(void *ipport_plugin_schema, size_t max_thread_num,
                                struct maat_garbage_bin *garbage_bin, 
                                struct log_handle *logger)
{
    if (NULL == ipport_plugin_schema) {
        return NULL;
    }

    struct ipport_plugin_schema *schema = (struct ipport_plugin_schema *)ipport_plugin_schema;
    struct ipport_plugin_runtime *ipport_plugin_rt = ALLOC(struct ipport_plugin_runtime, 1);

    ipport_plugin_rt->ex_data_rt = ex_data_runtime_new(schema->table_id, schema->gc_timeout_s,
                                                       logger);
    if (1 == schema->container_schema.set_flag) {
        ex_data_runtime_set_ex_container_schema(ipport_plugin_rt->ex_data_rt,
                                                &(schema->container_schema));
    }

    ipport_plugin_rt->n_worker_thread = max_thread_num;
    ipport_plugin_rt->ref_garbage_bin = garbage_bin;
    ipport_plugin_rt->logger = logger;
    
    return ipport_plugin_rt;
}

void ipport_plugin_runtime_free(void *ipport_plugin_runtime)
{
    if (NULL == ipport_plugin_runtime) {
        return;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt = (struct ipport_plugin_runtime *)ipport_plugin_runtime;
    if (ipport_plugin_rt->ip_matcher != NULL) {
        ip_matcher_free(ipport_plugin_rt->ip_matcher);
        ipport_plugin_rt->ip_matcher = NULL;
    }

    if (ipport_plugin_rt->intval_matcher != NULL) {
        interval_matcher_free(ipport_plugin_rt->intval_matcher);
        ipport_plugin_rt->intval_matcher = NULL;
    }

    if (ipport_plugin_rt->ex_data_rt != NULL) {
        ex_data_runtime_free(ipport_plugin_rt->ex_data_rt);
        ipport_plugin_rt->ex_data_rt = NULL;
    }

    FREE(ipport_plugin_rt);
}

static struct ipport_item *
ipport_item_new(struct ipport_plugin_schema *schema, const char *table_name,
                const char *line, struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    char ip_str[40] = {0};
    struct ipport_item *ipport_item = ALLOC(struct ipport_item, 1);

    int ret = get_column_pos(line, schema->item_id_column, &column_offset,
                             &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport table:<%s> has no item_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    ipport_item->item_id = atoll(line + column_offset);

    ret = get_column_pos(line, schema->ip_type_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport table:<%s> has no ip_type in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    ipport_item->ip_type = atoi(line + column_offset);

    if (ipport_item->ip_type != IPv4 && ipport_item->ip_type != IPv6) {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport table:<%s> has invalid ip type:%d in line:%s",
                  __FUNCTION__, __LINE__, table_name, ipport_item->ip_type, line);
        goto error;
    }

    ret = get_column_pos(line, schema->ip_addr_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport table:<%s> has no ip_addr in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    memcpy(ip_str, (line + column_offset), column_len);

    if (IPv4 == ipport_item->ip_type) {
        ret = ip_format2range(ipport_item->ip_type, IP_FORMAT_RANGE,
                              ip_str, ip_str, &ipport_item->ipv4.min_ip,
                              &ipport_item->ipv4.max_ip);
        if (ret < 0) {
            log_error(logger, MODULE_IPPORT_PLUGIN, 
                      "[%s:%d] ipport table:<%s> ip_format2range(ip4) failed in line:%s",
                      __FUNCTION__, __LINE__, table_name, line);
            goto error;
        }
    } else {
        //ipv6
        ret = ip_format2range(ipport_item->ip_type, IP_FORMAT_RANGE,
                              ip_str, ip_str, ipport_item->ipv6.min_ip,
                              ipport_item->ipv6.max_ip);
        if (ret < 0) {
            log_error(logger, MODULE_IPPORT_PLUGIN, 
                      "[%s:%d] ipport table:<%s> ip_format2range(ip6) failed in line:%s",
                      __FUNCTION__, __LINE__, table_name, line);
            goto error;
        }
    }

    ret = get_column_pos(line, schema->port1_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport table:<%s>) has no port1 in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    ipport_item->min_port = atoi(line + column_offset);

    ret = get_column_pos(line, schema->port2_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport table:<%s> has no port2 in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    ipport_item->max_port = atoi(line + column_offset);

    return ipport_item;
error:
    FREE(ipport_item);
    return NULL;
}

static void ipport_item_free(struct ipport_item *item)
{
    if (NULL == item) {
        return;
    }
    
    FREE(item);
}

static int ipport_plugin_runtime_update_row(struct ipport_plugin_runtime *ipport_plugin_rt,
                                            const char *table_name, const char *row, 
                                            const char *key, size_t key_len, 
                                            struct ipport_item *ipport_item, int is_valid)
{
    int ret = -1;
    struct ex_data_runtime *ex_data_rt = ipport_plugin_rt->ex_data_rt;
    if (NULL == ex_data_rt) {
        return -1;
    }

    if (0 == is_valid) {
        // delete
        ret = ex_data_runtime_del_ex_container(ex_data_rt, key, key_len);
        if (ret < 0) {
            return -1;
        }
    } else {
        // add
        void *ex_data = ex_data_runtime_row2ex_data(ex_data_rt, table_name, row, key, key_len);
        struct ex_container *ex_container = ex_container_new(ex_data, (void *)ipport_item);
        ret = ex_data_runtime_add_ex_container(ex_data_rt, key, key_len, ex_container);
        if (ret < 0) {
            return -1;
        }
    }

    return 0;
}

int ipport_plugin_runtime_update(void *ipport_plugin_runtime, void *ipport_plugin_schema, 
                                 const char *table_name, const char *line, int valid_column)
{
    if (NULL == ipport_plugin_runtime || NULL == ipport_plugin_schema || 
        NULL == line) {
        return -1;
    }

    struct ipport_item *ipport_item = NULL;
    struct ipport_plugin_schema *schema = (struct ipport_plugin_schema *)ipport_plugin_schema;
    struct ipport_plugin_runtime *ipport_plugin_rt = (struct ipport_plugin_runtime *)ipport_plugin_runtime;
    size_t item_id_offset = 0, item_id_len = 0;

    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        ipport_plugin_rt->update_err_cnt++;
        return -1;
    }

    int ret = get_column_pos(line, schema->item_id_column, &item_id_offset,
                             &item_id_len);
    if (ret < 0) {
        ipport_plugin_rt->update_err_cnt++;
        return -1;
    }

    if (1 == schema->container_schema.set_flag) {
        if (1 == is_valid) {
            // add
            ipport_item = ipport_item_new(schema, table_name, line,
                                          ipport_plugin_rt->logger);
            if (NULL == ipport_item) {
                ipport_plugin_rt->update_err_cnt++;
                return -1;
            }
        }

        const char *key = line + item_id_offset;
        size_t key_len = item_id_len;
        ret = ipport_plugin_runtime_update_row(ipport_plugin_rt, table_name, line,
                                               key, key_len, ipport_item, is_valid);
        if (ret < 0) {
            if (ipport_item != NULL) {
                ipport_item_free(ipport_item);
            }
            ipport_plugin_rt->update_err_cnt++;
            return -1;
        }
    } else {
        //ex_schema not set
        ex_data_runtime_cache_row_put(ipport_plugin_rt->ex_data_rt, line);
        ipport_plugin_rt->rule_num = ex_data_runtime_cached_row_count(ipport_plugin_rt->ex_data_rt);
    }

    return 0;
}

static void ipport_item_to_ip_rule(struct ipport_item *item, struct ip_rule *rule)
{
    if (IPv4 == item->ip_type) {
        rule->type = IPv4;
        rule->ipv4_rule.start_ip = item->ipv4.min_ip;
        rule->ipv4_rule.end_ip = item->ipv4.max_ip;
    } else {
        rule->type = IPv6;
        memcpy(rule->ipv6_rule.start_ip, item->ipv6.min_ip, 
               sizeof(item->ipv6.min_ip));
        memcpy(rule->ipv6_rule.end_ip, item->ipv6.max_ip, 
               sizeof(item->ipv6.max_ip));
    }
    rule->rule_id = item->item_id;
}

int ipport_plugin_runtime_commit(void *ipport_plugin_runtime, const char *table_name,
                                 long long maat_rt_version)
{
    if (NULL == ipport_plugin_runtime) {
        return -1;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt = (struct ipport_plugin_runtime *)ipport_plugin_runtime;
    struct ex_data_runtime *ex_data_rt = ipport_plugin_rt->ex_data_rt;
    if (NULL == ex_data_rt) {
        return -1;
    }

    int updating_flag = ex_data_runtime_is_updating(ex_data_rt);
    if (0 == updating_flag) {
        return 0;
    }

    ex_data_runtime_commit(ex_data_rt);

    struct ip_rule *rules = NULL;
    struct ex_container **ex_container = NULL;
    size_t rule_cnt = ex_data_runtime_list_ex_container(ex_data_rt, &ex_container);
    if (rule_cnt > 0) {
        rules = ALLOC(struct ip_rule, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            struct ipport_item *item = (struct ipport_item *)ex_container[i]->custom_data;
            ipport_item_to_ip_rule(item, &rules[i]);
            rules[i].user_tag = ex_container[i];
        }
    }

    int ret = 0;
    size_t mem_used = 0;
    struct ip_matcher *new_ip_matcher = NULL;
    struct ip_matcher *old_ip_matcher = NULL;

    if (rule_cnt > 0) {
        new_ip_matcher = ip_matcher_new(rules, rule_cnt, &mem_used);
        if (NULL == new_ip_matcher) {
            log_error(ipport_plugin_rt->logger, MODULE_IPPORT_PLUGIN,
                      "[%s:%d] ipport_plugin table[%s] rebuild ip_matcher failed when "
                      "update %zu rules", __FUNCTION__, __LINE__, table_name, rule_cnt);
            ret = -1;
        } else {
            log_info(ipport_plugin_rt->logger, MODULE_IPPORT_PLUGIN,
                     "table[%s] commit %zu ipport_plugin rules and rebuild ip_matcher "
                     "completed, version:%lld", table_name, rule_cnt, maat_rt_version);
        }
    }

    old_ip_matcher = ipport_plugin_rt->ip_matcher;
    ipport_plugin_rt->ip_matcher = new_ip_matcher;
    if (old_ip_matcher != NULL) {
        maat_garbage_bagging(ipport_plugin_rt->ref_garbage_bin, old_ip_matcher, NULL,
                             garbage_ip_matcher_free);
    }
    
    ipport_plugin_rt->rule_num = rule_cnt;

    if (rules != NULL) {
        FREE(rules);
    }
    
    if (ex_container != NULL) {
        FREE(ex_container);
    }

    return ret;
}

long long ipport_plugin_runtime_rule_count(void *ipport_plugin_runtime)
{
    if (NULL == ipport_plugin_runtime) {
        return 0;
    }
    
    struct ipport_plugin_runtime *ipport_plugin_rt = (struct ipport_plugin_runtime *)ipport_plugin_runtime;
    return ipport_plugin_rt->rule_num;
}

struct ex_data_runtime *ipport_plugin_runtime_get_ex_data_rt(void *ipport_plugin_runtime)
{
    if (NULL == ipport_plugin_runtime) {
        return NULL;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt = (struct ipport_plugin_runtime *)ipport_plugin_runtime;

    return ipport_plugin_rt->ex_data_rt;
}

static int validate_port(struct ipport_item *item, uint16_t port)
{
    if (NULL == item) {
        return -1;
    }
    
    uint16_t host_port = ntohs(port);

    if (item->min_port > host_port || item->max_port < host_port) {
        return -1;
    }

    return 0;
}

int ipport_plugin_runtime_get_ex_data(void *ipport_plugin_runtime, const struct ip_addr *ip_addr, 
                                      uint16_t port, void **ex_data_array, size_t array_size)
{
    if (NULL == ipport_plugin_runtime || NULL == ip_addr ||
        NULL == ex_data_array || 0 == array_size) {
        return -1;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt = (struct ipport_plugin_runtime *)ipport_plugin_runtime;
    if (0 == ipport_plugin_rt->rule_num) {
        return 0;
    }

    if (NULL == ipport_plugin_rt->ip_matcher) {
        return 0;
    }

    struct ip_data ip_data = *(const struct ip_data *)ip_addr;
	if (ip_data.type == IPv4) {
		ip_data.ipv4 = ntohl(ip_data.ipv4);
	} else {
		ipv6_ntoh(ip_data.ipv6);
	}

    struct scan_result ip_results[MAX_SCANNER_HIT_ITEM_NUM];
	int n_hit_ip_item = ip_matcher_match(ipport_plugin_rt->ip_matcher, &ip_data, ip_results,
                                         MAX_SCANNER_HIT_ITEM_NUM);
    if (n_hit_ip_item <= 0) {
        return n_hit_ip_item;
    }

    size_t hit_result_cnt = 0;
    for (size_t i = 0; i < n_hit_ip_item; i++) {
        struct ex_container *ex_container = ip_results[i].tag;
        struct ipport_item *item = (struct ipport_item *)ex_container->custom_data;

        int ret = validate_port(item, port);
        if (ret < 0) {
            continue;
        }

        ex_data_array[hit_result_cnt++] = ex_data_runtime_get_ex_data_by_container(ipport_plugin_rt->ex_data_rt,
                                                                                   ex_container); 
    }

	return hit_result_cnt;
}

long long ipport_plugin_runtime_update_err_count(void *ipport_plugin_runtime)
{
    if (NULL == ipport_plugin_runtime) {
        return 0;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt = (struct ipport_plugin_runtime *)ipport_plugin_runtime;
    return ipport_plugin_rt->update_err_cnt;
}