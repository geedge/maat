/*
**********************************************************************************************
*	File: maat_ip.cpp
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <stdint.h>
#include <assert.h>

#include "log/log.h"
#include "maat_utils.h"
#include "maat_ex_data.h"
#include "ip_matcher.h"
#include "interval_matcher.h"
#include "maat_ip.h"
#include "maat_rule.h"
#include "maat_compile.h"
#include "alignment.h"
#include "maat_garbage_collection.h"

#define MODULE_IP	 module_name_str("maat.ip")

struct ip_schema {
    int item_id_column;
    int group_id_column;
    int addr_type_column;
    int addr_format_column;
    int ip1_column;
    int ip2_column;
    int port_format_column;
    int port1_column;
    int port2_column;
    int protocol_column;
    int table_id; //ugly
    struct table_manager *ref_tbl_mgr;
};

struct ipv4_item_rule {
    uint32_t min_ip;   /* 源地址下界；0表示忽略本字段 */
    uint32_t max_ip;   /* 源地址上界；0表示固定IP=min_addr */
};

struct ipv6_item_rule {
    uint32_t min_ip[4]; /* 源地址下界；全0表示忽略本字段 */
    uint32_t max_ip[4]; /* 源地址上界；全0表示固定IP=min_addr */
};

struct ip_item {
    long long item_id;
    long long group_id;
    int addr_type;
    union {
        struct ipv4_item_rule ipv4;
        struct ipv6_item_rule ipv6;
    };
    enum ip_format ip_format;
    enum port_format port_format;
    uint16_t min_port;
    uint16_t max_port;
    int proto;
};

struct ip_runtime {
	struct ip_matcher *ip_matcher;
    struct interval_matcher *intval_matcher;
    struct rcu_hash_table *htable; //store ip rule for rebuild ip_matcher instance
    struct rcu_hash_table *item_htable;  //store this ip table's all maat_item which will be used in ip_runtime_scan
    long long version;
    long long rule_num;
    long long ipv6_rule_num;
    long long update_err_cnt;
    size_t n_worker_thread;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;

    long long *scan_cnt;
    long long *scan_cpu_time;
    long long *hit_cnt;
};

void *ip_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                    const char *table_name, struct log_handle *logger)
{
    struct ip_schema *ip_schema = ALLOC(struct ip_schema, 1);

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        ip_schema->table_id = item->valueint;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (NULL == item || item->type != cJSON_Object) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table %s has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->item_id_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] table %s has no item_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->group_id_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] table %s has no group_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "addr_type");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->addr_type_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] table %s has no add_type column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "addr_format");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->addr_format_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] table %s has no addr_format column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "ip1");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->ip1_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] table %s has no ip1 column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "ip2");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->ip2_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] table %s has no ip2 column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "port_format");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->port_format_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] table %s has no port_format column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "port1");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->port1_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] table %s has no port1 column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "port2");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->port2_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] table %s has no port2 column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "protocol");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->protocol_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] table %s has no protocol column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    ip_schema->ref_tbl_mgr = tbl_mgr;
    return ip_schema;
error:
    FREE(ip_schema);
    return NULL;
}

void ip_schema_free(void *ip_schema)
{
    FREE(ip_schema);
}

struct ip_item *ip_item_new(const char *line, struct ip_schema *ip_schema,
                            struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    char addr_format[16] = {0};
    char port_format[16] = {0};
    char ip1_str[40] = {0};
    char ip2_str[40] = {0};
    struct ip_item *ip_item = ALLOC(struct ip_item, 1);

    int ret = get_column_pos(line, ip_schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip plus table(table_id:%d) line:%s has no item_id",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    ip_item->item_id = atoll(line + column_offset);

    ret = get_column_pos(line, ip_schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP,
                  "[%s:%d] ip plus table(table_id:%d) line:%s has no group_id",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    ip_item->group_id = atoll(line + column_offset);

    ret = get_column_pos(line, ip_schema->addr_type_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip plus table(table_id:%d) line:%s has no addr_type",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    ip_item->addr_type = atoi(line + column_offset);

    if (ip_item->addr_type != IPv4 && ip_item->addr_type != IPv6) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table(table_id:%d) line:%s has invalid addr type:%d",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line, ip_item->addr_type);
        goto error;
    }

    ret = get_column_pos(line, ip_schema->addr_format_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP,
                  "[%s:%d] ip table(table_id:%d) line:%s has no addr_format",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    memcpy(addr_format, (line + column_offset), column_len);
    if (IP_FORMAT_UNKNOWN == ip_format_str2int(addr_format)) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table(table_id:%d) line:%s has invalid saddr_format, should be single/range/CIDR",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }

    ret = get_column_pos(line, ip_schema->ip1_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table(table_id:%d) line:%s has no ip1",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    memcpy(ip1_str, (line + column_offset), column_len);

    ret = get_column_pos(line, ip_schema->ip2_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table(table_id:%d) line:%s has no ip2",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    memcpy(ip2_str, (line + column_offset), column_len);

    if (IPv4 == ip_item->addr_type) {
        ret = ip_format2range(ip_item->addr_type, ip_format_str2int(addr_format), ip1_str, ip2_str, 
                              &ip_item->ipv4.min_ip, &ip_item->ipv4.max_ip);
        if (ret < 0) {
            log_error(logger, MODULE_IP, 
                      "[%s:%d] ip table(table_id:%d) line:%s ip_format2range(ip4) failed",
                      __FUNCTION__, __LINE__, ip_schema->table_id, line);
            goto error;
        }
    } else {
        //ipv6
        ret = ip_format2range(ip_item->addr_type, ip_format_str2int(addr_format), ip1_str, ip2_str, 
                              ip_item->ipv6.min_ip, ip_item->ipv6.max_ip);
        if (ret < 0) {
            log_error(logger, MODULE_IP, 
                      "[%s:%d] ip table(table_id:%d) line:%s ip_format2range(ip6) failed",
                      __FUNCTION__, __LINE__, ip_schema->table_id, line);
            goto error;
        }
    }

    ret = get_column_pos(line, ip_schema->port_format_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP,
                  "[%s:%d] ip table(table_id:%d) line:%s has no port_format",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    
    memcpy(port_format, (line + column_offset), column_len);
    if (PORT_FORMAT_UNKNOWN == port_format_str2int(port_format)) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table(table_id:%d) line:%s has invalid port_format, should be single/range",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    ip_item->port_format = port_format_str2int(port_format);

    ret = get_column_pos(line, ip_schema->port1_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table(table_id:%d) line:%s has no port1",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    ip_item->min_port = atoi(line + column_offset);

    ret = get_column_pos(line, ip_schema->port2_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table(table_id:%d) line:%s has no port2",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    ip_item->max_port = atoi(line + column_offset);

    ret = get_column_pos(line, ip_schema->protocol_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table(table_id:%d) line:%s has no protocol",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    ip_item->proto = atoi(line + column_offset);

    return ip_item;
error:
    FREE(ip_item);
    return NULL;
}

void ip_item_free(struct ip_item *ip_item)
{
    FREE(ip_item);
}

void ip_ex_data_free(void *user_ctx, void *data)
{
    struct ip_item *item = (struct ip_item *)data;
    ip_item_free(item);
}

void ip_maat_item_free(void *user_ctx, void *data)
{
    struct maat_item *item = (struct maat_item *)data;
    maat_item_free(item);
}

void *ip_runtime_new(void *ip_schema, size_t max_thread_num,
                     struct maat_garbage_bin *garbage_bin, 
                     struct log_handle *logger)
{
    if (NULL == ip_schema) {
        return NULL;
    }

    struct ip_runtime *ip_rt = ALLOC(struct ip_runtime, 1);

    ip_rt->htable = rcu_hash_new(ip_ex_data_free, NULL);
    ip_rt->item_htable = rcu_hash_new(ip_maat_item_free, NULL);
    ip_rt->n_worker_thread = max_thread_num;
    ip_rt->ref_garbage_bin = garbage_bin;
    ip_rt->logger = logger;

    ip_rt->hit_cnt = alignment_int64_array_alloc(max_thread_num);
    ip_rt->scan_cnt = alignment_int64_array_alloc(max_thread_num);

    return ip_rt;
}

void ip_runtime_free(void *ip_runtime)
{
    if (NULL == ip_runtime) {
        return;
    }

    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    if (ip_rt->ip_matcher != NULL) {
        ip_matcher_free(ip_rt->ip_matcher);
        ip_rt->ip_matcher = NULL;
    }

    if (ip_rt->intval_matcher != NULL) {
        interval_matcher_free(ip_rt->intval_matcher);
        ip_rt->intval_matcher = NULL;
    }

    if (ip_rt->htable != NULL) {
        rcu_hash_free(ip_rt->htable);
        ip_rt->htable = NULL;
    }

    if (ip_rt->item_htable != NULL) {
        rcu_hash_free(ip_rt->item_htable);
        ip_rt->item_htable = NULL;
    }

    if (ip_rt->hit_cnt != NULL) {
        alignment_int64_array_free(ip_rt->hit_cnt);
        ip_rt->hit_cnt = NULL;
    }

    if (ip_rt->scan_cnt != NULL) {
        alignment_int64_array_free(ip_rt->scan_cnt);
        ip_rt->scan_cnt = NULL;
    }

    if (ip_rt->scan_cpu_time != NULL) {
        alignment_int64_array_free(ip_rt->scan_cpu_time);
        ip_rt->scan_cpu_time = NULL;
    }

    FREE(ip_rt);
}

void ip_item_to_ip_rule(struct ip_item *item, struct ip_rule *rule)
{
    if (IPv4 == item->addr_type) {
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

void ip_item_to_port_rule(struct ip_item *item, struct interval_rule *rule)
{
    rule->start = item->min_port;
    rule->end = item->max_port;
    rule->result.rule_id = item->item_id;
}

int ip_runtime_update_row(struct ip_runtime *ip_rt, char *key, size_t key_len, 
                          struct ip_item *item, int is_valid)
{
    int ret = -1;
    
    if (0 == is_valid) {
        // delete
        rcu_hash_del(ip_rt->htable, key, key_len);
    } else {
        // add
        ret = rcu_hash_add(ip_rt->htable, key, key_len, (void *)item);
        if (ret < 0) {
            log_error(ip_rt->logger, MODULE_IP,
                      "[%s:%d] ip rule(rule_id:%lld) add to ip runtime htable failed", 
                      __FUNCTION__, __LINE__, item->item_id);
            return -1;
        }
    }

    return 0;
}

int ip_runtime_update(void *ip_runtime, void *ip_schema, 
                      const char *table_name, const char *line, 
                      int valid_column)
{
    if (NULL == ip_runtime || NULL == ip_schema || NULL == line) {
        return -1;
    }

    int ret = -1;
    struct maat_item *item = NULL;
    struct ip_item *ip_item = NULL;
    struct maat_item_inner *u_para = NULL;
    struct ip_schema *schema = (struct ip_schema *)ip_schema;
    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    long long item_id = get_column_value(line, schema->item_id_column);
    if (item_id < 0) {
        ip_rt->update_err_cnt++;
        return -1;
    }

    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        ip_rt->update_err_cnt++;
        return -1;
    } else if (0 == is_valid) {
        //delete
        rcu_hash_del(ip_rt->item_htable, (char *)&item_id, sizeof(item_id));
    } else {
        //add
        ip_item = ip_item_new(line, schema, ip_rt->logger);
        if (NULL == ip_item) {
            ip_rt->update_err_cnt++;
            return -1;
        }

        u_para = maat_item_inner_new(ip_item->group_id, item_id, 0);
        item = maat_item_new(item_id, ip_item->group_id, u_para, maat_item_inner_free);
        ret = rcu_hash_add(ip_rt->item_htable, (char *)&(item_id), sizeof(item_id), item);
        if (ret < 0) {
            log_error(ip_rt->logger, MODULE_IP, 
                      "[%s:%d] [table:%s] ip runtime add item(item_id:%lld) failed", 
                      __FUNCTION__, __LINE__, table_name, item_id);
            ip_item_free(ip_item);
            maat_item_free(item);
            ip_rt->update_err_cnt++;
            return -1;
        }
    }
    
    char *key = (char *)&item_id;
    ret = ip_runtime_update_row(ip_rt, key, sizeof(long long), ip_item, is_valid);
    if (ret < 0) {
        if (ip_item != NULL) {
            ip_item_free(ip_item);
            ip_item = NULL;
        }
        ip_rt->update_err_cnt++;
        return -1;
    }

    return 0;
}

void garbage_ip_matcher_free(void *ip_matcher, void *arg)
{
    struct ip_matcher *matcher = (struct ip_matcher *)ip_matcher;
    ip_matcher_free(matcher);
}

int ip_runtime_commit(void *ip_runtime, const char *table_name, long long maat_rt_version)
{
    if (NULL == ip_runtime) {
        return -1;
    }

    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;

    int updating_flag = rcu_hash_is_updating(ip_rt->htable);
    if (0 == updating_flag) {
        return 0;
    }

    rcu_hash_commit(ip_rt->htable);
    ip_rt->ipv6_rule_num = 0;

    struct ip_rule *rules = NULL;
    struct interval_rule *intval_rules = NULL;
    void **ex_data_array = NULL;
    size_t rule_cnt = rcu_hash_list(ip_rt->htable, &ex_data_array);
    if (rule_cnt > 0) {
        rules = ALLOC(struct ip_rule, rule_cnt);
        intval_rules = ALLOC(struct interval_rule, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            struct ip_item *item = (struct ip_item *)ex_data_array[i];
            if (item->addr_type == IPv6) {
                ip_rt->ipv6_rule_num++;
            }

            ip_item_to_ip_rule(item, &rules[i]);
            ip_item_to_port_rule(item, &intval_rules[i]);
        }
    }

    int ret = 0;
    size_t mem_used = 0;
    struct ip_matcher *new_ip_matcher = NULL;
    struct ip_matcher *old_ip_matcher = NULL;

    struct interval_matcher *new_intval_matcher = NULL;
    struct interval_matcher *old_intval_matcher = NULL;
    if (rule_cnt > 0) {
        new_ip_matcher = ip_matcher_new(rules, rule_cnt, &mem_used);
        if (NULL == new_ip_matcher) {
            log_error(ip_rt->logger, MODULE_IP,
                      "[%s:%d] table[%s] rebuild ip_matcher engine failed when update %zu ip rules",
                      __FUNCTION__, __LINE__, table_name, rule_cnt);
            ret = -1;
        }

        new_intval_matcher = interval_matcher_new(intval_rules, rule_cnt);
        if (NULL == new_intval_matcher) {
            log_error(ip_rt->logger, MODULE_IP,
                      "[%s:%d] table[%s] rebuild interval_matcher engine failed when update %zu ip rules",
                      __FUNCTION__, __LINE__, table_name, rule_cnt);
            ret = -1;
        }
    }

    old_ip_matcher = ip_rt->ip_matcher;
    ip_rt->ip_matcher = new_ip_matcher;
    if (old_ip_matcher != NULL) {
        maat_garbage_bagging(ip_rt->ref_garbage_bin, old_ip_matcher, NULL,
                             garbage_ip_matcher_free);
    }

    old_intval_matcher = ip_rt->intval_matcher;
    ip_rt->intval_matcher = new_intval_matcher;
    if (old_intval_matcher != NULL) {
        maat_garbage_bagging(ip_rt->ref_garbage_bin, old_intval_matcher, NULL,
                             garbage_interval_matcher_free);
    }

    rcu_hash_commit(ip_rt->item_htable);

    ip_rt->rule_num = rule_cnt;
    ip_rt->version = maat_rt_version;
    
    log_info(ip_rt->logger, MODULE_IP,
             "table[%s] commit %zu ip rules and rebuild ip_matcher completed, version:%lld", 
             table_name, rule_cnt, ip_rt->version);

    if (rules != NULL) {
        FREE(rules);
    }
    
    if (intval_rules != NULL) {
        FREE(intval_rules);
    }

    if (ex_data_array != NULL) {
        FREE(ex_data_array);
    }

    return ret;
}

long long ip_runtime_rule_count(void *ip_runtime)
{
    if (NULL == ip_runtime) {
        return 0;
    }
    
    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    return ip_rt->rule_num;
}

long long ip_runtime_ipv6_rule_count(void *ip_runtime)
{
     if (NULL == ip_runtime) {
        return 0;
    }
    
    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    return ip_rt->ipv6_rule_num;
}

int validate_port(struct rcu_hash_table *htable, const char *key, size_t key_len,
                  uint16_t port, int proto)
{
    struct ip_item *ip_item = (struct ip_item *)rcu_hash_find(htable, key, key_len);
    if (NULL == ip_item) {
        return -1;
    }

    uint16_t host_port = ntohs(port);
    if (ip_item->min_port > host_port || ip_item->max_port < host_port) {
        return -1;
    }
    
    if (ip_item->proto != -1 && ip_item->proto != proto) {
        return -1;
    }

    return 0;
}

int validate_proto(struct rcu_hash_table *htable, const char *key, size_t key_len, int proto)
{
    struct ip_item *ip_item = (struct ip_item *)rcu_hash_find(htable, key, key_len);
    if (NULL == ip_item) {
        return -1;
    }

    if (ip_item->proto != -1 && ip_item->proto != proto) {
        return -1;
    }

    return 0;
}

int ip_runtime_scan(struct ip_runtime *ip_rt, int thread_id, int ip_type, 
                    uint8_t *ip_addr, uint16_t port, int proto, int vtable_id, 
                    struct maat_state *state)
{
    if (0 == ip_rt->rule_num) {
        //empty ip table
        return 0;
    }
    
    struct scan_result ip_results[MAX_SCANNER_HIT_ITEM_NUM];

    /* if ip_addr = "0.0.0.0" means any ip */
    int any_ip_flag = 0;

    struct ip_data scan_data;
    if (ip_type == IPv4) {
        scan_data.type = IPv4;
        scan_data.ipv4 = ntohl(*(uint32_t *)ip_addr);
        if (0 == scan_data.ipv4) {
            any_ip_flag = 1;
        }
    } else {
        scan_data.type = IPv6;
        for (int i = 0; i < 4; i++) {
            scan_data.ipv6[i] = *((uint32_t *)ip_addr + i);
        }
        ipv6_ntoh(scan_data.ipv6);
        if (0 == scan_data.ipv6[0] && 0 == scan_data.ipv6[1] &&
            0 == scan_data.ipv6[2] && 0 == scan_data.ipv6[3]) {
            any_ip_flag = 1;
        }
    }

    int ret = 0;
    size_t real_hit_index = 0;
    long long hit_item_ids[MAX_SCANNER_HIT_ITEM_NUM];

    // any ip, so scan port+proto
    if (1 == any_ip_flag) {
        struct interval_result port_results[MAX_SCANNER_HIT_ITEM_NUM];
        uint16_t host_port = ntohs(port);
        int n_hit_port_item = interval_matcher_match(ip_rt->intval_matcher, host_port, 
                                                     port_results, MAX_SCANNER_HIT_ITEM_NUM);
        if (n_hit_port_item <= 0) {
            return n_hit_port_item;
        }

        if (n_hit_port_item > MAX_SCANNER_HIT_ITEM_NUM) {
            log_info(ip_rt->logger, MODULE_IP,
                     "hit port item count:%d exceed maxium:%d",
                     n_hit_port_item, MAX_SCANNER_HIT_ITEM_NUM);
            n_hit_port_item = MAX_SCANNER_HIT_ITEM_NUM;
        }

        for (size_t i = 0; i < n_hit_port_item; i++) {
            long long item_id = port_results[i].rule_id;
            ret = validate_proto(ip_rt->htable, (char *)&item_id, sizeof(item_id), proto);
            if (ret < 0) {
                continue;
            }
            hit_item_ids[real_hit_index++] = port_results[i].rule_id;
        }
    } else {
        int n_hit_ip_item = ip_matcher_match(ip_rt->ip_matcher, &scan_data,
                                             ip_results, MAX_SCANNER_HIT_ITEM_NUM);
        if (n_hit_ip_item <= 0) {
            return n_hit_ip_item;
        }

        if (n_hit_ip_item > MAX_SCANNER_HIT_ITEM_NUM) {
            log_info(ip_rt->logger, MODULE_IP,
                     "hit ip item count:%d exceed maxium:%d",
                     n_hit_ip_item, MAX_SCANNER_HIT_ITEM_NUM);
            n_hit_ip_item = MAX_SCANNER_HIT_ITEM_NUM;
        }

        for (size_t i = 0; i < n_hit_ip_item; i++) {
            long long item_id = ip_results[i].rule_id;
            ret = validate_port(ip_rt->htable, (char *)&item_id, sizeof(item_id), port, proto);
            if (ret < 0) {
                continue;
            }
            hit_item_ids[real_hit_index++] = ip_results[i].rule_id;
        }
    }

    size_t group_hit_cnt = 0;
    ret = maat_compile_state_update(ip_rt->item_htable, vtable_id, hit_item_ids, 
                                    real_hit_index, &group_hit_cnt, state);
    if (ret < 0) {
        return -1;
    }

    return group_hit_cnt;
}

void ip_runtime_hit_inc(struct ip_runtime *ip_rt, int thread_id)
{
    if (NULL == ip_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(ip_rt->hit_cnt, thread_id, 1);
}

void ip_runtime_perf_stat(struct ip_runtime *ip_rt, struct timespec *start,
                          struct timespec *end, int thread_id)
{
    if (NULL == ip_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(ip_rt->scan_cnt, thread_id, 1);
    
    if (start != NULL && end != NULL) {
        if (NULL == ip_rt->scan_cpu_time) {
            ip_rt->scan_cpu_time = alignment_int64_array_alloc(ip_rt->n_worker_thread);
        }

        long long consume_time = (end->tv_sec - start->tv_sec) * 1000000000 + end->tv_nsec - start->tv_nsec;
        alignment_int64_array_add(ip_rt->scan_cpu_time, thread_id, consume_time);
    }
}

long long ip_runtime_scan_count(void *ip_runtime)
{
    if (NULL == ip_runtime) {
        return 0;
    }

    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    long long sum = alignment_int64_array_sum(ip_rt->scan_cnt, ip_rt->n_worker_thread);
    alignment_int64_array_reset(ip_rt->scan_cnt, ip_rt->n_worker_thread);

    return sum;
}

long long ip_runtime_scan_cpu_time(void *ip_runtime)
{
    if (NULL == ip_runtime) {
        return 0;
    }

    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    long long sum = alignment_int64_array_sum(ip_rt->scan_cpu_time, 
                                              ip_rt->n_worker_thread);
    alignment_int64_array_reset(ip_rt->scan_cpu_time, ip_rt->n_worker_thread);

    return sum;
}

long long ip_runtime_hit_count(void *ip_runtime)
{
    if (NULL == ip_runtime) {
        return 0;
    }

    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    long long sum = alignment_int64_array_sum(ip_rt->hit_cnt, ip_rt->n_worker_thread);
    alignment_int64_array_reset(ip_rt->hit_cnt, ip_rt->n_worker_thread);

    return sum;
}

long long ip_runtime_update_err_count(void *ip_runtime)
{
    if (NULL == ip_runtime) {
        return 0;
    }

    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    return ip_rt->update_err_cnt;
}