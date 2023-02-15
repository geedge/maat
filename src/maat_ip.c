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
#include "IPMatcher.h"
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
    int saddr_format_column;
    int sip1_column;
    int sip2_column;
    int table_id; //ugly
    struct table_manager *ref_tbl_mgr;
};

struct ipv4_item_rule {
    uint32_t min_sip;   /* 源地址下界；0表示忽略本字段 */
    uint32_t max_sip;   /* 源地址上界；0表示固定IP=min_saddr */
};

struct ipv6_item_rule {
    uint32_t min_sip[4]; /* 源地址下界；全0表示忽略本字段 */
    uint32_t max_sip[4]; /* 源地址上界；全0表示固定IP=min_saddr */
};

struct ip_item {
    int item_id;
    int group_id;
    int addr_type;
    union {
        struct ipv4_item_rule ipv4;
        struct ipv6_item_rule ipv6;
    };
};

struct ip_runtime {
	struct ip_matcher* ip_matcher;
    struct ex_data_runtime* ex_data_rt;

    uint32_t rule_num;
    uint32_t updating_rule_num;
    struct maat_item *item_hash;
    void (*item_user_data_free)(void *);

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;

    long long *scan_cnt;
    long long *hit_cnt;
};

void *ip_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                    const char *table_name, struct log_handle *logger)
{
    size_t read_cnt = 0;
    struct ip_schema *ip_schema = ALLOC(struct ip_schema, 1);

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        ip_schema->table_id = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (NULL == item || item->type != cJSON_Object) {
        log_error(logger, MODULE_IP, 
                  "ip table %s has no custom column", table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->item_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->group_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "addr_type");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->addr_type_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "saddr_format");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->saddr_format_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "sip1");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->sip1_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "sip2");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_schema->sip2_column = custom_item->valueint;
        read_cnt++;
    }

    ip_schema->ref_tbl_mgr = tbl_mgr;

    if (read_cnt < 7) {
        goto error;
    }

    return ip_schema;
error:
    FREE(ip_schema);
    return NULL;
}

void ip_schema_free(void *ip_schema)
{
    FREE(ip_schema);
}

void *ip_runtime_new(void *ip_schema, int max_thread_num, 
                     struct maat_garbage_bin *garbage_bin,
                     struct log_handle *logger)
{
    if (NULL == ip_schema) {
        return NULL;
    }

    struct ip_schema *schema = (struct ip_schema *)ip_schema;
    struct ip_runtime *ip_rt = ALLOC(struct ip_runtime, 1);

    ip_rt->ex_data_rt = ex_data_runtime_new(schema->table_id, 
                                            ex_data_container_free, 
                                            logger);
    ip_rt->item_user_data_free = maat_item_inner_free;
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
    }

    if (ip_rt->ex_data_rt != NULL) {
        ex_data_runtime_free(ip_rt->ex_data_rt);
    }

    struct maat_item *item = NULL, *tmp_item = NULL;
    HASH_ITER(hh, ip_rt->item_hash, item, tmp_item) {
        HASH_DELETE(hh, ip_rt->item_hash, item);
        maat_item_free(item, ip_rt->item_user_data_free);
    }

    if (ip_rt->hit_cnt != NULL) {
        alignment_int64_array_free(ip_rt->hit_cnt);
        ip_rt->hit_cnt = NULL;
    }

    if (ip_rt->scan_cnt != NULL) {
        alignment_int64_array_free(ip_rt->scan_cnt);
        ip_rt->scan_cnt = NULL;
    }

    FREE(ip_rt);
}

struct ip_item *ip_item_new(const char *line, struct ip_schema *ip_schema,
                            struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    char saddr_format[16] = {0};
    char sip1_str[40] = {0};
    char sip2_str[40] = {0};
    struct ip_item *ip_item = ALLOC(struct ip_item, 1);

    int ret = get_column_pos(line, ip_schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, 
                  "ip plus table(table_id:%d) line:%s has no item_id",
                  ip_schema->table_id, line);
        goto error;
    }
    ip_item->item_id = atoi(line + column_offset);

    ret = get_column_pos(line, ip_schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP,
                  "ip plus table(table_id:%d) line:%s has no group_id",
                  ip_schema->table_id, line);
        goto error;
    }
    ip_item->group_id = atoi(line + column_offset);

    ret = get_column_pos(line, ip_schema->addr_type_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, 
                  "ip plus table(table_id:%d) line:%s has no addr_type",
                  ip_schema->table_id, line);
        goto error;
    }
    ip_item->addr_type = atoi(line + column_offset);

    if (ip_item->addr_type != IPv4 && ip_item->addr_type != IPv6) {
        log_error(logger, MODULE_IP, 
                  "ip table(table_id:%d) line:%s has invalid addr type:%d",
                  ip_schema->table_id, line, ip_item->addr_type);
        goto error;
    }

    ret = get_column_pos(line, ip_schema->saddr_format_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP,
                  "ip table(table_id:%d) line:%s has no saddr_format",
                  ip_schema->table_id, line);
        goto error;
    }
    memcpy(saddr_format, (line + column_offset), column_len);
    if (IP_FORMAT_UNKNOWN == ip_format_str2int(saddr_format)) {
        log_error(logger, MODULE_IP, 
                  "ip table(table_id:%d) line:%s has invalid saddr_format, should be range/mask/CIDR",
                  ip_schema->table_id, line);
        goto error;
    }

    ret = get_column_pos(line, ip_schema->sip1_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, "ip table(table_id:%d) line:%s has no sip1",
                  ip_schema->table_id, line);
        goto error;
    }
    memcpy(sip1_str, (line + column_offset), column_len);

    ret = get_column_pos(line, ip_schema->sip2_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, "ip table(table_id:%d) line:%s has no sip2",
                  ip_schema->table_id, line);
        goto error;
    }
    memcpy(sip2_str, (line + column_offset), column_len);

    if (IPv4 == ip_item->addr_type) {
        ret = ip_format2range(ip_item->addr_type, ip_format_str2int(saddr_format), sip1_str, sip2_str, 
                              &ip_item->ipv4.min_sip, &ip_item->ipv4.max_sip);
        if (ret < 0) {
            log_error(logger, MODULE_IP, 
                      "ip table(table_id:%d) line:%s ip_format2range(ip4) failed",
                      ip_schema->table_id, line);
            goto error;
        }
    } else {
        //ipv6
        ret = ip_format2range(ip_item->addr_type, ip_format_str2int(saddr_format), sip1_str, sip2_str, 
                              ip_item->ipv6.min_sip, ip_item->ipv6.max_sip);
        if (ret < 0) {
            log_error(logger, MODULE_IP, 
                      "ip table(table_id:%d) line:%s ip_format2range(ip6) failed",
                      ip_schema->table_id, line);
            goto error;
        }
    }

    return ip_item;
error:
    FREE(ip_item);
    return NULL;
}

void ip_item_free(struct ip_item *ip_item)
{
    FREE(ip_item);
}

void ip_item_to_ip_rule(struct ip_item *item, struct ip_rule *rule)
{
    if (IPv4 == item->addr_type) {
        rule->type = IPv4;
        rule->ipv4_rule.start_ip = item->ipv4.min_sip;
        rule->ipv4_rule.end_ip = item->ipv4.max_sip;
    } else {
        rule->type = IPv6;
        memcpy(rule->ipv6_rule.start_ip, item->ipv6.min_sip, 
               sizeof(item->ipv6.min_sip));
        memcpy(rule->ipv6_rule.end_ip, item->ipv6.max_sip, 
               sizeof(item->ipv6.max_sip));
    }
    rule->rule_id = item->item_id;
}

struct ex_data_runtime *ip_runtime_get_ex_data_rt(struct ip_runtime *ip_rt)
{
    return ip_rt->ex_data_rt;
}

int ip_runtime_update_row(struct ip_runtime *rt, char *key, size_t key_len, 
                          struct ip_item *item, int is_valid)
{
    int ret = -1;
    struct ex_data_runtime *ex_data_rt = rt->ex_data_rt;
    
    if (0 == is_valid) {
        // delete
        ret = ex_data_runtime_del_ex_container(ex_data_rt, key, key_len);
        if (ret < 0) {
            return -1;
        }
    } else {
        // add
        struct ex_data_container *ex_container = ex_data_container_new(NULL, (void *)item);
        ret = ex_data_runtime_add_ex_container(ex_data_rt, key, key_len, ex_container);
        if (ret < 0) {
            return -1;
        }
    }

    return 0;
}

int ip_runtime_update(void *ip_runtime, void *ip_schema, 
                      const char *line, int valid_column)
{
    if (NULL == ip_runtime || NULL == ip_schema || NULL == line) {
        return -1;
    }

    struct maat_item *item = NULL;
    struct ip_item *ip_item = NULL;
    struct maat_item_inner *u_para = NULL;
    struct ip_schema *schema = (struct ip_schema *)ip_schema;
    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    int item_id = get_column_value(line, schema->item_id_column);
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    } else if (0 == is_valid) {
        //delete
        HASH_FIND_INT(ip_rt->item_hash, &item_id, item);
        if (NULL == item) {
            return -1;
        }
        
        u_para = (struct maat_item_inner *)item->user_data;
        item->user_data = NULL;
        
	    if (NULL == u_para) {
		    return -1;
	    }

        HASH_DELETE(hh, ip_rt->item_hash, item);
        maat_garbage_bagging(ip_rt->ref_garbage_bin, u_para, 
                             (void (*)(void *))maat_item_inner_free);
    } else {
        //add
        HASH_FIND_INT(ip_rt->item_hash, &item_id, item);
        if (item) {
            log_error(ip_rt->logger, MODULE_IP, 
                      "ip runtime add item %d to item_hash failed, already exist", 
                      item_id);
            return -1;
        }

        ip_item = ip_item_new(line, schema, ip_rt->logger);
        if (NULL == ip_item) {
            return -1;
        }

        u_para = maat_item_inner_new(ip_item->group_id, item_id, 0);
        item = maat_item_new(item_id, ip_item->group_id, u_para);
        HASH_ADD_INT(ip_rt->item_hash, item_id, item);
    }
    
    char *key = (char *)&item_id;
    int ret = ip_runtime_update_row(ip_rt, key, sizeof(int), ip_item, is_valid);
    if (ret < 0) {
        if (ip_item != NULL) {
            ip_item_free(ip_item);
            ip_item = NULL;
        }
        return -1;
    } else {
        if (0 == is_valid) {
            ip_rt->rule_num--;
        } else {
            ip_rt->rule_num++;
        }
    }

    return 0;
}

int ip_runtime_commit(void *ip_runtime, const char *table_name)
{
    if (NULL == ip_runtime) {
        return -1;
    }

    int ret = 0;
    struct ex_data_container **ex_container = NULL;
    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    struct ex_data_runtime *ex_data_rt = ip_rt->ex_data_rt;

    size_t rule_cnt = ex_data_runtime_list_updating_ex_container(ex_data_rt, &ex_container);
    if (0 == rule_cnt) {
        FREE(ex_container);
        return 0;
    }

    struct ip_rule *rules = ALLOC(struct ip_rule, rule_cnt);

    for (size_t i = 0; i < rule_cnt; i++) {
        struct ip_item *item = (struct ip_item *)ex_container[i]->custom_data;
        ip_item_to_ip_rule(item, &rules[i]);
    }

    struct ip_matcher *new_ip_matcher = NULL;
    struct ip_matcher *old_ip_matcher = NULL;
    size_t mem_used = 0;

    if (rule_cnt > 0) {
        log_info(ip_rt->logger, MODULE_IP, 
                 "table[%s] committing %zu ip rules for rebuilding ip_matcher engine", 
                 table_name, rule_cnt);
        new_ip_matcher = ip_matcher_new(rules, rule_cnt, &mem_used);
        if (NULL == new_ip_matcher) {
            log_error(ip_rt->logger, MODULE_IP, 
                      "table[%s] rebuild ip_matcher engine failed when update %zu ip rules",
                       table_name, rule_cnt);
            ret = -1;
        }
    }

    old_ip_matcher = ip_rt->ip_matcher;
    ip_rt->ip_matcher = new_ip_matcher;
    maat_garbage_bagging(ip_rt->ref_garbage_bin, old_ip_matcher, 
                         (void (*)(void*))ip_matcher_free);
    ex_data_runtime_commit(ex_data_rt);

    FREE(rules);
    FREE(ex_container);

    return ret;
}

int ip_runtime_scan(struct ip_runtime *ip_rt, int thread_id, int ip_type, 
                    uint8_t *ip_addr, int *group_ids, size_t group_id_size, 
                    int vtable_id, struct maat_state *state)
{
    int n_hit_item = 0;
    struct scan_result scan_results[MAX_SCANNER_HIT_ITEM_NUM] = {0};

    struct ip_data scan_data;
    if (ip_type == IPv4) {
        scan_data.type = IPv4;
        scan_data.ipv4 = *(uint32_t *)ip_addr;
    } else {
        scan_data.type = IPv6;
        for (int i = 0; i < 4; i++) {
            scan_data.ipv6[i] = *((uint32_t *)ip_addr + i);
        }
    }

    n_hit_item = ip_matcher_match(ip_rt->ip_matcher, &scan_data, scan_results, MAX_SCANNER_HIT_ITEM_NUM);
    if (n_hit_item <= 0) {
        return n_hit_item;
    }

    if (n_hit_item > MAX_SCANNER_HIT_ITEM_NUM) {
        log_info(ip_rt->logger, MODULE_IP, 
                "hit ip item count:%d exceed maxium:%d", 
                 n_hit_item, MAX_SCANNER_HIT_ITEM_NUM);
        n_hit_item = MAX_SCANNER_HIT_ITEM_NUM;
    }

    int hit_item_ids[MAX_SCANNER_HIT_ITEM_NUM] = {-1};
    for (int i = 0; i < n_hit_item; i++) {
        hit_item_ids[i] = scan_results[i].rule_id;
    }

    size_t group_hit_cnt = 0;
    int ret = maat_compile_state_update(ip_rt->item_hash, vtable_id, hit_item_ids, n_hit_item,
                                        group_ids, group_id_size, &group_hit_cnt, state);
    if (ret < 0) {
        return -1;
    }

    return group_hit_cnt;
}

void ip_runtime_scan_hit_inc(struct ip_runtime *ip_rt, int thread_id)
{
    alignment_int64_array_add(ip_rt->hit_cnt, thread_id, 1);
}

long long ip_runtime_scan_hit_sum(struct ip_runtime *ip_rt, int n_thread)
{
    return alignment_int64_array_sum(ip_rt->hit_cnt, n_thread);
}