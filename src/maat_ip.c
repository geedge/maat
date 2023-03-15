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
    long long item_id;
    long long group_id;
    int addr_type;
    union {
        struct ipv4_item_rule ipv4;
        struct ipv6_item_rule ipv6;
    };
};

struct ip_runtime {
	struct ip_matcher* ip_matcher;
    struct rcu_hash_table* htable; //store ip rule for rebuild ip_matcher instance
    struct rcu_hash_table *item_htable;  //store this ip table's all maat_item which will be used in ip_runtime_scan
    uint32_t rule_num;
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
                  "[%s:%d] ip table %s has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
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

    ret = get_column_pos(line, ip_schema->saddr_format_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP,
                  "[%s:%d] ip table(table_id:%d) line:%s has no saddr_format",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    memcpy(saddr_format, (line + column_offset), column_len);
    if (IP_FORMAT_UNKNOWN == ip_format_str2int(saddr_format)) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table(table_id:%d) line:%s has invalid saddr_format, should be range/mask/CIDR",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }

    ret = get_column_pos(line, ip_schema->sip1_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table(table_id:%d) line:%s has no sip1",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    memcpy(sip1_str, (line + column_offset), column_len);

    ret = get_column_pos(line, ip_schema->sip2_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, 
                  "[%s:%d] ip table(table_id:%d) line:%s has no sip2",
                  __FUNCTION__, __LINE__, ip_schema->table_id, line);
        goto error;
    }
    memcpy(sip2_str, (line + column_offset), column_len);

    if (IPv4 == ip_item->addr_type) {
        ret = ip_format2range(ip_item->addr_type, ip_format_str2int(saddr_format), sip1_str, sip2_str, 
                              &ip_item->ipv4.min_sip, &ip_item->ipv4.max_sip);
        if (ret < 0) {
            log_error(logger, MODULE_IP, 
                      "[%s:%d] ip table(table_id:%d) line:%s ip_format2range(ip4) failed",
                      __FUNCTION__, __LINE__, ip_schema->table_id, line);
            goto error;
        }
    } else {
        //ipv6
        ret = ip_format2range(ip_item->addr_type, ip_format_str2int(saddr_format), sip1_str, sip2_str, 
                              ip_item->ipv6.min_sip, ip_item->ipv6.max_sip);
        if (ret < 0) {
            log_error(logger, MODULE_IP, 
                      "[%s:%d] ip table(table_id:%d) line:%s ip_format2range(ip6) failed",
                      __FUNCTION__, __LINE__, ip_schema->table_id, line);
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

void ip_ex_data_free(void *user_ctx, void *data)
{
    struct ip_item *item = (struct ip_item *)data;
    ip_item_free(item);
}

void *ip_runtime_new(void *ip_schema, int max_thread_num, 
                     struct maat_garbage_bin *garbage_bin,
                     struct log_handle *logger)
{
    struct ip_runtime *ip_rt = ALLOC(struct ip_runtime, 1);

    ip_rt->htable = rcu_hash_new(ip_ex_data_free);
    ip_rt->item_htable = rcu_hash_new(maat_item_free);
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

    FREE(ip_rt);
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

int ip_runtime_update_row(struct ip_runtime *ip_rt, char *key, size_t key_len, 
                          struct ip_item *item, int is_valid)
{
    void *data = NULL;
    
    if (0 == is_valid) {
        // delete
        data = rcu_hash_find(ip_rt->htable, key, key_len);
         if (NULL == data) {
            data = rcu_hash_updating_find(ip_rt->htable, key, key_len);
            if (NULL == data) {
                log_error(ip_rt->logger, MODULE_IP, 
                      "[%s:%d] the key of ip rule(rule_id:%lld) not exist, can't be deleted from ip runtime htable",
                      __FUNCTION__, __LINE__, item->item_id);
                return -1;
            } 
        }

        rcu_hash_del(ip_rt->htable, key, key_len);
    } else {
        // add
        data = rcu_hash_find(ip_rt->htable, key, key_len);
        if (data != NULL) {
            log_error(ip_rt->logger, MODULE_IP,
                      "[%s:%d] the key of ip rule(rule_id:%lld) already exist, can't be added to ip runtime htable", 
                      __FUNCTION__, __LINE__, item->item_id);
            return -1;
        }

        data = rcu_hash_updating_find(ip_rt->htable, key, key_len);
        if (data != NULL) {
            log_error(ip_rt->logger, MODULE_IP,
                      "[%s:%d] the key of ip rule(rule_id:%lld) already exist, can't be added to ip runtime htable", 
                      __FUNCTION__, __LINE__, item->item_id);
            return -1;
        }

        rcu_hash_add(ip_rt->htable, key, key_len, (void *)item);
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
    long long item_id = get_column_value(line, schema->item_id_column);
    if (item_id < 0) {
        return -1;
    }

    int is_valid = get_column_value(line, valid_column);
    //printf("<ip_runtime_update> item_id:%lld is_valid:%d\n", item_id, is_valid);
    if (is_valid < 0) {
        return -1;
    } else if (0 == is_valid) {
        //delete
        item = (struct maat_item *)rcu_hash_find(ip_rt->item_htable, 
                                                (char *)&item_id, 
                                                sizeof(item_id));
        if (NULL == item) {
            item = (struct maat_item *)rcu_hash_updating_find(ip_rt->item_htable, 
                                                             (char *)&item_id, 
                                                             sizeof(item_id));
            if (NULL == item) {
                return -1;
            }
        }

        rcu_hash_del(ip_rt->item_htable, (char *)&item_id, sizeof(item_id));
    } else {
        //add
        item = (struct maat_item *)rcu_hash_find(ip_rt->item_htable, 
                                                (char *)&item_id, sizeof(item_id));;
        if (item) {
            log_error(ip_rt->logger, MODULE_IP, 
                      "[%s:%d] ip runtime add item(item_id:%lld) to item_htable failed, already exist", 
                      __FUNCTION__, __LINE__, item_id);
            return -1;
        }

        item = (struct maat_item *)rcu_hash_updating_find(ip_rt->item_htable, 
                                                          (char *)&item_id, sizeof(item_id));;
        if (item) {
            log_error(ip_rt->logger, MODULE_IP, 
                      "[%s:%d] ip runtime add item(item_id:%lld) to item_htable failed, already exist", 
                      __FUNCTION__, __LINE__, item_id);
            return -1;
        }

        ip_item = ip_item_new(line, schema, ip_rt->logger);
        if (NULL == ip_item) {
            return -1;
        }

        u_para = maat_item_inner_new(ip_item->group_id, item_id, 0);
        item = maat_item_new(item_id, ip_item->group_id, u_para, maat_item_inner_free);
        rcu_hash_add(ip_rt->item_htable, (char *)&(item_id), sizeof(item_id), item);
    }
    
    char *key = (char *)&item_id;
    int ret = ip_runtime_update_row(ip_rt, key, sizeof(long long), ip_item, is_valid);
    if (ret < 0) {
        if (ip_item != NULL) {
            ip_item_free(ip_item);
            ip_item = NULL;
        }
        return -1;
    }

    return 0;
}

int ip_runtime_commit(void *ip_runtime, const char *table_name)
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

    struct ip_rule *rules = NULL;
    void **ex_data_array = NULL;
    size_t rule_cnt = rcu_hash_list(ip_rt->htable, &ex_data_array);
    if (rule_cnt > 0) {
        rules = ALLOC(struct ip_rule, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            struct ip_item *item = (struct ip_item *)ex_data_array[i];
            //printf("<ip_runtime_commit> item_id:%lld\n", item->item_id);
            ip_item_to_ip_rule(item, &rules[i]);
        }
    }

    log_info(ip_rt->logger, MODULE_IP,
             "table[%s] committing %zu ip rules for rebuilding ip_matcher engine",
             table_name, rule_cnt);

    int ret = 0;
    size_t mem_used = 0;
    struct ip_matcher *new_ip_matcher = NULL;
    struct ip_matcher *old_ip_matcher = NULL;

    new_ip_matcher = ip_matcher_new(rules, rule_cnt, &mem_used, ip_rt->logger);
    if (NULL == new_ip_matcher) {
        log_error(ip_rt->logger, MODULE_IP,
                  "[%s:%d] table[%s] rebuild ip_matcher engine failed when update %zu ip rules",
                  __FUNCTION__, __LINE__, table_name, rule_cnt);
        ret = -1;
    }

    old_ip_matcher = ip_rt->ip_matcher;
    ip_rt->ip_matcher = new_ip_matcher;
    if (old_ip_matcher != NULL) {
        maat_garbage_bagging(ip_rt->ref_garbage_bin, old_ip_matcher, 
                             (void (*)(void*))ip_matcher_free);
    }
    rcu_hash_commit(ip_rt->item_htable);
    ip_rt->rule_num = rule_cnt;
    
    if (rules != NULL) {
        FREE(rules);
    }
    
    if (ex_data_array != NULL) {
        FREE(ex_data_array);
    }

    return ret;
}

int ip_runtime_scan(struct ip_runtime *ip_rt, int thread_id, int ip_type, 
                    uint8_t *ip_addr, int vtable_id, struct maat_state *state)
{
    if (0 == ip_rt->rule_num) {
        //empty ip table
        return 0;
    }
    int n_hit_item = 0;
    struct scan_result scan_results[MAX_SCANNER_HIT_ITEM_NUM] = {0};

    struct ip_data scan_data;
    if (ip_type == IPv4) {
        scan_data.type = IPv4;
        scan_data.ipv4 = ntohl(*(uint32_t *)ip_addr);
    } else {
        scan_data.type = IPv6;
        for (int i = 0; i < 4; i++) {
            scan_data.ipv6[i] = *((uint32_t *)ip_addr + i);
        }
        ipv6_ntoh(scan_data.ipv6);
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

    long long hit_item_ids[MAX_SCANNER_HIT_ITEM_NUM];
    memset(hit_item_ids, 0, sizeof(hit_item_ids));
    
    for (int i = 0; i < n_hit_item; i++) {
        hit_item_ids[i] = scan_results[i].rule_id;
    }

    size_t group_hit_cnt = 0;
    int ret = maat_compile_state_update(ip_rt->item_htable, vtable_id, hit_item_ids, n_hit_item,
                                        &group_hit_cnt, state);
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
