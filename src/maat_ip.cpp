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

#include "utils.h"
#include "log/log.h"
#include "cJSON/cJSON.h"
#include "utils.h"
#include "maat_utils.h"
#include "maat_ex_data.h"
#include "IPMatcher.h"
#include "maat_ip.h"
#include "maat_rule.h"
#include "maat_compile.h"
#include "maat_garbage_collection.h"

#define MODULE_IP	 module_name_str("maat.ip")

struct port_range {
    uint16_t min_port;
    uint16_t max_port;
};

struct ip_plus_schema {
    int item_id_column;
    int group_id_column;
    int addr_type_column;
    int saddr_format_column;
    int sip1_column;
    int sip2_column;
    int sport_format_column;
    int sport1_column;
    int sport2_column;
    int daddr_format_column;
    int dip1_column;
    int dip2_column;
    int dport_format_column;
    int dport1_column;
    int dport2_column;
    int proto_column;
    int direction_column;
    int table_id; //ugly
};

struct ipv4_item_rule {
    uint32_t min_sip;   /* 源地址下界；0表示忽略本字段 */
    uint32_t max_sip;   /* 源地址上界；0表示固定IP=min_saddr */
    uint16_t min_sport; /* 源端口范围下界；0表示忽略本字段 */
    uint16_t max_sport; /* 源端口范围上界；0表示固定端口=min_sport */
    uint16_t proto;     /* 传输层协议，6表示TCP，17表示UDP；0表示忽略本字段 */
    uint16_t direction; /* 方向，0表示双向，1表示单向 */
};

struct ipv6_item_rule {
    uint32_t min_sip[4]; /* 源地址下界；全0表示忽略本字段 */
    uint32_t max_sip[4]; /* 源地址上界；全0表示固定IP=min_saddr */
    uint16_t min_sport;  /* 源端口范围下界；0表示忽略本字段 */
    uint16_t max_sport;  /* 源端口范围上界；0表示固定端口=min_sport */
    uint16_t proto;      /* 传输层协议，6表示TCP，17表示UDP，无限制默认为0 */
    uint16_t direction;  /* 方向，0表示双向，1表示单向 */
};

struct ip_plus_item {
    int item_id;
    int group_id;
    int addr_type;
    union {
        struct ipv4_item_rule ipv4;
        struct ipv6_item_rule ipv6;
    };
};

struct ip_plus_runtime {
	struct ip_matcher* ip_matcher;
    struct ex_data_runtime* ex_data_rt;

    uint32_t rule_num;
    uint32_t updating_rule_num;
    struct maat_item *item_hash;
    void (*item_user_data_free)(void *);

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

void *ip_plus_schema_new(cJSON *json, const char *table_name, struct log_handle *logger)
{
    size_t read_cnt = 0;
    struct ip_plus_schema *ip_plus_schema = ALLOC(struct ip_plus_schema, 1);

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        ip_plus_schema->table_id = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (NULL == item || item->type != cJSON_Object) {
        log_error(logger, MODULE_IP, "ip_plus table %s has no custom column", table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->item_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->group_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "addr_type");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->addr_type_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "saddr_format");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->saddr_format_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "sip1");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->sip1_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "sip2");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->sip2_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "sport_format");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->sport_format_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "sport1");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->sport1_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "sport2");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->sport2_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "daddr_format");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->daddr_format_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "dip1");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->dip1_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "dip2");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->dip2_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "dport_format");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->dport_format_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "dport1");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->dport1_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "dport2");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->dport2_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "proto");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->proto_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "direction");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        ip_plus_schema->direction_column = custom_item->valueint;
        read_cnt++;
    }

    if (read_cnt < 18) {
        goto error;
    }

    return ip_plus_schema;
error:
    FREE(ip_plus_schema);
    return NULL;
}

void ip_plus_schema_free(void *ip_plus_schema)
{
    FREE(ip_plus_schema);
}

void *ip_plus_runtime_new(void *ip_plus_schema, int max_thread_num, struct maat_garbage_bin *garbage_bin,
                          struct log_handle *logger)
{
    if (NULL == ip_plus_schema) {
        return NULL;
    }

    struct ip_plus_schema *schema = (struct ip_plus_schema *)ip_plus_schema;
    struct ip_plus_runtime *ip_plus_rt = ALLOC(struct ip_plus_runtime, 1);

    ip_plus_rt->ex_data_rt = ex_data_runtime_new(schema->table_id, ex_data_container_free, logger);
    ip_plus_rt->item_user_data_free = maat_item_inner_free;
    ip_plus_rt->ref_garbage_bin = garbage_bin;
    ip_plus_rt->logger = logger;

    return ip_plus_rt;
}

void ip_plus_runtime_free(void *ip_plus_runtime)
{
    if (NULL == ip_plus_runtime) {
        return;
    }

    struct ip_plus_runtime *ip_plus_rt = (struct ip_plus_runtime *)ip_plus_runtime;
    if (ip_plus_rt->ip_matcher != NULL) {
        ip_matcher_free(ip_plus_rt->ip_matcher);
    }

    if (ip_plus_rt->ex_data_rt != NULL) {
        ex_data_runtime_free(ip_plus_rt->ex_data_rt);
    }

    struct maat_item *item = NULL, *tmp_item = NULL;
    HASH_ITER(hh, ip_plus_rt->item_hash, item, tmp_item) {
        HASH_DELETE(hh, ip_plus_rt->item_hash, item);
        maat_item_free(item, ip_plus_rt->item_user_data_free);
    }

    FREE(ip_plus_rt);
}

struct ip_plus_item *ip_plus_item_new(const char *line, struct ip_plus_schema *ip_plus_schema,
                                      struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    char saddr_format[16] = {0};
    char sport_format[16] = {0};
    char sip1_str[40] = {0};
    char sip2_str[40] = {0};
    uint16_t sport1 = 0;
    uint16_t sport2 = 0;
    uint16_t protocol = 0;
    uint16_t direction = 0;
    struct ip_plus_item *ip_plus_item = ALLOC(struct ip_plus_item, 1);

    int ret = get_column_pos(line, ip_plus_schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, "ip plus table(table_id:%d) line:%s has no item_id",
                  ip_plus_schema->table_id, line);
        goto error;
    }
    ip_plus_item->item_id = atoi(line + column_offset);

    ret = get_column_pos(line, ip_plus_schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, "ip plus table(table_id:%d) line:%s has no group_id",
                  ip_plus_schema->table_id, line);
        goto error;
    }
    ip_plus_item->group_id = atoi(line + column_offset);

    ret = get_column_pos(line, ip_plus_schema->addr_type_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, "ip plus table(table_id:%d) line:%s has no addr_type",
                  ip_plus_schema->table_id, line);
        goto error;
    }
    ip_plus_item->addr_type = atoi(line + column_offset);

    if (ip_plus_item->addr_type != 4 && ip_plus_item->addr_type != 6) {
        log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s has invalid addr type:%d",
                  ip_plus_schema->table_id, line, ip_plus_item->addr_type);
        goto error;
    }

    ret = get_column_pos(line, ip_plus_schema->saddr_format_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s has no saddr_format",
                  ip_plus_schema->table_id, line);
        goto error;
    }
    memcpy(saddr_format, (line + column_offset), column_len);
    if (IP_FORMAT_UNKNOWN == ip_format_str2int(saddr_format)) {
        log_error(logger, MODULE_IP, 
                  "ip_plus table(table_id:%d) line:%s has invalid saddr_format, should be range/mask/CIDR",
                  ip_plus_schema->table_id, line);
        goto error;
    }

    ret = get_column_pos(line, ip_plus_schema->sip1_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s has no sip1",
                  ip_plus_schema->table_id, line);
        goto error;
    }
    memcpy(sip1_str, (line + column_offset), column_len);

    ret = get_column_pos(line, ip_plus_schema->sip2_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s has no sip2",
                  ip_plus_schema->table_id, line);
        goto error;
    }
    memcpy(sip2_str, (line + column_offset), column_len);

    ret = get_column_pos(line, ip_plus_schema->sport_format_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s has no sport_format",
                  ip_plus_schema->table_id, line);
        goto error;
    }
    memcpy(sport_format, (line + column_offset), column_len);
    if (IP_FORMAT_UNKNOWN == ip_format_str2int(sport_format)) {
        log_error(logger, MODULE_IP, 
                  "ip_plus table(table_id:%d) line:%s has invalid sport_format, should be range/mask/CIDR",
                  ip_plus_schema->table_id, line);
        goto error;
    }

    ret = get_column_pos(line, ip_plus_schema->sport1_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s has no sport1",
                  ip_plus_schema->table_id, line);
        goto error;
    }
    sport1 = atoi(line + column_offset);

    ret = get_column_pos(line, ip_plus_schema->sport2_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s has no sport2",
                  ip_plus_schema->table_id, line);
        goto error;
    }
    sport2 = atoi(line + column_offset);

    if (4 == ip_plus_item->addr_type) {
        ret = ip_format2range(ip_plus_item->addr_type, ip_format_str2int(saddr_format), sip1_str, sip2_str, 
                              &ip_plus_item->ipv4.min_sip, &ip_plus_item->ipv4.max_sip);
        if (ret < 0) {
            log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s ip_format2range(ip4) failed",
                      ip_plus_schema->table_id, line);
            goto error;
        }

        if(IP_FORMAT_MASK == ip_format_str2int(sport_format)) {
            ip_plus_item->ipv4.min_sport = sport1 & sport2;
            ip_plus_item->ipv4.max_sport = sport1 | ~sport2;
        } else {
            ip_plus_item->ipv4.min_sport = sport1;
			ip_plus_item->ipv4.max_sport = sport2;
        }

        ret = get_column_pos(line, ip_plus_schema->proto_column, &column_offset, &column_len);
        if (ret < 0) {
            log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s has no proto",
                      ip_plus_schema->table_id, line);
            goto error;
        }
        ip_plus_item->ipv4.proto = atoi(line + column_offset);
        protocol = ip_plus_item->ipv4.proto;

        ret = get_column_pos(line, ip_plus_schema->direction_column, &column_offset, &column_len);
        if (ret < 0) {
            log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s has no direction",
                      ip_plus_schema->table_id, line);
            goto error;
        }
        ip_plus_item->ipv4.direction = atoi(line + column_offset);
        direction = ip_plus_item->ipv4.direction;
    } else {
        //ipv6
        ret = ip_format2range(ip_plus_item->addr_type, ip_format_str2int(saddr_format), sip1_str, sip2_str, 
                              ip_plus_item->ipv6.min_sip, ip_plus_item->ipv6.max_sip);
        if (ret < 0) {
            log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s ip_format2range(ip6) failed",
                      ip_plus_schema->table_id, line);
            goto error;
        }

        if(IP_FORMAT_MASK == ip_format_str2int(sport_format)) {
            ip_plus_item->ipv6.min_sport = sport1 & sport2;
            ip_plus_item->ipv6.max_sport = sport1 | ~sport2;
        } else {
            ip_plus_item->ipv6.min_sport = sport1;
			ip_plus_item->ipv6.max_sport = sport2;
        }

        ret = get_column_pos(line, ip_plus_schema->proto_column, &column_offset, &column_len);
        if (ret < 0) {
            log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s has no proto",
                      ip_plus_schema->table_id, line);
            goto error;
        }
        ip_plus_item->ipv6.proto = atoi(line + column_offset);
        protocol = ip_plus_item->ipv6.proto;

        ret = get_column_pos(line, ip_plus_schema->direction_column, &column_offset, &column_len);
        if (ret < 0) {
            log_error(logger, MODULE_IP, "ip_plus table(table_id:%d) line:%s has no direction",
                      ip_plus_schema->table_id, line);
            goto error;
        }
        ip_plus_item->ipv6.direction = atoi(line + column_offset);
        direction = ip_plus_item->ipv6.direction;
    }

    if (protocol > 65535 || protocol < 0) {
        log_error(logger, MODULE_IP, 
                  "ip_plus table(table_id:%d) line:%s has invalid proto:%d",
                  ip_plus_schema->table_id, line, protocol);
        goto error;
    }

    if (direction != 0 && direction != 1) {
        log_error(logger, MODULE_IP, 
                  "ip_plus table(table_id:%d) line:%s has invalid direction:%d",
                  ip_plus_schema->table_id, line, direction);
        goto error;
    }

    return ip_plus_item;
error:
    FREE(ip_plus_item);
    return NULL;
}

void ip_plus_item_free(struct ip_plus_item *ip_plus_item)
{
    FREE(ip_plus_item);
}

void ip_plus_item_to_ip_rule(struct ip_plus_item *item, struct ip_rule *rule)
{
    struct port_range *sport_range = ALLOC(struct port_range, 1);
    if (4 == item->addr_type) {
        rule->type = IPv4;
        sport_range->min_port = item->ipv4.min_sport;
        sport_range->max_port = item->ipv4.max_sport;
        rule->ipv4_rule.start_ip = item->ipv4.min_sip;
        rule->ipv4_rule.end_ip = item->ipv4.max_sip;
    } else {
        rule->type = IPv6;
        sport_range->min_port = item->ipv6.min_sport;
        sport_range->max_port = item->ipv6.max_sport;
        memcpy(rule->ipv6_rule.start_ip, item->ipv6.min_sip, sizeof(item->ipv6.min_sip));
        memcpy(rule->ipv6_rule.end_ip, item->ipv6.max_sip, sizeof(item->ipv6.max_sip));
    }
    rule->rule_id = item->item_id;
    rule->user_tag = sport_range;
}

struct ex_data_runtime *ip_plus_runtime_get_ex_data_rt(struct ip_plus_runtime *ip_plus_rt)
{
    return ip_plus_rt->ex_data_rt;
}

int ip_plus_runtime_update_row(struct ip_plus_runtime *rt, char *key, size_t key_len, 
                                struct ip_plus_item *item, int is_valid)
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

int ip_plus_runtime_updating_flag(void *ip_plus_runtime)
{
    struct ip_plus_runtime *ip_plus_rt = (struct ip_plus_runtime *)ip_plus_runtime;
    return ex_data_runtime_updating_flag(ip_plus_rt->ex_data_rt);
}

int ip_plus_runtime_update(void *ip_plus_runtime, void *ip_plus_schema, const char *line,
                           int valid_column)
{
    if (NULL == ip_plus_runtime || NULL == ip_plus_schema || NULL == line) {
        return -1;
    }

    struct maat_item *item = NULL;
    struct ip_plus_item *ip_plus_item = NULL;
    struct maat_item_inner *u_para = NULL;
    struct ip_plus_schema *schema = (struct ip_plus_schema *)ip_plus_schema;
    struct ip_plus_runtime *ip_plus_rt = (struct ip_plus_runtime *)ip_plus_runtime;
    int item_id = get_column_value(line, schema->item_id_column);
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    } else if (0 == is_valid) {
        //delete
        HASH_FIND_INT(ip_plus_rt->item_hash, &item_id, item);
        if (NULL == item) {
            return -1;
        }
        
        u_para = (struct maat_item_inner *)item->user_data;
        item->user_data = NULL;
        
	    if (NULL == u_para) {
		    return -1;
	    }

        HASH_DELETE(hh, ip_plus_rt->item_hash, item);
        maat_garbage_bagging(ip_plus_rt->ref_garbage_bin, u_para, (void (*)(void *))maat_item_inner_free);
    } else {
        //add
        HASH_FIND_INT(ip_plus_rt->item_hash, &item_id, item);
        if (item) {
            log_error(ip_plus_rt->logger, MODULE_IP, 
                      "ip_plus runtime add item %d to item_hash failed, already exist", item_id);
            return -1;
        }

        ip_plus_item = ip_plus_item_new(line, schema, ip_plus_rt->logger);
        if (NULL == ip_plus_item) {
            return -1;
        }

        u_para = maat_item_inner_new(ip_plus_item->group_id, item_id, 0);
        item = maat_item_new(item_id, ip_plus_item->group_id, u_para);
        HASH_ADD_INT(ip_plus_rt->item_hash, item_id, item);
    }
    
    char *key = (char *)&item_id;
    int ret = ip_plus_runtime_update_row(ip_plus_rt, key, sizeof(int), ip_plus_item, is_valid);
    if (ret < 0) {
        if (ip_plus_item != NULL) {
            ip_plus_item_free(ip_plus_item);
            ip_plus_item = NULL;
        }
        return -1;
    } else {
        if (0 == is_valid) {
            ip_plus_rt->rule_num--;
        } else {
            ip_plus_rt->rule_num++;
        }
    }

    return 0;
}

int ip_plus_runtime_commit(void *ip_plus_runtime)
{
    if (NULL == ip_plus_runtime) {
        return -1;
    }

    int ret = 0;
    struct ex_data_container **ex_container = NULL;
    struct ip_plus_runtime *ip_plus_rt = (struct ip_plus_runtime *)ip_plus_runtime;
    struct ex_data_runtime *ex_data_rt = ip_plus_rt->ex_data_rt;

    size_t rule_cnt = ex_data_runtime_list_updating_ex_container(ex_data_rt, &ex_container);
    if (0 == rule_cnt) {
        FREE(ex_container);
        return 0;
    }

    struct ip_rule *rules = ALLOC(struct ip_rule, rule_cnt);

    for (size_t i = 0; i < rule_cnt; i++) {
        struct ip_plus_item *item = (struct ip_plus_item *)ex_container[i]->custom_data;
        ip_plus_item_to_ip_rule(item, &rules[i]);
    }

    struct ip_matcher *new_ip_matcher = NULL;
    struct ip_matcher *old_ip_matcher = NULL;
    size_t mem_used = 0;

    if (rule_cnt > 0) {
        log_info(ip_plus_rt->logger, MODULE_IP, 
                 "committing %zu ip_plus rules for rebuilding ip_matcher engine", rule_cnt);
        new_ip_matcher = ip_matcher_new(rules, rule_cnt, &mem_used);
        if (NULL == new_ip_matcher) {
            log_error(ip_plus_rt->logger, MODULE_IP, 
                      "rebuild ip_matcher engine failed when update %zu ip_plus rules", rule_cnt);
            ret = -1;
        }
    }

    old_ip_matcher = ip_plus_rt->ip_matcher;
    ip_plus_rt->ip_matcher = new_ip_matcher;
    maat_garbage_bagging(ip_plus_rt->ref_garbage_bin, old_ip_matcher, (void (*)(void*))ip_matcher_free);
    ex_data_runtime_commit(ex_data_rt);
    ip_plus_rt->rule_num = ex_data_runtime_ex_container_count(ex_data_rt);

    FREE(rules);
    FREE(ex_container);

    return ret;
}

int ip_plus_runtime_scan_ipv4(struct ip_plus_runtime *ip_plus_rt, int thread_id, uint32_t ip_addr, 
                          int *group_id_array, size_t n_group_id_array, int virtual_table_id,
                          struct maat_state *state)
{
    if (NULL == ip_plus_rt) {
        return -1;
    }

    int n_hit_item = 0;
    struct scan_result scan_results[MAX_SCANNER_HIT_ITEM_NUM] = {0};

    struct ip_data ip;
    ip.type = IPv4;
    ip.ipv4 = ip_addr;
   
    n_hit_item = ip_matcher_match(ip_plus_rt->ip_matcher, &ip, scan_results, MAX_SCANNER_HIT_ITEM_NUM);
    if (n_hit_item > MAX_SCANNER_HIT_ITEM_NUM) {
        n_hit_item = MAX_SCANNER_HIT_ITEM_NUM;
    }

    struct maat_compile_state *compile_state = state->compile_mid;
    //tranform item_id to group_id
    struct maat_item *item = NULL;
    size_t n_group_id = 0;
    int i = 0;
    for (i = 0; i < n_hit_item; i++) {
        HASH_FIND_INT(ip_plus_rt->item_hash, &(scan_results[i].rule_id), item);
        assert(item != NULL);
        if (!item) {
            // should not come here
            continue;
        }

        if (n_group_id >= n_group_id_array) {
            n_group_id = n_group_id_array;
            //Prevent group_id_array out of bounds
        } else {
            group_id_array[n_group_id++] = item->group_id;
        }

        // update hit path
        maat_compile_state_update_hit_path(compile_state, scan_results[i].rule_id, item->group_id,
                                           virtual_table_id, state->scan_cnt, i);
    }

    // update hit clause: literal_id{group_id,vt_id} to clause_id
    int compile_table_id = -1;
    if (state->compile_table_id == -1) {
        compile_table_id = state->maat_instance->default_compile_table_id;
    } else {
        compile_table_id = state->compile_table_id;
    }

    void *compile_rt = table_manager_get_runtime(state->maat_instance->tbl_mgr, compile_table_id);
    enum table_type table_type = table_manager_get_table_type(state->maat_instance->tbl_mgr, compile_table_id);
    assert(table_type == TABLE_TYPE_COMPILE);
    
    for (size_t idx = 0; idx < n_group_id; idx++) {
        maat_compile_state_update_hit_clause(compile_state, compile_rt, group_id_array[idx], virtual_table_id);
    }

    return n_group_id;
}