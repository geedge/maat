/*
**********************************************************************************************
*	File: maat_ip.c
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <stdint.h>
#include <assert.h>

#include "log/log.h"
#include "maat_utils.h"
#include "maat_ex_data.h"
#include "ip_matcher.h"
#include "maat_ip.h"
#include "maat_core.h"
#include "maat_rule.h"
#include "alignment.h"
#include "maat_garbage_collection.h"

#define MODULE_IP	 module_name_str("maat.ip")

struct ip_schema {
    int table_id;
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
    uuid_t item_uuid;
    uuid_t object_uuid;
    int addr_type;
    union {
        struct ipv4_item_rule ipv4;
        struct ipv6_item_rule ipv6;
    };
    int port_start;
    int port_end;
};

struct ip_runtime {
	struct ip_matcher *ip_matcher;
    struct rcu_hash_table *item_hash;  // <item_id, struct ip_item>

    long long rule_num;
    long long ipv6_rule_num;
    size_t n_worker_thread;
    struct log_handle *logger;
    struct maat_garbage_bin *ref_garbage_bin;
    
    long long *scan_times;
    long long *scan_cpu_time;

    long long *hit_times;
    long long *hit_item_num;

    long long update_err_cnt;
};

void *ip_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                    const char *table_name, struct log_handle *logger)
{
    struct ip_schema *ip_schema = ALLOC(struct ip_schema, 1);

    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        ip_schema->table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_IP, 
                  "[%s:%d] ip table:<%s> schema has no table_id column", 
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

static struct ip_item *
ip_item_new(struct ip_schema *ip_schema, const char *table_name,
            const cJSON *json, struct log_handle *logger, uuid_t item_uuid)
{
    char ip_str[128] = {0};
    struct ip_item *ip_item = ALLOC(struct ip_item, 1);
    cJSON *tmp_obj = NULL;
    int ret = 0;
    
    uuid_copy(ip_item->item_uuid, item_uuid);

    tmp_obj = cJSON_GetObjectItem(json, "object_uuid");
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(logger, MODULE_IP, 
                  "[%s:%d] ip table:<%s> has no object_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
        goto error;
    }
    uuid_parse(tmp_obj->valuestring, ip_item->object_uuid);

    tmp_obj = cJSON_GetObjectItem(json, "ip");
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(logger, MODULE_IP, 
                  "[%s:%d] ip table:<%s> has no ip in line:%s",
                  __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
        goto error;
    }
    memcpy(ip_str, tmp_obj->valuestring, strlen(tmp_obj->valuestring));

    if (strchr(ip_str, ':') != NULL) {
		ip_item->addr_type = IPV6;
	} else {
		ip_item->addr_type = IPV4;
    }

    if (IPv4 == ip_item->addr_type) {
        ret = ip_format2range(ip_str, ip_item->addr_type, &ip_item->ipv4.min_ip, &ip_item->ipv4.max_ip);
        if (ret < 0) {
            log_fatal(logger, MODULE_IP, 
                      "[%s:%d] ip table:<%s> ip_format2range(ip4) failed in line:%s",
                      __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
            goto error;
        }
    } else {
        //ipv6
        ret = ip_format2range(ip_str, ip_item->addr_type, ip_item->ipv6.min_ip, ip_item->ipv6.max_ip);
        if (ret < 0) {
            log_fatal(logger, MODULE_IP, 
                      "[%s:%d] ip table:<%s> ip_format2range(ip6) failed in line:%s",
                      __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
            goto error;
        }
    }

    tmp_obj = cJSON_GetObjectItem(json, "port");
    if(tmp_obj && tmp_obj->type == cJSON_String)
    {
        char port_range[20] = {0};
        memcpy(port_range, tmp_obj->valuestring, strlen(tmp_obj->valuestring));

        //port range is port or port_start-port_end
        if(strchr(port_range,'-')!=NULL){
            char *saveptr = NULL;
            char *port_start = strtok_r(port_range,"-", &saveptr);
            char *port_end = strtok_r(NULL,"-", &saveptr);
            ip_item->port_start = atoi(port_start);
            ip_item->port_end = atoi(port_end);
        } else {
            ip_item->port_start = atoi(port_range);
            ip_item->port_end = atoi(port_range);
        }
    } else {
        ip_item->port_start = 0;
        ip_item->port_end = 65535;
    }
    return ip_item;
error:
    FREE(ip_item);
    return NULL;
}

static void ip_item_free(struct ip_item *item)
{
    if (NULL == item) {
        return;
    }
    
    FREE(item);
}

static void ip_item_free_cb(void *user_ctx, void *data)
{
    struct ip_item *item = (struct ip_item *)data;
    ip_item_free(item);
}

void *ip_runtime_new(void *ip_schema, size_t max_thread_num,
                     struct maat_garbage_bin *garbage_bin, 
                     struct log_handle *logger)
{
    if (NULL == ip_schema) {
        return NULL;
    }

    struct ip_runtime *ip_rt = ALLOC(struct ip_runtime, 1);
    ip_rt->item_hash = rcu_hash_new(ip_item_free_cb, NULL, 0);
    ip_rt->n_worker_thread = max_thread_num;
    ip_rt->ref_garbage_bin = garbage_bin;
    ip_rt->logger = logger;

    ip_rt->scan_times = alignment_int64_array_alloc(max_thread_num);
    ip_rt->scan_cpu_time = alignment_int64_array_alloc(max_thread_num);

    ip_rt->hit_times = alignment_int64_array_alloc(max_thread_num);
    ip_rt->hit_item_num = alignment_int64_array_alloc(max_thread_num);

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

    if (ip_rt->item_hash != NULL) {
        rcu_hash_free(ip_rt->item_hash);
        ip_rt->item_hash = NULL;
    }

    if (ip_rt->scan_times != NULL) {
        alignment_int64_array_free(ip_rt->scan_times);
        ip_rt->scan_times = NULL;
    }

    if (ip_rt->scan_cpu_time != NULL) {
        alignment_int64_array_free(ip_rt->scan_cpu_time);
        ip_rt->scan_cpu_time = NULL;
    }

    if (ip_rt->hit_times != NULL) {
        alignment_int64_array_free(ip_rt->hit_times);
        ip_rt->hit_times = NULL;
    }

   if (ip_rt->hit_item_num != NULL) {
        alignment_int64_array_free(ip_rt->hit_item_num);
        ip_rt->hit_item_num = NULL;
    }

    FREE(ip_rt);
}

static void ip_item_to_ip_rule(struct ip_item *item, struct ip_rule *rule)
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
    uuid_copy(rule->rule_uuid, item->item_uuid);
}

static int ip_runtime_update_row(struct ip_runtime *ip_rt, char *key, size_t key_len, 
                                 struct ip_item *item, enum maat_operation op)
{
    int ret = -1;
    
    if (MAAT_OP_DEL == op) {
        // delete
        rcu_hash_del(ip_rt->item_hash, key, key_len);
    } else {
        // add
        ret = rcu_hash_add(ip_rt->item_hash, key, key_len, (void *)item);
        if (ret < 0) {
            char uuid_str[37] = {0};
            uuid_unparse(item->item_uuid, uuid_str);
            log_debug(ip_rt->logger, MODULE_IP,
                      "[%s:%d] ip item(item_id:%s) add to ip runtime htable failed", 
                      __FUNCTION__, __LINE__, uuid_str);
            return -1;
        }
    }

    return 0;
}

int ip_runtime_update(void *ip_runtime, void *ip_schema, 
                      const char *table_name, const char *line, 
                      enum maat_operation op)
{
    if (NULL == ip_runtime || NULL == ip_schema || NULL == line) {
        return -1;
    }

    struct ip_schema *schema = (struct ip_schema *)ip_schema;
    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    cJSON *json = NULL;
    cJSON *tmp_obj = NULL;
    
    json = cJSON_Parse(line);
    if (NULL == json) {
        log_fatal(ip_rt->logger, MODULE_IP,
                  "[%s:%d] ip table:<%s> line is not a valid json string",
                  __FUNCTION__, __LINE__, table_name);
        ip_rt->update_err_cnt++;
        goto ERROR;
    }

    tmp_obj = cJSON_GetObjectItem(json, "uuid");
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(ip_rt->logger, MODULE_IP,
                  "[%s:%d] ip table:<%s> has no item_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
        ip_rt->update_err_cnt++;
        goto ERROR;
    }

    uuid_t item_uuid;
    uuid_parse(tmp_obj->valuestring, item_uuid);
    
    struct ip_item *ip_item = NULL;
    if (MAAT_OP_ADD == op) {
        //add
        ip_item = ip_item_new(schema, table_name, json, ip_rt->logger, item_uuid);
        if (NULL == ip_item) {
            ip_rt->update_err_cnt++;
            goto ERROR;
        }
    }
    
    int ret = ip_runtime_update_row(ip_rt, (char *)&item_uuid, sizeof(uuid_t),
                                    ip_item, op);
    if (ret < 0) {
        if (ip_item != NULL) {
            ip_item_free(ip_item);
        }
        //don't return failed, ignore the case of adding duplicate keys
    }

    cJSON_Delete(json);
    return 0;
ERROR:
    if (json != NULL) {
        cJSON_Delete(json);
    }
    return -1;
}

void garbage_ip_matcher_free(void *ip_matcher, void *arg)
{
    struct ip_matcher *matcher = (struct ip_matcher *)ip_matcher;
    ip_matcher_free(matcher);
}

int ip_runtime_commit(void *ip_runtime, const char *table_name,
                      long long maat_rt_version)
{
    if (NULL == ip_runtime) {
        return -1;
    }

    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;

    int updating_flag = rcu_hash_is_updating(ip_rt->item_hash);
    if (0 == updating_flag) {
        return 0;
    }

    ip_rt->ipv6_rule_num = 0;

    struct ip_rule *rules = NULL;
    void **ex_data_array = NULL;

    size_t rule_cnt = rcu_updating_hash_list(ip_rt->item_hash, &ex_data_array);
    if (rule_cnt > 0) {
        rules = ALLOC(struct ip_rule, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            struct ip_item *item = (struct ip_item *)ex_data_array[i];
            if (item->addr_type == IPv6) {
                ip_rt->ipv6_rule_num++;
            }

            ip_item_to_ip_rule(item, &rules[i]);
        }
    }

    int ret = 0;
    size_t mem_used = 0;
    struct ip_matcher *new_ip_matcher = NULL;
    struct ip_matcher *old_ip_matcher = NULL;

    if (rule_cnt > 0) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        new_ip_matcher = ip_matcher_new(rules, rule_cnt, &mem_used);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                                   (end.tv_nsec - start.tv_nsec) / 1000000;

        if (NULL == new_ip_matcher) {
            log_fatal(ip_rt->logger, MODULE_IP,
                      "[%s:%d] table[%s] rebuild ip_matcher engine failed "
                      "when update %zu ip rules", __FUNCTION__, __LINE__,
                      table_name, rule_cnt);
            ret = -1;
        } else {
            log_info(ip_rt->logger, MODULE_IP,
                     "table[%s] commit %zu ip rules and rebuild ip_matcher completed"
                     ", version:%lld, consume:%lldms", table_name, rule_cnt,
                     maat_rt_version, time_elapse_ms);
        }
    }

    old_ip_matcher = ip_rt->ip_matcher;
    ip_rt->ip_matcher = new_ip_matcher;
    rcu_hash_commit(ip_rt->item_hash);

    if (old_ip_matcher != NULL) {
        maat_garbage_bagging(ip_rt->ref_garbage_bin, old_ip_matcher, NULL,
                             garbage_ip_matcher_free);
    }

    ip_rt->rule_num = rule_cnt;
    
    if (rules != NULL) {
        FREE(rules);
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

int ip_runtime_scan(struct ip_runtime *ip_rt, int thread_id, int ip_type, 
                    uint8_t *ip_addr, int port, int attribute_id, struct maat_state *state)
{
    //clear rule_state->last_hit_object
    if (state != NULL && state->rule_compile_state != NULL) {
        rule_compile_state_clear_last_hit_object(state->rule_compile_state);
    }

    if (0 == ip_rt->rule_num) {
        //empty ip table
        return 0;
    }
    
    if (NULL == ip_rt->ip_matcher) {
        return 0;
    }

    struct ip_data scan_data;
    struct scan_result ip_results[MAX_HIT_ITEM_NUM];

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

    size_t real_hit_item_cnt = 0;
    struct maat_item hit_maat_items[MAX_HIT_ITEM_NUM];

    int n_hit_ip_item = ip_matcher_match(ip_rt->ip_matcher, &scan_data,
                                         ip_results, MAX_HIT_ITEM_NUM);
    if (n_hit_ip_item < 0) {
        return -1;
    }

    if (0 == n_hit_ip_item) {
        goto next;
    }

    for (size_t i = 0; i < n_hit_ip_item; i++) {
        struct ip_item *ip_item = (struct ip_item *)rcu_hash_find(ip_rt->item_hash,
                                                                 (char *)&ip_results[i].rule_uuid,
                                                                 sizeof(uuid_t));
        if (!ip_item) {
            // item config has been deleted
            continue;
        }

        if (port < 0 && ip_item->port_start != 0 && ip_item->port_end != 65535) {
            //If port is not speicified, an IP should NOT match rules with port range.
            continue;
        }

        if (port >= 0 && (port < ip_item->port_start || port > ip_item->port_end)) {
            //If port is specified, the port should within the port range.
            continue;
        }
        
        uuid_copy(hit_maat_items[real_hit_item_cnt].item_uuid, ip_item->item_uuid);
        uuid_copy(hit_maat_items[real_hit_item_cnt].object_uuid, ip_item->object_uuid);
        real_hit_item_cnt++;
    }

    if (real_hit_item_cnt > 0) {
        alignment_int64_array_add(ip_rt->hit_item_num, state->thread_id,
                                  real_hit_item_cnt);
    }
next:
    if (NULL == state->rule_compile_state) {
        state->rule_compile_state = rule_compile_state_new();
        alignment_int64_array_add(state->maat_inst->stat->rule_state_cnt,
                                  state->thread_id, 1);
    }

    return rule_compile_state_update(state->rule_compile_state, state->maat_inst, attribute_id,
                                state->rule_table_id, state->Nth_scan,
                                hit_maat_items, real_hit_item_cnt);
}

void ip_runtime_perf_stat(struct ip_runtime *ip_rt, struct timespec *start,
                          struct timespec *end, int thread_id)
{
    if (NULL == ip_rt || thread_id < 0) {
        return;
    }

    if (start != NULL && end != NULL) {
        long long consume_time = (end->tv_sec - start->tv_sec) * 1000000000 +
                                 (end->tv_nsec - start->tv_nsec);
        alignment_int64_array_add(ip_rt->scan_cpu_time, thread_id, consume_time);
    }
}

void ip_runtime_scan_times_inc(struct ip_runtime *ip_rt, int thread_id)
{
    if (NULL == ip_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(ip_rt->scan_times, thread_id, 1);
}

long long ip_runtime_scan_times(void *ip_runtime)
{
    if (NULL == ip_runtime) {
        return 0;
    }

    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    long long sum = alignment_int64_array_sum(ip_rt->scan_times,
                                              ip_rt->n_worker_thread);
    alignment_int64_array_reset(ip_rt->scan_times,
                                ip_rt->n_worker_thread);

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

void ip_runtime_hit_times_inc(struct ip_runtime *ip_rt, int thread_id)
{
    if (NULL == ip_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(ip_rt->hit_times, thread_id, 1);
}

long long ip_runtime_hit_times(void *ip_runtime)
{
    if (NULL == ip_runtime) {
        return 0;
    }

    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    long long sum = alignment_int64_array_sum(ip_rt->hit_times,
                                              ip_rt->n_worker_thread);
    alignment_int64_array_reset(ip_rt->hit_times,
                                ip_rt->n_worker_thread);

    return sum;
}

long long ip_runtime_hit_item_num(void *ip_runtime)
{
    if (NULL == ip_runtime) {
        return 0;
    }

    struct ip_runtime *ip_rt = (struct ip_runtime *)ip_runtime;
    long long sum = alignment_int64_array_sum(ip_rt->hit_item_num,
                                              ip_rt->n_worker_thread);
    alignment_int64_array_reset(ip_rt->hit_item_num,
                                ip_rt->n_worker_thread);

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
