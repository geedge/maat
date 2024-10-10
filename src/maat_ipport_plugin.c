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
#include "uthash/utarray.h"
#include "maat_ipport_plugin.h"
#include "ipport_matcher.h"
#include "interval_matcher.h"
#include "maat_core.h"
#include "maat_garbage_collection.h"

#define MODULE_IPPORT_PLUGIN	 module_name_str("maat.ipport_plugin")

struct ipport_plugin_schema {
    int gc_timeout_s;
    int table_id;
    char key_name[MAX_NAME_STR_LEN];
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
    uuid_t item_uuid;
    int ip_type; //IPV4 or IPV6
    union {
        struct ipv4_item ipv4;
        struct ipv6_item ipv6;
    };
    uint16_t min_port;
    uint16_t max_port;
};

struct ipport_plugin_runtime {
    struct ipport_matcher *matcher;
    struct ex_data_runtime *ex_data_rt;
    size_t n_worker_thread;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;

    long long rule_num;
    long long update_err_cnt;
    long long *scan_times;
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
        log_fatal(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table:<%s> schema has no"
                  " table_id column", __FUNCTION__, __LINE__,
                  table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (NULL == item || item->type != cJSON_Object) {
        log_fatal(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table:<%s> schema has no"
                  " custom column", __FUNCTION__, __LINE__,
                  table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "key_name");
    if (custom_item != NULL && custom_item->type == cJSON_String) {
        strncpy(schema->key_name, custom_item->valuestring, sizeof(schema->key_name) - 1);
    } else {
        log_fatal(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table:<%s> schema has no"
                  " item_id column", __FUNCTION__, __LINE__,
                  table_name);
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
    struct ipport_plugin_schema *schema =
        (struct ipport_plugin_schema *)ipport_plugin_schema;

    if (1 == schema->container_schema.set_flag) {
        log_fatal(schema->logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport_plugin table(table_id:%d) ex_container_schema has been set"
                  ", can't set again", __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    schema->container_schema.table_id = table_id;
    schema->container_schema.table_name = (char*)table_manager_get_table_name(schema->ref_tbl_mgr, table_id);
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
    struct ipport_plugin_schema *schema =
        (struct ipport_plugin_schema *)ipport_plugin_schema;

    return &(schema->container_schema);
}

void *ipport_plugin_runtime_new(void *ipport_plugin_schema,
                                size_t max_thread_num,
                                struct maat_garbage_bin *garbage_bin, 
                                struct log_handle *logger)
{
    if (NULL == ipport_plugin_schema) {
        return NULL;
    }

    struct ipport_plugin_schema *schema =
        (struct ipport_plugin_schema *)ipport_plugin_schema;

    struct ipport_plugin_runtime *ipport_plugin_rt =
        ALLOC(struct ipport_plugin_runtime, 1);

    ipport_plugin_rt->ex_data_rt =
        ex_data_runtime_new(schema->table_id, schema->gc_timeout_s, logger);

    if (1 == schema->container_schema.set_flag) {
        ex_data_runtime_set_ex_container_schema(ipport_plugin_rt->ex_data_rt,
                                                &(schema->container_schema));
    }

    ipport_plugin_rt->n_worker_thread = max_thread_num;
    ipport_plugin_rt->ref_garbage_bin = garbage_bin;
    ipport_plugin_rt->logger = logger;
    ipport_plugin_rt->scan_times = alignment_int64_array_alloc(max_thread_num);

    return ipport_plugin_rt;
}

void ipport_plugin_runtime_free(void *ipport_plugin_runtime)
{
    if (NULL == ipport_plugin_runtime) {
        return;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt =
        (struct ipport_plugin_runtime *)ipport_plugin_runtime;

    if (ipport_plugin_rt->matcher != NULL) {
        ipport_matcher_free(ipport_plugin_rt->matcher);
        ipport_plugin_rt->matcher = NULL;
    }

    if (ipport_plugin_rt->ex_data_rt != NULL) {
        ex_data_runtime_free(ipport_plugin_rt->ex_data_rt);
        ipport_plugin_rt->ex_data_rt = NULL;
    }

    if (ipport_plugin_rt->scan_times != NULL) {
        alignment_int64_array_free(ipport_plugin_rt->scan_times);
        ipport_plugin_rt->scan_times = NULL;
    }

    FREE(ipport_plugin_rt);
}

static struct ipport_item *
ipport_item_new(struct ipport_plugin_schema *schema, const char *table_name,
                const cJSON *json, struct log_handle *logger)
{
    char ip_str[128] = {0};
    struct ipport_item *ipport_item = ALLOC(struct ipport_item, 1);
    cJSON *tmp_obj = NULL;
    int ret = 0;

    tmp_obj = cJSON_GetObjectItem(json, schema->key_name);
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport table:<%s> has no key or invalid format, line:%s",
                  __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
        goto error;
    }
    uuid_parse(tmp_obj->valuestring, ipport_item->item_uuid);

    tmp_obj = cJSON_GetObjectItem(json, "ip");
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport table:<%s> has no ip or invalid format in line:%s",
                  __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
        goto error;
    }
    strncpy(ip_str, tmp_obj->valuestring, strlen(tmp_obj->valuestring));

    if (strchr(ip_str, ':') != NULL) {
		ipport_item->ip_type = IPV6;
	} else {
		ipport_item->ip_type = IPV4;
    }

    if (IPV4 == ipport_item->ip_type) {
        ret = ip_format2range(ip_str, ipport_item->ip_type, &ipport_item->ipv4.min_ip, &ipport_item->ipv4.max_ip);
        if (ret < 0) {
            log_fatal(logger, MODULE_IPPORT_PLUGIN, 
                      "[%s:%d] ipport table:<%s> ip_format2range(ip4) failed in line:%s",
                      __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
            goto error;
        }
    } else {
        //ipv6
        ret = ip_format2range(ip_str, ipport_item->ip_type, ipport_item->ipv6.min_ip, ipport_item->ipv6.max_ip);
        if (ret < 0) {
            log_fatal(logger, MODULE_IPPORT_PLUGIN, 
                      "[%s:%d] ipport table:<%s> ip_format2range(ip6) failed in line:%s",
                      __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
            goto error;
        }
    }

    tmp_obj = cJSON_GetObjectItem(json, "port");
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(logger, MODULE_IPPORT_PLUGIN, 
                  "[%s:%d] ipport table:<%s> has no port or invalid format in line:%s",
                  __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
        goto error;
    }

    char port_range[20] = {0};
    memcpy(port_range, tmp_obj->valuestring, strlen(tmp_obj->valuestring));

    //port range is port or port_start-port_end
    if(strchr(port_range,'-')!=NULL){
        char *saveptr = NULL;
        char *port_start = strtok_r(port_range,"-", &saveptr);
        char *port_end = strtok_r(NULL,"-", &saveptr);
        ipport_item->min_port = atoi(port_start);
        ipport_item->max_port = atoi(port_end);
    } else {
        ipport_item->min_port = atoi(port_range);
        ipport_item->max_port = atoi(port_range);
    }

    return ipport_item;
error:
    FREE(ipport_item);
    return NULL;
}

void ipport_item_free(void *ipport_item)
{
    if (NULL == ipport_item) {
        return;
    }
    
    FREE(ipport_item);
}

static int
ipport_plugin_runtime_update_row(struct ipport_plugin_runtime *ipport_plugin_rt,
                                 const char *table_name, const char *row, 
                                 const char *key, size_t key_len, 
                                 struct ipport_item *ipport_item, enum maat_operation op)
{
    int ret = -1;
    struct ex_data_runtime *ex_data_rt = ipport_plugin_rt->ex_data_rt;
    if (NULL == ex_data_rt) {
        return -1;
    }

    if (MAAT_OP_DEL == op) {
        // delete
        ret = ex_data_runtime_del_ex_container(ex_data_rt, key, key_len);
        if (ret < 0) {
            return -1;
        }
    } else {
        // add
        void *ex_data = ex_data_runtime_row2ex_data(ex_data_rt, table_name,
                                                    row, key, key_len);

        struct ex_container *ex_container = ex_container_new(ex_data,
                                                            (void *)ipport_item);

        ret = ex_data_runtime_add_ex_container(ex_data_rt, key, key_len,
                                               ex_container);
        if (ret < 0) {
            log_debug(ipport_plugin_rt->logger, MODULE_IPPORT_PLUGIN,
                      "[%s:%d]ipport_plugin table:<%s> add key failed, "
                      "key:%s", __FUNCTION__, __LINE__, table_name, key);
            ex_container_free(ex_data_rt, ex_container);
            //don't return failed, ignore the case of adding duplicate keys
        }
    }

    return 0;
}

int ipport_plugin_runtime_update(void *ipport_plugin_runtime,
                                 void *ipport_plugin_schema, 
                                 const char *table_name,
                                 const char *line, enum maat_operation op)
{
    if (NULL == ipport_plugin_runtime || NULL == ipport_plugin_schema || 
        NULL == line) {
        return -1;
    }

    struct ipport_item *ipport_item = NULL;
    struct ipport_plugin_schema *schema =
        (struct ipport_plugin_schema *)ipport_plugin_schema;

    struct ipport_plugin_runtime *ipport_plugin_rt =
        (struct ipport_plugin_runtime *)ipport_plugin_runtime;

    int ret = 0;
    cJSON *tmp_obj = NULL;
    cJSON *json = cJSON_Parse(line);

    tmp_obj = cJSON_GetObjectItem(json, schema->key_name);
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(ipport_plugin_rt->logger, MODULE_IPPORT_PLUGIN,
                  "[%s:%d]ipport_plugin table:<%s> has no key or invalid format, line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        ipport_plugin_rt->update_err_cnt++;
        goto ERROR;
    }

    if (1 == schema->container_schema.set_flag) {
        if (MAAT_OP_ADD == op) {
            // add
            ipport_item = ipport_item_new(schema, table_name, json,
                                          ipport_plugin_rt->logger);
            if (NULL == ipport_item) {
                ipport_plugin_rt->update_err_cnt++;
                goto ERROR;
            }
        }

        const char *key = tmp_obj->valuestring;
        size_t key_len = strlen(key);
        ret = ipport_plugin_runtime_update_row(ipport_plugin_rt, table_name,
                                               line, key, key_len, ipport_item,
                                               op);
        if (ret < 0) {
            log_fatal(ipport_plugin_rt->logger, MODULE_IPPORT_PLUGIN,
                      "[%s:%d]ipport_plugin table:<%s> update one line failed, "
                      "line:%s", __FUNCTION__, __LINE__, table_name, line);
            ipport_plugin_rt->update_err_cnt++;
            goto ERROR;
        }

        log_debug(ipport_plugin_rt->logger, MODULE_IPPORT_PLUGIN,
                 "ipport_plugin table:<%s> update one line, key:%s, key_len:%zu,"
                 " maat_op:%d", table_name, key, key_len, op);
    } else {
        //ex_schema not set
        ex_data_runtime_cache_row_put(ipport_plugin_rt->ex_data_rt, line, op);
        ipport_plugin_rt->rule_num =
            ex_data_runtime_cached_row_count(ipport_plugin_rt->ex_data_rt);
    }

    cJSON_Delete(json);

    return 0;

ERROR:
    if (NULL != ipport_item) {
        ipport_item_free(ipport_item);
    }
    if (NULL != json) {
        cJSON_Delete(json);
    }

    return -1;
}

static void 
ipport_item_to_ipport_rule(struct ipport_item *item, struct ipport_rule *rule)
{
    if (IPV4 == item->ip_type) {
        rule->ip.ip_type= IPV4;
        rule->ip.ipv4 = item->ipv4.min_ip;
        rule->min_port = item->min_port;
        rule->max_port = item->max_port;
    } else {
        rule->ip.ip_type = IPV6;
        memcpy(rule->ip.ipv6, item->ipv6.min_ip, sizeof(item->ipv6.min_ip));
        rule->min_port = item->min_port;
        rule->max_port = item->max_port;
    }
    uuid_copy(rule->rule_uuid, item->item_uuid);
}

static void 
garbage_ipport_matcher_free(void *ipport_matcher, void *arg)
{
    struct ipport_matcher *matcher =
        (struct ipport_matcher *)ipport_matcher;

    ipport_matcher_free(matcher);
}

int ipport_plugin_runtime_commit(void *ipport_plugin_runtime,
                                 const char *table_name,
                                 long long maat_rt_version)
{
    if (NULL == ipport_plugin_runtime) {
        return -1;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt =
        (struct ipport_plugin_runtime *)ipport_plugin_runtime;

    struct ex_data_runtime *ex_data_rt = ipport_plugin_rt->ex_data_rt;
    if (NULL == ex_data_rt) {
        return -1;
    }

    int updating_flag = ex_data_runtime_is_updating(ex_data_rt);
    if (0 == updating_flag) {
        return 0;
    }

    struct ipport_rule *rules = NULL;
    struct ex_container **ex_container = NULL;
    size_t rule_cnt = ex_data_runtime_list_updating_ex_container(ex_data_rt,
                                                                &ex_container);
    if (rule_cnt > 0) {
        rules = ALLOC(struct ipport_rule, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            struct ipport_item *item =
                (struct ipport_item *)ex_container[i]->custom_data;

            ipport_item_to_ipport_rule(item, &rules[i]);
            rules[i].user_tag = ex_container[i];
        }
    }

    int ret = 0;
    struct ipport_matcher *new_matcher = NULL;
    struct ipport_matcher *old_matcher = NULL;

    if (rule_cnt > 0) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        new_matcher = ipport_matcher_new(rules, rule_cnt);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                                   (end.tv_nsec - start.tv_nsec) / 1000000;
        if (NULL == new_matcher) {
            log_fatal(ipport_plugin_rt->logger, MODULE_IPPORT_PLUGIN,
                      "[%s:%d] ipport_plugin table[%s] rebuild ipport_matcher"
                      " failed when update %zu rules", __FUNCTION__, __LINE__,
                      table_name, rule_cnt);
            ret = -1;
        } else {
            log_info(ipport_plugin_rt->logger, MODULE_IPPORT_PLUGIN,
                     "table[%s] commit %zu ipport_plugin rules and rebuild"
                     " ipport_matcher completed, version:%lld, consume:%lldms",
                     table_name, rule_cnt, maat_rt_version, time_elapse_ms);
        }
    }

    old_matcher = ipport_plugin_rt->matcher;
    ipport_plugin_rt->matcher = new_matcher;
    ex_data_runtime_commit(ex_data_rt);

    if (old_matcher != NULL) {
        maat_garbage_bagging(ipport_plugin_rt->ref_garbage_bin, old_matcher,
                             NULL, garbage_ipport_matcher_free);
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
    
    struct ipport_plugin_runtime *ipport_plugin_rt =
        (struct ipport_plugin_runtime *)ipport_plugin_runtime;

    return ipport_plugin_rt->rule_num;
}

struct ex_data_runtime *
ipport_plugin_runtime_get_ex_data_rt(void *ipport_plugin_runtime)
{
    if (NULL == ipport_plugin_runtime) {
        return NULL;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt =
        (struct ipport_plugin_runtime *)ipport_plugin_runtime;

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

int ipport_plugin_runtime_get_ex_data(void *ipport_plugin_runtime,
                                      const struct ip_addr *ip_addr, 
                                      uint16_t port, void **ex_data_array,
                                      size_t n_ex_data)
{
    if (NULL == ipport_plugin_runtime || NULL == ip_addr ||
        NULL == ex_data_array || 0 == n_ex_data) {
        return -1;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt =
        (struct ipport_plugin_runtime *)ipport_plugin_runtime;

    if (0 == ipport_plugin_rt->rule_num) {
        return 0;
    }

    if (NULL == ipport_plugin_rt->matcher) {
        return 0;
    }

    struct ipport_result results[n_ex_data];
    struct ip_addr ip_data;
	if (ip_addr->ip_type == IPV4) {
        ip_data.ip_type = IPV4;
		ip_data.ipv4 = ntohl(ip_addr->ipv4);
	} else {
        ip_data.ip_type = IPV6;
        memcpy(ip_data.ipv6, ip_addr->ipv6, sizeof(ip_data.ipv6));
		ipv6_ntoh(ip_data.ipv6);
	}
    
	int n_hit_item = ipport_matcher_match(ipport_plugin_rt->matcher, &ip_data,
                                          port, results, n_ex_data);
    if (n_hit_item <= 0) {
        return n_hit_item;
    }

    size_t hit_result_cnt = 0;
    for (size_t i = 0; i < n_hit_item; i++) {
        struct ex_container *ex_container = results[i].tag;
        struct ipport_item *item = (struct ipport_item *)ex_container->custom_data;

        int ret = validate_port(item, port);
        if (ret < 0) {
            continue;
        }

        ex_data_array[hit_result_cnt++] = 
            ex_data_runtime_get_ex_data_by_container(ipport_plugin_rt->ex_data_rt,
                                                     ex_container); 
    }

	return hit_result_cnt;
}

long long ipport_plugin_runtime_update_err_count(void *ipport_plugin_runtime)
{
    if (NULL == ipport_plugin_runtime) {
        return 0;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt =
        (struct ipport_plugin_runtime *)ipport_plugin_runtime;

    return ipport_plugin_rt->update_err_cnt;
}

void ipport_plugin_runtime_scan_times_inc(void *ipport_plugin_runtime,
                                          int thread_id)
{
    if (NULL == ipport_plugin_runtime || thread_id < 0) {
        return;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt =
        (struct ipport_plugin_runtime *)ipport_plugin_runtime;

    alignment_int64_array_add(ipport_plugin_rt->scan_times, thread_id, 1);
}

long long ipport_plugin_runtime_scan_times(void *ipport_plugin_runtime)
{
    if (NULL == ipport_plugin_runtime) {
        return 0;
    }

    struct ipport_plugin_runtime *ipport_plugin_rt =
        (struct ipport_plugin_runtime *)ipport_plugin_runtime;

    long long sum = alignment_int64_array_sum(ipport_plugin_rt->scan_times,
                                              ipport_plugin_rt->n_worker_thread);
                                              
    alignment_int64_array_reset(ipport_plugin_rt->scan_times,
                                ipport_plugin_rt->n_worker_thread);

    return sum;
}