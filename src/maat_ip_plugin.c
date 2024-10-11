/*
**********************************************************************************************
*	File: maat_ip_plugin.c
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
#include "maat_ip_plugin.h"
#include "ip_matcher.h"
#include "maat_core.h"
#include "maat_garbage_collection.h"

#define MODULE_IP_PLUGIN	 module_name_str("maat.ip_plugin")
#define MAX_IP_STR    128

struct ip_plugin_schema {
    int gc_timeout_s;
    int table_id;
    char key_name[MAX_NAME_STR_LEN];
	struct ex_container_schema container_schema;
    struct table_manager *ref_tbl_mgr;
    struct log_handle *logger;
};

struct ip_plugin_runtime {
	struct ip_matcher *ip_matcher;
    struct ex_data_runtime *ex_data_rt;
    size_t n_worker_thread;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;

    long long rule_num;
    long long update_err_cnt;
    long long *scan_times;
};

void *ip_plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                           const char *table_name, struct log_handle *logger)
{
    struct ip_plugin_schema *schema = ALLOC(struct ip_plugin_schema, 1);
    schema->logger = logger;

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
   if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_IP_PLUGIN, 
                  "[%s:%d] ip_plugin table:<%s> schema has no"
                  " table_id column", __FUNCTION__, __LINE__,
                  table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (NULL == item || item->type != cJSON_Object) {
        log_fatal(logger, MODULE_IP_PLUGIN, 
                  "[%s:%d] ip_plugin table:<%s> schema has no"
                  " custom column", __FUNCTION__, __LINE__,
                  table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "key_name");
    if (custom_item == NULL || custom_item->type != cJSON_String) {
        log_fatal(logger, MODULE_IP_PLUGIN, 
                  "[%s:%d] ip_plugin table:<%s> schema has no"
                  " key_name column", __FUNCTION__, __LINE__,
                  table_name);
        goto error;
    }
    strncpy(schema->key_name, custom_item->valuestring, sizeof(schema->key_name) - 1);

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

void ip_plugin_schema_free(void *ip_plugin_schema)
{
    if (NULL == ip_plugin_schema) {
        return;
    }

    FREE(ip_plugin_schema);
}

static int
ip_plugin_accept_tag_match(struct ip_plugin_schema *schema,
                           const char *table_name, const cJSON *json,
                           struct log_handle *logger)
{
    cJSON *tmp_obj = NULL;
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);

    tmp_obj = cJSON_GetObjectItem(json, "effective_range");
    if ((tmp_obj && cJSON_GetArraySize(tmp_obj) > 0) && n_tag > 0) {
        char *tag_str = cJSON_Print(tmp_obj);

        int ret = table_manager_accept_tags_match(schema->ref_tbl_mgr, tag_str);
        FREE(tag_str);
        
        if (TAG_MATCH_ERR == ret) {
            log_fatal(logger, MODULE_IP_PLUGIN,
                      "[%s:%d] ip_plugin table:<%s> has invalid tag format"
                      " in line:%s", __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
            return TAG_MATCH_ERR;
        }

        if (TAG_MATCH_UNMATCHED == ret) {
            log_fatal(logger, MODULE_IP_PLUGIN,
                      "[%s:%d] ip_plugin table:<%s> has unmatched tag in line:%s",
                      __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
            return TAG_MATCH_UNMATCHED;
        }
    }


    return TAG_MATCH_MATCHED;
}

static struct ip_rule *
ip_plugin_rule_new(struct ip_plugin_schema *schema, const char *table_name,
                   const cJSON *json, struct log_handle *logger)
{
    int ret = ip_plugin_accept_tag_match(schema, table_name, json, logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        return NULL;
    }

    char ip_str[128] = {0};
    cJSON *tmp_obj = NULL;
    struct ip_rule *ip_plugin_rule = ALLOC(struct ip_rule, 1);

    tmp_obj = cJSON_GetObjectItem(json, schema->key_name);
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(logger, MODULE_IP_PLUGIN, 
                  "[%s:%d] ip_plugin table:<%s> has no key %s or invalid format in line:%s",
                  __FUNCTION__, __LINE__, table_name, schema->key_name, cJSON_Print(json));
        goto error;
    }
    uuid_parse(tmp_obj->valuestring, ip_plugin_rule->rule_uuid);
    
    tmp_obj = cJSON_GetObjectItem(json, "ip");
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(logger, MODULE_IP_PLUGIN, 
                  "[%s:%d] ip_plugin table:<%s> has no ip field or invalid format in line:%s",
                  __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
        goto error;
    }
    strncpy(ip_str, tmp_obj->valuestring, strlen(tmp_obj->valuestring));

    if (strchr(ip_str, ':') != NULL) {
		ip_plugin_rule->type = IPV6;
	} else {
		ip_plugin_rule->type = IPV4;
    }

    if (IPv4 == ip_plugin_rule->type) {
        ret = ip_format2range(ip_str, ip_plugin_rule->type, &ip_plugin_rule->ipv4_rule.start_ip, &ip_plugin_rule->ipv4_rule.end_ip);
        if (ret < 0) {
            log_fatal(logger, MODULE_IP_PLUGIN, 
                      "[%s:%d] ip_plugin table:<%s>> ip_format2range(ip4)"
                      " failed in line:%s", __FUNCTION__, __LINE__,
                      table_name, cJSON_Print(json));
            goto error;
        }
    } else {
        //ipv6
        ret = ip_format2range(ip_str, ip_plugin_rule->type, ip_plugin_rule->ipv6_rule.start_ip, ip_plugin_rule->ipv6_rule.end_ip);
        if (ret < 0) {
            log_fatal(logger, MODULE_IP_PLUGIN, 
                      "[%s:%d] ip_plugin table:<%s> ip_format2range(ip6)"
                      " failed in line:%s", __FUNCTION__, __LINE__,
                      table_name, cJSON_Print(json));
            goto error;
        }
    }

    return ip_plugin_rule;
error:
    FREE(ip_plugin_rule);
    return NULL;
}

void ip_plugin_rule_free(void *ip_rule)
{
    FREE(ip_rule);
}

int ip_plugin_table_set_ex_container_schema(void *ip_plugin_schema, int table_id,
                                            maat_ex_new_func_t *new_func,
							                maat_ex_free_func_t *free_func,
							                maat_ex_dup_func_t *dup_func,
                                            void (*custom_data_free)(void *),
							                long argl, void *argp)
{
    struct ip_plugin_schema *schema = (struct ip_plugin_schema *)ip_plugin_schema;

    if (1 == schema->container_schema.set_flag) {
        log_fatal(schema->logger, MODULE_IP_PLUGIN, 
                  "[%s:%d] ip_plugin table(table_id:%d) ex_container_schema"
                  " has been set, can't set again",
                  __FUNCTION__, __LINE__, table_id);
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
ip_plugin_table_get_ex_container_schema(void *ip_plugin_schema)
{
    struct ip_plugin_schema *schema =
        (struct ip_plugin_schema *)ip_plugin_schema;

    return &(schema->container_schema);
}

static int
ip_plugin_runtime_update_row(struct ip_plugin_runtime *ip_plugin_rt,
                             const char *table_name, const char *row, 
                             const char *key, size_t key_len, 
                             struct ip_rule *ip_plugin_rule, enum maat_operation op)
{
    int ret = -1;
    struct ex_data_runtime *ex_data_rt = ip_plugin_rt->ex_data_rt;
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
        struct ex_container *ex_container =
            ex_container_new(ex_data, (void *)ip_plugin_rule);

        ret = ex_data_runtime_add_ex_container(ex_data_rt, key, key_len,
                                               ex_container);
        if (ret < 0) {
            log_debug(ip_plugin_rt->logger, MODULE_IP_PLUGIN,
                      "[%s:%d]ip_plugin table:<%s> add key failed, "
                      "key:%s", __FUNCTION__, __LINE__, table_name, key);
            ex_container_free(ex_data_rt, ex_container);
            //don't return failed, ignore the case of adding duplicate keys
        }
    }

    return 0;
}

void *ip_plugin_runtime_new(void *ip_plugin_schema, size_t max_thread_num,
                            struct maat_garbage_bin *garbage_bin, 
                            struct log_handle *logger)
{
    if (NULL == ip_plugin_schema) {
        return NULL;
    }

    struct ip_plugin_schema *schema =
        (struct ip_plugin_schema *)ip_plugin_schema;

    struct ip_plugin_runtime *ip_plugin_rt = ALLOC(struct ip_plugin_runtime, 1);

    ip_plugin_rt->ex_data_rt =
        ex_data_runtime_new(schema->table_id, schema->gc_timeout_s, logger);

    if (1 == schema->container_schema.set_flag) {
        ex_data_runtime_set_ex_container_schema(ip_plugin_rt->ex_data_rt,
                                                &(schema->container_schema));
    }

    ip_plugin_rt->n_worker_thread = max_thread_num;
    ip_plugin_rt->ref_garbage_bin = garbage_bin;
    ip_plugin_rt->logger = logger;
    ip_plugin_rt->scan_times = alignment_int64_array_alloc(max_thread_num);

    return ip_plugin_rt;
}

void ip_plugin_runtime_free(void *ip_plugin_runtime)
{
    if (NULL == ip_plugin_runtime) {
        return;
    }

    struct ip_plugin_runtime *ip_plugin_rt =
        (struct ip_plugin_runtime *)ip_plugin_runtime;

    if (ip_plugin_rt->ip_matcher != NULL) {
        ip_matcher_free(ip_plugin_rt->ip_matcher);
        ip_plugin_rt->ip_matcher = NULL;
    }

    if (ip_plugin_rt->ex_data_rt != NULL) {
        ex_data_runtime_free(ip_plugin_rt->ex_data_rt);
        ip_plugin_rt->ex_data_rt = NULL;
    }

    if (ip_plugin_rt->scan_times != NULL) {
        alignment_int64_array_free(ip_plugin_rt->scan_times);
        ip_plugin_rt->scan_times = NULL;
    }

    FREE(ip_plugin_rt);
}

int ip_plugin_runtime_update(void *ip_plugin_runtime, void *ip_plugin_schema, 
                             const char *table_name, const char *line, 
                             enum maat_operation op)
{
    if (NULL == ip_plugin_runtime || NULL == ip_plugin_schema || 
        NULL == line) {
        return -1;
    }

    struct ip_rule *ip_plugin_rule = NULL;
    struct ip_plugin_schema *schema =
        (struct ip_plugin_schema *)ip_plugin_schema;

    struct ip_plugin_runtime *ip_plugin_rt =
        (struct ip_plugin_runtime *)ip_plugin_runtime;

    int ret = 0;
    cJSON *tmp_obj = NULL;
    cJSON *json = cJSON_Parse(line);

    if (NULL == json) {
        log_fatal(ip_plugin_rt->logger, MODULE_IP_PLUGIN,
                  "[%s:%d]ip_plugin table:<%s> parse json failed, line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        ip_plugin_rt->update_err_cnt++;
        goto ERROR;
    }

    tmp_obj = cJSON_GetObjectItem(json, schema->key_name);
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(ip_plugin_rt->logger, MODULE_IP_PLUGIN,
                  "[%s:%d]ip_plugin table:<%s> has no entry_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        ip_plugin_rt->update_err_cnt++;
        goto ERROR;
    }

    if (1 == schema->container_schema.set_flag) {
        if (MAAT_OP_ADD == op) {
            // add
            ip_plugin_rule = ip_plugin_rule_new(schema, table_name, json,
                                                ip_plugin_rt->logger);
            if (NULL == ip_plugin_rule) {
                ip_plugin_rt->update_err_cnt++;
                goto ERROR;
            }
        }

        const char *key = tmp_obj->valuestring;
        size_t key_len = strlen(key);
        ret = ip_plugin_runtime_update_row(ip_plugin_rt, table_name, line, key,
                                           key_len, ip_plugin_rule, op);
        if (ret < 0) {
            log_fatal(ip_plugin_rt->logger, MODULE_IP_PLUGIN,
                      "[%s:%d]ip_plugin table:<%s> update one line failed, "
                      "line:%s", __FUNCTION__, __LINE__, table_name, line);
            ip_plugin_rt->update_err_cnt++;
            goto ERROR;
        }

        log_debug(ip_plugin_rt->logger, MODULE_IP_PLUGIN,
                 "ip_plugin table:<%s> update one line, key:%s, key_len:%zu,"
                 " maat_op:%d", table_name, key, key_len, op);
    } else {
        //ex_schema not set
        ex_data_runtime_cache_row_put(ip_plugin_rt->ex_data_rt, line, op);
        ip_plugin_rt->rule_num =
            ex_data_runtime_cached_row_count(ip_plugin_rt->ex_data_rt);
    }

    cJSON_Delete(json);
    return 0;

ERROR:
    if (ip_plugin_rule != NULL) {
        ip_plugin_rule_free(ip_plugin_rule);
    }
    if (json != NULL) {
        cJSON_Delete(json);
    }

    return -1;
}

int ip_plugin_runtime_commit(void *ip_plugin_runtime, const char *table_name,
                             long long maat_rt_version)
{
    if (NULL == ip_plugin_runtime) {
        return -1;
    }

    struct ip_plugin_runtime *ip_plugin_rt =
        (struct ip_plugin_runtime *)ip_plugin_runtime;

    struct ex_data_runtime *ex_data_rt = ip_plugin_rt->ex_data_rt;
    if (NULL == ex_data_rt) {
        return -1;
    }

    int updating_flag = ex_data_runtime_is_updating(ex_data_rt);
    if (0 == updating_flag) {
        return 0;
    }

    struct ip_rule *rules = NULL;
    struct ex_container **ex_container = NULL;
    size_t rule_cnt = ex_data_runtime_list_updating_ex_container(ex_data_rt,
                                                                 &ex_container);
    if (rule_cnt > 0) {
        rules = ALLOC(struct ip_rule, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            rules[i] = *(struct ip_rule *)ex_container[i]->custom_data;
            assert(rules[i].user_tag == ex_container[i] ||
                   rules[i].user_tag == NULL);
            rules[i].user_tag = ex_container[i];
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
            log_fatal(ip_plugin_rt->logger, MODULE_IP_PLUGIN,
                      "[%s:%d] ip_plugin table[%s] rebuild ip_matcher failed when "
                      "update %zu rules", __FUNCTION__, __LINE__, table_name, rule_cnt);
            ret = -1;
        } else {
            log_info(ip_plugin_rt->logger, MODULE_IP_PLUGIN,
                     "table[%s] commit %zu ip_plugin rules and rebuild ip_matcher "
                     "completed, version:%lld, consume:%lldms", table_name, rule_cnt,
                     maat_rt_version, time_elapse_ms);
        }
    }

    old_ip_matcher = ip_plugin_rt->ip_matcher;
    ip_plugin_rt->ip_matcher = new_ip_matcher;
    ex_data_runtime_commit(ex_data_rt);

    if (old_ip_matcher != NULL) {
        maat_garbage_bagging(ip_plugin_rt->ref_garbage_bin, old_ip_matcher,
                             NULL, garbage_ip_matcher_free);
    }
    
    ip_plugin_rt->rule_num = rule_cnt;

    if (rules != NULL) {
        FREE(rules);
    }
    
    if (ex_container != NULL) {
        FREE(ex_container);
    }

    return ret;
}

long long ip_plugin_runtime_rule_count(void *ip_plugin_runtime)
{
    if (NULL == ip_plugin_runtime) {
        return 0;
    }
    
    struct ip_plugin_runtime *ip_plugin_rt =
        (struct ip_plugin_runtime *)ip_plugin_runtime;

    return ip_plugin_rt->rule_num;
}

struct ex_data_runtime *
ip_plugin_runtime_get_ex_data_rt(void *ip_plugin_runtime)
{
    if (NULL == ip_plugin_runtime) {
        return NULL;
    }

    struct ip_plugin_runtime *ip_plugin_rt =
        (struct ip_plugin_runtime *)ip_plugin_runtime;

    return ip_plugin_rt->ex_data_rt;
}

int ip_plugin_runtime_get_ex_data(void *ip_plugin_runtime,
                                  const struct ip_addr *ip_addr, 
                                  void **ex_data_array,
                                  size_t n_ex_data)
{
    if (NULL == ip_plugin_runtime || NULL == ip_addr ||
        NULL == ex_data_array || 0 == n_ex_data) {
        return -1;
    }

    struct ip_plugin_runtime *ip_plugin_rt =
        (struct ip_plugin_runtime *)ip_plugin_runtime;

    if (0 == ip_plugin_rt->rule_num) {
        return 0;
    }

    if (NULL == ip_plugin_rt->ip_matcher) {
        return 0;
    }

    struct scan_result results[n_ex_data];
    struct ip_data ip_data = *(const struct ip_data *)ip_addr;
	if (ip_data.type == IPv4) {
		ip_data.ipv4 = ntohl(ip_data.ipv4);
	} else {
		ipv6_ntoh(ip_data.ipv6);
	}

	int n_result = ip_matcher_match(ip_plugin_rt->ip_matcher, &ip_data,
                                    results, n_ex_data);
	for (int i = 0; i < n_result; i++) {
		ex_data_array[i] = 
            ex_data_runtime_get_ex_data_by_container(ip_plugin_rt->ex_data_rt,
                                                    (struct ex_container *)results[i].tag);
	}
	return n_result;
}

long long ip_plugin_runtime_update_err_count(void *ip_plugin_runtime)
{
    if (NULL == ip_plugin_runtime) {
        return 0;
    }

    struct ip_plugin_runtime *ip_plugin_rt =
        (struct ip_plugin_runtime *)ip_plugin_runtime;

    return ip_plugin_rt->update_err_cnt;
}

void ip_plugin_runtime_scan_times_inc(void *ip_plugin_runtime, int thread_id)
{
    if (NULL == ip_plugin_runtime || thread_id < 0) {
        return;
    }

    struct ip_plugin_runtime *ip_plugin_rt =
        (struct ip_plugin_runtime *)ip_plugin_runtime;

    alignment_int64_array_add(ip_plugin_rt->scan_times, thread_id, 1);
}

long long ip_plugin_runtime_scan_times(void *ip_plugin_runtime)
{
    if (NULL == ip_plugin_runtime) {
        return 0;
    }

    struct ip_plugin_runtime *ip_plugin_rt =
        (struct ip_plugin_runtime *)ip_plugin_runtime;

    long long sum = alignment_int64_array_sum(ip_plugin_rt->scan_times,
                                              ip_plugin_rt->n_worker_thread);

    alignment_int64_array_reset(ip_plugin_rt->scan_times,
                                ip_plugin_rt->n_worker_thread);

    return sum;
}