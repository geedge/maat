/*
**********************************************************************************************
*	File: maat_fqdn_plugin.c
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "alignment.h"
#include "maat_fqdn_plugin.h"
#include "maat_utils.h"
#include "maat_table.h"
#include "maat_core.h"
#include "maat_garbage_collection.h"

#define MODULE_FQDN_PLUGIN	 module_name_str("maat.bool_plugin")

struct fqdn_plugin_schema {
    int gc_timeout_s;
    int table_id;
    char key_name[MAX_NAME_STR_LEN];
    struct ex_container_schema container_schema;
    struct table_manager *ref_tbl_mgr;
    struct log_handle *logger;
};

struct fqdn_plugin_runtime {
    struct FQDN_engine *engine;
    struct ex_data_runtime *ex_data_rt;
    size_t n_worker_thread;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;

    long long rule_num;
    long long update_err_cnt;
    long long *scan_times;
};

void *fqdn_plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger)
{
    struct fqdn_plugin_schema *schema = ALLOC(struct fqdn_plugin_schema, 1);
    schema->logger = logger;

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_FQDN_PLUGIN, 
                  "[%s:%d] fqdn_plugin table:<%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (NULL == item || item->type != cJSON_Object) {
        log_fatal(logger, MODULE_FQDN_PLUGIN, 
                  "[%s:%d] fqdn_plugin table:<%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "key_name");
    if (custom_item != NULL && custom_item->type == cJSON_String) {
        strncpy(schema->key_name, custom_item->valuestring, sizeof(schema->key_name) - 1);
    } else {
        log_fatal(logger, MODULE_FQDN_PLUGIN, 
                  "[%s:%d] fqdn_plugin table:<%s> schema has no item_id column", 
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

void fqdn_plugin_schema_free(void *fqdn_plugin_schema)
{
    if (NULL == fqdn_plugin_schema) {
        return;
    }

    FREE(fqdn_plugin_schema);
}

int fqdn_plugin_table_set_ex_container_schema(void *fqdn_plugin_schema, int table_id,
                                              maat_ex_new_func_t *new_func,
							                  maat_ex_free_func_t *free_func,
							                  maat_ex_dup_func_t *dup_func,
                                              void (*custom_data_free)(void *),
							                  long argl, void *argp)
{
    struct fqdn_plugin_schema *schema = (struct fqdn_plugin_schema *)fqdn_plugin_schema;

    if (1 == schema->container_schema.set_flag) {
        log_fatal(schema->logger, MODULE_FQDN_PLUGIN, 
                  "[%s:%d] fqdn_plugin table(table_id:%d) ex_container_schema "
                  "has been set, can't set again", __FUNCTION__, __LINE__, table_id);
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
fqdn_plugin_table_get_ex_container_schema(void *fqdn_plugin_schema)
{
    struct fqdn_plugin_schema *schema =
        (struct fqdn_plugin_schema *)fqdn_plugin_schema;

    return &(schema->container_schema);
}

void fqdn_rule_free(struct FQDN_rule *fqdn_rule)
{
    if (NULL == fqdn_rule) {
        return;
    }

	assert(fqdn_rule->user_tag == NULL);
    if (fqdn_rule->FQDN != NULL) {
        FREE(fqdn_rule->FQDN);
    }
	
	FREE(fqdn_rule);
}

void *fqdn_plugin_runtime_new(void *fqdn_plugin_schema, size_t max_thread_num,
                              struct maat_garbage_bin *garbage_bin, 
                              struct log_handle *logger)
{
    if (NULL == fqdn_plugin_schema) {
        return NULL;
    }

    struct fqdn_plugin_schema *schema = (struct fqdn_plugin_schema *)fqdn_plugin_schema;
    struct fqdn_plugin_runtime *fqdn_plugin_rt = ALLOC(struct fqdn_plugin_runtime, 1);

    fqdn_plugin_rt->ex_data_rt =
        ex_data_runtime_new(schema->table_id, schema->gc_timeout_s, logger);

    if (1 == schema->container_schema.set_flag) {
        ex_data_runtime_set_ex_container_schema(fqdn_plugin_rt->ex_data_rt,
                                                &(schema->container_schema));
    }

    fqdn_plugin_rt->n_worker_thread = max_thread_num;
    fqdn_plugin_rt->ref_garbage_bin = garbage_bin;
    fqdn_plugin_rt->logger = logger;
    fqdn_plugin_rt->scan_times = alignment_int64_array_alloc(max_thread_num);

    return fqdn_plugin_rt;
}

void fqdn_plugin_runtime_free(void *fqdn_plugin_runtime)
{
    if (NULL == fqdn_plugin_runtime) {
        return;
    }

    struct fqdn_plugin_runtime *fqdn_plugin_rt =
        (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;

    if (fqdn_plugin_rt->engine != NULL) {
        FQDN_engine_free(fqdn_plugin_rt->engine);
        fqdn_plugin_rt->engine = NULL;
    }

    if (fqdn_plugin_rt->ex_data_rt != NULL) {
        ex_data_runtime_free(fqdn_plugin_rt->ex_data_rt);
        fqdn_plugin_rt->ex_data_rt = NULL;
    }

    if (fqdn_plugin_rt->scan_times != NULL) {
        alignment_int64_array_free(fqdn_plugin_rt->scan_times);
        fqdn_plugin_rt->scan_times = NULL;
    }

    FREE(fqdn_plugin_rt);
}

static int
fqdn_plugin_accept_tag_match(struct fqdn_plugin_schema *schema,
                             const char *table_name, const cJSON *json,
                             struct log_handle *logger)
{
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);
    cJSON *tmp_obj = NULL;

    tmp_obj = cJSON_GetObjectItem(json, "tag");
    if (tmp_obj != NULL && n_tag > 0) {
        if (tmp_obj->type != cJSON_String) {
            log_fatal(logger, MODULE_FQDN_PLUGIN,
                      "[%s:%d] fqdn_plugin table:<%s> has invalid tag format"
                      " in line:%s", __FUNCTION__, __LINE__, table_name,
                      cJSON_Print(json));
            return TAG_MATCH_ERR;
        }

        const char *tag = tmp_obj->valuestring;
        if (strlen(tag) > 2) {
            int ret = table_manager_accept_tags_match(schema->ref_tbl_mgr, tag);
            if (TAG_MATCH_ERR == ret) {
                log_fatal(logger, MODULE_FQDN_PLUGIN,
                          "[%s:%d] fqdn_plugin table:<%s> has invalid tag"
                          " format in line:%s", __FUNCTION__, __LINE__,
                          table_name, cJSON_Print(json));
                return TAG_MATCH_ERR;
            }

            if (TAG_MATCH_UNMATCHED == ret) {
                log_fatal(logger, MODULE_FQDN_PLUGIN,
                          "[%s:%d] fqdn_plugin table:<%s> has unmatched tag"
                          " in line:%s", __FUNCTION__, __LINE__, table_name,
                          cJSON_Print(json));
                return TAG_MATCH_UNMATCHED;
            }
        }
    }

    return TAG_MATCH_MATCHED;
}

static struct FQDN_rule *
fqdn_plugin_rule_new(const cJSON *json, struct fqdn_plugin_schema *schema,
                     const char *table_name, struct log_handle *logger)
{
     int ret = fqdn_plugin_accept_tag_match(schema, table_name, json, logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        return NULL;
    }

    const char *fqdn = NULL;
    size_t fqdn_len = 0;
    struct FQDN_rule *fqdn_plugin_rule = ALLOC(struct FQDN_rule, 1);
    cJSON *tmp_obj = NULL;

    tmp_obj = cJSON_GetObjectItem(json, schema->key_name);
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(logger, MODULE_FQDN_PLUGIN, 
                  "[%s:%d] fqdn_plugin table:<%s> has no key_name or invalid format in line:%s",
                  __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
        goto error;
    }
    fqdn_plugin_rule->id = atoi(tmp_obj->valuestring);

    tmp_obj = cJSON_GetObjectItem(json, "fqdn");
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(logger, MODULE_FQDN_PLUGIN, 
                  "[%s:%d] fqdn_plugin table:<%s> has no fqdn in line:%s",
                  __FUNCTION__, __LINE__, table_name, cJSON_Print(json));
        goto error;
    }

    fqdn = tmp_obj->valuestring;
    fqdn_len = strlen(fqdn);

    if (fqdn[0] == '*') {
        fqdn_plugin_rule->is_suffix_match = 1;
        fqdn++;
        fqdn_len--;
    }

    if (fqdn[0] == '.') {
        fqdn++;
        fqdn_len--;
    }

    if (fqdn[fqdn_len] == '/') {
        fqdn_len--;
    }

    fqdn_plugin_rule->FQDN = ALLOC(char, fqdn_len + 1);
    memcpy(fqdn_plugin_rule->FQDN, fqdn, fqdn_len);
    fqdn_plugin_rule->len = fqdn_len;

    return fqdn_plugin_rule;
error:
    FREE(fqdn_plugin_rule);
    return NULL;
}

static int
fqdn_plugin_runtime_update_row(struct fqdn_plugin_runtime *fqdn_plugin_rt,
                               const char *table_name, const char *row, 
                               const char *key, size_t key_len, 
                               struct FQDN_rule *fqdn_plugin_rule,
                               enum maat_operation op)
{
    int ret = -1;
    struct ex_data_runtime *ex_data_rt = fqdn_plugin_rt->ex_data_rt;

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
            ex_container_new(ex_data, (void *)fqdn_plugin_rule);

        ret = ex_data_runtime_add_ex_container(ex_data_rt, key, key_len,
                                               ex_container);
        if (ret < 0) {
            log_debug(fqdn_plugin_rt->logger, MODULE_FQDN_PLUGIN,
                      "[%s:%d]fqdn_plugin table:<%s> add key failed, "
                      "key:%s", __FUNCTION__, __LINE__, table_name, key);
            ex_container_free(ex_data_rt, ex_container);
            //don't return failed, ignore the case of adding duplicate keys
        }
    }

    return 0;
}

int fqdn_plugin_runtime_update(void *fqdn_plugin_runtime,
                               void *fqdn_plugin_schema,
                               const char *table_name,
                               const char *line,
                               enum maat_operation op)
{
    if (NULL == fqdn_plugin_runtime || NULL == fqdn_plugin_schema || 
        NULL == line) {
        return -1;
    }

    struct FQDN_rule *fqdn_plugin_rule = NULL;
    struct fqdn_plugin_schema *schema =
        (struct fqdn_plugin_schema *)fqdn_plugin_schema;

    struct fqdn_plugin_runtime *fqdn_plugin_rt =
        (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;

    int ret = 0;
    cJSON *tmp_obj = NULL;
    cJSON *json = cJSON_Parse(line);

    if (NULL == json) {
        log_fatal(fqdn_plugin_rt->logger, MODULE_FQDN_PLUGIN,
                  "[%s:%d] fqdn_plugin table:<%s> line is not a json format, line: %s",
                  __FUNCTION__, __LINE__, table_name, line);
        fqdn_plugin_rt->update_err_cnt++;
        goto ERROR;
    }

    tmp_obj = cJSON_GetObjectItem(json, schema->key_name);
    if (NULL == tmp_obj || tmp_obj->type != cJSON_String) {
        log_fatal(fqdn_plugin_rt->logger, MODULE_FQDN_PLUGIN,
                  "[%s:%d] fqdn_plugin table:<%s> has no key_name or invalid format in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        fqdn_plugin_rt->update_err_cnt++;
        goto ERROR;
    }

    if (1 == schema->container_schema.set_flag) {
        if (MAAT_OP_ADD == op) {
            // add
            fqdn_plugin_rule = fqdn_plugin_rule_new(json, schema, table_name,
                                                    fqdn_plugin_rt->logger);
            if (NULL == fqdn_plugin_rule) {
                fqdn_plugin_rt->update_err_cnt++;
                goto ERROR;
            }
        }

        const char *key = tmp_obj->valuestring;
        size_t key_len = strlen(key);
        ret = fqdn_plugin_runtime_update_row(fqdn_plugin_rt, table_name, line,
                                             key, key_len, fqdn_plugin_rule,
                                             op);
        if (ret < 0) {
            log_fatal(fqdn_plugin_rt->logger, MODULE_FQDN_PLUGIN,
                      "[%s:%d]fqdn_plugin table:<%s> update one line failed, "
                      "line:%s", __FUNCTION__, __LINE__, table_name, line);
            fqdn_plugin_rt->update_err_cnt++;
            goto ERROR;
        }

        log_debug(fqdn_plugin_rt->logger, MODULE_FQDN_PLUGIN,
                  "fqdn_plugin table:<%s> update one line, key:%s, key_len:%zu,"
                  "maat_op:%d", table_name, key, key_len, op);
    } else {
        //ex_schema not set
        ex_data_runtime_cache_row_put(fqdn_plugin_rt->ex_data_rt, line, op);
        fqdn_plugin_rt->rule_num =
            ex_data_runtime_cached_row_count(fqdn_plugin_rt->ex_data_rt);
    }

    return 0;

ERROR:
    if (fqdn_plugin_rule != NULL) {
        fqdn_rule_free(fqdn_plugin_rule);
    }
    if (json != NULL) {
        cJSON_Delete(json);
    }

    return -1;
}

static void garbage_fqdn_engine_free(void *fqdn_engine, void *arg)
{
    struct FQDN_engine *engine = (struct FQDN_engine *)fqdn_engine;
    FQDN_engine_free(engine);
}

int fqdn_plugin_runtime_commit(void *fqdn_plugin_runtime,
                               const char *table_name,
                               long long maat_rt_version)
{
     if (NULL == fqdn_plugin_runtime) {
        return -1;
    }

    struct fqdn_plugin_runtime *fqdn_plugin_rt =
        (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;

    struct ex_data_runtime *ex_data_rt = fqdn_plugin_rt->ex_data_rt;
    if (NULL == ex_data_rt) {
        return -1;
    }

    int updating_flag = ex_data_runtime_is_updating(ex_data_rt);
    if (0 == updating_flag) {
        return 0;
    }

    struct FQDN_rule *rules = NULL;
    struct ex_container **ex_container = NULL;
    size_t rule_cnt = ex_data_runtime_list_updating_ex_container(ex_data_rt,
                                                                &ex_container);
    if (rule_cnt > 0) {
        rules = ALLOC(struct FQDN_rule, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            rules[i] = *(struct FQDN_rule *)ex_container[i]->custom_data;
            assert(rules[i].user_tag == ex_container[i] ||
                   rules[i].user_tag == NULL);
            rules[i].user_tag = ex_container[i];
        }
    }

    int ret = 0;
    struct FQDN_engine *new_fqdn_engine = NULL;
    struct FQDN_engine *old_fqdn_engine = NULL;

    if (rule_cnt > 0) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        new_fqdn_engine = FQDN_engine_new(rules, rule_cnt);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                                   (end.tv_nsec - start.tv_nsec) / 1000000;

        if (NULL == new_fqdn_engine) {
            log_fatal(fqdn_plugin_rt->logger, MODULE_FQDN_PLUGIN,
                      "[%s:%d] table[%s] rebuild FQDN engine failed when update"
                      " %zu fqdn_plugin rules", __FUNCTION__, __LINE__, table_name,
                      rule_cnt);
            ret = -1;
        } else {
            log_info(fqdn_plugin_rt->logger, MODULE_FQDN_PLUGIN,
                     "table[%s] commit %zu fqdn_plugin rules and rebuild"
                     " FQDN engine completed, version:%lld, consume:%lldms",
                     table_name, rule_cnt, maat_rt_version, time_elapse_ms);
        }
    }

    old_fqdn_engine = fqdn_plugin_rt->engine;
    fqdn_plugin_rt->engine = new_fqdn_engine;
    ex_data_runtime_commit(ex_data_rt);

    if (old_fqdn_engine != NULL) {
        maat_garbage_bagging(fqdn_plugin_rt->ref_garbage_bin, old_fqdn_engine,
                             NULL, garbage_fqdn_engine_free);
    }

    fqdn_plugin_rt->rule_num = rule_cnt;

    if (rules != NULL) {
        FREE(rules);
    }
    
    if (ex_container != NULL) {
        FREE(ex_container);
    }

    return ret;
}

long long fqdn_plugin_runtime_rule_count(void *fqdn_plugin_runtime)
{
    if (NULL == fqdn_plugin_runtime) {
        return 0;
    }
    
    struct fqdn_plugin_runtime *fqdn_plugin_rt =
        (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;

    return fqdn_plugin_rt->rule_num;
}

struct ex_data_runtime *
fqdn_plugin_runtime_get_ex_data_rt(void *fqdn_plugin_runtime)
{
    if (NULL == fqdn_plugin_runtime) {
        return NULL;
    }

    struct fqdn_plugin_runtime *fqdn_plugin_rt =
        (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;

    return fqdn_plugin_rt->ex_data_rt;
}


int fqdn_plugin_runtime_get_ex_data(void *fqdn_plugin_runtime,
                                    const char *query_fqdn, 
                                    void **ex_data_array,
                                    size_t n_ex_data)
{
    if (NULL == fqdn_plugin_runtime || NULL == query_fqdn ||
        NULL == ex_data_array || 0 == n_ex_data) {
        return -1;
    }

    struct fqdn_plugin_runtime *fqdn_plugin_rt =
        (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;

    if (0 == fqdn_plugin_rt->rule_num) {
        return 0;
    }

    if (NULL == fqdn_plugin_rt->engine) {
        return 0;
    }

    struct FQDN_match results[n_ex_data];
	int n_result = FQDN_engine_search(fqdn_plugin_rt->engine, query_fqdn,
                                      strlen(query_fqdn), results, n_ex_data);
	for (int i = 0; i < n_result; i++) {
		ex_data_array[i] =
            ex_data_runtime_get_ex_data_by_container(fqdn_plugin_rt->ex_data_rt,
                                                     (struct ex_container *)results[i].user_tag);
	}

	return n_result;
}

long long fqdn_plugin_runtime_update_err_count(void *fqdn_plugin_runtime)
{
    if (NULL == fqdn_plugin_runtime) {
        return 0;
    }

    struct fqdn_plugin_runtime *fqdn_plugin_rt =
        (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;

    return fqdn_plugin_rt->update_err_cnt;
}

void fqdn_plugin_runtime_scan_times_inc(void *fqdn_plugin_runtime, int thread_id)
{
    if (NULL == fqdn_plugin_runtime || thread_id < 0) {
        return;
    }

    struct fqdn_plugin_runtime *fqdn_plugin_rt =
        (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;

    alignment_int64_array_add(fqdn_plugin_rt->scan_times, thread_id, 1);
}

long long fqdn_plugin_runtime_scan_times(void *fqdn_plugin_runtime)
{
    if (NULL == fqdn_plugin_runtime) {
        return 0;
    }

    struct fqdn_plugin_runtime *fqdn_plugin_rt =
        (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;

    long long sum = alignment_int64_array_sum(fqdn_plugin_rt->scan_times,
                                              fqdn_plugin_rt->n_worker_thread);

    alignment_int64_array_reset(fqdn_plugin_rt->scan_times,
                                fqdn_plugin_rt->n_worker_thread);

    return sum;
}