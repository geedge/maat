/*
**********************************************************************************************
*	File: maat_api.cpp
*   Description: maat api entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "utils.h"
#include "maat_utils.h"
#include "json2iris.h"
#include "maat/maat.h"
#include "maat_rule.h"
#include "maat_common.h"
#include "maat_kv.h"
#include "maat_command.h"
#include "maat_ex_data.h"
#include "maat_table.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"
#include "maat_compile.h"
#include "alignment.h"
#include "maat_garbage_collection.h"
#include "maat_group.h"
#include "maat_expr.h"
#include "maat_ip.h"
#include "maat_plugin.h"
#include "maat_ip_plugin.h"

#define MODULE_MAAT_API	 module_name_str("maat.api")

#define	DISTRICT_ANY		-1
#define	DISTRICT_UNKNOWN	-2

inline int scan_state_should_compile_NOT(struct maat_state *mid)
{
	if (mid && mid->is_last_scan==1 && mid->compile_mid &&
		maat_compile_state_has_NOT_clause(mid->compile_mid)) {
		return 1;
	} else {
		return 0;
	}
}

struct maat_options* maat_options_new(void)
{
    struct maat_options *options = ALLOC(struct maat_options, 1);

    options->nr_worker_threads = 1;
    options->deferred_load_on = 0;
    options->rule_effect_interval_ms = 60 * 1000;
    options->rule_update_checking_interval_ms = 1 * 1000;
    options->gc_timeout_ms = 10 * 1000;
    options->input_mode = DATA_SOURCE_NONE;
    options->log_level = 0;

    return options;
}

void maat_options_free(struct maat_options *opts)
{
    if (NULL == opts) {
        return;
    }

    if (opts->accept_tags != NULL) {
        FREE(opts->accept_tags);
    }

    FREE(opts);
}

int maat_options_set_caller_thread_number(struct maat_options *opts, size_t n_thread)
{
    opts->nr_worker_threads = n_thread;
    
    return 0;
}

int maat_options_set_accept_tags(struct maat_options *opts, const char *accept_tags)
{
    opts->accept_tags = maat_strdup(accept_tags);

    return 0;
}

int maat_options_set_rule_effect_interval_ms(struct maat_options *opts, int interval_ms)
{
    opts->rule_effect_interval_ms = interval_ms;
    
    return 0;
}

int maat_options_set_rule_update_checking_interval_ms(struct maat_options *opts, int interval_ms)
{
    opts->rule_update_checking_interval_ms = interval_ms;

    return 0;
}

int maat_options_set_gc_timeout_ms(struct maat_options *opts, int interval_ms)
{
    opts->gc_timeout_ms = interval_ms;

    return 0;
}

int maat_options_set_instance_name(struct maat_options *opts, const char *instance_name, size_t name_len)
{
    memcpy(opts->instance_name, instance_name, name_len);

    return 0;
}

int maat_options_set_deferred_load_on(struct maat_options *opts)
{
    opts->deferred_load_on = 1;

    return 0;
}

int maat_options_set_iris(struct maat_options *opts, const char *full_directory, const char *increment_directory)
{
    if (strlen(full_directory) >= NAME_MAX || strlen(increment_directory) >= NAME_MAX) {
        return -1;
    }

    memcpy(opts->iris_ctx.full_idx_dir, full_directory, strlen(full_directory));
    memcpy(opts->iris_ctx.inc_idx_dir, increment_directory, strlen(increment_directory));
    opts->input_mode = DATA_SOURCE_IRIS_FILE;

    return 0;
}

int maat_options_set_json_file(struct maat_options *opts, const char *json_filename)
{
    strncpy(opts->json_ctx.json_file, json_filename, sizeof(opts->json_ctx.json_file));
    opts->input_mode = DATA_SOURCE_JSON_FILE;

    return 0;
}

int maat_options_set_redis(struct maat_options *opts, const char *redis_ip, uint16_t redis_port, int redis_db)
{
    memcpy(opts->redis_ctx.redis_ip, redis_ip, strlen(redis_ip));
    opts->redis_ctx.redis_port = redis_port;
    opts->redis_ctx.redis_db = redis_db;
    opts->input_mode = DATA_SOURCE_REDIS;

    return 0;
}

int maat_options_set_logger(struct maat_options *opts, void *logger)
{
    opts->logger = (struct log_handle *)logger;

    return 0;
}

void maat_read_full_config(struct maat *maat_instance)
{
    int ret = -1;
    char err_str[NAME_MAX] = {0};
    struct source_redis_ctx *mr_ctx = NULL;

    switch (maat_instance->input_mode) {
        case DATA_SOURCE_REDIS:
            mr_ctx = &(maat_instance->mr_ctx);
            log_info(maat_instance->logger, MODULE_MAAT_API, "Maat initiate from Redis %s:%hu db%d", 
                     mr_ctx->redis_ip, mr_ctx->redis_port, mr_ctx->redis_db);
            mr_ctx->read_ctx = maat_cmd_connect_redis(mr_ctx->redis_ip, mr_ctx->redis_port, 
                                                      mr_ctx->redis_db, maat_instance->logger);
            if (mr_ctx->read_ctx != NULL) {
                redis_monitor_traverse(maat_instance->maat_version, mr_ctx,
									   maat_start_cb, maat_update_cb, maat_finish_cb,
									   maat_instance);
            }

            if (NULL == maat_instance->creating_maat_rt) {
                log_error(maat_instance->logger, MODULE_MAAT_API, 
                          "At initiation: NO effective rule in redis %s:%hu db%d",
                          mr_ctx->redis_ip, mr_ctx->redis_port, mr_ctx->redis_db);
            }
            break;
        case DATA_SOURCE_IRIS_FILE:
			config_monitor_traverse(maat_instance->maat_version,
                                    maat_instance->iris_ctx.full_idx_dir,
                                    maat_start_cb, maat_update_cb, maat_finish_cb,
                                    maat_instance, maat_instance->logger);
            if (NULL == maat_instance->creating_maat_rt) {
                log_error(maat_instance->logger, MODULE_MAAT_API, 
                          "At initiation: NO effective rule in %s",
                          maat_instance->iris_ctx.full_idx_dir);
            }
            break;
        case DATA_SOURCE_JSON_FILE:
            ret = load_maat_json_file(maat_instance, maat_instance->json_ctx.json_file, err_str, sizeof(err_str));
            if (ret < 0) {
                log_error(maat_instance->logger, MODULE_MAAT_API, "Maat re-initiate with JSON file %s failed: %s", 
                          maat_instance->json_ctx.json_file, err_str);
                return;
            }
            
            config_monitor_traverse(maat_instance->maat_version,
                                    maat_instance->json_ctx.iris_file,
                                    maat_start_cb, maat_update_cb, maat_finish_cb,
                                    maat_instance, maat_instance->logger);
            if (NULL == maat_instance->creating_maat_rt) {
                log_error(maat_instance->logger, MODULE_MAAT_API, "At initiation: NO effective rule in %s",
                          maat_instance->json_ctx.iris_file);
            }
            break;
        default:
            break;
    }

    maat_instance->maat_rt = maat_instance->creating_maat_rt;
    maat_instance->creating_maat_rt = NULL;
    maat_instance->is_running = 1;
    if (maat_instance->maat_rt != NULL) {
        maat_instance->maat_version = maat_instance->maat_rt->version;
        maat_instance->last_full_version = maat_instance->maat_rt->version;
    }
}

struct maat *maat_new(struct maat_options *opts, const char *table_info_path)
{
    if (NULL == table_info_path) {
        return NULL;
    }

    int garbage_gc_timeout_s = 0;
    struct maat *maat_instance = ALLOC(struct maat, 1);
    
    if (opts->logger != NULL) {
        maat_instance->logger = opts->logger;
    } else {
        char log_path[1024] = {0};
        if (strlen(maat_instance->instance_name) > 0) {
            snprintf(log_path, sizeof(log_path), "%s.log", maat_instance->instance_name);
        } else {
            snprintf(log_path, sizeof(log_path), "maat.log");
        }
        maat_instance->logger = log_handle_create(log_path, opts->log_level);
    }

    maat_instance->tbl_mgr = table_manager_create(table_info_path, opts->accept_tags, maat_instance->logger);
    if (NULL == maat_instance->tbl_mgr) {
        goto failed;
    }

    maat_instance->default_compile_table_id = table_manager_get_defaut_compile_table_id(maat_instance->tbl_mgr);

    maat_instance->input_mode = opts->input_mode;
    switch (maat_instance->input_mode) {
        case DATA_SOURCE_REDIS:
            memcpy(maat_instance->mr_ctx.redis_ip, opts->redis_ctx.redis_ip, strlen(opts->redis_ctx.redis_ip));
            maat_instance->mr_ctx.redis_port = opts->redis_ctx.redis_port;
            maat_instance->mr_ctx.redis_db = opts->redis_ctx.redis_db;
            break;
        case DATA_SOURCE_IRIS_FILE:
            memcpy(maat_instance->iris_ctx.full_idx_dir, opts->iris_ctx.full_idx_dir, strlen(opts->iris_ctx.full_idx_dir));
            memcpy(maat_instance->iris_ctx.inc_idx_dir, opts->iris_ctx.inc_idx_dir, strlen(opts->iris_ctx.inc_idx_dir));
            break;
        case DATA_SOURCE_JSON_FILE:
            memcpy(maat_instance->json_ctx.json_file, opts->json_ctx.json_file, strlen(opts->json_ctx.json_file));
            break;
        default:
            log_error(maat_instance->logger, MODULE_MAAT_API, "data source unsupported:%d", maat_instance->input_mode);
            goto failed;
    }

    maat_instance->is_running = 0;
    maat_instance->maat_version = 0;
    maat_instance->last_full_version = 0;
    maat_instance->nr_worker_thread = opts->nr_worker_threads;
    maat_instance->rule_effect_interval_ms = opts->rule_effect_interval_ms;
    maat_instance->gc_timeout_ms = opts->gc_timeout_ms;
    maat_instance->deferred_load = opts->deferred_load_on;
    garbage_gc_timeout_s = (maat_instance->rule_effect_interval_ms / 1000) +
                                (maat_instance->gc_timeout_ms / 1000);
    maat_instance->garbage_bin = maat_garbage_bin_new(garbage_gc_timeout_s);

    maat_instance->outer_mid_cnt = alignment_int64_array_alloc(opts->nr_worker_threads);
    maat_instance->compile_mid_cnt = alignment_int64_array_alloc(opts->nr_worker_threads);
    maat_instance->thread_call_cnt = alignment_int64_array_alloc(opts->nr_worker_threads);

    pthread_mutex_init(&(maat_instance->background_update_mutex), NULL);

    if (0 == maat_instance->deferred_load) {
        maat_read_full_config(maat_instance);
    }

    pthread_create(&(maat_instance->cfg_mon_thread), NULL, rule_monitor_loop, (void *)maat_instance);

    return maat_instance;
failed:
    FREE(maat_instance);
    return NULL;
}

void maat_free(struct maat *maat_instance)
{
    if (NULL == maat_instance) {
        return;
    }

    void *ret = NULL;

    maat_instance->is_running = 0;
	pthread_join(maat_instance->cfg_mon_thread, &ret);
}

int maat_table_get_id(struct maat *maat_instance, const char *table_name)
{
    int table_id = -1;

    struct table_manager *table_mgr = maat_instance->tbl_mgr;
    table_id = table_manager_get_table_id(table_mgr, table_name);
    
    return table_id;
}

inline void maat_runtime_ref_inc(struct maat_runtime *maat_rt, int thread_id)
{
	alignment_int64_array_add(maat_rt->ref_cnt, thread_id, 1);
}

inline void maat_runtime_ref_dec(struct maat_runtime *maat_rt, int thread_id)
{
	alignment_int64_array_add(maat_rt->ref_cnt, thread_id, -1);
}

void fill_maat_rule(struct maat_rule *rule, const struct maat_rule_head *rule_head,
                    const char *srv_def, int srv_def_len)
{
    memcpy(rule, rule_head, sizeof(struct maat_rule_head));
	memcpy(rule->service_defined, srv_def, MIN(srv_def_len, MAX_SERVICE_DEFINE_LEN));
}

size_t generic_plugin_runtime_cached_row_count(void *custom_rt, enum table_type table_type)
{
    return 0;
}

const char *generic_plugin_runtime_get_cached_row(void *custom_rt, enum table_type table_type, size_t row_id)
{
    return NULL;
}

/* must be plugin table */
int maat_table_callback_register(struct maat *maat_instance, int table_id,
								 maat_start_callback_t *start,
								 maat_update_callback_t *update,
								 maat_finish_callback_t *finish,
								 void *u_para)
{
    int ret = -1;

    pthread_mutex_lock(&(maat_instance->background_update_mutex));
    void *schema = table_manager_get_schema(maat_instance->tbl_mgr, table_id);
    ret = plugin_table_add_callback(schema, table_id, start, update, finish, 
                                    u_para, maat_instance->logger);
    if (ret < 0) {
        pthread_mutex_unlock(&(maat_instance->background_update_mutex));
        return -1;
    }

    if (!maat_instance->maat_rt) {
        pthread_mutex_unlock(&(maat_instance->background_update_mutex));
        return 0;
    }

    void *runtime = table_manager_get_runtime(maat_instance->tbl_mgr, table_id);
    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    size_t row_cnt = generic_plugin_runtime_cached_row_count(runtime, table_type);

    if (row_cnt > 0) {
        if (start != NULL) {
            start(MAAT_RULE_UPDATE_TYPE_FULL, u_para);
        }

        for (size_t i = 0; i < row_cnt; i++) {
            const char *line = generic_plugin_runtime_get_cached_row(runtime, table_type, i);
            if (NULL == line) {
                break;
            }

            update(table_id, line, u_para);
        }

        if (finish != NULL) {
            finish(u_para);
        }
    }

    pthread_mutex_unlock(&(maat_instance->background_update_mutex));

    return 0;
}

int generic_plugin_table_ex_schema_register(struct table_manager *tbl_mgr, int table_id,
									       maat_plugin_ex_new_func_t *new_func,
									       maat_plugin_ex_free_func_t *free_func,
									       maat_plugin_ex_dup_func_t *dup_func,
									       long argl, void *argp, struct log_handle *logger)
{
    if (NULL == tbl_mgr || NULL == new_func || NULL == free_func || NULL == dup_func) {
        assert(0);
        log_error(logger, MODULE_MAAT_API, 
                  "table(table_id:%d) %s failed: invalid parameter", __FUNCTION__);
        return -1;
    }

    void *schema = table_manager_get_schema(tbl_mgr, table_id);
    if (NULL == schema) {
        log_error(logger, MODULE_MAAT_API, 
                  "Error: %s, table(table_id:%d) is not registered", __FUNCTION__, table_id);
        return -1;
    }

    struct ex_data_schema *ex_schema = NULL;
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            ex_schema = plugin_table_get_ex_data_schema(schema);
            if (NULL == ex_schema) {
                log_error(logger, MODULE_MAAT_API,
                          "Error: %s, table(table_id:%d) is not a valid plugin table",
                          __FUNCTION__, table_id);
                return -1;
            }
            plugin_table_set_ex_data_schema(schema, new_func, free_func,
                                            dup_func, argl, argp, logger);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ex_schema = ip_plugin_table_get_ex_data_schema(schema);
            if (NULL == ex_schema) {
                log_error(logger, MODULE_MAAT_API,
                          "Error: %s, table(table_id:%d) is not a valid ip_plugin table",
                          __FUNCTION__, table_id);
                return -1;
            }
            ip_plugin_table_set_ex_data_schema(schema, new_func, free_func,
                                                dup_func, argl, argp, logger);
            break;
        default:
            break;
    }

    return 0;
}

void generic_plugin_runtime_commit_ex_schema(void *runtime, void *schema, int table_id,
                                             enum table_type table_type, int valid_column)
{
    struct ex_data_schema *ex_data_schema = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            ex_data_schema = plugin_table_get_ex_data_schema(schema);
            ex_data_rt = plugin_runtime_get_ex_data_rt(runtime);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ex_data_schema = ip_plugin_table_get_ex_data_schema(schema);
            ex_data_rt = ip_plugin_runtime_get_ex_data_rt(runtime);
            break;
        default:
            break;
    }

    ex_data_runtime_set_schema(ex_data_rt, ex_data_schema);
    struct ex_container_ctx *ex_ctx = ALLOC(struct ex_container_ctx, 1);
    ex_ctx->table_id = table_id;
    ex_ctx->ex_schema = ex_data_schema;
    ex_data_runtime_set_ex_container_ctx(ex_data_rt, ex_ctx);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const char *row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        switch (table_type) {
            case TABLE_TYPE_PLUGIN:
                plugin_runtime_update(runtime, schema, row, valid_column);
                break;
            case TABLE_TYPE_IP_PLUGIN:
                ip_plugin_runtime_update(runtime, schema, row, valid_column);
                break;
            default:
                break;
        }
    }
    ex_data_runtime_clear_row_cache(ex_data_rt);

    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            plugin_runtime_commit(runtime);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ip_plugin_runtime_commit(runtime);
            break;
        default:
            break;
    }
}

int maat_plugin_table_ex_schema_register(struct maat *maat_instance, int table_id,
                                         maat_plugin_ex_new_func_t *new_func,
                                         maat_plugin_ex_free_func_t *free_func,
                                         maat_plugin_ex_dup_func_t *dup_func,
                                         long argl, void *argp)
{
    pthread_mutex_lock(&(maat_instance->background_update_mutex));
    int ret = generic_plugin_table_ex_schema_register(maat_instance->tbl_mgr, table_id,
                                                      new_func, free_func, dup_func, argl, argp,
                                                      maat_instance->logger);
    if (ret < 0) {
        pthread_mutex_unlock(&(maat_instance->background_update_mutex));
        return -1;
    }
    
    if (maat_instance->maat_rt != NULL) {
        void *runtime = table_manager_get_runtime(maat_instance->tbl_mgr, table_id);
        void *schema = table_manager_get_schema(maat_instance->tbl_mgr, table_id);
        enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
        int valid_column = table_manager_get_valid_column(maat_instance->tbl_mgr, table_id);
        generic_plugin_runtime_commit_ex_schema(runtime, schema, table_id, table_type, valid_column);
    }
    pthread_mutex_unlock(&(maat_instance->background_update_mutex));

    return 0;
}

void *maat_plugin_table_get_ex_data(struct maat *maat_instance, int table_id, const char *key, size_t key_len)
{
    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        return NULL;
    }

    enum table_type table_type = table_manager_get_table_type(maat_rt->ref_tbl_mgr, table_id);
    void *runtime = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == runtime) {
        return NULL;
    }

    struct ex_data_runtime *ex_data_rt = NULL;
    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            ex_data_rt = plugin_runtime_get_ex_data_rt(runtime);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ex_data_rt = ip_plugin_runtime_get_ex_data_rt(runtime);
            break;
        default:
            break;
    }
  
    if (NULL == ex_data_rt) {
        return NULL;
    }

    return ex_data_runtime_get_ex_data(ex_data_rt, key, key_len);
}

static void scan_count_inc(struct maat_state *mid)
{
	mid->scan_cnt++;
}

struct maat_state *make_outer_state(struct maat *maat_instance, int thread_id)
{
	struct maat_state *outer_state = NULL;

	outer_state = ALLOC(struct maat_state, 1);
	outer_state->maat_instance = maat_instance;
	outer_state->district_id = DISTRICT_ANY;
	outer_state->thread_id = (signed short)thread_id;
    outer_state->compile_table_id = -1; //-1 means caller not specify compile table, use default compile table

	return outer_state;
}

struct maat_state *grab_state(struct maat_state **state, struct maat *maat_instance, int thread_id)
{
    struct maat_state *mid = *state;

	if (NULL == mid) {
		mid = make_outer_state(maat_instance, thread_id);
        *state = mid;
        //Maat_set_scan_status calls grap_mid() with thread_num=-1.
		if (mid->thread_id >= 0) {
			alignment_int64_array_add(maat_instance->outer_mid_cnt, thread_id, 1);
		}
	}

	if (mid->thread_id < 0 && thread_id >= 0) {
		mid->thread_id = thread_id;		
		alignment_int64_array_add(maat_instance->outer_mid_cnt, thread_id, 1);
	}

    if (NULL == mid->compile_mid) {
        mid->compile_mid = maat_compile_state_new(thread_id);
        alignment_int64_array_add(maat_instance->compile_mid_cnt, thread_id, 1);
    }

    return mid;
}

int hit_group_to_compile(void *g2g_runtime, int *group_ids, int group_hit_cnt, int vt_id,
                         void *compile_runtime, int *compile_ids, size_t n_compile_id,
                         size_t *n_hit_compile_id, struct maat_state *mid)
{
    int top_group_ids[MAX_SCANNER_HIT_GROUP_NUM] = {-1};
    int n_top_group_ids = group2group_runtime_get_top_groups(g2g_runtime, group_ids, group_hit_cnt, top_group_ids);
    size_t n_all_group_ids = 0;
    if (n_top_group_ids > 0) {
        n_all_group_ids = group_hit_cnt + n_top_group_ids;
    } else {
        n_all_group_ids = group_hit_cnt;
    }

    int all_group_ids[n_all_group_ids] = {-1};
    // maat state find compile_table_id, if not found, maat_instance->default_compile_table_id
    int n_compile_ids = compile_runtime_match((struct compile_runtime *)compile_runtime, all_group_ids, n_all_group_ids,
                                               vt_id, compile_ids, n_compile_id, mid);
    *n_hit_compile_id = n_compile_ids;
    if (n_compile_ids > 0) {
        return MAAT_HIT;
    } else {
        return MAAT_HALF_HIT;
    }
}

int maat_scan_integer(struct maat *instance, int table_id, int thread_id,
                      unsigned int intval, int *results, size_t n_result,
                      size_t *n_hit_result, struct maat_state **state)
{
    return 0;
}

int maat_scan_ipv4(struct maat *maat_instance, int table_id, int thread_id, 
                   uint32_t ip_addr, int *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state **state)
{
    if ((NULL == maat_instance) || (table_id < 0) || (table_id >= MAX_TABLE_NUM) ||
        (thread_id < 0) || (NULL == results) || (0 == n_result) || (NULL == state)) {
        return -1;
    }

    struct maat_state *mid = NULL;
    mid = grab_state(state, maat_instance, thread_id);
    scan_count_inc(mid);

    int virtual_table_id = 0;
    // struct table_schema *table_schema = table_schema_get_by_scan_type(maat_instance->table_schema_mgr, table_id,
    //                                                                   SCAN_TYPE_IP, &virtual_table_id);
    // if (NULL == table_schema) {
    //     return MAAT_ERR;
    // }

    int group_ids[MAX_SCANNER_HIT_GROUP_NUM] = {-1};
    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    assert(table_type == TABLE_TYPE_IP_PLUS);

    // int table_id = table_schema_get_table_id(real_table);
    void *ip_plus_rt = table_manager_get_runtime(maat_instance->tbl_mgr, table_id);
    // size_t rule_num = table_runtime_rule_count(table_rt);
    // if (0 == rule_num) {
    //     return 0;
    // }

    int group_hit_cnt = ip_plus_runtime_scan_ipv4((struct ip_plus_runtime *)ip_plus_rt, thread_id, ip_addr, 
                                                  group_ids, MAX_SCANNER_HIT_GROUP_NUM, virtual_table_id, mid);
    if (group_hit_cnt < 0) {
        return MAAT_ERR;
    } else if (0 == group_hit_cnt) {
        return MAAT_OK;
    } else {
        // come here means group_hit_cnt > 0, at least MAAT_HALF_HIT, or MAAT_HIT
        void *g2g_runtime = table_manager_get_runtime(maat_instance->tbl_mgr, maat_instance->g2g_table_id);
        void *compile_runtime = table_manager_get_runtime(maat_instance->tbl_mgr, maat_instance->default_compile_table_id);
        int ret = hit_group_to_compile(g2g_runtime, group_ids, group_hit_cnt, virtual_table_id, compile_runtime,
                                       results, n_result, n_hit_result, mid);
        return ret;
    }
}


int maat_scan_ipv6(struct maat *instance, int table_id, int thread_id, 
                   uint8_t *ip_addr, int *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state **state)
{
    return 0;
}

int maat_scan_string(struct maat *maat_instance, int table_id, int thread_id,
                     const char *data, size_t data_len, int *results, size_t n_result,
                     size_t *n_hit_result, struct maat_state **state)
{
    if ((NULL == maat_instance) || (table_id < 0) || (table_id >= MAX_TABLE_NUM) ||
        (thread_id < 0) || (NULL == data) || (0 == data_len) || (NULL == results) || 
        (0 == n_result) || (NULL == state)) {
        return MAAT_ERR;
    }
    
    struct maat_state *mid = NULL;
    mid = grab_state(state, maat_instance, thread_id);
    scan_count_inc(mid);

    int virtual_table_id = 0;
    //TODO: by luis get virtual_table_id
    // struct table_schema *table_schema = table_schema_get_by_scan_type(maat_instance->table_schema_mgr, table_id,
    //                                                                   SCAN_TYPE_STRING, &virtual_table_id);
    // if (NULL == table_schema) {
    //     return MAAT_ERR;
    // }

    int group_ids[MAX_SCANNER_HIT_GROUP_NUM] = {-1};
    void *runtime = table_manager_get_runtime(maat_instance->tbl_mgr, table_id);
    int group_hit_cnt = expr_runtime_scan_string((struct expr_runtime *)runtime, thread_id, data, data_len, 
                                                 group_ids, MAX_SCANNER_HIT_GROUP_NUM, virtual_table_id, mid);
    if (group_hit_cnt < 0) {
        return MAAT_ERR;
    } else if (0 == group_hit_cnt) {
        return MAAT_OK;
    } else {
        // come here means group_hit_cnt > 0, at least MAAT_HALF_HIT, or MAAT_HIT
        void *g2g_runtime = table_manager_get_runtime(maat_instance->tbl_mgr, maat_instance->g2g_table_id);
        void *compile_runtime = table_manager_get_runtime(maat_instance->tbl_mgr, maat_instance->default_compile_table_id);
        int ret = hit_group_to_compile(g2g_runtime, group_ids, group_hit_cnt, virtual_table_id, compile_runtime,
                                       results, n_result, n_hit_result, mid);
        return ret;
    }
}

struct maat_stream *maat_scan_stream_open(struct maat *instance, int table_id, int thread_id)
{
    return NULL;
}

int maat_scan_stream(struct maat_stream **stream, int thread_id, const char *data, int data_len, 
                     int results[], size_t *n_result, struct maat_state **state)
{
    return 0;
}

void maat_scan_stream_close(struct maat_stream **stream)
{

}

int maat_state_set_scan_district(struct maat *maat_instance, struct maat_state **state, const char *district, size_t district_len)
{
    if (NULL == maat_instance->maat_rt || NULL == district || district_len <= 0) {
        return -1;
    }

    struct maat_state *mid = grab_state(state, maat_instance, -1);
    int map_ret = maat_kv_read_unNull(maat_instance->maat_rt->district_map, district, district_len, &(mid->district_id));
    if (map_ret < 0) {
        mid->district_id = DISTRICT_UNKNOWN;
    }

    mid->is_set_district = 1;

    return 0;
}

int maat_state_set_last_scan(struct maat *maat_instance, struct maat_state **state)
{
    if (NULL == maat_instance->maat_rt) {
        return -1;
    }

    struct maat_state *mid = grab_state(state, maat_instance, -1);
    assert(mid->is_last_scan == 0);
    mid->is_last_scan = 1;

    return 0;
}

int maat_state_set_scan_compile_table(struct maat *maat_instance, struct maat_state **state,
                                      int compile_table_id)
{
    if (NULL == maat_instance->maat_rt) {
        return -1;
    }

    struct maat_state *mid = grab_state(state, maat_instance, -1);
    mid->compile_table_id = compile_table_id;

    return 0;
}

size_t maat_get_hit_paths(struct maat *maat_instance, struct maat_state *mid,
                          struct maat_hit_path *paths, size_t n_path)
{
    int compile_table_id = -1;

    if (mid->compile_table_id == -1) {
        compile_table_id = maat_instance->default_compile_table_id;
    } else {
        compile_table_id = mid->compile_table_id;
    }

    void *compile_rt = table_manager_get_runtime(maat_instance->tbl_mgr, compile_table_id);
    void *g2g_runtime = table_manager_get_runtime(maat_instance->tbl_mgr, maat_instance->g2g_table_id);
    compile_runtime_get_hit_paths((struct compile_runtime *)compile_rt, 
                                  (struct group2group_runtime *)g2g_runtime, mid->compile_mid, paths, n_path);
    
    return 0;
}

size_t maat_get_hit_objects(struct maat_compile_state *compile_state, struct maat_hit_object *objs, size_t n_objs)
{
    return 0;
}

int maat_state_get_hit_paths(struct maat *maat_instance, struct maat_state **state,
                             struct maat_hit_path *paths, size_t n_path)
{
    struct maat_state *mid = NULL;

    mid = grab_state(state, maat_instance, 0);
    if (NULL == mid->compile_mid || NULL == maat_instance->maat_rt) {
        return 0;
    }

    int n_read = maat_get_hit_paths(mid->maat_instance, mid, paths, n_path);

    return n_read;
}

int maat_state_get_hit_objects(struct maat *instance, struct maat_state **state,
                               struct maat_hit_object *objs, size_t n_obj)
{
    return 0;
}

void maat_state_free(struct maat_state **state)
{
    struct maat_state *mid = NULL;
    if (NULL == *state) {
        return;
    }

    mid = *state;
    if (mid->thread_id >= 0) {
        alignment_int64_array_add(mid->maat_instance->outer_mid_cnt, mid->thread_id, -1);
    }

    if (mid->compile_mid != NULL) {
        maat_compile_state_free(mid->compile_mid);
        mid->compile_mid = NULL;
        alignment_int64_array_add(mid->maat_instance->compile_mid_cnt, mid->thread_id, -1);
    }
    
    mid->maat_instance = NULL;
    free(mid);
    *state = NULL;
}

int maat_hit_object_compile_id(struct maat *instance, struct maat_hit_object *obj)
{
    return 0;
}