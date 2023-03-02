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
#include <linux/limits.h>

#include "maat_utils.h"
#include "json2iris.h"
#include "maat.h"
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
#include "ip_matcher.h"
#include "maat_garbage_collection.h"
#include "maat_group.h"
#include "maat_expr.h"
#include "maat_flag.h"
#include "maat_interval.h"
#include "maat_ip.h"
#include "maat_plugin.h"
#include "maat_ip_plugin.h"
#include "maat_fqdn_plugin.h"
#include "maat_bool_plugin.h"
#include "maat_virtual.h"

#define MODULE_MAAT_API	 module_name_str("maat.api")

enum district_set_flag {
    DISTRICT_FLAG_UNSET,
    DISTRICT_FLAG_SET
};

struct maat_stream {
    struct maat *ref_maat_instance;
    int thread_id;
    int table_id;
    int vtable_id;
    int physical_table_ids[MAX_PHYSICAL_TABLE_NUM];
    size_t n_physical_table;
};

enum scan_type maat_table_get_scan_type(enum table_type table_type)
{
	enum scan_type ret = SCAN_TYPE_INVALID;

    switch (table_type) {
    case TABLE_TYPE_FLAG:
    case TABLE_TYPE_FLAG_PLUS:
        ret = SCAN_TYPE_FLAG;
        break;
    case TABLE_TYPE_EXPR:
    case TABLE_TYPE_EXPR_PLUS:
        ret = SCAN_TYPE_STRING;
        break;
    case TABLE_TYPE_INTERVAL:
    case TABLE_TYPE_INTERVAL_PLUS:
        ret = SCAN_TYPE_INTERVAL;
        break;
    case TABLE_TYPE_IP_PLUS:
        ret = SCAN_TYPE_IP;
        break;
    case TABLE_TYPE_PLUGIN:
        ret = SCAN_TYPE_PLUGIN;
        break;
    case TABLE_TYPE_IP_PLUGIN:
        ret = SCAN_TYPE_IP;
        break;
    case TABLE_TYPE_FQDN_PLUGIN:
        ret = SCAN_TYPE_FQDN_PLUGIN;
        break;
    case TABLE_TYPE_BOOL_PLUGIN:
        ret = SCAN_TYPE_BOOL_PLUGIN;
        break;
    case TABLE_TYPE_COMPILE:
        ret = SCAN_TYPE_NONE;
        break;
    default:
        break;
    }

    return ret;
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

int maat_options_set_instance_name(struct maat_options *opts, const char *instance_name,
                                   size_t name_len)
{
    memcpy(opts->instance_name, instance_name, name_len);

    return 0;
}

int maat_options_set_deferred_load_on(struct maat_options *opts)
{
    opts->deferred_load_on = 1;

    return 0;
}

int maat_options_set_iris(struct maat_options *opts, const char *full_directory,
                          const char *increment_directory)
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

int maat_options_set_redis(struct maat_options *opts, const char *redis_ip,
                           uint16_t redis_port, int redis_db)
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
            log_info(maat_instance->logger, MODULE_MAAT_API, 
                     "Maat initiate from Redis %s:%hu db%d", 
                     mr_ctx->redis_ip, mr_ctx->redis_port, mr_ctx->redis_db);
            mr_ctx->read_ctx = maat_cmd_connect_redis(mr_ctx->redis_ip,
                                                      mr_ctx->redis_port, 
                                                      mr_ctx->redis_db,
                                                      maat_instance->logger);
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
            ret = load_maat_json_file(maat_instance, maat_instance->json_ctx.json_file,
                                      err_str, sizeof(err_str));
            if (ret < 0) {
                log_error(maat_instance->logger, MODULE_MAAT_API, 
                          "Maat re-initiate with JSON file %s failed: %s", 
                          maat_instance->json_ctx.json_file, err_str);
                return;
            }
            
            config_monitor_traverse(maat_instance->maat_version,
                                    maat_instance->json_ctx.iris_file,
                                    maat_start_cb, maat_update_cb, maat_finish_cb,
                                    maat_instance, maat_instance->logger);
            if (NULL == maat_instance->creating_maat_rt) {
                log_error(maat_instance->logger, MODULE_MAAT_API, 
                          "At initiation: NO effective rule in %s",
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
            snprintf(log_path, sizeof(log_path), "%s.log", 
                     maat_instance->instance_name);
        } else {
            snprintf(log_path, sizeof(log_path), "maat.log");
        }
        maat_instance->logger = log_handle_create(log_path, opts->log_level);
    }

    maat_instance->input_mode = opts->input_mode;

    switch (maat_instance->input_mode) {
        case DATA_SOURCE_REDIS:
            memcpy(maat_instance->mr_ctx.redis_ip, opts->redis_ctx.redis_ip,
                   strlen(opts->redis_ctx.redis_ip));
            maat_instance->mr_ctx.redis_port = opts->redis_ctx.redis_port;
            maat_instance->mr_ctx.redis_db = opts->redis_ctx.redis_db;
            break;
        case DATA_SOURCE_IRIS_FILE:
            memcpy(maat_instance->iris_ctx.full_idx_dir, opts->iris_ctx.full_idx_dir,
                   strlen(opts->iris_ctx.full_idx_dir));
            memcpy(maat_instance->iris_ctx.inc_idx_dir, opts->iris_ctx.inc_idx_dir,
                   strlen(opts->iris_ctx.inc_idx_dir));
            break;
        case DATA_SOURCE_JSON_FILE:
            memcpy(maat_instance->json_ctx.json_file, opts->json_ctx.json_file,
                   strlen(opts->json_ctx.json_file));
            break;
        default:
            log_error(maat_instance->logger, MODULE_MAAT_API, 
                      "data source unsupported:%d", maat_instance->input_mode);
            goto failed;
    }

    maat_instance->is_running = 0;
    maat_instance->maat_version = 0;
    maat_instance->last_full_version = 0;
    maat_instance->nr_worker_thread = opts->nr_worker_threads;
    maat_instance->rule_effect_interval_ms = opts->rule_effect_interval_ms;
    maat_instance->rule_update_checking_interval_ms = opts->rule_update_checking_interval_ms;
    maat_instance->gc_timeout_ms = opts->gc_timeout_ms;
    maat_instance->deferred_load = opts->deferred_load_on;
    garbage_gc_timeout_s = (maat_instance->rule_effect_interval_ms / 1000) +
                                (maat_instance->gc_timeout_ms / 1000);
    maat_instance->garbage_bin = maat_garbage_bin_new(garbage_gc_timeout_s);

    maat_instance->tbl_mgr = table_manager_create(table_info_path, opts->accept_tags,
                                                  maat_instance->garbage_bin, maat_instance->logger);
    if (NULL == maat_instance->tbl_mgr) {
        goto failed;
    }

    maat_instance->default_compile_table_id = table_manager_get_defaut_compile_table_id(maat_instance->tbl_mgr);
    maat_instance->g2g_table_id = table_manager_get_group2group_table_id(maat_instance->tbl_mgr);

    maat_instance->outer_state_cnt = alignment_int64_array_alloc(opts->nr_worker_threads);
    maat_instance->compile_state_cnt = alignment_int64_array_alloc(opts->nr_worker_threads);
    maat_instance->thread_call_cnt = alignment_int64_array_alloc(opts->nr_worker_threads);
    maat_instance->hit_cnt = alignment_int64_array_alloc(opts->nr_worker_threads);
    maat_instance->not_grp_hit_cnt = alignment_int64_array_alloc(opts->nr_worker_threads);

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

int maat_helper_read_column(const char *table_line, int Nth_column, 
                            size_t *column_offset, size_t *column_len)
{
    return get_column_pos(table_line, Nth_column, column_offset, column_len);
}

int maat_get_table_id(struct maat *maat_instance, const char *table_name)
{
    int table_id = -1;

    struct table_manager *table_mgr = maat_instance->tbl_mgr;
    table_id = table_manager_get_table_id(table_mgr, table_name);
    
    return table_id;
}

static inline void maat_runtime_ref_inc(struct maat_runtime *maat_rt, int thread_id)
{
	alignment_int64_array_add(maat_rt->ref_cnt, thread_id, 1);
}

static inline void maat_runtime_ref_dec(struct maat_runtime *maat_rt, int thread_id)
{
	alignment_int64_array_add(maat_rt->ref_cnt, thread_id, -1);
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
    assert(table_type == TABLE_TYPE_PLUGIN);
    size_t row_cnt = plugin_runtime_cached_row_count(runtime);

    if (row_cnt > 0) {
        if (start != NULL) {
            start(MAAT_UPDATE_TYPE_FULL, u_para);
        }

        for (size_t i = 0; i < row_cnt; i++) {
            const char *line = plugin_runtime_cached_row_get(runtime, i);
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

int compile_table_ex_schema_register(struct maat *maat_instance, int table_id,
                                     maat_ex_new_func_t *new_func,
                                     maat_ex_free_func_t *free_func,
                                     maat_ex_dup_func_t *dup_func,
                                     long argl, void *argp)
{
    void *schema = table_manager_get_schema(maat_instance->tbl_mgr, table_id);
    assert(schema != NULL);

    int ret = compile_table_set_ex_data_schema((struct compile_schema *)schema,
                                                table_id, new_func, free_func, dup_func, 
                                                argl, argp, maat_instance->logger);
    if (ret < 0) {
        return -1;
    }

    if (maat_instance->maat_rt != NULL) {
        void *runtime = table_manager_get_runtime(maat_instance->tbl_mgr, table_id);
        assert(runtime != NULL);
        compile_runtime_ex_data_iterate((struct compile_runtime *)runtime,
                                        (struct compile_schema *)schema);
    }

    return 0;    
}

int generic_plugin_table_set_ex_schema(struct table_manager *tbl_mgr, int table_id,
									   maat_ex_new_func_t *new_func,
									   maat_ex_free_func_t *free_func,
									   maat_ex_dup_func_t *dup_func,
									   long argl, void *argp, struct log_handle *logger)
{
    void *schema = table_manager_get_schema(tbl_mgr, table_id);
    if (NULL == schema) {
        log_error(logger, MODULE_MAAT_API, 
                  "Error: %s, table(table_id:%d) is not registered, can't register ex schema", 
                  __FUNCTION__, table_id);
        return -1;
    }

    struct ex_data_schema *ex_schema = NULL;
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            ex_schema = plugin_table_get_ex_data_schema(schema);
            if (ex_schema != NULL) {
                log_error(logger, MODULE_MAAT_API,
                          "Error: %s, EX data schema already registed for plugin table(table_id:%d)",
                          __FUNCTION__, table_id);
                return -1;
            }
            plugin_table_set_ex_data_schema(schema, new_func, free_func,
                                            dup_func, argl, argp, logger);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ex_schema = ip_plugin_table_get_ex_data_schema(schema);
            if (ex_schema != NULL) {
                log_error(logger, MODULE_MAAT_API,
                          "Error: %s, EX data schema already registed for ip_plugin table(table_id:%d)",
                          __FUNCTION__, table_id);
                return -1;
            }
            ip_plugin_table_set_ex_data_schema(schema, new_func, free_func,
                                                dup_func, argl, argp, logger);
            break;
        case TABLE_TYPE_FQDN_PLUGIN:
            ex_schema = fqdn_plugin_table_get_ex_data_schema(schema);
            if (ex_schema != NULL) {
                log_error(logger, MODULE_MAAT_API,
                          "Error: %s, EX data schema already registed for fqdn_plugin table(table_id:%d)",
                          __FUNCTION__, table_id);
                return -1;
            }
            fqdn_plugin_table_set_ex_data_schema(schema, new_func, free_func,
                                                dup_func, argl, argp, logger);
            break;
        case TABLE_TYPE_BOOL_PLUGIN:
            ex_schema = bool_plugin_table_get_ex_data_schema(schema);
            if (ex_schema != NULL) {
                log_error(logger, MODULE_MAAT_API,
                          "Error: %s, EX data schema already registed for bool_plugin table(table_id:%d)",
                          __FUNCTION__, table_id);
                return -1;
            }
            bool_plugin_table_set_ex_data_schema(schema, new_func, free_func,
                                                dup_func, argl, argp, logger);
            break;
        default:
            log_error(logger, MODULE_MAAT_API,
                      "Error: %s, table(table_id:%d) is not plugin table, can't set ex schema",
                      __FUNCTION__, table_id);
            return -1;
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
        case TABLE_TYPE_FQDN_PLUGIN:
            ex_data_schema = fqdn_plugin_table_get_ex_data_schema(schema);
            ex_data_rt = fqdn_plugin_runtime_get_ex_data_rt(runtime);
            break;
        case TABLE_TYPE_BOOL_PLUGIN:
            ex_data_schema = bool_plugin_table_get_ex_data_schema(schema);
            ex_data_rt = bool_plugin_runtime_get_ex_data_rt(runtime);
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
            case TABLE_TYPE_FQDN_PLUGIN:
                fqdn_plugin_runtime_update(runtime, schema, row, valid_column);
                break;
            case TABLE_TYPE_BOOL_PLUGIN:
                bool_plugin_runtime_update(runtime, schema, row, valid_column);
                break;
            default:
                break;
        }
    }
    ex_data_runtime_clear_row_cache(ex_data_rt);

    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            plugin_runtime_commit(runtime, "unknown");
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ip_plugin_runtime_commit(runtime, "unknown");
            break;
        case TABLE_TYPE_FQDN_PLUGIN:
            fqdn_plugin_runtime_commit(runtime, "unknown");
            break;
        case TABLE_TYPE_BOOL_PLUGIN:
            bool_plugin_runtime_commit(runtime, "unknown");
            break;
        default:
            break;
    }
}

int generic_plugin_table_ex_schema_register(struct maat *maat_instance, int table_id,
									        maat_ex_new_func_t *new_func,
									        maat_ex_free_func_t *free_func,
									        maat_ex_dup_func_t *dup_func,
									        long argl, void *argp)
{
    int ret = generic_plugin_table_set_ex_schema(maat_instance->tbl_mgr, table_id, 
                                                 new_func, free_func, dup_func,
                                                 argl, argp, maat_instance->logger);
    if (ret < 0) {
        return -1;
    }
    
    enum table_type table_type = TABLE_TYPE_INVALID;
    int valid_column = -1;
    if (maat_instance->maat_rt != NULL) {
        void *runtime = table_manager_get_runtime(maat_instance->tbl_mgr, table_id);
        void *schema = table_manager_get_schema(maat_instance->tbl_mgr, table_id);
        assert(runtime != NULL && schema != NULL);

        table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
        valid_column = table_manager_get_valid_column(maat_instance->tbl_mgr, table_id);
        generic_plugin_runtime_commit_ex_schema(runtime, schema, table_id, table_type, valid_column);
    }

    return 0;
}

int maat_plugin_table_ex_schema_register(struct maat *maat_instance, int table_id,
                                         maat_ex_new_func_t *new_func,
                                         maat_ex_free_func_t *free_func,
                                         maat_ex_dup_func_t *dup_func,
                                         long argl, void *argp)
{
    if (NULL == maat_instance || table_id < 0 || table_id >= MAX_TABLE_NUM) {
        return -1;
    }

    pthread_mutex_lock(&(maat_instance->background_update_mutex));

    int ret = -1;
    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    if (TABLE_TYPE_COMPILE == table_type) {
        ret = compile_table_ex_schema_register(maat_instance, table_id, 
                                               new_func, free_func, dup_func,
                                               argl, argp);
    } else {
        ret = generic_plugin_table_ex_schema_register(maat_instance, table_id,
                                                      new_func, free_func, dup_func,
                                                      argl, argp);
    }

    pthread_mutex_unlock(&(maat_instance->background_update_mutex));
    return ret;
}

void *maat_plugin_table_get_ex_data(struct maat *maat_instance, int table_id,
                                    const char *key, size_t key_len)
{

    if (NULL == maat_instance || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || NULL == key || 0 == key_len) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "input parameter is invalid.");
        return NULL;
    }
    
    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, "maat runtime is NULL");
        return NULL;
    }

    void *runtime = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == runtime) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "table(table_id:%d) runtime is NULL", table_id);
        return NULL;
    }

    void *schema = table_manager_get_schema(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == schema) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "table(table_id:%d) schema is NULL", table_id);
        return NULL;
    }

    void *ret = NULL;
    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    if (TABLE_TYPE_COMPILE == table_type) {
        ret = compile_runtime_get_ex_data(runtime, schema, *(long long *)key);
    } else if (TABLE_TYPE_PLUGIN == table_type) {
        ret = plugin_runtime_get_ex_data(runtime, schema, key, key_len);
    } else {
        return NULL;
    }

    return ret;
}

int maat_ip_plugin_table_get_ex_data(struct maat *maat_instance, int table_id,
                                     const struct ip_addr *ip_addr, void **ex_data_array, 
                                     size_t n_ex_data)
{
    if (NULL == maat_instance || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || NULL == ip_addr || NULL == ex_data_array || 0 == n_ex_data) {
        return -1;
    }
    
    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        return -1;
    }

    void *ip_plugin_rt = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == ip_plugin_rt) {
        return -1;
    }

    int n_hit_ex_data = ip_plugin_runtime_get_ex_data(ip_plugin_rt, ip_addr, ex_data_array, n_ex_data);
    
    return n_hit_ex_data;
}

int maat_fqdn_plugin_table_get_ex_data(struct maat *maat_instance, int table_id,
                                       const char *fqdn, void **ex_data_array, 
                                       size_t n_ex_data)
{
    if (NULL == maat_instance || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || NULL == fqdn || NULL == ex_data_array || 0 == n_ex_data) {
        return -1;
    }

    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        return -1;
    }

    void *fqdn_plugin_rt = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == fqdn_plugin_rt) {
        return -1;
    }

    int n_hit_ex_data = fqdn_plugin_runtime_get_ex_data(fqdn_plugin_rt, fqdn, ex_data_array, n_ex_data);
    
    return n_hit_ex_data;
}

int maat_bool_plugin_table_get_ex_data(struct maat *maat_instance, int table_id,
                                       unsigned long long *item_ids, size_t n_item,
                                       void **ex_data_array, size_t n_ex_data)
{
    if (NULL == maat_instance || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || NULL == item_ids || NULL == ex_data_array || 0 == n_ex_data) {
        return -1;
    }
    
    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        return -1;
    }

    void *bool_plugin_rt = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == bool_plugin_rt) {
        return -1;
    }

    int n_hit_ex_data = bool_plugin_runtime_get_ex_data(bool_plugin_rt, item_ids, n_item, ex_data_array, n_ex_data);
    
    return n_hit_ex_data;
}

struct maat_state *make_outer_state(struct maat *maat_instance, int thread_id)
{
	struct maat_state *outer_state = NULL;

	outer_state = ALLOC(struct maat_state, 1);
	outer_state->maat_instance = maat_instance;
	outer_state->district_id = DISTRICT_ANY;
	outer_state->thread_id = (signed short)thread_id;
    outer_state->n_compile_table = 0;

	return outer_state;
}

struct maat_state *grab_state(struct maat_state **state, struct maat *maat_instance,
                              int thread_id)
{
    struct maat_state *mid = *state;

	if (NULL == mid) {
		mid = make_outer_state(maat_instance, thread_id);
        *state = mid;
        //Maat_set_scan_status calls grap_mid() with thread_num=-1.
		if (mid->thread_id >= 0) {
			alignment_int64_array_add(maat_instance->outer_state_cnt, thread_id, 1);
		}
	}

	if (mid->thread_id < 0 && thread_id >= 0) {
		mid->thread_id = thread_id;		
		alignment_int64_array_add(maat_instance->outer_state_cnt, thread_id, 1);
	}

    if (NULL == mid->compile_state) {
        mid->compile_state = maat_compile_state_new(thread_id);
        alignment_int64_array_add(maat_instance->compile_state_cnt, thread_id, 1);
    }

    return mid;
}

static inline int scan_status_should_compile_NOT(struct maat_state *state)
{
	if (state && (LAST_SCAN_SET == state->is_last_scan) && state->compile_state 
        && maat_compile_state_has_NOT_clause(state->compile_state)) {
		return 1;
	} 

    return 0;
}

size_t hit_group_to_compile(void *compile_runtime, long long *compile_ids, size_t compile_ids_size,
                         struct maat_state *mid)
{
    size_t n_hit_compile = compile_runtime_match((struct compile_runtime *)compile_runtime,
                                                 compile_ids, compile_ids_size, mid);
    return n_hit_compile;
}

static int vtable_get_physical_table_ids(struct table_manager *tbl_mgr, int table_id,
                                         int *physical_table_ids, size_t n_table_id_array,
                                         int *vtable_id)
{
    size_t physical_table_cnt = 0;
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);

    if (table_type == TABLE_TYPE_VIRTUAL) {
        //find physical table id
        *vtable_id = table_id;
        void *virtual_schema = table_manager_get_schema(tbl_mgr, table_id);
        assert(virtual_schema != NULL);
        physical_table_cnt = virtual_table_get_physical_table_id(virtual_schema, physical_table_ids);
        return physical_table_cnt;
    } else {
        *vtable_id = 0;
        physical_table_ids[0] = table_id;
        physical_table_cnt = 1;
    }

    return physical_table_cnt;
}

int flag_scan_hit_group_count(struct table_manager *tbl_mgr, int thread_id, long long flag,
                              int physical_table_ids[], int physical_table_cnt, int vtable_id,
                              struct maat_state *mid)
{
    int sum_hit_group_cnt = 0;

    for (int i = 0; i < physical_table_cnt; i++) {
        enum table_type table_type = table_manager_get_table_type(tbl_mgr, physical_table_ids[i]);
        if ((table_type == TABLE_TYPE_FLAG_PLUS) &&
            (NULL == mid || DISTRICT_FLAG_UNSET == mid->is_set_district)) {
            return -1;
        }

        if (table_type != TABLE_TYPE_FLAG && table_type != TABLE_TYPE_FLAG_PLUS) {
            continue;
        }

        void *flag_rt = table_manager_get_runtime(tbl_mgr, physical_table_ids[i]);
        if (NULL == flag_rt) {
            return -1;
        }

        int group_hit_cnt = flag_runtime_scan((struct flag_runtime *)flag_rt, thread_id,
                                              flag, vtable_id, mid);
        if (group_hit_cnt < 0) {
            return -1;
        }

        if (group_hit_cnt > 0) {
            flag_runtime_scan_hit_inc((struct flag_runtime *)flag_rt, thread_id);
        }
        sum_hit_group_cnt += group_hit_cnt;
    }

    return sum_hit_group_cnt;
}

int interval_scan_hit_group_count(struct table_manager *tbl_mgr, int thread_id, long long integer,
                              int physical_table_ids[], int physical_table_cnt, int vtable_id,
                              struct maat_state *mid)
{
    int sum_hit_group_cnt = 0;

    for (size_t i = 0; i < physical_table_cnt; i++) {
        enum table_type table_type = table_manager_get_table_type(tbl_mgr, physical_table_ids[i]);
        if ((table_type == TABLE_TYPE_INTERVAL_PLUS) &&
            (NULL == mid || DISTRICT_FLAG_UNSET == mid->is_set_district)) {
            //maat_instance->scan_err_cnt++;
            return -1;
        }

        if (table_type != TABLE_TYPE_INTERVAL && table_type != TABLE_TYPE_INTERVAL_PLUS) {
            continue;
        }

        void *interval_rt = table_manager_get_runtime(tbl_mgr, physical_table_ids[i]);
        if (NULL == interval_rt) {
            return -1;
        }

        int group_hit_cnt = interval_runtime_scan((struct interval_runtime *)interval_rt,
                                                  thread_id, integer, vtable_id, mid);
        if (group_hit_cnt < 0) {
            return -1;
        }
        
        if (group_hit_cnt > 0) {
            interval_runtime_scan_hit_inc((struct interval_runtime *)interval_rt, thread_id);
        }
        sum_hit_group_cnt += group_hit_cnt;
    }

    return sum_hit_group_cnt;
}

int ipv4_scan_hit_group_count(struct table_manager *tbl_mgr, int thread_id, uint32_t ip_addr,
                              int physical_table_ids[], int physical_table_cnt, int vtable_id,
                              struct maat_state *mid)
{
    int sum_hit_group_cnt = 0;

    for (size_t i = 0; i < physical_table_cnt; i++) {
        enum table_type table_type = table_manager_get_table_type(tbl_mgr, physical_table_ids[i]);
        if (table_type != TABLE_TYPE_IP_PLUS) {
            continue;
        }

        void *ip_rt = table_manager_get_runtime(tbl_mgr, physical_table_ids[i]);
        if (NULL == ip_rt) {
            return -1;
        }

        int group_hit_cnt = ip_runtime_scan((struct ip_runtime *)ip_rt, thread_id, IPv4,
                                            (uint8_t *)&ip_addr, vtable_id, mid);
        if (group_hit_cnt < 0) {
            return -1;
        }
        
        if (group_hit_cnt > 0) {
            ip_runtime_scan_hit_inc((struct ip_runtime *)ip_rt, thread_id);
        }
        sum_hit_group_cnt += group_hit_cnt;
    }

    return sum_hit_group_cnt;
}

int ipv6_scan_hit_group_count(struct table_manager *tbl_mgr, int thread_id, uint8_t *ip_addr,
                              int physical_table_ids[], int physical_table_cnt, int vtable_id,
                              struct maat_state *mid)
{
    int sum_hit_group_cnt = 0;

    for (size_t i = 0; i < physical_table_cnt; i++) {
        enum table_type table_type = table_manager_get_table_type(tbl_mgr, physical_table_ids[i]);
        if (table_type != TABLE_TYPE_IP_PLUS) {
            continue;
        }

        void *ip_rt = table_manager_get_runtime(tbl_mgr, physical_table_ids[i]);
        if (NULL == ip_rt) {
            return -1;
        }

        int group_hit_cnt = ip_runtime_scan((struct ip_runtime *)ip_rt, thread_id, IPv6,
                                            ip_addr, vtable_id, mid);
        if (group_hit_cnt < 0) {
            return -1;
        }
        
        if (group_hit_cnt > 0) {
            ip_runtime_scan_hit_inc((struct ip_runtime *)ip_rt, thread_id);
        }
        sum_hit_group_cnt += group_hit_cnt;
    }

    return sum_hit_group_cnt;
}

int string_scan_hit_group_count(struct table_manager *tbl_mgr, int thread_id, const char *data,
                                size_t data_len, int physical_table_ids[], int physical_table_cnt, 
                                int vtable_id, struct maat_state *mid)
{
    int sum_hit_group_cnt = 0;

    for (size_t i = 0; i < physical_table_cnt; i++) {
        enum table_type table_type = table_manager_get_table_type(tbl_mgr, physical_table_ids[i]);
        if ((table_type == TABLE_TYPE_EXPR_PLUS) &&
            (NULL == mid || DISTRICT_FLAG_UNSET == mid->is_set_district)) {
            //maat_instance->scan_err_cnt++;
            return -1;
        }

        if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
            continue;
        }

        void *expr_rt = table_manager_get_runtime(tbl_mgr, physical_table_ids[i]);
        if (NULL == expr_rt) {
            return -1;
        }

        int group_hit_cnt = expr_runtime_scan((struct expr_runtime *)expr_rt,
                                              thread_id, data, data_len,
                                              vtable_id, mid);
        if (group_hit_cnt < 0) {
            return -1;
        }

        if (group_hit_cnt > 0) {
            expr_runtime_scan_hit_inc((struct expr_runtime *)expr_rt, thread_id);
        }
        sum_hit_group_cnt += group_hit_cnt;
    }

    return sum_hit_group_cnt;
}

int stream_scan_hit_group_count(struct table_manager *tbl_mgr, int thread_id, const char *data,
                                size_t data_len, int physical_table_ids[], int physical_table_cnt, 
                                int vtable_id, struct maat_state *mid)
{
    int sum_hit_group_cnt = 0;

    for (size_t i = 0; i < physical_table_cnt; i++) {
        enum table_type table_type = table_manager_get_table_type(tbl_mgr, physical_table_ids[i]);
        if ((table_type == TABLE_TYPE_EXPR_PLUS) &&
            (NULL == mid || DISTRICT_FLAG_UNSET == mid->is_set_district)) {
            //maat_instance->scan_err_cnt++;
            return -1;
        }

        if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
            continue;
        }

        void *expr_rt = table_manager_get_runtime(tbl_mgr, physical_table_ids[i]);
        if (NULL == expr_rt) {
            return -1;
        }

        int group_hit_cnt = expr_runtime_stream_scan((struct expr_runtime *)expr_rt,
                                                      data, data_len, vtable_id, mid);
        if (group_hit_cnt < 0) {
            return -1;
        }

        if (group_hit_cnt > 0) {
            expr_runtime_scan_hit_inc((struct expr_runtime *)expr_rt, thread_id);
        }
        sum_hit_group_cnt += group_hit_cnt;
    }

    return sum_hit_group_cnt;
}

size_t group_to_compile(struct maat *maat_instance, long long *results, size_t n_result,
                        struct maat_state *mid)
{
    int compile_table_id[MAX_COMPILE_TABLE_NUM] = {0};
    size_t compile_table_cnt = 0;
    size_t sum_hit_compile_cnt = 0;

    if (0 == mid->n_compile_table) {
        compile_table_id[0] = maat_instance->default_compile_table_id;
        compile_table_cnt = 1;
    } else {
        for (size_t i = 0; i < mid->n_compile_table; i++) {
            compile_table_id[i] = maat_get_table_id(maat_instance, mid->compile_tables[i]);
        }
        compile_table_cnt = mid->n_compile_table;
    }

    for (size_t i = 0; i < compile_table_cnt; i++) {
        void *compile_rt = table_manager_get_runtime(maat_instance->tbl_mgr, compile_table_id[i]);
        size_t n_hit_compile = hit_group_to_compile(compile_rt, results, n_result, mid);
        sum_hit_compile_cnt += n_hit_compile;
    }

    assert(mid->is_last_scan < LAST_SCAN_FINISHED);
    if (LAST_SCAN_SET == mid->is_last_scan) {
        mid->is_last_scan = LAST_SCAN_FINISHED;
    }

    return sum_hit_compile_cnt;
}

int maat_scan_flag(struct maat *maat_instance, int table_id, int thread_id,
                   long long flag, long long *results, size_t n_result,
                   size_t *n_hit_result, struct maat_state **state)
{
    if ((NULL == maat_instance) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (thread_id < 0) || (NULL == results) || (0 == n_result) 
        || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }

    struct maat_state *mid = NULL;
    mid = grab_state(state, maat_instance, thread_id);
    mid->scan_cnt++;

    if (NULL == maat_instance->maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                 "maat_scan_flag error because of maat_runtime is NULL");
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int physical_table_cnt = 0;
    int physical_table_ids[MAX_PHYSICAL_TABLE_NUM];
    memset(physical_table_ids, -1, sizeof(physical_table_ids));
    
    physical_table_cnt = vtable_get_physical_table_ids(maat_instance->tbl_mgr, table_id,
                                                       physical_table_ids, 
                                                       MAX_PHYSICAL_TABLE_NUM, &vtable_id);
    if (physical_table_cnt <= 0) {
        return MAAT_SCAN_ERR;
    }

    enum table_type table_type = TABLE_TYPE_INVALID;
    if (0 == vtable_id) {
        table_type = table_manager_get_table_type(maat_instance->tbl_mgr, physical_table_ids[0]);
        if (table_type != TABLE_TYPE_FLAG && table_type != TABLE_TYPE_FLAG_PLUS) {
            return MAAT_SCAN_ERR;
        }
    }

    maat_runtime_ref_inc(maat_instance->maat_rt, thread_id);
    alignment_int64_array_add(maat_instance->thread_call_cnt, thread_id, 1);

    int hit_group_cnt = flag_scan_hit_group_count(maat_instance->tbl_mgr, thread_id, flag,
                                                  physical_table_ids,
                                                  physical_table_cnt, vtable_id, mid);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }

    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(mid)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(maat_instance, results, n_result, mid);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(maat_instance->hit_cnt, thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(maat_instance->not_grp_hit_cnt, thread_id, 1);
        }
        return MAAT_SCAN_HIT;
    } else {
        // sum_hit_compile_cnt == 0
        if (hit_group_cnt > 0) {
            return MAAT_SCAN_HALF_HIT;
        }
    }

    maat_runtime_ref_dec(maat_instance->maat_rt, thread_id);

    return MAAT_SCAN_OK;
}

int maat_scan_integer(struct maat *maat_instance, int table_id, int thread_id,
                      long long integer, long long *results, size_t n_result,
                      size_t *n_hit_result, struct maat_state **state)
{
    if ((NULL == maat_instance) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (thread_id < 0) || (NULL == results) || (0 == n_result) || 
        (NULL == state)) {
        return MAAT_SCAN_ERR;
    }
    
    struct maat_state *mid = NULL;
    mid = grab_state(state, maat_instance, thread_id);
    mid->scan_cnt++;

    if (NULL == maat_instance->maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                 "maat_scan_flag error because of maat_runtime is NULL");
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int physical_table_cnt = 0;
    int physical_table_ids[MAX_PHYSICAL_TABLE_NUM];
    memset(physical_table_ids, -1, sizeof(physical_table_ids));
    
    physical_table_cnt = vtable_get_physical_table_ids(maat_instance->tbl_mgr, table_id,
                                                       physical_table_ids, 
                                                       MAX_PHYSICAL_TABLE_NUM, &vtable_id);
    if (physical_table_cnt <= 0) {
        return MAAT_SCAN_ERR;
    }

    enum table_type table_type = TABLE_TYPE_INVALID;
    if (0 == vtable_id) {
        table_type = table_manager_get_table_type(maat_instance->tbl_mgr, physical_table_ids[0]);
        if (table_type != TABLE_TYPE_INTERVAL && table_type != TABLE_TYPE_INTERVAL_PLUS) {
            return MAAT_SCAN_ERR;
        }
    }

    maat_runtime_ref_inc(maat_instance->maat_rt, thread_id);
    alignment_int64_array_add(maat_instance->thread_call_cnt, thread_id, 1);

    int hit_group_cnt = interval_scan_hit_group_count(maat_instance->tbl_mgr, thread_id, integer,
                                                      physical_table_ids,
                                                      physical_table_cnt, vtable_id, mid);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }
    
    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(mid)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(maat_instance, results, n_result, mid);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(maat_instance->hit_cnt, thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(maat_instance->not_grp_hit_cnt, thread_id, 1);
        }
        return MAAT_SCAN_HIT;
    } else {
        // sum_hit_compile_cnt == 0
        if (hit_group_cnt > 0) {
            return MAAT_SCAN_HALF_HIT;
        }
    }

    maat_runtime_ref_dec(maat_instance->maat_rt, thread_id);

    return MAAT_SCAN_OK;
}

int maat_scan_ipv4(struct maat *maat_instance, int table_id, int thread_id, 
                   uint32_t ip_addr, long long *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state **state)
{
    if ((NULL == maat_instance) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (thread_id < 0) || (NULL == results) || (0 == n_result) 
        || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }

    struct maat_state *mid = NULL;
    mid = grab_state(state, maat_instance, thread_id);
    mid->scan_cnt++;

    if (NULL == maat_instance->maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                 "maat_scan_flag error because of maat_runtime is NULL");
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int physical_table_cnt = 0;
    int physical_table_ids[MAX_PHYSICAL_TABLE_NUM];
    memset(physical_table_ids, -1, sizeof(physical_table_ids));
    
    physical_table_cnt = vtable_get_physical_table_ids(maat_instance->tbl_mgr, table_id,
                                                       physical_table_ids, 
                                                       MAX_PHYSICAL_TABLE_NUM, &vtable_id);
    if (physical_table_cnt <= 0) {
        return MAAT_SCAN_ERR;
    }

    enum table_type table_type = TABLE_TYPE_INVALID;
    if (0 == vtable_id) {
        table_type = table_manager_get_table_type(maat_instance->tbl_mgr, physical_table_ids[0]);
        if (table_type != TABLE_TYPE_IP_PLUS) {
            return MAAT_SCAN_ERR;
        }
    }

    maat_runtime_ref_inc(maat_instance->maat_rt, thread_id);
    alignment_int64_array_add(maat_instance->thread_call_cnt, thread_id, 1);

    int hit_group_cnt = ipv4_scan_hit_group_count(maat_instance->tbl_mgr, thread_id, ip_addr,
                                                  physical_table_ids,
                                                  physical_table_cnt, vtable_id, mid);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }
    
    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(mid)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(maat_instance, results, n_result, mid);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(maat_instance->hit_cnt, thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(maat_instance->not_grp_hit_cnt, thread_id, 1);
        }
        return MAAT_SCAN_HIT;
    } else {
        // n_hit_compile == 0
        if (hit_group_cnt > 0) {
            return MAAT_SCAN_HALF_HIT;
        }
    }

    maat_runtime_ref_dec(maat_instance->maat_rt, thread_id);

    return MAAT_SCAN_OK;
}

int maat_scan_ipv4_tuple4(struct maat *instance, int table_id, int thread_id,
                          const struct ipv4_tuple *tuple4, long long *results,
                          size_t n_result, size_t *n_hit_result,
                          struct maat_state **state)
{
    return MAAT_SCAN_OK;
}

int maat_scan_ipv6(struct maat *maat_instance, int table_id, int thread_id, 
                   uint8_t *ip_addr, long long *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state **state)
{
    if ((NULL == maat_instance) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (thread_id < 0) || (NULL == ip_addr) || (NULL == results) 
        || (0 == n_result) || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }

    struct maat_state *mid = NULL;
    mid = grab_state(state, maat_instance, thread_id);
    mid->scan_cnt++;

    if (NULL == maat_instance->maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                 "maat_scan_flag error because of maat_runtime is NULL");
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int physical_table_cnt = 0;
    int physical_table_ids[MAX_PHYSICAL_TABLE_NUM];
    memset(physical_table_ids, -1, sizeof(physical_table_ids));
    
    physical_table_cnt = vtable_get_physical_table_ids(maat_instance->tbl_mgr, table_id,
                                                       physical_table_ids, 
                                                       MAX_PHYSICAL_TABLE_NUM, &vtable_id);
    if (physical_table_cnt <= 0) {
        return MAAT_SCAN_ERR;
    }

    enum table_type table_type = TABLE_TYPE_INVALID;
    if (0 == vtable_id) {
        table_type = table_manager_get_table_type(maat_instance->tbl_mgr, physical_table_ids[0]);
        if (table_type != TABLE_TYPE_IP_PLUS) {
            return MAAT_SCAN_ERR;
        }
    }

    maat_runtime_ref_inc(maat_instance->maat_rt, thread_id);
    alignment_int64_array_add(maat_instance->thread_call_cnt, thread_id, 1);

    int hit_group_cnt = ipv6_scan_hit_group_count(maat_instance->tbl_mgr, thread_id, ip_addr,
                                                  physical_table_ids,
                                                  physical_table_cnt, vtable_id, mid);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }

    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(mid)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(maat_instance, results, n_result, mid);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(maat_instance->hit_cnt, thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(maat_instance->not_grp_hit_cnt, thread_id, 1);
        }
        return MAAT_SCAN_HIT;
    } else {
        // n_hit_compile == 0
        if (hit_group_cnt > 0) {
            return MAAT_SCAN_HALF_HIT;
        }
    }

    maat_runtime_ref_dec(maat_instance->maat_rt, thread_id);

    return MAAT_SCAN_OK;
}

int maat_scan_ipv6_tuple4(struct maat *instance, int table_id, int thread_id,
                          const struct ipv6_tuple *tuple, long long *results,
                          size_t n_result, size_t *n_hit_result,
                          struct maat_state **state)
{
    return MAAT_SCAN_OK;
}

int maat_scan_string(struct maat *maat_instance, int table_id, int thread_id,
                     const char *data, size_t data_len, long long *results, size_t n_result,
                     size_t *n_hit_result, struct maat_state **state)
{
    if ((NULL == maat_instance) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (thread_id < 0) || (NULL == data) || (0 == data_len) 
        || (NULL == results) || (0 == n_result) || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }
    
    struct maat_state *mid = NULL;
    mid = grab_state(state, maat_instance, thread_id);
    mid->scan_cnt++;

    if (NULL == maat_instance->maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                 "maat_scan_string error because of maat_runtime is NULL");
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int physical_table_cnt = 0;
    int physical_table_ids[MAX_PHYSICAL_TABLE_NUM];
    memset(physical_table_ids, -1, sizeof(physical_table_ids));
    
    physical_table_cnt = vtable_get_physical_table_ids(maat_instance->tbl_mgr, table_id,
                                                       physical_table_ids, 
                                                       MAX_PHYSICAL_TABLE_NUM, &vtable_id);
    if (physical_table_cnt <= 0) {
        return MAAT_SCAN_ERR;
    }

    enum table_type table_type = TABLE_TYPE_INVALID;
    if (0 == vtable_id) {
        table_type = table_manager_get_table_type(maat_instance->tbl_mgr, physical_table_ids[0]);
        if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
            return MAAT_SCAN_ERR;
        }
    }

    maat_runtime_ref_inc(maat_instance->maat_rt, thread_id);
    alignment_int64_array_add(maat_instance->thread_call_cnt, thread_id, 1);

    int hit_group_cnt = string_scan_hit_group_count(maat_instance->tbl_mgr, thread_id, data,
                                                    data_len, physical_table_ids,
                                                    physical_table_cnt, vtable_id, mid);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }

     size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(mid)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(maat_instance, results, n_result, mid);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(maat_instance->hit_cnt, thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(maat_instance->not_grp_hit_cnt, thread_id, 1);
        }
        return MAAT_SCAN_HIT;
    } else {
        // n_hit_compile == 0
        if (hit_group_cnt > 0) {
            return MAAT_SCAN_HALF_HIT;
        }
    }

    maat_runtime_ref_dec(maat_instance->maat_rt, thread_id);

    return MAAT_SCAN_OK;
}

struct maat_stream *maat_scan_stream_open(struct maat *maat_instance, int table_id, int thread_id)
{
    if (NULL == maat_instance || table_id < 0 || table_id > MAX_TABLE_NUM
        || thread_id < 0) {
        return NULL;
    }

    struct maat_stream *stream = ALLOC(struct maat_stream, 1);
    memset(stream->physical_table_ids, -1, sizeof(stream->physical_table_ids));

    stream->ref_maat_instance = maat_instance;
    stream->table_id = table_id;
    stream->thread_id = thread_id;

    stream->n_physical_table = vtable_get_physical_table_ids(stream->ref_maat_instance->tbl_mgr, 
                                                             stream->table_id, stream->physical_table_ids, 
                                                             MAX_PHYSICAL_TABLE_NUM, &stream->vtable_id);
    if (stream->n_physical_table <= 0) {
        return NULL;
    }

    enum table_type table_type = TABLE_TYPE_INVALID;
    if (0 == stream->vtable_id) {
        table_type = table_manager_get_table_type(stream->ref_maat_instance->tbl_mgr, 
                                                  stream->physical_table_ids[0]);
        if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
            log_error(maat_instance->logger, MODULE_MAAT_API, 
                      "scan stream's physical table must be expr or expr_plus");
            return NULL;
        }
    }

    for (size_t i = 0; i < stream->n_physical_table; i++) {
        enum table_type table_type = table_manager_get_table_type(stream->ref_maat_instance->tbl_mgr,
                                                                  stream->physical_table_ids[i]);
        if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
            log_error(maat_instance->logger, MODULE_MAAT_API, 
                      "scan stream's physical table must be expr or expr_plus");
            return NULL;
        }

        void *expr_rt = table_manager_get_runtime(stream->ref_maat_instance->tbl_mgr, 
                                                  stream->physical_table_ids[i]);
        assert(expr_rt != NULL);

        int ret = expr_runtime_stream_open((struct expr_runtime *)expr_rt, thread_id);
        if (ret < 0) {
            return NULL;
        }
    }

    return stream;
}

int maat_scan_stream(struct maat_stream **maat_stream, const char *data, int data_len, 
                     long long *results, size_t n_result, size_t *n_hit_result,
                     struct maat_state **state)
{
    if ((NULL == maat_stream) || (NULL == data) || (0 == data_len) 
        || (NULL == results) || (0 == n_result) || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }

    struct maat_stream *stream = *maat_stream;
    struct maat_state *mid = NULL;
    mid = grab_state(state, stream->ref_maat_instance, stream->thread_id);
    mid->scan_cnt++;

    if (NULL == stream->ref_maat_instance->maat_rt) {
        log_error(stream->ref_maat_instance->logger, MODULE_MAAT_API, 
                 "maat_scan_string error because of maat_runtime is NULL");
        return MAAT_SCAN_OK;
    }

    alignment_int64_array_add(stream->ref_maat_instance->thread_call_cnt, stream->thread_id, 1);

    int hit_group_cnt = stream_scan_hit_group_count(stream->ref_maat_instance->tbl_mgr,
                                                    stream->thread_id, data, data_len, 
                                                    stream->physical_table_ids, 
                                                    stream->n_physical_table, 
                                                    stream->vtable_id, mid);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }

    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(mid)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(stream->ref_maat_instance, results, n_result, mid);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(stream->ref_maat_instance->hit_cnt, stream->thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(stream->ref_maat_instance->not_grp_hit_cnt, stream->thread_id, 1);
        }
        return MAAT_SCAN_HIT;
    } else {
        // n_hit_compile == 0
        if (hit_group_cnt > 0) {
            return MAAT_SCAN_HALF_HIT;
        }
    }    

    return sum_hit_compile_cnt;
}

void maat_scan_stream_close(struct maat_stream **maat_stream)
{
    struct maat_stream *stream = *maat_stream;

    for (size_t i = 0; i < stream->n_physical_table; i++) {
        void *expr_rt = table_manager_get_runtime(stream->ref_maat_instance->tbl_mgr, 
                                                  stream->physical_table_ids[i]);
        assert(expr_rt != NULL);
        expr_runtime_stream_close((struct expr_runtime *)expr_rt);
    }

    FREE(stream);
}

int maat_state_set_scan_district(struct maat *maat_instance,
                                 struct maat_state **state,
                                 const char *district,
                                 size_t district_len)
{
    if (NULL == maat_instance->maat_rt || NULL == district || 
        district_len <= 0) {
        return -1;
    }

    struct maat_state *mid = grab_state(state, maat_instance, -1);
    int ret = table_manager_set_scan_district(maat_instance->tbl_mgr, 
                                              district, district_len,
                                              &(mid->district_id));
    if (ret < 0) {
        mid->district_id = DISTRICT_UNKNOWN;
    }

    mid->is_set_district = DISTRICT_FLAG_SET;

    return 0;
}

int maat_state_set_last_scan(struct maat *maat_instance, struct maat_state **state)
{
    if (NULL == maat_instance->maat_rt) {
        return -1;
    }

    struct maat_state *mid = grab_state(state, maat_instance, -1);
    assert(mid->is_last_scan == LAST_SCAN_UNSET);
    mid->is_last_scan = LAST_SCAN_SET;

    return 0;
}

int maat_state_set_scan_compile_tables(struct maat *maat_instance, struct maat_state **state,
                                       const char *compile_tables[], size_t n_table)
{
    if (NULL == maat_instance->maat_rt) {
        return -1;
    }

    struct maat_state *mid = grab_state(state, maat_instance, -1);
    mid->n_compile_table = n_table;

    for (size_t i = 0; i < mid->n_compile_table; i++) {
        strncpy(mid->compile_tables[i], compile_tables[i], strlen(compile_tables[i]));
    }

    return 0;
}

size_t maat_get_hit_paths(struct maat *maat_instance, struct maat_state *state,
                          struct maat_hit_path *paths, size_t n_path)
{
    int compile_table_ids[MAX_COMPILE_TABLE_NUM] = {0};
    size_t compile_table_cnt = 0;

    if (0 == state->n_compile_table) {
        compile_table_ids[0] = maat_instance->default_compile_table_id;
        compile_table_cnt = 1;
    } else {
        for (size_t i = 0; i < state->n_compile_table; i++) {
            compile_table_ids[i] = maat_get_table_id(maat_instance, state->compile_tables[i]);
        }
        compile_table_cnt = state->n_compile_table;
    }

    size_t hit_path_index = 0;
    //size_t sum_hit_paths = 0;
    for (size_t i = 0; i < compile_table_cnt; i++) {
        void *compile_rt = table_manager_get_runtime(maat_instance->tbl_mgr, compile_table_ids[i]);
        void *g2g_runtime = table_manager_get_runtime(maat_instance->tbl_mgr, maat_instance->g2g_table_id);
        assert(NULL != compile_rt && NULL != g2g_runtime);
        size_t n_hit_path = compile_runtime_get_hit_paths((struct compile_runtime *)compile_rt, 
                                                          (struct group2group_runtime *)g2g_runtime,
                                                          state->compile_state, paths, hit_path_index, 
                                                          n_path);
        hit_path_index += n_hit_path;
    }
   
    return hit_path_index;
}

size_t maat_get_hit_objects(struct maat_compile_state *compile_state,
                            struct maat_hit_object *objs, size_t n_objs)
{
    return 0;
}

int maat_state_get_hit_paths(struct maat *maat_instance, struct maat_state **state,
                             struct maat_hit_path *paths, size_t n_path)
{
    struct maat_state *mid = NULL;

    mid = grab_state(state, maat_instance, 0);
    if (NULL == mid->compile_state || NULL == maat_instance->maat_rt) {
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
        alignment_int64_array_add(mid->maat_instance->outer_state_cnt, mid->thread_id, -1);
    }

    if (mid->compile_state != NULL) {
        maat_compile_state_free(mid->compile_state);
        mid->compile_state = NULL;
        alignment_int64_array_add(mid->maat_instance->compile_state_cnt, mid->thread_id, -1);
    }
    
    mid->maat_instance = NULL;
    free(mid);
    *state = NULL;
}

int maat_hit_object_compile_id(struct maat *instance, struct maat_hit_object *obj)
{
    return 0;
}
