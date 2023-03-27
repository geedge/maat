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

struct maat_stream {
    struct maat *ref_maat_instance;
    struct adapter_hs_stream *s_handle; //each physical table open one stream
    int thread_id;
    int vtable_id;
    int physical_table_id;
    struct log_handle *logger;
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
    if (NULL == opts) {
        return -1;
    }

    opts->nr_worker_threads = n_thread;
    return 0;
}

int maat_options_set_accept_tags(struct maat_options *opts, const char *accept_tags)
{
    if (NULL == opts || NULL == accept_tags) {
        return -1;
    }

    opts->accept_tags = maat_strdup(accept_tags);
    return 0;
}

int maat_options_set_rule_effect_interval_ms(struct maat_options *opts, int interval_ms)
{
    if (NULL == opts || interval_ms < 0) {
        return -1;
    }

    opts->rule_effect_interval_ms = interval_ms;
    return 0;
}

int maat_options_set_rule_update_checking_interval_ms(struct maat_options *opts, int interval_ms)
{
    if (NULL == opts || interval_ms < 0) {
        return -1;
    }

    opts->rule_update_checking_interval_ms = interval_ms;
    return 0;
}

int maat_options_set_gc_timeout_ms(struct maat_options *opts, int interval_ms)
{
    if (NULL == opts || interval_ms < 0) {
        return -1;
    }

    opts->gc_timeout_ms = interval_ms;
    return 0;
}

int maat_options_set_instance_name(struct maat_options *opts, const char *instance_name)
{
    if (NULL == opts || NULL == instance_name || 
        strlen(instance_name) >= NAME_MAX) {
        return -1;
    }

    memcpy(opts->instance_name, instance_name, strlen(instance_name));
    return 0;
}

int maat_options_set_deferred_load_on(struct maat_options *opts)
{
    if (NULL == opts) {
        return -1;
    }

    opts->deferred_load_on = 1;
    return 0;
}

int maat_options_set_foreign_cont_dir(struct maat_options *opts, const char *dir)
{
    if (NULL == opts || NULL == dir || strlen(dir) >= NAME_MAX) {
        return -1;
    }

    memcpy(opts->foreign_cont_dir, dir, strlen(dir));
    return 0;
}

int maat_options_set_iris(struct maat_options *opts, const char *full_directory,
                          const char *increment_directory)
{
    if (NULL == opts || strlen(full_directory) >= NAME_MAX || 
        strlen(increment_directory) >= NAME_MAX) {
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

int maat_options_set_logger_path(struct maat_options *opts, const char *log_path)
{
    if (NULL == opts || NULL == log_path || strlen(log_path) >= PATH_MAX) {
        return -1;
    }

    memcpy(opts->log_path, log_path, strlen(log_path));

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
                          "[%s:%d] At initiation: NO effective rule in redis %s:%hu db%d",
                          __FUNCTION__, __LINE__, mr_ctx->redis_ip, mr_ctx->redis_port, 
                          mr_ctx->redis_db);
            }
            break;
        case DATA_SOURCE_IRIS_FILE:
			config_monitor_traverse(maat_instance->maat_version,
                                    maat_instance->iris_ctx.full_idx_dir,
                                    maat_start_cb, maat_update_cb, maat_finish_cb,
                                    maat_instance, maat_instance->logger);
            if (NULL == maat_instance->creating_maat_rt) {
                log_error(maat_instance->logger, MODULE_MAAT_API, 
                          "[%s:%d] At initiation: NO effective rule in %s",
                          __FUNCTION__, __LINE__, maat_instance->iris_ctx.full_idx_dir);
            }
            break;
        case DATA_SOURCE_JSON_FILE:
            ret = load_maat_json_file(maat_instance, maat_instance->json_ctx.json_file,
                                      err_str, sizeof(err_str));
            if (ret < 0) {
                log_error(maat_instance->logger, MODULE_MAAT_API, 
                          "[%s:%d] Maat re-initiate with JSON file %s failed: %s", 
                          __FUNCTION__, __LINE__, maat_instance->json_ctx.json_file, err_str);
                return;
            }
            
            config_monitor_traverse(maat_instance->maat_version,
                                    maat_instance->json_ctx.iris_file,
                                    maat_start_cb, maat_update_cb, maat_finish_cb,
                                    maat_instance, maat_instance->logger);
            if (NULL == maat_instance->creating_maat_rt) {
                log_error(maat_instance->logger, MODULE_MAAT_API, 
                          "[%s:%d] At initiation: NO effective rule in %s",
                          __FUNCTION__, __LINE__, maat_instance->json_ctx.iris_file);
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
    if (NULL == opts || NULL == table_info_path) {
        return NULL;
    }

    int garbage_gc_timeout_s = 0;
    struct maat *maat_instance = ALLOC(struct maat, 1);
    
    if (strlen(opts->log_path) != 0) {
        maat_instance->logger = log_handle_create(opts->log_path, opts->log_level);
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
                      "[%s:%d] data source(%d) unsupported", 
                      __FUNCTION__, __LINE__, maat_instance->input_mode);
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
    memcpy(maat_instance->foreign_cont_dir, opts->foreign_cont_dir, strlen(opts->foreign_cont_dir));
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
                  "[%s:%d], table(table_id:%d) is not registered, can't register ex schema", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    struct ex_data_schema *ex_schema = NULL;
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            ex_schema = plugin_table_get_ex_data_schema(schema);
            if (ex_schema != NULL) {
                log_error(logger, MODULE_MAAT_API,
                          "[%s:%d], EX data schema already registed for plugin table(table_id:%d)",
                          __FUNCTION__, __LINE__, table_id);
                return -1;
            }
            plugin_table_set_ex_data_schema(schema, new_func, free_func,
                                            dup_func, argl, argp, logger);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ex_schema = ip_plugin_table_get_ex_data_schema(schema);
            if (ex_schema != NULL) {
                log_error(logger, MODULE_MAAT_API,
                          "[%s:%d], EX data schema already registed for ip_plugin table(table_id:%d)",
                          __FUNCTION__, __LINE__, table_id);
                return -1;
            }
            ip_plugin_table_set_ex_data_schema(schema, new_func, free_func,
                                                dup_func, argl, argp, logger);
            break;
        case TABLE_TYPE_FQDN_PLUGIN:
            ex_schema = fqdn_plugin_table_get_ex_data_schema(schema);
            if (ex_schema != NULL) {
                log_error(logger, MODULE_MAAT_API,
                          "[%s:%d], EX data schema already registed for fqdn_plugin table(table_id:%d)",
                          __FUNCTION__, __LINE__, table_id);
                return -1;
            }
            fqdn_plugin_table_set_ex_data_schema(schema, new_func, free_func,
                                                dup_func, argl, argp, logger);
            break;
        case TABLE_TYPE_BOOL_PLUGIN:
            ex_schema = bool_plugin_table_get_ex_data_schema(schema);
            if (ex_schema != NULL) {
                log_error(logger, MODULE_MAAT_API,
                          "[%s:%d], EX data schema already registed for bool_plugin table(table_id:%d)",
                          __FUNCTION__, __LINE__, table_id);
                return -1;
            }
            bool_plugin_table_set_ex_data_schema(schema, new_func, free_func,
                                                dup_func, argl, argp, logger);
            break;
        default:
            log_error(logger, MODULE_MAAT_API,
                      "[%s:%d], table(table_id:%d) is not plugin table, can't set ex schema",
                      __FUNCTION__, __LINE__, table_id);
            return -1;
    }

    return 0;
}

void generic_plugin_runtime_commit_ex_schema(void *runtime, void *schema, int table_id, 
                                             enum table_type table_type, int valid_column)
{
    if (NULL == runtime || NULL == schema || valid_column < 0) {
        return;
    }

    struct ex_data_schema *ex_schema = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            ex_schema = plugin_table_get_ex_data_schema(schema);
            ex_data_rt = plugin_runtime_get_ex_data_rt(runtime);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ex_schema = ip_plugin_table_get_ex_data_schema(schema);
            ex_data_rt = ip_plugin_runtime_get_ex_data_rt(runtime);
            break;
        case TABLE_TYPE_FQDN_PLUGIN:
            ex_schema = fqdn_plugin_table_get_ex_data_schema(schema);
            ex_data_rt = fqdn_plugin_runtime_get_ex_data_rt(runtime);
            break;
        case TABLE_TYPE_BOOL_PLUGIN:
            ex_schema = bool_plugin_table_get_ex_data_schema(schema);
            ex_data_rt = bool_plugin_runtime_get_ex_data_rt(runtime);
            break;
        default:
            break;
    }

    struct ex_container_schema *container_schema = ALLOC(struct ex_container_schema, 1);
    container_schema->table_id = table_id;
    container_schema->ex_schema = ex_schema;
    ex_data_runtime_set_ex_container_schema(ex_data_rt, container_schema);

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
        if (table_type == TABLE_TYPE_INVALID || valid_column < 0) {
            return -1;
        }
        
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
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] table(table_id:%d) input parameter is invalid.",
                  __FUNCTION__, __LINE__, table_id);
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

void *maat_plugin_table_get_ex_data(struct maat *maat_instance, int table_id, const char *key)
{

    if (NULL == maat_instance || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || NULL == key) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] table(table_id:%d) input parameter is invalid",
                  __FUNCTION__, __LINE__, table_id);
        return NULL;
    }
    
    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                  "[%s:%d] table(table_id:%d) maat runtime is NULL", 
                  __FUNCTION__, __LINE__, table_id);
        return NULL;
    }

    void *runtime = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == runtime) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] table(table_id:%d) runtime is NULL", 
                  __FUNCTION__, __LINE__, table_id);
        return NULL;
    }

    void *schema = table_manager_get_schema(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == schema) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] table(table_id:%d) schema is NULL", 
                  __FUNCTION__, __LINE__, table_id);
        return NULL;
    }

    void *ret = NULL;
    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    if (TABLE_TYPE_COMPILE == table_type) {
        ret = compile_runtime_get_ex_data(runtime, schema, *(long long *)key);
    } else if (TABLE_TYPE_PLUGIN == table_type) {
        ret = plugin_runtime_get_ex_data(runtime, schema, key, strlen(key));
    } else {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] table(table_id:%d) type is invalid, neither compile nor plugin", 
                  __FUNCTION__, __LINE__, table_id);
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
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] ip_plugin table(table_id:%d) input parameter is invalid.",
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }
    
    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                  "[%s:%d] ip_plugin table(table_id:%d) maat runtime is NULL", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    void *ip_plugin_rt = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == ip_plugin_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] ip_plugin table(table_id:%d) runtime is NULL",
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    void *ip_plugin_schema = table_manager_get_schema(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == ip_plugin_schema) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] table(table_id:%d) schema is NULL", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    int n_hit_ex_data = ip_plugin_runtime_get_ex_data(ip_plugin_rt, ip_plugin_schema, ip_addr, 
                                                      ex_data_array, n_ex_data);
    if (n_hit_ex_data < 0) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] ip_plugin table(table_id:%d) get ex_data error.", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    return n_hit_ex_data;
}

int maat_fqdn_plugin_table_get_ex_data(struct maat *maat_instance, int table_id,
                                       const char *fqdn, void **ex_data_array, 
                                       size_t n_ex_data)
{
    if (NULL == maat_instance || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || NULL == fqdn || NULL == ex_data_array || 0 == n_ex_data) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] fqdn_plugin table(table_id:%d) input parameter is invalid.",
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                  "[%s:%d] fqdn_plugin table(table_id:%d) maat runtime is NULL",
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    void *fqdn_plugin_rt = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == fqdn_plugin_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] fqdn_plugin table(table_id:%d) runtime is NULL", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    void *fqdn_plugin_schema = table_manager_get_schema(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == fqdn_plugin_schema) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] table(table_id:%d) schema is NULL", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    int n_hit_ex_data = fqdn_plugin_runtime_get_ex_data(fqdn_plugin_rt, fqdn_plugin_schema,
                                                        fqdn, ex_data_array, n_ex_data);
    if (n_hit_ex_data < 0) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] fqdn_plugin table(table_id:%d) get ex_data error.", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    return n_hit_ex_data;
}

int maat_bool_plugin_table_get_ex_data(struct maat *maat_instance, int table_id,
                                       unsigned long long *item_ids, size_t n_item,
                                       void **ex_data_array, size_t n_ex_data)
{
    if (NULL == maat_instance || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || NULL == item_ids || NULL == ex_data_array || 0 == n_ex_data) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] bool_plugin table(table_id:%d) input parameter is invalid.",
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }
    
    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                  "[%s:%d] bool_plugin table(table_id:%d) maat runtime is NULL", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    void *bool_plugin_rt = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == bool_plugin_rt) {
         log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] bool_plugin table(table_id:%d) runtime is NULL", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    void *bool_plugin_schema = table_manager_get_schema(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == bool_plugin_schema) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] table(table_id:%d) schema is NULL", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    int n_hit_ex_data = bool_plugin_runtime_get_ex_data(bool_plugin_rt, bool_plugin_schema,
                                                        item_ids, n_item, ex_data_array, 
                                                        n_ex_data);
    if (n_hit_ex_data < 0) {
        log_error(maat_instance->logger, MODULE_MAAT_API,
                  "[%s:%d] bool_plugin table(table_id:%d) get ex_data error.", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    return n_hit_ex_data;
}

static inline int scan_status_should_compile_NOT(struct maat_state *state)
{
	if (state && (LAST_SCAN_SET == state->is_last_scan) && state->compile_state 
        && maat_compile_state_has_NOT_clause(state->compile_state)) {
		return 1;
	} 

    return 0;
}

size_t hit_group_to_compile(void *compile_runtime, long long *compile_ids,
                            size_t compile_ids_size, struct maat_state *state)
{
    size_t n_hit_compile = compile_runtime_match((struct compile_runtime *)compile_runtime,
                                                 compile_ids, compile_ids_size, state);
    return n_hit_compile;
}

static int vtable_get_physical_table_id(struct table_manager *tbl_mgr, int table_id)
{
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);

    if (table_type != TABLE_TYPE_VIRTUAL) {
        return -1;
    }

    // find physical table id
    void *virtual_schema = table_manager_get_schema(tbl_mgr, table_id);
    assert(virtual_schema != NULL);
    return virtual_table_get_physical_table_id(virtual_schema);
}

int flag_scan(struct table_manager *tbl_mgr, int thread_id, long long flag,
              int physical_table_id, int vtable_id, struct maat_state *state)
{
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, physical_table_id);
    if (table_type == TABLE_TYPE_FLAG_PLUS && DISTRICT_FLAG_UNSET == state->is_set_district) {
        return -1;
    }

    if (table_type != TABLE_TYPE_FLAG && table_type != TABLE_TYPE_FLAG_PLUS) {
        return -1;
    }

    void *flag_rt = table_manager_get_runtime(tbl_mgr, physical_table_id);
    if (NULL == flag_rt) {
        return -1;
    }

    int group_hit_cnt = flag_runtime_scan((struct flag_runtime *)flag_rt, thread_id,
                                          flag, vtable_id, state);
    if (group_hit_cnt < 0) {
        return -1;
    }

    if (group_hit_cnt > 0) {
        flag_runtime_scan_hit_inc((struct flag_runtime *)flag_rt, thread_id);
    }

    return group_hit_cnt;
}

int interval_scan(struct table_manager *tbl_mgr, int thread_id, long long integer,
                  int physical_table_id, int vtable_id, struct maat_state *state)
{

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, physical_table_id);
    if (table_type == TABLE_TYPE_INTERVAL_PLUS && DISTRICT_FLAG_UNSET == state->is_set_district) {
        // maat_instance->scan_err_cnt++;
        return -1;
    }

    if (table_type != TABLE_TYPE_INTERVAL && table_type != TABLE_TYPE_INTERVAL_PLUS) {
        return -1;
    }

    void *interval_rt = table_manager_get_runtime(tbl_mgr, physical_table_id);
    if (NULL == interval_rt) {
        return -1;
    }

    int group_hit_cnt = interval_runtime_scan((struct interval_runtime *)interval_rt,
                                              thread_id, integer, vtable_id, state);
    if (group_hit_cnt < 0) {
        return -1;
    }

    if (group_hit_cnt > 0) {
        interval_runtime_scan_hit_inc((struct interval_runtime *)interval_rt, thread_id);
    }

    return group_hit_cnt;
}

int ipv4_scan(struct table_manager *tbl_mgr, int thread_id, uint32_t ip_addr,
              uint16_t port, int proto, int physical_table_id, int vtable_id, 
              struct maat_state *state)
{

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, physical_table_id);
    if (table_type != TABLE_TYPE_IP_PLUS) {
        return -1;
    }

    void *ip_rt = table_manager_get_runtime(tbl_mgr, physical_table_id);
    if (NULL == ip_rt) {
        return -1;
    }

    int group_hit_cnt = ip_runtime_scan((struct ip_runtime *)ip_rt, thread_id, IPv4,
                                        (uint8_t *)&ip_addr, port, proto, vtable_id, 
                                        state);
    if (group_hit_cnt < 0) {
        return -1;
    }

    if (group_hit_cnt > 0) {
        ip_runtime_scan_hit_inc((struct ip_runtime *)ip_rt, thread_id);
    }

    return group_hit_cnt;
}

int ipv6_scan(struct table_manager *tbl_mgr, int thread_id, uint8_t *ip_addr,
              uint16_t port, int proto, int physical_table_id, int vtable_id, 
              struct maat_state *state)
{

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, physical_table_id);
    if (table_type != TABLE_TYPE_IP_PLUS) {
        return -1;
    }

    void *ip_rt = table_manager_get_runtime(tbl_mgr, physical_table_id);
    if (NULL == ip_rt) {
        return -1;
    }

    int group_hit_cnt = ip_runtime_scan((struct ip_runtime *)ip_rt, thread_id, IPv6,
                                        ip_addr, port, proto, vtable_id, state);
    if (group_hit_cnt < 0) {
        return -1;
    }

    if (group_hit_cnt > 0) {
        ip_runtime_scan_hit_inc((struct ip_runtime *)ip_rt, thread_id);
    }

    return group_hit_cnt;
}

int string_scan(struct table_manager *tbl_mgr, int thread_id, const char *data, size_t data_len,
                int physical_table_id, int vtable_id, struct maat_state *state)
{
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, physical_table_id);
    if (table_type == TABLE_TYPE_EXPR_PLUS && DISTRICT_FLAG_UNSET == state->is_set_district) {
        // maat_instance->scan_err_cnt++;
        return -1;
    }

    if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
        return -1;
    }

    void *expr_rt = table_manager_get_runtime(tbl_mgr, physical_table_id);
    if (NULL == expr_rt) {
        return -1;
    }

    int group_hit_cnt = expr_runtime_scan((struct expr_runtime *)expr_rt,
                                          thread_id, data, data_len,
                                          vtable_id, state);
    if (group_hit_cnt < 0) {
        return -1;
    }

    if (group_hit_cnt > 0) {
        expr_runtime_scan_hit_inc((struct expr_runtime *)expr_rt, thread_id);
    }

    return group_hit_cnt;
}

int expr_stream_scan(struct maat_stream *stream, const char *data, size_t data_len, struct maat_state *state)
{
    if (NULL == stream || NULL == data) {
        return 0;
    }

    struct table_manager *tbl_mgr = stream->ref_maat_instance->tbl_mgr;
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, stream->physical_table_id);
    if (table_type == TABLE_TYPE_EXPR_PLUS && DISTRICT_FLAG_UNSET == state->is_set_district) {
        // maat_instance->scan_err_cnt++;
        return -1;
    }

    if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
        return -1;
    }

    void *expr_rt = table_manager_get_runtime(tbl_mgr, stream->physical_table_id);
    if (NULL == expr_rt) {
        return -1;
    }

    int group_hit_cnt = expr_runtime_stream_scan((struct expr_runtime *)expr_rt, stream->s_handle,
                                                 data, data_len, stream->vtable_id, state);
    if (group_hit_cnt < 0) {
        return -1;
    }

    if (group_hit_cnt > 0) {
        expr_runtime_scan_hit_inc((struct expr_runtime *)expr_rt, stream->thread_id);
    }

    return group_hit_cnt;
}

size_t group_to_compile(struct maat *maat_instance, long long *results, size_t n_result,
                        struct maat_state *state)
{
    int compile_table_id = -1;

    if (state->compile_table_id != 0) {
        compile_table_id = state->compile_table_id;
    } else {
        compile_table_id = maat_instance->default_compile_table_id;
    }

    void *compile_rt = table_manager_get_runtime(maat_instance->tbl_mgr, compile_table_id);
    size_t n_hit_compile = hit_group_to_compile(compile_rt, results, n_result, state);

    assert(state->is_last_scan < LAST_SCAN_FINISHED);
    if (LAST_SCAN_SET == state->is_last_scan) {
        state->is_last_scan = LAST_SCAN_FINISHED;
    }

    return n_hit_compile;
}

int maat_scan_flag(struct maat *maat_instance, int table_id, int thread_id,
                   long long flag, long long *results, size_t n_result,
                   size_t *n_hit_result, struct maat_state *state)
{
    if ((NULL == maat_instance) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (thread_id < 0) || (NULL == results) || (0 == n_result) 
        || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }

    state->scan_cnt++;

    if (NULL == maat_instance->maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                 "[%s:%d] table(table_id:%d) thread_id:%d maat_scan_flag error because of maat_runtime is NULL",
                 __FUNCTION__, __LINE__, table_id, thread_id);
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int physical_table_id = -1;
    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        physical_table_id = vtable_get_physical_table_id(maat_instance->tbl_mgr, table_id);
        vtable_id = table_id;
    } else {
        physical_table_id = table_id;
    }
    
    if (physical_table_id < 0) {
        return MAAT_SCAN_ERR;
    }

    table_type = table_manager_get_table_type(maat_instance->tbl_mgr, physical_table_id);
    if (table_type != TABLE_TYPE_FLAG && table_type != TABLE_TYPE_FLAG_PLUS) {
        return MAAT_SCAN_ERR;
    }

    maat_runtime_ref_inc(maat_instance->maat_rt, thread_id);
    alignment_int64_array_add(maat_instance->thread_call_cnt, thread_id, 1);

    int hit_group_cnt = flag_scan(maat_instance->tbl_mgr, thread_id, flag,
                                  physical_table_id, vtable_id, state);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }

    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(maat_instance, results, n_result, state);
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
                      size_t *n_hit_result, struct maat_state *state)
{
    if ((NULL == maat_instance) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (thread_id < 0) || (NULL == results) || (0 == n_result) || 
        (NULL == state)) {
        return MAAT_SCAN_ERR;
    }
    
    state->scan_cnt++;

    if (NULL == maat_instance->maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                 "[%s:%d] table(table_id:%d) thread_id:%d maat_scan_integer error because of maat_runtime is NULL",
                 __FUNCTION__, __LINE__, table_id, thread_id);
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int physical_table_id = -1;
    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        physical_table_id = vtable_get_physical_table_id(maat_instance->tbl_mgr, table_id);
        vtable_id = table_id;
    } else {
        physical_table_id = table_id;
    }
    
    if (physical_table_id < 0) {
        return MAAT_SCAN_ERR;
    }

    table_type = table_manager_get_table_type(maat_instance->tbl_mgr, physical_table_id);
    if (table_type != TABLE_TYPE_INTERVAL && table_type != TABLE_TYPE_INTERVAL_PLUS) {
        return MAAT_SCAN_ERR;
    }

    maat_runtime_ref_inc(maat_instance->maat_rt, thread_id);
    alignment_int64_array_add(maat_instance->thread_call_cnt, thread_id, 1);

    int hit_group_cnt = interval_scan(maat_instance->tbl_mgr, thread_id, integer,
                                      physical_table_id, vtable_id, state);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }
    
    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(maat_instance, results, n_result, state);
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
                   uint32_t ip_addr, uint16_t port, int protocol,
                   long long *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state *state)
{
    if ((NULL == maat_instance) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (protocol < -1) || (thread_id < 0) || (NULL == results) || (0 == n_result) 
        || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }

    state->scan_cnt++;

    if (NULL == maat_instance->maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                 "[%s:%d] table(table_id:%d) thread_id:%d maat_scan_ipv4 error because of maat_runtime is NULL",
                 __FUNCTION__, __LINE__, table_id, thread_id);
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int physical_table_id = -1;
    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        physical_table_id = vtable_get_physical_table_id(maat_instance->tbl_mgr, table_id);
        vtable_id = table_id;
    } else {
        physical_table_id = table_id;
    }
    
    if (physical_table_id < 0) {
        return MAAT_SCAN_ERR;
    }

    table_type = table_manager_get_table_type(maat_instance->tbl_mgr, physical_table_id);
    if (table_type != TABLE_TYPE_IP_PLUS) {
        return MAAT_SCAN_ERR;
    }

    maat_runtime_ref_inc(maat_instance->maat_rt, thread_id);
    alignment_int64_array_add(maat_instance->thread_call_cnt, thread_id, 1);

    int hit_group_cnt = ipv4_scan(maat_instance->tbl_mgr, thread_id, ip_addr, port, protocol,
                                  physical_table_id, vtable_id, state);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }
    
    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(maat_instance, results, n_result, state);
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
                          struct maat_state *state)
{
    return MAAT_SCAN_OK;
}

int maat_scan_ipv6(struct maat *maat_instance, int table_id, int thread_id, 
                   uint8_t *ip_addr, uint16_t port, int protocol,
                   long long *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state *state)
{
    if ((NULL == maat_instance) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (protocol < -1) || (thread_id < 0) || (NULL == ip_addr) 
        || (NULL == results) || (0 == n_result) || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }

    state->scan_cnt++;

    if (NULL == maat_instance->maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                 "[%s:%d] table(table_id:%d) thread_id:%d maat_scan_ipv6 error because of maat_runtime is NULL",
                 __FUNCTION__, __LINE__, table_id, thread_id);
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int physical_table_id = -1;
    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        physical_table_id = vtable_get_physical_table_id(maat_instance->tbl_mgr, table_id);
        vtable_id = table_id;
    } else {
        physical_table_id = table_id;
    }
    
    if (physical_table_id < 0) {
        return MAAT_SCAN_ERR;
    }

    table_type = table_manager_get_table_type(maat_instance->tbl_mgr, physical_table_id);
    if (table_type != TABLE_TYPE_IP_PLUS) {
        return MAAT_SCAN_ERR;
    }

    maat_runtime_ref_inc(maat_instance->maat_rt, thread_id);
    alignment_int64_array_add(maat_instance->thread_call_cnt, thread_id, 1);

    int hit_group_cnt = ipv6_scan(maat_instance->tbl_mgr, thread_id, ip_addr, port, protocol, 
                                  physical_table_id, vtable_id, state);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }

    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(maat_instance, results, n_result, state);
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
                          struct maat_state *state)
{
    return MAAT_SCAN_OK;
}

int maat_scan_string(struct maat *maat_instance, int table_id, int thread_id,
                     const char *data, size_t data_len, long long *results, size_t n_result,
                     size_t *n_hit_result, struct maat_state *state)
{
    if ((NULL == maat_instance) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (thread_id < 0) || (NULL == data) || (0 == data_len) 
        || (NULL == results) || (0 == n_result) || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }
    
    state->scan_cnt++;

    if (NULL == maat_instance->maat_rt) {
        log_error(maat_instance->logger, MODULE_MAAT_API, 
                 "[%s:%d] table(table_id:%d) thread_id:%d maat_scan_string error because of maat_runtime is NULL",
                 __FUNCTION__, __LINE__, table_id, thread_id);
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int physical_table_id = -1;
    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        physical_table_id = vtable_get_physical_table_id(maat_instance->tbl_mgr, table_id);
        vtable_id = table_id;
    } else {
        physical_table_id = table_id;
    }
    
    if (physical_table_id < 0) {
        return MAAT_SCAN_ERR;
    }

    table_type = table_manager_get_table_type(maat_instance->tbl_mgr, physical_table_id);
    if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
        return MAAT_SCAN_ERR;
    }

    maat_runtime_ref_inc(maat_instance->maat_rt, thread_id);
    alignment_int64_array_add(maat_instance->thread_call_cnt, thread_id, 1);

    int hit_group_cnt = string_scan(maat_instance->tbl_mgr, thread_id, data, data_len, 
                                    physical_table_id, vtable_id, state);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }

     size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(maat_instance, results, n_result, state);
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
    stream->ref_maat_instance = maat_instance;
    stream->thread_id = thread_id;
    stream->logger = maat_instance->logger;

    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        stream->physical_table_id = vtable_get_physical_table_id(maat_instance->tbl_mgr, table_id);
        stream->vtable_id = table_id;
    } else {
        stream->physical_table_id = table_id;
        stream->vtable_id = 0;
    }
    
    if (stream->physical_table_id < 0) {
        return NULL;
    }

    table_type = table_manager_get_table_type(maat_instance->tbl_mgr, stream->physical_table_id);
    if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
        return NULL;
    }

    void *expr_rt = table_manager_get_runtime(stream->ref_maat_instance->tbl_mgr,
                                              stream->physical_table_id);
    assert(expr_rt != NULL);

    struct adapter_hs_stream *handle = expr_runtime_stream_open((struct expr_runtime *)expr_rt, thread_id);
    if (NULL == handle) {
        goto error;
    }
    stream->s_handle = handle;

    return stream;

error:
    FREE(stream);
    return NULL;
}

int maat_scan_stream(struct maat_stream **maat_stream, const char *data, int data_len, 
                     long long *results, size_t n_result, size_t *n_hit_result,
                     struct maat_state *state)
{
    if ((NULL == maat_stream) || (NULL == data) || (0 == data_len) 
        || (NULL == results) || (0 == n_result) || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }

    state->scan_cnt++;
    struct maat_stream *stream = *maat_stream;

    int valid_table_id = -1;
    if (stream->vtable_id != 0) {
        valid_table_id = stream->vtable_id;
    } else {
        valid_table_id = stream->physical_table_id;
    }

    if (NULL == stream->ref_maat_instance->maat_rt) {
        log_error(stream->logger, MODULE_MAAT_API, 
                 "[%s:%d] table(table_id:%d) thread_id:%d maat_scan_stream error because of maat_runtime is NULL",
                 __FUNCTION__, __LINE__, valid_table_id, stream->thread_id);
        return MAAT_SCAN_OK;
    }

    alignment_int64_array_add(stream->ref_maat_instance->thread_call_cnt, stream->thread_id, 1);

    int hit_group_cnt = expr_stream_scan(stream, data, data_len, state);
    if (hit_group_cnt < 0) {
        return MAAT_SCAN_ERR;
    }

    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        // come here means group_hit_cnt > 0, at least MAAT_SCAN_HALF_HIT, or MAAT_SCAN_HIT
        sum_hit_compile_cnt = group_to_compile(stream->ref_maat_instance, results, n_result, state);
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

    expr_runtime_stream_close(stream->s_handle);
    FREE(stream);
}

struct maat_state *maat_state_new(struct maat *maat_instance, int thread_id)
{
    if (NULL == maat_instance || thread_id < 0) {
        return NULL;
    }

    struct maat_state *state = ALLOC(struct maat_state, 1);

    state->maat_instance = maat_instance;
    state->is_set_district = DISTRICT_FLAG_UNSET;
    state->is_last_scan = LAST_SCAN_UNSET;
    state->district_id = DISTRICT_ANY;
    state->thread_id = thread_id;

    state->compile_state = maat_compile_state_new(thread_id);
    return state;
}

void maat_state_reset(struct maat_state *state)
{
    if (NULL == state) {
        return;
    }

    state->compile_table_id = 0;
    state->is_set_district = DISTRICT_FLAG_UNSET;
    state->is_last_scan = LAST_SCAN_UNSET;
    state->district_id = DISTRICT_ANY;
    state->scan_cnt = 0;

    assert(state->compile_state != NULL);
    maat_compile_state_reset(state->compile_state);
}

void maat_state_free(struct maat_state *state)
{
    if (NULL == state) {
        return;
    }

    assert(state->compile_state != NULL);
    maat_compile_state_free(state->compile_state);
    state->compile_state = NULL;
    state->maat_instance = NULL;
    free(state);
}

int maat_state_set_scan_district(struct maat_state *state, const char *district, 
                                 size_t district_len)
{
    if (NULL == state || NULL == district || 0 == district_len) {
        return -1;
    }

    struct maat *maat_instance = state->maat_instance;
    assert(maat_instance != NULL);

    if (NULL == maat_instance->maat_rt) {
        return -1;
    }

    int ret = table_manager_set_scan_district(maat_instance->tbl_mgr, 
                                              district, district_len,
                                              &(state->district_id));
    if (ret < 0) {
        state->district_id = DISTRICT_UNKNOWN;
    }

    state->is_set_district = DISTRICT_FLAG_SET;

    return 0;
}

int maat_state_set_last_scan(struct maat_state *state)
{
    if (NULL == state) {
        return -1;
    }

    struct maat *maat_instance = state->maat_instance;
    assert(maat_instance != NULL);

    if (NULL == maat_instance->maat_rt) {
        return -1;
    }

    assert(state->is_last_scan == LAST_SCAN_UNSET);
    state->is_last_scan = LAST_SCAN_SET;

    return 0;
}

int maat_state_set_scan_compile_table(struct maat_state *state, int compile_table_id)
{
    if (NULL == state || compile_table_id < 0) {
        return -1;
    }

    struct maat *maat_instance = state->maat_instance;
    assert(maat_instance != NULL);

    if (NULL == maat_instance->maat_rt) {
        return -1;
    }

    state->compile_table_id = compile_table_id;

    return 0;
}

int maat_state_get_hit_paths(struct maat_state *state, struct maat_hit_path *paths, size_t n_path)
{
    if (NULL == state || NULL == paths || 0 == n_path) {
        return -1;
    }

    struct maat *maat_instance = state->maat_instance;
    assert(maat_instance != NULL);

    if (NULL == maat_instance->maat_rt) {
        return -1;
    }

    int compile_table_id = -1;
    if (state->compile_table_id != 0) {
        compile_table_id = state->compile_table_id;
    } else {
        compile_table_id = maat_instance->default_compile_table_id;
    }

    void *g2g_runtime = table_manager_get_runtime(maat_instance->tbl_mgr, maat_instance->g2g_table_id);
    assert(g2g_runtime != NULL);
    size_t internal_hit_path_cnt = maat_compile_state_get_internal_hit_paths(state->compile_state, 
                                                                            (struct group2group_runtime *)g2g_runtime,
                                                                             paths, n_path);
    
    void *compile_rt = table_manager_get_runtime(maat_instance->tbl_mgr, compile_table_id);
    assert(NULL != compile_rt);
        
    return compile_runtime_get_hit_paths((struct compile_runtime *)compile_rt,
                                          state->compile_state, paths, n_path,
                                          internal_hit_path_cnt);
}

int maat_state_get_hit_objects(struct maat_state *state, struct maat_hit_object *objs, size_t n_obj)
{
    return 0;
}

int maat_hit_object_compile_id(struct maat *instance, struct maat_hit_object *obj)
{
    return 0;
}
