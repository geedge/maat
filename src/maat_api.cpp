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

#include "utils.h"
#include "json2iris.h"
#include "maat/maat.h"
#include "maat_rule.h"
#include "maat_common.h"
#include "maat_kv.h"
#include "maat_command.h"
#include "maat_table_schema.h"
#include "maat_table_runtime.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"

struct maat_options* maat_options_new(void)
{
    struct maat_options *options = ALLOC(struct maat_options, 1);

    options->nr_worker_threads = 1;
    options->deferred_load_on = 0;
    options->rule_effect_interval_ms = 60 * 1000;
    options->rule_update_checking_interval_ms = 1 * 1000;
    options->gc_timeout_ms = 10 * 1000;
    options->input_mode = DATA_SOURCE_NONE;

    return options;
}

int maat_options_set_worker_thread_number(struct maat_options *opts, size_t n_worker_threads)
{
    opts->nr_worker_threads = n_worker_threads;
    
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

int maat_options_set_deferred_load_on(struct maat_options *opts)
{
    opts->deferred_load_on = 1;

    return 0;
}

int maat_options_set_iris_full_dir(struct maat_options *opts, const char *full_dir)
{
    if (strlen(full_dir) >= NAME_MAX) {
        return -1;
    }

    memcpy(opts->iris_ctx.full_dir, full_dir, strlen(full_dir));
    opts->input_mode = DATA_SOURCE_IRIS_FILE;

    return 0;
}

int maat_options_set_iris_inc_dir(struct maat_options *opts, const char *inc_dir)
{
    if (strlen(inc_dir) >= NAME_MAX) {
        return -1;
    }

    memcpy(opts->iris_ctx.inc_dir, inc_dir, strlen(inc_dir));
    opts->input_mode = DATA_SOURCE_IRIS_FILE;

    return 0;
}

int maat_options_set_json_file(struct maat_options *opts, const char *json_filename)
{
    strncpy(opts->json_ctx.json_file, json_filename, sizeof(opts->json_ctx.json_file));
    opts->input_mode = DATA_SOURCE_JSON_FILE;

    return 0;
}

int maat_options_set_redis_ip(struct maat_options *opts, const char *redis_ip)
{
    memcpy(opts->redis_ctx.redis_ip, redis_ip, strlen(redis_ip));
    opts->input_mode = DATA_SOURCE_REDIS;

    return 0;
}

int maat_options_set_redis_port(struct maat_options *opts, uint16_t redis_port)
{
    opts->redis_ctx.redis_port = redis_port;

    return 0;
}

int maat_options_set_redis_db_index(struct maat_options *opts, int db_index)
{
    opts->redis_ctx.redis_db = db_index;

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
            fprintf(stdout, "Maat initiate from Redis %s:%hu db%d.", 
                            mr_ctx->redis_ip, mr_ctx->redis_port, mr_ctx->redis_db);
            mr_ctx->read_ctx = maat_cmd_connect_redis(mr_ctx->redis_ip, mr_ctx->redis_port, mr_ctx->redis_db);
            if (mr_ctx->read_ctx != NULL) {
                redis_monitor_traverse(maat_instance->maat_version, mr_ctx,
									   maat_start_cb, maat_update_cb, maat_finish_cb,
									   maat_instance);
            }

            if (NULL == maat_instance->creating_maat_rt) {
                fprintf(stderr, "At initiation: NO effective rule in %s.",
                                maat_instance->iris_ctx.full_dir);
            }
            break;
        case DATA_SOURCE_IRIS_FILE:
			config_monitor_traverse(maat_instance->maat_version,
                                    maat_instance->iris_ctx.full_dir,
                                    maat_start_cb, maat_update_cb, maat_finish_cb,
                                    maat_instance);
            if (NULL == maat_instance->creating_maat_rt) {
                fprintf(stderr, "At initiation: NO effective rule in %s.",
                                maat_instance->iris_ctx.full_dir);
            }
            break;
        case DATA_SOURCE_JSON_FILE:
            ret = load_maat_json_file(maat_instance, maat_instance->json_ctx.json_file, err_str, sizeof(err_str));
            if (ret < 0) {
                fprintf(stderr, "Maat re-initiate with JSON file %s failed: %s", maat_instance->json_ctx.json_file, err_str);
                return;
            }
            
            config_monitor_traverse(maat_instance->maat_version,
                                    maat_instance->json_ctx.iris_file,
                                    maat_start_cb, maat_update_cb, maat_finish_cb,
                                    maat_instance);
            if (NULL == maat_instance->creating_maat_rt) {
                fprintf(stderr, "At initiation: NO effective rule in %s.",
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
    
    maat_instance->table_schema_mgr = table_schema_manager_create(table_info_path);
    if (NULL == maat_instance->table_schema_mgr) {
        goto failed;
    }

    maat_instance->input_mode = opts->input_mode;
    switch (maat_instance->input_mode) {
        case DATA_SOURCE_REDIS:
            memcpy(maat_instance->mr_ctx.redis_ip, opts->redis_ctx.redis_ip, strlen(opts->redis_ctx.redis_ip));
            maat_instance->mr_ctx.redis_port = opts->redis_ctx.redis_port;
            maat_instance->mr_ctx.redis_db = opts->redis_ctx.redis_db;
            break;
        case DATA_SOURCE_IRIS_FILE:
            memcpy(maat_instance->iris_ctx.full_dir, opts->iris_ctx.full_dir, strlen(opts->iris_ctx.full_dir));
            memcpy(maat_instance->iris_ctx.inc_dir, opts->iris_ctx.inc_dir, strlen(opts->iris_ctx.inc_dir));
            break;
        case DATA_SOURCE_JSON_FILE:
            memcpy(maat_instance->json_ctx.json_file, opts->json_ctx.json_file, strlen(opts->json_ctx.json_file));
            break;
        default:
            fprintf(stderr, "data source unsupported:%d\n", maat_instance->input_mode);
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
    pthread_mutex_init(&(maat_instance->background_update_mutex), NULL);

    if (0 == maat_instance->deferred_load) {
        maat_read_full_config(maat_instance);
    }

    pthread_create(&(maat_instance->cfg_mon_thread), NULL, rule_monitor_loop, (void*)maat_instance);

    return maat_instance;
failed:
    free(maat_instance);
    return NULL;
}

void maat_free(struct maat *maat_instance)
{

    void* ret = NULL;
	pthread_join(maat_instance->cfg_mon_thread, &ret);

	return;
}

int maat_table_get_id(struct maat *maat_instance, const char *table_name)
{
    int table_id = -1;

    struct table_schema_manager *table_schema_mgr = maat_instance->table_schema_mgr;
    table_id = table_schema_manager_get_table_id(table_schema_mgr, table_name);
    
    return table_id;
}

int maat_table_callback_register(struct maat *maat_instance, int table_id,
								 maat_start_callback_t *start,
								 maat_update_callback_t *update,
								 maat_finish_callback_t *finish,
								 void *u_para)
{
    int ret = -1;

    pthread_mutex_lock(&(maat_instance->background_update_mutex));
    ret = plugin_table_schema_add_callback(maat_instance->table_schema_mgr, table_id, start, update, finish, u_para);
    if (ret < 0) {
        pthread_mutex_unlock(&(maat_instance->background_update_mutex));
        return -1;
    }

    if (!maat_instance->maat_rt) {
        pthread_mutex_unlock(&(maat_instance->background_update_mutex));
        return 0;
    }

    struct table_runtime *table_rt = table_runtime_get(maat_instance->maat_rt->table_rt_mgr, table_id);
    size_t row_count = table_runtime_cached_row_count(table_rt);
    if (row_count > 0) {
        if (start != NULL) {
            start(MAAT_RULE_UPDATE_TYPE_FULL, u_para);
        }

        for (size_t i = 0; i < row_count; i++) {
            const char *line = table_runtime_get_cached_row(table_rt, i);
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

int maat_plugin_table_ex_schema_register(struct maat *maat_instance, int table_id,
                                         maat_plugin_ex_new_func_t *new_func,
                                         maat_plugin_ex_free_func_t *free_func,
                                         maat_plugin_ex_dup_func_t *dup_func,
                                         long argl, void *argp)
{
    struct table_schema *table_schema = table_schema_get(maat_instance->table_schema_mgr, table_id);
    pthread_mutex_lock(&(maat_instance->background_update_mutex));
    int ret = plugin_table_schema_set_ex_data_schema(table_schema, new_func, free_func, dup_func, argl, argp);
    if (ret < 0) {
        pthread_mutex_unlock(&(maat_instance->background_update_mutex));
        return -1;
    }
    
    struct table_runtime *table_rt = NULL;
    if (maat_instance->maat_rt != NULL) {
        table_rt = table_runtime_get(maat_instance->maat_rt->table_rt_mgr, table_id);
        table_runtime_commit_ex_data_schema(table_rt, table_schema);
    }
    pthread_mutex_unlock(&(maat_instance->background_update_mutex));

    return 0;
}

void *maat_plugin_table_get_ex_data(struct maat *maat_instance, int table_id,
                                    const char *key, size_t key_len)
{
    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    if (NULL == maat_rt) {
        return NULL;
    }

    struct table_schema *table_schema  = table_schema_get(maat_instance->table_schema_mgr, table_id);
    struct table_runtime *table_rt = table_runtime_get(maat_rt->table_rt_mgr, table_id);

    return table_runtime_get_ex_data(table_rt, table_schema, key, key_len);
}

int maat_scan_integer(struct maat *instance, int table_id, int thread_id,
                      unsigned int intval, int results[], size_t n_result,
                      struct maat_state *state)
{
    return 0;
}

int maat_scan_ip(struct maat *instance, int table_id, int thread_id, 
                 const struct ip_data *ip, int results[], size_t n_result, 
                 struct maat_state *state)
{
    return 0;
}

int maat_scan_string(struct maat *maat_instance, int table_id, int thread_id,
                     const char *data, size_t data_len, int results[], size_t *n_results,
                     struct maat_state *state)
{
    if ((NULL == maat_instance) || (table_id < 0) || (table_id >= MAX_TABLE_NUM) ||
        (thread_id < 0) || (NULL == data) || (0 == data_len) || (NULL == results) || 
        (NULL == n_results)) {
        return -1;
    }
    
    struct table_runtime_manager *table_rt_mgr = maat_instance->maat_rt->table_rt_mgr;
    struct table_runtime *table_rt = table_runtime_get(table_rt_mgr, table_id);
    
    return table_runtime_scan_string(table_rt, thread_id, data, data_len, results, n_results);
}

struct maat_stream *maat_scan_stream_open(struct maat *instance, int table_id, int thread_id)
{
    return NULL;
}

int maat_scan_stream(struct maat_stream **stream, int thread_id, const char* data, int data_len, 
                     int results[], size_t n_result, struct maat_state *state)
{
    return 0;
}

void maat_scan_stream_close(struct maat_stream **stream)
{

}

void maat_state_reset(struct maat_state *state)
{

}