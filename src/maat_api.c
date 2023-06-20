/*
**********************************************************************************************
*	File: maat_api.c
*   Description: maat api entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <linux/limits.h>

#include "maat_utils.h"
#include "json2iris.h"
#include "maat.h"
#include "maat_rule.h"
#include "maat_kv.h"
#include "maat_command.h"
#include "maat_ex_data.h"
#include "maat_table.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"
#include "maat_compile.h"
#include "alignment.h"
#include "ip_matcher.h"
#include "adapter_hs.h"
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
#include "maat_stat.h"
#include "uthash/utarray.h"

#define MODULE_MAAT_API	 module_name_str("maat.api")

enum district_flag {
    DISTRICT_FLAG_UNSET,
    DISTRICT_FLAG_SET
};

struct maat_stream {
    struct maat *ref_maat_inst;
    struct adapter_hs_stream *handle; //each physical table open one stream
    long long last_full_version;
    long long expr_rt_version;
    struct log_handle *logger;
    int thread_id;
    int vtable_id;
    int phy_table_id;
};

struct maat_options* maat_options_new(void)
{
    struct maat_options *options = ALLOC(struct maat_options, 1);

    options->nr_worker_thread = 1;
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

    FREE(opts);
}

int maat_options_set_caller_thread_number(struct maat_options *opts, size_t n_thread)
{
    if (NULL == opts) {
        return -1;
    }

    opts->nr_worker_thread = n_thread;
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
        strlen(instance_name) > MAX_INSTANCE_NAME_LEN) {
        return -1;
    }

    memcpy(opts->inst_name, instance_name, strlen(instance_name));
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

int maat_options_set_stat_on(struct maat_options *opts)
{
    if (NULL == opts) {
        return -1;
    }

    opts->stat_on = 1;
    return 0;
}

int maat_options_set_perf_on(struct maat_options *opts)
{
    if (NULL == opts) {
        return -1;
    }

    opts->perf_on = 1;
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

int maat_options_set_json_file_gzip_flag(struct maat_options *opts, int flag)
{
    if (NULL == opts || (flag != 0 && flag != 1)) {
        return -1;
    }

    opts->maat_json_is_gzipped = flag;

    return 0;
}

int maat_options_set_json_file_decrypt_key(struct maat_options *opts,
                                           const char *decrypt_key)
{
    if (NULL == opts || NULL == decrypt_key) {
        return -1;
    }

    size_t str_len = MIN(sizeof(opts->decrypt_key), strlen(decrypt_key));

    memcpy(opts->decrypt_key, decrypt_key, str_len);

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

int maat_options_set_stat_file(struct maat_options *opts, const char *stat_filename)
{
    size_t str_len = MIN(sizeof(opts->stat_file), strlen(stat_filename));

    memcpy(opts->stat_file, stat_filename, str_len);
    opts->stat_on = 1;
    
    return 0;
}

int maat_options_set_logger(struct maat_options *opts, const char *log_path,
                            enum log_level level)
{
    if (NULL == opts || NULL == log_path || strlen(log_path) >= PATH_MAX) {
        return -1;
    }

    memcpy(opts->log_path, log_path, strlen(log_path));
    opts->log_level = level;

    return 0;
}

static void _maat_free(struct maat *maat_inst)
{
    if (NULL == maat_inst) {
        return;
    }

    if (maat_inst->logger != NULL) {
        log_handle_destroy(maat_inst->logger);
        maat_inst->logger = NULL;
    }
    
    if (maat_inst->garbage_bin != NULL) {
        maat_garbage_bin_free(maat_inst->garbage_bin);
        maat_inst->garbage_bin = NULL;
    }
    
    if (maat_inst->stat != NULL) {
        maat_stat_free(maat_inst->stat);
        maat_inst->stat = NULL;
    }

    if (maat_inst->opts.accept_tags != NULL) {
        FREE(maat_inst->opts.accept_tags);
    }
    
    pthread_mutex_destroy(&(maat_inst->background_update_mutex));

    FREE(maat_inst);
}

struct maat *maat_new(struct maat_options *opts, const char *table_info_path)
{
    if (NULL == opts || NULL == table_info_path) {
        return NULL;
    }

    struct maat *maat_inst = ALLOC(struct maat, 1);

    maat_inst->opts = *opts;

    if (strlen(maat_inst->opts.log_path) != 0) {
        maat_inst->logger = log_handle_create(maat_inst->opts.log_path,
                                                  maat_inst->opts.log_level);
    } else {
        char log_path[MAX_NAME_STR_LEN] = {0};
        if (strlen(maat_inst->opts.inst_name) > 0) {
            snprintf(log_path, sizeof(log_path), "%s.log", maat_inst->opts.inst_name);
        } else {
            snprintf(log_path, sizeof(log_path), "maat.log");
        }
        maat_inst->logger = log_handle_create(log_path, maat_inst->opts.log_level);
    }

    if (0 == strlen(maat_inst->opts.foreign_cont_dir)) {
        snprintf(maat_inst->opts.foreign_cont_dir, sizeof(maat_inst->opts.foreign_cont_dir),
                 "%s_files", table_info_path);
    }
   
    system_cmd_mkdir(maat_inst->opts.foreign_cont_dir);

    if (0 == strlen(maat_inst->opts.stat_file)) {
        snprintf(maat_inst->opts.stat_file, sizeof(maat_inst->opts.stat_file), "maat.fs3");
    }

    snprintf(maat_inst->opts.decrypt_algo, sizeof(maat_inst->opts.decrypt_algo), "aes-256-cbc");

    maat_inst->is_running = 0;
    maat_inst->maat_version = 0;
    maat_inst->last_full_version = 0;

    int garbage_gc_timeout_s = (maat_inst->opts.rule_effect_interval_ms / 1000) +
                            (maat_inst->opts.gc_timeout_ms / 1000);

    if (maat_inst->opts.input_mode != DATA_SOURCE_IRIS_FILE &&
        maat_inst->opts.input_mode != DATA_SOURCE_JSON_FILE &&
        maat_inst->opts.input_mode != DATA_SOURCE_REDIS) {
        log_error(maat_inst->logger, MODULE_MAAT_API, 
                       "[%s:%d] data source(%d) unsupported", 
                       __FUNCTION__, __LINE__, maat_inst->opts.input_mode);
        goto failed;
    }

    maat_inst->garbage_bin = maat_garbage_bin_new(garbage_gc_timeout_s);
    maat_inst->stat = maat_stat_new(maat_inst->opts.stat_file,
                                    maat_inst->opts.nr_worker_thread, 
                                    maat_inst->logger);

    pthread_mutex_init(&(maat_inst->background_update_mutex), NULL);

    maat_inst->tbl_mgr = table_manager_create(table_info_path, maat_inst->opts.accept_tags,
                                              maat_inst->garbage_bin, maat_inst->logger);
    if (NULL == maat_inst->tbl_mgr) {
        goto failed;
    }

    if (0 == maat_inst->opts.deferred_load_on) {
        maat_read_full_config(maat_inst);
    }

    if (1 == maat_inst->opts.stat_on) {
        int ret = maat_stat_init(maat_inst->stat, maat_inst->tbl_mgr, maat_inst->garbage_bin);
        if (ret < 0) {
            log_error(maat_inst->logger, MODULE_MAAT_API,
                     "[%s:%d] maat_stat_init failed.", __FUNCTION__, __LINE__);
            goto failed;
        }
    }

    pthread_create(&(maat_inst->cfg_mon_thread), NULL, rule_monitor_loop, (void *)maat_inst);

    return maat_inst;
failed:
    _maat_free(maat_inst);
    return NULL;
}

void maat_free(struct maat *maat_inst)
{
    if (NULL == maat_inst) {
        return;
    }

    void *ret = NULL;
    while (0 == maat_inst->is_running) {
        usleep(500 * 1000); 
    }
    
    maat_inst->is_running = 0;
	pthread_join(maat_inst->cfg_mon_thread, &ret);
}

int maat_helper_read_column(const char *table_line, int Nth_column, 
                            size_t *column_offset, size_t *column_len)
{
    return get_column_pos(table_line, Nth_column, column_offset, column_len);
}

int maat_helper_verify_regex_expression(const char *regex_expr)
{
    if (NULL == regex_expr) {
        return 0;
    }

    int ret = adapter_hs_verify_regex_expression(regex_expr, NULL);
    if (ret < 0) {
        return 0;
    } else {
        return 1;
    }
}

int maat_get_table_id(struct maat *maat_inst, const char *table_name)
{
    int table_id = -1;

    struct table_manager *table_mgr = maat_inst->tbl_mgr;
    table_id = table_manager_get_table_id(table_mgr, table_name);
    
    return table_id;
}

static inline void maat_runtime_ref_inc(struct maat_runtime *maat_rt,
                                        int thread_id)
{
    if (NULL == maat_rt) {
        return;
    }

	alignment_int64_array_add(maat_rt->ref_cnt, thread_id, 1);
}

static inline void maat_runtime_ref_dec(struct maat_runtime *maat_rt,
                                        int thread_id)
{
    if (NULL == maat_rt) {
        return;
    }

	alignment_int64_array_add(maat_rt->ref_cnt, thread_id, -1);
}

/* must be plugin table */
int maat_table_callback_register(struct maat *maat_inst, int table_id,
								 maat_start_callback_t *start,
								 maat_update_callback_t *update,
								 maat_finish_callback_t *finish,
								 void *u_para)
{
    int ret = -1;

    pthread_mutex_lock(&(maat_inst->background_update_mutex));
    void *schema = table_manager_get_schema(maat_inst->tbl_mgr, table_id);
    if (NULL == schema) {
        pthread_mutex_unlock(&(maat_inst->background_update_mutex));
        log_error(maat_inst->logger, MODULE_MAAT_API,
                  "[%s:%d] table(table_id:%d) schema is NULL, register callback failed",
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    ret = plugin_table_add_callback(schema, table_id, start, update, finish, 
                                    u_para, maat_inst->logger);
    if (ret < 0) {
        pthread_mutex_unlock(&(maat_inst->background_update_mutex));
        return -1;
    }

    if (!maat_inst->maat_rt) {
        pthread_mutex_unlock(&(maat_inst->background_update_mutex));
        return 0;
    }

    void *runtime = table_manager_get_runtime(maat_inst->tbl_mgr, table_id);

    enum table_type table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_PLUGIN) {
        pthread_mutex_unlock(&(maat_inst->background_update_mutex));
        log_error(maat_inst->logger, MODULE_MAAT_API, 
                  "[%s:%d] table type:%d illegal", __FUNCTION__, __LINE__, table_type);
        return -1;
    }

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

    pthread_mutex_unlock(&(maat_inst->background_update_mutex));

    return 0;
}

static int compile_table_ex_schema_register(struct maat *maat_inst, int table_id,
                                            maat_ex_new_func_t *new_func,
                                            maat_ex_free_func_t *free_func,
                                            maat_ex_dup_func_t *dup_func,
                                            long argl, void *argp)
{
    void *schema = table_manager_get_schema(maat_inst->tbl_mgr, table_id);
    assert(schema != NULL);

    int ret = compile_table_set_ex_data_schema((struct compile_schema *)schema, table_id,
                                                new_func, free_func, dup_func, 
                                                argl, argp);
    if (ret < 0) {
        return -1;
    }

    if (maat_inst->maat_rt != NULL) {
        void *runtime = table_manager_get_runtime(maat_inst->tbl_mgr, table_id);
        assert(runtime != NULL);
        compile_runtime_ex_data_iterate((struct compile_runtime *)runtime,
                                        (struct compile_schema *)schema);
    }

    return 0;    
}

static int generic_plugin_table_set_ex_schema(struct table_manager *tbl_mgr, int table_id,
									          maat_ex_new_func_t *new_func,
									          maat_ex_free_func_t *free_func,
									          maat_ex_dup_func_t *dup_func,
									          long argl, void *argp,
                                              struct log_handle *logger)
{
    void *schema = table_manager_get_schema(tbl_mgr, table_id);
    if (NULL == schema) {
        log_error(logger, MODULE_MAAT_API, 
                  "[%s:%d], table(table_id:%d) is not registered, can't "
                  "register ex_container_schema", __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    int ret = -1;
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            ret = plugin_table_set_ex_container_schema(schema, table_id,
                                                       new_func, free_func, dup_func,
                                                       free, argl, argp);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ret = ip_plugin_table_set_ex_container_schema(schema, table_id,
                                                          new_func, free_func, dup_func,
                                                          free, argl, argp);
            break;
        case TABLE_TYPE_FQDN_PLUGIN:
            ret = fqdn_plugin_table_set_ex_container_schema(schema, table_id,
                                                            new_func, free_func, dup_func,
                                                            (void (*)(void *))fqdn_rule_free,
                                                            argl, argp);
            break;
        case TABLE_TYPE_BOOL_PLUGIN:
            ret = bool_plugin_table_set_ex_container_schema(schema, table_id,
                                                            new_func, free_func, dup_func,
                                                            free, argl, argp);
            break;
        default:
            log_error(logger, MODULE_MAAT_API,
                      "[%s:%d], table(table_id:%d) is not plugin table, can't set ex schema",
                      __FUNCTION__, __LINE__, table_id);
            return -1;
    }

    return ret;
}

static void plugin_runtime_commit_ex_schema(void *runtime, void *schema,
                                            const char *table_name,
                                            int valid_column)
{
    struct ex_container_schema *container_schema = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    container_schema = plugin_table_get_ex_container_schema(schema);
    ex_data_rt = plugin_runtime_get_ex_data_rt(runtime);
    ex_data_runtime_set_ex_container_schema(ex_data_rt, container_schema);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const char *row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        plugin_runtime_update(runtime, schema, table_name, row, valid_column);
    }

    ex_data_runtime_clear_row_cache(ex_data_rt);
    plugin_runtime_commit(runtime, table_name, 0);
}

static void ip_plugin_runtime_commit_ex_schema(void *runtime, void *schema,
                                               const char *table_name,
                                               int valid_column)
{
    struct ex_container_schema *container_schema = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    container_schema = ip_plugin_table_get_ex_container_schema(schema);
    ex_data_rt = ip_plugin_runtime_get_ex_data_rt(runtime);
    ex_data_runtime_set_ex_container_schema(ex_data_rt, container_schema);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const char *row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        ip_plugin_runtime_update(runtime, schema, table_name, row, valid_column);
    }

    ex_data_runtime_clear_row_cache(ex_data_rt);
    ip_plugin_runtime_commit(runtime, table_name, 0);
}

static void fqdn_plugin_runtime_commit_ex_schema(void *runtime, void *schema,
                                                 const char *table_name,
                                                 int valid_column)
{
    struct ex_container_schema *container_schema = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    container_schema = fqdn_plugin_table_get_ex_container_schema(schema);
    ex_data_rt = fqdn_plugin_runtime_get_ex_data_rt(runtime);
    ex_data_runtime_set_ex_container_schema(ex_data_rt, container_schema);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const char *row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        fqdn_plugin_runtime_update(runtime, schema, table_name, row, valid_column);
    }

    ex_data_runtime_clear_row_cache(ex_data_rt);
    fqdn_plugin_runtime_commit(runtime, table_name, 0);
}

static void bool_plugin_runtime_commit_ex_schema(void *runtime, void *schema,
                                                 const char *table_name,
                                                 int valid_column)
{
    struct ex_container_schema *container_schema = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    container_schema = bool_plugin_table_get_ex_container_schema(schema);
    ex_data_rt = bool_plugin_runtime_get_ex_data_rt(runtime);
    ex_data_runtime_set_ex_container_schema(ex_data_rt, container_schema);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const char *row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        bool_plugin_runtime_update(runtime, schema, table_name, row, valid_column);
    }

    ex_data_runtime_clear_row_cache(ex_data_rt);
    bool_plugin_runtime_commit(runtime, table_name, 0);
}

static int generic_plugin_runtime_commit_ex_schema(void *runtime, void *schema,
                                                   const char *table_name,
                                                   enum table_type table_type,
                                                   int valid_column,
                                                   struct log_handle *logger)
{
    if (NULL == runtime || NULL == schema || valid_column < 0) {
        log_error(logger, MODULE_MAAT_API, 
                 "[%s:%d] input parameter invalid, runtime:%p, schema:%p, valid_column:%d",
                 __FUNCTION__, __LINE__, runtime, schema, valid_column);
        return -1;
    }

    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            plugin_runtime_commit_ex_schema(runtime, schema, table_name, valid_column);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ip_plugin_runtime_commit_ex_schema(runtime, schema, table_name, valid_column);
            break;
        case TABLE_TYPE_FQDN_PLUGIN:
            fqdn_plugin_runtime_commit_ex_schema(runtime, schema, table_name, valid_column);
            break;
        case TABLE_TYPE_BOOL_PLUGIN:
            bool_plugin_runtime_commit_ex_schema(runtime, schema, table_name, valid_column);
            break;
        default:
            log_error(logger, MODULE_MAAT_API, 
                      "[%s:%d] table_type:%d invalid", __FUNCTION__, __LINE__, table_type);
            return -1;
    }

    return 0;
}

static int generic_plugin_table_ex_schema_register(struct maat *maat_inst, 
                                                   const char *table_name, int table_id,
									               maat_ex_new_func_t *new_func,
									               maat_ex_free_func_t *free_func,
									               maat_ex_dup_func_t *dup_func,
									               long argl, void *argp)
{
    int ret = generic_plugin_table_set_ex_schema(maat_inst->tbl_mgr, table_id, 
                                                 new_func, free_func, dup_func,
                                                 argl, argp, maat_inst->logger);
    if (ret < 0) {
        return -1;
    }
    
    enum table_type table_type = TABLE_TYPE_INVALID;
    int valid_column = -1;
    if (maat_inst->maat_rt != NULL) {
        void *runtime = table_manager_get_runtime(maat_inst->tbl_mgr, table_id);
        void *schema = table_manager_get_schema(maat_inst->tbl_mgr, table_id);
        assert(runtime != NULL && schema != NULL);

        table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
        valid_column = table_manager_get_valid_column(maat_inst->tbl_mgr, table_id);
        if (table_type == TABLE_TYPE_INVALID || valid_column < 0) {
            log_error(maat_inst->logger, MODULE_MAAT_API, 
                      "[%s:%d] table_type:%d or valid_column:%d invalid",
                      __FUNCTION__, __LINE__, table_type, valid_column);
            return -1;
        }

        ret = generic_plugin_runtime_commit_ex_schema(runtime, schema, table_name, 
                                                      table_type, valid_column,
                                                      maat_inst->logger);
    }

    return ret;
}

int maat_plugin_table_ex_schema_register(struct maat *maat_inst, 
                                         const char *table_name,
                                         maat_ex_new_func_t *new_func,
                                         maat_ex_free_func_t *free_func,
                                         maat_ex_dup_func_t *dup_func,
                                         long argl, void *argp)
{
    if (NULL == maat_inst || NULL == table_name) {
        log_error(maat_inst->logger, MODULE_MAAT_API,
                  "[%s:%d] [table:%s] ex_schema register input parameter is invalid.",
                  __FUNCTION__, __LINE__, table_name);
        return -1;
    }

    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        log_error(maat_inst->logger, MODULE_MAAT_API,
                  "[%s:%d] [table:%s] is not registered before.",
                  __FUNCTION__, __LINE__, table_name);
        return -1;
    }

    pthread_mutex_lock(&(maat_inst->background_update_mutex));

    int ret = -1;
    enum table_type table_type = table_manager_get_table_type(maat_inst->tbl_mgr,
                                                              table_id);
    if (TABLE_TYPE_COMPILE == table_type) {
        ret = compile_table_ex_schema_register(maat_inst, table_id, new_func,
                                               free_func, dup_func, argl, argp);
    } else {
        ret = generic_plugin_table_ex_schema_register(maat_inst, table_name,
                                                      table_id, new_func, free_func,
                                                      dup_func, argl, argp);
    }

    pthread_mutex_unlock(&(maat_inst->background_update_mutex));
    return ret;
}

void *maat_plugin_table_get_ex_data(struct maat *maat_inst, int table_id,
                                    const char *key, size_t key_len)
{

    if (NULL == maat_inst || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || NULL == key) {
        return NULL;
    }
    
    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return NULL;
    }

    void *runtime = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == runtime) {
        return NULL;
    }

    void *schema = table_manager_get_schema(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == schema) {
        return NULL;
    }

    void *ret = NULL;
    enum table_type table_type = table_manager_get_table_type(maat_inst->tbl_mgr,
                                                              table_id);
    if (TABLE_TYPE_COMPILE == table_type) {
        ret = compile_runtime_get_ex_data(runtime, schema, *(long long *)key);
    } else if (TABLE_TYPE_PLUGIN == table_type) {
        ret = plugin_runtime_get_ex_data(runtime, schema, key, key_len);
    } else {
        return NULL;
    }

    return ret;
}

int maat_ip_plugin_table_get_ex_data(struct maat *maat_inst, int table_id,
                                     const struct ip_addr *ip_addr,
                                     void **ex_data_array, size_t n_ex_data)
{
    if (NULL == maat_inst || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || NULL == ip_addr || NULL == ex_data_array || 0 == n_ex_data) {
        return -1;
    }
    
    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return -1;
    }

    void *ip_plugin_rt = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == ip_plugin_rt) {
        return -1;
    }

    int n_hit_ex_data = ip_plugin_runtime_get_ex_data(ip_plugin_rt, ip_addr, 
                                                      ex_data_array, n_ex_data);
    if (n_hit_ex_data < 0) {
        return -1;
    }

    return n_hit_ex_data;
}

int maat_fqdn_plugin_table_get_ex_data(struct maat *maat_inst, int table_id,
                                       const char *fqdn, void **ex_data_array, 
                                       size_t n_ex_data)
{
    if (NULL == maat_inst || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || NULL == fqdn || NULL == ex_data_array || 0 == n_ex_data) {
        return -1;
    }

    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return -1;
    }

    void *fqdn_plugin_rt = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == fqdn_plugin_rt) {
        return -1;
    }

    int n_hit_ex_data = fqdn_plugin_runtime_get_ex_data(fqdn_plugin_rt, fqdn,
                                                        ex_data_array, n_ex_data);
    if (n_hit_ex_data < 0) {
        return -1;
    }

    return n_hit_ex_data;
}

int maat_bool_plugin_table_get_ex_data(struct maat *maat_inst, int table_id,
                                       unsigned long long *item_ids, size_t n_item,
                                       void **ex_data_array, size_t n_ex_data)
{
    if (NULL == maat_inst || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || NULL == item_ids || NULL == ex_data_array || 0 == n_ex_data) {
        return -1;
    }
    
    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return -1;
    }

    void *bool_plugin_rt = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == bool_plugin_rt) {
        return -1;
    }

    int n_hit_ex_data = bool_plugin_runtime_get_ex_data(bool_plugin_rt, item_ids, n_item,
                                                        ex_data_array, n_ex_data);
    if (n_hit_ex_data < 0) {
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

static size_t hit_group_to_compile(void *compile_runtime, long long *compile_ids,
                                   size_t compile_ids_size, struct maat_state *state)
{
    size_t n_hit_compile = compile_runtime_match((struct compile_runtime *)compile_runtime,
                                                 compile_ids, compile_ids_size, state);
    return n_hit_compile;
}

static int flag_scan(struct table_manager *tbl_mgr, int thread_id, long long flag,
                     int phy_table_id, int vtable_id, struct maat_state *state)
{
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, phy_table_id);
    if (table_type == TABLE_TYPE_FLAG_PLUS && 
        DISTRICT_FLAG_UNSET == state->is_set_district) {
        return -1;
    }

    if (table_type != TABLE_TYPE_FLAG && table_type != TABLE_TYPE_FLAG_PLUS) {
        return -1;
    }

    void *flag_rt = table_manager_get_runtime(tbl_mgr, phy_table_id);
    if (NULL == flag_rt) {
        return -1;
    }

    int group_hit_cnt = flag_runtime_scan((struct flag_runtime *)flag_rt, thread_id,
                                          flag, vtable_id, state);
    if (group_hit_cnt <= 0) {
        return group_hit_cnt;
    }

    flag_runtime_hit_inc((struct flag_runtime *)flag_rt, thread_id);

    return group_hit_cnt;
}

static int interval_scan(struct table_manager *tbl_mgr, int thread_id, long long integer,
                         int phy_table_id, int vtable_id, struct maat_state *state)
{

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, phy_table_id);
    if (table_type == TABLE_TYPE_INTERVAL_PLUS && 
        DISTRICT_FLAG_UNSET == state->is_set_district) {
        return -1;
    }

    if (table_type != TABLE_TYPE_INTERVAL && table_type != TABLE_TYPE_INTERVAL_PLUS) {
        return -1;
    }

    void *interval_rt = table_manager_get_runtime(tbl_mgr, phy_table_id);
    if (NULL == interval_rt) {
        return -1;
    }

    int group_hit_cnt = interval_runtime_scan((struct interval_runtime *)interval_rt,
                                              thread_id, integer, vtable_id, state);
    if (group_hit_cnt <= 0) {
        return group_hit_cnt;
    }

    interval_runtime_hit_inc((struct interval_runtime *)interval_rt, thread_id);

    return group_hit_cnt;
}

static int ipv4_scan(struct table_manager *tbl_mgr, int thread_id, uint32_t ip_addr,
                     uint16_t port, int proto, int phy_table_id, int vtable_id, 
                     struct maat_state *state)
{

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, phy_table_id);
    if (table_type != TABLE_TYPE_IP_PLUS) {
        return -1;
    }

    void *ip_rt = table_manager_get_runtime(tbl_mgr, phy_table_id);
    if (NULL == ip_rt) {
        return -1;
    }

    int group_hit_cnt = ip_runtime_scan((struct ip_runtime *)ip_rt, thread_id, IPv4,
                                        (uint8_t *)&ip_addr, port, proto, vtable_id, 
                                        state);
    if (group_hit_cnt <= 0) {
        return group_hit_cnt;
    }

    ip_runtime_hit_inc((struct ip_runtime *)ip_rt, thread_id);
    
    return group_hit_cnt;
}

static int ipv6_scan(struct table_manager *tbl_mgr, int thread_id,
                     uint8_t *ip_addr, uint16_t port, int proto, 
                     int phy_table_id, int vtable_id, struct maat_state *state)
{

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, phy_table_id);
    if (table_type != TABLE_TYPE_IP_PLUS) {
        return -1;
    }

    void *ip_rt = table_manager_get_runtime(tbl_mgr, phy_table_id);
    if (NULL == ip_rt) {
        return -1;
    }

    int group_hit_cnt = ip_runtime_scan((struct ip_runtime *)ip_rt, thread_id, IPv6,
                                        ip_addr, port, proto, vtable_id, state);
    if (group_hit_cnt <= 0) {
        return group_hit_cnt;
    }

    ip_runtime_hit_inc((struct ip_runtime *)ip_rt, thread_id);
    
    return group_hit_cnt;
}

static int string_scan(struct table_manager *tbl_mgr, int thread_id,
                       const char *data, size_t data_len, int phy_table_id,
                       int vtable_id, struct maat_state *state)
{
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, phy_table_id);
    if (table_type == TABLE_TYPE_EXPR_PLUS && 
        DISTRICT_FLAG_UNSET == state->is_set_district) {
        return -1;
    }

    if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
        return -1;
    }

    void *expr_rt = table_manager_get_runtime(tbl_mgr, phy_table_id);
    if (NULL == expr_rt) {
        return -1;
    }

    int group_hit_cnt = expr_runtime_scan((struct expr_runtime *)expr_rt,
                                          thread_id, data, data_len,
                                          vtable_id, state);
    if (group_hit_cnt <= 0) {
        return group_hit_cnt;
    }

    expr_runtime_hit_inc((struct expr_runtime *)expr_rt, thread_id);

    return group_hit_cnt;
}

static int expr_stream_scan(struct maat_stream *stream, const char *data,
                            size_t data_len, struct maat_state *state)
{
    if (NULL == stream || NULL == data) {
        return 0;
    }

    enum table_type table_type = TABLE_TYPE_INVALID;
    struct table_manager *tbl_mgr = stream->ref_maat_inst->tbl_mgr;
    table_type = table_manager_get_table_type(tbl_mgr, stream->phy_table_id);
    if (table_type == TABLE_TYPE_EXPR_PLUS && 
        DISTRICT_FLAG_UNSET == state->is_set_district) {
        return -1;
    }

    if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
        return -1;
    }

    void *expr_rt = table_manager_get_runtime(tbl_mgr, stream->phy_table_id);
    if (NULL == expr_rt) {
        return -1;
    }

    int group_hit_cnt = expr_runtime_stream_scan((struct expr_runtime *)expr_rt,
                                                 stream->handle, data, data_len,
                                                 stream->vtable_id, state);
    if (group_hit_cnt <= 0) {
        return group_hit_cnt;
    }

    expr_runtime_hit_inc((struct expr_runtime *)expr_rt, stream->thread_id);

    return group_hit_cnt;
}

static size_t group_to_compile(struct maat *maat_inst, long long *results,
                               size_t n_result, struct maat_state *state)
{
    int compile_table_id = table_manager_get_default_compile_table_id(maat_inst->tbl_mgr);

    if (state->compile_table_id > 0) {
        compile_table_id = state->compile_table_id;
    } 

    void *compile_rt = table_manager_get_runtime(maat_inst->tbl_mgr, compile_table_id);
    if (NULL == compile_rt) {
        return 0;
    }

    size_t n_hit_compile = hit_group_to_compile(compile_rt, results, n_result, state);

    assert(state->is_last_scan < LAST_SCAN_FINISHED);
    if (LAST_SCAN_SET == state->is_last_scan) {
        state->is_last_scan = LAST_SCAN_FINISHED;
    }

    return n_hit_compile;
}

int maat_scan_flag(struct maat *maat_inst, int table_id,
                   long long flag, long long *results, size_t n_result,
                   size_t *n_hit_result, struct maat_state *state)
{
    if ((NULL == maat_inst) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (NULL == results) || (0 == n_result) || (NULL == state) ||
        (state->thread_id < 0)) {
        return MAAT_SCAN_ERR;
    }

    struct timespec start, end;
    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->scan_cnt++;

    if (NULL == maat_inst->maat_rt) {
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int phy_table_id = table_id;
    enum table_type table_type = TABLE_TYPE_INVALID;

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        phy_table_id = vtable_get_physical_table_id(maat_inst->tbl_mgr, table_id);
        vtable_id = table_id;
    }
    
    if (phy_table_id < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, phy_table_id);
    if (table_type != TABLE_TYPE_FLAG && table_type != TABLE_TYPE_FLAG_PLUS) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);
    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);

    int hit_group_cnt = flag_scan(maat_inst->tbl_mgr, state->thread_id, flag,
                                  phy_table_id, vtable_id, state);
    if (hit_group_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        sum_hit_compile_cnt = group_to_compile(maat_inst, results, n_result, state);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(maat_inst->stat->hit_cnt, state->thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(maat_inst->stat->not_grp_hit_cnt,
                                       state->thread_id, 1);
        }
    }

    void *flag_rt = table_manager_get_runtime(maat_inst->tbl_mgr, phy_table_id);
    assert(flag_rt != NULL);

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        flag_runtime_perf_stat(flag_rt, &start, &end, state->thread_id);
    } else {
        flag_runtime_perf_stat(flag_rt, NULL, NULL, state->thread_id);
    }

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    if (sum_hit_compile_cnt > 0) {
        return MAAT_SCAN_HIT;
    } else if (hit_group_cnt > 0) {
        return MAAT_SCAN_HALF_HIT;
    } else {
        return MAAT_SCAN_OK;
    }
}

int maat_scan_integer(struct maat *maat_inst, int table_id,
                      long long integer, long long *results, size_t n_result,
                      size_t *n_hit_result, struct maat_state *state)
{
    if ((NULL == maat_inst) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (NULL == results) || (0 == n_result) || (NULL == state) ||
        (state->thread_id < 0)) {
        return MAAT_SCAN_ERR;
    }
    
    struct timespec start, end;
    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->scan_cnt++;

    if (NULL == maat_inst->maat_rt) {
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int phy_table_id = table_id;
    enum table_type table_type = TABLE_TYPE_INVALID;

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        phy_table_id = vtable_get_physical_table_id(maat_inst->tbl_mgr, table_id);
        vtable_id = table_id;
    }
    
    if (phy_table_id < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, phy_table_id);
    if (table_type != TABLE_TYPE_INTERVAL && table_type != TABLE_TYPE_INTERVAL_PLUS) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);
    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);

    int hit_group_cnt = interval_scan(maat_inst->tbl_mgr, state->thread_id, integer,
                                      phy_table_id, vtable_id, state);
    if (hit_group_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }
    
    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        sum_hit_compile_cnt = group_to_compile(maat_inst, results, n_result, state);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(maat_inst->stat->hit_cnt, state->thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(maat_inst->stat->not_grp_hit_cnt,
                                       state->thread_id, 1);
        }
    }

    void *interval_rt = table_manager_get_runtime(maat_inst->tbl_mgr, phy_table_id);
    assert(interval_rt != NULL);

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        interval_runtime_perf_stat(interval_rt, &start, &end, state->thread_id);
    } else {
        interval_runtime_perf_stat(interval_rt, NULL, NULL, state->thread_id);
    }

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    if (sum_hit_compile_cnt > 0) {
        return MAAT_SCAN_HIT;
    } else if (hit_group_cnt > 0) {
        return MAAT_SCAN_HALF_HIT;
    } else {
        return MAAT_SCAN_OK;
    }
}

int maat_scan_ipv4(struct maat *maat_inst, int table_id, uint32_t ip_addr,
                   uint16_t port, int protocol, long long *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state *state)
{
    if ((NULL == maat_inst) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (protocol < -1) || (NULL == results) || (0 == n_result) 
        || (NULL == state) || (state->thread_id < 0)) {
        return MAAT_SCAN_ERR;
    }

    struct timespec start, end;
    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->scan_cnt++;

    if (NULL == maat_inst->maat_rt) {
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int phy_table_id = table_id;
    enum table_type table_type = TABLE_TYPE_INVALID;

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        phy_table_id = vtable_get_physical_table_id(maat_inst->tbl_mgr, table_id);
        vtable_id = table_id;
    }
    
    if (phy_table_id < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, phy_table_id);
    if (table_type != TABLE_TYPE_IP_PLUS) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);
    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);

    int hit_group_cnt = ipv4_scan(maat_inst->tbl_mgr, state->thread_id, ip_addr,
                                  port, protocol, phy_table_id, vtable_id, state);
    if (hit_group_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }
    
    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        sum_hit_compile_cnt = group_to_compile(maat_inst, results, n_result, state);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(maat_inst->stat->hit_cnt, state->thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(maat_inst->stat->not_grp_hit_cnt,
                                       state->thread_id, 1);
        }
    }

    void *ip_rt = table_manager_get_runtime(maat_inst->tbl_mgr, phy_table_id);
    assert(ip_rt != NULL);

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        ip_runtime_perf_stat(ip_rt, &start, &end, state->thread_id);
    } else {
        ip_runtime_perf_stat(ip_rt, NULL, NULL, state->thread_id);
    }

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    if (sum_hit_compile_cnt > 0) {
        return MAAT_SCAN_HIT;
    } else if (hit_group_cnt > 0) {
        return MAAT_SCAN_HALF_HIT;
    } else {
        return MAAT_SCAN_OK;
    }
}

int maat_scan_ipv6(struct maat *maat_inst, int table_id,
                   uint8_t *ip_addr, uint16_t port, int protocol,
                   long long *results, size_t n_result, 
                   size_t *n_hit_result, struct maat_state *state)
{
    if ((NULL == maat_inst) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (protocol < -1) || (NULL == ip_addr) || (NULL == results) 
        || (0 == n_result) || (NULL == state) || (state->thread_id < 0)) {
        return MAAT_SCAN_ERR;
    }

    struct timespec start, end;
    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->scan_cnt++;

    if (NULL == maat_inst->maat_rt) {
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int phy_table_id = table_id;
    enum table_type table_type = TABLE_TYPE_INVALID;

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        phy_table_id = vtable_get_physical_table_id(maat_inst->tbl_mgr, table_id);
        vtable_id = table_id;
    }
    
    if (phy_table_id < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, phy_table_id);
    if (table_type != TABLE_TYPE_IP_PLUS) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);
    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);

    int hit_group_cnt = ipv6_scan(maat_inst->tbl_mgr, state->thread_id, ip_addr,
                                  port, protocol, phy_table_id, vtable_id, state);
    if (hit_group_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        sum_hit_compile_cnt = group_to_compile(maat_inst, results, n_result, state);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(maat_inst->stat->hit_cnt, state->thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(maat_inst->stat->not_grp_hit_cnt,
                                       state->thread_id, 1);
        }
    }

    void *ip_rt = table_manager_get_runtime(maat_inst->tbl_mgr, phy_table_id);
    assert(ip_rt != NULL);

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        ip_runtime_perf_stat(ip_rt, &start, &end, state->thread_id);
    } else {
        ip_runtime_perf_stat(ip_rt, NULL, NULL, state->thread_id);
    }

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    if (sum_hit_compile_cnt > 0) {
        return MAAT_SCAN_HIT;
    } else if (hit_group_cnt > 0) {
        return MAAT_SCAN_HALF_HIT;
    } else {
        return MAAT_SCAN_OK;
    }
}

int maat_scan_string(struct maat *maat_inst, int table_id, const char *data, 
                     size_t data_len, long long *results, size_t n_result,
                     size_t *n_hit_result, struct maat_state *state)
{
    if ((NULL == maat_inst) || table_id < 0 || table_id >= MAX_TABLE_NUM 
        || (NULL == data) || (0 == data_len) || (NULL == results) 
        || (0 == n_result) || (NULL == state) || (state->thread_id < 0)) {
        return MAAT_SCAN_ERR;
    }
    
    struct timespec start, end;
    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->scan_cnt++;

    if (NULL == maat_inst->maat_rt) {
        return MAAT_SCAN_OK;
    }

    int vtable_id = 0;
    int phy_table_id = table_id;
    enum table_type table_type = TABLE_TYPE_INVALID;
    
    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        phy_table_id = vtable_get_physical_table_id(maat_inst->tbl_mgr, table_id);
        vtable_id = table_id;
    }
    
    if (phy_table_id < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, phy_table_id);
    if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);
    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);

    int hit_group_cnt = string_scan(maat_inst->tbl_mgr, state->thread_id, data,
                                    data_len, phy_table_id, vtable_id, state);
    if (hit_group_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        sum_hit_compile_cnt = group_to_compile(maat_inst, results, n_result, state);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(maat_inst->stat->hit_cnt, state->thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(maat_inst->stat->not_grp_hit_cnt,
                                       state->thread_id, 1);
        }
    }

    void *expr_rt = table_manager_get_runtime(maat_inst->tbl_mgr, phy_table_id);
    assert(expr_rt != NULL);

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        expr_runtime_perf_stat(expr_rt, data_len, &start, &end, state->thread_id);
    } else {
        expr_runtime_perf_stat(expr_rt, data_len, NULL, NULL, state->thread_id);
    }

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    if (sum_hit_compile_cnt > 0) {
        return MAAT_SCAN_HIT;
    } else if (hit_group_cnt > 0) {
        return MAAT_SCAN_HALF_HIT;
    } else {
        return MAAT_SCAN_OK;
    }
}

struct maat_stream *maat_stream_new(struct maat *maat_inst, int table_id, 
                                    struct maat_state *state)
{
    if (NULL == maat_inst || table_id < 0 || table_id > MAX_TABLE_NUM
        || NULL == state || state->thread_id < 0) {
        return NULL;
    }

    struct maat_stream *stream = ALLOC(struct maat_stream, 1);
    stream->ref_maat_inst = maat_inst;
    stream->last_full_version = maat_inst->last_full_version;
    stream->thread_id = state->thread_id;
    stream->phy_table_id = table_id;
    stream->logger = maat_inst->logger;

    enum table_type table_type = TABLE_TYPE_INVALID;

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_VIRTUAL) {
        stream->phy_table_id = vtable_get_physical_table_id(maat_inst->tbl_mgr, table_id);
        stream->vtable_id = table_id;
    }
    
    if (stream->phy_table_id < 0) {
        return NULL;
    }

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, stream->phy_table_id);
    if (table_type != TABLE_TYPE_EXPR && table_type != TABLE_TYPE_EXPR_PLUS) {
        return NULL;
    }

    void *expr_rt = table_manager_get_runtime(stream->ref_maat_inst->tbl_mgr,
                                              stream->phy_table_id);
    assert(expr_rt != NULL);
    stream->expr_rt_version = expr_runtime_get_version(expr_rt);

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);
    struct adapter_hs_stream *handle = expr_runtime_stream_open((struct expr_runtime *)expr_rt, 
                                                                state->thread_id);
    if (NULL == handle) {
        goto error;
    }
    stream->handle = handle;

    return stream;

error:
    FREE(stream);
    return NULL;
}

int maat_stream_scan(struct maat_stream *maat_stream, const char *data, int data_len, 
                     long long *results, size_t n_result, size_t *n_hit_result,
                     struct maat_state *state)
{
    if ((NULL == maat_stream) || (NULL == data) || (0 == data_len) 
        || (NULL == results) || (0 == n_result) || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }

    struct timespec start, end;
    if (1 == maat_stream->ref_maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->scan_cnt++;

    struct maat *maat_inst = maat_stream->ref_maat_inst;
    if (maat_stream->last_full_version != maat_inst->last_full_version) {
        return MAAT_SCAN_OK;
    }

    void *expr_rt = table_manager_get_runtime(maat_inst->tbl_mgr,
                                              maat_stream->phy_table_id);
    assert(expr_rt != NULL);
    
    long long cur_expr_rt_version = expr_runtime_get_version(expr_rt);
    if (maat_stream->expr_rt_version != cur_expr_rt_version) {
        return MAAT_SCAN_OK;
    }

    alignment_int64_array_add(maat_inst->stat->thread_call_cnt,
                              maat_stream->thread_id, 1);

    int hit_group_cnt = expr_stream_scan(maat_stream, data, data_len, state);
    if (hit_group_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    size_t sum_hit_compile_cnt = 0;
    if (hit_group_cnt > 0 || scan_status_should_compile_NOT(state)) {
        sum_hit_compile_cnt = group_to_compile(maat_inst, results, n_result, state);
        *n_hit_result = sum_hit_compile_cnt;
    }

    if (sum_hit_compile_cnt > 0) {
        alignment_int64_array_add(maat_inst->stat->hit_cnt, maat_stream->thread_id, 1);
        if (0 == hit_group_cnt) {
            //hit NOT group
             alignment_int64_array_add(maat_inst->stat->not_grp_hit_cnt,
                                       maat_stream->thread_id, 1);
        }
    }  

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        expr_runtime_perf_stat(expr_rt, data_len, &start, &end, state->thread_id);
    } else {
        expr_runtime_perf_stat(expr_rt, data_len, NULL, NULL, state->thread_id);
    }

     if (sum_hit_compile_cnt > 0) {
        return MAAT_SCAN_HIT;
    } else if (hit_group_cnt > 0) {
        return MAAT_SCAN_HALF_HIT;
    } else {
        return MAAT_SCAN_OK;
    }
}

void maat_stream_free(struct maat_stream *maat_stream)
{
    if (NULL == maat_stream) {
        return;
    }

    struct maat *maat_inst = maat_stream->ref_maat_inst;
    void *expr_rt = table_manager_get_runtime(maat_inst->tbl_mgr, 
                                              maat_stream->phy_table_id);
    assert(expr_rt != NULL);

    long long cur_expr_rt_version = expr_runtime_get_version(expr_rt);
    if ((maat_stream->last_full_version == maat_inst->last_full_version) && 
        (maat_stream->expr_rt_version == cur_expr_rt_version)) {
        maat_runtime_ref_dec(maat_inst->maat_rt, maat_stream->thread_id);
    } else {
        maat_inst->stat->zombie_rs_stream--;
    }

    expr_runtime_stream_close(expr_rt, maat_stream->thread_id, maat_stream->handle);
    FREE(maat_stream);
}

struct maat_state *maat_state_new(struct maat *maat_inst, int thread_id)
{
    if (NULL == maat_inst || thread_id < 0) {
        return NULL;
    }

    struct maat_state *state = ALLOC(struct maat_state, 1);

    state->maat_inst = maat_inst;
    state->is_set_district = DISTRICT_FLAG_UNSET;
    state->is_last_scan = LAST_SCAN_UNSET;
    state->district_id = DISTRICT_ANY;
    state->thread_id = thread_id;

    //state->compile_state no need to alloc memory at this point, but alloc it after hitting items
    alignment_int64_array_add(maat_inst->stat->maat_state_cnt, thread_id, 1);

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

    if (state->compile_state != NULL) {
        maat_compile_state_reset(state->compile_state);
    }
}

void maat_state_free(struct maat_state *state)
{
    if (NULL == state) {
        return;
    }

    assert(state->maat_inst != NULL);
    
    struct maat *maat_inst = state->maat_inst;
    long long thread_id = state->thread_id;

    if (state->compile_state != NULL) {
        maat_compile_state_free(state->compile_state, maat_inst, thread_id);
        state->compile_state = NULL;
        alignment_int64_array_add(maat_inst->stat->maat_compile_state_cnt,
                                  thread_id, -1);
    }
    
    state->maat_inst = NULL;
    FREE(state);
    
    alignment_int64_array_add(maat_inst->stat->maat_state_cnt,
                              thread_id, -1);
    alignment_int64_array_add(maat_inst->stat->maat_state_free_cnt,
                              thread_id, 1);
    alignment_int64_array_add(maat_inst->stat->maat_state_free_bytes,
                              thread_id, sizeof(struct maat_state));
}

int maat_state_set_scan_district(struct maat_state *state, int table_id, 
                                 const char *district, size_t district_len)
{
    if (NULL == state || NULL == district || 0 == district_len) {
        return -1;
    }

    struct maat *maat_inst = state->maat_inst;
    assert(maat_inst != NULL);

    if (NULL == maat_inst->maat_rt) {
        log_error(maat_inst->logger, MODULE_MAAT_API, 
                  "maat runtime is NULL, can't set district");
        return -1;
    }

    enum table_type table_type = TABLE_TYPE_INVALID;
    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_FLAG_PLUS && table_type != TABLE_TYPE_EXPR_PLUS &&
        table_type != TABLE_TYPE_INTERVAL_PLUS && table_type != TABLE_TYPE_VIRTUAL) {
        log_error(maat_inst->logger, MODULE_MAAT_API, 
                 "table_type:%d is invalid, can't set district", table_type);
        return -1;
    }

    int phy_table_id = table_id;
    if (table_type == TABLE_TYPE_VIRTUAL) {
        phy_table_id = vtable_get_physical_table_id(maat_inst->tbl_mgr, table_id);
    }

    int ret = -1;
    long long district_id;

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, phy_table_id);
    void *runtime = table_manager_get_runtime(maat_inst->tbl_mgr, phy_table_id);
    assert(runtime != NULL);
    
    switch (table_type) {
        case TABLE_TYPE_FLAG_PLUS:
            ret = flag_runtime_set_scan_district((struct flag_runtime *)runtime,
                                                 district, district_len, &district_id);
            break;
        case TABLE_TYPE_EXPR_PLUS:
            ret = expr_runtime_set_scan_district((struct expr_runtime *)runtime,
                                                 district, district_len, &district_id);
            break;
        case TABLE_TYPE_INTERVAL_PLUS:
            ret = interval_runtime_set_scan_district((struct interval_runtime *)runtime,
                                                     district, district_len, &district_id);
            break;
        default:
            log_error(maat_inst->logger, MODULE_MAAT_API, 
                      "[%s:%d] table_type:%d can't set district", 
                      __FUNCTION__, __LINE__, table_type);
            break;
    }

    if (ret < 0) {
        state->district_id = DISTRICT_UNKNOWN;
    } else {
        state->district_id = (int)district_id;
    }

    state->is_set_district = DISTRICT_FLAG_SET;

    return 0;
}

int maat_state_set_last_scan(struct maat_state *state)
{
    if (NULL == state) {
        return -1;
    }

    struct maat *maat_inst = state->maat_inst;
    assert(maat_inst != NULL);

    if (NULL == maat_inst->maat_rt) {
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

    struct maat *maat_inst = state->maat_inst;
    assert(maat_inst != NULL);

    if (NULL == maat_inst->maat_rt) {
        return -1;
    }

    state->compile_table_id = compile_table_id;

    return 0;
}

int maat_state_get_hit_paths(struct maat_state *state, struct maat_hit_path *paths,
                             size_t n_path)
{
    if (NULL == state || NULL == paths || 0 == n_path) {
        return -1;
    }

    struct maat *maat_inst = state->maat_inst;
    assert(maat_inst != NULL);

    if (NULL == maat_inst->maat_rt) {
        return -1;
    }

    int compile_table_id = table_manager_get_default_compile_table_id(maat_inst->tbl_mgr);
    if (state->compile_table_id > 0) {
        compile_table_id = state->compile_table_id;
    }

    void *compile_rt = table_manager_get_runtime(maat_inst->tbl_mgr, compile_table_id);
    if (NULL == compile_rt) {
        return -1;
    }

    int g2g_table_id = table_manager_get_group2group_table_id(maat_inst->tbl_mgr);
    void *g2g_runtime = table_manager_get_runtime(maat_inst->tbl_mgr, g2g_table_id);

    size_t internal_hit_path_cnt = maat_compile_state_get_internal_hit_paths(state->compile_state,
                                                                             (struct compile_runtime *)compile_rt,
                                                                             (struct group2group_runtime *)g2g_runtime,
                                                                             paths, n_path);

    return compile_runtime_get_hit_paths((struct compile_runtime *)compile_rt, state->thread_id,
                                         state->compile_state, paths, n_path, internal_hit_path_cnt);
}

int maat_state_get_hit_groups(struct maat_state *state, struct maat_hit_group *groups, 
                              size_t n_group)
{
    if (NULL == state || NULL == groups || 0 == n_group) {
        return -1;
    }

    int g2g_table_id = table_manager_get_group2group_table_id(state->maat_inst->tbl_mgr);
    void *g2g_runtime = table_manager_get_runtime(state->maat_inst->tbl_mgr, g2g_table_id);

    return maat_compile_state_get_hit_groups(state->compile_state,
                                             (struct group2group_runtime *)g2g_runtime,
                                             groups, n_group);
}

int maat_hit_group_compile_id(struct maat *instance, struct maat_hit_group *group)
{
    return 0;
}
