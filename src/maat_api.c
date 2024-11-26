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
#include "maat.h"
#include "maat_core.h"
#include "maat_kv.h"
#include "maat_command.h"
#include "maat_ex_data.h"
#include "maat_table.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"
#include "maat_rule.h"
#include "alignment.h"
#include "ip_matcher.h"
#include "adapter_hs.h"
#include "maat_garbage_collection.h"
#include "maat_object.h"
#include "maat_expr.h"
#include "maat_flag.h"
#include "maat_interval.h"
#include "maat_ip.h"
#include "maat_plugin.h"
#include "maat_ip_plugin.h"
#include "maat_ipport_plugin.h"
#include "maat_fqdn_plugin.h"
#include "maat_bool_plugin.h"
#include "maat_stat.h"
#include "uthash/utarray.h"

#define MODULE_MAAT_API	 module_name_str("maat.api")

enum logic_negate_option {
    LOGIC_NEGATE_OPTION_UNSET,
    LOGIC_NEGATE_OPTION_SET
};

struct maat_stream {
    struct maat *ref_maat_inst;
    struct expr_runtime_stream *expr_rt_stream; //each physical table open one stream
    long long last_full_version;
    long long expr_rt_version;
    struct log_handle *logger;
    int thread_id;
    int table_id;
    char field_name[MAX_FIELD_NAME_LEN];
};

struct maat_options* maat_options_new(void)
{
    struct maat_options *options = ALLOC(struct maat_options, 1);

    options->nr_worker_thread = 1;
    options->deferred_load_on = 0;
    options->rule_update_checking_interval_ms = 1 * 1000;
    options->gc_timeout_ms = 10 * 1000;
    options->input_mode = DATA_SOURCE_NONE;
    options->expr_engine = MAAT_EXPR_ENGINE_AUTO;
    options->log_level = 0;
    options->log_file_max_size_mb = 500;

    return options;
}

void maat_options_free(struct maat_options *opts)
{
    if (NULL == opts) {
        return;
    }

    FREE(opts);
}

int maat_options_set_caller_thread_number(struct maat_options *opts,
                                          size_t n_thread)
{
    if (NULL == opts) {
        return -1;
    }

    opts->nr_worker_thread = n_thread;
    return 0;
}

int maat_options_set_accept_tags(struct maat_options *opts,
                                 const char *accept_tags)
{
    if (NULL == opts || NULL == accept_tags) {
        return -1;
    }

    opts->accept_tags = maat_strdup(accept_tags);
    return 0;
}

int maat_options_set_rule_update_checking_interval_ms(struct maat_options *opts,
                                                      int interval_ms)
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

int maat_options_set_instance_name(struct maat_options *opts,
                                   const char *instance_name)
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

int maat_options_set_foreign_cont_dir(struct maat_options *opts,
                                      const char *dir)
{
    if (NULL == opts || NULL == dir || strlen(dir) >= NAME_MAX) {
        return -1;
    }

    memcpy(opts->foreign_cont_dir, dir, strlen(dir));
    return 0;
}

int maat_options_set_json_file(struct maat_options *opts,
                               const char *json_filename)
{
    strncpy(opts->json_ctx.json_file, json_filename,
            sizeof(opts->json_ctx.json_file));
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

int maat_options_set_stat_file(struct maat_options *opts,
                               const char *stat_filename)
{
    size_t str_len = MIN(sizeof(opts->stat_file), strlen(stat_filename));

    memcpy(opts->stat_file, stat_filename, str_len);
    opts->stat_on = 1;
    
    return 0;
}

int maat_options_set_expr_engine(struct maat_options *opts,
                                 enum maat_expr_engine expr_engine)
{
    if (NULL == opts || 
       (expr_engine != MAAT_EXPR_ENGINE_HS && 
        expr_engine != MAAT_EXPR_ENGINE_RS &&
        expr_engine != MAAT_EXPR_ENGINE_AUTO)) {
        return -1;
    }

    opts->expr_engine = expr_engine;

    return 0;
}

int maat_options_set_hit_path_enabled(struct maat_options *opts)
{
    if (NULL == opts) {
        return -1;
    }

    opts->hit_path_on = 1;

    return 0;
}

int maat_options_set_hit_object_enabled(struct maat_options *opts)
{
    if (NULL == opts) {
        return -1;
    }

    opts->hit_object_on = 1;

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

int maat_options_set_log_file_max_size(struct maat_options *opts,  size_t max_size_mb)
{
    if (NULL == opts || max_size_mb <= 0) {
        return -1;
    }

    opts->log_file_max_size_mb = max_size_mb;

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

    int garbage_gc_timeout_s = 0;
    struct maat *maat_inst = ALLOC(struct maat, 1);

    maat_inst->opts = *opts;

    if (strlen(maat_inst->opts.log_path) != 0) {
        maat_inst->logger = log_handle_create(maat_inst->opts.log_path,
                                              maat_inst->opts.log_level);
    } else {
        char log_path[MAX_NAME_STR_LEN] = {0};
        if (strlen(maat_inst->opts.inst_name) > 0) {
            snprintf(log_path, sizeof(log_path), "%s.log",
                     maat_inst->opts.inst_name);
        } else {
            snprintf(log_path, sizeof(log_path), "./maat.log");
        }
        maat_inst->logger = log_handle_create(log_path, maat_inst->opts.log_level);
    }
    if (maat_inst->opts.log_file_max_size_mb != 0) {
        log_handle_set_file_max_size(maat_inst->logger, maat_inst->opts.log_file_max_size_mb);
    }

    if (NULL == maat_inst->logger) {
        fprintf(stderr, "create log handle failed.\n");
        goto failed;
    }

    if (0 == strlen(maat_inst->opts.foreign_cont_dir)) {
        snprintf(maat_inst->opts.foreign_cont_dir,
                 sizeof(maat_inst->opts.foreign_cont_dir),
                 "%s_files", table_info_path);
    }
   
    system_cmd_mkdir(maat_inst->opts.foreign_cont_dir);

    if (0 == strlen(maat_inst->opts.stat_file)) {
        snprintf(maat_inst->opts.stat_file, sizeof(maat_inst->opts.stat_file),
                 "maat_stat.fs");
    }

    snprintf(maat_inst->opts.decrypt_algo, sizeof(maat_inst->opts.decrypt_algo),
             "aes-256-cbc");

    maat_inst->is_running = 0;
    maat_inst->maat_version = 0;
    maat_inst->last_full_version = 0;

    garbage_gc_timeout_s = MAX(1, (maat_inst->opts.gc_timeout_ms / 1000) );

    if (maat_inst->opts.input_mode != DATA_SOURCE_JSON_FILE &&
        maat_inst->opts.input_mode != DATA_SOURCE_REDIS) {
        log_fatal(maat_inst->logger, MODULE_MAAT_API, 
                       "[%s:%d] data source(%d) unsupported", 
                       __FUNCTION__, __LINE__, maat_inst->opts.input_mode);
        goto failed;
    }

    maat_inst->garbage_bin = maat_garbage_bin_new(garbage_gc_timeout_s);
    maat_inst->stat = maat_stat_new(maat_inst->opts.stat_file,
                                    maat_inst->opts.nr_worker_thread, 
                                    maat_inst->logger);

    pthread_mutex_init(&(maat_inst->background_update_mutex), NULL);

    maat_inst->tbl_mgr =
        table_manager_create(table_info_path, maat_inst->opts.accept_tags,
                             maat_inst->opts.expr_engine, maat_inst->garbage_bin,
                             maat_inst->logger);
    if (NULL == maat_inst->tbl_mgr) {
        goto failed;
    }

    if (0 == maat_inst->opts.deferred_load_on) {
        maat_read_full_config(maat_inst);
    }

    if (1 == maat_inst->opts.stat_on) {
        int ret = maat_stat_init(maat_inst->stat, maat_inst->opts.inst_name, maat_inst->tbl_mgr,
                                 maat_inst->garbage_bin);
        if (ret < 0) {
            log_fatal(maat_inst->logger, MODULE_MAAT_API,
                     "[%s:%d] maat_stat_init failed.", __FUNCTION__, __LINE__);
            goto failed;
        }
    }

    pthread_create(&(maat_inst->cfg_mon_thread), NULL, rule_monitor_loop,
                  (void *)maat_inst);

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

void maat_reload_log_level(struct maat *maat_inst, enum log_level level)
{
    maat_inst->opts.log_level = level;
    log_handle_set_level(maat_inst->logger, level);
}

__thread int _thread_local_tid = -1;
void maat_register_thread(struct maat *maat_inst)
{
    int thread_id = __sync_fetch_and_add(&maat_inst->thread_counter, 1);
    assert(thread_id < maat_inst->opts.nr_worker_thread);

    _thread_local_tid = thread_id;
}

static int _get_tid(struct maat *maat_inst)
{
    if (_thread_local_tid < 0 || 
        _thread_local_tid >= maat_inst->opts.nr_worker_thread) {
        return -1;
    }

    return _thread_local_tid;
}

int maat_helper_verify_regex_expression(const char *regex_expr)
{
    if (NULL == regex_expr) {
        return 0;
    }

    return expr_matcher_verify_regex_expression(regex_expr, NULL);
}

const char *
maat_get_table_schema_tag(struct maat *maat_inst, const char *table_name)
{
    if (NULL == maat_inst || table_name == NULL) {
        return NULL;
    }

    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return NULL;
    }

    struct table_manager *table_mgr = maat_inst->tbl_mgr;
    return table_manager_get_table_schema_tag(table_mgr, table_id);
}

static inline void
maat_runtime_ref_inc(struct maat_runtime *maat_rt, int thread_id)
{
    if (NULL == maat_rt || thread_id < 0) {
        return;
    }

	alignment_int64_array_add(maat_rt->ref_cnt, thread_id, 1);
}

static inline void
maat_runtime_ref_dec(struct maat_runtime *maat_rt, int thread_id)
{
    if (NULL == maat_rt || thread_id < 0) {
        return;
    }

	alignment_int64_array_add(maat_rt->ref_cnt, thread_id, -1);
}

/* must be plugin table */
int maat_table_callback_register(struct maat *maat_inst, const char *table_name,
								 maat_start_callback_t *start,
								 maat_update_callback_t *update,
								 maat_finish_callback_t *finish,
								 void *u_para)
{
    int ret = -1;
    int table_id = maat_get_table_id(maat_inst, table_name);

    if (table_id < 0) {
        log_fatal(maat_inst->logger, MODULE_MAAT_API,
                  "[%s:%d] table(table_name:%s) is not registered, "
                  "register callback failed", __FUNCTION__,
                  __LINE__, table_name);
        return -1;
    }

    pthread_mutex_lock(&(maat_inst->background_update_mutex));
    void *schema = table_manager_get_schema(maat_inst->tbl_mgr, table_id);
    if (NULL == schema) {
        pthread_mutex_unlock(&(maat_inst->background_update_mutex));
        log_fatal(maat_inst->logger, MODULE_MAAT_API,
                  "[%s:%d] table(table_name:%s) schema is NULL, "
                  "register callback failed", __FUNCTION__,
                  __LINE__, table_name);
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

    enum table_type table_type =
        table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_PLUGIN) {
        pthread_mutex_unlock(&(maat_inst->background_update_mutex));
        log_fatal(maat_inst->logger, MODULE_MAAT_API, 
                  "[%s:%d] table type:%d illegal",
                  __FUNCTION__, __LINE__, table_type);
        return -1;
    }

    size_t row_cnt = plugin_runtime_cached_row_count(runtime);
    if (row_cnt > 0) {
        if (start != NULL) {
            start(MAAT_UPDATE_TYPE_FULL, u_para);
        }

        for (size_t i = 0; i < row_cnt; i++) {
            const struct ex_data_row *ex_data_row = plugin_runtime_cached_row_get(runtime, i);
            if (NULL == ex_data_row) {
                break;
            }

            update(table_name, ex_data_row->row, ex_data_row->op, u_para);
        }

        if (finish != NULL) {
            finish(u_para);
        }
    }

    pthread_mutex_unlock(&(maat_inst->background_update_mutex));

    return 0;
}

static int
generic_plugin_table_set_ex_schema(struct table_manager *tbl_mgr, int table_id,
								   maat_ex_new_func_t *new_func,
								   maat_ex_free_func_t *free_func,
								   maat_ex_dup_func_t *dup_func,
								   long argl, void *argp,
                                   struct log_handle *logger)
{
    void *schema = table_manager_get_schema(tbl_mgr, table_id);
    if (NULL == schema) {
        log_fatal(logger, MODULE_MAAT_API, 
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
                                                          ip_plugin_rule_free,
                                                          argl, argp);
            break;
        case TABLE_TYPE_IPPORT_PLUGIN:
            ret = ipport_plugin_table_set_ex_container_schema(schema, table_id,
                                                              new_func, free_func, dup_func,
                                                              ipport_item_free,
                                                              argl, argp);
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
                                                            bool_plugin_expr_free,
                                                            argl, argp);
            break;
        default:
            log_fatal(logger, MODULE_MAAT_API,
                      "[%s:%d], table(table_id:%d) is not plugin table, can't set ex schema",
                      __FUNCTION__, __LINE__, table_id);
            return -1;
    }

    return ret;
}

static void plugin_runtime_commit_ex_schema(void *runtime, void *schema, const char *table_name)
{
    struct ex_container_schema *container_schema = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    container_schema = plugin_table_get_ex_container_schema(schema);
    ex_data_rt = plugin_runtime_get_ex_data_rt(runtime);
    ex_data_runtime_set_ex_container_schema(ex_data_rt, container_schema);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const struct ex_data_row *ex_data_row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        plugin_runtime_update(runtime, schema, table_name, ex_data_row->row, ex_data_row->op);
    }

    ex_data_runtime_clear_row_cache(ex_data_rt);
    plugin_runtime_commit(runtime, table_name, 0);
}

static void ip_plugin_runtime_commit_ex_schema(void *runtime, void *schema,
                                               const char *table_name)
{
    struct ex_container_schema *container_schema = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    container_schema = ip_plugin_table_get_ex_container_schema(schema);
    ex_data_rt = ip_plugin_runtime_get_ex_data_rt(runtime);
    ex_data_runtime_set_ex_container_schema(ex_data_rt, container_schema);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const struct ex_data_row *ex_data_row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        ip_plugin_runtime_update(runtime, schema, table_name, ex_data_row->row, ex_data_row->op);
    }

    ex_data_runtime_clear_row_cache(ex_data_rt);
    ip_plugin_runtime_commit(runtime, table_name, 0);
}

static void ipport_plugin_runtime_commit_ex_schema(void *runtime, void *schema, const char *table_name)
{
    struct ex_container_schema *container_schema = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    container_schema = ipport_plugin_table_get_ex_container_schema(schema);
    ex_data_rt = ipport_plugin_runtime_get_ex_data_rt(runtime);
    ex_data_runtime_set_ex_container_schema(ex_data_rt, container_schema);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const struct ex_data_row *ex_data_row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        ipport_plugin_runtime_update(runtime, schema, table_name, ex_data_row->row, ex_data_row->op);
    }

    ex_data_runtime_clear_row_cache(ex_data_rt);
    ipport_plugin_runtime_commit(runtime, table_name, 0);
}

static void fqdn_plugin_runtime_commit_ex_schema(void *runtime, void *schema, const char *table_name)
{
    struct ex_container_schema *container_schema = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    container_schema = fqdn_plugin_table_get_ex_container_schema(schema);
    ex_data_rt = fqdn_plugin_runtime_get_ex_data_rt(runtime);
    ex_data_runtime_set_ex_container_schema(ex_data_rt, container_schema);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const struct ex_data_row *ex_data_row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        fqdn_plugin_runtime_update(runtime, schema, table_name, ex_data_row->row, ex_data_row->op);
    }

    ex_data_runtime_clear_row_cache(ex_data_rt);
    fqdn_plugin_runtime_commit(runtime, table_name, 0);
}

static void bool_plugin_runtime_commit_ex_schema(void *runtime, void *schema, const char *table_name)
{
    struct ex_container_schema *container_schema = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    container_schema = bool_plugin_table_get_ex_container_schema(schema);
    ex_data_rt = bool_plugin_runtime_get_ex_data_rt(runtime);
    ex_data_runtime_set_ex_container_schema(ex_data_rt, container_schema);

    size_t n_cached_row = ex_data_runtime_cached_row_count(ex_data_rt);
    for (size_t i = 0; i < n_cached_row; i++) {
        const struct ex_data_row *ex_data_row = ex_data_runtime_cached_row_get(ex_data_rt, i);
        bool_plugin_runtime_update(runtime, schema, table_name, ex_data_row->row, ex_data_row->op);
    }

    ex_data_runtime_clear_row_cache(ex_data_rt);
    bool_plugin_runtime_commit(runtime, table_name, 0);
}

static int generic_plugin_runtime_commit_ex_schema(void *runtime, void *schema,
                                                   const char *table_name,
                                                   enum table_type table_type,
                                                   struct log_handle *logger)
{
    if (NULL == runtime || NULL == schema) {
        log_fatal(logger, MODULE_MAAT_API, 
                 "[%s:%d] input parameter invalid, runtime:%p, schema:%p",
                 __FUNCTION__, __LINE__, runtime, schema);
        return -1;
    }

    switch (table_type) {
        case TABLE_TYPE_PLUGIN:
            plugin_runtime_commit_ex_schema(runtime, schema, table_name);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ip_plugin_runtime_commit_ex_schema(runtime, schema, table_name);
            break;
        case TABLE_TYPE_IPPORT_PLUGIN:
            ipport_plugin_runtime_commit_ex_schema(runtime, schema, table_name);
            break;
        case TABLE_TYPE_FQDN_PLUGIN:
            fqdn_plugin_runtime_commit_ex_schema(runtime, schema, table_name);
            break;
        case TABLE_TYPE_BOOL_PLUGIN:
            bool_plugin_runtime_commit_ex_schema(runtime, schema, table_name);
            break;
        default:
            log_fatal(logger, MODULE_MAAT_API, 
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

    if (maat_inst->maat_rt != NULL) {
        void *runtime = table_manager_get_runtime(maat_inst->tbl_mgr, table_id);
        void *schema = table_manager_get_schema(maat_inst->tbl_mgr, table_id);
        assert(runtime != NULL && schema != NULL);

        table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);

        ret = generic_plugin_runtime_commit_ex_schema(runtime, schema, table_name, 
                                                      table_type, maat_inst->logger);
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
        log_fatal(maat_inst->logger, MODULE_MAAT_API,
                  "[%s:%d] [table:%s] ex_schema register input parameter is invalid.",
                  __FUNCTION__, __LINE__, table_name);
        return -1;
    }

    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        log_fatal(maat_inst->logger, MODULE_MAAT_API,
                  "[%s:%d] [table:%s] is not registered before.",
                  __FUNCTION__, __LINE__, table_name);
        return -1;
    }

    pthread_mutex_lock(&(maat_inst->background_update_mutex));

    int ret = -1;
    enum table_type table_type = table_manager_get_table_type(maat_inst->tbl_mgr,
                                                              table_id);
    if (table_type == TABLE_TYPE_PLUGIN || table_type == TABLE_TYPE_IP_PLUGIN ||
        table_type == TABLE_TYPE_IPPORT_PLUGIN || table_type == TABLE_TYPE_FQDN_PLUGIN ||
        table_type == TABLE_TYPE_BOOL_PLUGIN) {
        ret = generic_plugin_table_ex_schema_register(maat_inst, table_name,
                                                      table_id, new_func, free_func,
                                                      dup_func, argl, argp);
    }

    pthread_mutex_unlock(&(maat_inst->background_update_mutex));
    return ret;
}

void *maat_plugin_table_get_ex_data(struct maat *maat_inst, const char *table_name,
                                    const char *key, size_t key_len)
{
    if (NULL == maat_inst || NULL == key) {
        return NULL;
    }

    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0 || table_id >= MAX_TABLE_NUM) {
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

    int thread_id = _get_tid(maat_inst);
    if (thread_id >= 0 && thread_id < maat_inst->opts.nr_worker_thread) {
        plugin_runtime_scan_times_inc(runtime, thread_id);
    }

    void *ret = NULL;
    enum table_type table_type = table_manager_get_table_type(maat_inst->tbl_mgr,
                                                              table_id);
    if (TABLE_TYPE_PLUGIN == table_type) {
        ret = plugin_runtime_get_ex_data(runtime, schema, key, key_len);
    }

    return ret;
}

int maat_ip_plugin_table_get_ex_data(struct maat *maat_inst, const char *table_name,
                                     const struct ip_addr *ip_addr,
                                     void **ex_data_array, size_t array_size)
{
    if (NULL == maat_inst || NULL == ip_addr || NULL == ex_data_array || 0 == array_size) {
        return -1;
    }
    
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0 || table_id >= MAX_TABLE_NUM) {
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

    int thread_id = _get_tid(maat_inst);
    if (thread_id >= 0 && thread_id < maat_inst->opts.nr_worker_thread) {
        ip_plugin_runtime_scan_times_inc(ip_plugin_rt, thread_id);
    }

    return ip_plugin_runtime_get_ex_data(ip_plugin_rt, ip_addr, ex_data_array, array_size);
}

int maat_ipport_plugin_table_get_ex_data(struct maat *maat_inst, const char *table_name,
                                          const struct ip_addr *ip_addr, uint16_t port,
                                          void **ex_data_array, size_t array_size)
{
    if (NULL == maat_inst || NULL == ip_addr || NULL == ex_data_array || 0 == array_size) {
        return -1;
    }
    
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0 || table_id >= MAX_TABLE_NUM) {
        return -1;
    }

    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return -1;
    }

    void *ipport_plugin_rt = table_manager_get_runtime(maat_rt->ref_tbl_mgr, table_id);
    if (NULL == ipport_plugin_rt) {
        return -1;
    }

    int thread_id = _get_tid(maat_inst);
    if (thread_id >= 0 && thread_id < maat_inst->opts.nr_worker_thread) {
        ipport_plugin_runtime_scan_times_inc(ipport_plugin_rt, thread_id);
    }

    return ipport_plugin_runtime_get_ex_data(ipport_plugin_rt, ip_addr, port,
                                             ex_data_array, array_size);
}

int maat_fqdn_plugin_table_get_ex_data(struct maat *maat_inst, const char *table_name,
                                       const char *fqdn, void **ex_data_array, 
                                       size_t array_size)
{
    if (NULL == maat_inst || NULL == fqdn || NULL == ex_data_array || 0 == array_size) {
        return -1;
    }

    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0 || table_id >= MAX_TABLE_NUM) {
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

    int thread_id = _get_tid(maat_inst);
    if (thread_id >= 0 && thread_id < maat_inst->opts.nr_worker_thread) {
        fqdn_plugin_runtime_scan_times_inc(fqdn_plugin_rt, thread_id);
    }

    return fqdn_plugin_runtime_get_ex_data(fqdn_plugin_rt, fqdn, ex_data_array, array_size);
}

int maat_bool_plugin_table_get_ex_data(struct maat *maat_inst, const char *table_name,
                                       unsigned long long *item_ids, size_t n_item,
                                       void **ex_data_array, size_t array_size)
{
    if (NULL == maat_inst || NULL == item_ids || NULL == ex_data_array || 0 == array_size) {
        return -1;
    }

    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0 || table_id >= MAX_TABLE_NUM) {
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

    int thread_id = _get_tid(maat_inst);
    if (thread_id >= 0 && thread_id < maat_inst->opts.nr_worker_thread) {
        bool_plugin_runtime_scan_times_inc(bool_plugin_rt, thread_id);
    }

    return bool_plugin_runtime_get_ex_data(bool_plugin_rt, item_ids, n_item,
                                           ex_data_array, array_size);
}

static int
flag_scan(struct table_manager *tbl_mgr, int thread_id, long long flag,
          int table_id, const char *field_name, struct maat_state *state)
{
    enum table_type table_type =
        table_manager_get_table_type(tbl_mgr, table_id);

    if (table_type != TABLE_TYPE_FLAG) {
        return -1;
    }

    void *flag_rt = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == flag_rt) {
        return -1;
    }

    flag_runtime_scan_times_inc((struct flag_runtime *)flag_rt, thread_id);

    int object_hit_cnt = flag_runtime_scan((struct flag_runtime *)flag_rt,
                                         thread_id, flag, field_name, state);
    if (object_hit_cnt <= 0) {
        return object_hit_cnt;
    }

    flag_runtime_hit_times_inc((struct flag_runtime *)flag_rt, thread_id);

    return object_hit_cnt;
}

static int
interval_scan(struct table_manager *tbl_mgr, int thread_id, long long integer,
              int table_id, const char *field_name, struct maat_state *state)
{

    enum table_type table_type =
        table_manager_get_table_type(tbl_mgr, table_id);

    if (table_type != TABLE_TYPE_INTERVAL) {
        return -1;
    }

    void *interval_rt = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == interval_rt) {
        return -1;
    }

    interval_runtime_scan_times_inc((struct interval_runtime *)interval_rt, thread_id);

    int object_hit_cnt = interval_runtime_scan((struct interval_runtime *)interval_rt,
                                              thread_id, integer, field_name, state);
    if (object_hit_cnt <= 0) {
        return object_hit_cnt;
    }

    interval_runtime_hit_times_inc((struct interval_runtime *)interval_rt, thread_id);

    return object_hit_cnt;
}

static int
ipv4_scan(struct table_manager *tbl_mgr, int thread_id, uint32_t ip_addr,
          int port, int table_id, const char *field_name, struct maat_state *state)
{

    enum table_type table_type =
        table_manager_get_table_type(tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_IP) {
        return -1;
    }

    void *ip_rt = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == ip_rt) {
        return -1;
    }

    ip_runtime_scan_times_inc(ip_rt, thread_id);

    int object_hit_cnt = ip_runtime_scan((struct ip_runtime *)ip_rt, thread_id, IPv4,
                                        (uint8_t *)&ip_addr, port, field_name, state);
    if (object_hit_cnt <= 0) {
        return object_hit_cnt;
    }

    ip_runtime_hit_times_inc((struct ip_runtime *)ip_rt, thread_id);
    
    return object_hit_cnt;
}

static int
ipv6_scan(struct table_manager *tbl_mgr, int thread_id, uint8_t *ip_addr,
          int port, int table_id, const char *field_name, struct maat_state *state)
{

    enum table_type table_type =
        table_manager_get_table_type(tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_IP) {
        return -1;
    }

    void *ip_rt = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == ip_rt) {
        return -1;
    }

    ip_runtime_scan_times_inc(ip_rt, thread_id);

    int object_hit_cnt = ip_runtime_scan((struct ip_runtime *)ip_rt, thread_id, IPv6,
                                        ip_addr, port, field_name, state);
    if (object_hit_cnt <= 0) {
        return object_hit_cnt;
    }

    ip_runtime_hit_times_inc((struct ip_runtime *)ip_rt, thread_id);
    
    return object_hit_cnt;
}

static int
string_scan(struct table_manager *tbl_mgr, int thread_id,
            const char *data, size_t data_len, int table_id,
            const char *field_name, struct maat_state *state)
{
    enum table_type table_type =
        table_manager_get_table_type(tbl_mgr, table_id);

    if (table_type != TABLE_TYPE_EXPR) {
        return -1;
    }

    void *expr_rt = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == expr_rt) {
        return -1;
    }
    
    expr_runtime_scan_times_inc(expr_rt, thread_id);
    expr_runtime_scan_bytes_add(expr_rt, thread_id, data_len);

    int object_hit_cnt = expr_runtime_scan((struct expr_runtime *)expr_rt,
                                          thread_id, data, data_len,
                                          field_name, state);
    if (object_hit_cnt <= 0) {
        return object_hit_cnt;
    }

    expr_runtime_hit_times_inc((struct expr_runtime *)expr_rt, thread_id);

    return object_hit_cnt;
}

size_t maat_state_compile(struct maat_state *state, const char *table_name, uuid_t rule_array[], size_t n_result)
{
    int table_id = maat_get_table_id(state->maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }

    void *rule_rt = table_manager_get_runtime(state->maat_inst->tbl_mgr, table_id);
    if (NULL == rule_rt) {
        return 0;
    }

    int rule_num = rule_runtime_match(table_id, (struct rule_runtime *)rule_rt, rule_array, n_result, state);
    if (rule_num > 0) {
        alignment_int64_array_add(state->maat_inst->stat->hit_rule_cnt, state->thread_id, rule_num);
    }

    return rule_num;
}

int maat_state_need_compile(struct maat_state *state, const char *table_name)
{
    if (state == NULL || state->maat_inst == NULL) {
        return 0;
    }

    int table_id = maat_get_table_id(state->maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }

    void *rule_rt = table_manager_get_runtime(state->maat_inst->tbl_mgr, table_id);
    if (NULL == rule_rt) {
        return 0;
    }

    return rule_runtime_need_compile(table_id, (struct rule_runtime *)rule_rt, state->rule_compile_state);
}

int maat_scan_flag(struct maat *maat_inst, const char *table_name, const char *field_name,
                   long long flag, struct maat_state *state)
{
    if ((NULL == maat_inst) || (NULL == state) || (state->thread_id < 0)) {
        return MAAT_SCAN_ERR;
    }

    struct timespec start, end;
    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->Nth_scan++;

    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return MAAT_SCAN_OK;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);

    enum table_type table_type = TABLE_TYPE_INVALID;
    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_FLAG) {
        maat_inst->stat->scan_err_cnt++;
        goto ERROR;
    }

    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);
    int hit_object_cnt = flag_scan(maat_inst->tbl_mgr, state->thread_id, flag,
                                  table_id, field_name, state);
    if (hit_object_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        goto ERROR;
    }

    void *flag_rt = table_manager_get_runtime(maat_inst->tbl_mgr, table_id);
    assert(flag_rt != NULL);

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        flag_runtime_perf_stat(flag_rt, &start, &end, state->thread_id);
    } else {
        flag_runtime_perf_stat(flag_rt, NULL, NULL, state->thread_id);
    }

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    if (hit_object_cnt > 0) {
        return MAAT_SCAN_HIT;
    } else {
        return MAAT_SCAN_OK;
    }

ERROR:
    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);
    return MAAT_SCAN_ERR;
}

int maat_scan_integer(struct maat *maat_inst, const char *table_name, const char *field_name,
                      long long integer, struct maat_state *state)
{
    if ((NULL == maat_inst) || (NULL == state) || (state->thread_id < 0)) {
        return MAAT_SCAN_ERR;
    }
    
    struct timespec start, end;
    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->Nth_scan++;

    int table_id = table_manager_get_table_id(maat_inst->tbl_mgr, table_name);
    if (table_id < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return MAAT_SCAN_OK;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);

    enum table_type table_type = TABLE_TYPE_INVALID;
    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_INTERVAL) {
        maat_inst->stat->scan_err_cnt++;
        goto ERROR;
    }

    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);
    int hit_object_cnt = interval_scan(maat_inst->tbl_mgr, state->thread_id, integer,
                                      table_id, field_name, state);
    if (hit_object_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        goto ERROR;
    }

    void *interval_rt = table_manager_get_runtime(maat_inst->tbl_mgr, table_id);
    assert(interval_rt != NULL);

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        interval_runtime_perf_stat(interval_rt, &start, &end, state->thread_id);
    } else {
        interval_runtime_perf_stat(interval_rt, NULL, NULL, state->thread_id);
    }

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    if (hit_object_cnt > 0) {
        return MAAT_SCAN_HIT;
    } else {
        return MAAT_SCAN_OK;
    }

ERROR:
    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);
    return MAAT_SCAN_ERR;
}

int maat_scan_ipv4_port(struct maat *maat_inst, const char *table_name, const char *field_name, 
                        uint32_t ip_addr, int port, struct maat_state *state)
{
    if ((NULL == maat_inst) || (NULL == state) || (state->thread_id < 0)) {
        return MAAT_SCAN_ERR;
    }

    struct timespec start, end;
    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->Nth_scan++;

    int table_id = table_manager_get_table_id(maat_inst->tbl_mgr, table_name);
    if (table_id < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return MAAT_SCAN_OK;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);

    enum table_type table_type = TABLE_TYPE_INVALID;
    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_IP) {
        maat_inst->stat->scan_err_cnt++;
        goto ERROR;
    }

    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);
    int hit_object_cnt = ipv4_scan(maat_inst->tbl_mgr, state->thread_id, ip_addr, port,
                                  table_id, field_name, state);
    if (hit_object_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        goto ERROR;
    }

    void *ip_rt = table_manager_get_runtime(maat_inst->tbl_mgr, table_id);
    assert(ip_rt != NULL);

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        ip_runtime_perf_stat(ip_rt, &start, &end, state->thread_id);
    } else {
        ip_runtime_perf_stat(ip_rt, NULL, NULL, state->thread_id);
    }

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    if (hit_object_cnt > 0) {
        return MAAT_SCAN_HIT;
    } else {
        return MAAT_SCAN_OK;
    }

ERROR:
    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);
    return MAAT_SCAN_ERR;
}

int maat_scan_ipv6_port(struct maat *maat_inst, const char *table_name, const char *field_name, 
                        uint8_t *ip_addr, int port, struct maat_state *state)
{
    if ((NULL == maat_inst) || (NULL == ip_addr) || (NULL == state) || (state->thread_id < 0)) {
        return MAAT_SCAN_ERR;
    }

    struct timespec start, end;
    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->Nth_scan++;

    int table_id = table_manager_get_table_id(maat_inst->tbl_mgr, table_name);
    if (table_id < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return MAAT_SCAN_OK;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);

    enum table_type table_type = TABLE_TYPE_INVALID;
    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_IP) {
        maat_inst->stat->scan_err_cnt++;
        goto ERROR;
    }

    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);
    int hit_object_cnt = ipv6_scan(maat_inst->tbl_mgr, state->thread_id, ip_addr, port,
                                  table_id, field_name, state);
    if (hit_object_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        goto ERROR;
    }

    void *ip_rt = table_manager_get_runtime(maat_inst->tbl_mgr, table_id);
    assert(ip_rt != NULL);

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        ip_runtime_perf_stat(ip_rt, &start, &end, state->thread_id);
    } else {
        ip_runtime_perf_stat(ip_rt, NULL, NULL, state->thread_id);
    }

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    if (hit_object_cnt > 0) {
        return MAAT_SCAN_HIT;
    } else {
        return MAAT_SCAN_OK;
    }

ERROR:
    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);
    return MAAT_SCAN_ERR;
}

#define PORT_IGNORED -1
inline int maat_scan_ipv6(struct maat *instance, const char *table_name, const char *field_name,
                        uint8_t *ip_addr, struct maat_state *state)
{
    return maat_scan_ipv6_port(instance, table_name, field_name, ip_addr, PORT_IGNORED, state);
}

inline int maat_scan_ipv4(struct maat *instance, const char *table_name, const char *field_name, 
                        uint32_t ip_addr, struct maat_state *state)
{
    return maat_scan_ipv4_port(instance, table_name, field_name, ip_addr, PORT_IGNORED, state);
}

int maat_scan_string(struct maat *maat_inst, const char *table_name, const char *field_name,
                     const char *data, size_t data_len, struct maat_state *state)
{
    if ((NULL == maat_inst) || (NULL == data) || (0 == data_len) || (NULL == state) ||
        (state->thread_id < 0)) {
        return MAAT_SCAN_ERR;
    }
    
    struct timespec start, end;
    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->Nth_scan++;

    int table_id = table_manager_get_table_id(maat_inst->tbl_mgr, table_name);
    if (table_id < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return MAAT_SCAN_OK;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);

    enum table_type table_type = TABLE_TYPE_INVALID;
    table_type = table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_EXPR) {
        maat_inst->stat->scan_err_cnt++;
        goto ERROR;
    }

    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);
    int hit_object_cnt = string_scan(maat_inst->tbl_mgr, state->thread_id, data,
                                    data_len, table_id, field_name, state);
    if (hit_object_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        goto ERROR;
    }

    void *expr_rt = table_manager_get_runtime(maat_inst->tbl_mgr, table_id);
    assert(expr_rt != NULL);

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        expr_runtime_perf_stat(expr_rt, data_len, &start, &end, state->thread_id);
    } else {
        expr_runtime_perf_stat(expr_rt, data_len, NULL, NULL, state->thread_id);
    }

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    if (hit_object_cnt > 0) {
        return MAAT_SCAN_HIT;
    } else {
        return MAAT_SCAN_OK;
    }

ERROR:
    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);
    return MAAT_SCAN_ERR;
}

static void maat_state_add_hit_object(struct maat_state *state, const char *field_name,
                                     uuid_t object_uuid_array[], uuid_t item_uuid_array[], size_t array_size)
{
    struct maat *maat_inst = state->maat_inst;

    if (NULL == state->rule_compile_state) {
        state->rule_compile_state = rule_compile_state_new();
        alignment_int64_array_add(maat_inst->stat->rule_state_cnt,
                                  state->thread_id, 1); 
    }

    size_t n_hit_item = array_size;
    if (n_hit_item >= MAX_HIT_OBJECT_NUM) {
        n_hit_item = MAX_HIT_OBJECT_NUM;
    }

    struct maat_item hit_items[n_hit_item];
    for (size_t i = 0; i < n_hit_item; i++) {
        uuid_copy(hit_items[i].item_uuid, item_uuid_array[i]);
        uuid_copy(hit_items[i].object_uuid, object_uuid_array[i]);
    }

    rule_compile_state_update(state->rule_compile_state, maat_inst, field_name,
                         state->rule_table_id, state->Nth_scan,
                         hit_items, n_hit_item);
}

int maat_scan_object(struct maat *maat_inst, const char *table_name, const char *field_name,
                    uuid_t object_uuid_array[], uuid_t item_uuid_array[], size_t array_size, struct maat_state *state)
{
    if ((NULL == maat_inst) || (array_size == 0) || (NULL == state) ||
        (state->thread_id < 0)) {
        return -1;
    }

    state->Nth_scan++;

    int table_id = table_manager_get_table_id(maat_inst->tbl_mgr, table_name);
    if (table_id < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }

    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return MAAT_SCAN_OK;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);

    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);

    maat_state_add_hit_object(state, field_name, object_uuid_array, item_uuid_array, array_size);

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    return MAAT_SCAN_OK;
}

int maat_scan_not_logic(struct maat *maat_inst, const char *table_name, const char *field_name, struct maat_state *state)
{
    if ((NULL == maat_inst) || (NULL == state) || (state->thread_id < 0)) {
        return -1;
    }

    if (NULL == state->rule_compile_state) {
        return 0;
    }

    struct maat_runtime *maat_rt = maat_inst->maat_rt;
    if (NULL == maat_rt) {
        return MAAT_SCAN_OK;
    }

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);

    alignment_int64_array_add(maat_inst->stat->thread_call_cnt, state->thread_id, 1);

    rule_compile_state_not_logic_update(maat_inst, state->rule_compile_state, field_name, state->Nth_scan);

    maat_runtime_ref_dec(maat_inst->maat_rt, state->thread_id);

    return MAAT_SCAN_OK;
}

struct maat_stream *maat_stream_new(struct maat *maat_inst, const char *table_name, const char *field_name, struct maat_state *state)
{
    if ((NULL == maat_inst) || (NULL == state) || (state->thread_id < 0)) {
        return NULL;
    }

    struct maat_stream *stream = ALLOC(struct maat_stream, 1);
    stream->ref_maat_inst = maat_inst;
    stream->last_full_version = maat_inst->last_full_version;
    stream->thread_id = state->thread_id;
    stream->table_id = table_manager_get_table_id(maat_inst->tbl_mgr, table_name);
    snprintf(stream->field_name, sizeof(stream->field_name), "%s", field_name);
    stream->logger = maat_inst->logger;

    enum table_type table_type = TABLE_TYPE_INVALID;
    
    if (stream->table_id < 0) {
        goto error;
    }

    table_type = table_manager_get_table_type(maat_inst->tbl_mgr,
                                              stream->table_id);
    if (table_type != TABLE_TYPE_EXPR) {
        goto error;
    }

    void *expr_rt = table_manager_get_runtime(stream->ref_maat_inst->tbl_mgr,
                                              stream->table_id);
    assert(expr_rt != NULL);
    stream->expr_rt_version = expr_runtime_get_version(expr_rt);

    maat_runtime_ref_inc(maat_inst->maat_rt, state->thread_id);

    struct expr_runtime_stream *expr_rt_stream = NULL;
    expr_rt_stream = expr_runtime_stream_open((struct expr_runtime *)expr_rt,
                                              state->thread_id);
    if (NULL == expr_rt_stream) {
        goto error;
    }

    alignment_int64_array_add(maat_inst->stat->stream_cnt, stream->thread_id, 1);
    stream->expr_rt_stream = expr_rt_stream;

    return stream;

error:
    FREE(stream);
    return NULL;
}

static int expr_stream_scan(struct maat_stream *stream, const char *data,
                            size_t data_len, struct maat_state *state)
{
    if (NULL == stream || NULL == data) {
        return 0;
    }

    enum table_type table_type = TABLE_TYPE_INVALID;
    struct table_manager *tbl_mgr = stream->ref_maat_inst->tbl_mgr;
    table_type = table_manager_get_table_type(tbl_mgr, stream->table_id);

    if (table_type != TABLE_TYPE_EXPR) {
        return -1;
    }

    expr_runtime_stream_scan_times_inc(stream->expr_rt_stream, stream->thread_id);
    expr_runtime_stream_scan_bytes_add(stream->expr_rt_stream, stream->thread_id,
                                       data_len);

    int object_hit_cnt = expr_runtime_stream_scan(stream->expr_rt_stream, data,
                                                 data_len, stream->field_name, state);
    if (object_hit_cnt <= 0) {
        return object_hit_cnt;
    }

    expr_runtime_stream_hit_times_inc(stream->expr_rt_stream, stream->thread_id);

    return object_hit_cnt;
}

int maat_stream_scan(struct maat_stream *maat_stream, const char *data, int data_len, struct maat_state *state)
{
    if ((NULL == maat_stream) || (NULL == data) || (0 == data_len) || (NULL == state)) {
        return MAAT_SCAN_ERR;
    }

    struct timespec start, end;
    if (1 == maat_stream->ref_maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &start);
    }

    state->Nth_scan++;

    struct maat *maat_inst = maat_stream->ref_maat_inst;
    if (maat_stream->last_full_version != maat_inst->last_full_version) {
        return MAAT_SCAN_OK;
    }

    void *expr_rt = table_manager_get_runtime(maat_inst->tbl_mgr,
                                              maat_stream->table_id);
    assert(expr_rt != NULL);
    
    long long cur_expr_rt_version = expr_runtime_get_version(expr_rt);
    if (maat_stream->expr_rt_version != cur_expr_rt_version) {
        return MAAT_SCAN_OK;
    }

    alignment_int64_array_add(maat_inst->stat->thread_call_cnt,
                              maat_stream->thread_id, 1);

    int hit_object_cnt = expr_stream_scan(maat_stream, data, data_len, state);
    if (hit_object_cnt < 0) {
        maat_inst->stat->scan_err_cnt++;
        return MAAT_SCAN_ERR;
    }  

    if (1 == maat_inst->opts.perf_on) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        expr_runtime_perf_stat(expr_rt, data_len, &start, &end, state->thread_id);
    } else {
        expr_runtime_perf_stat(expr_rt, data_len, NULL, NULL, state->thread_id);
    }

    if (hit_object_cnt > 0) {
        return MAAT_SCAN_HIT;
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
                                              maat_stream->table_id);
    assert(expr_rt != NULL);

    long long cur_expr_rt_version = expr_runtime_get_version(expr_rt);
    if ((maat_stream->last_full_version == maat_inst->last_full_version) && 
        (maat_stream->expr_rt_version == cur_expr_rt_version)) {
        maat_runtime_ref_dec(maat_inst->maat_rt, maat_stream->thread_id);
    } else if (maat_stream->last_full_version != maat_inst->last_full_version) {
        maat_inst->stat->zombie_rs_stream--;
    }

    alignment_int64_array_add(maat_inst->stat->stream_cnt, maat_stream->thread_id, -1);

    if (maat_stream->expr_rt_stream != NULL) {
        expr_runtime_stream_close(maat_stream->expr_rt_stream);
        maat_stream->expr_rt_stream = NULL;
    }

    FREE(maat_stream);
}

struct maat_state *maat_state_new(struct maat *maat_inst, int thread_id)
{
    if (NULL == maat_inst || thread_id < 0) {
        return NULL;
    }

    struct maat_state *state = ALLOC(struct maat_state, 1);

    state->maat_inst = maat_inst;
    state->thread_id = thread_id;

    /* state->rule_state no need to alloc memory at this point,
       but alloc it after hitting items
     */
    alignment_int64_array_add(maat_inst->stat->maat_state_cnt, thread_id, 1);

    return state;
}

void maat_state_reset(struct maat_state *state)
{
    if (NULL == state) {
        return;
    }

    state->rule_table_id = 0;
    state->Nth_scan = 0;

    if (state->rule_compile_state != NULL) {
        rule_compile_state_reset(state->rule_compile_state);
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

    if (state->rule_compile_state != NULL) {
        rule_compile_state_free(state->rule_compile_state, maat_inst, thread_id);
        state->rule_compile_state = NULL;
        alignment_int64_array_add(maat_inst->stat->rule_state_cnt,
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

int maat_state_get_hit_paths(struct maat_state *state, struct maat_hit_path *path_array,
                             size_t array_size)
{
    if (NULL == state || NULL == path_array || 0 == array_size) {
        return -1;
    }

    struct maat *maat_inst = state->maat_inst;
    assert(maat_inst != NULL);

    if (NULL == maat_inst->maat_rt) {
        return -1;
    }

    if (NULL == state->rule_compile_state) {
        return 0;
    }

    int rule_table_id =
        table_manager_get_default_rule_table_id(maat_inst->tbl_mgr);
    if (state->rule_table_id > 0) {
        rule_table_id = state->rule_table_id;
    }

    void *rule_rt = table_manager_get_runtime(maat_inst->tbl_mgr,
                                                 rule_table_id);
    if (NULL == rule_rt) {
        return -1;
    }

    int object_group_table_id = table_manager_get_object_group_table_id(maat_inst->tbl_mgr);
    void *object_group_runtime = table_manager_get_runtime(maat_inst->tbl_mgr, object_group_table_id);

    size_t hit_path_cnt =
        rule_compile_state_get_internal_hit_paths(state->rule_compile_state,
                                            (struct rule_runtime *)rule_rt,
                                            (struct object_group_runtime *)object_group_runtime,
                                             path_array, array_size);

    return rule_runtime_get_hit_paths((struct rule_runtime *)rule_rt,
                                         state->thread_id, state->rule_compile_state,
                                         path_array, array_size, hit_path_cnt);
}

size_t maat_state_get_scan_count(struct maat_state *state)
{
    if (NULL == state) {
        return 0;
    }

    return state->Nth_scan;
}

size_t maat_state_get_hit_items(struct maat_state *state, const char *field_name,
                            uuid_t item_array[],  uuid_t direct_object_array[],
                            size_t array_size)
{
    if (NULL == state || 0 == array_size) {
        return -1;
    }

    if (NULL == state->rule_compile_state) {
        return 0;
    }
    
    return rule_compile_state_get_direct_hit_items(state->maat_inst, state->rule_compile_state, field_name, item_array, direct_object_array, array_size);
}

size_t maat_state_get_hit_item_cnt(struct maat_state *state, const char *field_name)
{
    if (NULL == state || NULL == state->rule_compile_state) {
        return 0;
    }

    return rule_compile_state_get_direct_hit_item_cnt(state->maat_inst, state->rule_compile_state, field_name);
}

size_t maat_state_get_indirect_hit_objects(struct maat_state *state, const char *field_name,
                                        uuid_t object_array[], size_t array_size)
{
    if (NULL == state || NULL == object_array || 0 == array_size) {
        return 0;
    }

    if (NULL == state->rule_compile_state) {
        return 0;
    }

    return rule_compile_state_get_indirect_hit_objects(state->maat_inst, state->rule_compile_state, field_name, object_array, array_size);
}

size_t maat_state_get_indirect_hit_object_cnt(struct maat_state *state, const char *field_name)
{
    if (NULL == state || NULL == state->rule_compile_state) {
        return 0;
    }

    return rule_compile_state_get_indirect_hit_object_cnt(state->maat_inst, state->rule_compile_state, field_name);
}

size_t maat_state_get_hit_objects(struct maat_state *state, const char *field_name, uuid_t object_array[], size_t array_size)
{
    if (NULL == state || NULL == object_array || 0 == array_size) {
        return 0;
    }

    if (NULL == state->rule_compile_state) {
        return 0;
    }

    return rule_compile_state_get_hit_objects(state->maat_inst, state->rule_compile_state, field_name, object_array, array_size);
}

size_t maat_state_get_hit_object_cnt(struct maat_state *state, const char *field_name)
{
    if (NULL == state || NULL == state->rule_compile_state) {
        return 0;
    }

    return rule_compile_state_get_hit_object_cnt(state->maat_inst, state->rule_compile_state, field_name);
}

size_t maat_state_get_field_names(struct maat_state *state, const char *field_names[], size_t array_size)
{
    if (NULL == state || NULL == field_names || 0 == array_size) {
        return 0;
    }

    if (NULL == state->rule_compile_state) {
        return 0;
    }

    return rule_compile_state_get_field_names(state->rule_compile_state, field_names, array_size);
}

size_t maat_state_get_field_cnt(struct maat_state *state)
{
    if (NULL == state || NULL == state->rule_compile_state) {
        return 0;
    }

    return rule_compile_state_get_field_cnt(state->rule_compile_state);
}