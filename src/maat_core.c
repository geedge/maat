/**********************************************************************************************
*	File: maat_core.c
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <assert.h>

#include "log/log.h"
#include "maat_utils.h"
#include "maat_core.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"
#include "maat_table.h"
#include "maat_rule.h"
#include "maat_plugin.h"
#include "maat_ip_plugin.h"
#include "maat_ipport_plugin.h"
#include "maat_fqdn_plugin.h"
#include "maat_bool_plugin.h"
#include "maat_stat.h"
#include "ip_matcher.h"
#include "alignment.h"
#include "maat_garbage_collection.h"

#define MODULE_MAAT_RULE	 module_name_str("maat.rule")

static struct maat_runtime *
maat_runtime_create(long long version, struct maat *maat_inst)
{
	struct maat_runtime *maat_rt = ALLOC(struct maat_runtime, 1);

	maat_rt->version = version;
	int ret = table_manager_runtime_create(maat_inst->tbl_mgr,
                                           maat_inst->opts.nr_worker_thread,
                                           maat_inst->garbage_bin);
    if (ret < 0) {
        FREE(maat_rt);
        return NULL;
    }

    maat_rt->ref_tbl_mgr = maat_inst->tbl_mgr;
	maat_rt->max_table_num = table_manager_table_size(maat_inst->tbl_mgr);
    maat_rt->sequence_map = maat_kv_store_new();
    maat_rt->logger = maat_inst->logger;
    maat_rt->ref_garbage_bin = maat_inst->garbage_bin;
    maat_rt->ref_cnt =
        alignment_int64_array_alloc(maat_inst->opts.nr_worker_thread);
    
    return maat_rt;
}

static void maat_runtime_destroy(struct maat_runtime *maat_rt)
{
    if (NULL == maat_rt) {
        return;
    }
    
    if (maat_rt->sequence_map != NULL) {
        maat_kv_store_free(maat_rt->sequence_map);
        maat_rt->sequence_map = NULL;
    }

    if (maat_rt->ref_cnt != NULL) {
        alignment_int64_array_free(maat_rt->ref_cnt);
        maat_rt->ref_cnt = NULL;
    }
    
    FREE(maat_rt);
}

static void
maat_runtime_commit(struct maat_runtime *maat_rt, int update_type, 
                    long long maat_rt_version, struct log_handle *logger)
{
	for (size_t i = 0; i < maat_rt->max_table_num; i++) {
		table_manager_commit_runtime(maat_rt->ref_tbl_mgr, i,
                                     update_type, maat_rt_version);
	}

    maat_rt->last_update_time = time(NULL);
}

static void
maat_start_cb(long long new_version, int update_type, void *u_param)
{
    size_t i = 0;
    enum table_type table_type = TABLE_TYPE_INVALID;
	struct maat *maat_inst = (struct maat *)u_param;

    size_t max_table_cnt = table_manager_table_size(maat_inst->tbl_mgr);
	maat_inst->new_version = new_version;

	if (update_type == MAAT_UPDATE_TYPE_FULL) {
		maat_inst->creating_maat_rt =
            maat_runtime_create(new_version, maat_inst);

        for (i = 0; i < max_table_cnt; i++) {
            table_type = table_manager_get_table_type(maat_inst->tbl_mgr, i);
            if (table_type == TABLE_TYPE_RULE) {
                // rule runtime need a reference to maat runtime
                void *rule_rt =
                    table_manager_get_updating_runtime(maat_inst->tbl_mgr, i);

                rule_runtime_init(rule_rt, maat_inst->creating_maat_rt);
            }
        }
    } else {
		maat_inst->maat_version = new_version;
	}

    for (i = 0; i < max_table_cnt; i++) {
        table_type = table_manager_get_table_type(maat_inst->tbl_mgr, i);
        if (table_type == TABLE_TYPE_PLUGIN) {
            void *schema = table_manager_get_schema(maat_inst->tbl_mgr, i);
            plugin_table_all_callback_start((struct plugin_schema *)schema,
                                            update_type);
        }
    }
}

static int
maat_update_cb(const char *table_name, const char *line, void *u_param, enum maat_operation op)
{
	if (NULL == table_name || NULL == line || NULL == u_param) {
		return 0;
	}
	
	struct maat *maat_inst =(struct maat *)u_param;
	int table_id = table_manager_get_table_id(maat_inst->tbl_mgr, table_name);
    if (table_id < 0) {
        log_fatal(maat_inst->logger, MODULE_MAAT_RULE, 
				  "[%s:%d] update warning, unknown table name %s", 
                  __FUNCTION__, __LINE__, table_name);
        return -1;
    }

    int update_type = MAAT_UPDATE_TYPE_INC;
    if (maat_inst->creating_maat_rt != NULL) {  // Full update
        update_type = MAAT_UPDATE_TYPE_FULL;
    }

    // find conjunction id for table_id
    long long conj_parent_table_ids[MAX_CONJ_PARENTS_NUM];
    int conj_parent_table_cnt =
        table_manager_get_conj_parent_table_ids(maat_inst->tbl_mgr, table_name,
                                                conj_parent_table_ids,
                                                MAX_CONJ_PARENTS_NUM);
    if (conj_parent_table_cnt > 0) {
        for (int i = 0; i < conj_parent_table_cnt; i++) {
            int ret = table_manager_update_runtime(maat_inst->tbl_mgr, table_name,
                                                   (int)conj_parent_table_ids[i],
                                                   line, op, update_type);
            if (ret < 0) {
                log_fatal(maat_inst->logger, MODULE_MAAT_RULE,
                          "[%s:%d] table<%s> update runtime error for rule:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                continue; 
            }
        }
    } else {
        int ret = table_manager_update_runtime(maat_inst->tbl_mgr, table_name,
                                               table_id, line, op, update_type);
            if (ret < 0) {
                log_fatal(maat_inst->logger, MODULE_MAAT_RULE,
                          "[%s:%d] table<%s> update runtime error for rules:%s",
                          __FUNCTION__, __LINE__, table_name, line);
                return -1;
            }
    }

	return 0;
}

static long long maat_runtime_rule_num(struct maat_runtime *maat_rt)
{
	long long total = 0;
	
	for (size_t i = 0; i < maat_rt->max_table_num; i++) {
        long long rule_cnt =
            table_manager_runtime_rule_count(maat_rt->ref_tbl_mgr, i);
		total += rule_cnt;

        if (rule_cnt != 0) {
            log_info(maat_rt->logger, MODULE_MAAT_RULE,
                     "table:<%s> rule_count:%lld",
                     table_manager_get_table_name(maat_rt->ref_tbl_mgr, i),
                     rule_cnt);
        }
	}

	return total;
}

static void
maat_plugin_table_all_callback_finish(struct table_manager *tbl_mgr)
{
    size_t max_table_cnt = table_manager_table_size(tbl_mgr);
    enum table_type table_type = TABLE_TYPE_INVALID;

    for (size_t i = 0; i < max_table_cnt; i++) {
        table_type = table_manager_get_table_type(tbl_mgr, i);
        if (table_type != TABLE_TYPE_PLUGIN) {
            continue;
        }

        void *plugin_schema = table_manager_get_schema(tbl_mgr, i);
        plugin_table_all_callback_finish((struct plugin_schema *)plugin_schema);
    }
}

static void
maat_plugin_table_garbage_collect_routine(struct table_manager *tbl_mgr)
{
    size_t max_table_cnt = table_manager_table_size(tbl_mgr);
    enum table_type table_type = TABLE_TYPE_INVALID;
    void *runtime = NULL;
    struct ex_data_runtime *ex_data_rt = NULL;

    for (size_t i = 0; i < max_table_cnt; i++) {
        table_type = table_manager_get_table_type(tbl_mgr, i);

        switch (table_type) {
            case TABLE_TYPE_PLUGIN:
                runtime = table_manager_get_runtime(tbl_mgr, i);
                ex_data_rt = plugin_runtime_get_ex_data_rt(runtime);
                break;
            case TABLE_TYPE_IP_PLUGIN:
                runtime = table_manager_get_runtime(tbl_mgr, i);
                ex_data_rt = ip_plugin_runtime_get_ex_data_rt(runtime);
                break;
            case TABLE_TYPE_IPPORT_PLUGIN:
                runtime = table_manager_get_runtime(tbl_mgr, i);
                ex_data_rt = ipport_plugin_runtime_get_ex_data_rt(runtime);
                break;
            case TABLE_TYPE_FQDN_PLUGIN:
                runtime = table_manager_get_runtime(tbl_mgr, i);
                ex_data_rt = fqdn_plugin_runtime_get_ex_data_rt(runtime);
                break;
            case TABLE_TYPE_BOOL_PLUGIN:
                runtime = table_manager_get_runtime(tbl_mgr, i);
                ex_data_rt = bool_plugin_runtime_get_ex_data_rt(runtime);
                break;
            default:
                break;
        }
        
        if (ex_data_rt != NULL) {
            ex_data_runtime_garbage_collect_routine(ex_data_rt);
            ex_data_rt = NULL;
        }
    }
}

static void maat_finish_cb(void *u_param)
{
	struct maat *maat_inst = (struct maat *)u_param;

    maat_plugin_table_all_callback_finish(maat_inst->tbl_mgr);

    if (maat_inst->creating_maat_rt != NULL) {
        maat_runtime_commit(maat_inst->creating_maat_rt,
                            MAAT_UPDATE_TYPE_FULL, 
                            maat_inst->creating_maat_rt->version,
                            maat_inst->logger);

        maat_inst->creating_maat_rt->rule_num =
            maat_runtime_rule_num(maat_inst->creating_maat_rt);

        log_info(maat_inst->logger, MODULE_MAAT_RULE, 
                 "Full config version %llu load %d entries complete", 
                 maat_inst->creating_maat_rt->version, 
                 maat_inst->creating_maat_rt->rule_num);
    } else if (maat_inst->maat_rt != NULL) {
        maat_inst->maat_rt->version = maat_inst->maat_version;
        maat_runtime_commit(maat_inst->maat_rt, MAAT_UPDATE_TYPE_INC,
                            maat_inst->maat_rt->version, maat_inst->logger);

        maat_inst->maat_rt->rule_num =
            maat_runtime_rule_num(maat_inst->maat_rt);

        log_info(maat_inst->logger, MODULE_MAAT_RULE, 
                 "Inc config version %llu load %d entries complete", 
                 maat_inst->maat_rt->version, 
                 maat_inst->maat_rt->rule_num);
    } else {
        log_info(maat_inst->logger, MODULE_MAAT_RULE,
                 "Version %d has no valid rules, plugin callback complete.", 
                 maat_inst->maat_version);
    }

    maat_inst->new_version = INVALID_VERSION;
}

void maat_read_full_config(struct maat *maat_inst)
{
    int ret = -1;
    char err_str[NAME_MAX] = {0};
    cJSON *json_root = NULL;
    struct source_redis_ctx *redis_ctx = NULL;

    switch (maat_inst->opts.input_mode) {
        case DATA_SOURCE_REDIS:
            redis_ctx = &(maat_inst->opts.redis_ctx);
            log_info(maat_inst->logger, MODULE_MAAT_RULE, 
                     "Maat initiate from Redis %s:%hu db%d", 
                     redis_ctx->redis_ip, redis_ctx->redis_port,
                     redis_ctx->redis_db);
            redis_ctx->read_ctx = maat_connect_redis(redis_ctx->redis_ip,
                                                     redis_ctx->redis_port, 
                                                     redis_ctx->redis_db,
                                                     maat_inst->logger);
            if (redis_ctx->read_ctx != NULL) {
                redis_monitor_traverse(maat_inst->maat_version, redis_ctx,
									   maat_start_cb, maat_update_cb,
                                       maat_finish_cb, maat_inst);
            }

            if (NULL == maat_inst->creating_maat_rt) {
                log_fatal(maat_inst->logger, MODULE_MAAT_RULE, 
                          "[%s:%d] At initiation: NO effective rule in redis"
                          " %s:%hu db%d", __FUNCTION__, __LINE__,
                          redis_ctx->redis_ip, redis_ctx->redis_port, 
                          redis_ctx->redis_db);
            }
            break;
        case DATA_SOURCE_JSON_FILE:
            ret = load_maat_json_rule_file(maat_inst, maat_inst->opts.json_ctx.json_file,
                                      &json_root, err_str, sizeof(err_str));
            if (ret < 0) {
                log_fatal(maat_inst->logger, MODULE_MAAT_RULE, 
                          "[%s:%d] Maat re-initiate with JSON file %s failed: %s", 
                          __FUNCTION__, __LINE__, maat_inst->opts.json_ctx.json_file,
                          err_str);
            }
            
            config_monitor_traverse(maat_inst->maat_version,
                                    json_root,
                                    maat_start_cb, maat_update_cb, maat_finish_cb,
                                    maat_inst, maat_inst->opts.decrypt_key,
                                    maat_inst->logger);
            if (NULL == maat_inst->creating_maat_rt) {
                log_fatal(maat_inst->logger, MODULE_MAAT_RULE, 
                          "[%s:%d] At initiation: NO effective rule in %s",
                          __FUNCTION__, __LINE__, maat_inst->opts.json_ctx.iris_file);
            }
            cJSON_Delete(json_root);
            break;
        default:
            break;
    }

    maat_inst->maat_rt = maat_inst->creating_maat_rt;
    maat_inst->creating_maat_rt = NULL;
    maat_inst->is_running = 1;

    if (maat_inst->maat_rt != NULL) {
        maat_inst->maat_version = maat_inst->maat_rt->version;
        maat_inst->last_full_version = maat_inst->maat_rt->version;
    }
}

long long maat_runtime_get_sequence(struct maat_runtime *maat_rt,
                                    const char *key)
{
    if (NULL == maat_rt || NULL == key) {
        return -1;
    }

    long long sequence = 1;
    int map_ret = maat_kv_read(maat_rt->sequence_map, key, &sequence, 1);
    if (map_ret < 0) {
        maat_kv_register(maat_rt->sequence_map, key, sequence);
    } else {
        sequence++;
        int ret = maat_kv_write(maat_rt->sequence_map, key, sequence);
        if (ret < 0) {
            return -1;
        }
    }

    return sequence;
}

void garbage_maat_kv_store_free(void *kv_store, void *arg)
{
    struct maat_kv_store *store = (struct maat_kv_store *)kv_store;
    maat_kv_store_free(store);
}

static void garbage_maat_runtime_destroy(void *maat_runtime, void *arg)
{
    struct maat_runtime *maat_rt = (struct maat_runtime *)maat_runtime;
    maat_runtime_destroy(maat_rt);
}

void *rule_monitor_loop(void *arg)
{
    /* Defined by prctl: The name can be up to 16 bytes long, and should 
        be null terminated if it contains fewer bytes. */
    char maat_name[MAX_INSTANCE_NAME_LEN + 1] = {0};
    struct maat *maat_inst = (struct maat *)arg;
    struct stat attrib;

    if (strlen(maat_inst->opts.inst_name) > 0) {
        snprintf(maat_name, sizeof(maat_name), "%s", maat_inst->opts.inst_name);
    } else {
        snprintf(maat_name, sizeof(maat_name), "MAAT_LOOP");
    }

    int ret = prctl(PR_SET_NAME, (unsigned long long)maat_name, NULL, NULL, NULL);
    assert(ret >= 0);

    pthread_mutex_lock(&(maat_inst->background_update_mutex));
    /* if deferred load on */
    if (maat_inst->opts.deferred_load_on != 0) {
        log_info(maat_inst->logger, MODULE_MAAT_RULE, 
                 "Deferred Loading ON, updating in %s:%d",
                 __FUNCTION__, __LINE__);
        maat_read_full_config(maat_inst);
    }
    stat(maat_inst->opts.json_ctx.json_file, &attrib);//maat has read fullconfig either in maat_new(deffer==0) or above(deffer==1)
    maat_inst->opts.json_ctx.last_md5_time = attrib.st_ctim;
    pthread_mutex_unlock(&(maat_inst->background_update_mutex));

    char md5_tmp[MD5_DIGEST_LENGTH * 2 + 1] = {0};
    char err_str[NAME_MAX] = {0};
    cJSON *json_root = NULL;

    while (maat_inst->is_running) {
        if (time(NULL) % 10 == 0) {
            log_info(maat_inst->logger, MODULE_MAAT_RULE,
                     "%s thread still alive.........", __FUNCTION__);
        }

        usleep(maat_inst->opts.rule_update_checking_interval_ms * 1000);
        pthread_mutex_lock(&(maat_inst->background_update_mutex));
        
        switch (maat_inst->opts.input_mode) {
            case DATA_SOURCE_REDIS:
                redis_monitor_traverse(maat_inst->maat_version,
                                        &(maat_inst->opts.redis_ctx),
                                        maat_start_cb, maat_update_cb, maat_finish_cb,
                                        maat_inst);
                break;
            case DATA_SOURCE_JSON_FILE:
                memset(md5_tmp, 0, sizeof(md5_tmp));
                stat(maat_inst->opts.json_ctx.json_file, &attrib);
                if (memcmp(&attrib.st_ctim, &(maat_inst->opts.json_ctx.last_md5_time),
                            sizeof(attrib.st_ctim))) {
                    maat_inst->opts.json_ctx.last_md5_time = attrib.st_ctim;
                    md5_file(maat_inst->opts.json_ctx.json_file, md5_tmp);
                    if (0 != strcmp(md5_tmp, maat_inst->opts.json_ctx.effective_json_md5)) {
                        ret = load_maat_json_rule_file(maat_inst, maat_inst->opts.json_ctx.json_file, 
                                                    &json_root, err_str, sizeof(err_str));
                        if (ret < 0) {
                            log_fatal(maat_inst->logger, MODULE_MAAT_RULE, 
                                        "[%s:%d] Maat re-initiate with JSON file %s (md5=%s)failed: %s\n",
                                        __FUNCTION__, __LINE__, maat_inst->opts.json_ctx.json_file, 
                                        md5_tmp, err_str);
                        } else {
                            config_monitor_traverse(0, json_root,
                                                    maat_start_cb, maat_update_cb, maat_finish_cb,
                                                    maat_inst, maat_inst->opts.decrypt_key,
                                                    maat_inst->logger);
                            log_info(maat_inst->logger, MODULE_MAAT_RULE, 
                                        "Maat re-initiate with JSON file %s success, md5: %s\n",
                                        maat_inst->opts.json_ctx.json_file, md5_tmp);
                        }
                        cJSON_Delete(json_root);
                    }
                }
                break;
            default:
                break;
        }

        if (maat_inst->creating_maat_rt != NULL) {
            struct maat_runtime *old_maat_rt = maat_inst->maat_rt;
            maat_inst->maat_rt = maat_inst->creating_maat_rt;

            if (old_maat_rt != NULL) {
                if (maat_inst->maat_rt->version > old_maat_rt->version) {
                    log_info(maat_inst->logger, MODULE_MAAT_RULE, 
                                "Maat version updated %lld -> %lld\n", 
                                old_maat_rt->version, maat_inst->maat_rt->version);
                } else {
                    log_info(maat_inst->logger, MODULE_MAAT_RULE, 
                                "Maat version roll back %lld -> %lld\n",
                                old_maat_rt->version, maat_inst->maat_rt->version);
                }

                maat_inst->stat->zombie_rs_stream +=
                    alignment_int64_array_sum(old_maat_rt->ref_cnt, 
                                                maat_inst->opts.nr_worker_thread);
                maat_garbage_bagging(maat_inst->garbage_bin, old_maat_rt, NULL,
                                        garbage_maat_runtime_destroy);
            }

            maat_inst->creating_maat_rt = NULL;
            maat_inst->maat_version = maat_inst->maat_rt->version;
            maat_inst->last_full_version = maat_inst->maat_rt->version;
        }

        pthread_mutex_unlock(&(maat_inst->background_update_mutex));
		
        maat_garbage_collect_routine(maat_inst->garbage_bin);
        maat_plugin_table_garbage_collect_routine(maat_inst->tbl_mgr);

        if ((1 == maat_inst->opts.stat_on) && (time(NULL) % 2 == 0)) {
            maat_stat_refresh(maat_inst->stat, maat_inst->tbl_mgr,
                             maat_inst->maat_version, maat_inst->opts.perf_on);
        }
    }

    maat_runtime_destroy(maat_inst->maat_rt);
    maat_garbage_bin_free(maat_inst->garbage_bin);
    table_manager_destroy(maat_inst->tbl_mgr); //table manager MUST be freed at last.

    if (maat_inst->stat != NULL) {
        maat_stat_free(maat_inst->stat);
        maat_inst->stat = NULL;
    }

    if (maat_inst->opts.input_mode == DATA_SOURCE_REDIS) {
        if (maat_inst->opts.redis_ctx.read_ctx != NULL) {
            redisFree(maat_inst->opts.redis_ctx.read_ctx);
            maat_inst->opts.redis_ctx.read_ctx = NULL;
        }

        if (maat_inst->opts.redis_ctx.write_ctx != NULL) {
            redisFree(maat_inst->opts.redis_ctx.write_ctx);
            maat_inst->opts.redis_ctx.write_ctx = NULL;
        }
    }

    if (maat_inst->opts.accept_tags != NULL) {
        FREE(maat_inst->opts.accept_tags);
        maat_inst->opts.accept_tags = NULL;
    }

    log_handle_destroy(maat_inst->logger);
    FREE(maat_inst);

    return NULL;
}