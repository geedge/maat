/*
**********************************************************************************************
*	File: maat_rule.cpp
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <limits.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <assert.h>

#include "utils.h"
#include "json2iris.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"

#include "maat_table_runtime.h"
#include "maat_table_schema.h"

struct maat_runtime* maat_runtime_create(long long version, struct maat *maat_instance)
{
	struct maat_runtime *maat_rt = ALLOC(struct maat_runtime, 1);

	maat_rt->version = version;
	maat_rt->table_rt_mgr = table_runtime_manager_create(maat_instance->table_schema_mgr,
                                                        maat_instance->nr_worker_thread,
                                                        maat_instance->garbage_bin);
	maat_rt->max_table_num = table_schema_manager_get_size(maat_instance->table_schema_mgr);
    maat_rt->max_thread_num = maat_instance->nr_worker_thread;

    return maat_rt;
}

void maat_runtime_commit(struct maat_runtime *maat_rt)
{
	for (size_t i = 0; i < maat_rt->max_table_num; i++) {
		struct table_runtime *table_rt = table_runtime_get(maat_rt->table_rt_mgr, i);
		if (NULL == table_rt) {
			continue;
		}

		table_runtime_commit(table_rt, maat_rt->max_thread_num);
	}

    maat_rt->last_update_time = time(NULL);
}

void maat_runtime_destroy(struct maat_runtime *maat_rt)
{
    if (NULL == maat_rt) {
        return;
    }

    if (maat_rt->table_rt_mgr != NULL) {
        table_runtime_manager_destroy(maat_rt->table_rt_mgr);
        maat_rt->table_rt_mgr = NULL;
    }

    FREE(maat_rt);
}

int maat_runtime_updating_flag(struct maat_runtime *maat_rt)
{
    for (size_t i = 0; i < maat_rt->max_table_num; i++) {
		struct table_runtime *table_rt = table_runtime_get(maat_rt->table_rt_mgr, i);
		if (NULL == table_rt) {
			continue;
		}
        
        int flag = table_runtime_updating_flag(table_rt);
        if (1 == flag) {
            return 1;
        }
	}

    return 0;
}

void maat_start_cb(long long new_version, int update_type, void *u_param)
{
	struct maat *maat_instance = (struct maat *)u_param;
	
	if (update_type == CM_UPDATE_TYPE_FULL) {
		maat_instance->creating_maat_rt = maat_runtime_create(new_version, maat_instance);
	} else {
		maat_instance->maat_version = new_version;
	}

    table_schema_manager_all_plugin_cb_start(maat_instance->table_schema_mgr, update_type);
}

int maat_update_cb(const char *table_name, const char *line, void *u_param)
{
	struct maat *maat_instance =(struct maat *)u_param; 
	struct maat_runtime* maat_rt = NULL;
	int table_id = table_schema_manager_get_table_id(maat_instance->table_schema_mgr, table_name);
    if (table_id < 0) {
        fprintf(stderr, "update warning, unknown table name %s\n", table_name);
        return -1;
    }

	struct table_schema* table_schema = table_schema_get(maat_instance->table_schema_mgr, table_id);
    if (NULL == table_schema) {
        fprintf(stderr, "update warning, table name %s doesn't have table schema\n", table_name);
        return -1;
    }

    table_schema_set_updating_name(table_schema, table_name);
    
	if (maat_instance->creating_maat_rt != NULL) {
		maat_rt = maat_instance->creating_maat_rt;
	} else {
		maat_rt = maat_instance->maat_rt;
	}

    struct table_item *table_item = table_schema_line_to_item(line, table_schema);
    if (table_item != NULL) {
        struct table_runtime *table_rt = table_runtime_get(maat_rt->table_rt_mgr, table_id);
        table_runtime_update(table_rt, table_schema, line, table_item);
	    FREE(table_item);
    }
     
	return 0;
}

uint32_t maat_runtime_rule_num(struct maat_runtime *maat_rt)
{
	uint32_t total = 0;
	struct table_runtime *table_rt = NULL;
	
	for (size_t i = 0; i < maat_rt->max_table_num; i++) {
		table_rt = table_runtime_get(maat_rt->table_rt_mgr, i);
		if (table_rt != NULL) {
			total += table_runtime_rule_count(table_rt);
		}
	}

	return total;
}

void maat_finish_cb(void *u_param)
{
	struct maat *maat_instance = (struct maat *)u_param;

    table_schema_manager_all_plugin_cb_finish(maat_instance->table_schema_mgr);
    
    if (maat_instance->creating_maat_rt != NULL) {
        maat_instance->creating_maat_rt->rule_num = maat_runtime_rule_num(maat_instance->creating_maat_rt);
        maat_runtime_commit(maat_instance->creating_maat_rt);
        fprintf(stdout, "Full config version %llu load %d entries complete\n", 
                        maat_instance->creating_maat_rt->version,
                        maat_instance->creating_maat_rt->rule_num);
    } else if (maat_instance->maat_rt != NULL) {
        maat_instance->maat_rt->rule_num = maat_runtime_rule_num(maat_instance->maat_rt);
        maat_instance->maat_rt->version = maat_instance->maat_version;
        maat_runtime_commit(maat_instance->maat_rt);
        fprintf(stdout, "Inc config version %llu load %d entries complete\n", 
                        maat_instance->maat_rt->version,
                        maat_instance->maat_rt->rule_num);
    }
}

void *rule_monitor_loop(void *arg)
{
    /* Defined by prctl: The name can be up to 16 bytes long, and should 
        be null terminated if it contains fewer bytes. */
    char maat_name[16] = {0};
    struct maat *maat_instance = (struct maat *)arg;

    if (strlen(maat_instance->instance_name) > 0) {
        snprintf(maat_name, sizeof(maat_name), "MAAT_%s", maat_instance->instance_name);
    } else {
        snprintf(maat_name, sizeof(maat_name), "MAAT");
    }

    int ret = prctl(PR_SET_NAME, (unsigned long long)maat_name, NULL, NULL, NULL);
    assert(ret >= 0);

    pthread_mutex_lock(&(maat_instance->background_update_mutex));
    /* if deferred load on */
    if (maat_instance->deferred_load != 0) {
        fprintf(stdout, "Deferred Loading ON, updating in %s\n", __func__);
        maat_read_full_config(maat_instance);
    }
    pthread_mutex_unlock(&(maat_instance->background_update_mutex));

    char md5_tmp[MD5_DIGEST_LENGTH * 2 + 1] = {0};
    char err_str[NAME_MAX] = {0};
    struct stat attrib;
    while (maat_instance->is_running) {
        usleep(maat_instance->rule_update_checking_interval_ms * 1000);
		if( 0 == pthread_mutex_trylock(&(maat_instance->background_update_mutex))) {
			switch (maat_instance->input_mode) {
                case DATA_SOURCE_REDIS:
                    redis_monitor_traverse(maat_instance->maat_version,
                                            &(maat_instance->mr_ctx),
                                            maat_start_cb,
                                            maat_update_cb,
                                            maat_finish_cb,
                                            maat_instance);
                    break;
				case DATA_SOURCE_IRIS_FILE:
					config_monitor_traverse(maat_instance->maat_version, 
											maat_instance->iris_ctx.inc_idx_dir,
											maat_start_cb,
											maat_update_cb,
											maat_finish_cb,
											maat_instance);
					break;
                case DATA_SOURCE_JSON_FILE:
                    memset(md5_tmp, 0, sizeof(md5_tmp));
				    stat(maat_instance->json_ctx.json_file, &attrib);
					if (memcmp(&attrib.st_ctim, &(maat_instance->json_ctx.last_md5_time), sizeof(attrib.st_ctim))) {
						maat_instance->json_ctx.last_md5_time = attrib.st_ctim;
						md5_file(maat_instance->json_ctx.json_file, md5_tmp);
						if (0 != strcmp(md5_tmp, maat_instance->json_ctx.effective_json_md5)) {
							ret = load_maat_json_file(maat_instance, maat_instance->json_ctx.json_file, err_str, sizeof(err_str));
							if (ret < 0) {
								fprintf(stdout, "Maat re-initiate with JSON file %s (md5=%s)failed: %s\n",
												maat_instance->json_ctx.json_file, md5_tmp, err_str);
							} else {
								config_monitor_traverse(0, maat_instance->json_ctx.iris_file,
														maat_start_cb,
														maat_update_cb,
														maat_finish_cb,
														maat_instance);
								fprintf(stdout, "Maat re-initiate with JSON file %s success, md5: %s\n",
												maat_instance->json_ctx.json_file, md5_tmp);
							}
						}
					}
                    break;
				default:
					break;
			}

			if (maat_instance->creating_maat_rt != NULL) {
				struct maat_runtime *old_maat_rt = maat_instance->maat_rt;
				maat_instance->maat_rt = maat_instance->creating_maat_rt;

				if (old_maat_rt != NULL) {
                    if (maat_instance->maat_rt->version > old_maat_rt->version) {
                        fprintf(stdout, "Maat version updated %lld -> %lld\n", 
                                        old_maat_rt->version, maat_instance->maat_rt->version);
                    } else {
                        fprintf(stdout, "Maat version roll back %lld -> %lld\n",
                                        old_maat_rt->version, maat_instance->maat_rt->version);
                    }
                    maat_garbage_bagging(maat_instance->garbage_bin, old_maat_rt, (void (*)(void*))maat_runtime_destroy);
				}

				maat_instance->creating_maat_rt = NULL;
				maat_instance->maat_version = maat_instance->maat_rt->version;
				maat_instance->last_full_version = maat_instance->maat_rt->version;
			}

			if (maat_instance->maat_rt != NULL) {
                int updating_flag = maat_runtime_updating_flag(maat_instance->maat_rt);
                time_t time_window = time(NULL) - maat_instance->maat_rt->last_update_time;
                
                if ((updating_flag > 0) && (time_window >= maat_instance->rule_effect_interval_ms / 1000)) {
                    maat_runtime_commit(maat_instance->maat_rt);
                }
				
			}

			pthread_mutex_unlock(&(maat_instance->background_update_mutex));
		}
        maat_garbage_collect_routine(maat_instance->garbage_bin);
    }

    maat_runtime_destroy(maat_instance->maat_rt);
	maat_garbage_bin_free(maat_instance->garbage_bin);
	table_schema_manager_destroy(maat_instance->table_schema_mgr);

    if (maat_instance->input_mode == DATA_SOURCE_REDIS) {
        if (maat_instance->mr_ctx.read_ctx != NULL) {
            redisFree(maat_instance->mr_ctx.read_ctx);
            maat_instance->mr_ctx.read_ctx = NULL;
        }

        if (maat_instance->mr_ctx.write_ctx != NULL) {
            redisFree(maat_instance->mr_ctx.write_ctx);
            maat_instance->mr_ctx.write_ctx = NULL;
        }
    }

    FREE(maat_instance);

    return NULL;
}