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

#include "json2iris.h"
#include "log/log.h"
#include "cJSON/cJSON.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"
#include "maat_table.h"
#include "maat_compile.h"
#include "maat_plugin.h"
#include "alignment.h"
#include "maat_garbage_collection.h"

#define MODULE_MAAT_RULE	 module_name_str("maat.rule")

struct maat_item *maat_item_new(int item_id, int group_id, void *user_data)
{
	struct maat_item *item = NULL;
	item = ALLOC(struct maat_item, 1);
	item->group_id = group_id;
	item->item_id = item_id;
	item->user_data = user_data;

	return item;
}

void maat_item_free(struct maat_item *item, void (* item_user_data_free)(void *))
{
	if (item_user_data_free && item->user_data) {
		item_user_data_free(item->user_data);
		item->user_data = NULL;
	}

	free(item);
}

static int compare_each_tag(cJSON *tag_obj, const struct rule_tag *accept_tags, size_t n_accept_tag)
{
    if (NULL == tag_obj || NULL == accept_tags) {
        return TAG_MATCH_ERR;
    }

	cJSON *tab_name_obj = cJSON_GetObjectItem(tag_obj, "tag");
	if (NULL == tab_name_obj || tab_name_obj->type != cJSON_String) {
		return TAG_MATCH_ERR;
	}

	const char *tag_name = tab_name_obj->valuestring;
	cJSON *tag_vals_array = cJSON_GetObjectItem(tag_obj, "value");
	if (NULL == tag_vals_array || tag_vals_array->type != cJSON_Array) {
		return TAG_MATCH_ERR;
	}

    int name_matched = 0;
	int n_val = cJSON_GetArraySize(tag_vals_array);
	for (size_t i = 0; i < n_accept_tag; i++) {
		if (0 != strcmp(accept_tags[i].tag_name, tag_name)) {
			continue;
		}
		name_matched++;

		for (int j = 0; j < n_val; j++) {
			cJSON *tag_val_obj = cJSON_GetArrayItem(tag_vals_array, j);
			if (NULL == tag_val_obj || tag_val_obj->type != cJSON_String) {
				return TAG_MATCH_ERR;
			}

			const char *tag_val = tag_val_obj->valuestring;
			// compare a/b/c with a/b/c/d is a miss.
			if (strlen(accept_tags[i].tag_val) < strlen(tag_val)) {
				continue;
			}

			// compare a1a2/b1/c1 with a1a2/b/ is a miss.
			//make sure the overlap is ended with a '/' 
            if (0 == strncmp(accept_tags[i].tag_val, tag_val, strlen(tag_val)) &&
				(strlen(accept_tags[i].tag_val) == strlen(tag_val) || accept_tags[i].tag_val[strlen(tag_val)] == '/')) {
				return TAG_MATCH_MATCHED;
			}
		}
	}

	//no matched name is considered as a 
	if (name_matched > 0) {
		return TAG_MATCH_UNMATCHED;
	} else {
		return TAG_MATCH_MATCHED;
	}
}

//@param tag_set likes [{"tag":"location","value":["北京/朝阳/华严北里","上海/浦东/陆家嘴"]},{"tag":"isp","value":["电信","移动"]}]
static int compare_each_tag_set(cJSON *tag_set, const struct rule_tag *accept_tags, size_t n_accept_tag)
{
	int matched = 0;

	int n_tag = cJSON_GetArraySize(tag_set);
	for (int i = 0; i < n_tag; i++) {
		cJSON *tag_obj = cJSON_GetArrayItem(tag_set, i);
		if (NULL == tag_obj || tag_obj->type != cJSON_Object) {
			return TAG_MATCH_ERR;
		}

		int ret = compare_each_tag(tag_obj,  accept_tags, n_accept_tag);
		if (ret < 0) {
			return TAG_MATCH_ERR;
		}

		if(1 == ret) {
			matched++;
		}
	}

	if (matched == n_tag) {
		return TAG_MATCH_MATCHED;
	} else {
		return TAG_MATCH_UNMATCHED;
	}
}

//@param value is a JSON, like {"tags":[{"tag":"location","value":"北京/朝阳/华严北里/甲22号},{"tag":"isp","value":"电信"}]}
size_t parse_accept_tag(const char *value, struct rule_tag **result, struct log_handle *logger)
{
    if (NULL == value || NULL == result || NULL == logger) {
        return 0;
    }

	cJSON *json = cJSON_Parse(value);
	if (!json) {
		log_error(logger, MODULE_MAAT_RULE,
				 "parse accept tag Error before: %-200.200s", cJSON_GetErrorPtr());
		return 0;
	}

	cJSON *tag = NULL, *tmp = NULL;
	cJSON *array = cJSON_GetObjectItem(json, "tags");
	int n_tag = cJSON_GetArraySize(array);
	struct rule_tag *p = ALLOC(struct rule_tag, n_tag);

	for (int i = 0; i < n_tag; i++) {
		tag = cJSON_GetArrayItem(array, i);
		tmp = cJSON_GetObjectItem(tag, "tag");
		p[i].tag_name = maat_strdup(tmp->valuestring);
		tmp = cJSON_GetObjectItem(tag, "value");
		p[i].tag_val = maat_strdup(tmp->valuestring);
	}

	cJSON_Delete(json);
	*result = p;
	return n_tag;
}

//@param value {"tag_sets":[[{"tag":"location","value":["北京/朝阳/华严北里","上海/浦东/陆家嘴"]},{"tag":"isp","value":["电信","移动"]}],[{"tag":"location","value":["北京"]},{"tag":"isp","value":["联通"]}]]}
//@return 1 on match, 0 on not match, -1 on error.
int compare_accept_tag(const char *value, const struct rule_tag *accept_tags, size_t n_accept_tag)
{
	int ret = TAG_MATCH_ERR;
    int n_set = 0;
    cJSON *tag_set = NULL;
    cJSON *tag_set_array = NULL;
    
	cJSON *root = cJSON_Parse(value);
	if (NULL == root) {
		goto error;
	}

	tag_set_array = cJSON_GetObjectItem(root, "tag_sets");
	if (NULL == tag_set_array || tag_set_array->type != cJSON_Array) {
		goto error;
	}

	n_set = cJSON_GetArraySize(tag_set_array);
	for (int i = 0; i < n_set; i++) {
		tag_set = cJSON_GetArrayItem(tag_set_array, i);
		if (NULL == tag_set || tag_set->type != cJSON_Array) {
			goto error;
		}

		ret = compare_each_tag_set(tag_set, accept_tags, n_accept_tag);
        //match or error occurs.
		if (ret != TAG_MATCH_UNMATCHED) {
			break;
		}
	}

error:
	cJSON_Delete(root);
	return ret;
}

struct maat_item_inner *maat_item_inner_new(int group_id, int item_id, int district_id)
{
	struct maat_item_inner *item = ALLOC(struct maat_item_inner, 1);
	item->magic_num = ITEM_RULE_MAGIC;
	item->item_id = item_id;
	item->group_id = group_id;
	item->district_id = district_id;

	return item;
}

void maat_item_inner_free(void *item_inner)
{
    if (NULL == item_inner) {
        return;
    }
    
    struct maat_item_inner *item = (struct maat_item_inner *)item_inner;
	assert(item->magic_num == ITEM_RULE_MAGIC);
	assert(item->expr_id_cnt == 0 || item->expr_id_cnt == item->expr_id_ub - item->expr_id_lb + 1);
	item->magic_num = 0;

	free(item);
}

struct maat_runtime* maat_runtime_create(long long version, struct maat *maat_instance)
{
	struct maat_runtime *maat_rt = ALLOC(struct maat_runtime, 1);

	maat_rt->version = version;
	int ret = table_manager_runtime_create(maat_instance->tbl_mgr, maat_instance->nr_worker_thread,
                                           maat_instance->garbage_bin);
    if (ret < 0) {
        FREE(maat_rt);
        return NULL;
    }

    maat_rt->ref_tbl_mgr = maat_instance->tbl_mgr;
	maat_rt->max_table_num = table_manager_table_count(maat_instance->tbl_mgr);

    maat_rt->logger = maat_instance->logger;
    maat_rt->ref_garbage_bin = maat_instance->garbage_bin;
    maat_rt->ref_cnt = alignment_int64_array_alloc(maat_instance->nr_worker_thread);
    
    return maat_rt;
}

void maat_runtime_commit(struct maat_runtime *maat_rt, struct log_handle *logger)
{
	for (size_t i = 0; i < maat_rt->max_table_num; i++) {
		table_manager_commit_runtime(maat_rt->ref_tbl_mgr, i);
	}

    maat_rt->last_update_time = time(NULL);
}

void maat_runtime_destroy(struct maat_runtime *maat_rt)
{
    if (NULL == maat_rt) {
        return;
    }

    if (maat_rt->ref_tbl_mgr != NULL) {
        table_manager_runtime_destroy(maat_rt->ref_tbl_mgr);
        maat_rt->ref_tbl_mgr = NULL;
    }

    FREE(maat_rt);
}

void maat_start_cb(long long new_version, int update_type, void *u_param)
{
	struct maat *maat_instance = (struct maat *)u_param;
	
	if (update_type == MAAT_UPDATE_TYPE_FULL) {
		maat_instance->creating_maat_rt = maat_runtime_create(new_version, maat_instance);
	} else {
		maat_instance->maat_version = new_version;
	}

	size_t table_cnt = table_manager_table_count(maat_instance->tbl_mgr);
	for (size_t i = 0; i < table_cnt; i++) {
		enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, i);
		if (table_type != TABLE_TYPE_PLUGIN) {
			continue;
		}

		void *schema = table_manager_get_schema(maat_instance->tbl_mgr, i);
		plugin_table_all_callback_start((struct plugin_schema *)schema, update_type);
	}
}

int maat_update_cb(const char *table_name, const char *line, void *u_param)
{
	if (NULL == table_name || NULL == line || NULL == u_param) {
		return 0;
	}
	
	struct maat *maat_instance =(struct maat *)u_param; 
	struct maat_runtime* maat_rt = NULL;
	int table_id = table_manager_get_table_id(maat_instance->tbl_mgr, table_name);
    if (table_id < 0) {
        log_error(maat_instance->logger, MODULE_MAAT_RULE, 
				  "update warning, unknown table name %s", table_name);
        return -1;
    }

	void *schema = table_manager_get_schema(maat_instance->tbl_mgr, table_id);
    if (NULL == schema) {
        log_error(maat_instance->logger, MODULE_MAAT_RULE, 
                  "update warning, table name %s doesn't have table schema", table_name);
        return -1;
    }
    
	if (maat_instance->creating_maat_rt != NULL) {
		maat_rt = maat_instance->creating_maat_rt;
	} else {
		maat_rt = maat_instance->maat_rt;
	}

	table_manager_update_runtime(maat_rt->ref_tbl_mgr, table_id, line);

	return 0;
}

uint32_t maat_runtime_rule_num(struct maat_runtime *maat_rt)
{
	uint32_t total = 0;
	void *runtime = NULL;
	
	for (size_t i = 0; i < maat_rt->max_table_num; i++) {
		runtime = table_manager_get_runtime(maat_rt->ref_tbl_mgr, i);
		if (runtime != NULL) {
            //TODO: by luis
			//total += table_runtime_rule_count(runtime);
		}
	}

	return total;
}

void maat_plugin_table_all_callback_finish(struct table_manager *tbl_mgr)
{
    size_t table_cnt = table_manager_table_count(tbl_mgr);
    enum table_type table_type = TABLE_TYPE_INVALID;

    for (size_t i = 0; i < table_cnt; i++) {
        table_type = table_manager_get_table_type(tbl_mgr, i);
        if (table_type != TABLE_TYPE_PLUGIN) {
            continue;
        }

        void *plugin_schema = table_manager_get_schema(tbl_mgr, i);
        plugin_table_all_callback_finish((struct plugin_schema *)plugin_schema);
    }
}

void maat_finish_cb(void *u_param)
{
	struct maat *maat_instance = (struct maat *)u_param;

    maat_plugin_table_all_callback_finish(maat_instance->tbl_mgr);

    if (maat_instance->creating_maat_rt != NULL) {
        maat_instance->creating_maat_rt->rule_num = maat_runtime_rule_num(maat_instance->creating_maat_rt);
        maat_runtime_commit(maat_instance->creating_maat_rt, maat_instance->logger);
        log_info(maat_instance->logger, MODULE_MAAT_RULE, 
                 "Full config version %llu load %d entries complete", 
                 maat_instance->creating_maat_rt->version, 
                 maat_instance->creating_maat_rt->rule_num);
    } else if (maat_instance->maat_rt != NULL) {
        maat_instance->maat_rt->rule_num = maat_runtime_rule_num(maat_instance->maat_rt);
        maat_instance->maat_rt->version = maat_instance->maat_version;
        maat_runtime_commit(maat_instance->maat_rt, maat_instance->logger);
        log_info(maat_instance->logger, MODULE_MAAT_RULE, 
                 "Inc config version %llu load %d entries complete", 
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
        log_info(maat_instance->logger, MODULE_MAAT_RULE, 
                 "Deferred Loading ON, updating in %s", __func__);
        maat_read_full_config(maat_instance);
    }
    pthread_mutex_unlock(&(maat_instance->background_update_mutex));

    char md5_tmp[MD5_DIGEST_LENGTH * 2 + 1] = {0};
    char err_str[NAME_MAX] = {0};
    struct stat attrib;
    while (maat_instance->is_running) {
        usleep(maat_instance->rule_update_checking_interval_ms * 1000);
		if (0 == pthread_mutex_trylock(&(maat_instance->background_update_mutex))) {
            log_info(maat_instance->logger, MODULE_MAAT_RULE,
                     "rule_monitor_loop.................%d", maat_instance->rule_update_checking_interval_ms * 1000);
			switch (maat_instance->input_mode) {
                case DATA_SOURCE_REDIS:
                    redis_monitor_traverse(maat_instance->maat_version,
                                            &(maat_instance->mr_ctx),
                                            maat_start_cb, maat_update_cb, maat_finish_cb,
                                            maat_instance);
                    break;
				case DATA_SOURCE_IRIS_FILE:
					config_monitor_traverse(maat_instance->maat_version, 
											maat_instance->iris_ctx.inc_idx_dir,
											maat_start_cb, maat_update_cb, maat_finish_cb,
											maat_instance, maat_instance->logger);
					break;
                case DATA_SOURCE_JSON_FILE:
                    memset(md5_tmp, 0, sizeof(md5_tmp));
				    stat(maat_instance->json_ctx.json_file, &attrib);
					if (memcmp(&attrib.st_ctim, &(maat_instance->json_ctx.last_md5_time), sizeof(attrib.st_ctim))) {
						maat_instance->json_ctx.last_md5_time = attrib.st_ctim;
						md5_file(maat_instance->json_ctx.json_file, md5_tmp);
						if (0 != strcmp(md5_tmp, maat_instance->json_ctx.effective_json_md5)) {
							ret = load_maat_json_file(maat_instance, maat_instance->json_ctx.json_file, 
                                                      err_str, sizeof(err_str));
							if (ret < 0) {
								log_error(maat_instance->logger, MODULE_MAAT_RULE, 
                                          "Maat re-initiate with JSON file %s (md5=%s)failed: %s\n",
										  maat_instance->json_ctx.json_file, md5_tmp, err_str);
							} else {
								config_monitor_traverse(0, maat_instance->json_ctx.iris_file,
														maat_start_cb, maat_update_cb, maat_finish_cb,
														maat_instance, maat_instance->logger);
								log_info(maat_instance->logger, MODULE_MAAT_RULE, 
                                         "Maat re-initiate with JSON file %s success, md5: %s\n",
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
                        log_info(maat_instance->logger, MODULE_MAAT_RULE, 
                                 "Maat version updated %lld -> %lld\n", 
                                 old_maat_rt->version, maat_instance->maat_rt->version);
                    } else {
                        log_info(maat_instance->logger, MODULE_MAAT_RULE, 
                                 "Maat version roll back %lld -> %lld\n",
                                 old_maat_rt->version, maat_instance->maat_rt->version);
                    }
                    maat_garbage_bagging(maat_instance->garbage_bin, old_maat_rt, 
                                         (void (*)(void*))maat_runtime_destroy);
				}

				maat_instance->creating_maat_rt = NULL;
				maat_instance->maat_version = maat_instance->maat_rt->version;
				maat_instance->last_full_version = maat_instance->maat_rt->version;
			}

			if (maat_instance->maat_rt != NULL) {
                time_t time_window = time(NULL) - maat_instance->maat_rt->last_update_time;
                
                if (time_window >= maat_instance->rule_effect_interval_ms / 1000) {
                    maat_runtime_commit(maat_instance->maat_rt, maat_instance->logger);
                    log_info(maat_instance->logger, MODULE_MAAT_RULE,
							 "Actual update config version %u, %d entries load to rulescan after postpone.",
							 maat_instance->maat_rt->version, maat_instance->maat_rt->rule_num);
                }
				
			}

			pthread_mutex_unlock(&(maat_instance->background_update_mutex));
		}
        maat_garbage_collect_routine(maat_instance->garbage_bin);
    }

    maat_runtime_destroy(maat_instance->maat_rt);
	maat_garbage_bin_free(maat_instance->garbage_bin);
	table_manager_destroy(maat_instance->tbl_mgr);

    alignment_int64_array_free(maat_instance->outer_state_cnt);
    alignment_int64_array_free(maat_instance->compile_state_cnt);
    alignment_int64_array_free(maat_instance->thread_call_cnt);
    alignment_int64_array_free(maat_instance->hit_cnt);
    alignment_int64_array_free(maat_instance->not_grp_hit_cnt);

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