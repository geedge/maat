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
#include <pthread.h>
#include <limits.h>

#include "maat_rule.h"
#include "maat_config_monitor.h"
#include "maat_utils.h"
#include "maat_table_runtime.h"
#include "maat_table_schema.h"

struct maat_runtime* create_maat_runtime(uint64_t version, struct maat *maat_instance)
{
	struct maat_runtime *maat_rt = ALLOC(struct maat_runtime, 1);

	maat_rt->version = version;
	maat_rt->table_rt_mgr = maat_table_runtime_manager_create(maat_instance->table_mgr);
	maat_rt->max_table_num = maat_table_manager_get_size(maat_instance->table_mgr);
}

void update_maat_runtime(struct maat_runtime *maat_rt)
{
	for (size_t i = 0; i < maat_rt->max_table_num; i++) {
		struct maat_table_runtime *table_rt = maat_table_runtime_get(maat_rt->table_rt_mgr, i);
		if (NULL == table_rt) {
			continue;
		}

		enum maat_table_type table_type = maat_table_runtime_get_type(table_rt);
	}
}

void destroy_maat_runtime(struct maat_runtime *maat_rt)
{

}

void maat_start_cb(uint64_t new_version, int update_type, void *u_param)
{
	struct maat *maat_instance = (struct maat *)u_param;
	
	if (update_type == CONFIG_UPDATE_TYPE_FULL) {
		maat_instance->rebuilding_maat_rt = create_maat_runtime(new_version, maat_instance);
	} else {
		maat_instance->maat_version = new_version;
	}
}

int maat_update_cb(const char* table_name, const char* line, void *u_param)
{
	struct maat *maat_instance =(struct maat *)u_param; 
	struct maat_runtime* maat_rt = NULL;
	int table_id = maat_table_manager_get_table_id(maat_instance->table_mgr, table_name);
	struct maat_table_schema* ptable = maat_table_manager_get_table_desc(maat_instance->table_mgr, table_id);

	if (maat_instance->rebuilding_maat_rt != NULL) {
		maat_rt = maat_instance->rebuilding_maat_rt;
	} else {
		maat_rt = maat_instance->maat_rt;
	}

	//TODO: update rule for table_schema
	update_maat_runtime();
	return 0;
}

void maat_finish_cb(void *u_param)
{
	struct maat *maat_instance = (struct maat *)u_param;

    if (maat_instance->latest_maat_rt != NULL) {
        update_maat_runtime(maat_instance->latest_maat_rt);
    }

    //

}

void *rule_monitor_loop(void *arg)
{
	char err_str[NAME_MAX] = {0};
    struct maat *maat_instance = (struct maat *)arg;

    while (maat_instance->is_running) {
        usleep(1000 * 1000);
		if( 0 == pthread_mutex_trylock(&(maat_instance->background_update_mutex))) {
			switch (maat_instance->rule_import_type) {
				case RULE_IMPORT_TYPE_IRIS:
					config_monitor_traverse(maat_instance->maat_version, 
											maat_instance->iris_ctx.inc_dir,
											maat_start_cb,
											maat_update_cb,
											maat_finish_cb,
											maat_instance);
					break;
				default:
					break;
			}

			if (maat_instance->latest_maat_rt != NULL) {
				struct maat_runtime *old_maat_rt = maat_instance->maat_rt;
				maat_instance->maat_rt = maat_instance->latest_maat_rt;

				if (old_maat_rt != NULL) {

				}

				maat_instance->latest_maat_rt = NULL;
				maat_instance->maat_version = maat_instance->maat_rt->version;
				maat_instance->last_full_version = maat_instance->maat_rt->version;
			}

			if (maat_instance->maat_rt != NULL) {
				update_maat_runtime(maat_instance->maat_rt);
			}

			pthread_mutex_unlock(&(maat_instance->background_update_mutex));
		}
        
    }
}