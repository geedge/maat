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

#include "maat_utils.h"
#include "maat_rule.h"
#include "maat_common.h"
#include "maat_table_schema.h"
#include "maat_table_runtime.h"
#include "sds/sds.h"

struct maat_options* maat_options_new(void)
{
    struct maat_options *options = ALLOC(struct maat_options, 1);

    options->nr_worker_threads = 1;

    return options;
}

int maat_options_set_worker_thread_number(struct maat_options *opts, size_t n_worker_threads)
{
    opts->nr_worker_threads = n_worker_threads;
    
    return 0;
}

struct maat *maat_new(struct maat_options opts, const char *table_info_path)
{
    #if 0
    if (NULL == table_info_path) {
        return NULL;
    }

    struct maat *maat_instance = ALLOC(struct maat, 1);
    
    maat_instance->table_mgr = maat_table_manager_create(table_info_path);
    maat_instance->is_running = 0;
    maat_instance->maat_version = 0;
    maat_instance->last_full_version = 0;
    maat_instance->nr_worker_thread = opts.nr_worker_threads;

    pthread_create(&(maat_instance->cfg_mon_thread), NULL, rule_monitor_loop, (void*)maat_instance);

    return maat_instance;
    #endif
    return NULL;
}

void maat_free(struct maat *maat_instance)
{

    void* ret = NULL;
	pthread_join(maat_instance->cfg_mon_thread, &ret);

	return;
}

int maat_table_get_id(struct maat *instance, const char *table_name)
{
    return 0;
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
    #if 0
    if (NULL == maat_instance || NULL == data ) {
        return -1;
    }
    
    struct maat_runtime *maat_rt = maat_instance->maat_rt;
    
    struct maat_table_runtime *table_rt = maat_table_runtime_get(maat_rt->table_rt_mgr, table_id);
    #endif
    return 0;
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