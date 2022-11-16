/*
**********************************************************************************************
*	File: maat_rule.h
*   Description: maat rule entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_RULE_H_
#define _MAAT_RULE_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <sys/time.h>
#include <pthread.h>

struct maat_runtime {
    /* maat_runtime can be created and destroy dynamic, so need version info */
    uint64_t version;

    time_t last_update_time;

    struct maat_table_runtime_manager *table_rt_mgr;
    size_t max_table_num;
    
    int max_thread_num;
    uint32_t rule_num;
};

enum rule_import_type {
    RULE_IMPORT_TYPE_IRIS = 1,
    RULE_IMPORT_TYPE_MAX
};

struct rule_import_iris_ctx {
    char inc_dir[NAME_MAX];
    char full_dir[NAME_MAX];
};

struct maat {
    struct maat_runtime *maat_rt;
    struct maat_runtime *rebuilding_maat_rt; //TODO: creating
    //struct maat_garbage_collector *gc;
    struct maat_table_manager *table_mgr;

    enum rule_import_type rule_import_type;
    union {
        struct rule_import_iris_ctx iris_ctx;
    };
    
    int is_running;
    pthread_mutex_t background_update_mutex;
    int nr_worker_thread;
    
    uint64_t maat_version;
    uint64_t last_full_version;
    pthread_t cfg_mon_thread;
};

void *rule_monitor_loop(void *arg);

#ifdef __cpluscplus
}
#endif

#endif