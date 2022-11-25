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
    long long version;

    time_t last_update_time;

    struct table_runtime_manager *table_rt_mgr;
    size_t max_table_num;
    
    size_t max_thread_num;
    uint32_t rule_num;
};

enum data_source {
    DATA_SOURCE_NONE = 0,
    DATA_SOURCE_IRIS_FILE
};

struct source_iris_ctx {
    char inc_dir[NAME_MAX];
    char full_dir[NAME_MAX];
};

struct maat {
    char instance_name[NAME_MAX];

    struct maat_runtime *maat_rt;
    struct maat_runtime *creating_maat_rt;

    struct table_schema_manager *table_schema_mgr;

    enum data_source input_mode;
    union {
        struct source_iris_ctx iris_ctx;
    };
    
    int deferred_load;

    int is_running;
    pthread_mutex_t background_update_mutex;
    int nr_worker_thread;
    
    long long maat_version;
    long long last_full_version;
    pthread_t cfg_mon_thread;

    int rule_effect_interval_ms;
    int rule_update_checking_interval_ms;
    int gc_timeout_ms; //garbage collection timeout_ms;

    struct maat_garbage_bin *garbage_bin;
};

void maat_start_cb(long long new_version, int update_type, void *u_para);

int maat_update_cb(const char *table_name, const char *line, void *u_para);

void maat_finish_cb(void *u_para);

void *rule_monitor_loop(void *arg);

void maat_read_full_config(struct maat *maat_instance);

#ifdef __cpluscplus
}
#endif

#endif