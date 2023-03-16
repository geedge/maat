/*
**********************************************************************************************
*	File: maat_common.h
*   Description: maat common entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_COMMON_H_
#define _MAAT_COMMON_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <limits.h>

#include "log/log.h"
#include "maat_rule.h"

struct maat_options {
    char instance_name[NAME_MAX];
    char foreign_cont_dir[NAME_MAX];
    char log_path[PATH_MAX];
    size_t nr_worker_threads;
    char *accept_tags;
    int rule_effect_interval_ms;
    int rule_update_checking_interval_ms;
    int gc_timeout_ms;
    int deferred_load_on;
    int log_level;
    enum data_source input_mode;
    union {
        struct source_iris_ctx iris_ctx;
        struct source_json_ctx json_ctx;
        struct source_redis_ctx redis_ctx;
    };
};

#ifdef __cplusplus
}
#endif

#endif