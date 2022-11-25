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

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stddef.h>

struct maat_options {
    size_t nr_worker_threads;
    int rule_effect_interval_ms;
    int rule_update_checking_interval_ms;
    int gc_timeout_ms;
    int deferred_load_on;
    enum data_source input_mode;
    char iris_full_dir[NAME_MAX];
    char iris_inc_dir[NAME_MAX];
};

#ifdef __cpluscplus
}
#endif

#endif