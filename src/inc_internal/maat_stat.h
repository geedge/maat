/*
**********************************************************************************************
*	File: maat_stat.h
*   Description: maat statistics
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_STAT_H_
#define _MAAT_STAT_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "maat_rule.h"

struct maat_stat *maat_stat_new(const char *stat_file, size_t max_thread_num, 
                                struct log_handle *logger);

void maat_stat_free(struct maat_stat *stat);

int maat_stat_init(struct maat_stat *stat, struct table_manager *tbl_mgr, 
                    struct maat_garbage_bin *garbage_bin);

void maat_stat_output(struct maat_stat *stat, long long maat_version, int perf_on);

#ifdef __cplusplus
}
#endif

#endif