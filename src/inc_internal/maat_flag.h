/*
**********************************************************************************************
*	File: maat_flag.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_FLAG_H_
#define _MAAT_FLAG_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdint.h>

#include "log/log.h"
#include "cJSON/cJSON.h"

struct flag_runtime;

void *flag_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                      const char *table_name, struct log_handle *logger);
void flag_schema_free(void *flag_schema);

/* flag runtime API */
void *flag_runtime_new(void *flag_schema, int max_thread_num, 
                       struct maat_garbage_bin *garbage_bin,
                       struct log_handle *logger);
void flag_runtime_free(void *flag_runtime);

int flag_runtime_update(void *flag_runtime, void *flag_schema, 
                        const char *line, int valid_column);
int flag_runtime_commit(void *flag_runtime, const char *table_name);

/* flag runtime scan API */
/**
 * @brief scan flag to get hit group_ids
 * 
 * @retval the num of hit group_id
*/
int flag_runtime_scan_flag(struct flag_runtime *flag_rt, int thread_id, 
                           uint64_t flag, int *group_ids, size_t group_ids_size, 
                           int vtable_id, struct maat_state *state);

void flag_runtime_scan_hit_inc(struct flag_runtime *flag_rt, int thread_id);
long long flag_runtime_scan_hit_sum(struct flag_runtime *flag_rt, int n_thread);

#ifdef __cpluscplus
}
#endif

#endif
