/*
**********************************************************************************************
*	File: maat_interval.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_INTERVAL_H_
#define _MAAT_INTERVAL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include "maat_rule.h"
#include "cJSON/cJSON.h"

struct interval_runtime;
struct table_manager;
struct log_handle;
struct maat_garbage_bin;

void *interval_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                          const char *table_name, struct log_handle *logger);
void interval_schema_free(void *interval_schema);

/* interval runtime API */
void *interval_runtime_new(void *interval_schema, int max_thread_num, 
                           struct maat_garbage_bin *garbage_bin,
                           struct log_handle *logger);
void interval_runtime_free(void *interval_runtime);

int interval_runtime_update(void *interval_runtime, void *interval_schema, 
                            const char *line, int valid_column);
int interval_runtime_commit(void *interval_runtime, const char *table_name);

/* interval runtime scan API */
/**
 * @brief scan intval to get hit group_ids
 * 
 * @retval the num of hit group_id
*/
int interval_runtime_scan(struct interval_runtime *interval_rt, int thread_id, 
                          uint64_t integer, int *group_ids, int hit_group_index, 
                          size_t group_ids_size, int vtable_id, struct maat_state *state);

void interval_runtime_scan_hit_inc(struct interval_runtime *interval_rt, int thread_id);
long long interval_runtime_scan_hit_sum(struct interval_runtime *interval_rt, int n_thread);

#ifdef __cplusplus
}
#endif

#endif
