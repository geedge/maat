/*
**********************************************************************************************
*	File: maat_interval.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_INTERVAL_H_
#define _MAAT_INTERVAL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include "cJSON/cJSON.h"
#include "maat_table.h"

struct interval_runtime;

void *interval_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                          const char *table_name, struct log_handle *logger);
void interval_schema_free(void *interval_schema);

/* interval runtime API */
void *interval_runtime_new(void *interval_schema, size_t max_thread_num,
                           struct maat_garbage_bin *garbage_bin, 
                           struct log_handle *logger);
void interval_runtime_free(void *interval_runtime);

int interval_runtime_update(void *interval_runtime, void *interval_schema, const char *table_name,
                            const char *line, int valid_column);

int interval_runtime_commit(void *interval_runtime, const char *table_name, long long maat_rt_version);

long long interval_runtime_rule_count(void *interval_runtime);

/* interval runtime scan API */
/**
 * @brief scan interval to get hit group_ids
 * 
 * @retval the num of hit group_id
*/
int interval_runtime_scan(struct interval_runtime *interval_rt, int thread_id, 
                          long long integer, int vtable_id, struct maat_state *state);

int interval_runtime_set_scan_district(struct interval_runtime *interval_rt, const char *district, 
                                       size_t district_len, long long *district_id);
                                       
void interval_runtime_perf_stat(struct interval_runtime *interval_rt, struct timespec *start,
                                struct timespec *end, int thread_id);

long long interval_runtime_scan_times(void *interval_runtime);

long long interval_runtime_scan_cpu_time(void *interval_runtime);

void interval_runtime_hit_times_inc(struct interval_runtime *interval_rt, int thread_id);

long long interval_runtime_hit_times(void *interval_runtime);

long long interval_runtime_hit_item_num(void *interval_runtime);

long long interval_runtime_update_err_cnt(void *interval_runtime);

#ifdef __cplusplus
}
#endif

#endif
