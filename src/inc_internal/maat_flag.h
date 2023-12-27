/*
**********************************************************************************************
*	File: maat_flag.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_FLAG_H_
#define _MAAT_FLAG_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include "maat_rule.h"
#include "cJSON/cJSON.h"
#include "maat_table.h"

struct flag_runtime;

void *flag_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                      const char *table_name, struct log_handle *logger);
void flag_schema_free(void *flag_schema);

/* flag runtime API */
void *flag_runtime_new(void *flag_schema, size_t max_thread_num,
                       struct maat_garbage_bin *garbage_bin, 
                       struct log_handle *logger);
void flag_runtime_free(void *flag_runtime);

int flag_runtime_update(void *flag_runtime, void *flag_schema, const char *table_name, 
                        const char *line, int valid_column);

int flag_runtime_commit(void *flag_runtime, const char *table_name, long long maat_rt_version);

long long flag_runtime_rule_count(void *flag_runtime);

/* flag runtime scan API */
/**
 * @brief scan flag to get hit group_ids
 * 
 * @retval the num of hit group_id
*/
int flag_runtime_scan(struct flag_runtime *flag_rt, int thread_id, long long flag,
                      int vtable_id, struct maat_state *state);

int flag_runtime_set_scan_district(struct flag_runtime *flag_rt, const char *district, 
                                    size_t district_len, long long *district_id);



void flag_runtime_perf_stat(struct flag_runtime *flag_rt, struct timespec *start,
                            struct timespec *end, int thread_id);

long long flag_runtime_scan_times(void *flag_runtime);

long long flag_runtime_scan_cpu_time(void *flag_runtime);

long long flag_runtime_hit_times(void *flag_runtime);

void flag_runtime_hit_times_inc(struct flag_runtime *flag_rt, int thread_id);

long long flag_runtime_hit_item_num(void *flag_runtime);

long long flag_runtime_update_err_count(void *flag_runtime);

#ifdef __cplusplus
}
#endif

#endif
