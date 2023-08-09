/*
**********************************************************************************************
*	File: maat_expr.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_EXPR_H_
#define _MAAT_EXPR_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "maat_rule.h"
#include "maat_table.h"
#include "cJSON/cJSON.h"

struct expr_runtime;

void *expr_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                      const char *table_name, struct log_handle *logger);
void expr_schema_free(void *expr_schema);

/* expr runtime API */
void *expr_runtime_new(void *expr_schema, size_t max_thread_num, 
                       struct maat_garbage_bin *garbage_bin, 
                       struct log_handle *logger);
void expr_runtime_free(void *expr_runtime);

int expr_runtime_update(void *expr_runtime, void *expr_schema, const char *table_name, 
                        const char *line, int valid_column);

int expr_runtime_commit(void *expr_runtime, const char *table_name, long long maat_rt_version);

long long expr_runtime_rule_count(void *expr_runtime);

long long expr_runtime_regex_rule_count(void *expr_runtime);

long long expr_runtime_get_version(void *expr_runtime);

/* expr runtime scan API */
/**
 * @brief scan string to get hit group_ids
 * 
 * @retval the num of hit group_id
*/
int expr_runtime_scan(struct expr_runtime *expr_rt, int thread_id, const char *data, 
                      size_t data_len, int vtable_id, struct maat_state *state);

struct adapter_hs_stream *expr_runtime_stream_open(struct expr_runtime *expr_rt, int thread_id);

int expr_runtime_stream_scan(struct expr_runtime *expr_rt, struct adapter_hs_stream *s_handle, 
                             const char *data, size_t data_len,
                             int vtable_id, struct maat_state *state);

void expr_runtime_stream_close(struct expr_runtime *expr_rt, int thread_id, 
                               struct adapter_hs_stream *s_handle);

int expr_runtime_set_scan_district(struct expr_runtime *expr_rt, const char *district, 
                                   size_t district_len, long long *district_id);

void expr_runtime_hit_inc(struct expr_runtime *expr_rt, int thread_id);

void expr_runtime_perf_stat(struct expr_runtime *flag_rt, size_t scan_len, 
                            struct timespec *start, struct timespec *end, 
                            int thread_id);

long long expr_runtime_scan_count(void *expr_runtime);

long long expr_runtime_scan_cpu_time(void *expr_runtime);

long long expr_runtime_hit_count(void *expr_runtime);

long long expr_runtime_update_err_count(void *expr_runtime);

long long expr_runtime_scan_bytes(struct expr_runtime *expr_rt);

#ifdef __cplusplus
}
#endif

#endif