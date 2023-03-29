/*
**********************************************************************************************
*	File: maat_expr.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
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
void *expr_runtime_new(void *expr_schema, int max_thread_num, 
                       struct maat_garbage_bin *garbage_bin,
                       struct log_handle *logger);
void expr_runtime_free(void *expr_runtime);

int expr_runtime_update(void *expr_runtime, void *expr_schema, 
                         const char *table_name, const char *line, 
                         int valid_column);
int expr_runtime_commit(void *expr_runtime, const char *table_name);

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
void expr_runtime_stream_close(struct adapter_hs_stream *s_handle);

void expr_runtime_scan_hit_inc(struct expr_runtime *expr_rt, int thread_id);
long long expr_runtime_scan_hit_sum(struct expr_runtime *expr_rt, int n_thread);

#ifdef __cplusplus
}
#endif

#endif
