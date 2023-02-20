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
#include "cJSON/cJSON.h"

struct expr_runtime;
struct table_manager;
struct log_handle;
struct maat_garbage_bin;

void *expr_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                      const char *table_name, struct log_handle *logger);
void expr_schema_free(void *expr_schema);

/* expr runtime API */
void *expr_runtime_new(void *expr_schema, int max_thread_num, 
                       struct maat_garbage_bin *garbage_bin,
                       struct log_handle *logger);
void expr_runtime_free(void *expr_runtime);

int expr_runtime_update(void *expr_runtime, void *expr_schema, 
                        const char *line, int valid_column);
int expr_runtime_commit(void *expr_runtime, const char *table_name);

/* expr runtime scan API */
/**
 * @brief scan string to get hit group_ids
 * 
 * @retval the num of hit group_id
*/
int expr_runtime_scan(struct expr_runtime *expr_rt, int thread_id, const char *data, 
                      size_t data_len, int *group_ids, int hit_group_index,
                      size_t group_ids_size, int vtable_ids, struct maat_state *state);

void expr_runtime_stream_open(struct expr_runtime *expr_rt, int thread_id);
int expr_runtime_stream_scan(struct expr_runtime *expr_rt, const char *data, size_t data_len, 
                             int *group_ids, int hit_group_index, size_t group_ids_size, 
                             int vtable_id, struct maat_state *state);
void expr_runtime_stream_close(struct expr_runtime *expr_rt);

void expr_runtime_scan_hit_inc(struct expr_runtime *expr_rt, int thread_id);
long long expr_runtime_scan_hit_sum(struct expr_runtime *expr_rt, int n_thread);

#ifdef __cplusplus
}
#endif

#endif
