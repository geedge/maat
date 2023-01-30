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

#ifdef __cpluscplus
extern "C"
{
#endif

#include "log/log.h"
#include "cJSON/cJSON.h"

struct expr_runtime;

void *expr_schema_new(cJSON *json, const char *table_name, struct log_handle *logger);
void expr_schema_free(void *expr_schema);

/* expr runtime API */
void *expr_runtime_new(void *expr_schema, struct maat_garbage_bin *garbage_bin, struct log_handle *logger);
void expr_runtime_free(void *expr_runtime);

int expr_runtime_updating_flag(struct expr_runtime *expr_rt);
int expr_runtime_update(void *expr_runtime, void *expr_schema, const char *line, int valid_column);
int expr_runtime_commit(void *expr_runtime);

/* expr runtime scan API */
/**
 * @brief scan string to get hit group_ids
 * 
 * @retval the num of hit group_id
*/
int expr_runtime_scan_string(struct expr_runtime *expr_rt, int thread_id, 
                             const char *data, size_t data_len, int group_ids[], 
                             size_t max_hit_num, int virtual_table_id, 
                             struct maat_state *state);

void expr_runtime_stream_open(struct expr_runtime *expr_rt, int thread_id);
int expr_runtime_scan_stream(struct expr_runtime *expr_rt, const char *data, size_t data_len, int results[], size_t *n_result);
void expr_runtime_stream_close(struct expr_runtime *expr_rt);

#ifdef __cpluscplus
}
#endif

#endif
