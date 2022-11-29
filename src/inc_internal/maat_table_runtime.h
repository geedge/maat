/*
**********************************************************************************************
*	File: maat_table_runtime.h
*   Description: maat table runtime entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_TABLE_RUNTIME_H_
#define _MAAT_TABLE_RUNTIME_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include "maat_table_schema.h"
#include "maat_garbage_collection.h"

struct table_item;
struct table_runtime;
struct table_runtime_manager;

/* table runtime manager API */
struct table_runtime_manager *table_runtime_manager_create(struct table_schema_manager *table_schema_mgr, int max_thread_num, 
                                                           struct maat_garbage_bin *bin);

void table_runtime_manager_destroy(struct table_runtime_manager *table_rt_mgr);

/* table runtime API */
struct table_runtime *table_runtime_get(struct table_runtime_manager *table_rt_mgr, int table_id);

size_t table_runtime_rule_count(struct table_runtime *table_rt);

enum table_type table_runtime_get_type(struct table_runtime* table_rt);

void table_runtime_update(struct table_runtime *table_rt, struct table_schema *table_schema, const char *line, struct table_item *table_item);

/**
 * @brief if table_runtime is updating
 * 
 * @retval 1(yes) 0(no)
*/
int table_runtime_updating_flag(struct table_runtime *table_rt);

void table_runtime_commit(struct table_runtime *table_rt, size_t nr_worker_thread);

/* table runtime scan API */
int table_runtime_scan_string(struct table_runtime *table_rt, int thread_id, const char *data, size_t data_len, 
                              int results[], size_t *n_result);

void table_runtime_stream_open(struct table_runtime *table_rt, int thread_id);
int table_runtime_scan_stream(struct table_runtime *table_rt, const char *data, size_t data_len,
                              int result[], size_t n_result);
void table_runtime_stream_close(struct table_runtime *table_rt);

/* table runtime cached row API */
size_t table_runtime_cached_row_count(struct table_runtime *table_rt);

const char* table_runtime_get_cached_row(struct table_runtime *table_rt, size_t row_seq);

/* table runtime ex data API */
void *table_runtime_get_ex_data(struct table_runtime *table_rt, struct table_schema *table_schema, const char *key, size_t key_len);

void table_runtime_commit_ex_data_schema(struct table_runtime *table_rt, struct table_schema *table_schema);

#ifdef __cpluscplus
}
#endif

#endif