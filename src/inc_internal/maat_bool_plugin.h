/*
**********************************************************************************************
*	File: maat_bool_plugin.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_BOOL_PLUGIN_H_
#define _MAAT_BOOL_PLUGIN_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "maat.h"
#include "maat_table.h"
#include "maat_ex_data.h"
#include "cJSON/cJSON.h"

struct bool_plugin_runtime;

/* bool plugin schema API */
void *bool_plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger);
void bool_plugin_schema_free(void *bool_plugin_schema);

int bool_plugin_table_set_ex_container_schema(void *bool_plugin_schema, int table_id,
                                              maat_ex_new_func_t *new_func,
							                  maat_ex_free_func_t *free_func,
							                  maat_ex_dup_func_t *dup_func,
                                              void (*custom_data_free)(void *),
							                  long argl, void *argp);
struct ex_container_schema *bool_plugin_table_get_ex_container_schema(void *bool_plugin_schema);

/* ip plugin runtime API */
void *bool_plugin_runtime_new(void *bool_plugin_schema, size_t max_thread_num,
                              struct maat_garbage_bin *garbage_bin, 
                              struct log_handle *logger);
void bool_plugin_runtime_free(void *bool_plugin_runtime);

int bool_plugin_runtime_update(void *bool_plugin_runtime, void *bool_plugin_schema, 
                                const char *table_name, const char *line, int valid_column);

int bool_plugin_runtime_commit(void *bool_plugin_runtime, const char *table_name,
                               long long maat_rt_version);

long long bool_plugin_runtime_rule_count(void *bool_plugin_runtime);

struct ex_data_runtime *bool_plugin_runtime_get_ex_data_rt(void *bool_plugin_runtime);

int bool_plugin_runtime_get_ex_data(void *bool_plugin_runtime, unsigned long long *item_ids, 
                                    size_t n_item, void **ex_data_array, size_t n_ex_data);

long long bool_plugin_runtime_update_err_count(void *bool_plugin_runtime);

void bool_plugin_runtime_scan_inc(void *bool_plugin_runtime, int thread_id);

long long bool_plugin_runtime_scan_count(void *bool_plugin_runtime);

#ifdef __cplusplus
}
#endif

#endif
