/*
**********************************************************************************************
*	File: maat_bool_plugin.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
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
#include "cJSON/cJSON.h"

struct bool_plugin_runtime;

/* bool plugin schema API */
void *bool_plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger);
void bool_plugin_schema_free(void *bool_plugin_schema);

/* ip plugin table ex data API */
struct ex_data_schema *bool_plugin_table_get_ex_data_schema(void *bool_plugin_schema);

int bool_plugin_table_set_ex_data_schema(void *bool_plugin_schema, 
                                         maat_ex_new_func_t *new_func,
							             maat_ex_free_func_t *free_func,
							             maat_ex_dup_func_t *dup_func,
							             long argl, void *argp,
                                         struct log_handle *logger);

/* ip plugin runtime API */
void *bool_plugin_runtime_new(void *bool_plugin_schema, int max_thread_num,
                              struct maat_garbage_bin *garbage_bin,
                              struct log_handle *logger);
void bool_plugin_runtime_free(void *bool_plugin_runtime);

int bool_plugin_runtime_update(void *bool_plugin_runtime, void *bool_plugin_schema, 
                                const char *table_name, const char *line, int valid_column);
int bool_plugin_runtime_commit(void *bool_plugin_runtime, const char *table_name);

struct ex_data_runtime *bool_plugin_runtime_get_ex_data_rt(void *bool_plugin_runtime);

int bool_plugin_runtime_get_ex_data(void *bool_plugin_runtime, void *bool_plugin_schema,
                                    unsigned long long *item_ids, size_t n_item, 
                                    void **ex_data_array, size_t n_ex_data);

#ifdef __cplusplus
}
#endif

#endif
