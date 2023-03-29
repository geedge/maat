/*
**********************************************************************************************
*	File: maat_fqdn_plugin.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_FQDN_PLUGIN_H_
#define _MAAT_FQDN_PLUGIN_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "maat.h"
#include "maat_table.h"
#include "cJSON/cJSON.h"

struct fqdn_plugin_runtime;

/* fqdn plugin schema API */
void *fqdn_plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger);
void fqdn_plugin_schema_free(void *fqdn_plugin_schema);

/* fqdn plugin table ex data API */
struct ex_data_schema *fqdn_plugin_table_get_ex_data_schema(void *fqdn_plugin_schema);

int fqdn_plugin_table_set_ex_data_schema(void *fqdn_plugin_schema, 
                                         maat_ex_new_func_t *new_func,
							             maat_ex_free_func_t *free_func,
							             maat_ex_dup_func_t *dup_func,
							             long argl, void *argp,
                                         struct log_handle *logger);

/* fqdn plugin runtime API */
void *fqdn_plugin_runtime_new(void *fqdn_plugin_schema, int max_thread_num,
                              struct maat_garbage_bin *garbage_bin,
                              struct log_handle *logger);
void fqdn_plugin_runtime_free(void *fqdn_plugin_runtime);

int fqdn_plugin_runtime_update(void *fqdn_plugin_runtime, void *fqdn_plugin_schema, 
                                const char *table_name, const char *line, int valid_column);
int fqdn_plugin_runtime_commit(void *fqdn_plugin_runtime, const char *table_name);

struct ex_data_runtime *fqdn_plugin_runtime_get_ex_data_rt(void *fqdn_plugin_runtime);

int fqdn_plugin_runtime_get_ex_data(void *fqdn_plugin_runtime, void *fqdn_plugin_schema,
                                    const char *fqdn, void **ex_data_array, size_t n_ex_data);
#ifdef __cplusplus
}
#endif

#endif
