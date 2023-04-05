/*
**********************************************************************************************
*	File: maat_plugin.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_PLUGIN_H_
#define _MAAT_PLUGIN_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "cJSON/cJSON.h"
#include "maat.h"
#include "maat_ex_data.h"

#define	MAX_FOREIGN_CLMN_NUM 8

/* plugin schema API */
void *plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                        const char *table_name, struct log_handle *logger);
void plugin_schema_free(void *plugin_schema);

struct plugin_schema;
/* plugin table callback API */
int plugin_table_add_callback(void *plugin_schema, int table_id,
                        	  maat_start_callback_t *start,
							  maat_update_callback_t *update,
							  maat_finish_callback_t *finish,
							  void *u_para, struct log_handle *logger);

void plugin_table_all_callback_start(struct plugin_schema *plugin_schema, int update_type);
void plugin_table_all_callback_finish(struct plugin_schema *plugin_schema);

int plugin_table_get_foreign_column(struct plugin_schema *plugin_schema, int *foreign_columns);

/* plugin table ex data API */
int plugin_table_set_ex_container_schema(void *plugin_schema, int table_id,
                                         maat_ex_new_func_t *new_func,
							             maat_ex_free_func_t *free_func,
							             maat_ex_dup_func_t *dup_func,
                                         void (*custom_data_free)(void *),
							             long argl, void *argp);
struct ex_container_schema *plugin_table_get_ex_container_schema(void *plugin_schema);

/* plugin runtime API */
void *plugin_runtime_new(void *plugin_schema, int max_thread_num, 
                         struct maat_garbage_bin *garbage_bin,
                         struct log_handle *logger);
void plugin_runtime_free(void *plugin_runtime);

int plugin_runtime_update(void *plugin_runtime, void *plugin_schema, 
                          const char *table_name, const char *line, 
                          int valid_column);
int plugin_runtime_commit(void *plugin_runtime, const char *table_name);

struct ex_data_runtime *plugin_runtime_get_ex_data_rt(void *plugin_runtime);

size_t plugin_runtime_cached_row_count(void *plugin_runtime);

const char *plugin_runtime_cached_row_get(void *plugin_runtime, size_t index);

void *plugin_runtime_get_ex_data(void *plugin_runtime, void *plugin_schema,
                                 const char *key, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif