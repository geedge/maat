/*
**********************************************************************************************
*	File: maat_ip_plugin.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_IP_PLUGIN_H_
#define _MAAT_IP_PLUGIN_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include "log/log.h"
#include "maat/maat.h"
#include "cJSON/cJSON.h"

struct ip_plugin_runtime;

/* ip plugin schema API */
void *ip_plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                           const char *table_name, struct log_handle *logger);
void ip_plugin_schema_free(void *ip_plugin_schema);

/* ip plugin table ex data API */
struct ex_data_schema *ip_plugin_table_get_ex_data_schema(void *ip_plugin_schema);

int ip_plugin_table_set_ex_data_schema(void *ip_plugin_schema, 
                                       maat_plugin_ex_new_func_t *new_func,
							           maat_plugin_ex_free_func_t *free_func,
							           maat_plugin_ex_dup_func_t *dup_func,
							           long argl, void *argp,
                                       struct log_handle *logger);

/* ip plugin runtime API */
void *ip_plugin_runtime_new(void *ip_plugin_schema, int max_thread_num,
                            struct maat_garbage_bin *garbage_bin,
                            struct log_handle *logger);
void ip_plugin_runtime_free(void *ip_plugin_runtime);

int ip_plugin_runtime_update(void *ip_plugin_runtime, void *ip_plugin_schema, 
                             const char *line, int valid_column);
int ip_plugin_runtime_commit(void *ip_plugin_runtime, const char *table_name);

struct ex_data_runtime *ip_plugin_runtime_get_ex_data_rt(void *ip_plugin_runtime);

#ifdef __cpluscplus
}
#endif

#endif