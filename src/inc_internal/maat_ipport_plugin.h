/*
**********************************************************************************************
*	File: maat_ipport_plugin.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_IPPORT_PLUGIN_H_
#define _MAAT_IPPORT_PLUGIN_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "maat.h"
#include "cJSON/cJSON.h"
#include "maat_table.h"
#include "maat_ex_data.h"

struct ipport_plugin_runtime;

/* ipport plugin schema API */
void *ipport_plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                               const char *table_name, struct log_handle *logger);
void ipport_plugin_schema_free(void *ipport_plugin_schema);

/* ipport plugin table ex data API */
int ipport_plugin_table_set_ex_container_schema(void *ipport_plugin_schema, int table_id,
                                                maat_ex_new_func_t *new_func,
							                    maat_ex_free_func_t *free_func,
							                    maat_ex_dup_func_t *dup_func,
                                                void (*custom_data_free)(void *),
							                    long argl, void *argp);
struct ex_container_schema *
ipport_plugin_table_get_ex_container_schema(void *ipport_plugin_schema);

/* ipport plugin runtime API */
void *ipport_plugin_runtime_new(void *ipport_plugin_schema, size_t max_thread_num,
                                struct maat_garbage_bin *garbage_bin, 
                                struct log_handle *logger);
void ipport_plugin_runtime_free(void *ipport_plugin_runtime);

int ipport_plugin_runtime_update(void *ipport_plugin_runtime, void *ipport_plugin_schema, 
                                 const char *table_name, const char *line, int valid_column);

int ipport_plugin_runtime_commit(void *ipport_plugin_runtime, const char *table_name,
                                 long long maat_rt_version);

long long ipport_plugin_runtime_rule_count(void *ipport_plugin_runtime);

struct ex_data_runtime *ipport_plugin_runtime_get_ex_data_rt(void *ipport_plugin_runtime);

int ipport_plugin_runtime_get_ex_data(void *ipport_plugin_runtime, const struct ip_addr *ip_addr, 
                                      uint16_t port, void **ex_data_array, size_t n_ex_data_array);

long long ipport_plugin_runtime_update_err_count(void *ipport_plugin_runtime);

#ifdef __cplusplus
}
#endif

#endif