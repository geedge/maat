/*
**********************************************************************************************
*	File: maat_ip.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_IP_H_
#define _MAAT_IP_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "cJSON/cJSON.h"

struct ip_runtime;
struct table_manager;
struct log_handle;
struct maat_garbage_bin;

void *ip_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                    const char *table_name, struct log_handle *logger);
void ip_schema_free(void *ip_schema);

/* ip runtime API */
void *ip_runtime_new(void *ip_schema, int max_thread_num, 
                     struct maat_garbage_bin *garbage_bin,
                     struct log_handle *logger);
void ip_runtime_free(void *ip_runtime);

int ip_runtime_update(void *ip_runtime, void *ip_schema, 
                      const char *line, int valid_column);
int ip_runtime_commit(void *ip_runtime, const char *table_name);

struct ex_data_runtime *ip_runtime_get_ex_data_rt(struct ip_runtime *ip_rt);

/* ip runtime scan API */
int ip_runtime_scan(struct ip_runtime *ip_rt, int thread_id, int ip_type, 
                    uint8_t *ip_addr, int vtable_id, struct maat_state *state);

void ip_runtime_scan_hit_inc(struct ip_runtime *ip_rt, int thread_id);
long long ip_runtime_scan_hit_sum(struct ip_runtime *ip_rt, int n_thread);

#ifdef __cplusplus
}
#endif

#endif
