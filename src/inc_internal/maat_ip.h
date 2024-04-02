/*
**********************************************************************************************
*	File: maat_ip.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_IP_H_
#define _MAAT_IP_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "cJSON/cJSON.h"
#include "maat_table.h"

struct ip_runtime;

void *ip_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                    const char *table_name, struct log_handle *logger);
void ip_schema_free(void *ip_schema);

/* ip runtime API */
void *ip_runtime_new(void *ip_schema, size_t max_thread_num,
                     struct maat_garbage_bin *garbage_bin, 
                     struct log_handle *logger);
void ip_runtime_free(void *ip_runtime);

int ip_runtime_update(void *ip_runtime, void *ip_schema, const char *table_name, 
                      const char *line, int valid_column);

int ip_runtime_commit(void *ip_runtime, const char *table_name, long long maat_rt_version);

long long ip_runtime_rule_count(void *ip_runtime);

long long ip_runtime_ipv6_rule_count(void *ip_runtime);

/* ip runtime scan API */
int ip_runtime_scan(struct ip_runtime *ip_rt, int thread_id, int ip_type, 
                    uint8_t *ip_addr, int port, int vtable_id, struct maat_state *state);

void ip_runtime_perf_stat(struct ip_runtime *ip_rt, struct timespec *start,
                          struct timespec *end, int thread_id);

void ip_runtime_scan_times_inc(struct ip_runtime *ip_rt, int thread_id);

long long ip_runtime_scan_times(void *ip_runtime);

long long ip_runtime_scan_cpu_time(void *ip_runtime);

void ip_runtime_hit_times_inc(struct ip_runtime *ip_rt, int thread_id);

long long ip_runtime_hit_times(void *ip_runtime);

long long ip_runtime_hit_item_num(void *ip_runtime);

long long ip_runtime_update_err_count(void *ip_runtime);

#ifdef __cplusplus
}
#endif

#endif
