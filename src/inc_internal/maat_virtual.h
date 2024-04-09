/*
**********************************************************************************************
*	File: maat_virtual.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_VIRTUAL_H_
#define _MAAT_VIRTUAL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "cJSON/cJSON.h"
#include "maat_table.h"

struct virtual_runtime;

void *virtual_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                         const char *table_name, struct log_handle *logger);

void virtual_schema_free(void *virtual_schema);

void *virtual_runtime_new(void *virtual_schema, size_t max_thread_num,
                          struct maat_garbage_bin *garbage_bin,
                          struct log_handle *logger);

void virtual_runtime_free(void *virtual_runtime);

void virtual_runtime_scan_times_inc(struct virtual_runtime *virt_rt,
                                    int thread_id);

void virtual_runtime_scan_bytes_add(struct virtual_runtime *virt_rt,
                                    int thread_id, long long val);

long long virtual_runtime_scan_bytes(void *virt_rt);

long long virtual_runtime_scan_times(void *virtual_runtime);

long long virtual_runtime_scan_cpu_time(void *virtual_runtime);

void virtual_runtime_hit_times_inc(struct virtual_runtime *virt_rt,
                                   int thread_id);

long long virtual_runtime_hit_times(void *virtual_runtime);

void virtual_runtime_hit_item_num_add(struct virtual_runtime *virt_rt,
                                      int thread_id, long long val);

long long virtual_runtime_hit_item_num(void *virtual_runtime);

int vtable_get_physical_table_id(struct table_manager *tbl_mgr, int vtable_id);

#ifdef __cplusplus
}
#endif

#endif