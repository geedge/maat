/*
**********************************************************************************************
*	File: maat_attribute.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_ATTRIBUTE_H_
#define _MAAT_ATTRIBUTE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "cJSON/cJSON.h"
#include "maat_table.h"

struct attribute_runtime;

void *attribute_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                         const char *table_name, struct log_handle *logger);

void attribute_schema_free(void *attribute_schema);

void *attribute_runtime_new(void *attribute_schema, size_t max_thread_num,
                          struct maat_garbage_bin *garbage_bin,
                          struct log_handle *logger);

void attribute_runtime_free(void *attribute_runtime);

void attribute_runtime_scan_times_inc(struct attribute_runtime *virt_rt,
                                    int thread_id);

void attribute_runtime_scan_bytes_add(struct attribute_runtime *virt_rt,
                                    int thread_id, long long val);

long long attribute_runtime_scan_bytes(void *virt_rt);

long long attribute_runtime_scan_times(void *attribute_runtime);

long long attribute_runtime_scan_cpu_time(void *attribute_runtime);

void attribute_runtime_hit_times_inc(struct attribute_runtime *virt_rt,
                                   int thread_id);

long long attribute_runtime_hit_times(void *attribute_runtime);

void attribute_runtime_hit_item_num_add(struct attribute_runtime *virt_rt,
                                      int thread_id, long long val);

long long attribute_runtime_hit_item_num(void *attribute_runtime);


#ifdef __cplusplus
}
#endif

#endif