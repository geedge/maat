/*
**********************************************************************************************
*	File: maat_object.h
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_OBJECT_H_
#define _MAAT_OBJECT_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include "cJSON/cJSON.h"
#include "maat_kv.h"
#include "maat_table.h"

struct maat_object;
struct object2object_runtime;

/* object2object schema API */
void *object2object_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger);
void object2object_schema_free(void *g2g_schema);

/* object2object runtime API */
void *object2object_runtime_new(void *g2g_schema, size_t max_thread_num,
                              struct maat_garbage_bin *garbage_bin,
                              struct log_handle *logger);
void object2object_runtime_free(void *g2g_runtime);

int object2object_runtime_update(void *g2g_runtime, void *g2g_schema, const char *table_name, 
                               const char *line, int valid_column);

int object2object_runtime_commit(void *g2g_runtime, const char *table_name, long long maat_rt_version);

size_t object2object_runtime_get_super_objects(void *g2g_runtime, long long *object_ids, 
                                            size_t n_object_ids, long long *super_object_ids,
                                            size_t super_object_ids_size);
                                       
long long object2object_runtime_rule_count(void *g2g_runtime);

long long object2object_runtime_exclude_rule_count(void *g2g_runtime);

long long object2object_runtime_update_err_count(void *g2g_runtime);

#ifdef __cplusplus
}
#endif

#endif
