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
struct object_group_runtime;

/* object_group schema API */
void *object_group_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger);
void object_group_schema_free(void *object_group_schema);

/* object_group runtime API */
void *object_group_runtime_new(void *object_group_schema, size_t max_thread_num,
                              struct maat_garbage_bin *garbage_bin,
                              struct log_handle *logger);
void object_group_runtime_free(void *object_group_runtime);

int object_group_runtime_update(void *object_group_runtime, void *object_group_schema, const char *table_name, 
                               const char *line, enum maat_operation op);

int object_group_runtime_commit(void *object_group_runtime, const char *table_name, long long maat_rt_version);

size_t object_group_runtime_get_super_objects(void *object_group_runtime, uuid_t *object_uuids, 
                                            size_t n_object_uuids, uuid_t *super_object_uuids,
                                            size_t super_object_uuids_size);
                                       
long long object_group_runtime_rule_count(void *object_group_runtime);

long long object_group_runtime_exclude_rule_count(void *object_group_runtime);

long long object_group_runtime_update_err_count(void *object_group_runtime);

#ifdef __cplusplus
}
#endif

#endif
