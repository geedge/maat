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
void object2object_schema_free(void *o2o_schema);

/* object2object runtime API */
void *object2object_runtime_new(void *o2o_schema, size_t max_thread_num,
                              struct maat_garbage_bin *garbage_bin,
                              struct log_handle *logger);
void object2object_runtime_free(void *o2o_runtime);

int object2object_runtime_update(void *o2o_runtime, void *o2o_schema, const char *table_name, 
                               const char *line, enum maat_operation op);

int object2object_runtime_commit(void *o2o_runtime, const char *table_name, long long maat_rt_version);

size_t object2object_runtime_get_super_objects(void *o2o_runtime, uuid_t *object_uuids, 
                                            size_t n_object_uuids, uuid_t *super_object_uuids,
                                            size_t super_object_uuids_size);
                                       
long long object2object_runtime_rule_count(void *o2o_runtime);

long long object2object_runtime_exclude_rule_count(void *o2o_runtime);

long long object2object_runtime_update_err_count(void *o2o_runtime);

#ifdef __cplusplus
}
#endif

#endif
