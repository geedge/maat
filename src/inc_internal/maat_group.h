/*
**********************************************************************************************
*	File: maat_group.h
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_GROUP_H_
#define _MAAT_GROUP_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include "cJSON/cJSON.h"
#include "maat_kv.h"
#include "maat_table.h"

struct maat_group;
struct group2group_runtime;

/* group2group schema API */
void *group2group_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger);
void group2group_schema_free(void *g2g_schema);

/* group2group runtime API */
void *group2group_runtime_new(void *g2g_schema, size_t max_thread_num,
                              struct maat_garbage_bin *garbage_bin,
                              struct log_handle *logger);
void group2group_runtime_free(void *g2g_runtime);

int group2group_runtime_update(void *g2g_runtime, void *g2g_schema, const char *table_name, 
                               const char *line, int valid_column);

int group2group_runtime_commit(void *g2g_runtime, const char *table_name, long long maat_rt_version);

size_t group2group_runtime_get_super_groups(void *g2g_runtime, long long *group_ids, 
                                            size_t n_group_ids, long long *super_group_ids,
                                            size_t super_group_ids_size);
                                       
long long group2group_runtime_rule_count(void *g2g_runtime);

long long group2group_runtime_update_err_count(void *g2g_runtime);

#ifdef __cplusplus
}
#endif

#endif
