/*
**********************************************************************************************
*	File: maat_group.h
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_GROUP_H_
#define _MAAT_GROUP_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include "cJSON/cJSON.h"
#include "uthash/uthash.h"
#include "igraph/igraph.h"
#include "maat_kv.h"

struct maat_group;

/* group2group schema API */
void *group2group_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger);
void group2group_schema_free(void *g2g_schema);

/* group2group runtime API */
void *group2group_runtime_new(void *g2g_schema, int max_thread_num, 
                              struct maat_garbage_bin *garbage_bin,
						      struct log_handle *logger);
void group2group_runtime_free(void *g2g_runtime);

void maat_group_ref_inc(struct maat_group *group);
void maat_group_ref_dec(struct maat_group *group);

struct maat_group *group2group_runtime_add_group(void *g2g_runtime, int group_id);
void group2group_runtime_remove_group(void *g2g_runtime, struct maat_group *group);
struct maat_group *group2group_runtime_find_group(void *g2g_runtime, int group_id);

int group2group_runtime_build_top_groups(void *g2g_runtime);
int group2group_runtime_get_top_groups(void *g2g_runtime, int *group_ids, 
                                       size_t n_group_ids, int *top_group_ids);

int group2group_runtime_update(void *g2g_runtime, void *g2g_schema, 
                               const char *line, int valid_column);			   
int group2group_runtime_commit(void *g2g_runtime, const char *table_name);

#ifdef __cpluscplus
}
#endif

#endif