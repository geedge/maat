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

struct maat_group {
	igraph_integer_t vertex_id;
	int group_id;
	int ref_by_compile_cnt;
	int ref_by_superior_group_cnt;
	int ref_by_subordinate_group_cnt;

	size_t top_group_cnt;
	int *top_group_ids;

	UT_hash_handle hh_group_id;
	UT_hash_handle hh_vertex_id;
};

/* maat group topology API */
struct maat_group_topology;

/**
 * @retval if not found, return NULL
*/


//struct maat_group *maat_group_topology_add_group(struct maat_group_topology *group_topo, int group_id);
//struct maat_group *maat_group_topology_find_group(struct maat_group_topology *group_topo, int group_id);
//void maat_group_topology_remove_group(struct maat_group_topology *group_topo, struct maat_group *group);
//int maat_group_topology_add_group_to_group(struct maat_group_topology *group_topo, int group_id, int superior_group_id);
//int maat_group_topology_remove_group_from_group(struct maat_group_topology *group_topo, int group_id, int superior_group_id);

/* build top groups */
//int maat_group_topology_build_top_groups(struct maat_group_topology *group_topo);


/* group2group schema API */
void *group2group_schema_new(cJSON *json, const char *table_name, struct log_handle *logger);
void group2group_schema_free(void *g2g_schema);

/* group2group runtime API */
void *group2group_runtime_new(void *ip_plus_schema, int max_thread_num, struct maat_garbage_bin *garbage_bin,
						      struct log_handle *logger);
void group2group_runtime_free(void *g2g_runtime);

struct maat_group *group2group_runtime_add_group(void *g2g_runtime, int group_id);
void group2group_runtime_remove_group(void *g2g_runtime, struct maat_group *group);
struct maat_group *group2group_runtime_find_group(void *g2g_runtime, int group_id);

int group2group_runtime_add_group_to_group(void *g2g_runtime, int group_id, int superior_group_id);
int group2group_runtime_remove_group_from_group(void *g2g_runtime, int group_id, int superior_group_id);

int group2group_runtime_build_top_groups(void *g2g_runtime);


int group2group_runtime_update(void *g2g_runtime, void *g2g_schema, const char *line, int valid_column);			   
int group2group_runtime_commit(void *g2g_runtime);

int group2group_runtime_get_top_groups(void *g2g_runtime, int *group_ids, size_t n_group_ids, 
                              			int *top_group_ids);

#ifdef __cpluscplus
}
#endif

#endif