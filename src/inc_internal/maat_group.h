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

struct maat_item {
	int item_id;
	int group_id;

	struct maat_group *ref_parent_group;
	UT_hash_handle hh;

	void *user_data;
};

struct maat_group {
	igraph_integer_t vertex_id;
	int group_id;
	int ref_by_compile_cnt;
	int ref_by_superior_group_cnt;
	int ref_by_subordinate_group_cnt;
	int ref_by_item_cnt;

	size_t top_group_cnt;
	int *top_group_ids;
	UT_hash_handle hh_group_id;
	UT_hash_handle hh_vertex_id;
};

struct maat_group_topology;

struct maat_group_topology *maat_group_topology_new(struct log_handle *logger);
void maat_group_topology_free(struct maat_group_topology *group_topo);

struct maat_group *maat_group_topology_add_group(struct maat_group_topology *group_topo, int group_id);
void maat_group_topology_remove_group(struct maat_group_topology *group_topo, struct maat_group *group);

/**
 * @retval if not found, return NULL
*/
struct maat_group *maat_group_topology_find_group(struct maat_group_topology *group_topo, int group_id);

int maat_group_topology_add_group_to_group(struct maat_group_topology *group_topo, int group_id, int superior_group_id);
int maat_group_topology_remove_group_from_group(struct maat_group_topology *group_topo, int group_id, int superior_group_id);

/* build top groups */
int maat_group_topology_build_top_groups(struct maat_group_topology *group_topo);

#ifdef __cpluscplus
}
#endif

#endif