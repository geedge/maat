/*
**********************************************************************************************
*	File: maat_group.cpp
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>
#include <pthread.h>

#include "maat_group.h"
#include "utils.h"
#include "maat_utils.h"
#include "uthash/uthash.h"
#include "igraph/igraph.h"
#include "log/log.h"

#define MODULE_GROUP	 module_name_str("maat.group")

struct group2group_item {
    int group_id;
    int superior_group_id;
};

struct group2group_schema {
    int group_id_column;
    int superior_group_id_column;
    int table_id;//ugly
};

struct group2group_runtime {
    struct maat_group_topology *group_topo;

	uint32_t rule_num;
    uint32_t updating_rule_num;

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

struct maat_group_topology {
    struct maat_group *hash_group_by_id;	 //key: group_id, value: struct maat_group *.
	struct maat_group *hash_group_by_vertex; //key: vetex_id, value: struct maat_group *. Multimap (Items with multiple keys).
    igraph_t group_graph;
	igraph_integer_t group_graph_vcount;
	igraph_vector_t dfs_vids;
	igraph_integer_t grp_vertex_id_generator;

    pthread_rwlock_t rwlock;
    struct log_handle *logger;
};

void *group2group_schema_new(cJSON *json, const char *table_name, struct log_handle *logger)
{
    int read_cnt = 0;
	struct group2group_schema *g2g_schema = ALLOC(struct group2group_schema, 1);
	
	cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (NULL == item || item->type != cJSON_Number) {
        goto error;
    }
    g2g_schema->table_id = item->valueint;

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_GROUP, "table %s has no custom column", table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2g_schema->group_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "superior_group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2g_schema->superior_group_id_column = custom_item->valueint;
        read_cnt++;
    }

    if (read_cnt < 2) {
		goto error;
    }

	return g2g_schema;
error:
	FREE(g2c_schema);
	return NULL;
}

void group2group_schema_free(void *g2g_schema)
{
	FREE(g2g_schema);
}

struct group2group_runtime *
group2group_runtime_new(void *ip_plus_schema, struct maat_garbage_bin *garbage_bin,
						struct log_handle *logger)
{
	struct group2group_runtime *g2g_rt = ALLOC(struct group2group_runtime, 1);

	g2g_rt->group_topo = maat_group_topology_new(logger);
    g2g_rt->ref_garbage_bin = garbage_bin;
    g2g_rt->logger = logger;

	return g2g_rt;
}

void group2group_runtime_free(void *g2g_runtime)
{
    if (NULL == g2g_runtime) {
        return;
    }

    struct group2group_runtime *g2g_rt = (struct group2group_runtime *)g2g_runtime;

    if (g2g_rt->group_topo != NULL) {
        maat_group_topology_free(g2g_rt->group_topo);
    }
    
    FREE(g2g_rt);
}

struct group2group_item *
group2group_item_new(const char *line, struct group2group_schema *g2g_schema,
                     struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    struct group2group_item *g2g_item = ALLOC(struct group2group_item, 1);

    int ret = get_column_pos(line, g2g_schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_GROUP,
                  "group2group table(table_id:%d) line:%s has no group_id",
                  g2g_schema->table_id, line);
        goto error;
    }
    g2g_item->group_id = atoi(line + column_offset);

    ret = get_column_pos(line, g2g_schema->superior_group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_GROUP,
                  "group2group table(table_id:%d) line:%s has no superior_group_id",
                  g2g_schema->table_id, line);
        goto error;
    }
    g2g_item->superior_group_id = atoi(line + column_offset);

    return g2g_item;
error:
    FREE(g2g_item);
    return NULL;
}

void group2group_item_free(struct group2group_item *g2g_item)
{
    FREE(g2g_item);
}

void group_vertex_free(struct maat_group *group)
{
	free(group->top_group_ids);
	free(group);
}

struct maat_group_topology *maat_group_topology_new(struct log_handle *logger)
{
    struct maat_group_topology *group_topo = ALLOC(struct maat_group_topology, 1);
    UNUSED int ret = 0;

    group_topo->hash_group_by_id = NULL;
    group_topo->hash_group_by_vertex = NULL;

    ret = igraph_empty(&group_topo->group_graph, 0, IGRAPH_DIRECTED);
    assert(ret == IGRAPH_SUCCESS);

    ret = pthread_rwlock_init(&group_topo->rwlock, NULL);
    assert(ret == 0);

    group_topo->logger = logger;

    return group_topo;
}

void maat_group_topology_free(struct maat_group_topology *group_topo)
{
    struct maat_group *group = NULL, *tmp_group = NULL;

    HASH_CLEAR(hh_vertex_id, group_topo->hash_group_by_vertex);//No need group memory clean up.
	HASH_ITER(hh_group_id, group_topo->hash_group_by_id, group, tmp_group) {
		HASH_DELETE(hh_group_id, group_topo->hash_group_by_id, group);
		group_vertex_free(group);
	}
	assert(group_topo->hash_group_by_id == NULL);	
	
	igraph_destroy(&group_topo->group_graph);

    pthread_rwlock_unlock(&group_topo->rwlock);
	pthread_rwlock_destroy(&group_topo->rwlock);
}

size_t print_igraph_vector(igraph_vector_t *v, char *buff, size_t sz) {
  long int i;
  int printed = 0;

  for (i = 0; i < igraph_vector_size(v); i++) {
    printed += snprintf(buff + printed, sz - printed, " %li", (long int) VECTOR(*v)[i]);
  }

  return printed;
}

struct maat_group *maat_group_topology_add_group(struct maat_group_topology *group_topo, int group_id)
{
	struct maat_group *group = ALLOC(struct maat_group, 1);

	group->group_id = group_id;
	group->vertex_id = group_topo->grp_vertex_id_generator++;

	assert(igraph_vcount(&group_topo->group_graph)==group->vertex_id);
	igraph_add_vertices(&group_topo->group_graph, 1, NULL);	//Add 1 vertice.
	
	HASH_ADD(hh_group_id, group_topo->hash_group_by_id, group_id, sizeof(group->group_id), group);
	HASH_ADD(hh_vertex_id, group_topo->hash_group_by_vertex, vertex_id, sizeof(group->vertex_id), group);

	return group;
}

void maat_group_topology_remove_group(struct maat_group_topology *group_topo, struct maat_group *group)
{
	igraph_vector_t v; 
	char buff[4096] = {0};

	assert(group->ref_by_compile_cnt == 0 && group->ref_by_superior_group_cnt == 0);
	igraph_vector_init(&v, 8);
	igraph_neighbors(&group_topo->group_graph, &v, group->vertex_id, IGRAPH_ALL);
	if (igraph_vector_size(&v) > 0) {
		print_igraph_vector(&v, buff, sizeof(buff));
		log_error(group_topo->logger, MODULE_GROUP, "Del group %d exception, still reached by %s.",
						                            group->vertex_id, buff);
		assert(0);
	}
	igraph_vector_destroy(&v);
	assert(group->top_group_ids==NULL);
	//We should not call igraph_delete_vertices, because this is function changes the ids of the vertices.
	//igraph_delete_vertices(&hier->group_graph, igraph_vss_1(group->vertex_id));

	
	HASH_DELETE(hh_group_id, group_topo->hash_group_by_id, group);
	HASH_DELETE(hh_vertex_id, group_topo->hash_group_by_vertex, group);

	group_vertex_free(group);
}

struct maat_group *maat_group_topology_find_group(struct maat_group_topology *group_topo, int group_id)
{
    struct maat_group *group = NULL;

    HASH_FIND(hh_group_id, group_topo->hash_group_by_id, &group_id, sizeof(group_id), group);

    return group;
}

int maat_group_topology_add_group_to_group(struct maat_group_topology *group_topo, int group_id, int superior_group_id)
{
    int ret = 0;
	igraph_integer_t edge_id;
	struct maat_group *group = NULL, *superior_group = NULL;

    group = maat_group_topology_find_group(group_topo, group_id);
	if (NULL == group) {
		group = maat_group_topology_add_group(group_topo, group_id);
	}
	
    superior_group = maat_group_topology_find_group(group_topo, superior_group_id);
	if (NULL == superior_group) {
		superior_group = maat_group_topology_add_group(group_topo, superior_group_id);
	}

	ret = igraph_get_eid(&group_topo->group_graph, &edge_id, group->vertex_id, superior_group->vertex_id, IGRAPH_DIRECTED, /*error*/ 0);
	
    //No duplicated edges between two groups.
    if (edge_id > 0) {
		log_error(group_topo->logger, MODULE_GROUP,
                  "Add group %d to group %d failed, relation already exisited.",
				  group->group_id, superior_group->group_id);
		ret = -1;
	} else {
		igraph_add_edge(&group_topo->group_graph, group->vertex_id, superior_group->vertex_id);
		group->ref_by_superior_group_cnt++;
		superior_group->ref_by_subordinate_group_cnt++;
		ret = 0;
	}
	
	return ret;
}

int maat_group_topology_remove_group_from_group(struct maat_group_topology *group_topo, int group_id, int superior_group_id)
{
    int ret = 0;
	struct maat_group *group = NULL, *superior_group = NULL;

	//No hash write operation, LOCK protection is unnecessary.
	group = maat_group_topology_find_group(group_topo, group_id);
	if (NULL == group) {
		log_error(group_topo->logger, MODULE_GROUP,
				  "Del group %d from group %d failed, group %d not exisited.",
				  group_id, superior_group_id, group_id);
		return -1;	
	}

    superior_group = maat_group_topology_find_group(group_topo, superior_group_id);
	if (NULL == superior_group) {
		log_error(group_topo->logger, MODULE_GROUP,
				  "Del group %d from group %d failed, superior group %d not exisited.",
				  group_id, superior_group_id, superior_group_id);
		return -1;	
	}

	igraph_es_t es;
	igraph_integer_t edge_num_before = 0, edge_num_after = 0;

	edge_num_before = igraph_ecount(&group_topo->group_graph);
	// The edges between the given pairs of vertices will be included in the edge selection.
	//The vertex pairs must be given as the arguments of the function call, the third argument 
	//is the first vertex of the first edge, the fourth argument is the second vertex of the 
	//first edge, the fifth is the first vertex of the second edge and so on. The last element
	//of the argument list must be -1 to denote the end of the argument list.
	//https://igraph.org/c/doc/igraph-Iterators.html#igraph_es_pairs_small
	ret = igraph_es_pairs_small(&es, IGRAPH_DIRECTED, group->vertex_id, superior_group->vertex_id, -1);
	assert(ret==IGRAPH_SUCCESS);
	// ignore no such edge to abort().
	igraph_set_error_handler(igraph_error_handler_ignore);
	ret = igraph_delete_edges(&group_topo->group_graph, es);
	edge_num_after = igraph_ecount(&group_topo->group_graph);
	igraph_es_destroy(&es);
	
	if (ret != IGRAPH_SUCCESS || edge_num_before - edge_num_after != 1) {
		assert(0);
		return -1;
	}

	group->ref_by_superior_group_cnt--;
	superior_group->ref_by_subordinate_group_cnt--;

	return 0;
}

static size_t effective_vertices_count(igraph_vector_t *vids)
{
    size_t i = 0;
	int tmp_vid = 0;

	for (i = 0; i < (size_t)igraph_vector_size(vids); i++) {
		tmp_vid = (int) VECTOR(*vids)[i];
		if (tmp_vid < 0) {
			break;
		}
	}

	return i;
}

int maat_group_topology_build_top_groups(struct maat_group_topology *group_topo)
{
	struct maat_group *group = NULL, *tmp = NULL;
	struct maat_group *superior_group = NULL;
	int tmp_vid=0;
	size_t i=0, top_group_cnt=0;
	int* temp_group_ids=NULL;
	
	igraph_bool_t is_dag;
	igraph_is_dag(&(group_topo->group_graph), &is_dag);
	if (!is_dag) {
		log_error(group_topo->logger, MODULE_GROUP, "Sub group cycle detected!");
		return -1;
	}

	group_topo->group_graph_vcount = igraph_vcount(&group_topo->group_graph);
	igraph_vector_init(&(group_topo->dfs_vids), group_topo->group_graph_vcount);
	
	HASH_ITER (hh_group_id, group_topo->hash_group_by_id, group, tmp) {
		top_group_cnt = 0;
		temp_group_ids = NULL;
		//Orphan, Not reference by any one, free it.
		if (0 == group->ref_by_compile_cnt
			&& 0 == group->ref_by_superior_group_cnt
			&& 0 == group->ref_by_subordinate_group_cnt) {
		
			FREE(group->top_group_ids);
			maat_group_topology_remove_group(group_topo, group);
			continue;
		}

		//A group is need to build top groups when it has items and referenced by superior groups or compiles.
		if (group->ref_by_compile_cnt > 0 || group->ref_by_superior_group_cnt > 0) {
			if (0 == group->ref_by_superior_group_cnt) {
				//fast path, group is only referenced by compile rules.
				top_group_cnt = 1;
				temp_group_ids = ALLOC(int, top_group_cnt);
				temp_group_ids[0] = group->group_id;
			} else {
				igraph_vector_t *vids = &(group_topo->dfs_vids);
				igraph_dfs(&group_topo->group_graph, group->vertex_id, IGRAPH_OUT, 
							0, vids, NULL, NULL, NULL, NULL, NULL, NULL);
				
				temp_group_ids = ALLOC(int, effective_vertices_count(vids));
				
				for (size_t i = 0; i < (size_t)igraph_vector_size(vids); i++) {
					tmp_vid = (int) VECTOR(*vids)[i];
					if (tmp_vid < 0) {
						break;
					}

					HASH_FIND(hh_vertex_id, group_topo->hash_group_by_vertex, &tmp_vid, sizeof(tmp_vid), superior_group);

                    //including itself
					if (superior_group->ref_by_compile_cnt > 0) {
						temp_group_ids[top_group_cnt] = superior_group->group_id;
						top_group_cnt++;
					}
				}
			}
		}

		free(group->top_group_ids);
		group->top_group_cnt = top_group_cnt;
		group->top_group_ids = ALLOC(int, group->top_group_cnt);
		memcpy(group->top_group_ids, temp_group_ids, sizeof(int)*group->top_group_cnt);

		FREE(temp_group_ids);
	}	
	igraph_vector_destroy(&group_topo->dfs_vids);

	return 0;
}

int group2group_runtime_update(void *g2g_runtime, void *g2g_schema, const char *line,
                               int valid_column)
{
    if (NULL == g2g_runtime || NULL == g2g_schema || NULL == line) {
        return -1;
    }

	int ret = -1;
    struct group2group_item *g2g_item = NULL;
    struct group2group_schema *schema = (struct group2group_schema *)g2g_schema;
	struct group2group_runtime *g2g_rt = (struct group2group_runtime *)g2g_runtime;
    int item_id = get_column_value(line, schema->table_id);
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    } else if (0 == is_valid) {
        //delete
        ret = maat_group_topology_remove_group_from_group(g2g_rt->group_topo, g2g_item->group_id, g2g_item->superior_group_id);
    } else {
        //add
        g2g_item = group2group_item_new(line, schema, logger);
    }

    if (1 == is_valid) {
        //add
        ret = maat_group_topology_add_group_to_group(g2g_rt->group_topo, g2g_item->group_id, g2g_item->superior_group_id);
    } else {
        //delete
        
    }
    
    return ret;
}

int group2group_runtime_commit(void *g2g_runtime)
{
    if (NULL == g2g_runtime) {
		return -1;
	}

	struct group2group_runtime *g2g_rt = (struct group2group_runtime *)g2g_runtime;
    int ret = maat_group_topology_build_top_groups(g2g_rt->group_topo);

    return ret;
}

int group2group_runtime_get_top_groups(struct group2group_runtime *g2g_rt, int *group_ids, size_t n_group_ids, 
                              			int *top_group_ids)
{
    if (NULL == table_rt || NULL == group_ids || 0 == n_group_ids || 
        table_rt->table_type != TABLE_TYPE_GROUP2GROUP) {
        return -1;
    }
    
    size_t top_group_index = 0;
    struct group2group_runtime *g2g_rt = &(table_rt->g2g_rt);
    for (size_t i = 0; i < n_group_ids; i++) {
        struct maat_group *group = maat_group_topology_find_group(g2g_rt->group_topo, group_ids[i]);
        if (!group) {
            continue;
        }

        for (size_t j = 0; j < group->top_group_cnt; j++) {
            top_group_ids[top_group_index++] = group->top_group_ids[j];
        }
    }
    
    return top_group_index;
}