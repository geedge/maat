/*
**********************************************************************************************
*	File: maat_group.c
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>
#include <pthread.h>

#include "log/log.h"
#include "maat_group.h"
#include "maat_utils.h"
#include "maat_limits.h"
#include "uthash/uthash.h"
#include "uthash/utarray.h"
#include "igraph/igraph.h"
#include "maat_kv.h"

#define MODULE_GROUP	 module_name_str("maat.group")

struct group2group_item {
    UT_array *sub_group_ids;
    long long super_group_id;
    int is_exclude;
};

struct group2group_schema {
    int group_id_column;
    int super_group_id_column;
    int is_exclude_column;
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

struct maat_group {
	igraph_integer_t vertex_id;
	long long group_id;

	int ref_by_super_group_cnt;
	int ref_by_sub_group_cnt;

	UT_array *incl_super_group_ids;
    UT_array *excl_super_group_ids;
    UT_array *incl_sub_group_ids;
    UT_array *excl_sub_group_ids;

	UT_hash_handle hh_group_id;
	UT_hash_handle hh_vertex_id;
};

struct maat_group_topology {
    struct maat_group *hash_by_group_id;  //key: group_id, value: struct maat_group *.
	struct maat_group *hash_by_vertex_id; //key: vetex_id, value: struct maat_group *.
    igraph_t group_graph;
	igraph_integer_t grp_vertex_id_generator;
    struct log_handle *logger;
};

struct group2group_runtime {
    struct maat_group_topology *group_topo;
    struct maat_group_topology *updating_group_topo;
	long long rule_num;
    long long excl_rule_num; //exclude g2g rule num
    long long update_err_cnt;
    int updating_flag;

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

UT_icd ut_group_id_icd = {sizeof(long long), NULL, NULL, NULL};

static inline int compare_group_id(const void *a, const void *b)
{
	long long ret = *(const long long *)a - *(const long long *)b;

	if (0 == ret) {
		return 0;
	} else if(ret < 0) {
		return -1;
	} else {
		return 1;
	}
}

void *group2group_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger)
{
	struct group2group_schema *g2g_schema = ALLOC(struct group2group_schema, 1);
	
	cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        g2g_schema->table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_GROUP, 
                  "[%s:%d] g2g table:<%s> schema has no table_id column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_fatal(logger, MODULE_GROUP, 
                  "[%s:%d] g2g table:<%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2g_schema->group_id_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_GROUP, 
                  "[%s:%d] g2g table:<%s> schema has no group_id column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "super_group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2g_schema->super_group_id_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_GROUP, 
                  "[%s:%d] g2g table:<%s> schema has no super_group_id column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "is_exclude");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        g2g_schema->is_exclude_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_GROUP, 
                  "[%s:%d] g2g table:<%s> schema has no is_exclude column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    g2g_schema->ref_tbl_mgr = tbl_mgr;
	return g2g_schema;
error:
	FREE(g2g_schema);
	return NULL;
}

void group2group_schema_free(void *g2g_schema)
{
	FREE(g2g_schema);
}

static void group_vertex_free(struct maat_group *group)
{
    if (NULL == group) {
        return;
    }

    if (group->incl_super_group_ids != NULL) {
        utarray_free(group->incl_super_group_ids);
        group->incl_super_group_ids = NULL;
    }
	
    if (group->excl_super_group_ids != NULL) {
        utarray_free(group->excl_super_group_ids);
        group->excl_super_group_ids = NULL;
    }
    
    if (group->incl_sub_group_ids != NULL) {
        utarray_free(group->incl_sub_group_ids);
        group->incl_sub_group_ids = NULL;
    }
    
    if (group->excl_sub_group_ids != NULL) {
        utarray_free(group->excl_sub_group_ids);
        group->excl_sub_group_ids = NULL;
    }

	FREE(group);
}

static struct maat_group_topology *
maat_group_topology_new(struct log_handle *logger)
{
    struct maat_group_topology *group_topo = ALLOC(struct maat_group_topology, 1);
    UNUSED int ret = 0;

    group_topo->hash_by_group_id = NULL;
    group_topo->hash_by_vertex_id = NULL;

    ret = igraph_empty(&(group_topo->group_graph), 0, IGRAPH_DIRECTED);
    assert(ret == IGRAPH_SUCCESS);

    group_topo->logger = logger;

    return group_topo;
}

static void maat_group_topology_free(struct maat_group_topology *group_topo)
{
    if (NULL == group_topo) {
        return;
    }
    
    struct maat_group *group = NULL, *tmp_group = NULL;

    HASH_CLEAR(hh_vertex_id, group_topo->hash_by_vertex_id);//No need group memory clean up.
	HASH_ITER(hh_group_id, group_topo->hash_by_group_id, group, tmp_group) {
		HASH_DELETE(hh_group_id, group_topo->hash_by_group_id, group);
		group_vertex_free(group);
	}
	assert(group_topo->hash_by_group_id == NULL);	
	
	igraph_destroy(&group_topo->group_graph);
    FREE(group_topo);
}

static struct maat_group *maat_group_clone(struct maat_group *group)
{
    struct maat_group *group_copy = ALLOC(struct maat_group, 1);

    group_copy->group_id = group->group_id;
    group_copy->vertex_id = group->vertex_id;
    group_copy->ref_by_sub_group_cnt = group->ref_by_sub_group_cnt;
    group_copy->ref_by_super_group_cnt = group->ref_by_super_group_cnt;
    utarray_new(group_copy->incl_super_group_ids, &ut_group_id_icd);
    utarray_new(group_copy->excl_super_group_ids, &ut_group_id_icd);
    utarray_new(group_copy->incl_sub_group_ids, &ut_group_id_icd);
    utarray_new(group_copy->excl_sub_group_ids, &ut_group_id_icd);

    long long *p = NULL;
    for (p = (long long *)utarray_front(group->incl_super_group_ids); p != NULL;
         p = (long long *)utarray_next(group->incl_super_group_ids, p)) {
        utarray_push_back(group_copy->incl_super_group_ids, p);
    }

    for (p = (long long *)utarray_front(group->excl_super_group_ids); p != NULL;
         p = (long long *)utarray_next(group->excl_super_group_ids, p)) {
        utarray_push_back(group_copy->excl_super_group_ids, p);
    }

    for (p = (long long *)utarray_front(group->incl_sub_group_ids); p != NULL;
         p = (long long *)utarray_next(group->incl_sub_group_ids, p)) {
        utarray_push_back(group_copy->incl_sub_group_ids, p);
    }

    for (p = (long long *)utarray_front(group->excl_sub_group_ids); p != NULL;
         p = (long long *)utarray_next(group->excl_sub_group_ids, p)) {
        utarray_push_back(group_copy->excl_sub_group_ids, p);
    }

    return group_copy;
}

static struct maat_group_topology *
maat_group_topology_clone(struct maat_group_topology *group_topo)
{
    if (NULL == group_topo) {
        return NULL;
    }

    struct maat_group_topology *group_topo_copy = ALLOC(struct maat_group_topology, 1);

    struct maat_group *group = NULL, *tmp_group = NULL;
    HASH_ITER(hh_group_id, group_topo->hash_by_group_id, group, tmp_group) {
        struct maat_group *group_copy = maat_group_clone(group);

        HASH_ADD(hh_group_id, group_topo_copy->hash_by_group_id, group_id, 
                 sizeof(group_copy->group_id), group_copy);
        HASH_ADD(hh_vertex_id, group_topo_copy->hash_by_vertex_id, vertex_id,
                sizeof(group_copy->vertex_id), group_copy);
    }

    igraph_copy(&(group_topo_copy->group_graph), &(group_topo->group_graph));
    group_topo_copy->grp_vertex_id_generator = group_topo->grp_vertex_id_generator;
    group_topo_copy->logger = group_topo->logger;

    return group_topo_copy;
}

void *group2group_runtime_new(void *g2g_schema, size_t max_thread_num,
                              struct maat_garbage_bin *garbage_bin, 
                              struct log_handle *logger)
{
    if (NULL == g2g_schema) {
        return NULL;
    }

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
        g2g_rt->group_topo = NULL;
    }
    
    if (g2g_rt->updating_group_topo != NULL) {
        maat_group_topology_free(g2g_rt->updating_group_topo);
        g2g_rt->updating_group_topo = NULL;
    }

    FREE(g2g_rt);
}

static struct group2group_item *
group2group_item_new(const char *line, struct group2group_schema *g2g_schema,
                     const char *table_name, struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    struct group2group_item *g2g_item = ALLOC(struct group2group_item, 1);
    utarray_new(g2g_item->sub_group_ids, &ut_group_id_icd);

    int ret = get_column_pos(line, g2g_schema->group_id_column,
                             &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_GROUP,
                  "[%s:%d] g2g table:<%s> has no group_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }

    char group_ids_str[MAX_GROUP_IDS_STR_LEN] = {0};
    memcpy(group_ids_str, line + column_offset, MIN(MAX_GROUP_IDS_STR_LEN, column_len));

    ret = ids_str2longlong_array(group_ids_str, g2g_item->sub_group_ids);
    if (ret < 0) {
        log_fatal(logger, MODULE_GROUP,
				  "[%s:%d] g2c table:<%s> sub_group_ids str2longlong failed in line:%s",
				  __FUNCTION__, __LINE__, table_name, line);
		goto error; 
    }

    if (utarray_len(g2g_item->sub_group_ids) > MAX_GROUP_CNT) {
        log_fatal(logger, MODULE_GROUP,
				  "[%s:%d] g2c table:<%s> sub_group_ids exceed maximum:%d in line:%s",
				  __FUNCTION__, __LINE__, table_name, MAX_GROUP_CNT, line);
		goto error;
    }

    ret = get_column_pos(line, g2g_schema->super_group_id_column, 
                         &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_GROUP,
                  "[%s:%d] g2 table:<%s> has no super_group_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    g2g_item->super_group_id = atoll(line + column_offset);

    ret = get_column_pos(line, g2g_schema->is_exclude_column, 
                         &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(logger, MODULE_GROUP,
                  "[%s:%d] g2g table:<%s> has no is_exclude in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }

    g2g_item->is_exclude = atoi(line + column_offset);
    if (g2g_item->is_exclude != 0 && g2g_item->is_exclude != 1) {
        log_fatal(logger, MODULE_GROUP,
                  "[%s:%d] g2g table:<%s> is_exclude:%d is illegal in line:%s",
                  __FUNCTION__, __LINE__, table_name, g2g_item->is_exclude, line);
        goto error;
    }

    if (g2g_item->is_exclude != 0 && g2g_item->is_exclude != 1) {
        log_fatal(logger, MODULE_GROUP,
                  "[%s:%d] g2g table:<%s> is_exclude:%d is illegal in line:%s",
                  __FUNCTION__, __LINE__, table_name, g2g_item->is_exclude, line);
        goto error;
    }

    return g2g_item;
error:
    FREE(g2g_item);
    return NULL;
}

static void group2group_item_free(struct group2group_item *g2g_item)
{
    if (NULL == g2g_item) {
        return;
    }

    if (g2g_item->sub_group_ids != NULL) {
        utarray_free(g2g_item->sub_group_ids);
        g2g_item->sub_group_ids = NULL;
    }

    FREE(g2g_item);
}

static size_t print_igraph_vector(igraph_vector_t *v, char *buff, size_t sz) {
  long int i;
  int printed = 0;

  for (i = 0; i < igraph_vector_size(v); i++) {
    printed += snprintf(buff + printed, sz - printed, " %li", 
                        (long int) VECTOR(*v)[i]);
  }

  return printed;
}

static struct maat_group *
group_topology_add_group(struct maat_group_topology *group_topo, long long group_id)
{
    assert(group_topo != NULL);

	struct maat_group *group = ALLOC(struct maat_group, 1);
	group->group_id = group_id;
	group->vertex_id = group_topo->grp_vertex_id_generator++;
    utarray_new(group->incl_super_group_ids, &ut_group_id_icd);
    utarray_new(group->excl_super_group_ids, &ut_group_id_icd);
    utarray_new(group->incl_sub_group_ids, &ut_group_id_icd);
    utarray_new(group->excl_sub_group_ids, &ut_group_id_icd);

	assert(igraph_vcount(&group_topo->group_graph)==group->vertex_id);
	igraph_add_vertices(&group_topo->group_graph, 1, NULL);	//Add 1 vertice.
	
	HASH_ADD(hh_group_id, group_topo->hash_by_group_id, group_id,
             sizeof(group->group_id), group);
	HASH_ADD(hh_vertex_id, group_topo->hash_by_vertex_id, vertex_id,
             sizeof(group->vertex_id), group);
    
	return group;
}

static void group_topology_del_group(struct maat_group_topology *group_topo,
                                     struct maat_group *group)
{
    if (NULL == group_topo || NULL == group) {
        return;
    }

    igraph_vector_t v; 
	char buff[4096] = {0};

    assert(group->ref_by_super_group_cnt == 0);

	igraph_vector_init(&v, 8);
	igraph_neighbors(&group_topo->group_graph, &v, group->vertex_id, IGRAPH_ALL);
	if (igraph_vector_size(&v) > 0) {
		print_igraph_vector(&v, buff, sizeof(buff));
		log_fatal(group_topo->logger, MODULE_GROUP, 
                 "[%s:%d] Del group %d exception, still reached by %s.",
				  __FUNCTION__, __LINE__, group->vertex_id, buff);
		assert(0);
	}
	igraph_vector_destroy(&v);
	
	//We should not call igraph_delete_vertices, because this is function changes the ids of the vertices.

	HASH_DELETE(hh_group_id, group_topo->hash_by_group_id, group);
	HASH_DELETE(hh_vertex_id, group_topo->hash_by_vertex_id, group);
	group_vertex_free(group);
}

static struct maat_group *
group_topology_find_group(struct maat_group_topology *group_topo, long long group_id)
{
    if (NULL == group_topo || group_id < 0) {
        return NULL;
    }

    struct maat_group *group = NULL;
    HASH_FIND(hh_group_id, group_topo->hash_by_group_id, &group_id, sizeof(group_id), group);

    return group;
}

static void maat_group_reference_super_group(struct maat_group *group,
                                             long long super_group_id,
                                             int is_exclude)
{
    if (NULL == group || super_group_id < 0) {
        return;
    }

    if (0 == is_exclude) {
        //include superior group
        if (!utarray_find(group->incl_super_group_ids, &super_group_id,
                          compare_group_id)) {
            utarray_push_back(group->incl_super_group_ids, &super_group_id);
            utarray_sort(group->incl_super_group_ids, compare_group_id);
        }
    } else {
        //exclude superior group
        if (!utarray_find(group->excl_super_group_ids, &super_group_id,
                          compare_group_id)) {
            utarray_push_back(group->excl_super_group_ids, &super_group_id);
            utarray_sort(group->excl_super_group_ids, compare_group_id);
        }
    }
}

static void maat_group_reference_sub_group(struct maat_group *group,
                                           long long sub_group_id,
                                           int is_exclude)
{
    if (NULL == group || sub_group_id < 0) {
        return;
    }

    if (0 == is_exclude) {
        //include sub group
        if (!utarray_find(group->incl_sub_group_ids, &sub_group_id,
                          compare_group_id)) {
            utarray_push_back(group->incl_sub_group_ids, &sub_group_id);
            utarray_sort(group->incl_sub_group_ids, compare_group_id);
        }
    } else {
        //exclude sub group
        if (!utarray_find(group->excl_sub_group_ids, &sub_group_id,
                          compare_group_id)) {
            utarray_push_back(group->excl_sub_group_ids, &sub_group_id);
            utarray_sort(group->excl_sub_group_ids, compare_group_id);
        }
    }
}

static void maat_group_dereference_super_group(struct maat_group *group,
                                               long long super_group_id,
                                               int is_exclude)
{
    if (NULL == group || super_group_id < 0) {
        return;
    }

    size_t remove_idx = 0;
    long long *tmp_id = NULL;
    if (0 == is_exclude) {
        //include superior group
        tmp_id = utarray_find(group->incl_super_group_ids, &super_group_id,
                              compare_group_id);
        if (tmp_id != NULL) {
            remove_idx = utarray_eltidx(group->incl_super_group_ids, tmp_id);
            utarray_erase(group->incl_super_group_ids, remove_idx, 1);
        }
    } else {
        //exclude superior group
        tmp_id = utarray_find(group->excl_super_group_ids, &super_group_id,
                              compare_group_id);
        if (tmp_id != NULL) {
            remove_idx = utarray_eltidx(group->excl_super_group_ids, tmp_id);
            utarray_erase(group->excl_super_group_ids, remove_idx, 1);
        }
    }
}

static void maat_group_dereference_sub_group(struct maat_group *group,
                                             long long sub_group_id,
                                             int is_exclude)
{
    if (NULL == group || sub_group_id < 0) {
        return;
    }

    size_t remove_idx = 0;
    long long *tmp_id = NULL;
    if (0 == is_exclude) {
        //include superior group
        tmp_id = utarray_find(group->incl_sub_group_ids, &sub_group_id,
                              compare_group_id);
        if (tmp_id != NULL) {
            remove_idx = utarray_eltidx(group->incl_sub_group_ids, tmp_id);
            utarray_erase(group->incl_sub_group_ids, remove_idx, 1);
        }
    } else {
        //exclude superior group
        tmp_id = utarray_find(group->excl_sub_group_ids, &sub_group_id,
                              compare_group_id);
        if (tmp_id != NULL) {
            remove_idx = utarray_eltidx(group->excl_sub_group_ids, tmp_id);
            utarray_erase(group->excl_sub_group_ids, remove_idx, 1);
        }
    }
}

static int group_topology_add_group_to_group(struct maat_group_topology *group_topo, 
                                             long long group_id, long long super_group_id,
                                             int is_exclude)
{
    if (NULL == group_topo) {
        return -1;
    }

    struct maat_group *group = group_topology_find_group(group_topo, group_id);
    if (NULL == group) {
        group = group_topology_add_group(group_topo, group_id);
	}
	
    struct maat_group *super_group = group_topology_find_group(group_topo, super_group_id);
	if (NULL == super_group) {
		super_group = group_topology_add_group(group_topo, super_group_id);
	}

    maat_group_reference_super_group(group, super_group_id, is_exclude);
    maat_group_reference_sub_group(super_group, group_id, is_exclude);

    igraph_integer_t edge_id;
	int ret = igraph_get_eid(&group_topo->group_graph, &edge_id, group->vertex_id, 
                             super_group->vertex_id, IGRAPH_DIRECTED, /*error*/ 0);
	
    //No duplicated edges between two groups.
    if (edge_id > 0) {
		log_fatal(group_topo->logger, MODULE_GROUP,
                  "[%s:%d] Add group %d to group %d failed, relation already existed.",
				  __FUNCTION__, __LINE__, group->group_id, super_group->group_id);
		ret = -1;
	} else {
		igraph_add_edge(&group_topo->group_graph, group->vertex_id, 
                        super_group->vertex_id);
		group->ref_by_super_group_cnt++;
		super_group->ref_by_sub_group_cnt++;
		ret = 0;
	}

    igraph_bool_t is_dag;
	igraph_is_dag(&(group_topo->group_graph), &is_dag);
	if (!is_dag) {
		log_fatal(group_topo->logger, MODULE_GROUP,
                  "[%s:%d] Sub group cycle detected, sub_group_id:%lld, super_group_id:%lld!",
                  __FUNCTION__, __LINE__, group_id, super_group_id);
		return -1;
	}

	return ret;
}

static int group_topology_del_group_from_group(struct maat_group_topology *group_topo, 
                                               long long group_id, long long super_group_id,
                                               int is_exclude)
{
    if (NULL == group_topo) {
        return -1;
    }

	//No hash write operation, LOCK protection is unnecessary.
	struct maat_group *group = group_topology_find_group(group_topo, group_id);
	if (NULL == group) {
		log_fatal(group_topo->logger, MODULE_GROUP,
				  "[%s:%d] Del group %d from group %d failed, group %d not existed.",
				  __FUNCTION__, __LINE__, group_id, super_group_id, group_id);
		return -1;	
	}

    struct maat_group *super_group = group_topology_find_group(group_topo, super_group_id);
	if (NULL == super_group) {
		log_fatal(group_topo->logger, MODULE_GROUP,
				  "[%s:%d] Del group %d from group %d failed, superior group %d not existed.",
				  __FUNCTION__, __LINE__, group_id, super_group_id, super_group_id);
		return -1;	
	}

    maat_group_dereference_super_group(group, super_group_id, is_exclude);
    maat_group_dereference_sub_group(super_group, group_id, is_exclude);

	igraph_es_t es;
	igraph_integer_t edge_num_before = 0, edge_num_after = 0;

	edge_num_before = igraph_ecount(&group_topo->group_graph);
	// The edges between the given pairs of vertices will be included in the edge selection.
	//The vertex pairs must be given as the arguments of the function call, the third argument 
	//is the first vertex of the first edge, the fourth argument is the second vertex of the 
	//first edge, the fifth is the first vertex of the second edge and so on. The last element
	//of the argument list must be -1 to denote the end of the argument list.
	//https://igraph.org/c/doc/igraph-Iterators.html#igraph_es_pairs_small
	int ret = igraph_es_pairs_small(&es, IGRAPH_DIRECTED, group->vertex_id, 
                                    super_group->vertex_id, -1);
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

	group->ref_by_super_group_cnt--;
	super_group->ref_by_sub_group_cnt--;

	return 0;
}

static int group_topology_build_super_groups(struct maat_group_topology *group_topo)
{
    if (NULL == group_topo) {
        return -1;
    }

	igraph_bool_t is_dag;
	igraph_is_dag(&(group_topo->group_graph), &is_dag);
	if (!is_dag) {
		log_fatal(group_topo->logger, MODULE_GROUP,
                  "[%s:%d] Sub group cycle detected!", __FUNCTION__, __LINE__);
		return -1;
	}

    struct maat_group *group = NULL, *tmp_group = NULL;
	HASH_ITER (hh_group_id, group_topo->hash_by_group_id, group, tmp_group) {
		//Orphan, Not reference by any one, free it.
		if (0 == group->ref_by_super_group_cnt
			&& 0 == group->ref_by_sub_group_cnt) {
			group_topology_del_group(group_topo, group);
			continue;
		}
	}

	return 0;
}

int group2group_runtime_update(void *g2g_runtime, void *g2g_schema, 
                               const char *table_name, const char *line, 
                               int valid_column)
{
    if (NULL == g2g_runtime || NULL == g2g_schema || 
        NULL == line) {
        return -1;
    }

    struct group2group_schema *schema = (struct group2group_schema *)g2g_schema;
	struct group2group_runtime *g2g_rt = (struct group2group_runtime *)g2g_runtime;
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        log_fatal(g2g_rt->logger, MODULE_GROUP,
                  "[%s:%d] g2g table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        g2g_rt->update_err_cnt++;
        return -1;
    }

    struct group2group_item *g2g_item = group2group_item_new(line, schema, table_name,
                                                             g2g_rt->logger);
    if (NULL == g2g_item) {
        g2g_rt->update_err_cnt++;
        return -1;
    }
    
    if (0 == g2g_rt->updating_flag) {
        assert(g2g_rt->updating_group_topo == NULL);
        g2g_rt->updating_group_topo = maat_group_topology_clone(g2g_rt->group_topo);
        g2g_rt->updating_flag = 1;
    }

    int ret = 0;
    size_t i = 0;
    long long *tmp_group_id = NULL;
    if (0 == is_valid) {
        //delete
        for (i = 0; i < utarray_len(g2g_item->sub_group_ids); i++) {
            tmp_group_id = (long long *)utarray_eltptr(g2g_item->sub_group_ids, i);
            ret = group_topology_del_group_from_group(g2g_rt->updating_group_topo, *tmp_group_id,
                                                      g2g_item->super_group_id, g2g_item->is_exclude);
            if (0 == ret) {
                g2g_rt->rule_num--;
                if (1 == g2g_item->is_exclude) {
                    g2g_rt->excl_rule_num--;
                }
            } else {
                g2g_rt->update_err_cnt++;
            }
        }
    } else {
        //add
        for (i = 0; i < utarray_len(g2g_item->sub_group_ids); i++) {
            tmp_group_id = (long long *)utarray_eltptr(g2g_item->sub_group_ids, i);
            ret = group_topology_add_group_to_group(g2g_rt->updating_group_topo, *tmp_group_id,
                                                    g2g_item->super_group_id, g2g_item->is_exclude);
            if (0 == ret) {
                g2g_rt->rule_num++;
                if (1 == g2g_item->is_exclude) {
                    g2g_rt->excl_rule_num++;
                }
            } else {
                g2g_rt->update_err_cnt++;
            }
        }
    }
    group2group_item_free(g2g_item);

    return ret;
}

static void garbage_maat_group_topology_free(void *data, void *arg)
{
    struct maat_group_topology *group_topo = (struct maat_group_topology *)data;
    maat_group_topology_free(group_topo);
}

int group2group_runtime_commit(void *g2g_runtime, const char *table_name,
                               long long maat_rt_version)
{
    if (NULL == g2g_runtime) {
		return -1;
	}

    struct group2group_runtime *g2g_rt = (struct group2group_runtime *)g2g_runtime;
    if (0 == g2g_rt->updating_flag) {
        return 0;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int ret = group_topology_build_super_groups(g2g_rt->updating_group_topo);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                               (end.tv_nsec - start.tv_nsec) / 1000000;

    if (ret < 0) {
        log_fatal(g2g_rt->logger, MODULE_GROUP, 
                  "[%s:%d] table[%s] group2group runtime commit failed", 
                  __FUNCTION__, __LINE__, table_name);
        return -1;
    }

    struct maat_group_topology *old_group_topo = g2g_rt->group_topo;
    g2g_rt->group_topo = g2g_rt->updating_group_topo;
    g2g_rt->updating_group_topo = NULL;
    g2g_rt->updating_flag = 0;

    maat_garbage_bagging(g2g_rt->ref_garbage_bin, old_group_topo, NULL, 
                         garbage_maat_group_topology_free);

    log_info(g2g_rt->logger, MODULE_GROUP,
             "table[%s] commit %zu g2g rules and rebuild super_groups completed,"
             " version:%lld, consume:%lldms", table_name, g2g_rt->rule_num,
             maat_rt_version, time_elapse_ms);

    return 0;
}

#define MAX_RECURSION_DEPTH 5
static void get_candidate_super_group_ids(struct maat_group_topology *group_topo,
                                          UT_array *hit_group_ids,
                                          UT_array *super_group_ids)
{
    long long *p = NULL;

    //Find super candidates
    for (p = (long long *)utarray_front(hit_group_ids); p != NULL;
         p = (long long *)utarray_next(hit_group_ids, p)) {
        struct maat_group *group = group_topology_find_group(group_topo, *p);
        if (NULL == group) {
            //group_id not in group2group table
            continue;
        }

        for (int i = 0; i < utarray_len(group->incl_super_group_ids); i++) {
            long long *tmp = (long long *)utarray_eltptr(group->incl_super_group_ids, i);
            utarray_push_back(super_group_ids, tmp);
        }
    }
}

static void verify_group_by_sub_include_groups(struct maat_group *group,
                                               UT_array *candidate_group_ids, 
                                               UT_array *kept_super_group_ids,
                                               UT_array *all_hit_group_ids)
{
    size_t remove_idx = 0;
    long long *tmp_id = NULL;

    // delete groups whose all incl sub not in all_hit_group_ids
    if (utarray_len(group->incl_sub_group_ids) != 0) {
        int sub_incl_flag = 0;

        for (tmp_id = (long long *)utarray_front(group->incl_sub_group_ids); tmp_id != NULL;
             tmp_id = (long long *)utarray_next(group->incl_sub_group_ids, tmp_id)) {
            if (utarray_find(candidate_group_ids, tmp_id, compare_group_id)) {
                sub_incl_flag = 1;
                break;
            }
        }

        if (0 == sub_incl_flag) {
            tmp_id = utarray_find(all_hit_group_ids, &(group->group_id), compare_group_id);
            if (tmp_id != NULL) {
                remove_idx = utarray_eltidx(all_hit_group_ids, tmp_id);
                utarray_erase(all_hit_group_ids, remove_idx, 1);
            }

            tmp_id = utarray_find(kept_super_group_ids, &(group->group_id), compare_group_id);
            if (tmp_id != NULL) {
                remove_idx = utarray_eltidx(kept_super_group_ids, tmp_id);
                utarray_erase(kept_super_group_ids, remove_idx, 1);
            }
        }
    }
}

static void verify_group_by_sub_exclude_groups(struct maat_group *group,
                                               UT_array *candidate_group_ids, 
                                               UT_array *kept_super_group_ids,
                                               UT_array *all_hit_group_ids)
{
    if (0 == utarray_len(group->excl_sub_group_ids)) {
        return;
    }

    // delete groups whose excl sub in all_hit_group_ids
    int sub_excl_flag = 0;
    long long *tmp_id = NULL;
    for (tmp_id = (long long *)utarray_front(group->excl_sub_group_ids); tmp_id != NULL;
         tmp_id = (long long *)utarray_next(group->excl_sub_group_ids, tmp_id)) {
        if (utarray_find(candidate_group_ids, tmp_id, compare_group_id)) {
            sub_excl_flag = 1;
            break;
        }
    }

    if (1 == sub_excl_flag) {
        size_t remove_idx = 0;
        tmp_id = utarray_find(all_hit_group_ids, &(group->group_id), compare_group_id);
        if (tmp_id != NULL) {
            remove_idx = utarray_eltidx(all_hit_group_ids, tmp_id);
            utarray_erase(all_hit_group_ids, remove_idx, 1);
        }

        tmp_id = utarray_find(kept_super_group_ids, &(group->group_id), compare_group_id);
        if (tmp_id != NULL) {
            remove_idx = utarray_eltidx(kept_super_group_ids, tmp_id);
            utarray_erase(kept_super_group_ids, remove_idx, 1);
        }
    }
}

static void verify_candidate_super_group_ids(struct maat_group_topology *group_topo,
                                             UT_array *candidate_super_group_ids,
                                             UT_array *all_hit_group_ids,
                                             UT_array *kept_super_group_ids)
{
    long long *p = NULL;
    UT_array *candidate_group_ids;

    utarray_new(candidate_group_ids, &ut_group_id_icd);

    /* merge this round of candidate super groups with hit groups from the previous round */
    for (p = (long long *)utarray_front(candidate_super_group_ids); p != NULL;
         p = (long long *)utarray_next(candidate_super_group_ids, p)) {
        utarray_push_back(candidate_group_ids, p);
    }

    for (p = (long long *)utarray_front(all_hit_group_ids); p != NULL;
         p = (long long *)utarray_next(all_hit_group_ids, p)) {
        utarray_push_back(candidate_group_ids, p);
    }

    utarray_sort(candidate_group_ids, compare_group_id);

    /**
     * verify sub exclude for candidate_super_group_ids
    */
    long long prev_group_id = -1;
    for (p = (long long *)utarray_front(candidate_super_group_ids); p != NULL;
         p = (long long *)utarray_next(candidate_super_group_ids, p)) {
        //filter duplicated group id
        if (*p == prev_group_id) {
            continue;
        }
        prev_group_id = *p;

        struct maat_group *group = group_topology_find_group(group_topo, *p);
        if (NULL == group) {
            continue;
        }

        //if group's sub excl in candidate_group_ids
        int sub_excl_flag = 0;
        long long *tmp_id = NULL;
        for (tmp_id = (long long *)utarray_front(group->excl_sub_group_ids); tmp_id != NULL;
             tmp_id = (long long *)utarray_next(group->excl_sub_group_ids, tmp_id)) {
            if (utarray_find(candidate_group_ids, tmp_id, compare_group_id)) {
                sub_excl_flag = 1;
                break;
            }
        }

        //kept super groups should not store this group
        if (1 == sub_excl_flag) {
            continue;
        }

        utarray_push_back(kept_super_group_ids, p);
        utarray_push_back(all_hit_group_ids, p);
    }

    utarray_sort(all_hit_group_ids, compare_group_id);
    utarray_sort(kept_super_group_ids, compare_group_id);

    /**
     * candidate_group_ids clone all_hit_group_ids
    */
    utarray_clear(candidate_group_ids);
    for (p = (long long *)utarray_front(all_hit_group_ids); p != NULL;
         p = (long long *)utarray_next(all_hit_group_ids, p)) {
        utarray_push_back(candidate_group_ids, p);
    }

    /**
     * 1. delete groups whose excl sub in all_hit_group_ids
     * 2. delete groups whose all incl sub is non-exist in all_hit_group_ids
    */
    for (p = (long long *)utarray_front(candidate_group_ids); p != NULL;
         p = (long long *)utarray_next(candidate_group_ids, p)) {
        struct maat_group *group = group_topology_find_group(group_topo, *p);
        if (NULL == group) {
            continue;
        }

        verify_group_by_sub_exclude_groups(group, candidate_group_ids,
                                           kept_super_group_ids, all_hit_group_ids);
        verify_group_by_sub_include_groups(group, candidate_group_ids,
                                           kept_super_group_ids, all_hit_group_ids);
    }

    utarray_free(candidate_group_ids);
}

static void get_super_group_ids(struct maat_group_topology *group_topo,
                                UT_array *hit_group_ids, UT_array *all_hit_group_ids,
                                size_t depth)
{
    UT_array *candidate_super_group_ids;
    UT_array *kept_super_group_ids;

    if (depth >= MAX_RECURSION_DEPTH) {
        log_error(group_topo->logger, MODULE_GROUP,
                  "[%s:%d]exceed max recursion depth(5)",
                  __FUNCTION__, __LINE__);
        for (int i = 0; i < utarray_len(hit_group_ids); i++) {
            long long *p = (long long *)utarray_eltptr(hit_group_ids, i);
            log_error(group_topo->logger, MODULE_GROUP,
                      "[%s:%d]group_id:%lld can't recursively get super group_id",
                      __FUNCTION__, __LINE__, *p);
        }
        return;
    }

    utarray_new(kept_super_group_ids, &ut_group_id_icd);
    utarray_new(candidate_super_group_ids, &ut_group_id_icd);   

    /**
       candidate super groups means all hit groups' super include group,
       don't consider super exclude groups
       for example:
            hit_groups = {g4, g11}
            g4's super include groups  = {g7, g8}
            g11's super include groups = {g12}

            candidate super groups = {g7, g8, g12}
    */
    get_candidate_super_group_ids(group_topo, hit_group_ids, candidate_super_group_ids);

    if (0 == utarray_len(candidate_super_group_ids)) {
        goto next;
    }

    /**
      verify if candidates should be kept for hit super groups, must consider exclude groups
      for example:
           hit_groups = {g4, g11}
           \:include  x:exclude
                             g12
                             x \
                            x   \
                           x     \
                          x       \        
                g7       g8        \
                x \      /\         \
               x   \    /  \         \
              x     \  /    \         \
             x       \/      \         \
            g3       g4      g5        g11
            candidate super groups = {g7, g8, g12}
            verify logic:
                1. g12's sub_exclude g8 in candidates, so g12 should be dropped
                2. g7 & g8, their sub_include in hit groups, so kept them
                   if their all sub_include not exist in hit groups, they should be dropped
            after verify candidates, kept super groups = {g7, g8}, 
                                     all hit groups = {g4, g11, g7, g8}
    */
    verify_candidate_super_group_ids(group_topo, candidate_super_group_ids, all_hit_group_ids,
                                     kept_super_group_ids);

    depth++;
    get_super_group_ids(group_topo, kept_super_group_ids, all_hit_group_ids, depth);
next: 
    utarray_free(candidate_super_group_ids);
    utarray_free(kept_super_group_ids);
}

static size_t group_topology_get_super_groups(struct maat_group_topology *group_topo, 
                                              long long *group_ids, size_t n_group_ids,
                                              long long *super_group_ids,
                                              size_t super_group_ids_size)
{
    size_t i = 0, idx = 0;
    UT_array *all_hit_group_ids;
    UT_array *candidate_group_ids;

    utarray_new(all_hit_group_ids, &ut_group_id_icd);
    utarray_new(candidate_group_ids, &ut_group_id_icd);

    for (i = 0; i < n_group_ids; i++) {
        utarray_push_back(all_hit_group_ids, &(group_ids[i]));
        utarray_push_back(candidate_group_ids, &(group_ids[i]));
    }

    get_super_group_ids(group_topo, candidate_group_ids, all_hit_group_ids, 0);

    for (i = 0; i < n_group_ids; i++) {
        long long *tmp_id = utarray_find(all_hit_group_ids, &(group_ids[i]),
                                         compare_group_id);
        if (tmp_id != NULL) {
            size_t remove_idx = utarray_eltidx(all_hit_group_ids, tmp_id);
            utarray_erase(all_hit_group_ids, remove_idx, 1);
        }
    }

    long long *p = NULL;
    for (p = (long long *)utarray_front(all_hit_group_ids); p != NULL;
         p = (long long *)utarray_next(all_hit_group_ids, p)) {
        if (idx >= super_group_ids_size) {
            break;
        }
        super_group_ids[idx++] = *p;
    }

    utarray_free(all_hit_group_ids);
    utarray_free(candidate_group_ids);

    return idx;
}

size_t group2group_runtime_get_super_groups(void *g2g_runtime, long long *group_ids, 
                                            size_t n_group_ids, long long *super_group_ids,
                                            size_t super_group_ids_size)
{
    if (NULL == g2g_runtime || NULL == group_ids || 0 == n_group_ids) {
        return 0;
    }
    
    struct group2group_runtime *g2g_rt = (struct group2group_runtime *)g2g_runtime;
    long long g2g_group_ids[n_group_ids];
    size_t g2g_group_ids_cnt = 0;
    
    for (size_t i = 0; i < n_group_ids; i++) {
        struct maat_group *group = group_topology_find_group(g2g_rt->group_topo, group_ids[i]);
        if (NULL == group) {
            continue;
        }

        g2g_group_ids[g2g_group_ids_cnt++] = group_ids[i];
    }

    if (0 == g2g_group_ids_cnt) {
        return 0;
    }

    return group_topology_get_super_groups(g2g_rt->group_topo, g2g_group_ids, g2g_group_ids_cnt,
                                           super_group_ids, super_group_ids_size);
}

long long group2group_runtime_rule_count(void *g2g_runtime)
{
    if (NULL == g2g_runtime) {
        return 0;
    }
    
    struct group2group_runtime *g2g_rt = (struct group2group_runtime *)g2g_runtime;
    return g2g_rt->rule_num;
}

long long group2group_runtime_exclude_rule_count(void *g2g_runtime)
{
    if (NULL == g2g_runtime) {
        return 0;
    }
    
    struct group2group_runtime *g2g_rt = (struct group2group_runtime *)g2g_runtime;
    return g2g_rt->excl_rule_num;
}

long long group2group_runtime_update_err_count(void *g2g_runtime)
{
    if (NULL == g2g_runtime) {
        return 0;
    }
    
    struct group2group_runtime *g2g_rt = (struct group2group_runtime *)g2g_runtime;
    return g2g_rt->update_err_cnt;
}