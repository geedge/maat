/*
**********************************************************************************************
*	File: maat_object.c
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>
#include <pthread.h>

#include "log/log.h"
#include "maat_object.h"
#include "maat_utils.h"
#include "maat_limits.h"
#include "uthash/uthash.h"
#include "uthash/utarray.h"
#include "igraph/igraph.h"
#include "maat_kv.h"

#define MODULE_OBJECT	 module_name_str("maat.object")

struct object2object_item {
    uuid_t object_uuid;
    UT_array *incl_sub_object_uuids;
    UT_array *excl_sub_object_uuids;
};

struct object2object_schema {
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

struct maat_object {
	igraph_integer_t vertex_id;
	uuid_t object_uuid;

	int ref_by_super_object_cnt;
	int ref_by_sub_object_cnt;

	UT_array *incl_super_object_uuids;
    UT_array *excl_super_object_uuids;
    UT_array *incl_sub_object_uuids;
    UT_array *excl_sub_object_uuids;

	UT_hash_handle hh_object_uuid;
	UT_hash_handle hh_vertex_id;
};

struct maat_object_topology {
    struct maat_object *hash_by_object_uuid;  //key: object_id, value: struct maat_object *.
	struct maat_object *hash_by_vertex_id; //key: vetex_id, value: struct maat_object *.
    igraph_t object_graph;
	igraph_integer_t grp_vertex_id_generator;
    struct log_handle *logger;
};

struct object2object_runtime {
    struct maat_object_topology *object_topo;
    struct maat_object_topology *updating_object_topo;
	long long rule_num;
    long long excl_rule_num; //exclude o2o rule num
    long long update_err_cnt;
    int updating_flag;

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

UT_icd ut_object_uuid_icd = {sizeof(uuid_t), NULL, NULL, NULL};

static inline int compare_object_uuid(const void *a, const void *b)
{
    return uuid_compare(*(uuid_t *)a, *(uuid_t *)b);
}

void *object2object_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger)
{
	struct object2object_schema *o2o_schema = ALLOC(struct object2object_schema, 1);
	
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        o2o_schema->table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_OBJECT, 
                  "[%s:%d] o2o table:<%s> schema has no table_id column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    o2o_schema->ref_tbl_mgr = tbl_mgr;
	return o2o_schema;
error:
	FREE(o2o_schema);
	return NULL;
}

void object2object_schema_free(void *o2o_schema)
{
	FREE(o2o_schema);
}

static void object_vertex_free(struct maat_object *object)
{
    if (NULL == object) {
        return;
    }

    if (object->incl_super_object_uuids != NULL) {
        utarray_free(object->incl_super_object_uuids);
        object->incl_super_object_uuids = NULL;
    }
	
    if (object->excl_super_object_uuids != NULL) {
        utarray_free(object->excl_super_object_uuids);
        object->excl_super_object_uuids = NULL;
    }
    
    if (object->incl_sub_object_uuids != NULL) {
        utarray_free(object->incl_sub_object_uuids);
        object->incl_sub_object_uuids = NULL;
    }
    
    if (object->excl_sub_object_uuids != NULL) {
        utarray_free(object->excl_sub_object_uuids);
        object->excl_sub_object_uuids = NULL;
    }

	FREE(object);
}

static struct maat_object_topology *
maat_object_topology_new(struct log_handle *logger)
{
    struct maat_object_topology *object_topo = ALLOC(struct maat_object_topology, 1);
    UNUSED int ret = 0;

    object_topo->hash_by_object_uuid = NULL;
    object_topo->hash_by_vertex_id = NULL;

    ret = igraph_empty(&(object_topo->object_graph), 0, IGRAPH_DIRECTED);
    assert(ret == IGRAPH_SUCCESS);

    object_topo->logger = logger;

    return object_topo;
}

static void maat_object_topology_free(struct maat_object_topology *object_topo)
{
    if (NULL == object_topo) {
        return;
    }
    
    struct maat_object *object = NULL, *tmp_object = NULL;

    HASH_CLEAR(hh_vertex_id, object_topo->hash_by_vertex_id);//No need object memory clean up.
	HASH_ITER(hh_object_uuid, object_topo->hash_by_object_uuid, object, tmp_object) {
		HASH_DELETE(hh_object_uuid, object_topo->hash_by_object_uuid, object);
		object_vertex_free(object);
	}
	assert(object_topo->hash_by_object_uuid == NULL);	
	
	igraph_destroy(&object_topo->object_graph);
    FREE(object_topo);
}

static struct maat_object *maat_object_clone(struct maat_object *object)
{
    struct maat_object *object_copy = ALLOC(struct maat_object, 1);

    uuid_copy(object_copy->object_uuid, object->object_uuid);
    object_copy->vertex_id = object->vertex_id;
    object_copy->ref_by_sub_object_cnt = object->ref_by_sub_object_cnt;
    object_copy->ref_by_super_object_cnt = object->ref_by_super_object_cnt;
    utarray_new(object_copy->incl_super_object_uuids, &ut_object_uuid_icd);
    utarray_new(object_copy->excl_super_object_uuids, &ut_object_uuid_icd);
    utarray_new(object_copy->incl_sub_object_uuids, &ut_object_uuid_icd);
    utarray_new(object_copy->excl_sub_object_uuids, &ut_object_uuid_icd);

    uuid_t *p = NULL;
    for (p = (uuid_t *)utarray_front(object->incl_super_object_uuids); p != NULL;
         p = (uuid_t *)utarray_next(object->incl_super_object_uuids, p)) {
        utarray_push_back(object_copy->incl_super_object_uuids, p);
    }

    for (p = (uuid_t *)utarray_front(object->excl_super_object_uuids); p != NULL;
         p = (uuid_t *)utarray_next(object->excl_super_object_uuids, p)) {
        utarray_push_back(object_copy->excl_super_object_uuids, p);
    }

    for (p = (uuid_t *)utarray_front(object->incl_sub_object_uuids); p != NULL;
         p = (uuid_t *)utarray_next(object->incl_sub_object_uuids, p)) {
        utarray_push_back(object_copy->incl_sub_object_uuids, p);
    }

    for (p = (uuid_t *)utarray_front(object->excl_sub_object_uuids); p != NULL;
         p = (uuid_t *)utarray_next(object->excl_sub_object_uuids, p)) {
        utarray_push_back(object_copy->excl_sub_object_uuids, p);
    }

    return object_copy;
}

static struct maat_object_topology *
maat_object_topology_clone(struct maat_object_topology *object_topo)
{
    if (NULL == object_topo) {
        return NULL;
    }

    struct maat_object_topology *object_topo_copy = ALLOC(struct maat_object_topology, 1);

    struct maat_object *object = NULL, *tmp_object = NULL;
    HASH_ITER(hh_object_uuid, object_topo->hash_by_object_uuid, object, tmp_object) {
        struct maat_object *object_copy = maat_object_clone(object);

        HASH_ADD(hh_object_uuid, object_topo_copy->hash_by_object_uuid, object_uuid, 
                 sizeof(object_copy->object_uuid), object_copy);
        HASH_ADD(hh_vertex_id, object_topo_copy->hash_by_vertex_id, vertex_id,
                sizeof(object_copy->vertex_id), object_copy);
    }

    igraph_copy(&(object_topo_copy->object_graph), &(object_topo->object_graph));
    object_topo_copy->grp_vertex_id_generator = object_topo->grp_vertex_id_generator;
    object_topo_copy->logger = object_topo->logger;

    return object_topo_copy;
}

void *object2object_runtime_new(void *o2o_schema, size_t max_thread_num,
                              struct maat_garbage_bin *garbage_bin, 
                              struct log_handle *logger)
{
    if (NULL == o2o_schema) {
        return NULL;
    }

	struct object2object_runtime *o2o_rt = ALLOC(struct object2object_runtime, 1);

	o2o_rt->object_topo = maat_object_topology_new(logger);
    o2o_rt->ref_garbage_bin = garbage_bin;
    o2o_rt->logger = logger;

	return o2o_rt;
}

void object2object_runtime_free(void *o2o_runtime)
{
    if (NULL == o2o_runtime) {
        return;
    }

    struct object2object_runtime *o2o_rt = (struct object2object_runtime *)o2o_runtime;

    if (o2o_rt->object_topo != NULL) {
        maat_object_topology_free(o2o_rt->object_topo);
        o2o_rt->object_topo = NULL;
    }
    
    if (o2o_rt->updating_object_topo != NULL) {
        maat_object_topology_free(o2o_rt->updating_object_topo);
        o2o_rt->updating_object_topo = NULL;
    }

    FREE(o2o_rt);
}

static struct object2object_item *
object2object_item_new(const char *line, struct object2object_schema *o2o_schema,
                     const char *table_name, struct log_handle *logger)
{
    cJSON *tmp_obj = NULL;
    cJSON *json = cJSON_Parse(line);

    if (json == NULL) {
        log_fatal(logger, MODULE_OBJECT,
                  "[%s:%d] o2o table:<%s> line:<%s> parse json failed",
                  __FUNCTION__, __LINE__, table_name, line);
        return NULL;
    }

    struct object2object_item *o2o_item = ALLOC(struct object2object_item, 1);
    utarray_new(o2o_item->incl_sub_object_uuids, &ut_object_uuid_icd);
    utarray_new(o2o_item->excl_sub_object_uuids, &ut_object_uuid_icd);

    tmp_obj = cJSON_GetObjectItem(json, "object_uuid");
    if (tmp_obj == NULL || tmp_obj->type != cJSON_String) {
        log_fatal(logger, MODULE_OBJECT,
                  "[%s:%d] o2o table:<%s> has no object_uuid or format is not string in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    uuid_parse(tmp_obj->valuestring, o2o_item->object_uuid);

    tmp_obj = cJSON_GetObjectItem(json, "included_sub_object_uuids");
    if (tmp_obj) {
        if (tmp_obj->type != cJSON_Array) {
            log_fatal(logger, MODULE_OBJECT,
                    "[%s:%d] o2o table:<%s> included_sub_object_ids format is not array in line:%s",
                    __FUNCTION__, __LINE__, table_name, line);
            goto error;
        }

        for (int i = 0; i < cJSON_GetArraySize(tmp_obj); i++) {
            cJSON *item = cJSON_GetArrayItem(tmp_obj, i);
            if (item == NULL || item->type != cJSON_String) {
                log_fatal(logger, MODULE_OBJECT,
                        "[%s:%d] o2o table:<%s> included_sub_object_ids format error in line:%s",
                        __FUNCTION__, __LINE__, table_name, line);
                goto error;
            }
            uuid_t object_uuid;
            uuid_parse(item->valuestring, object_uuid);
            utarray_push_back(o2o_item->incl_sub_object_uuids, &object_uuid);
        }

        if (utarray_len(o2o_item->incl_sub_object_uuids) > MAX_OBJECT_CNT) {
            log_fatal(logger, MODULE_OBJECT,
                    "[%s:%d] o2r table:<%s> included_sub_object_ids exceed maximum:%d in line:%s",
                    __FUNCTION__, __LINE__, table_name, MAX_OBJECT_CNT, line);
            goto error;
        }
    }

    tmp_obj = cJSON_GetObjectItem(json, "excluded_sub_object_uuids");
    if (tmp_obj) {
        if (tmp_obj->type != cJSON_Array) {
            log_fatal(logger, MODULE_OBJECT,
                    "[%s:%d] o2o table:<%s> excluded_sub_object_ids format is not array in line:%s",
                    __FUNCTION__, __LINE__, table_name, line);
            goto error;
        }

        for (int i = 0; i < cJSON_GetArraySize(tmp_obj); i++) {
            cJSON *item = cJSON_GetArrayItem(tmp_obj, i);
            if (item == NULL || item->type != cJSON_String) {
                log_fatal(logger, MODULE_OBJECT,
                        "[%s:%d] o2o table:<%s> excluded_sub_object_ids format error in line:%s",
                        __FUNCTION__, __LINE__, table_name, line);
                goto error;
            }
            uuid_t object_uuid;
            uuid_parse(item->valuestring, object_uuid);
            utarray_push_back(o2o_item->excl_sub_object_uuids, &object_uuid);
        }

        if (utarray_len(o2o_item->excl_sub_object_uuids) > MAX_OBJECT_CNT) {
            log_fatal(logger, MODULE_OBJECT,
                    "[%s:%d] o2r table:<%s> excluded_sub_object_ids exceed maximum:%d in line:%s",
                    __FUNCTION__, __LINE__, table_name, MAX_OBJECT_CNT, line);
            goto error;
        }
    }

    cJSON_Delete(json);

    return o2o_item;
error:
    if (json) {
        cJSON_Delete(json);
    }
    FREE(o2o_item);
    return NULL;
}

static void object2object_item_free(struct object2object_item *o2o_item)
{
    if (NULL == o2o_item) {
        return;
    }

    if (o2o_item->incl_sub_object_uuids != NULL) {
        utarray_free(o2o_item->incl_sub_object_uuids);
        o2o_item->incl_sub_object_uuids = NULL;
    }

    if (o2o_item->excl_sub_object_uuids != NULL) {
        utarray_free(o2o_item->excl_sub_object_uuids);
        o2o_item->excl_sub_object_uuids = NULL;
    }

    FREE(o2o_item);
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

static struct maat_object *
object_topology_add_object(struct maat_object_topology *object_topo, uuid_t *object_uuid)
{
    assert(object_topo != NULL);

	struct maat_object *object = ALLOC(struct maat_object, 1);
    uuid_copy(object->object_uuid, *object_uuid);
	object->vertex_id = object_topo->grp_vertex_id_generator++;
    utarray_new(object->incl_super_object_uuids, &ut_object_uuid_icd);
    utarray_new(object->excl_super_object_uuids, &ut_object_uuid_icd);
    utarray_new(object->incl_sub_object_uuids, &ut_object_uuid_icd);
    utarray_new(object->excl_sub_object_uuids, &ut_object_uuid_icd);

	assert(igraph_vcount(&object_topo->object_graph)==object->vertex_id);
	igraph_add_vertices(&object_topo->object_graph, 1, NULL);	//Add 1 vertice.
	
	HASH_ADD(hh_object_uuid, object_topo->hash_by_object_uuid, object_uuid,
             sizeof(object->object_uuid), object);
	HASH_ADD(hh_vertex_id, object_topo->hash_by_vertex_id, vertex_id,
             sizeof(object->vertex_id), object);
    
	return object;
}

static void object_topology_del_object(struct maat_object_topology *object_topo,
                                     struct maat_object *object)
{
    if (NULL == object_topo || NULL == object) {
        return;
    }

    igraph_vector_t v; 
	char buff[4096] = {0};

    assert(object->ref_by_super_object_cnt == 0);

	igraph_vector_init(&v, 8);
	igraph_neighbors(&object_topo->object_graph, &v, object->vertex_id, IGRAPH_ALL);
	if (igraph_vector_size(&v) > 0) {
		print_igraph_vector(&v, buff, sizeof(buff));
		log_fatal(object_topo->logger, MODULE_OBJECT, 
                 "[%s:%d] Del object %d exception, still reached by %s.",
				  __FUNCTION__, __LINE__, object->vertex_id, buff);
		assert(0);
	}
	igraph_vector_destroy(&v);
	
	//We should not call igraph_delete_vertices, because this is function changes the ids of the vertices.

	HASH_DELETE(hh_object_uuid, object_topo->hash_by_object_uuid, object);
	HASH_DELETE(hh_vertex_id, object_topo->hash_by_vertex_id, object);
	object_vertex_free(object);
}

static struct maat_object *
object_topology_find_object(struct maat_object_topology *object_topo, uuid_t *object_uuid)
{
    if (NULL == object_topo || uuid_is_null(*object_uuid)) {
        return NULL;
    }

    struct maat_object *object = NULL;
    HASH_FIND(hh_object_uuid, object_topo->hash_by_object_uuid, (char*)object_uuid, sizeof(uuid_t), object);

    return object;
}

static void maat_object_reference_super_object(struct maat_object *object,
                                             uuid_t *super_object_uuid,
                                             int is_exclude)
{
    if (NULL == object || uuid_is_null(*super_object_uuid)) {
        return;
    }

    if (0 == is_exclude) {
        //include superior object
        if (!utarray_find(object->incl_super_object_uuids, super_object_uuid,
                          compare_object_uuid)) {
            utarray_push_back(object->incl_super_object_uuids, super_object_uuid);
            utarray_sort(object->incl_super_object_uuids, compare_object_uuid);
        }
    } else {
        //exclude superior object
        if (!utarray_find(object->excl_super_object_uuids, super_object_uuid,
                          compare_object_uuid)) {
            utarray_push_back(object->excl_super_object_uuids, super_object_uuid);
            utarray_sort(object->excl_super_object_uuids, compare_object_uuid);
        }
    }
}

static void maat_object_reference_sub_object(struct maat_object *object,
                                           uuid_t *sub_object_uuid,
                                           int is_exclude)
{
    if (NULL == object || uuid_is_null(*sub_object_uuid)) {
        return;
    }

    if (0 == is_exclude) {
        //include sub object
        if (!utarray_find(object->incl_sub_object_uuids, sub_object_uuid,
                          compare_object_uuid)) {
            utarray_push_back(object->incl_sub_object_uuids, sub_object_uuid);
            utarray_sort(object->incl_sub_object_uuids, compare_object_uuid);
        }
    } else {
        //exclude sub object
        if (!utarray_find(object->excl_sub_object_uuids, sub_object_uuid,
                          compare_object_uuid)) {
            utarray_push_back(object->excl_sub_object_uuids, sub_object_uuid);
            utarray_sort(object->excl_sub_object_uuids, compare_object_uuid);
        }
    }
}

static void maat_object_dereference_super_object(struct maat_object *object,
                                               uuid_t *super_object_uuid,
                                               int is_exclude)
{
    if (NULL == object || uuid_is_null(*super_object_uuid)) {
        return;
    }

    size_t remove_idx = 0;
    uuid_t *tmp_uuid = NULL;
    if (0 == is_exclude) {
        //include superior object
        tmp_uuid = utarray_find(object->incl_super_object_uuids, super_object_uuid,
                              compare_object_uuid);
        if (tmp_uuid != NULL) {
            remove_idx = utarray_eltidx(object->incl_super_object_uuids, tmp_uuid);
            utarray_erase(object->incl_super_object_uuids, remove_idx, 1);
        }
    } else {
        //exclude superior object
        tmp_uuid = utarray_find(object->excl_super_object_uuids, super_object_uuid,
                              compare_object_uuid);
        if (tmp_uuid != NULL) {
            remove_idx = utarray_eltidx(object->excl_super_object_uuids, tmp_uuid);
            utarray_erase(object->excl_super_object_uuids, remove_idx, 1);
        }
    }
}

static void maat_object_dereference_sub_object(struct maat_object *object,
                                             uuid_t *sub_object_uuid,
                                             int is_exclude)
{
    if (NULL == object || uuid_is_null(*sub_object_uuid)) {
        return;
    }

    size_t remove_idx = 0;
    uuid_t *tmp_uuid = NULL;
    if (0 == is_exclude) {
        //include superior object
        tmp_uuid = utarray_find(object->incl_sub_object_uuids, sub_object_uuid,
                              compare_object_uuid);
        if (tmp_uuid != NULL) {
            remove_idx = utarray_eltidx(object->incl_sub_object_uuids, tmp_uuid);
            utarray_erase(object->incl_sub_object_uuids, remove_idx, 1);
        }
    } else {
        //exclude superior object
        tmp_uuid = utarray_find(object->excl_sub_object_uuids, sub_object_uuid,
                              compare_object_uuid);
        if (tmp_uuid != NULL) {
            remove_idx = utarray_eltidx(object->excl_sub_object_uuids, tmp_uuid);
            utarray_erase(object->excl_sub_object_uuids, remove_idx, 1);
        }
    }
}

static int object_topology_add_object_to_object(struct maat_object_topology *object_topo, 
                                             uuid_t *object_uuid, uuid_t *sub_object_uuid,
                                             int is_exclude)
{
    if (NULL == object_topo) {
        return -1;
    }

    struct maat_object *sub_object = object_topology_find_object(object_topo, sub_object_uuid);
    if (NULL == sub_object) {
        sub_object = object_topology_add_object(object_topo, sub_object_uuid);
	}
	
    struct maat_object *object = object_topology_find_object(object_topo, object_uuid);
	if (NULL == object) {
		object = object_topology_add_object(object_topo, object_uuid);
	}

    maat_object_reference_super_object(sub_object, object_uuid, is_exclude);
    maat_object_reference_sub_object(object, sub_object_uuid, is_exclude);

    igraph_integer_t edge_id;
	int ret = igraph_get_eid(&object_topo->object_graph, &edge_id, sub_object->vertex_id, 
                             object->vertex_id, IGRAPH_DIRECTED, /*error*/ 0);
	
    //No duplicated edges between two objects.
    if (edge_id > 0) {
        char object_uuid_str[37] = {0};
        char sub_object_uuid_str[37] = {0};
        uuid_unparse(*object_uuid, object_uuid_str);
        uuid_unparse(*sub_object_uuid, sub_object_uuid_str);
		log_fatal(object_topo->logger, MODULE_OBJECT,
                  "[%s:%d] Add object %s to object %s failed, relation already existed.",
				  __FUNCTION__, __LINE__, sub_object_uuid_str, object_uuid_str);
		ret = -1;
	} else {
		igraph_add_edge(&object_topo->object_graph, sub_object->vertex_id, 
                        object->vertex_id);
		sub_object->ref_by_super_object_cnt++;
		object->ref_by_sub_object_cnt++;
		ret = 0;
	}

    igraph_bool_t is_dag;
	igraph_is_dag(&(object_topo->object_graph), &is_dag);
	if (!is_dag) {
        char object_uuid_str[37] = {0};
        char sub_object_uuid_str[37] = {0};
        uuid_unparse(*object_uuid, object_uuid_str);
        uuid_unparse(*sub_object_uuid, sub_object_uuid_str);
		log_fatal(object_topo->logger, MODULE_OBJECT,
                  "[%s:%d] Sub object cycle detected, sub_object_id:%s, object_id:%s!",
                  __FUNCTION__, __LINE__, sub_object_uuid_str, object_uuid_str);
		return -1;
	}

	return ret;
}

static int object_topology_del_object_from_object(struct maat_object_topology *object_topo, 
                                               uuid_t *object_uuid, uuid_t *sub_object_uuid,
                                               int is_exclude)
{
    if (NULL == object_topo) {
        return -1;
    }

	//No hash write operation, LOCK protection is unnecessary.
	struct maat_object *sub_object = object_topology_find_object(object_topo, sub_object_uuid);
	if (NULL == sub_object) {
        char object_uuid_str[37] = {0};
        char sub_object_uuid_str[37] = {0};
        uuid_unparse(*object_uuid, object_uuid_str);
        uuid_unparse(*sub_object_uuid, sub_object_uuid_str);
		log_fatal(object_topo->logger, MODULE_OBJECT,
				  "[%s:%d] Del object %s from object %s failed, object %s not existed.",
				  __FUNCTION__, __LINE__, sub_object_uuid_str, object_uuid_str, sub_object_uuid_str);
		return -1;	
	}

    struct maat_object *object = object_topology_find_object(object_topo, object_uuid);
	if (NULL == object) {
        char object_uuid_str[37] = {0};
        char sub_object_uuid_str[37] = {0};
        uuid_unparse(*object_uuid, object_uuid_str);
        uuid_unparse(*sub_object_uuid, sub_object_uuid_str);
		log_fatal(object_topo->logger, MODULE_OBJECT,
				  "[%s:%d] Del object %s from object %s failed, object %s not existed.",
				  __FUNCTION__, __LINE__, sub_object_uuid_str, object_uuid_str, object_uuid_str);
		return -1;	
	}

    maat_object_dereference_super_object(sub_object, object_uuid, is_exclude);
    maat_object_dereference_sub_object(object, sub_object_uuid, is_exclude);

	igraph_es_t es;
	igraph_integer_t edge_num_before = 0, edge_num_after = 0;

	edge_num_before = igraph_ecount(&object_topo->object_graph);
	// The edges between the given pairs of vertices will be included in the edge selection.
	//The vertex pairs must be given as the arguments of the function call, the third argument 
	//is the first vertex of the first edge, the fourth argument is the second vertex of the 
	//first edge, the fifth is the first vertex of the second edge and so on. The last element
	//of the argument list must be -1 to denote the end of the argument list.
	//https://igraph.org/c/doc/igraph-Iterators.html#igraph_es_pairs_small
	int ret = igraph_es_pairs_small(&es, IGRAPH_DIRECTED, sub_object->vertex_id, 
                                    object->vertex_id, -1);
	assert(ret==IGRAPH_SUCCESS);
	// ignore no such edge to abort().
	igraph_set_error_handler(igraph_error_handler_ignore);
	ret = igraph_delete_edges(&object_topo->object_graph, es);
	edge_num_after = igraph_ecount(&object_topo->object_graph);
	igraph_es_destroy(&es);
	
	if (ret != IGRAPH_SUCCESS || edge_num_before - edge_num_after != 1) {
		assert(0);
		return -1;
	}

	sub_object->ref_by_super_object_cnt--;
	object->ref_by_sub_object_cnt--;

	return 0;
}

static int object_topology_build_super_objects(struct maat_object_topology *object_topo)
{
    if (NULL == object_topo) {
        return -1;
    }

	igraph_bool_t is_dag;
	igraph_is_dag(&(object_topo->object_graph), &is_dag);
	if (!is_dag) {
		log_fatal(object_topo->logger, MODULE_OBJECT,
                  "[%s:%d] Sub object cycle detected!", __FUNCTION__, __LINE__);
		return -1;
	}

    struct maat_object *object = NULL, *tmp_object = NULL;
	HASH_ITER (hh_object_uuid, object_topo->hash_by_object_uuid, object, tmp_object) {
		//Orphan, Not reference by any one, free it.
		if (0 == object->ref_by_super_object_cnt
			&& 0 == object->ref_by_sub_object_cnt) {
			object_topology_del_object(object_topo, object);
			continue;
		}
	}

	return 0;
}

int object2object_runtime_update(void *o2o_runtime, void *o2o_schema, 
                               const char *table_name, const char *line, 
                               enum maat_operation op)
{
    if (NULL == o2o_runtime || NULL == o2o_schema || 
        NULL == line) {
        return -1;
    }

    struct object2object_schema *schema = (struct object2object_schema *)o2o_schema;
	struct object2object_runtime *o2o_rt = (struct object2object_runtime *)o2o_runtime;

    struct object2object_item *o2o_item = object2object_item_new(line, schema, table_name,
                                                             o2o_rt->logger);
    if (NULL == o2o_item) {
        o2o_rt->update_err_cnt++;
        return -1;
    }
    
    if (0 == o2o_rt->updating_flag) {
        assert(o2o_rt->updating_object_topo == NULL);
        o2o_rt->updating_object_topo = maat_object_topology_clone(o2o_rt->object_topo);
        o2o_rt->updating_flag = 1;
    }

    int ret = 0;
    size_t i = 0;
    int err_flag = 0;
    uuid_t *sub_object_uuid = NULL;
    if (MAAT_OP_DEL == op) {
        //delete
        for (i = 0; i < utarray_len(o2o_item->incl_sub_object_uuids); i++) {
            sub_object_uuid = (uuid_t *)utarray_eltptr(o2o_item->incl_sub_object_uuids, i);
            ret = object_topology_del_object_from_object(o2o_rt->updating_object_topo,
                                                      &o2o_item->object_uuid, sub_object_uuid, 0);
            if (ret != 0) {
                err_flag = 1;
            }
        }

        for (i = 0; i < utarray_len(o2o_item->excl_sub_object_uuids); i++) {
            sub_object_uuid = (uuid_t *)utarray_eltptr(o2o_item->excl_sub_object_uuids, i);
            ret = object_topology_del_object_from_object(o2o_rt->updating_object_topo,
                                                      &o2o_item->object_uuid, sub_object_uuid, 1);
            if (ret != 0) {
                err_flag = 1;
            }
        }

        if (1 == err_flag) {
            o2o_rt->update_err_cnt++;
        } else {
            if (utarray_len(o2o_item->excl_sub_object_uuids) > 0) {
                o2o_rt->excl_rule_num--;
            }
            o2o_rt->rule_num--;
        }
    } else {
        //add
        for (i = 0; i < utarray_len(o2o_item->incl_sub_object_uuids); i++) {
            sub_object_uuid = (uuid_t *)utarray_eltptr(o2o_item->incl_sub_object_uuids, i);
            ret = object_topology_add_object_to_object(o2o_rt->updating_object_topo,
                                                    &o2o_item->object_uuid, sub_object_uuid, 0);
            if (ret != 0) {
                err_flag = 1;
            }
        }

        for (i = 0; i < utarray_len(o2o_item->excl_sub_object_uuids); i++) {
            sub_object_uuid = (uuid_t *)utarray_eltptr(o2o_item->excl_sub_object_uuids, i);
            ret = object_topology_add_object_to_object(o2o_rt->updating_object_topo,
                                                    &o2o_item->object_uuid, sub_object_uuid, 1);
            if (ret != 0) {
                err_flag = 1;
            }
        }

        if (1 == err_flag) {
            o2o_rt->update_err_cnt++;
        } else {
            if (utarray_len(o2o_item->excl_sub_object_uuids) > 0) {
                o2o_rt->excl_rule_num++;
            }
            o2o_rt->rule_num++;
        }
    }
    object2object_item_free(o2o_item);

    return ret;
}

static void garbage_maat_object_topology_free(void *data, void *arg)
{
    struct maat_object_topology *object_topo = (struct maat_object_topology *)data;
    maat_object_topology_free(object_topo);
}

int object2object_runtime_commit(void *o2o_runtime, const char *table_name,
                               long long maat_rt_version)
{
    if (NULL == o2o_runtime) {
		return -1;
	}

    struct object2object_runtime *o2o_rt = (struct object2object_runtime *)o2o_runtime;
    if (0 == o2o_rt->updating_flag) {
        return 0;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int ret = object_topology_build_super_objects(o2o_rt->updating_object_topo);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                               (end.tv_nsec - start.tv_nsec) / 1000000;

    if (ret < 0) {
        log_fatal(o2o_rt->logger, MODULE_OBJECT, 
                  "[%s:%d] table[%s] object2object runtime commit failed", 
                  __FUNCTION__, __LINE__, table_name);
        return -1;
    }

    struct maat_object_topology *old_object_topo = o2o_rt->object_topo;
    o2o_rt->object_topo = o2o_rt->updating_object_topo;
    o2o_rt->updating_object_topo = NULL;
    o2o_rt->updating_flag = 0;

    maat_garbage_bagging(o2o_rt->ref_garbage_bin, old_object_topo, NULL, 
                         garbage_maat_object_topology_free);

    log_info(o2o_rt->logger, MODULE_OBJECT,
             "table[%s] commit %zu o2o rules and rebuild super_objects completed,"
             " version:%lld, consume:%lldms", table_name, o2o_rt->rule_num,
             maat_rt_version, time_elapse_ms);

    return 0;
}

#define MAX_RECURSION_DEPTH 5
static void get_candidate_super_object_ids(struct maat_object_topology *object_topo,
                                          UT_array *hit_object_uuids,
                                          UT_array *super_object_uuids)
{
    uuid_t *p = NULL;

    //Find super candidates
    for (p = (uuid_t *)utarray_front(hit_object_uuids); p != NULL;
         p = (uuid_t *)utarray_next(hit_object_uuids, p)) {
        struct maat_object *object = object_topology_find_object(object_topo, p);
        if (NULL == object) {
            //object_id not in object2object table
            continue;
        }

        for (int i = 0; i < utarray_len(object->incl_super_object_uuids); i++) {
            uuid_t *tmp = (uuid_t *)utarray_eltptr(object->incl_super_object_uuids, i);
            utarray_push_back(super_object_uuids, tmp);
        }
    }
}

static void verify_object_by_sub_include_objects(struct maat_object *object,
                                               UT_array *candidate_object_uuids, 
                                               UT_array *kept_super_object_uuids,
                                               UT_array *all_hit_object_uuids)
{
    size_t remove_idx = 0;
    uuid_t *tmp_uuid = NULL;

    // delete objects whose all incl sub not in all_hit_object_ids
    if (utarray_len(object->incl_sub_object_uuids) != 0) {
        int sub_incl_flag = 0;

        for (tmp_uuid = (uuid_t *)utarray_front(object->incl_sub_object_uuids); tmp_uuid != NULL;
             tmp_uuid = (uuid_t *)utarray_next(object->incl_sub_object_uuids, tmp_uuid)) {
            if (utarray_find(candidate_object_uuids, tmp_uuid, compare_object_uuid)) {
                sub_incl_flag = 1;
                break;
            }
        }

        if (0 == sub_incl_flag) {
            tmp_uuid = utarray_find(all_hit_object_uuids, &(object->object_uuid), compare_object_uuid);
            if (tmp_uuid != NULL) {
                remove_idx = utarray_eltidx(all_hit_object_uuids, tmp_uuid);
                utarray_erase(all_hit_object_uuids, remove_idx, 1);
            }

            tmp_uuid = utarray_find(kept_super_object_uuids, &(object->object_uuid), compare_object_uuid);
            if (tmp_uuid != NULL) {
                remove_idx = utarray_eltidx(kept_super_object_uuids, tmp_uuid);
                utarray_erase(kept_super_object_uuids, remove_idx, 1);
            }
        }
    }
}

static void verify_object_by_sub_exclude_objects(struct maat_object *object,
                                               UT_array *candidate_object_uuids, 
                                               UT_array *kept_super_object_uuids,
                                               UT_array *all_hit_object_uuids)
{
    if (0 == utarray_len(object->excl_sub_object_uuids)) {
        return;
    }

    // delete objects whose excl sub in all_hit_object_ids
    int sub_excl_flag = 0;
    uuid_t *tmp_uuid = NULL;
    for (tmp_uuid = (uuid_t *)utarray_front(object->excl_sub_object_uuids); tmp_uuid != NULL;
         tmp_uuid = (uuid_t *)utarray_next(object->excl_sub_object_uuids, tmp_uuid)) {
        if (utarray_find(candidate_object_uuids, tmp_uuid, compare_object_uuid)) {
            sub_excl_flag = 1;
            break;
        }
    }

    if (1 == sub_excl_flag) {
        size_t remove_idx = 0;
        tmp_uuid = utarray_find(all_hit_object_uuids, &(object->object_uuid), compare_object_uuid);
        if (tmp_uuid != NULL) {
            remove_idx = utarray_eltidx(all_hit_object_uuids, tmp_uuid);
            utarray_erase(all_hit_object_uuids, remove_idx, 1);
        }

        tmp_uuid = utarray_find(kept_super_object_uuids, &(object->object_uuid), compare_object_uuid);
        if (tmp_uuid != NULL) {
            remove_idx = utarray_eltidx(kept_super_object_uuids, tmp_uuid);
            utarray_erase(kept_super_object_uuids, remove_idx, 1);
        }
    }
}

static void verify_candidate_super_object_ids(struct maat_object_topology *object_topo,
                                             UT_array *candidate_super_object_uuids,
                                             UT_array *all_hit_object_uuids,
                                             UT_array *kept_super_object_uuids)
{
    uuid_t *p = NULL;
    UT_array *candidate_object_uuids;

    utarray_new(candidate_object_uuids, &ut_object_uuid_icd);

    /* merge this round of candidate super objects with hit objects from the previous round */
    for (p = (uuid_t *)utarray_front(candidate_super_object_uuids); p != NULL;
         p = (uuid_t *)utarray_next(candidate_super_object_uuids, p)) {
        utarray_push_back(candidate_object_uuids, p);
    }

    for (p = (uuid_t *)utarray_front(all_hit_object_uuids); p != NULL;
         p = (uuid_t *)utarray_next(all_hit_object_uuids, p)) {
        utarray_push_back(candidate_object_uuids, p);
    }

    utarray_sort(candidate_object_uuids, compare_object_uuid);

    /**
     * verify sub exclude for candidate_super_object_ids
    */
    uuid_t prev_object_uuid;
    uuid_clear(prev_object_uuid);
    for (p = (uuid_t *)utarray_front(candidate_super_object_uuids); p != NULL;
         p = (uuid_t *)utarray_next(candidate_super_object_uuids, p)) {
        //filter duplicated object id
        if (uuid_compare(*p, prev_object_uuid) == 0) {
            continue;
        }
        uuid_copy(prev_object_uuid, *p);

        struct maat_object *object = object_topology_find_object(object_topo, p);
        if (NULL == object) {
            continue;
        }

        //if object's sub excl in candidate_object_ids
        int sub_excl_flag = 0;
        uuid_t *tmp_uuid = NULL;
        for (tmp_uuid = (uuid_t *)utarray_front(object->excl_sub_object_uuids); tmp_uuid != NULL;
             tmp_uuid = (uuid_t *)utarray_next(object->excl_sub_object_uuids, tmp_uuid)) {
            if (utarray_find(candidate_object_uuids, tmp_uuid, compare_object_uuid)) {
                sub_excl_flag = 1;
                break;
            }
        }

        //kept super objects should not store this object
        if (1 == sub_excl_flag) {
            continue;
        }

        utarray_push_back(kept_super_object_uuids, p);
        utarray_push_back(all_hit_object_uuids, p);
    }

    utarray_sort(all_hit_object_uuids, compare_object_uuid);
    utarray_sort(kept_super_object_uuids, compare_object_uuid);

    /**
     * candidate_object_ids clone all_hit_object_ids
    */
    utarray_clear(candidate_object_uuids);
    for (p = (uuid_t *)utarray_front(all_hit_object_uuids); p != NULL;
         p = (uuid_t *)utarray_next(all_hit_object_uuids, p)) {
        utarray_push_back(candidate_object_uuids, p);
    }

    /**
     * 1. delete objects whose excl sub in all_hit_object_ids
     * 2. delete objects whose all incl sub is non-exist in all_hit_object_ids
    */
    for (p = (uuid_t *)utarray_front(candidate_object_uuids); p != NULL;
         p = (uuid_t *)utarray_next(candidate_object_uuids, p)) {
        struct maat_object *object = object_topology_find_object(object_topo, p);
        if (NULL == object) {
            continue;
        }

        verify_object_by_sub_exclude_objects(object, candidate_object_uuids,
                                           kept_super_object_uuids, all_hit_object_uuids);
        verify_object_by_sub_include_objects(object, candidate_object_uuids,
                                           kept_super_object_uuids, all_hit_object_uuids);
    }

    utarray_free(candidate_object_uuids);
}

static void get_super_object_ids(struct maat_object_topology *object_topo,
                                UT_array *hit_object_uuids, UT_array *all_hit_object_uuids,
                                size_t depth)
{
    UT_array *candidate_super_object_uuids;
    UT_array *kept_super_object_uuids;

    if (depth >= MAX_RECURSION_DEPTH) {
        log_error(object_topo->logger, MODULE_OBJECT,
                  "[%s:%d]exceed max recursion depth(5)",
                  __FUNCTION__, __LINE__);
        for (int i = 0; i < utarray_len(hit_object_uuids); i++) {
            uuid_t *p = (uuid_t *)utarray_eltptr(hit_object_uuids, i);
            char uuid_str[UUID_STR_LEN] = {0};
            uuid_unparse(*p, uuid_str);
            log_error(object_topo->logger, MODULE_OBJECT,
                      "[%s:%d]object_id:%s can't recursively get super object_id",
                      __FUNCTION__, __LINE__, uuid_str);
        }
        return;
    }

    utarray_new(kept_super_object_uuids, &ut_object_uuid_icd);
    utarray_new(candidate_super_object_uuids, &ut_object_uuid_icd);   

    /**
       candidate super objects means all hit objects' super include object,
       don't consider super exclude objects
       for example:
            hit_objects = {g4, g11}
            g4's super include objects  = {g7, g8}
            g11's super include objects = {g12}

            candidate super objects = {g7, g8, g12}
    */
    get_candidate_super_object_ids(object_topo, hit_object_uuids, candidate_super_object_uuids);

    if (0 == utarray_len(candidate_super_object_uuids)) {
        goto next;
    }

    /**
      verify if candidates should be kept for hit super objects, must consider exclude objects
      for example:
           hit_objects = {g4, g11}
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
            candidate super objects = {g7, g8, g12}
            verify logic:
                1. g12's sub_exclude g8 in candidates, so g12 should be dropped
                2. g7 & g8, their sub_include in hit objects, so kept them
                   if their all sub_include not exist in hit objects, they should be dropped
            after verify candidates, kept super objects = {g7, g8}, 
                                     all hit objects = {g4, g11, g7, g8}
    */
    verify_candidate_super_object_ids(object_topo, candidate_super_object_uuids, all_hit_object_uuids,
                                     kept_super_object_uuids);

    depth++;
    get_super_object_ids(object_topo, kept_super_object_uuids, all_hit_object_uuids, depth);
next: 
    utarray_free(candidate_super_object_uuids);
    utarray_free(kept_super_object_uuids);
}

static size_t object_topology_get_super_objects(struct maat_object_topology *object_topo, 
                                              uuid_t *object_uuids, size_t n_object_uuids,
                                              uuid_t *super_object_uuids,
                                              size_t super_object_uuids_size)
{
    size_t i = 0, idx = 0;
    UT_array *all_hit_object_uuids;
    UT_array *candidate_object_uuids;

    utarray_new(all_hit_object_uuids, &ut_object_uuid_icd);
    utarray_new(candidate_object_uuids, &ut_object_uuid_icd);

    for (i = 0; i < n_object_uuids; i++) {
        utarray_push_back(all_hit_object_uuids, &(object_uuids[i]));
        utarray_push_back(candidate_object_uuids, &(object_uuids[i]));
    }

    get_super_object_ids(object_topo, candidate_object_uuids, all_hit_object_uuids, 0);

    for (i = 0; i < n_object_uuids; i++) {
        uuid_t *tmp_id = utarray_find(all_hit_object_uuids, &(object_uuids[i]),
                                         compare_object_uuid);
        if (tmp_id != NULL) {
            size_t remove_idx = utarray_eltidx(all_hit_object_uuids, tmp_id);
            utarray_erase(all_hit_object_uuids, remove_idx, 1);
        }
    }

    uuid_t *p = NULL;
    for (p = (uuid_t *)utarray_front(all_hit_object_uuids); p != NULL;
         p = (uuid_t *)utarray_next(all_hit_object_uuids, p)) {
        if (idx >= super_object_uuids_size) {
            break;
        }
        uuid_copy(super_object_uuids[idx++], *p);
    }

    utarray_free(all_hit_object_uuids);
    utarray_free(candidate_object_uuids);

    return idx;
}

size_t object2object_runtime_get_super_objects(void *o2o_runtime, uuid_t *object_uuids, 
                                            size_t n_object_uuids, uuid_t *super_object_uuids,
                                            size_t super_object_uuids_size)
{
    if (NULL == o2o_runtime || NULL == object_uuids || 0 == n_object_uuids) {
        return 0;
    }
    
    struct object2object_runtime *o2o_rt = (struct object2object_runtime *)o2o_runtime;
    uuid_t o2o_object_uuids[n_object_uuids];
    size_t o2o_object_uuids_cnt = 0;
    
    for (size_t i = 0; i < n_object_uuids; i++) {
        struct maat_object *object = object_topology_find_object(o2o_rt->object_topo, &object_uuids[i]);
        if (NULL == object) {
            continue;
        }

        uuid_copy(o2o_object_uuids[o2o_object_uuids_cnt++], object_uuids[i]);
    }

    if (0 == o2o_object_uuids_cnt) {
        return 0;
    }

    return object_topology_get_super_objects(o2o_rt->object_topo, o2o_object_uuids, o2o_object_uuids_cnt,
                                           super_object_uuids, super_object_uuids_size);
}

long long object2object_runtime_rule_count(void *o2o_runtime)
{
    if (NULL == o2o_runtime) {
        return 0;
    }
    
    struct object2object_runtime *o2o_rt = (struct object2object_runtime *)o2o_runtime;
    return o2o_rt->rule_num;
}

long long object2object_runtime_exclude_rule_count(void *o2o_runtime)
{
    if (NULL == o2o_runtime) {
        return 0;
    }
    
    struct object2object_runtime *o2o_rt = (struct object2object_runtime *)o2o_runtime;
    return o2o_rt->excl_rule_num;
}

long long object2object_runtime_update_err_count(void *o2o_runtime)
{
    if (NULL == o2o_runtime) {
        return 0;
    }
    
    struct object2object_runtime *o2o_rt = (struct object2object_runtime *)o2o_runtime;
    return o2o_rt->update_err_cnt;
}