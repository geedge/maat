/*
**********************************************************************************************
*	File: maat_ex_data.cpp
*   Description: ex data
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <stddef.h>
#include <stdio.h>

#include "uthash/uthash.h"
#include "uthash/utarray.h"
#include "log/log.h"
#include "maat_utils.h"
#include "maat_ex_data.h"

#define MODULE_EX_DATA	 module_name_str("maat.ex_data")

struct ex_data_runtime {
    UT_array *cache_rows;
    size_t cache_row_num;
    size_t cache_size;

    struct rcu_hash_table *htable;
    struct maat_garbage_bin *ref_garbage_bin;
	int table_id;

    struct log_handle *logger;
};

void cache_row_free(void *p)
{
	free(*(char **)p);
}

UT_icd ut_cache_row_icd = {sizeof(char*), NULL, NULL, cache_row_free};

struct ex_data_runtime *
ex_data_runtime_new(int table_id, rcu_hash_data_free_fn *data_free_fn,
                    struct maat_garbage_bin *garbage_bin, struct log_handle *logger)
{
    if (NULL == data_free_fn || NULL == garbage_bin ||
        NULL == logger) {
        return NULL;
    }

    struct ex_data_runtime *ex_data_rt = ALLOC(struct ex_data_runtime, 1);

    utarray_new(ex_data_rt->cache_rows, &ut_cache_row_icd);
    ex_data_rt->htable = rcu_hash_new(data_free_fn);
    ex_data_rt->table_id = table_id;
    ex_data_rt->ref_garbage_bin = garbage_bin;
    ex_data_rt->logger = logger;

    return ex_data_rt;
}

void ex_data_runtime_free(struct ex_data_runtime *ex_data_rt)
{
    if (NULL == ex_data_rt) {
        return;
    }

    if (ex_data_rt->cache_rows != NULL) {
		utarray_free(ex_data_rt->cache_rows);
		ex_data_rt->cache_rows = NULL;
		ex_data_rt->cache_row_num = 0;
	}

    if (ex_data_rt->htable != NULL) {
        rcu_hash_free(ex_data_rt->htable);
    }

    FREE(ex_data_rt);
}

void ex_data_runtime_commit(struct ex_data_runtime *ex_data_rt)
{    
    if (NULL == ex_data_rt) {
        return;
    }

    rcu_hash_commit(ex_data_rt->htable);
}

void ex_data_runtime_cache_row_put(struct ex_data_runtime *ex_data_rt, const char *row)
{
    if (NULL == ex_data_rt || NULL == row) {
        return;
    }

	size_t len = strlen(row) + 1;
	char* row_copy = ALLOC(char, len);

	memcpy(row_copy, row, len);
	ex_data_rt->cache_size += len;
	utarray_push_back(ex_data_rt->cache_rows, &row_copy);
	ex_data_rt->cache_row_num++;	
}

const char *ex_data_runtime_cached_row_get(struct ex_data_runtime *ex_data_rt, size_t index)
{
    if (NULL == ex_data_rt) {
        return NULL;
    }

    const char **row = NULL;
	row = (const char **)utarray_eltptr(ex_data_rt->cache_rows, index);
	return *row;
}

size_t ex_data_runtime_cached_row_count(struct ex_data_runtime *ex_data_rt)
{
    if (NULL == ex_data_rt) {
        return 0;
    }

    return ex_data_rt->cache_row_num;
}

void ex_data_runtime_clear_row_cache(struct ex_data_runtime *ex_data_rt)
{
    if (NULL == ex_data_rt) {
        return;
    }

    utarray_free(ex_data_rt->cache_rows);
    ex_data_rt->cache_rows = NULL;
    ex_data_rt->cache_row_num = 0;
    ex_data_rt->cache_size = 0;
}

struct ex_data_schema *ex_data_schema_new(maat_ex_new_func_t *new_func,
										  maat_ex_free_func_t *free_func,
										  maat_ex_dup_func_t *dup_func,
										  long argl, void *argp)
{
    struct ex_data_schema *ex_schema = ALLOC(struct ex_data_schema, 1);

    ex_schema->new_func = new_func;
    ex_schema->free_func = free_func;
    ex_schema->dup_func = dup_func;
    ex_schema->argl = argl;
    ex_schema->argp = argp;

    return ex_schema;
}

void ex_data_schema_free(struct ex_data_schema *ex_schema)
{
    if (ex_schema != NULL) {
        FREE(ex_schema);
    }
    
}

void ex_data_runtime_set_ex_container_schema(struct ex_data_runtime *ex_data_rt, 
                                             struct ex_container_schema *container_schema)
{
    if (NULL == ex_data_rt) {
        return;
    }

    rcu_hash_set_user_ctx(ex_data_rt->htable, container_schema);
}

struct ex_container_schema *
ex_data_runtime_get_ex_container_schema(struct ex_data_runtime *ex_data_rt)
{
    if (NULL == ex_data_rt) {
        return NULL;
    }

    return (struct ex_container_schema *)rcu_hash_get_user_ctx(ex_data_rt->htable);
}

void *ex_data_runtime_row2ex_data(struct ex_data_runtime *ex_data_rt, 
                                  struct ex_data_schema *ex_schema,
                                  const char *row, const char *key, 
                                  size_t key_len)
{   
    void *ex_data = NULL;
    
    ex_schema->new_func(ex_data_rt->table_id, key, row, &ex_data, 
                        ex_schema->argl, ex_schema->argp);
    return ex_data;
}

struct ex_container *ex_container_new(void *ex_data, void *custom_data)
{
    struct ex_container *ex_container = ALLOC(struct ex_container, 1);

    ex_container->ex_data = ex_data;
    ex_container->custom_data = custom_data;

    return ex_container;
}

void ex_container_free(void *schema, void *data)
{
    /* schema is NULL if not call ex_data_runtime_set_ex_container_schema */
    if (NULL == schema || NULL == data) {
        return;
    }

    struct ex_container *ex_container = (struct ex_container *)data;
    struct ex_container_schema *container_schema = (struct ex_container_schema *)schema;
    long argl = container_schema->ex_schema->argl;
    void *argp = container_schema->ex_schema->argp;

    if (ex_container->ex_data != NULL 
        && container_schema->ex_schema->free_func != NULL) {
        container_schema->ex_schema->free_func(container_schema->table_id, 
                                            &(ex_container->ex_data), argl, argp);
    }
    
    if (ex_container->custom_data != NULL 
        && container_schema->custom_data_free != NULL) {
        container_schema->custom_data_free(ex_container->custom_data);
    }

    FREE(ex_container);
}

int ex_data_runtime_add_ex_container(struct ex_data_runtime *ex_data_rt,
                                     const char *key, size_t key_len,
                                     struct ex_container *ex_container)
{
    return rcu_hash_add(ex_data_rt->htable, key, key_len, ex_container);
}

int ex_data_runtime_del_ex_container(struct ex_data_runtime *ex_data_rt,
                                     const char *key, size_t key_len)
{
    return rcu_hash_del(ex_data_rt->htable, key, key_len);
}

void *ex_data_runtime_get_ex_data_by_key(struct ex_data_runtime *ex_data_rt,
                                         struct ex_data_schema *ex_schema,
                                         const char *key, size_t key_len)
{
    struct ex_container *ex_container = NULL;

    ex_container = (struct ex_container *)rcu_hash_find(ex_data_rt->htable, 
                                                             key, key_len);
    if (NULL == ex_container) {
        return NULL;
    }

    void *dup_ex_data = NULL;
    ex_schema->dup_func(ex_data_rt->table_id, &dup_ex_data, &(ex_container->ex_data), 
                        ex_schema->argl, ex_schema->argp);
    return dup_ex_data;
}

void *ex_data_runtime_get_ex_data_by_container(struct ex_data_runtime *ex_data_rt,
                                               struct ex_data_schema *ex_schema,
                                               struct ex_container *ex_container)
{
    void *dup_ex_data = NULL;
    ex_schema->dup_func(ex_data_rt->table_id, &dup_ex_data, &(ex_container->ex_data), 
                        ex_schema->argl, ex_schema->argp);
    return dup_ex_data;
}

void *ex_data_runtime_get_custom_data(struct ex_data_runtime *ex_data_rt, 
                                      const char *key, size_t key_len)
{
    struct ex_container *ex_container = NULL;
    ex_container = (struct ex_container *)rcu_hash_find(ex_data_rt->htable, 
                                                             key, key_len);
    if (NULL == ex_container) {
        return NULL;
    }

    return ex_container->custom_data;
}

size_t ex_data_runtime_ex_container_count(struct ex_data_runtime *ex_data_rt)
{
    return rcu_hash_count(ex_data_rt->htable);
}

int ex_data_runtime_is_updating(struct ex_data_runtime *ex_data_rt)
{
    return rcu_hash_is_updating(ex_data_rt->htable);
}

size_t ex_data_runtime_list_ex_container(struct ex_data_runtime *ex_data_rt, 
                                         struct ex_container ***ex_container)
{
    return rcu_hash_list(ex_data_rt->htable, (void ***)ex_container);
}
