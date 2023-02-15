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

struct ex_data_schema {
	maat_plugin_ex_new_func_t *new_func;
	maat_plugin_ex_free_func_t *free_func;
	maat_plugin_ex_dup_func_t *dup_func;
	long argl;
	void *argp;
};

struct ex_data_runtime {
    UT_array *cache_rows;
    size_t cache_row_num;
    size_t cache_size;

    struct rcu_hash_table *htable;
    struct ex_data_schema *ex_schema;
	int table_id;

    struct log_handle *logger;
};

void cache_row_free(void *p)
{
	FREE(*(char **)p);
}

UT_icd ut_cache_row_icd = {sizeof(char*), NULL, NULL, cache_row_free};

struct ex_data_runtime *
ex_data_runtime_new(int table_id, rcu_hash_data_free_fn *data_free_fn,
                    struct log_handle *logger)
{
    struct ex_data_runtime *ex_data_rt = ALLOC(struct ex_data_runtime, 1);

    utarray_new(ex_data_rt->cache_rows, &ut_cache_row_icd);
    ex_data_rt->htable = rcu_hash_new(data_free_fn);
    ex_data_rt->table_id = table_id;
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
    rcu_hash_commit(ex_data_rt->htable);
}

void ex_data_runtime_cache_row_put(struct ex_data_runtime *ex_data_rt, const char *row)
{
	size_t len = strlen(row) + 1;
	char* row_copy = ALLOC(char, len);

	memcpy(row_copy, row, len);
	ex_data_rt->cache_size += len;
	utarray_push_back(ex_data_rt->cache_rows, &row_copy);
	ex_data_rt->cache_row_num++;	
}

const char *ex_data_runtime_cached_row_get(struct ex_data_runtime *ex_data_rt, size_t index)
{
    const char** row = NULL;
	row = (const char **)utarray_eltptr(ex_data_rt->cache_rows, index);
	return *row;
}

void ex_data_runtime_clear_cached_row(struct ex_data_runtime *ex_data_rt)
{
	utarray_free(ex_data_rt->cache_rows);
	ex_data_rt->cache_rows = NULL;
	ex_data_rt->cache_row_num = 0;
	ex_data_rt->cache_size = 0;
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
    utarray_free(ex_data_rt->cache_rows);
    ex_data_rt->cache_rows = NULL;
    ex_data_rt->cache_row_num = 0;
    ex_data_rt->cache_size = 0;
}

struct ex_data_schema *ex_data_schema_new(maat_plugin_ex_new_func_t *new_func,
										  maat_plugin_ex_free_func_t *free_func,
										  maat_plugin_ex_dup_func_t *dup_func,
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
    FREE(ex_schema);
}

void ex_data_runtime_set_schema(struct ex_data_runtime *ex_data_rt, 
                                struct ex_data_schema *schema)
{
    ex_data_rt->ex_schema = schema;
}

void ex_data_runtime_set_ex_container_ctx(struct ex_data_runtime *ex_data_rt, 
                                          struct ex_container_ctx *container_ctx)
{
    rcu_hash_set_user_ctx(ex_data_rt->htable, container_ctx);
}

struct ex_container_ctx *
ex_data_runtime_get_ex_container_ctx(struct ex_data_runtime *ex_data_rt)
{
    return (struct ex_container_ctx *)rcu_hash_get_user_ctx(ex_data_rt->htable);
}

void *ex_data_runtime_row2ex_data(struct ex_data_runtime *ex_data_rt, const char *row, 
                                  const char *key, size_t key_len)
{   
    void *ex_data = NULL;
    struct ex_data_schema *ex_schema = ex_data_rt->ex_schema;
    ex_schema->new_func(ex_data_rt->table_id, key, row, &ex_data, 
                        ex_schema->argl, ex_schema->argp);

    return ex_data;
}

struct ex_data_container *ex_data_container_new(void *ex_data, void *custom_data)
{
    struct ex_data_container *ex_container = ALLOC(struct ex_data_container, 1);

    ex_container->ex_data = ex_data;
    ex_container->custom_data = custom_data;

    return ex_container;
}

void ex_data_container_free(void *ctx, void *data)
{
    if (NULL == ctx || NULL == data) {
        return;
    }

    struct ex_container_ctx *container_ctx = (struct ex_container_ctx *)ctx;
    long argl = container_ctx->ex_schema->argl;
    void *argp = container_ctx->ex_schema->argp;

    struct ex_data_container *ex_container = (struct ex_data_container *)data;
    if (ex_container->ex_data != NULL 
        && container_ctx->ex_schema->free_func != NULL) {
        container_ctx->ex_schema->free_func(container_ctx->table_id, 
                                            &(ex_container->ex_data), argl, argp);
    }
    
    if (ex_container->custom_data != NULL 
        && container_ctx->custom_data_free != NULL) {
        container_ctx->custom_data_free(ex_container->custom_data);
    }

    FREE(ex_container);
}

int ex_data_runtime_add_ex_container(struct ex_data_runtime *ex_data_rt,
                                     const char *key, size_t key_len,
                                     struct ex_data_container *ex_container)
{
    struct ex_data_container *tmp_container = NULL;

    tmp_container = (struct ex_data_container *)rcu_hash_find(ex_data_rt->htable, 
                                                              key, key_len);
    if (tmp_container != NULL) {
        log_error(ex_data_rt->logger, MODULE_EX_DATA,
                  "ex_data_runtime add ex container error: already exist same key:%s",
                  key);
        return -1;
    }

    rcu_hash_add(ex_data_rt->htable, key, key_len, ex_container);

    return 0;
}

int ex_data_runtime_del_ex_container(struct ex_data_runtime *ex_data_rt,
                                     const char *key, size_t key_len)
{
    struct ex_data_container *tmp_container = NULL;
    tmp_container = (struct ex_data_container *)rcu_hash_find(ex_data_rt->htable, 
                                                              key, key_len);
    if (NULL == tmp_container) {
        log_error(ex_data_rt->logger, MODULE_EX_DATA, 
                  "ex_data_runtime del ex container error: no such key:%s", 
                  key);
        return -1;
    }

    rcu_hash_del(ex_data_rt->htable, key, key_len);

    return 0;
}

void *ex_data_runtime_get_ex_data(struct ex_data_runtime *ex_data_rt, 
                                  const char *key, size_t key_len)
{
    struct ex_data_container *ex_container = NULL;
    ex_container = (struct ex_data_container *)rcu_hash_find(ex_data_rt->htable, 
                                                             key, key_len);
    if (NULL == ex_container) {
        return NULL;
    }

    void *dup_ex_data = NULL;
    ex_data_rt->ex_schema->dup_func(ex_data_rt->table_id, &dup_ex_data, 
                                    &(ex_container->ex_data), 
                                    ex_data_rt->ex_schema->argl, 
                                    ex_data_rt->ex_schema->argp);
    return dup_ex_data;
}

void *ex_data_runtime_get_custom_data(struct ex_data_runtime *ex_data_rt, 
                                      const char *key, size_t key_len)
{
    struct ex_data_container *ex_container = NULL;
    ex_container = (struct ex_data_container *)rcu_hash_find(ex_data_rt->htable, 
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

size_t ex_data_runtime_list_updating_ex_container(struct ex_data_runtime *ex_data_rt, 
                                                  struct ex_data_container ***ex_container)
{
    return rcu_hash_list_updating_data(ex_data_rt->htable, (void ***)ex_container);
}