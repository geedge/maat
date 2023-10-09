/*
**********************************************************************************************
*	File: maat_ex_data.h
*   Description: ex data
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_EX_DATA_H_
#define _MAAT_EX_DATA_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "maat.h"
#include "rcu_hash.h"
#include "maat_garbage_collection.h"

struct ex_data_schema {
	maat_ex_new_func_t *new_func;
	maat_ex_free_func_t *free_func;
	maat_ex_dup_func_t *dup_func;
	long argl;
	void *argp;
};

struct ex_container {
    void *ex_data;
    void *custom_data;
};

struct ex_container_schema {
    int table_id;
    int set_flag;
    struct ex_data_schema ex_schema;
    void (*custom_data_free)(void *);
};

struct ex_data_runtime;

/* ex_data_runtime API */
struct ex_data_runtime *
ex_data_runtime_new(int table_id, int gc_timeout_s, struct log_handle *logger);

void ex_data_runtime_free(struct ex_data_runtime *ex_data_rt);

void ex_data_runtime_commit(struct ex_data_runtime *ex_data_rt);

/* ex_data_runtime cache row API */
void ex_data_runtime_cache_row_put(struct ex_data_runtime *ex_data_rt, const char *row);

const char *ex_data_runtime_cached_row_get(struct ex_data_runtime *ex_data_rt, size_t index);

size_t ex_data_runtime_cached_row_count(struct ex_data_runtime *ex_data_rt);

void ex_data_runtime_clear_row_cache(struct ex_data_runtime *ex_data_rt);

/* set user_ctx API */
void ex_data_runtime_set_ex_container_schema(struct ex_data_runtime *ex_data_rt, 
                                             struct ex_container_schema *container_schema);

struct ex_container *ex_container_new(void *ex_data, void *custom_data);

/* ex_data_runtime ex data API */
void *ex_data_runtime_row2ex_data(struct ex_data_runtime *ex_data_rt,
                                  const char *table_name, const char *row, 
                                  const char *key, size_t key_len);

int ex_data_runtime_add_ex_container(struct ex_data_runtime *ex_data_rt,
                                      const char *key, size_t key_len,
                                      struct ex_container *ex_container);

int ex_data_runtime_del_ex_container(struct ex_data_runtime *ex_data_rt,
                                      const char *key, size_t key_len);

size_t ex_data_runtime_list_updating_ex_container(struct ex_data_runtime *ex_data_rt,
                                                  struct ex_container ***ex_container);

size_t ex_data_runtime_ex_container_count(struct ex_data_runtime *ex_data_rt);

int ex_data_runtime_is_updating(struct ex_data_runtime *ex_data_rt);

void *ex_data_runtime_get_ex_data_by_key(struct ex_data_runtime *ex_data_rt,
                                         const char *key, size_t key_len);

void *ex_data_runtime_get_ex_data_by_container(struct ex_data_runtime *ex_data_rt,
                                               struct ex_container *ex_container);
                                               
void ex_data_runtime_garbage_collect_routine(struct ex_data_runtime *ex_data_rt);

#ifdef __cplusplus
}
#endif

#endif
