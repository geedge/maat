/*
**********************************************************************************************
*	File: maat_ex_data.h
*   Description: ex data
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_EX_DATA_H_
#define _MAAT_EX_DATA_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include "maat/maat.h"
#include "rcu_hash.h"

struct ex_data_container {
    void *ex_data;
    void *custom_data;
};

struct ex_container_ctx {
    int table_id;
    void (*custom_data_free)(void *custom_data);
    struct ex_data_schema *ex_schema;
};

struct ex_data_runtime;

/* ex_data_runtime API */
struct ex_data_runtime *ex_data_runtime_new(int table_id, rcu_hash_data_free_fn *data_free_fn,
                                            struct log_handle *logger);

void ex_data_runtime_free(struct ex_data_runtime *ex_data_rt);

void ex_data_runtime_commit(struct ex_data_runtime *ex_data_rt);

/* ex_data_runtime cache row API */
void ex_data_runtime_cache_row_put(struct ex_data_runtime *ex_data_rt, const char *row);

const char *ex_data_runtime_cached_row_get(struct ex_data_runtime *ex_data_rt, size_t index);

size_t ex_data_runtime_cached_row_count(struct ex_data_runtime *ex_data_rt);

void ex_data_runtime_clear_row_cache(struct ex_data_runtime *ex_data_rt);

/* set schema API */
struct ex_data_schema *ex_data_schema_new(maat_plugin_ex_new_func_t *new_func,
										  maat_plugin_ex_free_func_t *free_func,
										  maat_plugin_ex_dup_func_t *dup_func,
										  long argl, void *argp);
void ex_data_schema_free(struct ex_data_schema *ex_schema);

void ex_data_runtime_set_schema(struct ex_data_runtime *ex_data_rt, struct ex_data_schema *schema);

/* set user_ctx API */
void ex_data_runtime_set_ex_container_ctx(struct ex_data_runtime *ex_data_rt, struct ex_container_ctx *container_ctx);

struct ex_container_ctx *ex_data_runtime_get_ex_container_ctx(struct ex_data_runtime *ex_data_rt);

struct ex_data_container *ex_data_container_new(void *ex_data, void *custom_data);
void ex_data_container_free(void *ctx, void *data);

/* ex_data_runtime ex data API */
void *ex_data_runtime_row2ex_data(struct ex_data_runtime *ex_data_rt,
                                  const char *row, const char *key, size_t key_len);

int ex_data_runtime_add_ex_container(struct ex_data_runtime *ex_data_rt,
                                      const char *key, size_t key_len,
                                      struct ex_data_container *ex_container);

int ex_data_runtime_del_ex_container(struct ex_data_runtime *ex_data_rt,
                                      const char *key, size_t key_len);

size_t ex_data_runtime_list_updating_ex_container(struct ex_data_runtime *ex_data_rt,
                                                  struct ex_data_container ***ex_container);

void *ex_data_runtime_get_ex_data(struct ex_data_runtime *ex_data_rt, const char *key, size_t key_len);

void *ex_data_runtime_get_custom_data(struct ex_data_runtime *ex_data_rt, const char *key, size_t key_len);

size_t ex_data_runtime_ex_container_count(struct ex_data_runtime *ex_data_rt);

int ex_data_runtime_updating_flag(struct ex_data_runtime *ex_data_rt);

#ifdef __cpluscplus
}
#endif

#endif