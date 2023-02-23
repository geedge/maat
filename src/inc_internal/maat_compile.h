/*
**********************************************************************************************
*	File: maat_compile.h
*   Description: 
*	Authors: Zheng Chao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_COMPILE_H_
#define _MAAT_COMPILE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "cJSON/cJSON.h"
#include "maat.h"
#include "maat_kv.h"
#include "maat_rule.h"

struct compile_schema;
struct compile_runtime;
struct maat_compile_state;
struct group2group_runtime;

/* compile schema API */
void *compile_schema_new(cJSON *json, struct table_manager *tbl_mgr,
                         const char *table_name, struct log_handle *logger);
void compile_schema_free(void *compile_schema);

void *group2compile_schema_new(cJSON *json, struct table_manager *tbl_mgr,
                               const char *table_name, struct log_handle *logger);
void group2compile_schema_free(void *g2c_schema);
int group2compile_associated_compile_table_id(void *g2c_schema);

int compile_table_set_ex_data_schema(struct compile_schema *compile_schema, int table_id,
                                     maat_ex_new_func_t *new_func,
                                     maat_ex_free_func_t *free_func,
                                     maat_ex_dup_func_t *dup_func,
                                     long argl, void *argp,
                                     struct log_handle *logger);
void *compile_table_get_ex_data(struct compile_schema *compile_schema, long long compile_id);
void compile_table_ex_data_iterate(struct compile_schema *compile_schema);

/* compile runtime API */
void *compile_runtime_new(void *compile_schema, int max_thread_num,
                          struct maat_garbage_bin *garbage_bin,
                          struct log_handle *logger);
void compile_runtime_free(void *compile_runtime);

int compile_runtime_update(void *compile_runtime, void *compile_schema,
                           const char *line, int valid_column);
int compile_runtime_commit(void *compile_runtime, const char *table_name);

int compile_runtime_match(struct compile_runtime *compile_rt, long long *compile_ids,
                          size_t compile_ids_size, struct maat_state *state);

size_t compile_runtime_get_hit_paths(struct compile_runtime *compile_rt,
                                     struct group2group_runtime *g2g_rt, 
                                     struct maat_compile_state *compile_state,
                                     struct maat_hit_path *hit_paths,
                                     size_t hit_path_index, size_t n_hit_path);
/* group2compile runtime API */
void *group2compile_runtime_new(void *g2c_schema, int max_thread_num,
                                struct maat_garbage_bin *garbage_bin,
                                struct log_handle *logger);
void group2compile_runtime_init(void *g2c_runtime, void *compile_runtime, void *g2g_runtime);
void group2compile_runtime_free(void *g2c_runtime);

int group2compile_runtime_update(void *g2c_runtime, void *g2c_schema,
                                 const char *line, int valid_column);

/* maat compile state API */
struct maat_compile_state;
struct maat_compile_state *maat_compile_state_new(int thread_id);
void maat_compile_state_free(struct maat_compile_state *compile_state);

int maat_compile_state_update(struct maat_item *item_hash, int vtable_id,
                              long long *hit_item_ids, size_t hit_item_cnt,
                              size_t *n_hit_group_id, struct maat_state *state);
                              
int maat_compile_state_has_NOT_clause(struct maat_compile_state *compile_state);

#ifdef __cplusplus
}
#endif

#endif
