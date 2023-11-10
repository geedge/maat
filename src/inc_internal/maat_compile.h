/*
**********************************************************************************************
*	File: maat_compile.h
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_COMPILE_H_
#define _MAAT_COMPILE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "cJSON/cJSON.h"
#include "rcu_hash.h"
#include "maat.h"
#include "maat_kv.h"
#include "maat_rule.h"

struct compile_schema;
struct compile_runtime;
struct compile_state;
struct group2group_runtime;

/* compile schema API */
void *compile_schema_new(cJSON *json, struct table_manager *tbl_mgr,
                         const char *table_name, struct log_handle *logger);
void compile_schema_free(void *compile_schema);

void *group2compile_schema_new(cJSON *json, struct table_manager *tbl_mgr,
                               const char *table_name, struct log_handle *logger);
void group2compile_schema_free(void *g2c_schema);
int group2compile_associated_compile_table_id(void *g2c_schema);

/* compile runtime API */
void *compile_runtime_new(void *compile_schema, size_t max_thread_num,
                          struct maat_garbage_bin *garbage_bin, 
                          struct log_handle *logger);
void compile_runtime_free(void *compile_runtime);

void compile_runtime_init(void *compile_runtime, struct maat_runtime *maat_rt);

int compile_runtime_update(void *compile_runtime, void *compile_schema,
                           const char *table_name, const char *line,
                           int valid_column);

int compile_runtime_commit(void *compile_runtime, const char *table_name,
                           long long maat_rt_version);

long long compile_runtime_rule_count(void *compile_runtime);

long long compile_runtime_update_err_count(void *compile_runtime);

int compile_runtime_match(struct compile_runtime *compile_rt, long long *compile_ids,
                          size_t compile_ids_size, struct maat_state *state);

size_t compile_runtime_get_hit_paths(struct compile_runtime *compile_rt, int thread_id,
									 struct compile_state *compile_state, 
                                  	 struct maat_hit_path *hit_path_array, 
                                     size_t array_size, size_t n_hit_path);

/* group2compile runtime API */
void *group2compile_runtime_new(void *g2c_schema, size_t max_thread_num,
                                struct maat_garbage_bin *garbage_bin, 
                                struct log_handle *logger);

void group2compile_runtime_init(void *g2c_runtime, void *compile_runtime);

void group2compile_runtime_free(void *g2c_runtime);

int group2compile_runtime_update(void *g2c_runtime, void *g2c_schema,
                                 const char *table_name, const char *line,
                                 int valid_column);

long long group2compile_runtime_not_clause_count(void *g2c_runtime);

long long group2compile_runtime_rule_count(void *g2c_runtime);

long long group2compile_runtime_update_err_count(void *g2c_runtime);

/* maat compile state API */
struct compile_state;
struct compile_state *compile_state_new(void);

void compile_state_reset(struct compile_state *compile_state);

void compile_state_free(struct compile_state *compile_state,
                        struct maat *maat_instance, int thread_id);

int compile_state_update(struct compile_state *compile_state, struct maat *maat_inst,
                         int vtable_id, int custom_compile_tbl_id, int Nth_scan,
                         struct maat_item *hit_items, size_t n_hit_item);

void compile_state_not_logic_update(struct compile_state *compile_state, 
                                    struct compile_runtime *compile_rt,
                                    struct maat *maat_inst, int vtable_id,
                                    int Nth_scan);

size_t compile_state_get_internal_hit_paths(struct compile_state *compile_state,
                                            struct compile_runtime *compile_rt,
                                            struct group2group_runtime *g2g_rt,
                                            struct maat_hit_path *hit_path_array, 
                                            size_t array_size);

size_t compile_state_get_direct_hit_groups(struct compile_state *compile_state,
                                           struct maat_hit_group *group_array,
                                           size_t array_size);

size_t compile_state_get_direct_hit_group_cnt(struct compile_state *compile_state);

size_t compile_state_get_indirect_hit_groups(struct compile_state *compile_state,
                                             struct maat_hit_group *group_array,
                                             size_t array_size);

size_t compile_state_get_indirect_hit_group_cnt(struct compile_state *compile_state);

int compile_state_get_compile_table_id(struct compile_state *compile_state,
                                       long long compile_id);

#ifdef __cplusplus
}
#endif

#endif