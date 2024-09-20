/*
**********************************************************************************************
*	File: maat_rule.h
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_RULE_H_
#define _MAAT_RULE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "cJSON/cJSON.h"
#include "rcu_hash.h"
#include "maat.h"
#include "maat_kv.h"
#include "maat_core.h"

struct rule_schema;
struct rule_runtime;
struct rule_state;
struct object2object_runtime;

/* rule schema API */
void *rule_schema_new(cJSON *json, struct table_manager *tbl_mgr,
                         const char *table_name, struct log_handle *logger);
void rule_schema_free(void *rule_schema);

/* rule runtime API */
void *rule_runtime_new(void *rule_schema, size_t max_thread_num,
                          struct maat_garbage_bin *garbage_bin, 
                          struct log_handle *logger);
void rule_runtime_free(void *rule_runtime);

void rule_runtime_init(void *rule_runtime, struct maat_runtime *maat_rt);

int rule_runtime_update(void *rule_runtime, void *rule_schema,
                           const char *table_name, const char *line,
                           enum maat_operation op);

int rule_runtime_commit(void *rule_runtime, const char *table_name,
                           long long maat_rt_version);

long long rule_runtime_rule_count(void *rule_runtime);

long long rule_runtime_update_err_count(void *rule_runtime);

int rule_runtime_match(struct rule_runtime *rule_rt, uuid_t *rule_uuids,
                          size_t rule_ids_size, struct maat_state *state);

size_t rule_runtime_get_hit_paths(struct rule_runtime *rule_rt, int thread_id,
									 struct rule_compile_state *rule_compile_state, 
                                  	 struct maat_hit_path *hit_path_array, 
                                     size_t array_size, size_t n_hit_path);

/* maat rule state API */
struct rule_compile_state;
struct rule_compile_state *rule_compile_state_new(void);

void rule_compile_state_reset(struct rule_compile_state *rule_compile_state);

void rule_compile_state_free(struct rule_compile_state *rule_compile_state,
                        struct maat *maat_instance, int thread_id);

int rule_compile_state_update(struct rule_compile_state *rule_compile_state, struct maat *maat_inst,
                         int attribute_id, int custom_rule_tbl_id, int Nth_scan,
                         struct maat_item *hit_items, size_t n_hit_item);

void rule_compile_state_clear_last_hit_object(struct rule_compile_state *rule_state);

void rule_compile_state_not_logic_update(struct rule_compile_state *rule_compile_state, 
                                    struct rule_runtime *rule_rt,
                                    struct maat *maat_inst, int attribute_id,
                                    int Nth_scan);

size_t rule_compile_state_get_internal_hit_paths(struct rule_compile_state *rule_compile_state,
                                            struct rule_runtime *rule_rt,
                                            struct object2object_runtime *o2o_rt,
                                            struct maat_hit_path *hit_path_array, 
                                            size_t array_size);

size_t rule_compile_state_get_direct_hit_objects(struct rule_compile_state *rule_compile_state,
                                           struct maat_hit_object *object_array,
                                           size_t array_size);

size_t rule_compile_state_get_direct_hit_object_cnt(struct rule_compile_state *rule_compile_state);

size_t rule_compile_state_get_indirect_hit_objects(struct rule_compile_state *rule_compile_state,
                                             struct maat_hit_object *object_array,
                                             size_t array_size);

size_t rule_compile_state_get_indirect_hit_object_cnt(struct rule_compile_state *rule_compile_state);

size_t rule_compile_state_get_last_hit_objects(struct rule_compile_state *rule_compile_state,
                                         struct maat_hit_object *object_arary,
                                         size_t array_size);

size_t rule_compile_state_get_last_hit_object_cnt(struct rule_compile_state *rule_compile_state);

int rule_compile_state_get_rule_table_id(struct rule_compile_state *rule_compile_state,
                                       long long rule_id);

#ifdef __cplusplus
}
#endif

#endif