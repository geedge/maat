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
struct group2group_runtime;

/* rule schema API */
void *rule_schema_new(cJSON *json, struct table_manager *tbl_mgr,
                         const char *table_name, struct log_handle *logger);
void rule_schema_free(void *rule_schema);

void *group2rule_schema_new(cJSON *json, struct table_manager *tbl_mgr,
                               const char *table_name, struct log_handle *logger);
void group2rule_schema_free(void *g2c_schema);
int group2rule_associated_rule_table_id(void *g2c_schema);

/* rule runtime API */
void *rule_runtime_new(void *rule_schema, size_t max_thread_num,
                          struct maat_garbage_bin *garbage_bin, 
                          struct log_handle *logger);
void rule_runtime_free(void *rule_runtime);

void rule_runtime_init(void *rule_runtime, struct maat_runtime *maat_rt);

int rule_runtime_update(void *rule_runtime, void *rule_schema,
                           const char *table_name, const char *line,
                           int valid_column);

int rule_runtime_commit(void *rule_runtime, const char *table_name,
                           long long maat_rt_version);

long long rule_runtime_rule_count(void *rule_runtime);

long long rule_runtime_update_err_count(void *rule_runtime);

int rule_runtime_match(struct rule_runtime *rule_rt, long long *rule_ids,
                          size_t rule_ids_size, struct maat_state *state);

size_t rule_runtime_get_hit_paths(struct rule_runtime *rule_rt, int thread_id,
									 struct rule_state *rule_state, 
                                  	 struct maat_hit_path *hit_path_array, 
                                     size_t array_size, size_t n_hit_path);

/* group2rule runtime API */
void *group2rule_runtime_new(void *g2c_schema, size_t max_thread_num,
                                struct maat_garbage_bin *garbage_bin, 
                                struct log_handle *logger);

void group2rule_runtime_init(void *g2c_runtime, void *rule_runtime);

void group2rule_runtime_free(void *g2c_runtime);

int group2rule_runtime_update(void *g2c_runtime, void *g2c_schema,
                                 const char *table_name, const char *line,
                                 int valid_column);

long long group2rule_runtime_not_clause_count(void *g2c_runtime);

long long group2rule_runtime_rule_count(void *g2c_runtime);

long long group2rule_runtime_update_err_count(void *g2c_runtime);

/* maat rule state API */
struct rule_state;
struct rule_state *rule_state_new(void);

void rule_state_reset(struct rule_state *rule_state);

void rule_state_free(struct rule_state *rule_state,
                        struct maat *maat_instance, int thread_id);

int rule_state_update(struct rule_state *rule_state, struct maat *maat_inst,
                         int vtable_id, int custom_rule_tbl_id, int Nth_scan,
                         struct maat_item *hit_items, size_t n_hit_item);

void rule_state_clear_last_hit_group(struct rule_state *rule_state);

void rule_state_not_logic_update(struct rule_state *rule_state, 
                                    struct rule_runtime *rule_rt,
                                    struct maat *maat_inst, int vtable_id,
                                    int Nth_scan);

size_t rule_state_get_internal_hit_paths(struct rule_state *rule_state,
                                            struct rule_runtime *rule_rt,
                                            struct group2group_runtime *g2g_rt,
                                            struct maat_hit_path *hit_path_array, 
                                            size_t array_size);

size_t rule_state_get_direct_hit_groups(struct rule_state *rule_state,
                                           struct maat_hit_group *group_array,
                                           size_t array_size);

size_t rule_state_get_direct_hit_group_cnt(struct rule_state *rule_state);

size_t rule_state_get_indirect_hit_groups(struct rule_state *rule_state,
                                             struct maat_hit_group *group_array,
                                             size_t array_size);

size_t rule_state_get_indirect_hit_group_cnt(struct rule_state *rule_state);

size_t rule_state_get_last_hit_groups(struct rule_state *rule_state,
                                         struct maat_hit_group *group_arary,
                                         size_t array_size);

size_t rule_state_get_last_hit_group_cnt(struct rule_state *rule_state);

int rule_state_get_rule_table_id(struct rule_state *rule_state,
                                       long long rule_id);

#ifdef __cplusplus
}
#endif

#endif