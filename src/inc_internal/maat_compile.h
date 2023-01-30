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

#ifdef __cpluscplus
extern "C"
{
#endif

#include "log/log.h"
#include "cJSON/cJSON.h"
#include "maat.h"
#include "maat_kv.h"
#include "maat_rule.h"

struct compile_ex_data_schema {
	maat_rule_ex_new_func_t *new_func;
	maat_rule_ex_free_func_t *free_func;
	maat_rule_ex_dup_func_t *dup_func;
	long argl;
	void *argp;
	int idx;
	int table_id;
};

/* compile schema API */
void *compile_schema_new(cJSON *json, const char *table_name, struct log_handle *logger);
void compile_schema_free(void *compile_schema);

void *group2compile_schema_new(cJSON *json, const char *table_name, struct log_handle *logger);
void group2compile_schema_free(void *g2c_schema);

int compile_table_set_rule_ex_data_schema(struct compile_schema *compile_schema, int table_id,
                                          maat_rule_ex_new_func_t *new_func,
                                          maat_rule_ex_free_func_t *free_func,
                                          maat_rule_ex_dup_func_t *dup_func,
                                          long argl, void *argp,
                                          struct log_handle *logger);
struct compile_ex_data_schema *
compile_table_get_rule_ex_data_schema(struct compile_schema *compile_schema, size_t idx);

size_t compile_table_rule_ex_data_schema_count(struct compile_schema *compile_schema);

/* compile runtime API */
void *compile_runtime_new(void *compile_schema, struct maat_garbage_bin *garbage_bin,
                          struct log_handle *logger);
void compile_runtime_free(void *compile_runtime);

int compile_runtime_update(void *compile_runtime, void *compile_schema, const char *line,
                           int valid_column);
int compile_runtime_commit(void *compile_runtime);

int compile_runtime_match(struct compile_runtime *compile_rt, int *group_ids, size_t n_group_ids, 
						  int *compile_ids, size_t compile_ids_size, struct maat_state *state);

size_t compile_runtime_get_hit_paths(struct compile_runtime *compile_rt, struct maat_group_topology *group_topo, 
                                     struct maat_compile_state *compile_state, 
                                     struct maat_hit_path *hit_paths, size_t hit_path_siz);
/* group2compile runtime API */
void *group2compile_runtime_new(void *g2c_schema, struct maat_garbage_bin *garbage_bin,
                                struct log_handle *logger);
void group2compile_runtime_free(void *g2c_runtime);

int group2compile_runtime_update(void *g2c_runtime, void *g2c_schema, const char *line,
                                 int valid_column);

/* maat compile state API */
struct maat_compile_state;
struct maat_compile_state *maat_compile_state_new(int thread_id);
void maat_compile_state_free(struct maat_compile_state *compile_state);
void maat_compile_state_update_hit_path(struct maat_compile_state *compile_state, int item_id, int group_id, int virtual_table_id, 
                                        int Nth_scan, int Nth_item_result);
void maat_compile_state_update_hit_clause(struct maat_compile_state *compile_state, struct maat_compile **compile_hash, 
										  int group_id, int virtual_table_id);
int maat_compile_state_has_NOT_clause(struct maat_compile_state *compile_state);

#ifdef __cpluscplus
}
#endif

#endif