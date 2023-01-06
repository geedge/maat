/*
**********************************************************************************************
*	File: maat_hierarchy.h
*   Description: 
*	Authors: Zheng Chao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_HIERARCHY_H_
#define _MAAT_HIERARCHY_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include "maat_garbage_collection.h"

/* maat hierarchy API */
struct maat_hierarchy;
struct maat_hierarchy *maat_hierarchy_new(int thread_num, struct maat_garbage_bin *bin, struct log_handle *logger);
void maat_hierarchy_free(struct maat_hierarchy *hier);
int maat_hierarchy_rebuild(struct maat_hierarchy *hier);

size_t maat_hierarchy_get_hit_paths(struct maat_hierarchy *hier, struct maat_hierarchy_compile_mid *mid, 
									struct maat_hit_path *hit_paths, size_t n_path);

/* maat hierarchy compile mid API */
struct maat_hierarchy_compile_mid;
struct maat_hierarchy_compile_mid *maat_hierarchy_compile_mid_new(struct maat_hierarchy *hier, int thread_id);
void maat_hierarchy_compile_mid_free(struct maat_hierarchy_compile_mid *mid);
void maat_hierarchy_compile_mid_update(struct maat_hierarchy *hier, struct maat_hierarchy_compile_mid *mid, 
                                       int item_id, int virtual_table_id, int Nth_scan, int Nth_item_result);
int maat_hierarchy_compile_mid_has_NOT_clause(struct maat_hierarchy_compile_mid *mid);

/* maat hierarchy compile API */
int maat_hierarchy_compile_add(struct maat_hierarchy *hier, int compile_id, int declared_clause_num, void* user_data);
int maat_hierarchy_compile_remove(struct maat_hierarchy *hier, int compile_id);

void maat_hierarchy_set_compile_user_data_free_func(struct maat_hierarchy *hier,  void (* func)(void *));
void *maat_hierarchy_compile_dettach_user_data(struct maat_hierarchy *hier, int compile_id);
void *maat_hierarchy_compile_read_user_data(struct maat_hierarchy *hier, int compile_id);
void maat_hierarchy_compile_user_data_iterate(struct maat_hierarchy *hier, void (*callback)(void *user_data, void *param), void *param);

/* maat hierarchy group2compile API */
int maat_hierarchy_add_group_to_compile(struct maat_hierarchy *hier, int group_id, int vt_id, int not_flag, 
                                        int clause_index, int compile_id);
int maat_hierarchy_remove_group_from_compile(struct maat_hierarchy *hier, int group_id, int vt_id, int not_flag, 
                                             int clause_index, int compile_id);

/* maat hierarchy item API */
int maat_hierarchy_item_compile(struct maat_hierarchy *hier, struct maat_hierarchy_compile_mid *mid, 
                                  int is_last_compile, void **user_data_array, size_t ud_array_sz);
void *maat_hierarchy_item_dettach_user_data(struct maat_hierarchy *hier, int item_id);
void maat_hierarchy_set_item_user_data_free_func(struct maat_hierarchy *hier,  void (* func)(void *));

/* maat hierarchy item2group API */
int maat_hierarchy_add_item_to_group(struct maat_hierarchy *hier, int group_id, int item_id, void* user_data);
int maat_hierarchy_remove_item_from_group(struct maat_hierarchy *hier, int group_id, int item_id);

#ifdef __cpluscplus
}
#endif

#endif