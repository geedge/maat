#pragma once

#include "Maat_rule.h"
#include "Maat_garbage_collection.h"
#include <sys/queue.h>

struct Maat_hierarchy;
struct Maat_hierarchy* Maat_hierarchy_new(int thread_num, void* mesa_handle_logger, struct Maat_garbage_bin* bin);
void Maat_hierarchy_free(struct Maat_hierarchy* hier);
void Maat_hierarchy_set_compile_user_data_free_func(struct Maat_hierarchy* hier,  void (* func)(void *));
void Maat_hierarchy_set_region_user_data_free_func(struct Maat_hierarchy* hier,  void (* func)(void *));



struct Maat_hierarchy_compile_mid;
struct Maat_hierarchy_compile_mid* Maat_hierarchy_compile_mid_new(struct Maat_hierarchy* hier, int thread_num);
void Maat_hierarchy_compile_mid_free(struct Maat_hierarchy_compile_mid* mid);
void Maat_hierarchy_compile_mid_udpate(struct Maat_hierarchy* hier, struct Maat_hierarchy_compile_mid* mid, int region_id, int virtual_table_id, int Nth_scan, int Nth_region_result);
void Maat_hierarchy_compile_user_data_iterate(struct Maat_hierarchy* hier, void (*callback)(void *user_data, void* apram), void* param);

int Maat_hierarchy_compile_mid_has_NOT_clause(struct Maat_hierarchy_compile_mid* mid);

size_t Maat_hierarchy_get_hit_paths(struct Maat_hierarchy* hier, struct Maat_hierarchy_compile_mid* mid, 
															struct Maat_hit_path_t* hit_paths, size_t n_path);

int Maat_hierarchy_compile_add(struct Maat_hierarchy* hier, int compile_id, int declared_clause_num, void* user_data);
int Maat_hierarchy_compile_remove(struct Maat_hierarchy * hier, int compile_id);

void* Maat_hierarchy_compile_dettach_user_data(struct Maat_hierarchy* hier, int compile_id);
void* Maat_hierarchy_compile_read_user_data(struct Maat_hierarchy* hier, int compile_id);

void* Maat_hierarchy_region_dettach_user_data(struct Maat_hierarchy* hier, int region_id);


int Maat_hierarchy_add_group_to_compile(struct Maat_hierarchy* hier, int group_id, int vt_id, int not_flag, int clause_index, int compile_id);
int Maat_hierarchy_remove_group_from_compile(struct Maat_hierarchy* hier, int group_id, int vt_id, int not_flag, int clause_index, int compile_id);
int Maat_hierarchy_add_group_to_group(struct Maat_hierarchy* hier, int group_id, int superior_group_id);
int Maat_hierarchy_remove_group_from_group(struct Maat_hierarchy* hier, int group_id, int superior_group_id);

int Maat_hierarchy_add_region_to_group(struct Maat_hierarchy* hier, int group_id, int region_id, int table_id, void* user_data);
int Maat_hierarchy_remove_region_from_group(struct Maat_hierarchy* hier, int group_id, int region_id);

int Maat_hierarchy_rebuild(struct Maat_hierarchy* hier);
int Maat_hierarchy_region_compile(struct Maat_hierarchy* hier, struct Maat_hierarchy_compile_mid* mid, int is_last_compile, void** user_data_array, size_t ud_array_sz);


