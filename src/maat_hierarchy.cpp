/*
**********************************************************************************************
*	File: maat_hierarchy.cpp
*   Description: 
*	Authors: Zheng Chao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>
#include <pthread.h>

#include "utils.h"
#include "maat_utils.h"
#include "log/log.h"
#include "uthash/utarray.h"
#include "uthash/uthash.h"
#include "bool_matcher.h"
#include "igraph/igraph.h"
#include "maat_hierarchy.h"
#include "maat_garbage_collection.h"
#include "maat_group.h"
#include "maat/maat.h"

#define MODULE_HIERARCHY	 module_name_str("maat.hierarchy")

struct maat_hierarchy_clause_state {
	unsigned long long clause_id;
	char not_flag;
	char in_use;
	UT_array *literal_ids;
};

struct maat_hierarchy_compile {
	unsigned int magic;
	int compile_id;
	int actual_clause_num;
	int declared_clause_num;
	int not_clause_cnt;
	void *user_data;
	UT_hash_handle hh;
	struct maat_hierarchy_clause_state clause_states[MAX_ITEMS_PER_BOOL_EXPR];
};

struct maat_hierarchy_literal_id {
	int group_id;
	int vt_id;
};

struct maat_hierarchy_clause {
	long long clause_id;
	size_t n_literal_id;
	struct maat_hierarchy_literal_id *literal_ids;
	UT_hash_handle hh;
};

struct item2clause_key {
	int item_id;
	int vt_id;
};

struct group2item {
	int group_id;
	UT_array *item_ids;
	UT_hash_handle hh;	//index to 
};

struct item2clause_value {	
	struct item2clause_key key;
	UT_array *clause_ids;
	int group_id;
	UT_hash_handle hh;	//index to 
};

struct maat_hierarchy_internal_hit_path {
	int Nth_scan;
	int Nth_hit_item;
	int item_id;
	int virtual_table_id;
};

struct maat_hierarchy {
	pthread_rwlock_t rwlock;
	time_t version;				//After full update, clause id may indicate a different clause. Comparing hier->version and mid->hier_ver can prevent false positive match.
	int changed_flag;
	
	struct maat_hierarchy_compile *hash_compile_by_id;		     //key: compile_id, value: struct maat_hierarchy_compile*.
	void (* compile_user_data_free)(void *compile_ud);

	struct maat_hierarchy_item *hash_item_by_id;		     //key: item_id, value: struct maat_hierarchy_item*.

	struct maat_hierarchy_clause *hash_dedup_clause_by_literals; //key: literal combination, value: struct maat_hierarchy_clause*. For generating unique clause_id.
	unsigned long long clause_id_generator;					     //Increasing number.
	
	void (* item_user_data_free)(void *item_ud);

	/*Following members are accessed from scan threads.*/
	struct item2clause_value *hash_item2clause;			     //key: item_id+virtual_table_id, value: struct item2clause_value.
	struct bool_matcher *bm;

    struct maat_group_topology *ref_group_topo;
	int thread_num;
	struct maat_garbage_bin *ref_garbage_bin;
	struct log_handle *logger;
	struct bool_expr_match *expr_match_buff;
};

struct maat_hierarchy_compile_mid {
	int thread_id;
	int Nth_scan;
	time_t hier_ver;
	size_t this_scan_item_hit_cnt;
	int	not_clause_hitted_flag;
	int is_no_count_scan;
	size_t hit_path_cnt;

	UT_array *internal_hit_paths;
	UT_array *all_hit_clause_array;
	UT_array *this_scan_hit_clause_ids;
};

struct maat_hierarchy *maat_hierarchy_new(int thread_num, struct maat_garbage_bin *bin, struct log_handle *logger)
{
    struct maat_hierarchy *hier = ALLOC(struct maat_hierarchy, 1);
	UNUSED int ret = 0;
	hier->logger = logger;
	hier->thread_num = thread_num;
	hier->version = time(NULL);

	hier->hash_compile_by_id = NULL;
	hier->hash_item2clause = NULL;
	hier->hash_item_by_id = NULL;
	hier->hash_dedup_clause_by_literals = NULL;
	hier->clause_id_generator = 0;
	hier->ref_garbage_bin = bin;	
	hier->expr_match_buff = ALLOC(struct bool_expr_match, thread_num * MAX_SCANNER_HIT_NUM);

	ret = pthread_rwlock_init(&hier->rwlock, NULL);
	assert(ret == 0);

	return hier;
}

UT_icd ut_literal_id_icd = {sizeof(struct maat_hierarchy_literal_id), NULL, NULL, NULL};
UT_icd ut_clause_id_icd = {sizeof(unsigned long long), NULL, NULL, NULL};
UT_icd ut_item_id_icd = {sizeof(int), NULL, NULL, NULL};
UT_icd ut_hit_path_icd = {sizeof(struct maat_hierarchy_internal_hit_path), NULL, NULL, NULL};

#define MAAT_HIER_COMPILE_MAGIC	0x4a5b6c7d
static struct maat_hierarchy_compile *maat_hierarchy_compile_new(struct maat_hierarchy *hier, int compile_id)
{
	struct maat_hierarchy_compile *compile = NULL;
	compile = ALLOC(struct maat_hierarchy_compile, 1);
	compile->magic = MAAT_HIER_COMPILE_MAGIC;
	compile->compile_id = compile_id;
	HASH_ADD_INT(hier->hash_compile_by_id, compile_id, compile);
	
    for(int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {	
		utarray_new(compile->clause_states[i].literal_ids, &ut_literal_id_icd);
		compile->clause_states[i].in_use=0;
	}	
	return compile;
}

static void maat_hierarchy_compile_free(struct maat_hierarchy_compile *compile)
{
	struct maat_hierarchy_clause_state *clause_state = NULL;
	//user_data must be freed before calling this function.
	assert(compile->user_data == NULL);

	for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		clause_state = compile->clause_states + i;
		utarray_free(clause_state->literal_ids);
		clause_state->literal_ids = NULL;
		clause_state->in_use = 0;
	}
	compile->magic = 0;
	free(compile);
}

void maat_hierarchy_free_item2clause_hash(struct item2clause_value* hash)
{
	struct item2clause_value *i2c_val = NULL, *tmp_i2c_val = NULL;
	HASH_ITER(hh, hash, i2c_val, tmp_i2c_val) {
		HASH_DEL(hash, i2c_val);
		utarray_free(i2c_val->clause_ids);
		free(i2c_val);
	}
	assert(hash == NULL);
}

static struct maat_hierarchy_item *
maat_hierarchy_item_new(struct maat_hierarchy *hier, int item_id, int group_id, 
                        struct maat_group *parent_group, void *user_data)
{
	struct maat_hierarchy_item *item = NULL;
	item = ALLOC(struct maat_hierarchy_item, 1);
	item->group_id = group_id;
	item->item_id = item_id;
	item->ref_parent_group = parent_group;
	item->user_data = user_data;
	HASH_ADD_INT(hier->hash_item_by_id, item_id, item);
	parent_group->ref_by_item_cnt++;

	return item;
}

static void maat_hierarchy_item_free(struct maat_hierarchy *hier, struct maat_hierarchy_item *item)
{
	HASH_DELETE(hh, hier->hash_item_by_id, item);
	item->ref_parent_group->ref_by_item_cnt--;

	if (hier->item_user_data_free && item->user_data) {
		hier->item_user_data_free(item->user_data);
		item->user_data = NULL;
	}
	free(item);
}

static const struct maat_hierarchy_clause *
maat_hierarchy_clause_fetch(struct maat_hierarchy *hier, struct maat_hierarchy_literal_id *literal_ids, 
                            size_t n_literal_id)
{
	struct maat_hierarchy_clause *clause = NULL;

	HASH_FIND(hh, hier->hash_dedup_clause_by_literals, literal_ids, 
			  n_literal_id * sizeof(struct maat_hierarchy_literal_id), clause);
	if (!clause) {
		clause = ALLOC(struct maat_hierarchy_clause, 1);
		clause->clause_id = hier->clause_id_generator;
		clause->n_literal_id = n_literal_id;
		clause->literal_ids = ALLOC(struct maat_hierarchy_literal_id, n_literal_id);
		memcpy(clause->literal_ids, literal_ids, n_literal_id * sizeof(struct maat_hierarchy_literal_id));
		
		hier->clause_id_generator++;
		HASH_ADD_KEYPTR(hh, hier->hash_dedup_clause_by_literals, clause->literal_ids, 
			            n_literal_id * sizeof(struct maat_hierarchy_literal_id), clause);
	}

	return clause;
}

static void maat_hierarchy_clause_free(struct maat_hierarchy *hier, struct maat_hierarchy_clause *clause)
{
	HASH_DELETE(hh, hier->hash_dedup_clause_by_literals, clause);
	free(clause->literal_ids);
	clause->n_literal_id = 0;
	free(clause);
}

void maat_hierarchy_free(struct maat_hierarchy *hier)
{
    struct maat_hierarchy_compile *compile = NULL, *tmp_compile = NULL;
	struct item2clause_value *i2c_val = NULL, *tmp_i2c_val = NULL;
	struct maat_hierarchy_item *item = NULL, *tmp_item = NULL;
	struct maat_hierarchy_clause *clause = NULL, *tmp_clause = NULL;
	pthread_rwlock_wrlock(&hier->rwlock);

	//Reference: https://troydhanson.github.io/uthash/userguide.html#_what_can_it_do
	//Some have asked how uthash cleans up its internal memory. 
	//The answer is simple: when you delete the final item from a hash table, 
	//uthash releases all the internal memory associated with that hash table, 
	//and sets its pointer to NULL.
	HASH_ITER(hh, hier->hash_compile_by_id, compile, tmp_compile) {
		if (hier->compile_user_data_free && compile->user_data) {
			hier->compile_user_data_free(compile->user_data);
			compile->user_data = NULL;
		}		
		HASH_DEL(hier->hash_compile_by_id, compile);
		maat_hierarchy_compile_free(compile);
	}
	assert(hier->hash_compile_by_id == NULL);
	
	HASH_ITER(hh, hier->hash_item2clause, i2c_val, tmp_i2c_val) {
		HASH_DEL(hier->hash_item2clause, i2c_val);
		utarray_free(i2c_val->clause_ids);
		free(i2c_val);
	}

	maat_hierarchy_free_item2clause_hash(hier->hash_item2clause);

	HASH_ITER(hh, hier->hash_item_by_id, item, tmp_item) {
		maat_hierarchy_item_free(hier, item);
	}

	HASH_ITER(hh, hier->hash_dedup_clause_by_literals, clause, tmp_clause) {
		maat_hierarchy_clause_free(hier, clause);
	}

	bool_matcher_free(hier->bm);
	hier->bm = NULL;

	pthread_rwlock_unlock(&hier->rwlock);
	pthread_rwlock_destroy(&hier->rwlock);

	FREE(hier->expr_match_buff);
	FREE(hier);
}

size_t print_igraph_vector(igraph_vector_t *v, char *buff, size_t sz) 
{
  int printed = 0;

  for (long int i = 0; i < igraph_vector_size(v); i++) {
    printed += snprintf(buff + printed, sz - printed, " %li", (long int)VECTOR(*v)[i]);
  }

  return printed;
}

static struct bool_matcher *maat_hierarchy_build_bool_matcher(struct maat_hierarchy *hier)
{
	struct bool_matcher *bm = NULL;
	size_t compile_num = 0, expr_cnt = 0;
	struct bool_expr *bool_expr_array = NULL;
	struct maat_hierarchy_compile *compile = NULL, *tmp_compile = NULL;
	
	struct maat_hierarchy_clause_state *clause_state = NULL;
	const struct maat_hierarchy_clause *clause = NULL;
	size_t i = 0, j = 0;
	int has_clause_num = 0;
	compile_num = HASH_COUNT(hier->hash_compile_by_id);	
	
	if (0 == compile_num) {
		log_error(hier->logger, MODULE_HIERARCHY, "No compile to build.");
		return NULL;
	}

	//STEP 1, update clause_id of each compile and literal
	struct maat_hierarchy_literal_id *literal_ids = NULL;
	size_t n_literal_id = 0;
	HASH_ITER(hh, hier->hash_compile_by_id, compile, tmp_compile) {
		has_clause_num = 0;
		for (i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
			clause_state = compile->clause_states + i;
			clause_state->clause_id = 0;
			if (!clause_state->in_use) {
				continue;
			}

			has_clause_num++;
			literal_ids = (struct maat_hierarchy_literal_id *)utarray_eltptr(clause_state->literal_ids, 0);
			n_literal_id = utarray_len(clause_state->literal_ids);
			clause = maat_hierarchy_clause_fetch(hier, literal_ids, n_literal_id);
			clause_state->clause_id = clause->clause_id;
		}
		assert(has_clause_num == compile->actual_clause_num);
	}
	
	//STEP 2, serial compile clause states to a bool expression array.
	compile_num = HASH_COUNT(hier->hash_compile_by_id);
	bool_expr_array = ALLOC(struct bool_expr, compile_num);
	HASH_ITER(hh, hier->hash_compile_by_id, compile, tmp_compile) {
		for (i = 0, j = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
			if (compile->clause_states[i].in_use) {
				if (compile->clause_states[i].not_flag) {
					compile->not_clause_cnt++;
				}
				bool_expr_array[expr_cnt].items[j].item_id = compile->clause_states[i].clause_id;
				bool_expr_array[expr_cnt].items[j].not_flag = compile->clause_states[i].not_flag;
				j++;
			}
		}
		//some compile may have zero groups, e.g. default policy.
		if (j == (size_t)compile->declared_clause_num && j > 0) {
			bool_expr_array[expr_cnt].expr_id = compile->compile_id;
			bool_expr_array[expr_cnt].user_tag = compile;
			bool_expr_array[expr_cnt].item_num = j;
			expr_cnt++;
		}
	}

	//STEP 3, build the bool matcher.
	size_t mem_size = 0;
	if (0 == expr_cnt) {		
		log_error(hier->logger, MODULE_HIERARCHY, "No bool expression to build.");
		goto error_out;
	}

	bm = bool_matcher_new(bool_expr_array, expr_cnt, &mem_size);
	if (bm != NULL) {
		log_info(hier->logger, MODULE_HIERARCHY,
				"Build bool matcher of %zu expressions with %zu bytes memory.", expr_cnt, mem_size);
	} else {
		log_error(hier->logger, MODULE_HIERARCHY, "Build bool matcher failed!");
	}

error_out:
	FREE(bool_expr_array);

	return bm;
}

static inline int compare_clause_id(const void *a, const void *b)
{
	long long ret = *(const unsigned long long *)a - *(const unsigned long long *)b;

	if (0 == ret) {
		return 0;
	} else if(ret < 0) {
		return -1;
	} else {
		return 1;
	}
}

static inline int compare_item_id(const void *a, const void *b)
{
	return (*(int*)a - *(int*)b);
}

struct item2clause_value *maat_hierarchy_build_item2clause_hash(struct maat_hierarchy *hier)
{
	size_t i = 0, j = 0, k = 0;
	struct maat_hierarchy_compile *compile = NULL, *tmp_compile = NULL;
	struct maat_hierarchy_literal_id *literal_id = NULL;
	struct maat_hierarchy_clause_state *clause_state = NULL;

	struct maat_hierarchy_item *item = NULL, *tmp_item = NULL;
	struct maat_group *group = NULL;
	struct group2item *g2i_hash = NULL, *g2i = NULL, *g2i_tmp = NULL;
	struct item2clause_value *item2clause_hash = NULL, *i2c_val = NULL;
	struct item2clause_key i2c_key;

	//Build a temporary hash that maps group to its items.
	HASH_ITER(hh, hier->hash_item_by_id, item, tmp_item) {
		group = item->ref_parent_group;
		for (i = 0; i < group->top_group_cnt; i++) {
			HASH_FIND_INT(g2i_hash, group->top_group_ids+i, g2i);
			if (!g2i) {
				g2i = ALLOC(struct group2item, 1);
				utarray_new(g2i->item_ids, &ut_item_id_icd);
				utarray_reserve(g2i->item_ids, group->ref_by_item_cnt);
				g2i->group_id = group->top_group_ids[i];
				HASH_ADD_INT(g2i_hash, group_id, g2i);
			}
			
			//One item belongs to one group, one group may have many items. So duplicate item check is unnecessary.
			//if(utarray_find(g2i->item_ids, &(item->item_id), compare_item_id)) assert(0);

			utarray_push_back(g2i->item_ids, &(item->item_id));
			//utarray_sort(g2i->item_ids, compare_item_id);
		}
	}

	//Build short cut hash that maps item_id+vt_id to clause_ids.
	HASH_ITER(hh, hier->hash_compile_by_id, compile, tmp_compile) {
		for (i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
			clause_state = compile->clause_states + i;
			if (!clause_state->in_use) {
				continue;
			}

			for (j = 0; j < utarray_len(clause_state->literal_ids); j++) {
				literal_id = (struct maat_hierarchy_literal_id *)utarray_eltptr(clause_state->literal_ids, j);
				HASH_FIND(hh_group_id, hier->hash_group_by_id, &(literal_id->group_id), sizeof(literal_id->group_id), group);
				if (!group) {
					continue;
				}
				HASH_FIND_INT(g2i_hash, &(group->group_id), g2i);

                //group declared by compile, but has no subordinate or item.
				if (!g2i) {
					continue;
				}

				for (k = 0; k < utarray_len(g2i->item_ids); k++) {
					i2c_key.item_id = *((int*)utarray_eltptr(g2i->item_ids, k));
					i2c_key.vt_id = literal_id->vt_id;
					HASH_FIND(hh, item2clause_hash, &i2c_key, sizeof(i2c_key), i2c_val);
					if (!i2c_val) {
						i2c_val = ALLOC(struct item2clause_value, 1);
						i2c_val->key = i2c_key;
						i2c_val->group_id = g2i->group_id;
						utarray_new(i2c_val->clause_ids, &ut_clause_id_icd);
						HASH_ADD(hh, item2clause_hash, key, sizeof(i2c_val->key), i2c_val);
					}

					if (utarray_find(i2c_val->clause_ids, &(clause_state->clause_id), compare_clause_id)) {
						continue;
					}
					utarray_push_back(i2c_val->clause_ids, &(clause_state->clause_id));
					utarray_sort(i2c_val->clause_ids, compare_clause_id);
				}				
			}
		}
	}

	int tmp1 = 0, tmp2 = 0;
	HASH_ITER(hh, g2i_hash, g2i, g2i_tmp) {
		HASH_DEL(g2i_hash, g2i);
		//Sanity Check
		utarray_sort(g2i->item_ids, compare_item_id);
		for (i = 1; i < utarray_len(g2i->item_ids); i++) {			
			tmp1 = *((int*)utarray_eltptr(g2i->item_ids, i-1));
			tmp2 = *((int*)utarray_eltptr(g2i->item_ids, i));
			assert(tmp1!=tmp2);
		}
		utarray_free(g2i->item_ids);
		g2i->item_ids = NULL;
		free(g2i);
	}

	log_info(hier->logger, MODULE_HIERARCHY, "Build item2clause hash with %llu element.",
								             HASH_COUNT(item2clause_hash));
	return item2clause_hash;
}

int maat_hierarchy_rebuild(struct maat_hierarchy *hier)
{
    int ret=0;
	struct bool_matcher *new_bm = NULL, *old_bm = NULL;
	struct item2clause_value *new_item2clause_hash = NULL, *old_item2clause_hash = NULL;

	//Read hier from update thread is OK.
	if (!hier->changed_flag) {
		return ret;
	}

	ret = maat_group_topology_build_top_groups(hier->ref_group_topo);
	new_bm = maat_hierarchy_build_bool_matcher(hier);
	new_item2clause_hash = maat_hierarchy_build_item2clause_hash(hier);

	pthread_rwlock_wrlock(&hier->rwlock);

	old_bm = hier->bm;		
	old_item2clause_hash = hier->hash_item2clause;

	hier->bm = new_bm;
	hier->hash_item2clause = new_item2clause_hash;
	hier->changed_flag = 0;
	pthread_rwlock_unlock(&hier->rwlock);

	maat_garbage_bagging(hier->ref_garbage_bin, old_bm, (void (*)(void*))bool_matcher_free);	
	maat_garbage_bagging(hier->ref_garbage_bin, old_item2clause_hash, 
                        (void (*)(void*))maat_hierarchy_free_item2clause_hash);

	return ret;
}

static int maat_hierarchy_compile_has_literal(struct maat_hierarchy_compile *compile, struct maat_hierarchy_literal_id *literal_id)
{
    if (NULL == compile || NULL == literal_id) {
        return 0;
    }

	for (int i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		struct maat_hierarchy_clause_state *clause_state = compile->clause_states + i;
		if (!clause_state->in_use) {
			continue;
		}

		struct maat_hierarchy_literal_id *tmp = (struct maat_hierarchy_literal_id *)utarray_find(clause_state->literal_ids, literal_id, compare_literal_id);
		if (tmp) {
			assert(tmp->group_id == literal_id->group_id && tmp->vt_id == literal_id->vt_id);
			return 1;
		}
	}

	return 0;
}

static int maat_hierarchy_is_hit_path_existed(const struct maat_hit_path *hit_paths, size_t n_path, const struct maat_hit_path *find)
{
    if (NULL == hit_paths || NULL == find) {
        return 0;
    }

	for (size_t i = 0; i < n_path; i++) {
		if (0 == memcmp(hit_paths + i, find, sizeof(*find))) {
			return 1;
		}
	}

	return 0;
}

size_t maat_hierarchy_get_hit_paths(struct maat_hierarchy *hier, struct maat_hierarchy_compile_mid *mid, 
									struct maat_hit_path *hit_paths, size_t n_path)
{
    struct maat_hierarchy_internal_hit_path *p = NULL;
	struct maat_hierarchy_item *item = NULL;
	struct maat_group *group = NULL;
	struct maat_hierarchy_compile *compile = NULL;
	struct maat_hierarchy_literal_id literal_id = {0, 0};
	size_t n_made_by_item = 0, n_made_by_compile = 0;
	size_t i = 0, j = 0, bool_match_ret = 0;	
	struct bool_expr_match *expr_match = hier->expr_match_buff + mid->thread_id * MAX_SCANNER_HIT_NUM;
	struct maat_hit_path tmp_path;

	if (hier->version != mid->hier_ver) {
		return 0;
	}
	pthread_rwlock_rdlock(&hier->rwlock);
	
	for (i = 0; i < utarray_len(mid->internal_hit_paths); i++) {
		p = (struct maat_hierarchy_internal_hit_path *)utarray_eltptr(mid->internal_hit_paths, i);

		HASH_FIND_INT(hier->hash_item_by_id, &(p->item_id), item);
		if (!item) {
			continue;
		}

		group = item->ref_parent_group;
		if (group->top_group_cnt == 0 && n_made_by_item < n_path) {
			hit_paths[n_made_by_item].Nth_scan = p->Nth_scan;
			hit_paths[n_made_by_item].item_id = p->item_id;
			hit_paths[n_made_by_item].sub_group_id = group->group_id;
			hit_paths[n_made_by_item].top_group_id = -1;			
			hit_paths[n_made_by_item].virtual_table_id = p->virtual_table_id;
			hit_paths[n_made_by_item].compile_id = -1;
			n_made_by_item++;
		} else {
			for (j = 0; j < group->top_group_cnt && n_made_by_item < n_path; j++, n_made_by_item++) {
				hit_paths[n_made_by_item].Nth_scan = p->Nth_scan;
				hit_paths[n_made_by_item].item_id = p->item_id;
				hit_paths[n_made_by_item].sub_group_id = group->group_id;
				hit_paths[n_made_by_item].top_group_id = group->top_group_ids[j];			
				hit_paths[n_made_by_item].virtual_table_id = p->virtual_table_id;
				hit_paths[n_made_by_item].compile_id = -1;
			}
		}
	}

	bool_match_ret = bool_matcher_match(hier->bm, (unsigned long long *)utarray_eltptr(mid->all_hit_clause_array, 0), 
                                        utarray_len(mid->all_hit_clause_array),
						                expr_match, MAX_SCANNER_HIT_NUM);
	for (i = 0; i < bool_match_ret; i++) {
		compile = (struct maat_hierarchy_compile *)expr_match[i].user_tag;
		assert(compile->magic == MAAT_HIER_COMPILE_MAGIC);
		assert((unsigned long long)compile->compile_id == expr_match[i].expr_id);
		if (compile->actual_clause_num == 0 || !compile->user_data) {
			continue;
		}

		for (j = 0; j < n_made_by_item && n_made_by_item + n_made_by_compile < n_path; j++) {
			if (hit_paths[j].top_group_id < 0) {
				continue;
			}

			literal_id.group_id = hit_paths[j].top_group_id;
			literal_id.vt_id = hit_paths[j].virtual_table_id;
			if (maat_hierarchy_compile_has_literal(compile, &literal_id)) {
				if (hit_paths[j].compile_id < 0) {
					hit_paths[j].compile_id = compile->compile_id;
				} else {
					tmp_path = hit_paths[j];
					tmp_path.compile_id=compile->compile_id;
					if (maat_hierarchy_is_hit_path_existed(hit_paths, n_made_by_item + n_made_by_compile, &tmp_path)) {
						hit_paths[n_made_by_item + n_made_by_compile] = tmp_path;
						n_made_by_compile++;
					}
				}
			}
		}
	}

	pthread_rwlock_unlock(&hier->rwlock);
	return (n_made_by_item + n_made_by_compile);
}

void maat_hierarchy_set_compile_user_data_free_func(struct maat_hierarchy *hier,  void (* func)(void *))
{
    hier->compile_user_data_free = func;
}

void maat_hierarchy_set_item_user_data_free_func(struct maat_hierarchy *hier,  void (* func)(void *))
{
    hier->item_user_data_free = func;
}

struct maat_hierarchy_compile_mid *maat_hierarchy_compile_mid_new(struct maat_hierarchy *hier, int thread_id)
{
    struct maat_hierarchy_compile_mid *mid = ALLOC(struct maat_hierarchy_compile_mid, 1);

	mid->thread_id = thread_id;
	mid->hier_ver = hier->version;
	utarray_new(mid->internal_hit_paths, &ut_hit_path_icd);
	utarray_new(mid->all_hit_clause_array, &ut_clause_id_icd);
	utarray_new(mid->this_scan_hit_clause_ids, &ut_clause_id_icd);

	return mid;
}

void maat_hierarchy_compile_mid_free(struct maat_hierarchy_compile_mid *mid)
{
    utarray_free(mid->internal_hit_paths);
	utarray_free(mid->all_hit_clause_array);
	utarray_free(mid->this_scan_hit_clause_ids);
	free(mid);
}

static int maat_hierarchy_hit_path_add(UT_array *hit_paths, int item_id, int virtual_table_id, 
                                       int Nth_scan, int Nth_item_result)
{
	struct maat_hierarchy_internal_hit_path new_path;

	new_path.item_id = item_id;
	new_path.Nth_hit_item = Nth_item_result;
	new_path.Nth_scan = Nth_scan;
	new_path.virtual_table_id = virtual_table_id;
	
	utarray_push_back(hit_paths, &new_path);
	return 1;
}

void maat_hierarchy_compile_mid_update(struct maat_hierarchy *hier, 
                                       struct maat_hierarchy_compile_mid *mid, 
                                       int item_id, int virtual_table_id, 
                                       int Nth_scan, int Nth_item_result)
{
	if (mid->Nth_scan != Nth_scan) {
		assert(mid->this_scan_item_hit_cnt == 0);
		mid->Nth_scan = Nth_scan;
		utarray_clear(mid->this_scan_hit_clause_ids);
	}

	int ret = maat_hierarchy_hit_path_add(mid->internal_hit_paths, item_id, virtual_table_id, 
                                          Nth_scan, Nth_item_result);
	if (!ret) {
		return;
	}
	mid->hit_path_cnt++;
	mid->this_scan_item_hit_cnt++;

	struct item2clause_value* i2c_val = NULL;
	struct item2clause_key i2c_key;
	i2c_key.item_id = item_id;
	i2c_key.vt_id = virtual_table_id;

	HASH_FIND(hh, hier->hash_item2clause, &i2c_key, sizeof(i2c_key), i2c_val);
	if (!i2c_val) {
		return;
	}

    size_t i = 0;
    unsigned long long *clause_id = 0;
	size_t new_clause_idx = utarray_len(mid->this_scan_hit_clause_ids);
	for (size_t i = 0; i < utarray_len(r2c_val->clause_ids); i++) {
		clause_id = (unsigned long long *)utarray_eltptr(r2c_val->clause_ids, i);
		if (utarray_find(mid->all_hit_clause_array, clause_id, compare_clause_id)) {
			continue;
		}
		utarray_push_back(mid->this_scan_hit_clause_ids, clause_id);
	}

	if (utarray_len(mid->this_scan_hit_clause_ids) - new_clause_idx) {
		utarray_reserve(mid->all_hit_clause_array, utarray_len(mid->this_scan_hit_clause_ids) - new_clause_idx);
		for (i = new_clause_idx; i < utarray_len(mid->this_scan_hit_clause_ids); i++) {
			clause_id = (unsigned long long *)utarray_eltptr(mid->this_scan_hit_clause_ids, i);
			utarray_push_back(mid->all_hit_clause_array, clause_id);
		}
		utarray_sort(mid->all_hit_clause_array, compare_clause_id);
	}
}

int maat_hierarchy_compile_mid_has_NOT_clause(struct maat_hierarchy_compile_mid *mid)
{   
    return mid->not_clause_hitted_flag;
}

int maat_hierarchy_compile_add(struct maat_hierarchy *hier, int compile_id, 
                               int declared_clause_num, void *user_data)
{
    int ret = 0;
	struct maat_hierarchy_compile *compile = NULL;
	
	pthread_rwlock_wrlock(&hier->rwlock);
	hier->changed_flag = 1;
	HASH_FIND_INT(hier->hash_compile_by_id, &compile_id, compile);
	if (!compile) {
		assert(declared_clause_num >= 0);
		compile = maat_hierarchy_compile_new(hier, compile_id);
		compile->declared_clause_num = declared_clause_num;
		compile->user_data = user_data;
	} else {
		if (compile->user_data != NULL) {
			log_error(hier->logger, MODULE_HIERARCHY, 
                      "Add compile %d failed, compile is already exisited.", compile_id);
			ret = -1;
		} else {
			compile->declared_clause_num = declared_clause_num;
			compile->user_data = user_data;
		}
	}
	pthread_rwlock_unlock(&hier->rwlock);

	return ret;
}

int maat_hierarchy_compile_remove(struct maat_hierarchy *hier, int compile_id)
{
    int ret = 0;
    struct maat_hierarchy_compile *compile = NULL;
	
	pthread_rwlock_wrlock(&hier->rwlock);
	hier->changed_flag = 1;
	HASH_FIND_INT(hier->hash_compile_by_id, &compile_id, compile);
	if (compile) {
		if (hier->compile_user_data_free && compile->user_data) {
			hier->compile_user_data_free(compile->user_data);
			compile->user_data = NULL;
		}
        
		if (0 == compile->actual_clause_num) {		
			HASH_DEL(hier->hash_compile_by_id, compile);
			maat_garbage_bagging(hier->ref_garbage_bin, compile, (void (*)(void*))maat_hierarchy_compile_free);
		}
		ret = 0;
	} else {
		log_error(hier->logger, MODULE_HIERARCHY,
				  "Remove compile %d failed, compile is not exisited.", compile_id);
		ret = -1;
	}
	pthread_rwlock_unlock(&hier->rwlock);

	return ret;
}

static void *maat_hier_compile_get_user_data(struct maat_hierarchy* hier, int compile_id, int is_dettach)
{
	struct maat_hierarchy_compile *compile = NULL;
	void *ret = NULL;
	
	pthread_rwlock_rdlock(&hier->rwlock);
	HASH_FIND_INT(hier->hash_compile_by_id, &compile_id, compile);
	if (compile) {
		ret = compile->user_data;
		if (is_dettach) {
			compile->user_data = NULL;
		}
	}
	pthread_rwlock_unlock(&hier->rwlock);

	return ret;
}

void *maat_hierarchy_compile_dettach_user_data(struct maat_hierarchy *hier, int compile_id)
{
	return maat_hier_compile_get_user_data(hier, compile_id, 1);
}

void *maat_hierarchy_compile_read_user_data(struct maat_hierarchy *hier, int compile_id)
{
    return maat_hier_compile_get_user_data(hier, compile_id, 0);
}

void maat_hierarchy_compile_user_data_iterate(struct maat_hierarchy *hier, void (*callback)(void *user_data, void *param), void *param)
{
    struct maat_hierarchy_compile *compile = NULL, *tmp_compile = NULL;

	pthread_rwlock_rdlock(&hier->rwlock);
	HASH_ITER(hh, hier->hash_compile_by_id, compile, tmp_compile) {
		if (compile->user_data) {
			callback(compile->user_data, param);
		}
	}
	pthread_rwlock_unlock(&hier->rwlock);
}

static int maat_hierarchy_compile_has_clause(struct maat_hierarchy_compile* compile, unsigned long long clause_id)
{
	struct maat_hierarchy_clause_state *clause_state = NULL;

	for (size_t i = 0; i < MAX_ITEMS_PER_BOOL_EXPR; i++) {
		clause_state = compile->clause_states + i;
		if (!clause_state->in_use) {
			continue;
		}

		if (clause_state->clause_id == clause_id) {
			return 1;
		}
	}

	return 0;
}

static size_t maat_hierarchy_compile_mid_if_new_hit_compile(struct maat_hierarchy_compile_mid *mid, 
                                                            struct maat_hierarchy_compile *compile)
{
	size_t r_in_c_cnt = 0;

	unsigned long long new_hit_clause_id = 0;
	for(size_t i = 0; i<utarray_len(mid->this_scan_hit_clause_ids); i++) {
		new_hit_clause_id = *(unsigned long long*)utarray_eltptr(mid->this_scan_hit_clause_ids, i);
		int ret = maat_hierarchy_compile_has_clause(compile, new_hit_clause_id);
		if (ret) {
			r_in_c_cnt++;
		}
	}
	return r_in_c_cnt;
}

int maat_hierarchy_item_compile(struct maat_hierarchy *hier, struct maat_hierarchy_compile_mid *mid, 
                                  int is_last_compile, void **user_data_array, size_t ud_array_sz)
{
    int bool_match_ret = 0, i = 0;
	struct maat_hierarchy_compile *compile = NULL;
	struct bool_expr_match *expr_match = hier->expr_match_buff + (mid->thread_id * MAX_SCANNER_HIT_NUM);

	size_t r_in_c_cnt = 0;
    size_t ud_result_cnt = 0;
    size_t this_scan_item_hits = mid->this_scan_item_hit_cnt;
	
	if (!hier->bm || 0 == utarray_len(mid->all_hit_clause_array) || hier->version != mid->hier_ver) {
		mid->this_scan_item_hit_cnt = 0;
		return 0;
	}

	bool_match_ret = bool_matcher_match(hier->bm, (unsigned long long *)utarray_eltptr(mid->all_hit_clause_array, 0), 
                                        utarray_len(mid->all_hit_clause_array), expr_match, MAX_SCANNER_HIT_NUM);
	for (i = 0; i < bool_match_ret && ud_result_cnt < ud_array_sz; i++) {
		compile = (struct maat_hierarchy_compile *)expr_match[i].user_tag;
		assert(compile->magic == MAAT_HIER_COMPILE_MAGIC);
		assert((unsigned long long)compile->compile_id == expr_match[i].expr_id);
		if (0 == compile->actual_clause_num) {
			continue;
		}

		r_in_c_cnt = maat_hierarchy_compile_mid_if_new_hit_compile(mid, compile);
		if (compile->not_clause_cnt > 0 && !is_last_compile) {
			mid->not_clause_hitted_flag = 1;
		} else if(compile->user_data) {
            //For compile may be dettached by Maat_hierarchy_compile_dettach_user_data, only return non-NULL userdata.		
			if (r_in_c_cnt > 0 ||				//compile hitted becasue of new reigon
				this_scan_item_hits == 0)	//or hit a compile that refer a NOT-logic group in previous scan.
			{
				user_data_array[ud_result_cnt]=compile->user_data;
				ud_result_cnt++;
			}
		}
	}

	mid->this_scan_item_hit_cnt = 0;

	return ud_result_cnt;
}

void *maat_hierarchy_item_dettach_user_data(struct maat_hierarchy *hier, int item_id)
{
    struct maat_hierarchy_item *item = NULL;
	void *ret = NULL;

	pthread_rwlock_wrlock(&hier->rwlock);
	hier->changed_flag = 1;
	HASH_FIND_INT(hier->hash_item_by_id, &item_id, item);
	if (item) {
		ret = item->user_data;
		item->user_data = NULL;
	}
	pthread_rwlock_unlock(&hier->rwlock);

	return ret;
}

int compare_literal_id(const void *pa, const void *pb)
{
	struct maat_hierarchy_literal_id *la = (struct maat_hierarchy_literal_id *)pa;
	struct maat_hierarchy_literal_id *lb = (struct maat_hierarchy_literal_id *)pb;

	int ret = la->vt_id - lb->vt_id;
	if (ret == 0) {
		ret = la->group_id - lb->group_id;
	}

	return ret;
}

static int maat_hierarchy_compile_add_literal(struct maat_hierarchy_compile *compile, 
                                              struct maat_hierarchy_literal_id *literal_id, 
                                              int not_flag, int clause_index)
{
    struct maat_hierarchy_literal_id *tmp = NULL;
	struct maat_hierarchy_clause_state *clause_state = compile->clause_states + clause_index;
	clause_state->not_flag = not_flag;

	if (!clause_state->in_use) {
		clause_state->in_use = 1;
		compile->actual_clause_num++;
	}

    tmp = (struct maat_hierarchy_literal_id *)utarray_find(clause_state->literal_ids, literal_id, compare_literal_id);
	if (tmp) {
		assert(*(unsigned long long*)tmp == *(unsigned long long*)(literal_id));
		return -1;
	} else {
		utarray_push_back(clause_state->literal_ids, literal_id);
		utarray_sort(clause_state->literal_ids, compare_literal_id);
	}

	return 0;
}

static int maat_hierarchy_compile_remove_literal(struct maat_hierarchy_compile *compile, 
                                                 struct maat_hierarchy_literal_id *literal_id, 
                                                 int clause_index)
{
    struct maat_hierarchy_literal_id *tmp = NULL;
	struct maat_hierarchy_clause_state *clause_state = compile->clause_states + clause_index;

	tmp = (struct maat_hierarchy_literal_id *)utarray_find(clause_state->literal_ids, literal_id , compare_literal_id);
	if (tmp) {
		assert(*(unsigned long long*)tmp == *(unsigned long long*)(literal_id));
	} else {
		return -1;
	}

	size_t remove_idx = utarray_eltidx(clause_state->literal_ids, tmp);
	utarray_erase(clause_state->literal_ids, remove_idx, 1);
	if (0 == utarray_len(clause_state->literal_ids)) {
		clause_state->in_use = 0;
		compile->actual_clause_num--;
	}

	return 0;
}

int maat_hierarchy_add_group_to_compile(struct maat_hierarchy *hier, int group_id, int vt_id, 
                                        int not_flag, int clause_index, int compile_id)
{
    int ret = 0;
	struct maat_group *group = NULL;
	struct maat_hierarchy_literal_id literal_id = {group_id, vt_id};
	struct maat_hierarchy_compile *compile = NULL;
	
	pthread_rwlock_wrlock(&hier->rwlock);
	hier->changed_flag = 1;

	HASH_FIND(hh, hier->hash_compile_by_id, &compile_id, sizeof(compile_id), compile);
	if (!compile) {
		compile = maat_hierarchy_compile_new(hier, compile_id);
	}
	
	ret = maat_hierarchy_compile_add_literal(compile, &literal_id, not_flag, clause_index);	
	if (ret < 0) {
		log_error(hier->logger, MODULE_HIERARCHY,
				  "Add group %d vt_id %d to clause %d of compile %d failed, group is already exisited.",
				  group_id, vt_id, clause_index, compile_id);
		ret = -1;
	} else {
		ret = 0;
	}	
	pthread_rwlock_unlock(&hier->rwlock);

	return ret;
}

int maat_hierarchy_remove_group_from_compile(struct maat_hierarchy *hier, int group_id, int vt_id, 
                                             int not_flag, int clause_index, int compile_id)
{
	struct maat_hierarchy_literal_id literal_id = {group_id, vt_id};	
	struct maat_hierarchy_compile *compile = NULL;
	int ret = 0;
	
	pthread_rwlock_wrlock(&hier->rwlock);
	hier->changed_flag = 1;

	HASH_FIND(hh, hier->hash_compile_by_id, &compile_id, sizeof(compile_id), compile);
	if (!compile) {
		log_error(hier->logger, MODULE_HIERARCHY,
				  "Remove group %d from compile %d failed, compile is not exisited.",
				  group_id, compile_id);
		goto error_out;		
	}

	ret = maat_hierarchy_compile_remove_literal(compile, &literal_id, clause_index);
	if (ret < 0) {
		log_error(hier->logger, MODULE_HIERARCHY,
				  "Remove group %d vt_id %d from clause %d of compile %d failed, literal is not in compile.",
				  group_id, vt_id, clause_index, compile_id);
		goto error_out;
	}

	if (0 == compile->actual_clause_num && !compile->user_data) {		
		HASH_DEL(hier->hash_compile_by_id, compile);
		maat_garbage_bagging(hier->ref_garbage_bin, compile, (void (*)(void*))maat_hierarchy_compile_free);
	}
	pthread_rwlock_unlock(&hier->rwlock);
	return 0;
	
error_out:
	pthread_rwlock_unlock(&hier->rwlock);
	return -1;
}

int maat_hierarchy_add_item_to_group(struct maat_hierarchy *hier, int group_id, int item_id, void *user_data)
{
    //A item rule belongs to ONE group only.
	struct maat_group *group = NULL;
	struct maat_hierarchy_item *item = NULL;
	int ret = 0;
	
	pthread_rwlock_wrlock(&hier->rwlock);
	hier->changed_flag = 1;
    /*
	HASH_FIND(hh_group_id, hier->hash_group_by_id, &group_id, sizeof(group_id), group);
	if (!group) {
		group = maat_hierarchy_group_new(hier, group_id);
	}*/

	HASH_FIND_INT(hier->hash_item_by_id, &item_id, item);
	if (item) {
		log_error(hier->logger, MODULE_HIERARCHY,
				  "Add item %d to group %d failed, item already in group %d.", 
				  item_id, group_id, item->ref_parent_group->group_id);
		ret = -1;
	} else {
		item = maat_hierarchy_item_new(hier, item_id, group_id, group, user_data);
		ret = 0;
	}
	pthread_rwlock_unlock(&hier->rwlock);
	
	return ret;
}

int maat_hierarchy_remove_item_from_group(struct maat_hierarchy *hier, int group_id, int item_id)
{
    struct maat_group *group = NULL;
	struct maat_hierarchy_item *item = NULL;

	pthread_rwlock_wrlock(&hier->rwlock);
	hier->changed_flag =  1;
	HASH_FIND(hh_group_id, hier->ref_group_topo->hash_group_by_id, &group_id, sizeof(group_id), group);
	if (!group) {
		log_error(hier->logger, MODULE_HIERARCHY,
				  "Remove item %d from group %d failed, group is not existed.", 
				  item_id, group_id);
		goto error_out;
	}

	HASH_FIND_INT(hier->hash_item_by_id, &item_id, item);
	if (!item) {
		log_error(hier->logger, MODULE_HIERARCHY,
				  "Remove item %d from group %d failed, item is not exisited.", 
				  item_id, group_id);
		goto error_out;
	}
	
	assert(item->group_id == group->group_id);
	maat_hierarchy_item_free(hier, item);
	pthread_rwlock_unlock(&hier->rwlock);
	return 0;

error_out:
	pthread_rwlock_unlock(&hier->rwlock);
	return -1;
}