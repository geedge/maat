
#include "Maat_hierarchy.h"
#include "Maat_utils.h"
#include "Maat_limits.h"

#include "uthash/uthash.h"
#include "uthash/utarray.h"
#include "igraph/igraph.h"
#include "bool_matcher.h"

#include <MESA/MESA_handle_logger.h>

#include <pthread.h>
#include <assert.h>

#define module_maat_hierarchy	"MAAT_HIERARCHY"



struct Maat_hierarchy_group
{
	igraph_integer_t vertex_id;
	int group_id;
	int ref_by_compile_cnt;
	int ref_by_superior_group_cnt;
	int ref_by_subordinate_group_cnt;
	int ref_by_region_cnt;

	int top_group_cnt;
	int* top_group_ids;
	UT_hash_handle hh_group_id;
	UT_hash_handle hh_vertex_id;
};
struct Maat_hierarchy_region
{
	int region_id;
	int group_id;
	int table_id;

	struct Maat_hierarchy_group* ref_parent_group;
	UT_hash_handle hh;

	void* user_data;
};

struct Maat_hierarchy_literal_id
{
	int group_id;
	int virtual_table_id;
};

struct Maat_hierarchy_literal
{
	struct Maat_hierarchy_literal_id literal_id;
	UT_array *clause_ids;
	UT_hash_handle hh;	//index to 
};
struct Maat_hierarchy_clause_state
{

	unsigned long long clause_id;
	char not_flag;
	char in_use;
	UT_array *literal_ids;
};
UT_icd ut_literal_id_icd = {sizeof(struct Maat_hierarchy_literal_id), NULL, NULL, NULL};
UT_icd ut_clause_id_icd = {sizeof(unsigned long long), NULL, NULL, NULL};

struct Maat_hierarchy_compile
{
	int compile_id;
	int actual_clause_num;
	int declared_clause_num;
	int not_clause_cnt;
	void* user_data;
	UT_hash_handle hh;
	struct Maat_hierarchy_clause_state clause_states[MAX_ITEMS_PER_BOOL_EXPR];
};

static void _group_vertex_free(struct Maat_hierarchy_group* group)
{
	free(group->top_group_ids);
	free(group);
}


struct Maat_hierarchy
{
	pthread_rwlock_t rwlock;
	struct bool_matcher* bm;

	struct Maat_hierarchy_compile* hash_compile_by_id;		//key: compile_id, value: struct Maat_hierarchy_compile*.
	void (* compile_user_data_free)(void *compile_ud);

	struct Maat_hierarchy_group* hash_group_by_id;			//key: group_id, value: struct Maat_hierarchy_group*.
	struct Maat_hierarchy_group* hash_group_by_vertex;		//key:vetex_id, value: struct Maat_hierarchy_group*. Multimap (Items with multiple keys).

	struct Maat_hierarchy_literal* hash_literal_by_id;		//key: virtual_table<<32|group_id, aka literal_id, value: struct Maat_hierarchy_literal*.

	struct Maat_hierarchy_region* hash_region_by_id;		//key: region_id, value: struct Maat_hierarchy_region*.
	void (* region_user_data_free)(void *region_ud);	


	igraph_t group_graph;
	igraph_integer_t group_graph_vcount;
	igraph_vector_t dfs_vids;

	igraph_integer_t grp_vertex_id_generator;

	int thread_num;
	struct Maat_garbage_bin* garbage_bin;
	void* logger;
	void **expr_match_buff;
};

int compare_literal_id(const void *pa, const void *pb)
{
	struct Maat_hierarchy_literal_id *la=(struct Maat_hierarchy_literal_id *)pa;
	struct Maat_hierarchy_literal_id *lb=(struct Maat_hierarchy_literal_id *)pb;
	int ret=la->virtual_table_id-lb->virtual_table_id;
	if(ret==0)
	{
		ret=la->group_id-lb->group_id;
	}
	return ret;

}
static inline int compare_clause_id(const void* a, const void* b)
{
	long long ret=*(const unsigned long long *)a - *(const unsigned long long *)b;
	if(ret==0)
	{
		return 0;
	}
	else if(ret<0)
	{
		return -1;
	}
	else
	{
		return 1;
	}
}
static struct Maat_hierarchy_literal* Maat_hierarchy_literal_new(struct Maat_hierarchy_literal** hash_table, int group_id, int vt_id)
{
	struct Maat_hierarchy_literal* literal=ALLOC(struct Maat_hierarchy_literal, 1);
	literal->literal_id.group_id=group_id;
	literal->literal_id.virtual_table_id=vt_id;
	utarray_new(literal->clause_ids, &ut_clause_id_icd);
	
	HASH_ADD(hh, *hash_table, literal_id, sizeof(literal->literal_id), literal);	
	return literal;
}
static void Maat_hierarchy_literal_free(struct Maat_hierarchy_literal** hash_table, struct Maat_hierarchy_literal* literal)
{
	utarray_free(literal->clause_ids);
	literal->clause_ids=NULL;
	HASH_DELETE(hh, *hash_table, literal);
	free(literal);	
}
static int Maat_hierarchy_compile_has_literal(struct Maat_hierarchy_compile* compile, struct Maat_hierarchy_literal_id* literal_id)
{
	int i=0;
	struct Maat_hierarchy_literal_id* tmp=NULL;
	struct Maat_hierarchy_clause_state* clause_state=NULL;
	for(i=0; i<MAX_ITEMS_PER_BOOL_EXPR; i++)
	{
		clause_state=compile->clause_states+i;
		if(!clause_state->in_use)
		{
			continue;
		}
		tmp=(struct Maat_hierarchy_literal_id*)utarray_find(clause_state->literal_ids, literal_id, compare_literal_id);
		if(tmp)
		{
			assert(tmp->group_id==literal_id->group_id && tmp->virtual_table_id==literal_id->virtual_table_id);
			return 1;
		}
	}
	return 0;
}
static int Maat_hierarchy_compile_add_literal(struct Maat_hierarchy_compile* compile, struct Maat_hierarchy_literal_id* literal_id, int not_flag, int clause_index)
{
	struct Maat_hierarchy_clause_state* clause_state=compile->clause_states+clause_index;
	struct Maat_hierarchy_literal_id* tmp=NULL;
	clause_state->not_flag=not_flag;
	if(!clause_state->in_use)
	{
		clause_state->in_use=1;
		compile->actual_clause_num++;
	}
	tmp=(struct Maat_hierarchy_literal_id*)utarray_find(clause_state->literal_ids, literal_id, compare_literal_id);
	if(tmp)
	{
		assert(*(unsigned long long*)tmp == *(unsigned long long*)(literal_id));
		return -1;
	}
	else
	{
		utarray_push_back(clause_state->literal_ids, literal_id);
		utarray_sort(clause_state->literal_ids, compare_literal_id);
	}
	return 0;
}
static int Maat_hierarchy_compile_remove_literal(struct Maat_hierarchy_compile* compile, struct Maat_hierarchy_literal_id* literal_id, int clause_index)
{
	struct Maat_hierarchy_clause_state* clause_state=compile->clause_states+clause_index;
	struct Maat_hierarchy_literal_id* tmp=NULL;
	size_t remove_idx=0;
	tmp=(struct Maat_hierarchy_literal_id*)utarray_find(clause_state->literal_ids, literal_id , compare_literal_id);
	if(tmp)
	{
		assert(*(unsigned long long*)tmp == *(unsigned long long*)(literal_id));
	}
	else
	{
		return -1;
	}
	remove_idx=utarray_eltidx(clause_state->literal_ids, tmp);
	utarray_erase(clause_state->literal_ids, remove_idx, 1);
	if(0==utarray_len(clause_state->literal_ids))
	{
		clause_state->in_use=0;
		compile->actual_clause_num--;
	}
	return 0;
}
static struct Maat_hierarchy_compile* Maat_hierarchy_compile_new(struct Maat_hierarchy* hier, int compile_id)
{
	int i=0;
	struct Maat_hierarchy_compile* compile=NULL;
	compile=ALLOC(struct Maat_hierarchy_compile, 1);
	compile->compile_id=compile_id;
	HASH_ADD_INT(hier->hash_compile_by_id, compile_id, compile);
	for(i=0; i<MAX_ITEMS_PER_BOOL_EXPR; i++)
	{	
		utarray_new(compile->clause_states[i].literal_ids, &ut_literal_id_icd);
		compile->clause_states[i].in_use=0;
	}	
	return compile;
}
static void Maat_hierarchy_compile_free(struct Maat_hierarchy* hier, struct Maat_hierarchy_compile* compile)
{
	int i=0;
	HASH_DEL(hier->hash_compile_by_id, compile);
	if(compile->user_data && hier->compile_user_data_free)
	{
		hier->compile_user_data_free(compile->user_data);
		compile->user_data=NULL;
	}
	for(i=0; i<MAX_ITEMS_PER_BOOL_EXPR; i++)
	{		
		utarray_free(compile->clause_states[i].literal_ids);
		compile->clause_states[i].literal_ids=NULL;
		compile->clause_states[i].in_use=0;
	}
	free(compile);
}

static struct Maat_hierarchy_region* Maat_hierarchy_region_new(struct Maat_hierarchy* hier, int region_id, int group_id, int table_id, struct Maat_hierarchy_group* parent_group, void* user_data)
{
	struct Maat_hierarchy_region* region=NULL;
	region=ALLOC(struct Maat_hierarchy_region, 1);
	region->group_id=group_id;
	region->region_id=region_id;
	region->table_id=table_id;
	region->ref_parent_group=parent_group;
	region->user_data=user_data;
	HASH_ADD_INT(hier->hash_region_by_id, region_id, region);
	parent_group->ref_by_region_cnt++;
	return region;
}
static void Maat_hierarchy_region_free(struct Maat_hierarchy* hier, struct Maat_hierarchy_region* region)
{
	HASH_DELETE(hh, hier->hash_region_by_id, region);
	region->ref_parent_group->ref_by_region_cnt--;
	if(hier->region_user_data_free && region->user_data)
	{
		hier->region_user_data_free(region->user_data);
		region->user_data=NULL;
	}
	free(region);
	return;
}


struct Maat_hierarchy* Maat_hierarchy_new(int thread_num, void* mesa_handle_logger)
{
	struct Maat_hierarchy* hier=ALLOC(struct Maat_hierarchy, 1);
	int ret=0;
	hier->logger=mesa_handle_logger;
	hier->thread_num=thread_num;

	hier->hash_group_by_id=NULL;
	hier->hash_group_by_vertex=NULL;
	hier->hash_compile_by_id=NULL;
	hier->hash_literal_by_id=NULL;
	hier->hash_region_by_id=NULL;

	hier->expr_match_buff=ALLOC(void*, thread_num*MAX_SCANNER_HIT_NUM);

	ret=igraph_empty(&hier->group_graph, 0, IGRAPH_DIRECTED);
	assert(ret==IGRAPH_SUCCESS);
	return hier;
}
void Maat_hierarchy_free(struct Maat_hierarchy* hier)
{
	struct Maat_hierarchy_compile* compile=NULL, *tmp_compile=NULL;
	struct Maat_hierarchy_group* group=NULL, *tmp_group=NULL;
	struct Maat_hierarchy_literal* literal=NULL, *tmp_literal=NULL;
	struct Maat_hierarchy_region* region=NULL, *tmp_region=NULL;
	pthread_rwlock_wrlock(&hier->rwlock);

	//Reference: https://troydhanson.github.io/uthash/userguide.html#_what_can_it_do
	//Some have asked how uthash cleans up its internal memory. 
	//The answer is simple: when you delete the final item from a hash table, 
	//uthash releases all the internal memory associated with that hash table, 
	//and sets its pointer to NULL.
	HASH_ITER(hh, hier->hash_compile_by_id, compile, tmp_compile)
	{
		Maat_hierarchy_compile_free(hier, compile);
	}
	assert(hier->hash_compile_by_id==NULL);
	
	HASH_ITER(hh, hier->hash_literal_by_id, literal, tmp_literal)
	{
		Maat_hierarchy_literal_free(&hier->hash_literal_by_id, literal);
	}
	assert(hier->hash_literal_by_id==NULL);

	HASH_ITER(hh, hier->hash_region_by_id, region, tmp_region)
	{
		Maat_hierarchy_region_free(hier, region);
	}


	//Free group as the last.
	HASH_CLEAR(hh_vertex_id, hier->hash_group_by_vertex);//No need group memory clean up.
	HASH_ITER(hh_group_id, hier->hash_group_by_id, group, tmp_group)
	{
		HASH_DELETE(hh_group_id, hier->hash_group_by_id, group);
		_group_vertex_free(group);
	}
	assert(hier->hash_group_by_id==NULL);	
	
	igraph_destroy(&hier->group_graph);
	bool_matcher_free(hier->bm);
	hier->bm=NULL;
	pthread_rwlock_unlock(&hier->rwlock);
	free(hier->expr_match_buff);
	hier->expr_match_buff=NULL;
	free(hier);
}

void Maat_hierarchy_set_compile_user_data_free_func(struct Maat_hierarchy* hier,  void (* func)(void *))
{
	hier->compile_user_data_free=func;
	return;
}
void Maat_hierarchy_set_region_user_data_free_func(struct Maat_hierarchy* hier,  void (* func)(void *))
{
	hier->region_user_data_free=func;
	return;
}


int Maat_hierarchy_compile_add(struct Maat_hierarchy* hier, int compile_id, int declared_clause_num, void* user_data)
{
	int ret=0;
	struct Maat_hierarchy_compile* compile=NULL;
	
	pthread_rwlock_wrlock(&hier->rwlock);
	HASH_FIND_INT(hier->hash_compile_by_id, &compile_id, compile);
	if(!compile)
	{
		assert(declared_clause_num>=0);
		compile=Maat_hierarchy_compile_new(hier, compile_id);
		compile->declared_clause_num=declared_clause_num;
		compile->user_data=user_data;
	}
	else
	{
		if(compile->user_data!=NULL)
		{
			MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
				"Add compile %d failed, compile is already exisited.",
				compile_id);
			ret=-1;
		}
		else
		{
			compile->declared_clause_num=declared_clause_num;
			compile->user_data=user_data;
		}
	}
	pthread_rwlock_unlock(&hier->rwlock);
	return ret;
}
int Maat_hierarchy_compile_remove(struct Maat_hierarchy * hier, int compile_id)
{
	struct Maat_hierarchy_compile* compile=NULL;
	int ret=0;
	
	pthread_rwlock_wrlock(&hier->rwlock);
	HASH_FIND_INT(hier->hash_compile_by_id, &compile_id, compile);
	if(compile)
	{
		if(hier->compile_user_data_free && compile->user_data)
		{
			hier->compile_user_data_free(compile->user_data);
			compile->user_data=NULL;
		}
		if(compile->actual_clause_num==0)
		{
			Maat_hierarchy_compile_free(hier, compile);
		}
		ret=0;
	}
	else
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
				"Remove compile %d failed, compile is not exisited.",
				compile_id);
		ret=-1;

	}
	pthread_rwlock_unlock(&hier->rwlock);
	return ret;
}
static void* Maat_hier_compile_get_user_data(struct Maat_hierarchy* hier, int compile_id, int is_dettach)
{
	struct Maat_hierarchy_compile* compile=NULL;
	void* ret=NULL;
	
	pthread_rwlock_rdlock(&hier->rwlock);
	HASH_FIND_INT(hier->hash_compile_by_id, &compile_id, compile);
	if(compile)
	{
		ret=compile->user_data;
		if(is_dettach)
		{
			compile->user_data=NULL;
		}
	}
	pthread_rwlock_unlock(&hier->rwlock);
	return ret;

}
void* Maat_hierarchy_compile_dettach_user_data(struct Maat_hierarchy* hier, int compile_id)
{
	void* user_data=NULL;
	user_data=Maat_hier_compile_get_user_data(hier, compile_id, 1);
	return user_data;
}
void* Maat_hierarchy_compile_read_user_data(struct Maat_hierarchy* hier, int compile_id)
{
	void* user_data=NULL;
	user_data=Maat_hier_compile_get_user_data(hier, compile_id, 0);
	return user_data;

}
void Maat_hierarchy_compile_user_data_iterate(struct Maat_hierarchy* hier, void (*callback)(void *user_data, void* apram), void* param)
{
	struct Maat_hierarchy_compile* compile=NULL, *tmp_compile=NULL;
	pthread_rwlock_rdlock(&hier->rwlock);
	HASH_ITER(hh, hier->hash_compile_by_id, compile, tmp_compile)
	{
		if(compile->user_data)
		{
			callback(compile->user_data, param);
		}
	}
	pthread_rwlock_unlock(&hier->rwlock);
	return;
}
struct Maat_hierarchy_group* Maat_hierarchy_group_new(struct Maat_hierarchy* hier, int group_id)
{
	struct Maat_hierarchy_group* group=NULL;
	group=ALLOC(struct Maat_hierarchy_group, 1);
	group->group_id=group_id;
	group->vertex_id=hier->grp_vertex_id_generator++;
	assert(igraph_vcount(&hier->group_graph)==group->vertex_id);
	igraph_add_vertices(&hier->group_graph, 1, NULL);	//Add 1 vertice.
	
	HASH_ADD(hh_group_id, hier->hash_group_by_id, group_id, sizeof(group->group_id), group);
	HASH_ADD(hh_vertex_id, hier->hash_group_by_vertex, vertex_id, sizeof(group->vertex_id), group);

	return group;
}
void vector_print(igraph_vector_t *v) {
  long int i;
  for (i=0; i<igraph_vector_size(v); i++) {
    printf(" %li", (long int) VECTOR(*v)[i]);
  }
  printf("\n");
}
static size_t effective_vertices_count(igraph_vector_t *vids)
{
	size_t i=0;
	int tmp_vid=0;
	for(i=0; i<(size_t)igraph_vector_size(vids); i++)
	{
		tmp_vid=(int) VECTOR(*vids)[i];
		if(tmp_vid<0)
		{
			break;
		}
	}
	return i;
}
size_t print_igraph_vector(igraph_vector_t *v, char* buff, size_t sz) {
  long int i;
  int printed=0;
  for (i=0; i<igraph_vector_size(v); i++) {
    printed+=snprintf(buff+printed, sz-printed, " %li", (long int) VECTOR(*v)[i]);
  }
  return printed;
}

static void Maat_hierarchy_group_free(struct Maat_hierarchy* hier, struct Maat_hierarchy_group* group)
{
	igraph_vector_t v; 
	char buff[4096];
	assert(group->ref_by_compile_cnt==0&&group->ref_by_superior_group_cnt==0);
	igraph_vector_init(&v, 8);
	igraph_neighbors(&hier->group_graph, &v, group->vertex_id, IGRAPH_ALL);
	if(igraph_vector_size(&v)>0)
	{
		print_igraph_vector(&v, buff, sizeof(buff));
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
						"Del group %d exception, still reached by %s.",
						group->vertex_id, buff);
		assert(0);
	}
	igraph_vector_destroy(&v);
	assert(group->top_group_ids==NULL);
	//We should not call igraph_delete_vertices, because this is function changes the ids of the vertices.
	//igraph_delete_vertices(&hier->group_graph, igraph_vss_1(group->vertex_id));

	
	HASH_DELETE(hh_group_id, hier->hash_group_by_id, group);
	HASH_DELETE(hh_vertex_id, hier->hash_group_by_vertex, group);

	_group_vertex_free(group);

	return;
}

int Maat_hierarchy_add_group_to_compile(struct Maat_hierarchy* hier, int group_id, int vt_id, int not_flag, int clause_index, int compile_id)
{
	int ret=0;
	struct Maat_hierarchy_group* group=NULL;
	struct Maat_hierarchy_literal_id literal_id={group_id, vt_id};
	struct Maat_hierarchy_compile* compile=NULL;
	
	pthread_rwlock_wrlock(&hier->rwlock);
	HASH_FIND(hh_group_id, hier->hash_group_by_id, &group_id, sizeof(group_id), group);
	if(!group)
	{
		group=Maat_hierarchy_group_new(hier, group_id);
	}

	HASH_FIND(hh, hier->hash_compile_by_id, &compile_id, sizeof(compile_id), compile);
	if(!compile)
	{
		compile=Maat_hierarchy_compile_new(hier, compile_id);
	}
	
	ret=Maat_hierarchy_compile_add_literal(compile, &literal_id, not_flag, clause_index);	
	if(ret<0)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
					"Add group %d vt_id %d to clause %d of compile %d failed, group is already exisited.",
					group_id, vt_id, clause_index, compile_id);
		ret=-1;
	}
	else
	{
		ret=0;
		group->ref_by_compile_cnt++;
	}	
	pthread_rwlock_unlock(&hier->rwlock);
	return ret;
}
int Maat_hierarchy_remove_group_from_compile(struct Maat_hierarchy* hier, int group_id, int vt_id, int not_flag, int clause_index, int compile_id)
{
	struct Maat_hierarchy_group* group=NULL;
	struct Maat_hierarchy_literal_id literal_id={group_id, vt_id};	
	struct Maat_hierarchy_compile* compile=NULL;
	int ret=0;
	
	pthread_rwlock_wrlock(&hier->rwlock);
	HASH_FIND(hh_group_id, hier->hash_group_by_id, &group_id, sizeof(group_id), group);
	if(!group)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
						"Remove group %d from compile %d failed, group is not exisited.",
						group_id, compile_id);
		goto error_out;
	}
	HASH_FIND(hh, hier->hash_compile_by_id, &compile_id, sizeof(compile_id), compile);
	if(!compile)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
						"Remove group %d from compile %d failed, compile is not exisited.",
						group_id, compile_id);
		goto error_out;		
	}

	ret=Maat_hierarchy_compile_remove_literal(compile, &literal_id, clause_index);
	if(ret<0)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
					"Remove group %d vt_id %d from clause %d of compile %d failed, literal is not in compile.",
					group_id, vt_id, clause_index, compile_id);
		goto error_out;
	}
	if(compile->actual_clause_num==0 && !compile->user_data)
	{
		Maat_hierarchy_compile_free(hier, compile);
	}
	pthread_rwlock_unlock(&hier->rwlock);
	return 0;
	
error_out:
	pthread_rwlock_unlock(&hier->rwlock);
	return -1;
}


int Maat_hierarchy_add_group_to_group(struct Maat_hierarchy* hier, int group_id, int superior_group_id)
{
	int ret=0;
	igraph_integer_t edge_id;
	struct Maat_hierarchy_group* group=NULL, *superior_group=NULL;

	pthread_rwlock_wrlock(&hier->rwlock);
	HASH_FIND(hh_group_id, hier->hash_group_by_id, &group_id, sizeof(group_id), group);
	if(!group)
	{
		group=Maat_hierarchy_group_new(hier, group_id);
	}
	
	HASH_FIND(hh_group_id, hier->hash_group_by_id, &superior_group_id, sizeof(superior_group_id), superior_group);
	if(!superior_group)
	{
		superior_group=Maat_hierarchy_group_new(hier, superior_group_id);
	}
	ret=igraph_get_eid(&hier->group_graph, &edge_id, group->vertex_id, superior_group->vertex_id, IGRAPH_DIRECTED, /*error*/ 0);
	if(edge_id>0)//No duplicated edges between two groups.
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
						"Add group %d to group %d failed, relation already exisited.",
						group->group_id, superior_group->group_id);
		ret=-1;
	}
	else
	{
		igraph_add_edge(&hier->group_graph, group->vertex_id, superior_group->vertex_id);
		group->ref_by_superior_group_cnt++;
		superior_group->ref_by_subordinate_group_cnt++;
		ret=0;
	}
	pthread_rwlock_unlock(&hier->rwlock);
	return ret;
}

int Maat_hierarchy_remove_group_from_group(struct Maat_hierarchy* hier, int group_id, int superior_group_id)
{
	int ret=0;
	struct Maat_hierarchy_group* group=NULL, *superior_group=NULL;

	//No hash write operation, LOCK protection is unnecessary.
	
	HASH_FIND(hh_group_id, hier->hash_group_by_id, &group_id, sizeof(group_id), group);
	if(group==NULL)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
						"Del group %d from group %d failed, group %d not exisited.",
						group_id, superior_group_id, group_id);
		return -1;	
	}
	HASH_FIND(hh_group_id, hier->hash_group_by_id, &superior_group_id, sizeof(superior_group_id), superior_group);
	if(superior_group==NULL)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
						"Del group %d from group %d failed, superior group %d not exisited.",
						group_id, superior_group_id, superior_group_id);
		return -1;	
	}
	igraph_es_t es;
	igraph_integer_t edge_num_before=0, edge_num_after=0;

	edge_num_before=igraph_ecount(&hier->group_graph);
	// The edges between the given pairs of vertices will be included in the edge selection.
	//The vertex pairs must be given as the arguments of the function call, the third argument 
	//is the first vertex of the first edge, the fourth argument is the second vertex of the 
	//first edge, the fifth is the first vertex of the second edge and so on. The last element
	//of the argument list must be -1 to denote the end of the argument list.
	//https://igraph.org/c/doc/igraph-Iterators.html#igraph_es_pairs_small
	ret=igraph_es_pairs_small(&es, IGRAPH_DIRECTED, group->vertex_id, superior_group->vertex_id, -1);
	assert(ret==IGRAPH_SUCCESS);
	// ignore no such edge to abort().
	igraph_set_error_handler(igraph_error_handler_ignore);
	ret=igraph_delete_edges(&hier->group_graph, es);
	edge_num_after=igraph_ecount(&hier->group_graph);
	igraph_es_destroy(&es);
	
	if(ret!=IGRAPH_SUCCESS||edge_num_before-edge_num_after!=1)
	{
		assert(0);
		return -1;
	}

	group->ref_by_superior_group_cnt--;
	superior_group->ref_by_subordinate_group_cnt--;
	return 0;

}


int Maat_hierarchy_add_region_to_group(struct Maat_hierarchy* hier, int group_id, int region_id, int table_id, void* user_data)
{
	//A region rule belongs to ONE group only.
	struct Maat_hierarchy_group* group=NULL;
	struct Maat_hierarchy_region* region=NULL;
	int ret=0;
	
	pthread_rwlock_wrlock(&hier->rwlock);
	HASH_FIND(hh_group_id, hier->hash_group_by_id, &group_id, sizeof(group_id), group);
	if(!group)
	{
		group=Maat_hierarchy_group_new(hier, group_id);
	}
	HASH_FIND_INT(hier->hash_region_by_id, &region_id, region);
	if(region)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
							"Add region %d to group %d failed, region already in group %d.", 
							region_id,
							group_id,
							region->ref_parent_group->group_id);
		ret=-1;
	}
	else
	{
		region=Maat_hierarchy_region_new(hier, region_id, group_id, table_id, group, user_data);
		ret=0;
	}
	pthread_rwlock_unlock(&hier->rwlock);
	
	return ret;
}
void* Maat_hierarchy_region_dettach_user_data(struct Maat_hierarchy* hier, int region_id)
{
	struct Maat_hierarchy_region* region=NULL;
	void* ret=NULL;
	pthread_rwlock_wrlock(&hier->rwlock);
	HASH_FIND(hh, hier->hash_region_by_id, &region_id, sizeof(region_id), region);
	if(region)
	{
		ret=region->user_data;
		region->user_data=NULL;
	}
	pthread_rwlock_unlock(&hier->rwlock);
	return ret;
}
int Maat_hierarchy_remove_region_from_group(struct Maat_hierarchy* hier, int group_id, int region_id)
{
	struct Maat_hierarchy_group* group=NULL;
	struct Maat_hierarchy_region* region=NULL;
	pthread_rwlock_wrlock(&hier->rwlock);
	HASH_FIND(hh_group_id, hier->hash_group_by_id, &group_id, sizeof(group_id), group);
	if(!group)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
							"Remove region %d from group %d failed, group is not existed.", 
							region_id,
							group_id);
		goto error_out;
	}
	HASH_FIND(hh, hier->hash_region_by_id, &region_id, sizeof(region_id), region);
	if(!region)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
							"Remove region %d from group %d failed, region is not exisited.", 
							region_id,
							group_id);
		goto error_out;
	}
	
	assert(region->group_id==group->group_id);
	Maat_hierarchy_region_free(hier, region);
	pthread_rwlock_unlock(&hier->rwlock);
	return 0;

error_out:
	pthread_rwlock_unlock(&hier->rwlock);
	return -1;
}
struct clause_entry
{
	long long clause_id;
	const UT_array *literal_ids;//a reference of struct Maat_hierarchy_clause_state->literal_ids
	UT_hash_handle hh;
};
static struct bool_matcher* Maat_hierarchy_build_bool_matcher(struct Maat_hierarchy* hier)
{
	struct bool_matcher* bm=NULL;
	size_t compile_num=0, expr_cnt=0;
	struct bool_expr* bool_expr_array=NULL;
	struct Maat_hierarchy_compile* compile=NULL, *tmp_compile=NULL;
	
	struct Maat_hierarchy_clause_state* clause_state=NULL;
	size_t i=0, j=0;
	int has_clause_num=0;
	compile_num=HASH_COUNT(hier->hash_compile_by_id);	
	size_t all_clause_num=compile_num*MAX_ITEMS_PER_BOOL_EXPR;
	
	if(compile_num==0)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
								"No compile to build.");
		return NULL;
	}

	//STEP 1, create a clause hash by literals it contains
	unsigned long long clause_id_generator=0;
	struct Maat_hierarchy_literal_id* literal_ids=NULL;
	size_t n_literal_id=0;
	struct clause_entry* clause_entry_array=ALLOC(struct clause_entry, all_clause_num);
	struct clause_entry* clause_dedup_hash=NULL, *clause_entry=NULL, *tmp_clause_entry=NULL;
	HASH_ITER(hh, hier->hash_compile_by_id, compile, tmp_compile)
	{
		has_clause_num=0;
		for(i=0; i<MAX_ITEMS_PER_BOOL_EXPR; i++)
		{
			clause_state=compile->clause_states+i;
			clause_state->clause_id=0;
			if(!clause_state->in_use)
			{
				continue;
			}
			has_clause_num++;
			literal_ids=(struct Maat_hierarchy_literal_id*)utarray_eltptr(clause_state->literal_ids, 0);
			n_literal_id=utarray_len(clause_state->literal_ids);
			HASH_FIND(hh, clause_dedup_hash, literal_ids, 
					n_literal_id*sizeof(struct Maat_hierarchy_literal_id), clause_entry);
			if(!clause_entry)
			{
				clause_entry_array[clause_id_generator].clause_id=clause_id_generator;
				clause_entry_array[clause_id_generator].literal_ids=clause_state->literal_ids;
				HASH_ADD_KEYPTR(hh, clause_dedup_hash, literal_ids, 
					n_literal_id*sizeof(struct Maat_hierarchy_literal_id), 
					clause_entry_array+clause_id_generator);
				clause_id_generator++;
			}
		}
		assert(has_clause_num==compile->actual_clause_num);
	}
	
	//STEP 2, update clause_id of each compile and literal
	HASH_ITER(hh, hier->hash_compile_by_id, compile, tmp_compile)
	{
		for(i=0; i<MAX_ITEMS_PER_BOOL_EXPR; i++)
		{
			clause_state=compile->clause_states+i;
			if(!clause_state->in_use)
			{
				continue;
			}
			literal_ids=(struct Maat_hierarchy_literal_id*)utarray_eltptr(clause_state->literal_ids, 0);
			n_literal_id=utarray_len(clause_state->literal_ids);
			HASH_FIND(hh, clause_dedup_hash, literal_ids, 
					n_literal_id*sizeof(struct Maat_hierarchy_literal_id), clause_entry);
			assert(clause_entry);
			clause_state->clause_id=clause_entry->clause_id;
		}
	}
	
	//STEP 3, serial compile clause states to a bool expression array.
	compile_num=HASH_COUNT(hier->hash_compile_by_id);
	bool_expr_array=ALLOC(struct bool_expr, compile_num);
	HASH_ITER(hh, hier->hash_compile_by_id, compile, tmp_compile)
	{
		for(i=0, j=0; i<MAX_ITEMS_PER_BOOL_EXPR; i++)
		{
			if(compile->clause_states[i].in_use)
			{
				if(compile->clause_states[i].not_flag)
				{
					compile->not_clause_cnt++;
				}
				bool_expr_array[expr_cnt].items[j].item_id=compile->clause_states[i].clause_id;
				bool_expr_array[expr_cnt].items[j].not_flag=compile->clause_states[i].not_flag;
				j++;
			}
		}
		//some compile may have zero groups, e.g. default policy.
		if(j==(size_t)compile->declared_clause_num&&j>0)
		{
			bool_expr_array[expr_cnt].user_tag=compile;
			bool_expr_array[expr_cnt].item_num=j;
			expr_cnt++;
		}
	}

	//STEP 4, build the bool matcher.
	size_t mem_size=0;
	if(expr_cnt==0)
	{		
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
								"No bool expression to build.");
		goto error_out;
	}
	bm=bool_matcher_new(bool_expr_array, expr_cnt, hier->thread_num, &mem_size);
	if(bm!=NULL)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_INFO, module_maat_hierarchy,
								"Build bool matcher of %zu expressions and %llu clauses, use %zu bytes memory.",
								expr_cnt,
								HASH_COUNT(clause_dedup_hash),
								mem_size);
	}
	else
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, module_maat_hierarchy,
								"Build bool matcher failed!");
	}

	//STEP 5, release resources
	HASH_ITER(hh, clause_dedup_hash, clause_entry, tmp_clause_entry)
	{
		HASH_DELETE(hh, clause_dedup_hash, clause_entry);
	}
error_out:
	free(clause_entry_array);
	clause_entry_array=NULL;
	
	free(bool_expr_array);
	bool_expr_array=NULL;

	return bm;
}
static int Maat_hierarchy_build_top_groups(struct Maat_hierarchy* hier)
{
	struct Maat_hierarchy_group* group=NULL, *tmp=NULL;
	struct Maat_hierarchy_group* superior_group=NULL;
	int tmp_vid=0;
	size_t i=0, top_group_cnt=0;
	int* temp_group_ids=NULL;
	
	igraph_bool_t is_dag;
	igraph_is_dag(&(hier->group_graph), &is_dag);
	if(!is_dag)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, maat_module,
								"Sub group cycle detected!");
		return -1;
	}
	hier->group_graph_vcount=igraph_vcount(&hier->group_graph);
	igraph_vector_init(&(hier->dfs_vids), hier->group_graph_vcount);
	
	HASH_ITER(hh_group_id, hier->hash_group_by_id, group, tmp)
	{
		top_group_cnt=0;
		temp_group_ids=NULL;
		//Orphan, Not reference by any one, free it.
		if(group->ref_by_compile_cnt==0
			&& group->ref_by_superior_group_cnt==0
			&& group->ref_by_subordinate_group_cnt==0
			&& group->ref_by_region_cnt==0)
		{
		
			pthread_rwlock_wrlock(&hier->rwlock);
			free(group->top_group_ids);
			group->top_group_ids=NULL;
			Maat_hierarchy_group_free(hier, group);
			pthread_rwlock_unlock(&hier->rwlock);
			continue;
		}

		//A group is need to build top groups when it has regions and referenced by superior groups or compiles.
		if(group->ref_by_region_cnt>0 && (group->ref_by_compile_cnt>0 || group->ref_by_superior_group_cnt>0))
		{
			if(group->ref_by_superior_group_cnt==0)
			{
				//fast path, group is only referenced by compile rules.
				top_group_cnt=1;
				temp_group_ids=ALLOC(int, top_group_cnt);
				temp_group_ids[0]=group->group_id;
			}
			else
			{
				igraph_vector_t *vids=&(hier->dfs_vids);
				igraph_dfs(&hier->group_graph, group->vertex_id, IGRAPH_OUT, 
							 0, vids, NULL, NULL, NULL, NULL, NULL, NULL);
				
				temp_group_ids=ALLOC(int, effective_vertices_count(vids));
				
				for(i=0; i<(size_t)igraph_vector_size(vids); i++)
				{
					tmp_vid=(int) VECTOR(*vids)[i];
					if(tmp_vid<0)
					{
						break;
					}
					HASH_FIND(hh_vertex_id, hier->hash_group_by_vertex, &tmp_vid, sizeof(tmp_vid), superior_group);
					if(superior_group->ref_by_compile_cnt>0)//including itself
					{
						temp_group_ids[top_group_cnt]=superior_group->group_id;
						top_group_cnt++;
					}
				}
			}

		}

		pthread_rwlock_wrlock(&hier->rwlock);
		free(group->top_group_ids);
		group->top_group_cnt=top_group_cnt;
		group->top_group_ids=ALLOC(int, group->top_group_cnt);
		memcpy(group->top_group_ids, temp_group_ids, sizeof(int)*group->top_group_cnt);
		pthread_rwlock_unlock(&hier->rwlock);

		free(temp_group_ids);
		temp_group_ids=NULL;
	}	
	igraph_vector_destroy(&hier->dfs_vids);
	return 0;
}
struct Maat_hierarchy_literal* Maat_hierarchy_build_literal_hash(struct Maat_hierarchy* hier)
{
	size_t i=0, j=0;
	struct Maat_hierarchy_compile* compile=NULL, *tmp_compile=NULL;
	struct Maat_hierarchy_literal* literal=NULL;
	struct Maat_hierarchy_literal_id* literal_id=NULL;
	struct Maat_hierarchy_literal* literal_hash=NULL;
	struct Maat_hierarchy_clause_state* clause_state=NULL;
	unsigned long long* tmp_clause_id=NULL;
	
	HASH_ITER(hh, hier->hash_compile_by_id, compile, tmp_compile)
	{
		for(i=0; i<MAX_ITEMS_PER_BOOL_EXPR; i++)
		{
			clause_state=compile->clause_states+i;
			if(!clause_state->in_use)
			{
				continue;
			}
			for(j=0; j<utarray_len(clause_state->literal_ids); j++)
			{
				literal_id=(struct Maat_hierarchy_literal_id*)utarray_eltptr(clause_state->literal_ids, j);
				HASH_FIND(hh, literal_hash, literal_id, sizeof(*literal_id), literal);
				if(!literal)
				{
					literal=Maat_hierarchy_literal_new(&literal_hash, literal_id->group_id, literal_id->virtual_table_id);
				}
				tmp_clause_id=(unsigned long long*)utarray_find(literal->clause_ids, &(clause_state->clause_id), compare_clause_id);
				if(tmp_clause_id)//literal already in this clause.
				{
					continue;
				}
				utarray_push_back(literal->clause_ids, &clause_state->clause_id);
				utarray_sort(literal->clause_ids, compare_clause_id);
			}
		}

	}
	MESA_handle_runtime_log(hier->logger, RLOG_LV_INFO, module_maat_hierarchy,
								"Build literal hash with %llu literals.",
								HASH_COUNT(literal_hash));

	return literal_hash;
}

int Maat_hierarchy_rebuild(struct Maat_hierarchy* hier)
{
	int ret=0;
	struct bool_matcher* new_bm=NULL, *old_bm=NULL;
	struct Maat_hierarchy_literal* new_literal_hash=NULL, *old_literal_hash=NULL;	
	struct Maat_hierarchy_literal* literal=NULL, *tmp_literal=NULL;
	
	new_bm=Maat_hierarchy_build_bool_matcher(hier);
	old_bm=hier->bm;
	
	new_literal_hash=Maat_hierarchy_build_literal_hash(hier);
	old_literal_hash=hier->hash_literal_by_id;

	
	pthread_rwlock_wrlock(&hier->rwlock);
	hier->bm=new_bm;
	hier->hash_literal_by_id=new_literal_hash;
	pthread_rwlock_unlock(&hier->rwlock);
	
	HASH_ITER(hh, old_literal_hash, literal, tmp_literal)
	{
		Maat_hierarchy_literal_free(&old_literal_hash, literal);
	}
	
	bool_matcher_free(old_bm);
	ret=Maat_hierarchy_build_top_groups(hier);
	return ret;
}

TAILQ_HEAD(hit_path_q, Maat_hierarchy_hit_path);

struct Maat_hierarchy_compile_mid
{
	struct Maat_hierarchy* ref_hier;
	int thread_num;
	int Nth_scan;
	size_t this_scan_region_hit_cnt;
	int	not_clause_hitted_flag;
	size_t hit_path_cnt;
	struct hit_path_q hit_path_qhead;
	
	UT_array* _all_hit_clause_array;
};

struct Maat_hierarchy_compile_mid* Maat_hierarchy_compile_mid_new(struct Maat_hierarchy* hier, int thread_num)
{
	struct Maat_hierarchy_compile_mid* mid=ALLOC(struct Maat_hierarchy_compile_mid, 1);
	TAILQ_INIT(&mid->hit_path_qhead);
	mid->thread_num=thread_num;
	mid->ref_hier=hier;	
	utarray_new(mid->_all_hit_clause_array, &ut_clause_id_icd);
	return mid;
}
void Maat_hierarchy_compile_mid_free(struct Maat_hierarchy_compile_mid* mid)
{
	struct Maat_hierarchy_hit_path * tmp = TAILQ_FIRST(&mid->hit_path_qhead);
	while(tmp != NULL)
	{
		TAILQ_REMOVE(&mid->hit_path_qhead, tmp, entries);
		free(tmp);
		mid->hit_path_cnt--;
		tmp = TAILQ_FIRST(&mid->hit_path_qhead);
	}
	assert(mid->hit_path_cnt==0);
	mid->ref_hier=NULL;
	utarray_free(mid->_all_hit_clause_array);
	free(mid);
}
int  Maat_hierarchy_compile_mid_has_NOT_clause(struct Maat_hierarchy_compile_mid* mid)
{
	return mid->not_clause_hitted_flag;
}

void Maat_hit_path_init(struct Maat_hit_path_t* hit_path)
{
	hit_path->Nth_scan=-1;
	hit_path->region_id=-1;
	hit_path->sub_group_id=-1;
	hit_path->top_group_id=-1;
	hit_path->virtual_table_id=-1;
	hit_path->compile_id=-1;
}
static size_t hit_path_select(const struct hit_path_q *hit_path_qhead, struct Maat_hit_path_t* condition, 
															struct Maat_hierarchy_hit_path** hit_paths, size_t n_path)
{

	struct Maat_hierarchy_hit_path* p=NULL;
	size_t i=0;
	TAILQ_FOREACH(p, hit_path_qhead, entries)
	{
		if((condition->compile_id==p->path.compile_id||condition->compile_id<0)
			&& (condition->Nth_scan==p->path.Nth_scan||condition->Nth_scan<0)
			&& (condition->region_id==p->path.region_id||condition->region_id<0)
			&& (condition->sub_group_id==p->path.sub_group_id||condition->sub_group_id<0)
			&& (condition->top_group_id==p->path.top_group_id||condition->top_group_id<0))
		{
			if(i<n_path)
			{
				hit_paths[i]=p;
				i++;
			}
			else if(hit_paths==NULL)//count only
			{
				i++;
			}
		}

	}
	return i;

}


size_t Maat_hierarchy_hit_path_select0(const struct Maat_hierarchy_compile_mid* mid, struct Maat_hit_path_t* condition, 
															struct Maat_hierarchy_hit_path** hit_paths, size_t n_path)
{
	size_t ret=0;
	ret=hit_path_select(&mid->hit_path_qhead, condition, hit_paths, n_path);
	return ret;
}

void Maat_hierarchy_compile_mid_udpate(struct Maat_hierarchy_compile_mid* mid, int region_id, int virtual_table_id, int Nth_scan, int Nth_region_result)
{
	size_t i=0, j=0;
	unsigned long long *clause_id=0;
	struct Maat_hierarchy_hit_path* hit_path=NULL;
	struct Maat_hierarchy_region* region=NULL;
	struct Maat_hierarchy_group* group=NULL;

	struct Maat_hierarchy_literal_id literal_id={0,0};
	struct Maat_hierarchy_literal* literal=NULL;
	
	struct Maat_hierarchy* hier=mid->ref_hier;
	if(mid->Nth_scan!=Nth_scan)
	{
		assert(mid->this_scan_region_hit_cnt==0);
		mid->Nth_scan=Nth_scan;
	}
	mid->this_scan_region_hit_cnt++;
	pthread_rwlock_rdlock(&hier->rwlock);
	HASH_FIND_INT(hier->hash_region_by_id, &region_id, region);
	if(!region)
	{
		pthread_rwlock_unlock(&hier->rwlock);
		return;
	}
	
	group=region->ref_parent_group;
	
	if(group->top_group_cnt==0)
	{
		hit_path=ALLOC(struct Maat_hierarchy_hit_path, 1);
		Maat_hit_path_init(&(hit_path->path));
		hit_path->Nth_hit_region=Nth_region_result;
		hit_path->path.Nth_scan=Nth_scan;
		hit_path->path.region_id=region_id;
		hit_path->path.sub_group_id=group->group_id;
		hit_path->path.virtual_table_id=virtual_table_id;
		TAILQ_INSERT_TAIL(&mid->hit_path_qhead, hit_path, entries);
		mid->hit_path_cnt++;
	}
	else
	{
		for(i=0; i<(size_t)group->top_group_cnt; i++)
		{
			hit_path=ALLOC(struct Maat_hierarchy_hit_path, 1);
			Maat_hit_path_init(&(hit_path->path));
			hit_path->Nth_hit_region=Nth_region_result;
			hit_path->path.Nth_scan=Nth_scan;
			hit_path->path.region_id=region_id;
			hit_path->path.sub_group_id=group->group_id;
			hit_path->path.top_group_id=group->top_group_ids[i];
			hit_path->path.virtual_table_id=virtual_table_id;
			TAILQ_INSERT_TAIL(&mid->hit_path_qhead, hit_path, entries);
			mid->hit_path_cnt++;

			literal_id.virtual_table_id=virtual_table_id;
			literal_id.group_id=group->top_group_ids[i];
			HASH_FIND(hh, hier->hash_literal_by_id, &literal_id, sizeof(literal_id), literal);
			if(!literal)
			{
				continue;
			}
			for(j=0; j<utarray_len(literal->clause_ids); j++)
			{
				clause_id=(unsigned long long*)utarray_eltptr(literal->clause_ids, j);
				if(utarray_find(mid->_all_hit_clause_array, clause_id, compare_clause_id))
				{
					continue;
				}
				utarray_push_back(mid->_all_hit_clause_array, clause_id);
				utarray_sort(mid->_all_hit_clause_array, compare_clause_id);
			}
		}
	}
	pthread_rwlock_unlock(&hier->rwlock);
	return;
}


static size_t Maat_hierarchy_compile_mid_update_by_compile(struct Maat_hierarchy_compile_mid* mid, struct Maat_hierarchy_compile* compile)
{
	size_t r_in_c_cnt=0;
	struct Maat_hierarchy_hit_path* p=NULL, *q=NULL;
	struct Maat_hierarchy_literal_id literal_id={0, 0};
	struct Maat_hit_path_t condition;

	size_t n_exsited_path=0;
	struct hit_path_q new_path_qhead;
	TAILQ_INIT(&new_path_qhead);


	TAILQ_FOREACH(p, &mid->hit_path_qhead, entries)
	{		
		n_exsited_path=0;
		if(p->path.compile_id==compile->compile_id)
		{
			continue;
		}
		literal_id.group_id=p->path.top_group_id;
		literal_id.virtual_table_id=p->path.virtual_table_id;
		if(!Maat_hierarchy_compile_has_literal(compile, &literal_id))
		{
			continue;
		}
		if(p->path.compile_id<0)
		{
			p->path.compile_id=compile->compile_id;
		}
		else //p->path.compile_id!=compile->compile_id, current literal already in a path that has a compile, may be a new path.
		{
			condition=p->path;
			condition.compile_id=compile->compile_id;
			n_exsited_path=hit_path_select(&new_path_qhead, &condition, NULL, 0);
			if(n_exsited_path==0)
			{
				q=ALLOC(struct Maat_hierarchy_hit_path, 1);
				*q=*p;
				q->path.compile_id=compile->compile_id;
				TAILQ_INSERT_TAIL(&new_path_qhead, q, entries);
				mid->hit_path_cnt++;
			}

		}
		
		if(p->path.Nth_scan==mid->Nth_scan && n_exsited_path==0)//Compile was satisfied by new region hits.
		{
			r_in_c_cnt++;
		}
		
	}
	
	p = TAILQ_FIRST(&new_path_qhead);
	while(p != NULL)
	{
		TAILQ_REMOVE(&new_path_qhead, p, entries);
		TAILQ_INSERT_TAIL(&mid->hit_path_qhead, p, entries);
		p = TAILQ_FIRST(&new_path_qhead);
	}
	return r_in_c_cnt;
}


int Maat_hierarchy_region_compile(struct Maat_hierarchy_compile_mid* mid, int is_last_compile, void** user_data_array, size_t ud_array_sz)
{
	int bool_match_ret=0, i=0;
	struct Maat_hierarchy* hier=mid->ref_hier;
	struct Maat_hierarchy_compile* compile_array=NULL;
	void **expr_match=hier->expr_match_buff+mid->thread_num*MAX_SCANNER_HIT_NUM;

	size_t r_in_c_cnt=0, this_scan_region_hits=mid->this_scan_region_hit_cnt;
	size_t ud_result_cnt=0;
	if(!hier->bm)
	{
		mid->this_scan_region_hit_cnt=0;
		return 0;
	}
	pthread_rwlock_rdlock(&hier->rwlock);
	bool_match_ret=bool_matcher_match(hier->bm, mid->thread_num, 
						(unsigned long long*)utarray_eltptr(mid->_all_hit_clause_array, 0), utarray_len(mid->_all_hit_clause_array),
						expr_match, MAX_SCANNER_HIT_NUM);
	for(i=0; i<bool_match_ret && ud_result_cnt<ud_array_sz; i++)
	{
		compile_array=(struct Maat_hierarchy_compile*)expr_match[i];
		r_in_c_cnt=Maat_hierarchy_compile_mid_update_by_compile(mid, compile_array);
		if(compile_array->not_clause_cnt>0 && !is_last_compile)
		{
			mid->not_clause_hitted_flag=1;
		}
		else if(compile_array->user_data)//For compile may be dettached by Maat_hierarchy_compile_dettach_user_data, only return non-NULL userdata.
		{		
			if(r_in_c_cnt>0 ||				//compile hitted becasue of new reigon
				this_scan_region_hits==0)	//or hit a compile that refer a NOT-logic group in previous scan.
			{
				user_data_array[ud_result_cnt]=compile_array->user_data;
				ud_result_cnt++;
			}
		}
	}
	pthread_rwlock_unlock(&hier->rwlock);
	
	mid->this_scan_region_hit_cnt=0;
	return ud_result_cnt;
}

