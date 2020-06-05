

#define module_maat_hierarchy	"MAAT_HIERARCHY"

struct Maat_CNF_literal
{
	int group_id;
	int virtual_table_id;
};
struct Maat_CNF_clause
{
	int compile_id;
	int Nth_clause;
	long long clause_id;
	char not_flag;
	TAILQ_ENTRY(Maat_CNF_clause) entries;
};
TAILQ_HEAD(Maat_clause_q, Maat_CNF_clause);

struct Maat_clause_list
{
	size_t clause_id_count;
	Maat_clause_q clause_q;
};


struct _CNF_clause
{
	char not_flag;
	char in_use;
	long long clause_id;
	//Following varibles are used when no Nth clause is given, another word, this is forward compatible.
	int vt_id;
	int group_id;
};
struct Maat_CNF
{
	int compile_id;
	int declared_clause_number;
	struct _CNF_clause clauses[MAX_ITEMS_PER_BOOL_EXPR];
	void* user_tag;
};

struct Maat_hierarchy
{
	struct bool_matcher* bm;
	MESA_htable_handle literal2clause_list_hash;		//key: virtual_table<<32|group_id, aka literal_id, value: struct Maat_clause_list*
	MESA_htable_handle cnf_hash;		//key: compile_id, value: struct Maat_CNF *
	MESA_htable_handle group_hash;		//key: group_id, value: struct Maat_group_vertex*
	MESA_htable_handle vertex_id2group_hash;	//key:vetex_id, value: struct Maat_group_vertex* (reference of group hash, do NOT free)
	
	igraph_t group_graph;
	igraph_integer_t group_graph_vcount;
	igraph_vector_t dfs_vids;

	igraph_integer_t grp_vertex_id_generator;

	int thread_num;
	struct Maat_garbage_bin* garbage_bin;
	void* logger;
};

struct Maat_hierarchy* Maat_hierarchy_new(int thread_num, struct Maat_garbage_bin* garbage_bin, void* mesa_handle_logger)
{
	struct Maat_hierarchy* hier=ALLOC(struct Maat_hierarchy, 1);
	int ret=0;
	hier->logger=mesa_handle_logger;
	hier->garbage_bin=garbage_bin;
	hier->thread_num=thread_num;
	
	MESA_htable_create_args_t hargs;
	memset(&hargs,0,sizeof(hargs));
	hargs.thread_safe=0;
	hargs.hash_slot_size = 1024*1024;
	hargs.max_elem_num = 0;
	hargs.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	hargs.expire_time = 0;
	hargs.key_comp = NULL;
	hargs.key2index = NULL;
	hargs.recursive = 0; 
//	hargs.data_free = _void_destroy_compile_rule;
	hargs.data_free = free;

	hargs.data_expire_with_condition = NULL;



	hargs.thread_safe=0;
	hargs.data_free = free;
	hier->literal2clause_list_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(hier->literal2clause_list_hash, 0);

	hargs.thread_safe=0;
	hargs.data_free = free;
	hier->cnf_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(hier->cnf_hash, 0);

	hargs.thread_safe=0;
	hargs.data_free = EMPTY_FREE;
	hier->group_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(hier->group_hash,0);

	hargs.thread_safe=0;
	hargs.data_free = EMPTY_FREE;	//data stored in group_hash, no need free.
	hier->vertex_id2group_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(hier->vertex_id2group_hash, 0);


	ret=igraph_empty(&hier->group_graph, 0, IGRAPH_DIRECTED);
	assert(ret==IGRAPH_SUCCESS);
	return hier;
}
void Maat_hierarchy_free(struct Maat_hierarchy* hier)
{

	MESA_htable_destroy(hier->literal2clause_list_hash, NULL);
	MESA_htable_destroy(hier->cnf_hash, NULL);
	MESA_htable_destroy(hier->group_hash, NULL);
	MESA_htable_destroy(hier->vertex_id2group_hash, NULL);

	igraph_destroy(&hier->group_graph);
	free(hier);
}

#define	TO_CLAUSE_ID(Nth_clause, compile_id)	((long long)Nth_clause<<32|compile_id)
#define	TO_CLAUSE_ID_COMPATBILE(vid, gid)	((unsigned long long)vid<<32|gid)
#define	TO_LITERAL_ID(vt_id, group_id)	((long long)vt_id<<32|group_id)

int Maat_hierarchy_add_compile(struct Maat_hierarchy* hier, int compile_id, int clause_num, void* user)
{
	struct Maat_CNF* cnf=NULL;
	cnf=MESA_htable_search(hier->cnf_hash, &compile_id, sizeof(compile_id));
	if(cnf)//duplicated
	{
		return -1;
	}
	cnf=ALLOC(struct Maat_CNF, 1);
	cnf->compile_id=compile_id;
	cnf->declared_clause_number=clause_num;
	cnf->user_tag=user;
	MESA_htable_add(hier->cnf_hash, &compile_id, sizeof(compile_id), cnf);
	return 0;
}
int Maat_hierarchy_remove_compile(struct Maat_hierarchy * hier, int compile_id)
{
	struct Maat_CNF* cnf=NULL;
	cnf=MESA_htable_search(hier->cnf_hash, &compile_id, sizeof(compile_id));
	if(!cnf)
	{
		return -1;
	}
	cnf=MESA_htable_del(hier->cnf_hash, &compile_id, sizeof(compile_id), NULL);
	return 0;
}
int Maat_hierarchy_add_group_to_compile(struct Maat_hierarchy* hier, int group_id, int vt_id, int not_flag, int Nth_clause, int compile_id)
{
	struct Maat_clause_list* clause_list=NULL;
	struct Maat_CNF_clause* p=NULL;
	struct Maat_group_vertex* group=NULL;
	group=(struct Maat_group_vertex*)MESA_htable_search(hier->group_hash, &group_id, sizeof(group_id));
	if(!group)
	{
		group=Maat_hierarchy_group_vertex_new(hier, group_id);
	}
	group->ref_by_compile_cnt++;
	clause_list=(struct Maat_clause_list*)MESA_htable_search(hier->literal2clause_list_hash, TO_LITERAL_ID(vt_id, group_id), sizeof(long long));
	if(!clause_list)
	{
		clause_list=ALLOC(struct Maat_clause_list, 1);
		TAILQ_INIT(&clause_list->clause_q);
		MESA_htable_add(hier->literal2clause_list_hash, TO_LITERAL_ID(vt_id, group_id), sizeof(long long), clause_list);
	}
	TAILQ_FOREACH(p, &clause_list->clause_q, entries)
	{
		if(p->compile_id==compile_id && p->not_flag==not_flag && p->Nth_clause==Nth_clause)
		{
			return -1; //duplicated
		}
	}
	p=ALLOC(struct Maat_CNF_clause, 1);
	p->compile_id=compile_id;
	p->not_flag=not_flag;
	p->Nth_clause=Nth_clause;
	p->clause_id=TO_CLAUSE_ID(Nth_clause, compile_id);

	TAILQ_INSERT_TAIL(&clause_list->clause_q, p, entries);
	clause_list->clause_id_count++;
	return 0;
}
int Maat_hierarchy_remove_group_from_compile(struct Maat_hierarchy* hier, int group_id, int vt_id, int not_flag, int Nth_clause, int compile_id)
{
	struct Maat_clause_list* clause_list=NULL;
	struct Maat_CNF_clause* p=NULL, *tmp=NULL;
	int found=0;
	clause_list=(struct Maat_clause_list*)MESA_htable_search(hier->literal2clause_list_hash, TO_LITERAL_ID(vt_id, group_id), sizeof(long long));
	if(!clause_list)
	{
		return -1;
	}
	for(p=TAILQ_FIRST(&clause_list->clause_q); p!=NULL; p=tmp)
	{
		tmp=TAILQ_NEXT(p, entries);
		if(p->compile_id==compile_id && p->not_flag==not_flag && p->Nth_clause==Nth_clause)
		{
			TAILQ_REMOVE(clause_list->clause_q, p, entries);
			clause_list->clause_id_count--;
			free(p);
			return 0;
		}

	}
	return -1;
}
struct Maat_group_vertex
{
	igraph_integer_t vertex_id;
	int group_id;
	int ref_by_compile_cnt;
	int ref_by_group_cnt;

	pthread_mutex_t mutex;
	int top_group_cnt;
	int* top_groups;
};
struct Maat_group_vertex* Maat_hierarchy_group_vertex_new(struct Maat_hierarchy* hier, int group_id)
{
	int ret=0;
	struct Maat_group_vertex* group=NULL;
	group=ALLOC(struct Maat_group_vertex, 1);
	group->group_id=group_id;
	group->vertex_id=hier->grp_vertex_id_generator++;
	assert(igraph_vcount(&hier->group_graph)==group->vertex_id);
	igraph_add_vertices(&hier->group_graph, 1, NULL);	//Add 1 vertice.
	pthread_mutex_init(&(group->mutex), NULL);

	ret=MESA_htable_add(hier->vertex_id2group_hash, &group->vertex_id, sizeof(group->vertex_id), group);
	assert(ret>0);
	ret=MESA_htable_add(hier->group_hash, &group_id, sizeof(group_id), group);
	assert(ret>0);
	return group;
}
static void group_vertex_free(struct Maat_group_vertex* group)
{
	free(group->top_groups);
	free(group);
}
void Maat_hierarchy_group_vertex_free(struct Maat_hierarchy* hier, int group_id)
{
	struct Maat_group_vertex* group=NULL, superior_group=NULL;
	group=(struct Maat_group_vertex*)MESA_htable_search(hier->group_graph, &group_id, sizeof(group));
	assert(group!=NULL);
	int ret=0;
	igraph_vector_t v; 
	char buff[4096];
	assert(group->ref_by_compile_cnt==0&&group->ref_by_group_cnt==0);
	igraph_vector_init(&v, 8);
	igraph_neighbors(&hier->group_graph, &v, group->vertex_id, IGRAPH_ALL);
	if(igraph_vector_size(&v)>0)
	{
		print_igraph_vector(&v, buff, sizeof(buff));
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, maat_module,
						"Del group %d exception, still reached by %s.",
						group->vertex_id, buff);
		assert(0);
	}
	igraph_vector_destroy(&v);
	assert(group->top_groups==NULL);
	igraph_delete_vertices(&hier->group_graph, igraph_vss_1(group->vertex_id));

	ret=MESA_htable_del(hier->grp_vertex_id_generator, group->vertex_id, sizeof(group->vertex_id), NULL);
	assert(ret==0);
	ret=MESA_htable_del(hier->group_hash, &group_id, sizeof(group_id), NULL); //group is freed by MESA_htable
	assert(ret==0);
	Maat_garbage_bag(hier->garbage_bin, group, group_vertex_free);
	return;
}

int Maat_hierarchy_add_group_to_group(struct Maat_hierarchy* hier, int group_id, int superior_group_id)
{
	int ret=0;
	igraph_integer_t edge_id;
	struct Maat_group_vertex* group=NULL, superior_group=NULL;
	group=(struct Maat_group_vertex*)MESA_htable_search(hier->group_graph, &group_id, sizeof(group_id));
	if(!group)
	{
		group=Maat_hierarchy_group_vertex_new(hier, group_id);
	}
	superior_group=(struct Maat_group_vertex*)MESA_htable_search(hier->group_graph, &superior_group_id, sizeof(superior_group_id));
	if(!superior_group)
	{
		superior_group=Maat_hierarchy_group_vertex_new(hier, superior_group_id);
	}
	ret=igraph_get_eid(&hier->group_graph, &edge_id, group->vertex_id, superior_group->vertex_id, IGRAPH_DIRECTED, /*error*/ 0);
	if(edge_id>0)//The edge was found. Only one edge between two groups.
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, maat_module,
						"Add group %d to group %d failed, relation already exisited.",
						group->group_id, superior_group->group_id);
		return -1;
	}
	igraph_add_edge(&hier->group_graph, group->vertex_id, superior_group->vertex_id);
	group->ref_by_group_cnt++;
	return 0;
}

int Maat_hierarchy_remove_group_from_group(struct Maat_hierarchy* hier, int group_id, int superior_group_id)
{
	int ret=0;
	igraph_integer_t edge_id;
	struct Maat_group_vertex* group=NULL, superior_group=NULL;
	group=(struct Maat_group_vertex*)MESA_htable_search(hier->group_graph, &group_id, sizeof(group_id));
	if(group==NULL)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, maat_module,
						"Del group %d from group %d failed, group %d not exisited.",
						group_id, superior_group_id, group_id);
		return -1;	
	}
	superior_group=(struct Maat_group_vertex*)MESA_htable_search(hier->group_graph, &superior_group_id, sizeof(superior_group_id));
	if(superior_group==NULL)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_FATAL, maat_module,
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
		assert(0)
		return -1;
	}
	else
	{
		group->ref_by_group_cnt--;
		return 0;
	}
}

static void reset_cnf_hash(const uchar * key, uint size, void * data, void * user)
{
	struct Maat_CNF* cnf=(struct Maat_CNF*)data;
	memset(cnf->clauses, 0, sizeof(cnf->clauses));
	(*(size_t*)user)++;
	return;
}
struct clause_list_walker
{
	size_t n_literal;
	size_t n_clause;
	size_t n_not_flag;
	MESA_htable_handle cnf_hash;
};
static void walk_literal2clause_list_hash(const uchar * key, uint size, void * data, void * user)
{
	struct Maat_clause_list* clause_list=(struct Maat_clause_list*)data;
	struct Maat_CNF_clause* p=NULL;
	struct clause_list_walker* walker=(struct clause_list_walker*)user;
	struct Maat_CNF* cnf=NULL;
	walker->n_literal++;
	TAILQ_FOREACH(p, &clause_list->clause_q, entries)
	{
		cnf=MESA_htable_search(walker->cnf_hash, &p->compile_id, sizeof(p->compile_id));
		if(cnf==NULL)//no compile declared.
		{
			continue;
		}

		if(cnf->clauses[p->Nth_clause].in_use)
		{
			assert(cnf->clauses[p->Nth_clause].clause_id==p->clause_id);
			assert(cnf->clauses[p->Nth_clause].not_flag==p->not_flag);

		}
		else
		{
			walker->n_clause++;
			cnf->clauses[p->Nth_clause].in_use=1;
			cnf->clauses[p->Nth_clause].clause_id=p->clause_id;
			cnf->clauses[p->Nth_clause].not_flag=p->not_flag;
			if(cnf->clauses[p->Nth_clause].not_flag)
			{
				walker->n_not_flag++;
			}
		}
		assert(cnf->compile_id==p->compile_id);
	}	
	return;
}
struct cnf_walker
{
	size_t sz, cnt;
	struct bool_expr* bool_expr_array;

};
static void walk_cnf_hash(const uchar * key, uint size, void * data, void * user)
{
	struct Maat_CNF* cnf=(struct Maat_CNF*)data;
	struct cnf_walker* walker=(struct cnf_walker*)walker;
	struct bool_expr* a_expr=walker->bool_expr_array[walker->cnt];
	int i=0, j=0;
	for(i=0; i<MAX_ITEMS_PER_BOOL_EXPR; i++)
	{
		if(cnf->clauses.in_use)
		{
			a_expr->items[j].item_id=cnf->clauses[i].clause_id;
			a_expr->items[j].not_flag=cnf->clauses[i].not_flag;
			j++;
		}
	}
	if(j==cnf->declared_clause_number)
	{
		a_expr->user_tag=cnf->user_tag;
		a_expr->item_num=j;
		walker->cnt++;
	}
}

static struct bool_matcher*  Maat_CNF_build_bool_matcher(struct Maat_hierarchy* hier)
{	
	struct bool_matcher* bm=NULL;
	struct clause_list_walker clause_walker;
	memset(&clause_walker, 0, sizeof(clause_walker));	
	clause_walker->cnf_hash=hier->cnf_hash;
	size_t n_cnf=0;
	MESA_htable_iterate(hier->cnf_hash, reset_cnf_hash, &n_cnf);
	MESA_htable_iterate(hier->literal2clause_list_hash, walk_literal2clause_list_hash, &clause_walker);
	MESA_handle_runtime_log(hier->logger, RLOG_LV_INFO, module_maat_hierarchy,
								"Maat CNF number: %zu, clause number: %zu (NOT: %zu), literal number: %zu .", 
								n_cnf, clause_walker->n_clause, clause_walker->n_not_flag, clause_walker->n_literal);
	struct cnf_walker cnf_walker;
	cnf_walker.bool_expr_array=ALLOC(struct bool_expr, n_cnf);
	cnf_walker.sz=n_cnf;
	cnf_walker.cnt=0;
	MESA_htable_iterate(hier->cnf_hash, walk_cnf_hash, &cnf_walker);
	
	MESA_handle_runtime_log(hier->logger, RLOG_LV_INFO, module_maat_hierarchy,
								"Valid CNF count: %zu .", cnf_walker.cnt);
	
	size_t mem_size=0;
	bm=bool_matcher_new(cnf_walker.bool_expr_array, cnf_walker.cnt, hier->thread_num, &mem_size);
	if(bm!=NULL)
	{
		MESA_handle_runtime_log(hier->logger, RLOG_LV_INFO, module_maat_hierarchy,
								"Build bool matcher use %zu bytes memory", mem_size);
	}
	else
	{
		MESA_handle_runtime_log(hier->logger,RLOG_LV_FATAL, module_maat_hierarchy,
								"Build bool matcher failed!");
	}
	free(cnf_walker.bool_expr_array);
	cnf_walker.bool_expr_array=NULL;
	return bm;
}

int Maat_hierarchy_add_region(struct Maat_hierarchy* hier, int region_id, int group_id)
{
}
static void _walk_group_hash(const uchar * key, uint size, void * data, void * user)
{
	struct Maat_hierarchy* hier=(struct Maat_hierarchy*)user;
	struct Maat_group_vertex* group=(struct Maat_group_vertex*)data;
	struct Maat_group_vertex* superior_group=NULL;
	int tmp_vid=0;
	size_t i=0, top_group_cnt=0;
	long long* temp_group_ids=NULL;

	if(group->ref_by_compile_cnt==0&&group->ref_by_group_cnt==0)
	{
		free(group->top_groups);
		Maat_hierarchy_group_vertex_free(hier, group->group_id);
	}
	if(group->ref_by_group_cnt==0)
	{
		//fast path, group is only referenced by compile rules.
		top_group_cnt=1;
		temp_group_ids=ALLOC(long long, top_group_cnt);
		temp_group_ids[0]=group->group_id;
	}
	else
	{
		igraph_vector_t *vids=&(hier->dfs_vids);
		igraph_dfs(&hier->group_graph), group->vertex_id, IGRAPH_OUT, 
					 0, vids, NULL, NULL, NULL, NULL, NULL, NULL);
		
		temp_group_ids=ALLOC(long long, effective_vertices_count(vids));
		
		for(i=0; i<(size_t)igraph_vector_size(vids); i++)
		{
			tmp_vid=(int) VECTOR(*vids)[i];
			if(tmp_vid<0)
			{
				break;
			}
			superior_group=(struct Maat_group_vertex*)MESA_htable_search(hier->vertex_id2group_hash, tmp_vid, sizeof(tmp_vid));
			if(superior_group->ref_by_compile_cnt>0)//including itself
			{
				temp_group_ids[top_group_cnt]=superior_group->group_id;
				top_group_cnt++;
			}
		}

	}
	pthread_mutex_lock(&(group->mutex));
	free(group->top_groups);
	group->top_group_cnt=top_group_cnt;
	group->top_groups=ALLOC(long long, group->top_group_cnt);
	memcpy(group->top_groups, temp_group_ids, sizeof(long long)*group->top_group_cnt);
	pthread_mutex_unlock(&(group->mutex));
	free(temp_group_ids);
	temp_group_ids=NULL;
	return;
}

static void Maat_hierarchy_build_top_group(struct Maat_hierarchy* hier)
{
	MESA_htable_iterate(hier->group_hash, _walk_group_hash, &n_cnf);

}
int Maat_hierarchy_rebuild(struct Maat_hierarchy* hier)
{
	struct bool_matcher* bm=NULL;
	bm=Maat_CNF_build_bool_matcher(hier);
	Maat_garbage_bag(hier->garbage_bin, hier->bm, 10, bool_matcher_free);
	hier->bm=bm;
	
		
}

