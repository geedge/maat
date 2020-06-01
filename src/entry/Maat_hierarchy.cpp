


struct Maat_group_internal
{
	int group_id;

	int ref_by_compile_cnt;
};

struct Maat_CNF_literal
{
	int group_id;
	int virtual_table_id;
};
struct Maat_CNF_clause
{
	int compile_id;
	int Nth_clause;
	char not_flag;
	TAILQ_ENTRY(Maat_CNF_clause) entries;
};
TAILQ_HEAD(Maat_clause_id_q, Maat_CNF_clause);

struct Maat_clause_list
{
	size_t clause_id_count;
	Maat_clause_id_q clause_id_q;
};


struct _CNF_clause
{
	char not_flag;
	char in_use;
	//Following varibles are used when no Nth clause is given, another word, this is forward compatible.
	int vt_id;
	int group_id;
};
struct Maat_CNF
{
	int compile_id;
	int clause_cnt;
	struct _CNF_clause clauses[MAX_ITEMS_PER_BOOL_EXPR];
};
enum MAAT_HIERARCHY_LEVEL
{
	HIERARCHY_LVL_GROUP,
	HIERARCHY_LVL_LITERAL,
	HIERARCHY_LVL_CLAUSE
};
struct Maat_hierarchy_element
{
	int vertex_id;
	enum MAAT_HIERARCHY_LEVEL level;
	union
	{
		struct Maat_group_internal group;
		struct Maat_CNF_literal literal;
		struct Maat_CNF_clause clause;
	};
	int ref_by_superior_cnt;
	int ref_by_subordinate_cnt;
};
struct Maat_hierarchy
{
	igraph_t hierarchy_graph;
	igraph_t cnf_graph;//?
	igraph_integer_t vcount;
	igraph_vector_t dfs_vids;

	int vertex_id_generator;
	int global_clause_id_generator;
	MESA_htable_handle vertex_id2ele;//key:vertex_id, value: struct Maat_hierarchy_element*
	
	MESA_htable_handle grp_and_vt2clause_id_hash;	//key: virtual_table<<32|group_id, value: struct Maat_clause_list*
	struct bool_matcher * bool_matcher_expr_compiler;
	
	MESA_htable_handle cnf_hash;		//key: compile_id, value: struct Maat_CNF *
	MESA_htable_handle clause_hash;		//key: compile_id+Nth_clause, value: global_clause_id
	MESA_htable_handle literal_hash;
	MESA_htable_handle group_hash;		//

};

struct Maat_hierarchy* Maat_hierarchy_new()
{
	struct Maat_hierarchy* hier=ALLOC(struct Maat_hierarchy, 1);
	int ret=0;
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
	hier->cnf_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(hier->cnf_hash, 0);

	hargs.thread_safe=0;
	hargs.data_free = free;
	hier->clause_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(hier->clause_hash, 0);


	hargs.thread_safe=0;
	hargs.data_free = free;
	hier->literal_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(hier->literal_hash, 0);


	hargs.thread_safe=0;
	hargs.data_free = free;
	hier->group_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(hier->group_hash,0);

	hargs.thread_safe=0;
	hargs.data_free = EMPTY_FREE;	//data stored in cnf_hash, group_hash, clause_hash
	hier->vertex_id2ele=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(hier->vertex_id2ele, 0);


	ret=igraph_empty(&hier->hierarchy_graph, 0, IGRAPH_DIRECTED);
	assert(ret==IGRAPH_SUCCESS);
	return hier;
}
void Maat_hierarchy_free(struct Maat_hierarchy* hier)
{

	MESA_htable_destroy(hier->cnf_hash, NULL);
	MESA_htable_destroy(hier->clause_hash, NULL);
	MESA_htable_destroy(hier->literal_hash, NULL);
	MESA_htable_destroy(hier->group_hash, NULL);

	MESA_htable_destroy(hier->vertex_id2ele, NULL);

	igraph_destroy(&hier->hierarchy_graph);
	free(hier);
}

struct Maat_hierarchy_element* Maat_hierarchy_element_new(struct Maat_hierarchy* hier, enum MAAT_HIERARCHY_LEVEL lvl)
{
	int ret=0;
	struct Maat_hierarchy_element* ele=NULL;
	ele=ALLOC(struct Maat_hierarchy_element, 1);
	ele->level=lvl;
	ele->vertex_id=hier->vertex_id_generator++;
	assert(igraph_vcount(&hier->hierarchy_graph)==ele->vertex_id);
	igraph_add_vertices(&hier->hierarchy_graph, 1, NULL);	//Add 1 vertice.
	ret=HASH_add_by_id(hier->vertex_id2ele, ele->vertex_id, ele);
	assert(ret>0);
	return ele;
}
void Maat_hierarchy_element_free(struct Maat_hierarchy_element* ele)
{

}
#define	TO_CLAUSE_ID(Nth_clause, compile_id)	((long long)Nth_clause<<32|compile_id)
static long long get_Nth_clause(struct Maat_CNF* cnf, int group_id, int vt_id, int not_flag)
{
	int i=0, Nth_clause=0;
	if(Nth_clause==0)//compatible
	{
		for(i=0; i<MAX_ITEMS_PER_BOOL_EXPR; i++)
		{
			if(cnf->clauses.group_id==group_id && 
				cnf->clauses.vt_id==vt_id &&
				cnf->clauses.not_flag==not_flag)
			{
				Nth_clause=i+1;
				break;
			}
		}
		if(Nth_clause<1)
		{
			Nth_clause=cnf->clause_cnt;
			cnf->clauses[Nth_clause].group_id=group_id;
			cnf->clauses[Nth_clause].vt_id=vt_id;
			cnf->clause_cnt++;
		}
		assert(cnf->clause_cnt<MAX_ITEMS_PER_BOOL_EXPR);
	}
	return Nth_clause;
}
#define	TO_LITERAL_ID(vt_id, group_id)	((long long)vt_id<<32|group_id)
int Maat_hierarchy_add_compile(struct Maat_hierarchy* hier, int compile_id, int clause_num){}
int Maat_hierarchy_add_group_to_compile(struct Maat_hierarchy* hier, int group_id, int vt_id, int not_flag, int Nth_clause, int compile_id)
{
	int ret=0;
	igraph_integer_t edge_id;
	struct Maat_hierarchy_element* ele_group=NULL, *ele_literal=NULL, *ele_clause=NULL;
	struct Maat_CNF* cnf=NULL;
	cnf=(struct Maat_CNF*)HASH_fetch_by_id(hier->cnf_hash, compile_id);
	if(!cnf)
	{
		cnf=ALLOC(struct Maat_CNF, 1);
		cnf->compile_id=compile_id;
	}
	if(Nth_clause==0)//for compatible
	{
		Nth_clause=get_Nth_clause(cnf, group_id, vt_id, not_flag);
	}
	cnf->clauses[Nth_clause-1].in_use=1;
	cnf->clauses[Nth_clause-1].not_flag=not_flag;
	
	ele_group=(struct Maat_hierarchy_element*)HASH_fetch_by_id(hier->group_hash, group_id);
	if(!ele_group)
	{
		ele_group=Maat_hierarchy_element_new(hier, HIERARCHY_LVL_GROUP);
		ele_group->group.group_id=group_id;
		ret=HASH_add_by_id(hier->group_hash, group_id, ele_group);
		assert(ret>0);
	}
	ele_literal=(struct Maat_hierarchy_element*)MESA_htable_search(hier->literal_hash, TO_LITERAL_ID(vt_id, group_id), sizeof(long long));
	if(!ele_literal)
	{
		ele_literal=Maat_hierarchy_element_new(hier, HIERARCHY_LVL_LITERAL);
		ele_literal->literal.group_id=group_id;
		ele_literal->literal.virtual_table_id=vt_id;
		MESA_htable_add(hier->literal_hash, TO_LITERAL_ID(vt_id, group_id), sizeof(long long), ele_literal);
		ret=igraph_get_eid(&hier->hierarchy_graph, &edge_id, ele_group->vertex_id, ele_literal->vertex_id, IGRAPH_DIRECTED, /*error*/ 0);
		assert(edge_id==0);//For new literal, the edge should not exisited.
		igraph_add_edge(&hier->hierarchy_graph, ele_group->vertex_id, ele_literal->vertex_id);
		ele_group->group.ref_by_compile_cnt++;
		ele_group->ref_by_superior_cnt++;
		ele_literal->ref_by_subordinate_cnt++;
	}
	else
	{
		ret=igraph_get_eid(&hier->hierarchy_graph, &edge_id, ele_group->vertex_id, ele_literal->vertex_id, IGRAPH_DIRECTED, /*error*/ 0);
		assert(edge_id>0);//For existed literal, the edge should exisited.
	}
	ele_clause=(struct Maat_hierarchy_element*)MESA_htable_search(hier->clause_hash, TO_CLAUSE_ID(Nth_clause, compile_id), sizeof(long long));
	if(!ele_clause)
	{
		ele_clause=Maat_hierarchy_element_new(hier, HIERARCHY_LVL_CLAUSE);
		ele_clause->clause.compile_id=compile_id;
		ele_clause->clause.Nth_clause=Nth_clause;
		ele_clause->clause.not_flag=not_flag;
		MESA_htable_add(hier->clause_hash, TO_CLAUSE_ID(Nth_clause, compile_id), sizeof(long long), ele_clause);
	}
	if(ele_clause->clause.not_flag!=not_flag)
	{
		return -1;
	}
	
	ret=igraph_get_eid(&hier->hierarchy_graph, &edge_id, ele_literal->vertex_id, ele_clause->vertex_id, IGRAPH_DIRECTED, /*error*/ 0);
	if(edge_id>0)//The edge was found. Only one edge between a literal and a clause.
	{
		return -1;
	}

	//igraph allow add multiple edges between two vetex, igraph_delete_edges removes one edge per call.
	igraph_add_edge(&hier->hierarchy_graph, ele_literal->vertex_id, ele_clause->vertex_id);
	ele_literal->ref_by_superior_cnt++;
	ele_clause->ref_by_subordinate_cnt++;
	return 0;
}
int Maat_hierarchy_add_group_to_group(struct Maat_hierarchy* hier, int group_id, int superior_group_id)
{
	int ret=0;
	igraph_integer_t edge_id;
	struct Maat_hierarchy_element* ele_group=NULL, *ele_superior_group=NULL;
	ele_group=(struct Maat_hierarchy_element*)HASH_fetch_by_id(hier->group_hash, group_id);
	if(!ele_group)
	{
		ele_group=Maat_hierarchy_element_new(hier, HIERARCHY_LVL_GROUP);
		ele_group->group.group_id=group_id;
		ret=HASH_add_by_id(hier->group_hash, group_id, ele_group);
		assert(ret>0);
	}

	ele_superior_group=(struct Maat_hierarchy_element*)HASH_fetch_by_id(hier->group_hash, superior_group_id);
	if(!ele_superior_group)
	{
		ele_superior_group=Maat_hierarchy_element_new(hier, HIERARCHY_LVL_GROUP);
		ele_superior_group->group.group_id=superior_group_id;
		ret=HASH_add_by_id(hier->group_hash, superior_group_id, ele_superior_group);
		assert(ret>0);
	}
	
	ret=igraph_get_eid(&hier->hierarchy_graph, &edge_id, ele_group->vertex_id, ele_superior_group->vertex_id, IGRAPH_DIRECTED, /*error*/ 0);
	if(edge_id>0)//The edge was found. Only one edge between two groups.
	{
		return -1;
	}
	igraph_add_edge(&hier->hierarchy_graph, ele_group->vertex_id, ele_superior_group->vertex_id);
	ele_group->ref_by_superior_cnt++;
	ele_superior_group->ref_by_subordinate_cnt++;
	return 0;
}
int Maat_hierarchy_add_region(struct Maat_hierarchy* hier, int region_id, int group_id)
{
}
static int hierarchy_graph_reomve_edge(igrahp_t* graph, int from_vertex_id, int to_vertex_id)
{
	igraph_es_t es;
	int ret=0;
	igraph_integer_t edge_num_before=0, edge_num_after=0;

	edge_num_before=igraph_ecount(graph);
	// The edges between the given pairs of vertices will be included in the edge selection.
	//The vertex pairs must be given as the arguments of the function call, the third argument 
	//is the first vertex of the first edge, the fourth argument is the second vertex of the 
	//first edge, the fifth is the first vertex of the second edge and so on. The last element
	//of the argument list must be -1 to denote the end of the argument list.
	//https://igraph.org/c/doc/igraph-Iterators.html#igraph_es_pairs_small
	ret=igraph_es_pairs_small(&es, IGRAPH_DIRECTED, from_vertex_id, to_vertex_id, -1);
	assert(ret==IGRAPH_SUCCESS);
	// ignore no such edge to abort().
	igraph_set_error_handler(igraph_error_handler_ignore);
	ret=igraph_delete_edges(graph, es);
	edge_num_after=igraph_ecount(graph);
	igraph_es_destroy(&es);
	
	if(ret!=IGRAPH_SUCCESS||edge_num_before-edge_num_after!=1)
	{

		return -1;
	}
	else
	{
		return 0;
	}

}
int Maat_hierarchy_remove_group_from_compile(struct Maat_hierarchy* hier, int group_id, int vt_id, int not_flag, int Nth_clause, int compile_id)
{
	int ret=0;
	struct Maat_CNF* cnf=NULL;
	cnf=(struct Maat_CNF*)HASH_fetch_by_id(hier->cnf_hash, compile_id);
	if(!cnf)
	{
		return -2;
	}
	if(Nth_clause==0)
	{
		Nth_clause=get_Nth_clause(cnf, group_id, vt_id,  not_flag);
		cnf->clauses[Nth_clause-1].
	}
	struct Maat_hierarchy_element* ele_group=NULL, *ele_literal=NULL, *ele_clause=NULL;
	ele_group=(struct Maat_hierarchy_element*)HASH_fetch_by_id(hier->group_hash, group_id);
	ele_literal=(struct Maat_hierarchy_element*)MESA_htable_search(hier->literal_hash, TO_LITERAL_ID(vt_id, group_id), sizeof(long long));
	ele_clause=(struct Maat_hierarchy_element*)MESA_htable_search(hier->clause_hash, TO_CLAUSE_ID(Nth_clause, compile_id), sizeof(long long));
	if(!ele_group||!ele_literal||!ele_clause)
	{
		return -1;
	}
	ret=hierarchy_graph_reomve_edge(&hier->hierarchy_graph, ele_group->vertex_id, ele_literal->vertex_id);
	if(ret<0)
	{
		return -1;
	}
	ele_group->group->ref_by_compile_cnt--;
	ele_group->ref_by_subordinate_cnt--;
	ele_literal->ref_by_superior_cnt--;

	ret=hierarchy_graph_reomve_edge(&hier->hierarchy_graph, ele_literal->vertex_id, ele_clause->vertex_id);
	if(ret<0)
	{
		return -1;
	}
	ele_literal->ref_by_superior_cnt--;
	ele_clause->ref_by_subordinate_cnt--;
	return 0;
}
int Maat_hierarchy_remove_group_from_group(struct Maat_hierarchy* hier, int group_id, int superior_group_id)
{
	int ret=0;
	struct Maat_hierarchy_element* ele_group=NULL, *ele_superior_group=NULL;
	ele_group=(struct Maat_hierarchy_element*)HASH_fetch_by_id(hier->group_hash, group_id);
	ele_superior_group=(struct Maat_hierarchy_element*)HASH_fetch_by_id(hier->group_hash, superior_group_id);
	if(!ele_group||!ele_superior_group)
	{
		return -1;
	}
	ret=hierarchy_graph_reomve_edge(&hier->hierarchy_graph, ele_group->vertex_id, ele_superior_group->vertex_id);
	if(ret<0)
	{
		return -1;
	}
	ele_group->ref_by_superior_cnt--;
	ele_superior_group->ref_by_subordinate_cnt--;
	return 0;
}
int Maat_hierarchy_rebuild(struct Maat_hierarchy* hier)
{

}

