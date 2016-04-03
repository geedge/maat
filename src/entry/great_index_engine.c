#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
#include<assert.h>
#include<MESA/MESA_htable.h>
#include "great_index_engine.h"
#include "queue.h"
int GIE_VERSION_1_0_20151109=1;
#define HTABLE_SIZE 1024*1024
#define MAX 10000
#define TOLERENCE_SIZE 0
#define CONF_MAX 10
#define BLOCKSIZE_MIN 3
#define MAX_UINT64 (0xFFFFFFFFFFFFFFFF)

typedef struct 
{
	unsigned long long user_precision;
	double user_query_accuracy;
	MESA_htable_handle id_table;
	MESA_htable_handle index_table;
	struct VL * valuelist;
}GIE_handle_inner_t;

struct valuelist_node
{
	unsigned long long value;
	struct VL * valuelist_name;
	TAILQ_ENTRY(valuelist_node) vlistentry;
};

struct linklist_node
{
	unsigned long long index_key;
	struct TQ * listname;
	struct id_table_data * basicinfo;
	TAILQ_ENTRY(linklist_node) listentry;
};

struct index_table_data
{
	struct TQ * listhead;
	int cnt;
	unsigned long long prev_value;
	unsigned long long next_value;
};

struct id_table_data
{
	unsigned int id;
	unsigned long long origin_len;
	unsigned long long blocksize;
	char * fh;
	short cfds_lvl;
	void * tag;
	struct linklist_node * backtrack;
};

TAILQ_HEAD(TQ, linklist_node);
TAILQ_HEAD(VL, valuelist_node);

void idtable_free(void * data);
void indextable_free(void * data);
int GIE_insert_indextable(GIE_handle_inner_t * handle, struct id_table_data * info, unsigned long long index_key);
int GIE_delete_from_indextable_by_key(GIE_handle_inner_t * handle, struct linklist_node * backtrack);
int GIE_delete(GIE_handle_inner_t * handle, GIE_digest_t ** digests, int size);
int GIE_union(struct TQ ** union_list, int list_num, struct id_table_data ** result,\
	unsigned long long min, unsigned long long max, unsigned long long query_blocksize);

struct TQ * linklist_union(struct TQ * list_first, struct TQ * list_second, unsigned long long min, unsigned long long max,\
								unsigned long long query_blocksize);


int minof3(int x, int y, int z);
int GIE_edit_distance(char* w1, int l1, const char* w2, int l2);
int GIE_edit_distance_with_position(char * fh, const char * fuzzy_string, unsigned long long orilen, int * fuzzy_actual_size,\
										unsigned long long * calculate_len);

GIE_handle_t * GIE_create(const GIE_create_para_t * para)
{
	GIE_handle_inner_t * handle = (GIE_handle_inner_t *)malloc(sizeof(GIE_handle_inner_t));
	handle->user_precision = para->index_interval;
	handle->user_query_accuracy = para->query_accuracy;

	struct VL * head = (struct VL *)malloc(sizeof(struct VL));
	TAILQ_INIT(head); 
	handle->valuelist = head;

	
	MESA_htable_create_args_t idtable_args,indextable_args;
	memset(&idtable_args, 0, sizeof(idtable_args));
	memset(&indextable_args, 0, sizeof(indextable_args));

	
	idtable_args.thread_safe = 0;
	idtable_args.hash_slot_size = HTABLE_SIZE;
	idtable_args.max_elem_num = 4 * HTABLE_SIZE;
	idtable_args.expire_time = 0;
	idtable_args.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	idtable_args.key_comp = NULL;
	idtable_args.key2index = NULL;
	idtable_args.data_free = idtable_free;
	idtable_args.data_expire_with_condition = NULL;
	idtable_args.recursive = 1;

	indextable_args.thread_safe = 0;
	indextable_args.hash_slot_size = HTABLE_SIZE;
	indextable_args.max_elem_num = 4 * HTABLE_SIZE;
	indextable_args.expire_time = 0;
	indextable_args.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	indextable_args.key_comp = NULL;
	indextable_args.key2index = NULL;
	indextable_args.data_free = indextable_free;
	indextable_args.data_expire_with_condition = NULL;
	indextable_args.recursive = 1;

    handle->id_table = MESA_htable_create(&idtable_args, sizeof(idtable_args));
    handle->index_table = MESA_htable_create(&indextable_args, sizeof(indextable_args));

	return (GIE_handle_t *)(handle);
}

void idtable_free(void * data)
{
	struct id_table_data * tmp = (struct id_table_data *)data;
	free(tmp->fh);
	free(tmp);
//	printf("free id_table_data!\n");
	return;
}

void indextable_free(void * data)
{
//	printf("free index_table_data!\n");
	struct index_table_data * tmp = (struct index_table_data *)data;
	struct linklist_node * tmp_node = TAILQ_FIRST(tmp->listhead);
	while(tmp_node != NULL)
	{
		struct linklist_node * linklist_tmp = TAILQ_NEXT(tmp_node, listentry);
		free(tmp_node);
//		printf("free list_node_data!\n");
		tmp_node = linklist_tmp;
	}
	free(tmp->listhead);
	free(tmp);
	return;
}

void GIE_destory(GIE_handle_t * handle)
{
	GIE_handle_inner_t * _handle = (GIE_handle_inner_t *)(handle);
	MESA_htable_destroy(_handle->index_table, NULL);
	MESA_htable_destroy(_handle->id_table, NULL);

	struct valuelist_node * tmp_node = TAILQ_FIRST(_handle->valuelist);
	while(tmp_node != NULL)
	{
		struct valuelist_node * valuelist_tmp = TAILQ_NEXT(tmp_node, vlistentry);
		free(tmp_node);
		tmp_node = valuelist_tmp;
	}
	free(_handle->valuelist);
	free(_handle);
}


unsigned long long calc_fh_blocksize(unsigned long long orilen)
{
	double tmp = orilen/(64 * BLOCKSIZE_MIN);
	double index = floor(log(tmp)/log(2));
	double tmp_t = pow(2, index);
	unsigned long long blocksize = (unsigned long long)(tmp_t * BLOCKSIZE_MIN);
	return blocksize;
}

void print_item_iterate(const uchar * key, uint size, void * data, void * user)
{
	struct index_table_data * index_data = (struct index_table_data *)data;
	struct linklist_node * first_node = TAILQ_FIRST(index_data->listhead);
	printf("index_key = %llu\n", first_node->index_key);
	struct linklist_node * tmp_node = NULL;
	TAILQ_FOREACH(tmp_node, index_data->listhead, listentry)
	{
		printf("id = %u  orilen = %llu  ", tmp_node->basicinfo->id, tmp_node->basicinfo->origin_len);
	}
	printf("\n");
}

int GIE_update(GIE_handle_t * handle, GIE_digest_t ** digests, int size)
{
	GIE_handle_inner_t * _handle = (GIE_handle_inner_t *)(handle);
	struct id_table_data * info=NULL;
	int success_cnt=0;
	int i = 0;

	unsigned int input_fh_len=0;

	for(i = 0; i < size; i++)
	{
		switch(digests[i]->operation)
		{
			case GIE_INSERT_OPT:
			{
				unsigned long long first_index_key = (digests[i]->origin_len)/(_handle->user_precision)*(_handle->user_precision);
				info = (struct id_table_data *)malloc(sizeof(struct id_table_data));
				//printf("malloc id_table_data!\n");
				input_fh_len=strlen(digests[i]->fuzzy_hash);
				info->fh = (char *)calloc(sizeof(char),input_fh_len+1);
				memcpy(info->fh, digests[i]->fuzzy_hash, input_fh_len);
				
				info->origin_len = digests[i]->origin_len;
				info->blocksize = calc_fh_blocksize(digests[i]->origin_len);
				info->tag = digests[i]->tag;
				info->id = digests[i]->id;
				info->cfds_lvl = digests[i]->cfds_lvl;

				info->backtrack = NULL;
				if(MESA_htable_add(_handle->id_table, (const uchar *)(&(digests[i]->id)), sizeof(digests[i]->id), (const void *)info) < 0)
				{
					printf("add %d id_table failed!",digests[i]->id);
					free(info->fh);
					free(info);
					continue;
				}				
				if(GIE_insert_indextable(_handle, info, first_index_key) < 0)
				{
					printf("insert %d first failed\n",info->id);
					assert(0);
					free(info->fh);
					free(info);
					continue;
				}
	    		//printf("(info->first_backtrack)->index_key = %llu\n", (info->first_backtrack)->index_key);
				success_cnt++;
				break;
			}
			case GIE_DELETE_OPT:
			{
				success_cnt += GIE_delete(_handle, digests, i);
				break;
			}
			default:
				break;
		}
	/*struct valuelist_node * tmp = NULL;
	TAILQ_FOREACH(tmp, _handle->valuelist, vlistentry)
	{
		struct index_table_data * tmp_t = (struct index_table_data *)(MESA_htable_search_cb(_handle->index_table, (const uchar *)(&(tmp->value)), sizeof(tmp->value), NULL, NULL, NULL));
		printf("prev_value = %llu    ", tmp_t->prev_value);
		printf("next_value = %llu    ", tmp_t->next_value);
		printf("value = %llu\n", tmp->value);
	}*/
	}
	return success_cnt;
}


int GIE_insert_indextable(GIE_handle_inner_t * handle, struct id_table_data * info, unsigned long long index_key)
{		
	struct linklist_node * node_data = (struct linklist_node *)malloc(sizeof(struct linklist_node));
    //printf("linklist_node malloc success\n");
	node_data->basicinfo = info;
	node_data->index_key = index_key;
	node_data->listname = NULL;

	info->backtrack = node_data;  //Backtracking pointer to index table, it is a pointer to a structure pointer
	//printf("1: (info->first_backtrack)->index_key = %llu\n", (info->first_backtrack)->index_key);
	
	struct index_table_data * ret = (struct index_table_data *)(MESA_htable_search_cb(handle->index_table, (const uchar *)(&index_key), sizeof(index_key), NULL, NULL, NULL));
	if(ret != NULL)
	{
	    //printf("ret != NULL\n");
		struct linklist_node * tmp = NULL;
		node_data->listname = ret->listhead;		
		//If there are linked list exists in index table, sorted according to id
		TAILQ_FOREACH(tmp, ret->listhead, listentry)               
		{
			if(tmp->basicinfo->id > node_data->basicinfo->id) 
			{
				TAILQ_INSERT_BEFORE(tmp, node_data, listentry);
				ret->cnt++;
				return 0;
			}
			if(node_data->basicinfo->id == tmp->basicinfo->id)
			{
				printf("invalid insert!");
				return -1;
			}
				//TODO 如果id是以前插入过的id，就要返回invalid insert
		}
		TAILQ_INSERT_TAIL(ret->listhead, node_data, listentry);
		ret->cnt ++;
	}
	else
	{
		struct index_table_data * index_data = (struct index_table_data *)malloc(sizeof(struct index_table_data));

		struct valuelist_node * tmp_t = NULL;
		struct valuelist_node * value_data = (struct valuelist_node *)malloc(sizeof(struct valuelist_node));
		value_data->value = index_key;
		value_data->valuelist_name = handle->valuelist;
		
		int insert_flag = 0;	
		TAILQ_FOREACH(tmp_t, handle->valuelist, vlistentry)
		{
			if(tmp_t->value > value_data->value)
			{
				TAILQ_INSERT_BEFORE(tmp_t, value_data, vlistentry);
				insert_flag = 1;
				break;
			}
		}
	  	if(!insert_flag)
		{
			TAILQ_INSERT_TAIL(handle->valuelist, value_data, vlistentry);
		}	

		struct valuelist_node * tmp_prev = TAILQ_PREV(value_data, VL, vlistentry);
		struct valuelist_node * tmp_next = TAILQ_NEXT(value_data, vlistentry);

		if(tmp_prev != NULL && tmp_next != NULL)
		{
			struct index_table_data * index_tmp_prev = MESA_htable_search(handle->index_table, (const uchar *)(&(tmp_prev->value)),\
																			sizeof(tmp_prev->value));
			
			struct index_table_data * index_tmp_next = MESA_htable_search(handle->index_table, (const uchar *)(&(tmp_next->value)),\
																			sizeof(tmp_next->value));
			index_tmp_prev->next_value = value_data->value;
			index_data->prev_value = tmp_prev->value;
			index_data->next_value = tmp_next->value;
			index_tmp_next->prev_value = value_data->value;
		}
		if(tmp_prev != NULL && tmp_next == NULL)
		{
			
			struct index_table_data * index_tmp_prev = MESA_htable_search(handle->index_table, (const uchar *)(&(tmp_prev->value)),\
																			sizeof(tmp_prev->value));
			
			index_tmp_prev->next_value = value_data->value;
			index_data->prev_value = tmp_prev->value;
			index_data->next_value = MAX_UINT64;
		}
		if(tmp_prev == NULL && tmp_next != NULL)
		{
			
			struct index_table_data * index_tmp_next = MESA_htable_search(handle->index_table, (const uchar *)(&(tmp_next->value)),\
																			sizeof(tmp_next->value));

			index_data->prev_value = MAX_UINT64;
			index_data->next_value = tmp_next->value;
			index_tmp_next->prev_value = value_data->value;
		}
		if(tmp_prev == NULL && tmp_next == NULL)
		{
			index_data->prev_value = MAX_UINT64;
			index_data->next_value = MAX_UINT64;
		}


		//If there are no entries， have to create a list head pointer, 
		  //and add the corresponding entry in the index table, the data link to the back
		
		struct TQ * head = (struct TQ *)malloc(sizeof(struct TQ));
		index_data->listhead = head;
		index_data->cnt = 0;
		
		TAILQ_INIT(head); 
		TAILQ_INSERT_TAIL(head, node_data, listentry);
		index_data->cnt++;
		node_data->listname = index_data->listhead;
		
		if(MESA_htable_add(handle->index_table, (const uchar *)(&index_key), sizeof(index_key), (const void *)index_data) < 0)
		{
			printf("add index_table failed!\n");
			assert(0);
			return -1;
		}
		
	//	struct index_table_data * tmp_v = (struct index_table_data *)(MESA_htable_search_cb(handle->index_table, (const uchar *)(&index_key), sizeof(index_key), NULL, NULL, NULL));
	//	printf("index_data->prev_value = %llu    ", index_data->prev_value);
	//	printf("index_data->next_value = %llu    ", index_data->next_value);
	//	printf("index_key = %llu     ", index_key);
	//	printf("prev_value = %llu    ", tmp_v->prev_value);
	//	printf("next_value = %llu\n", tmp_v->next_value);
		
	}
	return 0;
}
		


int GIE_delete_from_indextable_by_key(GIE_handle_inner_t * handle, struct linklist_node * backtrack)
{
		struct linklist_node * backtrack_node = backtrack;  //Find the index table in the first meet of the list node pointer by backtracking

		//find the key
		unsigned long long tmp_key = backtrack_node->index_key;
		
		//delete the node
		TAILQ_REMOVE(backtrack_node->listname, backtrack, listentry);
		
		//if first node is NULL, linklist is NULL, delete the record in the hashtable
		if(TAILQ_EMPTY(backtrack_node->listname) == 1)
		{
			if(MESA_htable_del(handle->index_table, (const uchar *)(&tmp_key), sizeof(tmp_key), indextable_free) < 0)
			{
				printf("indextable backtrack delete error!\n");
				assert(0);
				return -1;
			}
			else
			{
				struct valuelist_node * tmp = NULL;
				TAILQ_FOREACH(tmp, handle->valuelist, vlistentry)
				{
					if(tmp->value == backtrack_node->index_key)
					{
						break;
					}
				}
				struct valuelist_node * tmp_prev = TAILQ_PREV(tmp, VL, vlistentry);
				struct valuelist_node * tmp_next = TAILQ_NEXT(tmp, vlistentry);
				if(tmp_prev != NULL && tmp_next != NULL)
				{
					struct index_table_data * index_tmp_prev = MESA_htable_search_cb(handle->index_table, (const uchar *)(&(tmp_prev->value)), \
						                                                             sizeof(tmp_prev->value), NULL, NULL, NULL);
					struct index_table_data * index_tmp_next = MESA_htable_search_cb(handle->index_table, (const uchar *)(&(tmp_next->value)), \
						                                                             sizeof(tmp_next->value), NULL, NULL, NULL);
					index_tmp_prev->next_value = tmp_next->value;
					index_tmp_next->prev_value = tmp_prev->value;
				}
				if(tmp_prev != NULL && tmp_next == NULL)
				{
					struct index_table_data * index_tmp_prev = MESA_htable_search_cb(handle->index_table, (const uchar *)(&(tmp_prev->value)), \
						                                                             sizeof(tmp_prev->value), NULL, NULL, NULL);
					index_tmp_prev->next_value = MAX_UINT64;
				}
				if(tmp_prev == NULL && tmp_next != NULL)  
				{
					struct index_table_data * index_tmp_next = MESA_htable_search_cb(handle->index_table, (const uchar *)(&(tmp_next->value)), \
						                                                             sizeof(tmp_next->value), NULL, NULL, NULL);
					index_tmp_next->prev_value = MAX_UINT64;
				}
				TAILQ_REMOVE(handle->valuelist, tmp, vlistentry);
				free(tmp);
				//printf("indextable backtrack delete success!\n");
			}
		}
		free(backtrack_node);
		return 0;
	
}


int GIE_delete(GIE_handle_inner_t * handle, GIE_digest_t ** digests, int i)
{
	int success_cnt=0;
	struct id_table_data * ret = (struct id_table_data *) MESA_htable_search(handle->id_table, \
		                         (const uchar *)(&(digests[i]->id)), sizeof(digests[i]->id));
		
	//if the record doesn't exist, printf delID doesn't exist!
	//printf("ret->id = %u\n", ret->id);
	//printf("(ret->first_backtrack)->index_key = %llu\n", (ret->first_backtrack)->index_key);
	if(ret == NULL)
	{
		printf("del %d doesn't exist!\n",digests[i]->id);
	}
	else
	{
		GIE_delete_from_indextable_by_key(handle, ret->backtrack);
		success_cnt++;
	}
	if(MESA_htable_del(handle->id_table, (const uchar *)(&(digests[i]->id)), sizeof(digests[i]->id), idtable_free) < 0)
	{
		printf("delete id failed!");
		assert(0);
	}
	return success_cnt;
}



int GIE_union(struct TQ ** union_list, int list_num, struct id_table_data ** result,\
	unsigned long long min, unsigned long long max, unsigned long long query_blocksize)
{
	struct TQ * tmp_list = (struct TQ *)malloc(sizeof(struct TQ));
	TAILQ_INIT(tmp_list);
	struct linklist_node * tmp_node = NULL;
	int size = 0;
	TAILQ_FOREACH(tmp_node, union_list[0], listentry)
	{
		if(tmp_node->basicinfo->origin_len >= min && tmp_node->basicinfo->origin_len <= max && tmp_node->basicinfo->blocksize == query_blocksize)
		{
			struct linklist_node * new_node = (struct linklist_node *)malloc(sizeof(struct linklist_node));
			new_node->index_key = tmp_node->index_key;
			new_node->basicinfo = tmp_node->basicinfo;
			new_node->listname = tmp_list;
			TAILQ_INSERT_TAIL(tmp_list, new_node, listentry);
		}		
	}
	int i = 0;
	for(i = 1; i < list_num; i++)
	{
		tmp_list = linklist_union(tmp_list, union_list[i], min, max, query_blocksize);
	}

	struct linklist_node * tmp_node_t = NULL;
	TAILQ_FOREACH(tmp_node_t, tmp_list, listentry)
	{
		result[size++] = tmp_node_t->basicinfo;
	}

	struct linklist_node * first_node = TAILQ_FIRST(tmp_list); 
	while(first_node != NULL)
	{
		struct linklist_node * linklist_tmp = TAILQ_NEXT(first_node, listentry);
		free(first_node);
		first_node = linklist_tmp;
	}
	free(tmp_list);
	return size;
}




struct TQ * linklist_union(struct TQ * list_first, struct TQ * list_second, unsigned long long min, unsigned long long max,\
								unsigned long long query_blocksize)
{
	struct TQ * link_result = (struct TQ *)malloc(sizeof(struct TQ));
	TAILQ_INIT(link_result);
	struct linklist_node * tmp_first = TAILQ_FIRST(list_first);
	struct linklist_node * tmp_second = TAILQ_FIRST(list_second);
	while(tmp_first != NULL && tmp_second != NULL)
	{
		//When combined final result in a relatively small deposit on id, id small pointer will move backward, 
		// if both are equal, both pointers move backward until a move to the tail end of the list
		if(tmp_first->basicinfo->id < tmp_second->basicinfo->id)
		{
			if(tmp_first->basicinfo->origin_len >= min && tmp_first->basicinfo->origin_len <= max && tmp_first->basicinfo->blocksize == query_blocksize)
			{
				struct linklist_node * new_node = (struct linklist_node *)malloc(sizeof(struct linklist_node));
				new_node->index_key = tmp_first->index_key;
				new_node->basicinfo = tmp_first->basicinfo;
				new_node->listname = link_result;
				TAILQ_INSERT_TAIL(link_result, new_node, listentry);

			}
			tmp_first = TAILQ_NEXT(tmp_first, listentry);   
	    }
		else if(tmp_first->basicinfo->id > tmp_second->basicinfo->id)
		{
			if(tmp_second->basicinfo->origin_len >= min && tmp_second->basicinfo->origin_len <= max && tmp_second->basicinfo->blocksize == query_blocksize)
			{
				struct linklist_node * new_node = (struct linklist_node *)malloc(sizeof(struct linklist_node));
				new_node->index_key = tmp_second->index_key;
				new_node->basicinfo = tmp_second->basicinfo;
				new_node->listname = link_result;
				TAILQ_INSERT_TAIL(link_result, new_node, listentry);
			}
			tmp_second = TAILQ_NEXT(tmp_second, listentry);
		}
		
		/*else
		{	
			if(tmp_first->basicinfo->origin_len >= min && tmp_first->basicinfo->origin_len <= max && tmp_first->basicinfo->blocksize == query_blocksize)
			{
				struct linklist_node * new_node = (struct linklist_node *)malloc(sizeof(struct linklist_node));
				new_node->index_key = tmp_first->index_key;
				new_node->basicinfo = tmp_first->basicinfo;
				new_node->listname = link_result;
				TAILQ_INSERT_TAIL(link_result, new_node, listentry);
			}
			tmp_first = TAILQ_NEXT(tmp_first, listentry);
			tmp_second = TAILQ_NEXT(tmp_second, listentry);
		}*/
		
	}

	//The list is not linked to the end nodes remaining deposit to results
	while(tmp_first != NULL)
	{
		if(tmp_first->basicinfo->origin_len >= min && tmp_first->basicinfo->origin_len <= max && tmp_first->basicinfo->blocksize == query_blocksize)
		{
			struct linklist_node * new_node = (struct linklist_node *)malloc(sizeof(struct linklist_node));
			new_node->index_key = tmp_first->index_key;
			new_node->basicinfo = tmp_first->basicinfo;
			new_node->listname = link_result;
			TAILQ_INSERT_TAIL(link_result, new_node, listentry);
		}
		tmp_first = TAILQ_NEXT(tmp_first, listentry);
	}
	while(tmp_second != NULL)
	{
		if(tmp_second->basicinfo->origin_len >= min && tmp_second->basicinfo->origin_len <= max && tmp_second->basicinfo->blocksize == query_blocksize)
		{
			struct linklist_node * new_node = (struct linklist_node *)malloc(sizeof(struct linklist_node));
			new_node->index_key = tmp_second->index_key;
			new_node->basicinfo = tmp_second->basicinfo;
			new_node->listname = link_result;
			TAILQ_INSERT_TAIL(link_result, new_node, listentry);
		}
		tmp_second = TAILQ_NEXT(tmp_second, listentry);
	}

	
	struct linklist_node * first_node = TAILQ_FIRST(list_first);
	while(first_node != NULL)
	{
		struct linklist_node * linklist_tmp = TAILQ_NEXT(first_node, listentry);
		free(first_node);
		first_node = linklist_tmp;
	}
	free(list_first);


	return link_result;	
}


int minof3(int x, int y, int z)
{
  x = (x<y)?x:y;
  return (x<z)?x:z;
}


int GIE_edit_distance(char* w1, int l1, const char* w2, int l2) 
{
  	// dp[x][y] means the min edit distance from partial word1 (0..x-1) to partial word2 (0..y-1)
  	// please note this takes O(mn) space; O(n) solution also available because only last iteration of result needs to be stored
	int i, j;
	int ** dp = (int **)malloc(sizeof(int *) * (l1 + 1));
	for(i = 0; i < l1 + 1; i++)
	{
		dp[i] = (int *)malloc(sizeof(int) * (l2 + 1));
	}	

  	// init the dynamic programming matrix
  	dp[0][0] = 0;
  	for(i = 1; i<=l1; i++) dp[i][0] = i;
  	for(j = 1; j<=l2; j++) dp[0][j] = j;

  	for(i = 1; i<=l1; i++)
    	for(j = 1; j<=l2; j++)
      		if(w1[i-1] != w2[j-1])
        		//different char; so adding/replacing/deleting all takes one more step
        		dp[i][j] = minof3(dp[i][j-1], dp[i-1][j-1], dp[i-1][j]) + 1;
     		 else
        		//same char; so no need to replace it; adding/deleting one still takes one more step
        		dp[i][j] = minof3(dp[i][j-1]+1, dp[i-1][j-1], dp[i-1][j]+1);	
	int result = dp[l1][l2];
	for(i = 0; i < l1 + 1; i++)
	{
		free(dp[i]);
	}
	free(dp);
  	return result; 
}


int GIE_edit_distance_with_position(char * fh, const char * fuzzy_string, unsigned long long orilen, int * fuzzy_actual_size, unsigned long long * calculate_len)
{
    *fuzzy_actual_size = 0;
	*calculate_len = 0;
	int edit_distance = 0;
	const char * tmpstr = fuzzy_string;
	const char * tmp_fuzzy = fuzzy_string;
	char * fh_tmp = fh;
	int tmp_fuzzy_len = 0;
	int fh_actual_len = 0;
    unsigned long long blocksize = 0;
	while(*fh_tmp != '\0')
	{
		if(*fh_tmp == '[')
		{
			break;
		}
		fh_actual_len ++;
		fh_tmp++;		
	}
	//*fuzzy_all_actual_size = fh_actual_len;
	if(fh_actual_len != 0)
	{
		blocksize = (orilen - 1)/fh_actual_len;
	}
	else
	{
		blocksize = calc_fh_blocksize(orilen);
	}
	while(*tmpstr != '\0')
	{

		int left = 0;
		int right = 0;
		if(*tmpstr == '[')
		{
			char numleft[100],numright[100];
			int i = 0 , j = 0;
			tmpstr ++;
			memset(numleft, '\0', sizeof(numleft));
			memset(numright, '\0', sizeof(numright));
			while(*tmpstr != '\0' && *tmpstr != ':')
			{
				numleft[i++] = *tmpstr;
				tmpstr ++;
			}
			//printf("i = %d\n", i);
			left = atoi(numleft);
			tmpstr++;
			while(*tmpstr != '\0' && *tmpstr !=']')
			{
				numright[j++] = *tmpstr;
				tmpstr ++;
			}
		    //printf("j = %d\n", j);
			right = atoi(numright);
			*calculate_len += right - left;
			
			//TODO: edit distance compare
			int index = left/blocksize - TOLERENCE_SIZE > 0 ? left/blocksize - TOLERENCE_SIZE: 0;
			int fh_size = right/blocksize + TOLERENCE_SIZE - index > fh_actual_len - index ? fh_actual_len - index: right/blocksize + TOLERENCE_SIZE - index; 
			if(tmp_fuzzy_len != 0)
			{
				edit_distance += GIE_edit_distance(fh + index, fh_size, tmp_fuzzy, tmp_fuzzy_len);
			}
			*fuzzy_actual_size += tmp_fuzzy_len;

			if(*tmpstr == ']')
			{
				tmp_fuzzy = tmpstr + 1;
				tmp_fuzzy_len = 0;
			}
			tmpstr ++;
		}
		else
		{
		    tmp_fuzzy_len++;
			tmpstr ++;
		}
	}
	return edit_distance;
}


int GIE_query(GIE_handle_t * handle, unsigned long long origin_len,	const char * fuzzy_string, GIE_result_t * results, int size)
{
	GIE_handle_inner_t * _handle = (GIE_handle_inner_t *)handle;

	//find min_index
	double min_tmp = (double)(origin_len * (1 - _handle->user_query_accuracy));
	unsigned long long min_tmp_t = (unsigned long long )(floor(min_tmp));
	unsigned long long min_index = min_tmp_t/(_handle->user_precision)*(_handle->user_precision);

	//find max_index
	double max_tmp = (double)(origin_len * (1 + _handle->user_query_accuracy));
	unsigned long long max_tmp_t = (unsigned long long)(floor(max_tmp));
	unsigned long long max_index = max_tmp_t/(_handle->user_precision)*(_handle->user_precision); 
	
	unsigned long long tmp_size = (max_index - min_index)/(_handle->user_precision) + 1;
	struct TQ * union_list[tmp_size];
	
	unsigned long long i = min_index;
	unsigned long long query_blocksize = calc_fh_blocksize(origin_len);
	int list_num = 0;
	int union_size = 0;
	int union_size_max = 0;
	int ret_size = 0;

	//find 
	while(i <= max_index)
	{
		struct index_table_data * list_tmp = (struct index_table_data *)MESA_htable_search_cb(_handle->index_table, (const uchar * )(&i), \
		                                                 sizeof(i), NULL, NULL, NULL);
		if(list_tmp != NULL)
		{
			union_list[list_num++] = list_tmp->listhead;
			i = list_tmp->next_value;
			union_size_max += list_tmp->cnt;
		}
		else
		{
			i = i + _handle->user_precision;
		}

	}

	struct id_table_data ** result_union = (struct id_table_data **)malloc(sizeof(struct id_table_data *)*union_size_max);

	if(list_num != 0)
	{
		union_size = GIE_union(union_list, list_num, result_union, min_tmp_t, max_tmp_t, query_blocksize);
		//printf("union_size = %d\n", union_size);
	}
	else
	{
		printf("the fh doesn't exsit!\n");
		free(result_union);
		return 0;
	}

	for(i = 0; i < union_size; i++)
	{	
	    int fuzzy_actual_len;
		unsigned long long calculate_len;
	   	if(result_union[i]->id == 8885)
		{
			printf("right\n");
		}
		int edit_distance = GIE_edit_distance_with_position(result_union[i]->fh, fuzzy_string, origin_len, &fuzzy_actual_len, &calculate_len);
		//printf("fuzzy_actual_len = %d\n", fuzzy_actual_len);
		short conf_tmp;
		if(fuzzy_actual_len != 0 && edit_distance < fuzzy_actual_len)
		{
			//conf_tmp = CONF_MAX - (fuzzy_all_actual_len - (fuzzy_actual_len - edit_distance))*CONF_MAX/fuzzy_all_actual_len;
			conf_tmp = (fuzzy_actual_len - edit_distance)*(calculate_len + 1)*CONF_MAX/(fuzzy_actual_len * origin_len);
			//conf_tmp = CONF_MAX - edit_distance*CONF_MAX/fuzzy_actual_len;
		}
		else
		{
			conf_tmp = 0;
		}
		if(conf_tmp >= result_union[i]->cfds_lvl)
		{
			results[ret_size].cfds_lvl = conf_tmp;
			results[ret_size].id = result_union[i]->id;
			results[ret_size].origin_len = result_union[i]->origin_len;
			results[ret_size++].tag = result_union[i]->tag;
		}
		if(ret_size == size)
		{
			break;
		}
		
	}

	free(result_union);
	return ret_size;
} 
