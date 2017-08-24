#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
#include<assert.h>
#include<MESA/MESA_htable.h>
#include<unistd.h>

#include "gram_index_engine.h"
#include "queue.h"

#define HTABLE_SIZE 128*1024
#define GRAM_CNT_MAX 2
#define GRAM_MAX 128
#define TOLERENCE_SIZE 0
#define UNION_INIT_SIZE 1000
#define BLOCKSIZE_MIN 3
#define MEM_OCCUPY 1
#define CNT_MAX 10
#define GRAM_CNT_THRESHOLD 10
#define QUERY_LEN_ACCURACY 0.1
#define HTABLE_NUM 8
//#define GIE_INPUT_FORMAT_SFH 1
//#define GIE_INPUT_FORMAT_PLAIN 0
#define MAX_LENGTH 10000
#define KEY_MAX_LENGTH 10
#define EDIT_DISTN_INSERT_COST 1
#define EDIT_DISTN_REMOVE_COST 1
#define EDIT_DISTN_REPLACE_COST 2
#define MIN(x,y) ((x)<(y)?(x):(y))

int before(unsigned int off1, unsigned int off2)
{
	return (signed int)(off1-off2)<0;
}
#define after(off2,off1) before(off1,off2)

typedef struct
{
	unsigned int user_gram_value;
	unsigned int user_position_accuracy;
	short ED_reexamine;
	short input_format;
	MESA_htable_handle id_table;
	MESA_htable_handle index_table[HTABLE_NUM];
	unsigned long long mem_occupy;
	unsigned long long hash_cnt;
}GIE_handle_inner_t;


struct linklist_node
{
	short * position;
	struct id_table_data * basicinfo;	
	short size;
	short index;
	unsigned long long blocksize;
	TAILQ_ENTRY(linklist_node) listentry;
};


struct index_table_data
{
	struct TQ * listhead;
	int cnt;
};


struct id_table_data
{
	unsigned int id;
	short sfh_length;
	short gram_cnt;
	unsigned long long blocksize;
	char * sfh;
	void * tag;
	char cfds_lvl;
};


struct htable_handle
{
	MESA_htable_handle runtime_table;
	MESA_htable_handle para;
};

struct key_list_node
{
	char * key;
	int digest_id;
	int pos;
	unsigned long long blocksize;
	TAILQ_ENTRY(key_list_node) keylistentry;
};


unsigned long long hash_cnt;
unsigned long long cnt_sum;

TAILQ_HEAD(TQ, linklist_node);
TAILQ_HEAD(KL, key_list_node);          

void idtable_free(void * data);
void indextable_free(void * data);
int key_compare(const uchar * key1, uint size1, const uchar * key2, uint size2);
int GIE_insert_indextable(MESA_htable_handle handle, struct id_table_data * info, char * key, unsigned int index,unsigned long long blocksize);

int GIE_delete_from_indextable_by_key(MESA_htable_handle handle, char * key, unsigned int id);
int GIE_delete(GIE_handle_inner_t * handle, GIE_digest_t * digest);
int GIE_cmp(const void * a, const void * b);
inline unsigned int get_real_length(const char * string, unsigned int length);
void print_item_iterate(const uchar * key, unsigned int size, void * data, void * user);
inline unsigned long long calc_fh_blocksize(unsigned long long orilen);
inline unsigned long long get_blocksize_from_head(const char * fuzzy_string, unsigned int str_len);

MESA_htable_handle copy_htable(void * htable_para,void (* func)(const uchar * key, uint size, void * data, void *user),void (*free_fuc)(void * data));
void copy_idtable_item_iterate(const uchar * key, uint size, void * data, void * user);
void copy_indextable_item_iterate(const uchar * key, uint size, void * data, void * user);

GIE_handle_t * GIE_create(const GIE_create_para_t * para)
{
	int i = 0;
	GIE_handle_inner_t * handle = (GIE_handle_inner_t *)calloc(1, sizeof(GIE_handle_inner_t));
	handle->mem_occupy = 0;
	handle->mem_occupy += sizeof(GIE_handle_inner_t);
	
	handle->user_gram_value = para->gram_value;
	handle->user_position_accuracy = para->position_accuracy;
	handle->input_format = para->format;
	//handle->user_cmp = GIE_INPUT_FORMAT_PLAIN;
	handle->ED_reexamine = para->ED_reexamine;
	handle->hash_cnt = 0;

	
	MESA_htable_create_args_t idtable_args,indextable_args[HTABLE_NUM];
	memset(&idtable_args, 0, sizeof(idtable_args));
	idtable_args.thread_safe = 0;
	idtable_args.hash_slot_size = HTABLE_SIZE;
	idtable_args.max_elem_num = 0;
	idtable_args.expire_time = 0;
	idtable_args.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	idtable_args.key_comp = NULL;
	idtable_args.key2index = NULL;
	idtable_args.data_free = idtable_free;
	idtable_args.data_expire_with_condition = NULL;
	idtable_args.recursive = 0;
	handle->id_table = MESA_htable_create(&idtable_args, sizeof(idtable_args));

	for(i = 0;i < HTABLE_NUM;i++)
	{
		memset(&indextable_args[i], 0, sizeof(indextable_args[i]));
		indextable_args[i].thread_safe = 0;
		indextable_args[i].hash_slot_size = HTABLE_SIZE;
		indextable_args[i].max_elem_num = 0;
		indextable_args[i].expire_time = 0;
		indextable_args[i].eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
		indextable_args[i].key_comp = key_compare;
		indextable_args[i].key2index = NULL;
		indextable_args[i].data_free = indextable_free;
		indextable_args[i].data_expire_with_condition = NULL;
		indextable_args[i].recursive = 0;
		handle->index_table[i] = MESA_htable_create(&indextable_args[i], sizeof(indextable_args[i]));
	}
    
	return (GIE_handle_t *)(handle);
}

int key_compare(const uchar * key1, uint size1, const uchar * key2, uint size2)
{
	 return ( (*(long*)key1) - (*(long*)key2));
}


void idtable_free(void * data)
{
	struct id_table_data * tmp = (struct id_table_data *)data;
	free(tmp->sfh);
	tmp->sfh = NULL;
	tmp->tag = NULL;
	free(tmp);
	tmp = NULL;
	
	return;
}

void indextable_delete_with_threshold(MESA_htable_handle * htable_handle, struct index_table_data * tmp, char * key)
{
	int key_length = strnlen(key,KEY_MAX_LENGTH);
	struct linklist_node * tmp_node = TAILQ_FIRST(tmp->listhead);
	while(tmp_node != NULL)
	{
		struct linklist_node * linklist_tmp = TAILQ_NEXT(tmp_node,listentry);
		if(tmp_node->basicinfo->gram_cnt <= GRAM_CNT_THRESHOLD)
		{
			tmp_node = linklist_tmp;
			continue;
		}
		TAILQ_REMOVE(tmp->listhead, tmp_node, listentry);
		tmp_node->basicinfo->gram_cnt--;
		tmp->cnt--;
		if(TAILQ_EMPTY(tmp->listhead) == 1)
		{
			//_handle->hash_cnt--;
			//_handle->mem_occupy -= (sizeof(struct index_table_data) + sizeof(struct TQ));
			if(MESA_htable_del(htable_handle, (const uchar *)(key), key_length, indextable_free) < 0)
            {
                printf("indextable backtrack delete error!\n");
                assert(0);
                return;
            }   
		}
		//_handle->mem_occupy -= (sizeof(struct linklist_node) + sizeof(short)*(tmp_node->size));
		free(tmp_node->position);
		tmp_node->position = NULL;
		free(tmp_node);
		tmp_node = NULL;
		tmp_node = linklist_tmp;
		
	}
	return;	
}


void indextable_free(void * data)
{
	struct index_table_data * tmp = (struct index_table_data *)data;
	struct linklist_node * tmp_node = TAILQ_FIRST(tmp->listhead);
	while(tmp_node != NULL)
	{
		struct linklist_node * linklist_tmp = TAILQ_NEXT(tmp_node, listentry);
		TAILQ_REMOVE(tmp->listhead, tmp_node, listentry);
		tmp->cnt--;
		free(tmp_node->position);
		tmp_node->position = NULL;
		free(tmp_node);
		tmp_node = NULL;
		tmp_node = linklist_tmp;
	}
	free(tmp->listhead);
	tmp->listhead = NULL;
	free(tmp);
	tmp = NULL;
	return;
}


void indextable_free_cnt(void * data)
{
	struct index_table_data * tmp = (struct index_table_data *)data;
	hash_cnt++;
	cnt_sum += tmp->cnt;
	struct linklist_node * tmp_node = TAILQ_FIRST(tmp->listhead);
	while(tmp_node != NULL)
	{
		struct linklist_node * linklist_tmp = TAILQ_NEXT(tmp_node, listentry);
		TAILQ_REMOVE(tmp->listhead, tmp_node, listentry);
		tmp->cnt--;
		free(tmp_node->position);
		tmp_node->position = NULL;
		free(tmp_node);
		tmp_node = NULL;
		tmp_node = linklist_tmp;
	}
	free(tmp->listhead);
	tmp->listhead = NULL;
	free(tmp);
	tmp = NULL;
	return;
}

void print_item_iterate_idtable(const uchar * key, uint size, void * data, void * user)
{
	struct id_table_data * id_data = (struct id_table_data *)data;
	printf("id:%u\n",id_data->id);
}



void print_item_iterate(const uchar * key, uint size, void * data, void * user)
{
	struct index_table_data * index_data = (struct index_table_data *)data;
	printf("%s %d\n", (char *)key, index_data->cnt);
    struct linklist_node * tmp_node = NULL;
	int i  = 0;
	TAILQ_FOREACH(tmp_node, index_data->listhead, listentry)
	{
		printf("id = %u\n",tmp_node->basicinfo->id);
		printf("position is :\n");
		for(i = 0;i < tmp_node->index;i++)
		{
			printf("%d    ",tmp_node->position[i]);
		}
		printf("\n");
	}
	printf("\n");
}

int edit_distn(const char *s1, int s1len, const char *s2, int s2len) 
{
  long int max_len = 0;
  if(s1len >= s2len)
  {  
         max_len = s1len;
  }
  else
  {
         max_len = s2len;
  }
  int **t = (int **)malloc(2*sizeof(int *));
  t[0] = (int *)malloc((max_len +1)*sizeof(int));
  t[1] = (int *)malloc((max_len +1)*sizeof(int));
  //int t[2][EDIT_DISTN_MAXLEN+1];
  int *t1 = t[0];
  int *t2 = t[1];
  int *t3;
  size_t i1, i2;
  for (i2 = 0; i2 <= s2len; i2++)
    t[0][i2] = i2 * EDIT_DISTN_REMOVE_COST;
  for (i1 = 0; i1 < s1len; i1++) {
    t2[0] = (i1 + 1) * EDIT_DISTN_INSERT_COST;
    for (i2 = 0; i2 < s2len; i2++) {
      int cost_a = t1[i2+1] + EDIT_DISTN_INSERT_COST;
      int cost_d = t2[i2] + EDIT_DISTN_REMOVE_COST;
      int cost_r = t1[i2] + (s1[i1] == s2[i2] ? 0 : EDIT_DISTN_REPLACE_COST);
      t2[i2+1] = MIN(MIN(cost_a, cost_d), cost_r);
    }
    t3 = t1;
    t1 = t2;
    t2 = t3;
  }
  long int ret = t1[s2len];
  free(t[0]);
  free(t[1]);
  free(t);
  return ret;
  //return t1[s2len];
}


void GIE_destory(GIE_handle_t * handle)
{
	GIE_handle_inner_t * _handle = (GIE_handle_inner_t *)(handle);
	//printf("hash_cnt:%llu\n",_handle->hash_cnt);
	//printf("mem_occupy:%llu\n",_handle->mem_occupy);
	int i = 0;
	for(i = 0;i < HTABLE_NUM;i++)
	{
		MESA_htable_destroy(_handle->index_table[i], indextable_free_cnt);
	}
	MESA_htable_destroy(_handle->id_table, idtable_free);
	//printf("index_free hash_cnt :%llu\n", hash_cnt);
	//printf("cnt sum :%llu\n",cnt_sum);
	free(_handle);
	_handle = NULL;
}


int grab_key_set(char *	str_begin,short str_length,int i,unsigned int gram_value,short * gram_cnt,struct KL** to_process_list, unsigned long long blocksize)
{
	int k = 0,j = 0;
	char * tmp_gram = str_begin;
	char key[gram_value+1];
	int sum = 0,htable_index = 0;
	if(str_length < gram_value)
	{
		return 0;
	}
	str_length = MIN(str_length,strnlen(str_begin,str_length));
	*gram_cnt = str_length - gram_value + 1;	
	//printf("str_length:%d\n",str_length);			
	for(k = 0; k < str_length - gram_value + 1; k++)
	{
		sum = 0;
	 	memset(key,'\0', gram_value+1);
	    memcpy(key, tmp_gram++, gram_value);
		//printf("k:%d key:%s\n",k,key);
		for(j = 0; j < gram_value; j++)
		{
			sum += key[j];
		}	
		htable_index = sum%HTABLE_NUM; 
		struct key_list_node *tmp_node = (struct key_list_node *)calloc(1,sizeof(struct key_list_node));
		tmp_node->key = (char *)calloc(gram_value+1,sizeof(char));
		memcpy(tmp_node->key,key,gram_value);
		tmp_node->digest_id = i;
		tmp_node->pos = k;
		tmp_node->blocksize = blocksize;
		TAILQ_INSERT_TAIL(to_process_list[htable_index], tmp_node, keylistentry);
	}
    return 1;
}
int sfh_grab_key_set(char *sfh,short sfh_length,int i,unsigned int gram_value,short * gram_cnt,struct KL** to_process_list)
{
	int t = 0;
	char * tmp_gram = sfh;
	unsigned long long blocksize = 0;
	for(t = 0; t < 2;t++)
	{
		blocksize = get_blocksize_from_head(tmp_gram, sfh_length);
		while(*tmp_gram != '\0')
		{
			if(*tmp_gram == ':')
			{
				tmp_gram++;
				break;
			}
			tmp_gram++;
		}
		unsigned int real_length = get_real_length(tmp_gram, sfh_length);
		if(real_length < gram_value)
		{		
			if(t==0)
			{
				return 0;
			}
			else
			{
				continue;
			}
		}
		grab_key_set(tmp_gram, real_length, i, gram_value, gram_cnt, to_process_list, blocksize);
		while(*tmp_gram != '\0') 
		{
			 if(*tmp_gram == '#')
             {
                  tmp_gram++;
                  break;
             }
             tmp_gram++;
        }       
	}	
	return 1;
}

void free_key_set(struct KL ** to_process_list,int size)
{
	int i = 0;
	for(i = 0;i < size;i++)
	{
		struct key_list_node *tmp_node = TAILQ_FIRST(to_process_list[i]);
		while(tmp_node != NULL)
		{
			struct key_list_node *key_list_tmp = TAILQ_NEXT(tmp_node, keylistentry);
			TAILQ_REMOVE(to_process_list[i], tmp_node, keylistentry);
			free(tmp_node->key);
			tmp_node->key = NULL;
			free(tmp_node);
			tmp_node = NULL;
			tmp_node = key_list_tmp;
		}
		free(to_process_list[i]);
		to_process_list[i]= NULL;
	}
}

int GIE_update(GIE_handle_t * handle,GIE_digest_t * * digests,int size)
{
	GIE_handle_inner_t * _handle = (GIE_handle_inner_t *)(handle);
	struct id_table_data * info = NULL;
	int success_cnt = 0;
	int m = 0, i = 0, grab_ret = 0;
	short gram_cnt = 0;
	unsigned int input_fh_len = 0;
	unsigned int gram_value = _handle->user_gram_value;
	struct KL* to_process_list[HTABLE_NUM];
	
	MESA_htable_handle htable_index_copy;
	MESA_htable_handle htable_id_copy;
	MESA_htable_handle htable_tmp_index=NULL,htable_tmp_id=NULL;
	struct htable_handle * htable_copied_id_para = (struct htable_handle *)calloc(1,sizeof(struct htable_handle));
	struct htable_handle * htable_copied_index_para = (struct htable_handle *)calloc(1,sizeof(struct htable_handle));

	htable_copied_id_para->runtime_table = _handle->id_table;
	htable_copied_id_para->para = NULL;
	htable_id_copy = copy_htable((void *)htable_copied_id_para, copy_idtable_item_iterate,idtable_free);	

	MESA_htable_handle garbage_htable[HTABLE_NUM];
    /*if(MESA_htable_iterate(htable_id_copy, print_item_iterate_idtable, NULL) == -1)
	{
		printf("iterate error!\n");
	}
	printf("size:%u\n",id_size);*/
	 
	for(m = 0;m < HTABLE_NUM;m++)
	{
		to_process_list[m]=(struct KL*)calloc(1,sizeof(struct KL));
		TAILQ_INIT(to_process_list[m]);
	}

	for(i = 0; i < size; i++)
	{
		switch(digests[i]->operation)
		{
			case GIE_INSERT_OPT:
			{
				assert(digests[i]->tag!=NULL);
				if(_handle->input_format == GIE_INPUT_FORMAT_SFH)
				{
					grab_ret = sfh_grab_key_set(digests[i]->sfh,digests[i]->sfh_length,i,gram_value,&gram_cnt,to_process_list);
				}
				else if(_handle->input_format == GIE_INPUT_FORMAT_PLAIN)
				{
					
					grab_ret = grab_key_set(digests[i]->sfh,digests[i]->sfh_length,i,gram_value,&gram_cnt,to_process_list,0);
				}
				if(grab_ret == 0)
				{
					continue;
				}
				else
				{
					info = (struct id_table_data *)calloc(1,sizeof(struct id_table_data));
					input_fh_len = digests[i]->sfh_length;
					info->sfh = (char *)calloc(input_fh_len + 1,sizeof(char));
					memcpy(info->sfh, digests[i]->sfh, input_fh_len);
					_handle->mem_occupy += sizeof(struct id_table_data) + sizeof(char)*(input_fh_len+1);
					info->sfh_length = digests[i]->sfh_length;
					info->gram_cnt = gram_cnt;

					/*int tag_len = strnlen(digests[i]->tag,MAX_LENGTH);
					info->tag = (char *)calloc(tag_len+1,sizeof(char));
					memcpy(info->tag,digests[i]->tag,tag_len);*/
					info->tag = digests[i]->tag;
					
					info->id = digests[i]->id;
					info->cfds_lvl = digests[i]->cfds_lvl;
					if(_handle->input_format == GIE_INPUT_FORMAT_SFH)
					{
						info->blocksize = get_blocksize_from_head(digests[i]->sfh, digests[i]->sfh_length);
					}
					else if(_handle->input_format == GIE_INPUT_FORMAT_PLAIN)
					{
					    info->blocksize = 0;
					}

					if(MESA_htable_add(htable_id_copy, (const uchar *)(&(digests[i]->id)), sizeof(digests[i]->id), (const void *)info) < 0)
					{
						_handle->mem_occupy -= (sizeof(struct id_table_data) + sizeof(char)*(input_fh_len+1));
						free(info->sfh);
						info->sfh = NULL;
						free(info);
						info = NULL;
						continue;
					}
				}
				success_cnt ++;
				break;
			}

			case GIE_DELETE_OPT:
			{
				
				struct id_table_data * ret = (struct id_table_data *) MESA_htable_search(htable_id_copy, \
		                         (const uchar *)(&(digests[i]->id)), sizeof(digests[i]->id));
				if(ret!= NULL)
				{
					if(_handle->input_format == GIE_INPUT_FORMAT_SFH)
					{
						success_cnt += sfh_grab_key_set(ret->sfh,ret->sfh_length,i,gram_value,&gram_cnt,to_process_list);
					}
					else if(_handle->input_format == GIE_INPUT_FORMAT_PLAIN)
					{
						
						success_cnt += grab_key_set(ret->sfh,ret->sfh_length,i,gram_value,&gram_cnt,to_process_list,0);
					}
				}
				else
				{
					break;
				}
				if(MESA_htable_del(htable_id_copy, (const uchar *)(&(digests[i]->id)), sizeof(digests[i]->id), idtable_free) < 0)
				{
					printf("delete id failed!");
					assert(0);
				}
				//success_cnt += GIE_delete(_handle, digests[i]);
				break;
			}

			default:
				break;
		}
		
	}
	unsigned int digest_id = 0;
	struct id_table_data * tmp_info= NULL;
	
	for(i = 0;i < HTABLE_NUM;i++)
	{	
		htable_copied_index_para->runtime_table = _handle->index_table[i];
		htable_copied_index_para->para = htable_id_copy;
		htable_index_copy = copy_htable((void *)htable_copied_index_para,copy_indextable_item_iterate,indextable_free);
		struct key_list_node * tmp_node;
		TAILQ_FOREACH(tmp_node, to_process_list[i], keylistentry)
		{
			digest_id = tmp_node->digest_id;
			if(digests[digest_id]->operation == GIE_INSERT_OPT)
			{
				tmp_info =(struct id_table_data *)MESA_htable_search(htable_id_copy, (const uchar *)(&(digests[digest_id])->id), \
								sizeof((digests[digest_id])->id));
				if(tmp_info == NULL)
				{
					printf("id %u not insert\n",digests[digest_id]->id);
				}
				if(GIE_insert_indextable(htable_index_copy, tmp_info, tmp_node->key, tmp_node->pos,tmp_node->blocksize) < 0)
				{
					printf("insert %d indextable failed!\n",digests[digest_id]->id); 
					continue;
				} 
			}
			else if(digests[digest_id]->operation == GIE_DELETE_OPT)
			{
				if(GIE_delete_from_indextable_by_key(htable_index_copy, tmp_node->key, (digests[digest_id])->id) < 0)
				{
					printf("delete %d indextable failed!\n",digests[digest_id]->id);
					continue;
				}
			}
		}		
		htable_tmp_index= _handle->index_table[i];
		_handle->index_table[i] = htable_index_copy;
		garbage_htable[i]=htable_tmp_index;
	}

	htable_tmp_id = _handle->id_table;
	_handle->id_table = htable_id_copy;
	usleep(200);     
	MESA_htable_destroy(htable_tmp_id, idtable_free);
    /*if(MESA_htable_iterate(_handle->index_table, print_item_iterate, NULL) == -1)
	{
		printf("iterate error!\n");
	}*/
	for(i=0;i<HTABLE_NUM;i++)
	{
		MESA_htable_destroy(garbage_htable[i], indextable_free_cnt);

	}
	free_key_set(to_process_list,HTABLE_NUM);
	free(htable_copied_id_para);
	htable_copied_id_para = NULL;
	free(htable_copied_index_para);
	htable_copied_index_para = NULL;
    return success_cnt;
}


MESA_htable_handle copy_htable(void * htable_para,void (* func)(const uchar * key, uint size, void * data, void *user),void (*free_fuc)(void * data))
{
	MESA_htable_create_args_t copy_table_args;
	memset(&copy_table_args, 0, sizeof(copy_table_args));
	copy_table_args.thread_safe = 0;
	copy_table_args.hash_slot_size = HTABLE_SIZE;
	copy_table_args.max_elem_num = 0;
	copy_table_args.expire_time = 0;
	copy_table_args.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	copy_table_args.key_comp = NULL;
	copy_table_args.key2index = NULL;
	copy_table_args.data_free = free_fuc;
	copy_table_args.data_expire_with_condition = NULL;
	copy_table_args.recursive = 0;
	MESA_htable_handle copy_htable_handle = MESA_htable_create(&copy_table_args, sizeof(copy_table_args));

	struct htable_handle * htable_copied_para = (struct htable_handle *)htable_para;
	struct htable_handle * htable_iterate_para = (struct htable_handle *)calloc(1,sizeof(struct htable_handle));
	htable_iterate_para->runtime_table = copy_htable_handle;
	htable_iterate_para->para = htable_copied_para->para;
	
	if(MESA_htable_iterate(htable_copied_para->runtime_table, func, htable_iterate_para) == -1)
	{
		printf("iterate error!\n");
	}
	free(htable_iterate_para);
	htable_copied_para=NULL;
	return copy_htable_handle;
}

void copy_indextable_item_iterate(const uchar * key, uint size, void * data, void * user)
{
	struct index_table_data * index_data = (struct index_table_data *)data;
	struct htable_handle * htable_copied_para = (struct htable_handle *)user;

	struct index_table_data * index_data_copy = (struct index_table_data *)calloc(1, sizeof(struct index_table_data));
	struct TQ * head = (struct TQ *)calloc(1, sizeof(struct TQ));
	index_data_copy->listhead = head;
	index_data_copy->cnt = index_data->cnt;

	TAILQ_INIT(head); 	
   	struct linklist_node * tmp_node = NULL;
	struct id_table_data * ret = NULL;
	int i  = 0;
	
	TAILQ_FOREACH(tmp_node, index_data->listhead, listentry)
	{
		struct linklist_node * node_data = (struct linklist_node *)calloc(1,sizeof(struct linklist_node));
		node_data->size = tmp_node->size;
		node_data->position = (short *)calloc(node_data->size, sizeof(short));
		for(i = 0;i < tmp_node->index;i++)
		{
			node_data->position[i] = tmp_node->position[i];
		}
		ret = (struct id_table_data *)MESA_htable_search(htable_copied_para->para, (const uchar *)(&(tmp_node->basicinfo->id)), sizeof(tmp_node->basicinfo->id));
		if(ret == NULL)
		{
			//printf("copy id  %u not exist\n",tmp_node->basicinfo->id);
			free(node_data->position);
			node_data->position = NULL;
			free(node_data);
			node_data = NULL;
			continue;
		}
		node_data->basicinfo = ret;
		node_data->index = tmp_node->index;
		node_data->blocksize = tmp_node->blocksize;
		TAILQ_INSERT_TAIL(head, node_data, listentry);
	}
	MESA_htable_add(htable_copied_para->runtime_table, key, size, (const void *)index_data_copy);
}
//TODO: Using the orginal value instead of make a duplication to be faster.
void copy_idtable_item_iterate(const uchar * key, uint size, void * data, void * user)
{
	struct id_table_data * id_data = (struct id_table_data *)data;
	struct htable_handle * htable_para = (struct htable_handle *)user;
	struct id_table_data * id_data_copy = (struct id_table_data *)calloc(1, sizeof(struct id_table_data));
	assert(id_data->tag!=NULL);
	memcpy(id_data_copy,id_data,sizeof(struct id_table_data));
	id_data_copy->sfh = (char *)calloc(id_data_copy->sfh_length,sizeof(char));
	memcpy(id_data_copy->sfh,id_data->sfh,id_data_copy->sfh_length);
	
	MESA_htable_add(htable_para->runtime_table, (const uchar *)(&(id_data_copy->id)), sizeof(id_data_copy->id), (const void *)id_data_copy);
}
	



int GIE_insert_indextable(MESA_htable_handle htable_copy, struct id_table_data * info, char * key, unsigned int index, unsigned long long blocksize)
{
	int key_length = strnlen(key,KEY_MAX_LENGTH);
	struct linklist_node * node_data = (struct linklist_node *)calloc(1,sizeof(struct linklist_node));
    node_data->size = GRAM_CNT_MAX;
    node_data->position = (short *)calloc(node_data->size, sizeof(short));
	node_data->basicinfo = info;
	node_data->index = 0;
	node_data->position[(node_data->index)++] = index;
	node_data->blocksize = blocksize;

	//_handle->mem_occupy += sizeof(struct linklist_node) + sizeof(short)*(node_data->size);
	
	struct index_table_data * ret = (struct index_table_data *)(MESA_htable_search(htable_copy, \
									(const uchar *)(key), key_length));


	if(ret != NULL)
	{
		struct linklist_node * tmp = NULL;
		TAILQ_FOREACH(tmp, ret->listhead, listentry)
		{
			if(tmp->basicinfo->id > node_data->basicinfo->id)
			{
				TAILQ_INSERT_BEFORE(tmp, node_data, listentry);
				ret->cnt ++;
				if(ret->cnt >= CNT_MAX)
				{	 
					indextable_delete_with_threshold(htable_copy,ret,key);
				}
				return 0;
			}
			if(tmp->basicinfo->id == node_data->basicinfo->id && tmp->blocksize == blocksize)
			{
				if(tmp->index >= tmp->size)
				{
					tmp->size *= 2;
					tmp->position = realloc(tmp->position, (tmp->size)*sizeof(short));
				}
				tmp->position[(tmp->index)++] = index;
				//_handle->mem_occupy -= (sizeof(struct linklist_node) + sizeof(short)*(node_data->size));
				free(node_data->position);
				node_data->position = NULL;
				free(node_data);
				node_data = NULL;
				return 0;
			}
		}	
		TAILQ_INSERT_TAIL(ret->listhead, node_data, listentry);
		ret->cnt ++;	
		if(ret->cnt >= CNT_MAX)
		{ 		
			indextable_delete_with_threshold(htable_copy,ret,key);
		}
	}

	else
	{
		struct index_table_data * index_data = (struct index_table_data *)calloc(1, sizeof(struct index_table_data));
		struct TQ * head = (struct TQ *)calloc(1, sizeof(struct TQ));
		//_handle->mem_occupy += sizeof(struct index_table_data) + sizeof(struct TQ);
		
		index_data->listhead = head;
		index_data->cnt = 0;
		
		TAILQ_INIT(head); 
		TAILQ_INSERT_TAIL(head, node_data, listentry);
		index_data->cnt++;
		//_handle->hash_cnt++;
		if(MESA_htable_add(htable_copy, (const uchar *)(key), key_length, (const void *)index_data) < 0)
		{
			printf("add index_table failed!\n");
			assert(0);
			return -1;
		}
	}
	return 0;
	
}



int GIE_delete(GIE_handle_inner_t * _handle, GIE_digest_t * digest)
{
	int success_cnt = 0;
	struct id_table_data * ret = (struct id_table_data *) MESA_htable_search(_handle->id_table, \
		                         (const uchar *)(&(digest->id)), sizeof(digest->id));
	if(ret == NULL)
	{
		printf("del %d doesn't exist!\n",digest->id);
		return -1;
	}
	else
	{
		int gram_value = _handle->user_gram_value;
		char key[gram_value+1];
		char * tmp_gram = ret->sfh;
		while(*tmp_gram != '\0')
		{
			if(*tmp_gram == ':')
			{
				tmp_gram++;
				break;
			}
			tmp_gram++;
		}
		unsigned int real_length = get_real_length(tmp_gram, ret->sfh_length);
		int gram_cnt = real_length - gram_value + 1;
		int k = 0;
		for(k = 0; k < gram_cnt; k++)
		{
			memset(key, '\0', gram_value+1);
		    memcpy(key, tmp_gram++, gram_value);	
			if(GIE_delete_from_indextable_by_key(_handle, key, digest->id) < 0)
			{
				printf("delete %d indextable failed!\n",digest->id);
				continue;
			}
		}	
		success_cnt++;
	}
	
	return success_cnt;
}



int GIE_delete_from_indextable_by_key(MESA_htable_handle htable, char * key, unsigned int id)
{
	int key_length = strnlen(key,KEY_MAX_LENGTH);
	struct index_table_data * ret = (struct index_table_data *)(MESA_htable_search(htable, \
									(const uchar *)(key), key_length));
	if(ret == NULL)
	{
		return 0;
	}
	

	struct linklist_node * tmp = TAILQ_FIRST(ret->listhead);
	while(tmp != NULL)
	{
		struct linklist_node * linklist_tmp = TAILQ_NEXT(tmp, listentry);
		if(tmp->basicinfo->id != id)
		{
			tmp=linklist_tmp;
			continue;
		}
		TAILQ_REMOVE(ret->listhead, tmp, listentry);
		ret->cnt--;
		//_handle->mem_occupy -= (sizeof(struct linklist_node) + sizeof(short)*(tmp->size));
		free(tmp->position);
		tmp->position = NULL;
		free(tmp);
		tmp = NULL;
		if(TAILQ_EMPTY(ret->listhead) == 1)
		{
			//_handle->mem_occupy -= (sizeof(struct index_table_data) + sizeof(struct TQ));
			int ret = MESA_htable_del(htable, (const uchar *)(key), key_length, indextable_free);
			if(ret < 0)
	    		{
	        		printf("indextable backtrack delete error!\n");
	        		assert(0);
	         		return -1;
	     		}   
			
		}
	}
	return 0;
}




int GIE_cmp(const void * a, const void * b)
{
	unsigned int tmp_a = *(unsigned int *)a;
	unsigned int tmp_b = *(unsigned int *)b;
	if(before(tmp_a, tmp_b))
	{
		return -1;
	}
	else if(after(tmp_a, tmp_b))
	{
		return 1;
	}	
	else
	{
		return 0;
	}
}


inline unsigned int get_real_length(const char * string, unsigned int length)
{
	unsigned int ret = 0;
	const char * tmp_str = string;
	while(*tmp_str != '\0')
	{
		if(*tmp_str == '[')
		{
			break;
		}
		tmp_str++;
		ret ++;
	}
	return ret; 
}


inline int GIE_part_query(GIE_handle_inner_t * _handle, const char * query_string, int index_begin, int part_query_len,unsigned int ** id_union, unsigned int * union_index, unsigned int * union_size, unsigned long long blocksize)
{
	unsigned int gram_value = _handle->user_gram_value;
	
	unsigned int real_length = part_query_len;
	unsigned int chunk_count_max = 0;
	if(real_length < gram_value)
	{
		 return 0;
	}
	else
	{
		 chunk_count_max = real_length/gram_value;
	} 
	char key[gram_value+1];
	struct index_table_data * ret = NULL;
	struct linklist_node * tmp_node_t = NULL;

	unsigned int position_accuracy = _handle->user_position_accuracy;
	
	int i=0,j=0,k=0;
	unsigned int tmp_min = 0;
	int sum = 0, htable_index = 0;
	for(i = index_begin; i < chunk_count_max + index_begin; i++)
	{
		sum = 0;
		memset(key,'\0',gram_value+1);
		memcpy(key, query_string, gram_value);
		for(k = 0; k < gram_value; k++)
		{
			sum += key[k];
		}
		htable_index = sum%HTABLE_NUM;
		ret = (struct index_table_data *) MESA_htable_search(_handle->index_table[htable_index], \
		                         (const uchar *)(key), strnlen(key,gram_value));
		query_string = query_string + gram_value;
		
		if(ret ==NULL)
		{
			break;
		}
		
		tmp_node_t = NULL;
		TAILQ_FOREACH(tmp_node_t, ret->listhead, listentry)
		{
			tmp_min = 0;
			if(i*gram_value >= position_accuracy)
			{
				tmp_min = i*gram_value - position_accuracy;
			}
			for(j = 0; j < tmp_node_t->index; j++)
			{
				if((blocksize == tmp_node_t->basicinfo->blocksize) && (tmp_node_t->position[j] >= tmp_min) && (tmp_node_t->position[j] <= i*gram_value + position_accuracy))
					//if(blocksize == tmp_node_t->basicinfo->blocksize)
				{
					if((*union_index) >=  (*union_size))
					{
						*union_size = (*union_size) * 2;
						*id_union = (unsigned int *)realloc(*id_union, (*union_size)*sizeof(unsigned int));
					}
					(*id_union)[(*union_index)] = tmp_node_t->basicinfo->id;
					(*union_index)++;
					break;
				}
			}
		}
	}
	return chunk_count_max;
}

inline int GIE_gram_with_position(GIE_handle_inner_t * _handle, unsigned long long query_blocksize, const char * fuzzy_string, unsigned int ** id_union, 
									unsigned int * union_index,unsigned int * union_size, unsigned int * chunk_cnt)
{
	const char * tmpstr = fuzzy_string;
	const char * query_string_begin;
	unsigned long long blocksize = query_blocksize;
	int part_query_len = 0;
	int query_actual_len = 0;
	while(*tmpstr != ':'&& *tmpstr != '\0')
	{
		tmpstr ++;
	}
	if(*tmpstr == ':')
	{
		tmpstr ++;
	}
	else
	{
		return 0;
	}
	query_string_begin = tmpstr;
	char *p = NULL;

	while((*query_string_begin) != '\0')
	{
		int left = 0;
		int right = 0;		
		p=strchr(query_string_begin,'[');
		if(p!=NULL)
		{
			part_query_len = p-query_string_begin;
			int ret = sscanf(p,"[%d:%d]",&left,&right);
			if(ret != 2)
			{
				break;
			}
			p=strchr(p,']');
			if(p != NULL && (*p) != '\0')
			{
				int index_begin = (left/blocksize - TOLERENCE_SIZE > 0 ? (left/blocksize - TOLERENCE_SIZE) : 0); 
				(*chunk_cnt) += GIE_part_query(_handle,query_string_begin,index_begin, part_query_len,
												id_union, union_index, union_size, blocksize);
				query_actual_len += part_query_len;
				query_string_begin = p+1;
			}
			else
			{
				break;
			}
		}
		else
		{
			break;
		}
	}
	return query_actual_len;
}

inline unsigned long long calc_fh_blocksize(unsigned long long orilen)
{
	double tmp = orilen/(64 * BLOCKSIZE_MIN);
	double index = floor(log(tmp)/log(2));
	double tmp_t = pow(2,index);
	unsigned long long blocksize = (unsigned long long)(tmp_t * BLOCKSIZE_MIN);
	return blocksize;
}

inline unsigned long long get_blocksize_from_head(const char * fuzzy_string, unsigned int str_len)
{
	const char * tmp_str = fuzzy_string;
	char blk[100];
	memset(blk,'\0',sizeof(blk));
	unsigned long long blocksize = 0;
	int i = 0;
	while(*tmp_str != '\0' && *tmp_str != ':' && str_len != 0 && i < 100)
	{
		blk[i++] = *tmp_str;
		tmp_str++;
		str_len--;
	}
	blocksize = (unsigned long long)atoi(blk);
	return blocksize;
}
int GIE_string_similiarity(const char *str1, int len1, const char *str2, int len2)
{
	int edit_distance=0;
	int conf=0;
	edit_distance = edit_distn(str1, len1,str2,len2);
	conf = 100-(edit_distance*100)/(len1 + len2);
	return conf;
}

int GIE_sfh_similiarity(const char *sfh1, int len1, const char *sfh2, int len2)
{
	int j = 0, t = 0;
	unsigned long long query_blocksize = 0, index_blocksize = 0;
	unsigned int query_real_length = 0, index_real_length = 0;
	const char *query_gram_begin = sfh1;
	const char *index_gram_begin = sfh2;
	char *splice_str = (char *)malloc(sizeof(char)*len1);
	memset(splice_str,'\0',len1);
	char *spli_str_begin = splice_str;
	int edit_distance = 0;
	int ret = 0;
	char *p = NULL;
	int splice_len = 0;
	
	for(j = 0; j < 2; j++)
	{				
		index_blocksize = get_blocksize_from_head(index_gram_begin, len2);
		while((*index_gram_begin) != '\0')
		{
			if((*index_gram_begin) == ':')
			{
				index_gram_begin++;
				break;
			}
			index_gram_begin++;
		}
		index_real_length = get_real_length(index_gram_begin, len2);
		query_gram_begin = sfh1;
		for(t = 0; t < 2; t++)
		{
				query_blocksize = get_blocksize_from_head(query_gram_begin, len1);
				//printf("gram_begin:%c\n",*index_gram_begin);
				//printf("gram_str:%s\n",index_gram_begin);
				while((*query_gram_begin) != '\0')
				{
					if((*query_gram_begin) == ':')
					{
						query_gram_begin++;
						break;
					}
					query_gram_begin++;
				}
				//printf("query_blocksize:%lld, index_blocksize:%lld\n",query_blocksize,index_blocksize);
				//index_real_length = get_real_length(index_gram_begin, len1);
				if(query_blocksize == index_blocksize)
				{
					while((*query_gram_begin) != '#' && (*query_gram_begin) != '\0')
					{		
						p=strchr(query_gram_begin,'[');
						if(p!=NULL)
						{
							query_real_length = p-query_gram_begin;
							p=strchr(p,']');
							if(p != NULL && (*p) != '\0')
							{
								
								memcpy(spli_str_begin,query_gram_begin,query_real_length);
								spli_str_begin += query_real_length;
						    //edit_distance += edit_distn(query_gram_begin, query_real_length, index_gram_begin, index_real_length);
								query_gram_begin = p+1;
							}
							else
							{
								break;
							}
						}
						else
						{
							break;
						}
					}				
					splice_len = strnlen(splice_str,len1);
					edit_distance = edit_distn(index_gram_begin, index_real_length, splice_str, splice_len);
					//printf("query_real_length:%d splice_length:%d edit_distance:%d\n",query_real_length,splice_len,edit_distance);
					ret = 100-(edit_distance*100)/(index_real_length + splice_len);
					//ret = (100*ret)/SPAM_LENGTH;
					//ret = 100-ret;
					//ret = 100 - (100*edit_distance)/(query_real_length);
					free(splice_str);
					return ret;
				}
				while(*query_gram_begin != '\0')
				{
					if(*query_gram_begin == '#')
					{
						query_gram_begin++;
						break;
					}
					query_gram_begin++;
				}				
			
		}
		while(*index_gram_begin != '\0')
		{
			if(*index_gram_begin == '#')
			{
				index_gram_begin++;
				break;
			}
			index_gram_begin++;
		}				
	}
	//printf("no blocksize:query_real_length:%d splice_length:%d edit_distance:%d\n",query_real_length,splice_len,edit_distance);
	free(splice_str);
	return 0;
}




int GIE_query(GIE_handle_t * handle, const char * data, int data_len, GIE_result_t * results, int result_size)
{       
	GIE_handle_inner_t * _handle = (GIE_handle_inner_t *) handle;
	int i = 0, j = 0;
	unsigned int union_index = 0;
	unsigned int gram_value = _handle->user_gram_value;
	unsigned int query_actual_len = 0;
	unsigned int union_size = UNION_INIT_SIZE;
	unsigned int chunk_cnt = 0;
	const char *fuzzy_string_begin = data;
	unsigned int * id_union =(unsigned int *)calloc(union_size, sizeof(unsigned int));
	unsigned long long query_blocksize = 0; 	
	unsigned int fuzzy_string_len = (unsigned int)data_len;
	
	if(_handle->input_format == GIE_INPUT_FORMAT_SFH)
	{
		for(j = 0;j < 2;j++)                                                                                                                          
    	{
        	query_blocksize = get_blocksize_from_head(fuzzy_string_begin, fuzzy_string_len);
         	if(query_blocksize == 0)
         	{
            	 return 0;
         	}
        	query_actual_len += GIE_gram_with_position(_handle, query_blocksize, fuzzy_string_begin, &id_union, &union_index, &union_size, &chunk_cnt);
         	while(*fuzzy_string_begin != '#' && *fuzzy_string_begin != '\0')
         	{
            	fuzzy_string_begin++;
         	}
         	if(*fuzzy_string_begin == '#')
         	{
            	fuzzy_string_begin++;
         	}     
		}
	}
	else if(_handle->input_format == GIE_INPUT_FORMAT_PLAIN)
	{
		query_actual_len = fuzzy_string_len;
		chunk_cnt = GIE_part_query(_handle, fuzzy_string_begin, 0, query_actual_len, &id_union, &union_index, &union_size, 0);
	}
	
	if(union_index == 0)
	{
		free(id_union);
		id_union = NULL;
		return 0;
	}	

	qsort(id_union, union_index, sizeof(id_union[0]), GIE_cmp);

	unsigned int current_id = id_union[0];
	unsigned int * tmp_id = id_union;
	unsigned int count = 0;
	struct id_table_data * ret_tmp = NULL;
	short conf = 0;
	int ret_size = 0;
	for(i = 0; i <= union_index; i++)
	{
		if( i == union_index || *tmp_id != current_id )
		{
			ret_tmp = (struct id_table_data *) MESA_htable_search(_handle->id_table, \
		                         (const uchar *)(&(current_id)), sizeof(current_id));
			
			if(ret_tmp == NULL)
			{
				break;
			}
			char * tmp_gram = ret_tmp->sfh;
			int length = ret_tmp->sfh_length;
			if(ret_tmp->gram_cnt == 0||chunk_cnt == 0)
			{
				conf = 0;
			}
			else
			{
				conf = (count*(query_actual_len-gram_value+1)*10)/(chunk_cnt*(ret_tmp->gram_cnt));
			}
			
			if(_handle->ED_reexamine == 1)
			{
				if(_handle->input_format == GIE_INPUT_FORMAT_SFH)
				{
					conf = GIE_sfh_similiarity(data, fuzzy_string_len, tmp_gram, length);
				}
				else
				{
					conf=GIE_string_similiarity(data, fuzzy_string_len, tmp_gram, length);
				}
			}
			
			if(conf >= ret_tmp->cfds_lvl)
			{
				  results[ret_size].cfds_lvl = conf;
					results[ret_size].id = current_id;
					/*results[ret_size].tag = (char *)malloc((ret_tmp->sfh_length + 1)*sizeof(char));
					memset(results[ret_size].tag,'\0',(ret_tmp->sfh_length+1));
					memcpy(results[ret_size].tag, ret_tmp->sfh,ret_tmp->sfh_length);*/
					results[ret_size].tag = ret_tmp->tag;
					ret_size++;
			}

		  if(ret_size == result_size)
			{
				break;
			}

			current_id = *tmp_id;
			count = 1;
			
		}
		else
		{
			count++;
		}
		
		tmp_id ++;
	}
	
	free(id_union);
	id_union = NULL;
	return ret_size;
}


unsigned long long GIE_status(GIE_handle_t * handle, int type)
{
	unsigned long long length;
	GIE_handle_inner_t * _handle = (GIE_handle_inner_t *)handle;
	switch(type)
	{
		case MEM_OCCUPY:
			length = _handle->mem_occupy;
			break;
		default:
			return 0;
	}
	return length;
}

