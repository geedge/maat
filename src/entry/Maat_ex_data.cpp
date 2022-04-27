#include "Maat_ex_data.h"
#include "Maat_table.h"
#include "Maat_utils.h"
#include "Maat_garbage_collection.h"

#include "uthash/uthash.h"
#include "uthash/utarray.h"

#include <MESA/MESA_handle_logger.h>
#include <assert.h>


struct EX_data_container
{
	void* ex_data;
	char* key;
	size_t key_len;
	void* user_data;

	UT_hash_handle hh_a, hh_b;
	const struct EX_data_rt* rt;
	
};

struct EX_data_rt
{
	UT_array *cache_rows;
	size_t cache_row_num;
	size_t cache_size;

	pthread_mutex_t mutex_update_commit;
	int is_updating;
	char effective_hash;//value 'a' or 'b', indicates which hash is effective
	struct EX_data_container* hash_key2ex_a, *hash_key2ex_b; //two hash for read-copy-update (RCU)

	const struct EX_data_schema* ex_schema;
	int table_id;
	void (* user_data_free)(void *user_data);	
	struct Maat_garbage_bin* garbage_bin;
};


void EX_data_container_free(struct EX_data_container* ex_container)
{
	const struct EX_data_schema* ex_schema=ex_container->rt->ex_schema;
	ex_schema->free_func(ex_container->rt->table_id, &(ex_container->ex_data), ex_schema->argl, ex_schema->argp);
	if(ex_container->user_data && ex_container->rt->user_data_free)
	{
		ex_container->rt->user_data_free(ex_container->user_data);
	}
	free(ex_container->key);
	ex_container->key=NULL;
	ex_container->key_len=0;
	ex_container->user_data=NULL;	
	ex_container->rt=NULL;
	free(ex_container);
	return;
}
void cache_row_free(void*p)
{
	free(*(char**)p);
}
UT_icd ut_cache_row_icd = {sizeof(char*), NULL, NULL, cache_row_free};

struct EX_data_rt* EX_data_rt_new(int table_id, Maat_plugin_EX_key2index_func_t * key2index, void (* user_data_free)(void *user_data))
{
	struct EX_data_rt* p=ALLOC(struct EX_data_rt, 1);
	p->hash_key2ex_a=NULL;
	p->hash_key2ex_b=NULL;
	p->effective_hash='a';
	utarray_new(p->cache_rows, &ut_cache_row_icd);
	p->table_id=table_id;
	p->user_data_free=user_data_free;
	p->garbage_bin=Maat_garbage_bin_new(60);
	pthread_mutex_init(&p->mutex_update_commit, NULL);
	return p;
};
size_t EX_data_rt_get_cached_row_num(struct EX_data_rt* ex_rt)
{
	return ex_rt->cache_row_num;
}
void EX_data_rt_set_schema(struct EX_data_rt* p, const struct EX_data_schema* schema)
{
	p->ex_schema=schema;
}
void EX_data_rt_free(struct EX_data_rt* ex_rt)
{
	struct EX_data_container* ex_container=NULL, *tmp=NULL;

	assert(ex_rt->is_updating==0);
	if(ex_rt->effective_hash=='a')
	{
		HASH_ITER(hh_a, ex_rt->hash_key2ex_a, ex_container, tmp)
		{
			HASH_DELETE(hh_a, ex_rt->hash_key2ex_a, ex_container);
			EX_data_container_free(ex_container);
		}
	}
	else
	{
		HASH_ITER(hh_b, ex_rt->hash_key2ex_b, ex_container, tmp)
		{
			HASH_DELETE(hh_b, ex_rt->hash_key2ex_b, ex_container);
			EX_data_container_free(ex_container);
		}
		
	}
	//ex_rt->hash_key2ex's memory is freed when its last element was deleted.
	
	if(ex_rt->cache_rows)
	{
		utarray_free(ex_rt->cache_rows);
		ex_rt->cache_rows=NULL;
		ex_rt->cache_row_num=0;
	}
	Maat_garbage_bin_free(ex_rt->garbage_bin);
	ex_rt->garbage_bin=NULL;
	free(ex_rt);
	return;
}
void EX_data_rt_cache_row_put(struct EX_data_rt* p, const char* row)
{
	size_t len=strlen(row)+1;
	char* row_copy=ALLOC(char, len);
	memcpy(row_copy, row, len);
	p->cache_size+=len;
	utarray_push_back(p->cache_rows, &row_copy);
	p->cache_row_num++;	
	return;
}
const char* EX_data_rt_cached_row_get(struct EX_data_rt* p, size_t index)
{
	const char** row=NULL;
	row=(const char**)utarray_eltptr(p->cache_rows, index);
	return *row;
}
void EX_data_rt_clear_row_cache(struct EX_data_rt* p)
{
	utarray_free(p->cache_rows);
	p->cache_rows=NULL;
	p->cache_row_num=0;
	p->cache_size=0;
}
void EX_data_rt_update_prepare(struct EX_data_rt* ex_rt)
{
	struct EX_data_container* ex_container=NULL, *tmp=NULL;
	if(ex_rt->effective_hash=='a')
	{
		assert(ex_rt->hash_key2ex_b==NULL);
		HASH_ITER(hh_a, ex_rt->hash_key2ex_a, ex_container, tmp)
		{
			HASH_ADD_KEYPTR(hh_b, ex_rt->hash_key2ex_b, ex_container->key, ex_container->key_len, ex_container);
		}
	}
	else
	{
		assert(ex_rt->hash_key2ex_a==NULL);
		HASH_ITER(hh_b, ex_rt->hash_key2ex_b, ex_container, tmp)
		{
			HASH_ADD_KEYPTR(hh_a, ex_rt->hash_key2ex_a, ex_container->key, ex_container->key_len, ex_container);
		}
	}
	assert(0==Maat_garbage_bin_get_size(ex_rt->garbage_bin));
	ex_rt->is_updating=1;
	return;
}

void EX_data_rt_update_commit(struct EX_data_rt* ex_rt)
{	
	struct EX_data_container* ex_container=NULL, *tmp=NULL;
	//lock contention of Maat_plugin_EX_register and rule update thread.
	pthread_mutex_lock(&ex_rt->mutex_update_commit);
	if(!ex_rt->is_updating)
	{
		pthread_mutex_unlock(&ex_rt->mutex_update_commit);
		return;
	}
	if(ex_rt->effective_hash=='a')
	{
		ex_rt->effective_hash='b';
		usleep(100); //urgly sleep, wait for EX_data_rt_get_EX_data_by_key to release the effective hash table.
		HASH_ITER(hh_a, ex_rt->hash_key2ex_a, ex_container, tmp)
		{
			HASH_DELETE(hh_a, ex_rt->hash_key2ex_a, ex_container);
			//ex_container is no need to free, it's either in new hash table or garbage collection queue.
		}
	}
	else
	{
		ex_rt->effective_hash='a';
		usleep(100);
		HASH_ITER(hh_b, ex_rt->hash_key2ex_b, ex_container, tmp)
		{
			HASH_DELETE(hh_b, ex_rt->hash_key2ex_b, ex_container);
		}
	}	
	ex_rt->is_updating=0;
	Maat_garbage_collect_by_force(ex_rt->garbage_bin);
	pthread_mutex_unlock(&ex_rt->mutex_update_commit);
	return;
}

struct EX_data_container* EX_data_rt_effective_hash_find(struct EX_data_rt* ex_rt, const char* key, size_t key_len)
{
	struct EX_data_container* exc=NULL;

	if(ex_rt->effective_hash=='a')
	{
		HASH_FIND(hh_a, ex_rt->hash_key2ex_a, key, key_len, exc);
	}
	else
	{
		assert(ex_rt->effective_hash=='b');
		HASH_FIND(hh_b, ex_rt->hash_key2ex_b, key, key_len, exc);
	}
	return exc;
}

struct EX_data_container* EX_data_rt_updating_hash_find(struct EX_data_rt* ex_rt, const char* key, size_t key_len)
{
	struct EX_data_container* exc=NULL;

	if(ex_rt->effective_hash=='a')
	{
		HASH_FIND(hh_b, ex_rt->hash_key2ex_b, key, key_len, exc);
	}
	else
	{
		assert(ex_rt->effective_hash=='b');
		HASH_FIND(hh_a, ex_rt->hash_key2ex_a, key, key_len, exc);
	}
	return exc;
}
void EX_data_rt_updating_hash_add(struct EX_data_rt* ex_rt, const char* key, size_t key_len, struct EX_data_container* exc)
{
	if(ex_rt->effective_hash=='a')
	{
		HASH_ADD_KEYPTR(hh_b, ex_rt->hash_key2ex_b, key,key_len, exc);
	}
	else
	{
		HASH_ADD_KEYPTR(hh_a, ex_rt->hash_key2ex_a, key,key_len, exc);
	}
	return;
}
void EX_data_rt_updating_hash_del(struct EX_data_rt* ex_rt, struct EX_data_container* exc)
{
	if(ex_rt->effective_hash=='a')
	{
		HASH_DELETE(hh_b, ex_rt->hash_key2ex_b, exc);	
	}
	else
	{
		HASH_DELETE(hh_a, ex_rt->hash_key2ex_a, exc);	
	}
	return;
}
int EX_data_rt_row2EX_data(struct EX_data_rt* ex_rt, 
											const char* row, const char* key, size_t key_len,
											void* user_data, void* logger)
{

	MAAT_RULE_EX_DATA ex_data=NULL;
 	const struct EX_data_schema* ex_schema=ex_rt->ex_schema;
	struct EX_data_container* ex_container=NULL, *tmp=NULL;
	int ret=0;
	if(!ex_rt->is_updating)
	{
		EX_data_rt_update_prepare(ex_rt);
	}
	tmp=EX_data_rt_updating_hash_find(ex_rt, key, key_len);
	if(tmp==NULL)
	{
		ex_container=ALLOC(struct EX_data_container, 1);
		ex_container->key=ALLOC(char, key_len+1);
		memcpy(ex_container->key, key, key_len);
		ex_schema->new_func(ex_rt->table_id, ex_container->key, row, &ex_data, 
							ex_schema->argl, ex_schema->argp);
		ex_container->ex_data=ex_data;
		ex_container->rt=ex_rt;
		ex_container->user_data=user_data;

		ex_container->key_len=key_len;
		EX_data_rt_updating_hash_add(ex_rt, ex_container->key, ex_container->key_len, ex_container);
		ret=0;
	}
	else
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"EX data add error: duplicated key %.*s of %s",
								key_len, key, row);

		ret=-1;
	}
	return ret;
}
int EX_data_rt_delete_by_row(struct EX_data_rt* ex_rt, const char* row, const char* key, size_t key_len,
									void *logger)
{
	struct EX_data_container* exc=NULL;
	int ret=0;
	if(!ex_rt->is_updating)
	{
		EX_data_rt_update_prepare(ex_rt);
	}
	exc=EX_data_rt_updating_hash_find(ex_rt, key, key_len);
	if(exc)
	{
		EX_data_rt_updating_hash_del(ex_rt, exc);
		Maat_garbage_bagging(ex_rt->garbage_bin, exc, (void (*)(void*))EX_data_container_free);
		ret=0;
	}
	else
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"EX data del error: no such key %.*s of %s",
								key_len, key, row);
		ret=-1;
	}
	return ret;
}

MAAT_RULE_EX_DATA  EX_data_rt_get_EX_data_by_key(struct EX_data_rt* ex_rt, const char* key, size_t key_len)
{
	struct EX_data_container* exc=NULL;
	MAAT_RULE_EX_DATA ex_data=NULL;

	if(!ex_rt->ex_schema)
	{	
		assert(0);
		return NULL;
	}
	exc=EX_data_rt_effective_hash_find(ex_rt, key, key_len);
	if(exc!=NULL)
	{
		ex_rt->ex_schema->dup_func(ex_rt->table_id, &(ex_data), &(exc->ex_data), 
			ex_rt->ex_schema->argl, ex_rt->ex_schema->argp);
	}
	return ex_data;
}
MAAT_RULE_EX_DATA  EX_data_rt_get_EX_data_by_container(struct EX_data_rt* ex_rt, struct EX_data_container* container)
{
	MAAT_RULE_EX_DATA dupped_ex_data=NULL;
	ex_rt->ex_schema->dup_func(ex_rt->table_id, &(dupped_ex_data), &(container->ex_data), 
		ex_rt->ex_schema->argl, ex_rt->ex_schema->argp);
	return dupped_ex_data;
}

size_t EX_data_rt_list_all_ex_container(struct EX_data_rt* ex_rt, struct EX_data_container*** ex_container_array)
{
	size_t ex_data_cnt=0, i=0;
	struct EX_data_container* ex_container=NULL, *tmp=NULL;
	assert(ex_rt->is_updating==0);
	if(ex_rt->effective_hash=='a')
	{
		ex_data_cnt=HASH_CNT(hh_a, ex_rt->hash_key2ex_a);
		*ex_container_array=ALLOC(struct EX_data_container*, ex_data_cnt);
		HASH_ITER(hh_a, ex_rt->hash_key2ex_a, ex_container, tmp)
		{
			(*ex_container_array)[i]=ex_container;
			i++;
		}
	}
	else
	{
		ex_data_cnt=HASH_CNT(hh_b, ex_rt->hash_key2ex_b);
		*ex_container_array=ALLOC(struct EX_data_container*, ex_data_cnt);
		HASH_ITER(hh_b, ex_rt->hash_key2ex_b, ex_container, tmp)
		{
			(*ex_container_array)[i]=ex_container;
			i++;
		}
	}
	return ex_data_cnt;
}
void* EX_data_container_get_user_data(struct EX_data_container* ex_container)
{
	return ex_container->user_data;
}
size_t EX_data_rt_get_ex_container_count(struct EX_data_rt* ex_rt)
{
	size_t count=0;
	if(ex_rt->effective_hash=='a')
	{
		count=HASH_CNT(hh_a, ex_rt->hash_key2ex_a);
	}
	else
	{
		count=HASH_CNT(hh_b, ex_rt->hash_key2ex_b);
	}
	return count;
}

