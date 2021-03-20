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

	UT_hash_handle hh;
	const struct EX_data_rt* rt;
	
};

struct EX_data_rt
{
	UT_array *cache_rows;
	size_t cache_row_num;
	size_t cache_size;
	pthread_rwlock_t rwlock;
	struct EX_data_container* hash_key2ex;

	const struct EX_data_schema* ex_schema;
	int table_id;
	void (* user_data_free)(void *user_data);	
	struct Maat_garbage_bin* bin;
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
	p->hash_key2ex=NULL;
	utarray_new(p->cache_rows, &ut_cache_row_icd);
	p->table_id=table_id;
	p->user_data_free=user_data_free;
	pthread_rwlock_init(&p->rwlock, NULL);
	p->bin=Maat_garbage_bin_new(0);
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
void EX_data_rt_free(struct EX_data_rt* p)
{
	struct EX_data_container* ex_container=NULL, *tmp=NULL;
	
	HASH_ITER(hh, p->hash_key2ex, ex_container, tmp)
	{
		HASH_DELETE(hh, p->hash_key2ex, ex_container);
		EX_data_container_free(ex_container);
	}
	//p->hash_key2ex's memory is freed when its last element was deleted.
	if(p->cache_rows)
	{
		utarray_free(p->cache_rows);
		p->cache_rows=NULL;
		p->cache_row_num=0;
	}
	pthread_rwlock_destroy(&p->rwlock);
	Maat_garbage_bin_free(p->bin);
	free(p);
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

int EX_data_rt_row2EX_data(struct EX_data_rt* ex_rt, 
											const char* row, const char* key, size_t key_len,
											void* user_data, void* logger)
{

	MAAT_RULE_EX_DATA ex_data=NULL;
 	const struct EX_data_schema* ex_schema=ex_rt->ex_schema;
	struct EX_data_container* ex_container=NULL, *tmp=NULL;
	int ret=0;
	pthread_rwlock_wrlock(&ex_rt->rwlock);

	HASH_FIND(hh, ex_rt->hash_key2ex, key, key_len, tmp);
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
		HASH_ADD_KEYPTR(hh, ex_rt->hash_key2ex, ex_container->key, ex_container->key_len, ex_container);
		ret=0;
	}
	else
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"EX data add error: duplicated key %.*s of %s",
								key_len, key, row);

		ret=-1;
	}

	pthread_rwlock_unlock(&ex_rt->rwlock);
	return ret;
}
int EX_data_rt_delete_by_row(struct EX_data_rt* ex_rt, const char* row, const char* key, size_t key_len,
									void *logger)
{
	struct EX_data_container* exc=NULL;
	int ret=0;
	pthread_rwlock_wrlock(&ex_rt->rwlock);
	HASH_FIND(hh, ex_rt->hash_key2ex, key, key_len, exc);
	if(exc)
	{
		HASH_DELETE(hh, ex_rt->hash_key2ex, exc);	
		Maat_garbage_bagging(ex_rt->bin, exc, (void (*)(void*))EX_data_container_free);
		ret=0;
	}
	else
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"EX data del error: no such key %.*s of %s",
								key_len, key, row);
		ret=-1;
	}
	pthread_rwlock_unlock(&ex_rt->rwlock);
	return ret;
}

MAAT_RULE_EX_DATA  EX_data_rt_get_EX_data_by_key(struct EX_data_rt* ex_rt, const char* key, size_t key_len)
{
	struct EX_data_container* container=NULL;
	MAAT_RULE_EX_DATA ex_data=NULL;

	if(!ex_rt->ex_schema)
	{	
		assert(0);
		return NULL;
	}
	pthread_rwlock_rdlock(&ex_rt->rwlock);
	HASH_FIND(hh, ex_rt->hash_key2ex, key, key_len, container);
	if(container!=NULL)
	{
		ex_rt->ex_schema->dup_func(ex_rt->table_id, &(ex_data), &(container->ex_data), 
			ex_rt->ex_schema->argl, ex_rt->ex_schema->argp);
	}
	pthread_rwlock_unlock(&ex_rt->rwlock);
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

	pthread_rwlock_rdlock(&ex_rt->rwlock);
	ex_data_cnt=HASH_COUNT(ex_rt->hash_key2ex);
	*ex_container_array=ALLOC(struct EX_data_container*, ex_data_cnt);
	HASH_ITER(hh, ex_rt->hash_key2ex, ex_container, tmp)
	{
		(*ex_container_array)[i]=ex_container;
		i++;
	}
	pthread_rwlock_unlock(&ex_rt->rwlock);
	return ex_data_cnt;
}
void* EX_data_container_get_user_data(struct EX_data_container* ex_container)
{
	return ex_container->user_data;
}
size_t EX_data_rt_get_ex_container_count(struct EX_data_rt* ex_rt)
{
	size_t count=0;
	pthread_rwlock_rdlock(&ex_rt->rwlock);
	count=HASH_COUNT(ex_rt->hash_key2ex);
	pthread_rwlock_unlock(&ex_rt->rwlock);
	return count;
}
void EX_data_rt_garbage_collection(struct EX_data_rt* ex_rt)
{
	Maat_garbage_collect_routine(ex_rt->bin);
}

