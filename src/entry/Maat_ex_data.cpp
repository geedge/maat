#include "Maat_ex_data.h"
#include "Maat_table.h"
#include "Maat_utils.h"

#include <MESA/MESA_handle_logger.h>
#include <assert.h>

void EX_data_container_free(void *data)
{
	struct EX_data_container* wrap_data=(struct EX_data_container*)data;
	const struct EX_data_schema* ex_schema=wrap_data->rt->ex_schema;
	ex_schema->free_func(wrap_data->rt->table_id, &(wrap_data->ex_data), ex_schema->argl, ex_schema->argp);
	if(wrap_data->user_data && wrap_data->rt->user_data_free)
	{
		wrap_data->rt->user_data_free(wrap_data->user_data);
	}
	wrap_data->user_data=NULL;	
	wrap_data->rt=NULL;
	free(wrap_data);
	return;
}
static MESA_htable_handle EX_data_hash_new(long long estimate_size, Maat_plugin_EX_key2index_func_t * key2index)
{
	MESA_htable_handle key2ex_hash=NULL;
	unsigned int slot_size=1;
	while(estimate_size!=0)
	{
		estimate_size=estimate_size>>1;
		slot_size*=2;
	}
	if(slot_size==1)
	{
		slot_size=4096;
	}

	MESA_htable_create_args_t hargs;
	memset(&hargs,0,sizeof(hargs));
	hargs.thread_safe=8;
	hargs.hash_slot_size = slot_size;
	hargs.max_elem_num = 0;
	hargs.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	hargs.expire_time = 0;
	hargs.key_comp = NULL;
	hargs.key2index = NULL;	//Not supported yet.
	hargs.recursive = 1;
	hargs.data_free = EX_data_container_free;
	hargs.data_expire_with_condition = NULL;
	key2ex_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(key2ex_hash, 0);
	return key2ex_hash;
}

struct EX_data_rt* EX_data_rt_new(int table_id, long long estimate_size, Maat_plugin_EX_key2index_func_t * key2index, void (* user_data_free)(void *user_data))
{
	struct EX_data_rt* p=ALLOC(struct EX_data_rt, 1);
	p->key2ex_hash=EX_data_hash_new(estimate_size, key2index);
	p->cache_rows=dynamic_array_create(4, 1024);
	p->table_id=table_id;
	p->user_data_free=user_data_free;
	return p;
};
void EX_data_rt_set_schema(struct EX_data_rt* p, const struct EX_data_schema* schema)
{
	p->ex_schema=schema;
}
void EX_data_rt_free(struct EX_data_rt* p)
{
	if(p->cache_rows)
	{
		dynamic_array_destroy(p->cache_rows, free);
		p->cache_rows=NULL;
	}
	MESA_htable_destroy(p->key2ex_hash, NULL);
	free(p);
	return;
}
void EX_data_rt_cache_row(struct EX_data_rt* p, const char* row)
{
	size_t len=strlen(row)+1;
	char* row_copy=ALLOC(char, len);
	memcpy(row_copy, row, len);
	p->cache_size+=len;
	dynamic_array_write(p->cache_rows, p->cache_row_num, row_copy);
	p->cache_row_num++;	
	return;
}
const char* EX_data_rt_get_cached_row(struct EX_data_rt* p, int i)
{
	const char* row=NULL;
	row=(const char*)dynamic_array_read(p->cache_rows, i);
	return row;
}
void EX_data_rt_clear_row_cache(struct EX_data_rt* p)
{
	dynamic_array_destroy(p->cache_rows, free);
	p->cache_rows=NULL;
	p->cache_row_num=0;
	p->cache_size=0;
}
int EX_data_rt_get_row_num(struct EX_data_rt* p)
{
	return p->cache_row_num;
}
struct EX_data_container* EX_data_rt_row2EX_data(struct EX_data_rt* ex_rt, 
											const char* row, const char* key, size_t key_len,
											void* user_data, void* logger)
{

	MAAT_RULE_EX_DATA ex_data=NULL;
	int ret=0;
	const struct EX_data_schema* ex_schema=ex_rt->ex_schema;
	struct EX_data_container* ex_container=ALLOC(struct EX_data_container, 1);
	ex_schema->new_func(ex_rt->table_id, key, row, &ex_data, 
						ex_schema->argl, ex_schema->argp);
	ex_container->ex_data=ex_data;
	ex_container->rt=ex_rt;
	ex_container->user_data=user_data;
	ret=MESA_htable_add(ex_rt->key2ex_hash, (unsigned char*)key, key_len, ex_container);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"EX data add error: duplicated key %.*s of %s",
								key_len, key, row);
		EX_data_container_free(ex_container);
		return NULL;
	}
	return ex_container;
}
int EX_data_rt_delete_by_row(struct EX_data_rt* ex_rt, const char* row, const char* key, size_t key_len,
									void *logger)
{
	int ret=0;
	ret=MESA_htable_del(ex_rt->key2ex_hash, (const unsigned char*)key, key_len, NULL);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"EX data del error: no such key %.*s of %s",
								key_len, key, row);
		return -1;
	}	
	return 0;
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
	container=(struct EX_data_container*)MESA_htable_search(ex_rt->key2ex_hash,
													(const unsigned char*)key, strlen(key));
	if(container!=NULL)
	{
		ex_rt->ex_schema->dup_func(ex_rt->table_id, &(ex_data), &(container->ex_data), 
			ex_rt->ex_schema->argl, ex_rt->ex_schema->argp);
	}
	return ex_data;
}
MAAT_RULE_EX_DATA  EX_data_rt_get_EX_data_by_container(struct EX_data_rt* ex_rt, struct EX_data_container* container)
{
	MAAT_RULE_EX_DATA ex_data=NULL;
	ex_rt->ex_schema->dup_func(ex_rt->table_id, &(ex_data), &(container->ex_data), 
		ex_rt->ex_schema->argl, ex_rt->ex_schema->argp);
	return ex_data;
}
struct key2EX_hash_walker
{
	EX_data_container_q* listed;
	size_t count;
};

void walk_key2EX_hash(const uchar * key, uint size, void * data, void * user)
{
	struct key2EX_hash_walker *walker=(struct key2EX_hash_walker*)user;
	struct EX_data_container* ex_container=(struct EX_data_container*)data;
	TAILQ_INSERT_TAIL(walker->listed, ex_container, entries);
	walker->count++;
	return;
}
size_t EX_data_rt_list_all(struct EX_data_rt* ex_rt, EX_data_container_q* listed)
{
	size_t ex_data_cnt;
	struct key2EX_hash_walker walker={listed, 0};
	TAILQ_INIT(listed);
	MESA_htable_iterate(ex_rt->key2ex_hash, walk_key2EX_hash, &walker);
	ex_data_cnt=(size_t)MESA_htable_get_elem_num(ex_rt->key2ex_hash);
	assert(walker.count==ex_data_cnt);
	return ex_data_cnt;
}

