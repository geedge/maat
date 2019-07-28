#include "Maat_table_runtime.h"
#include "Maat_rule.h"
#include "Maat_utils.h"

#include <MESA/MESA_handle_logger.h>
#include <MESA/MESA_list_queue.h>
#include <assert.h>

struct wrap_plugin_EX_data
{
	MAAT_RULE_EX_DATA exdata;
	const struct Maat_table_desc* ref_plugin_table;
};
void wrap_plugin_EX_data_free(void *data)
{
	struct wrap_plugin_EX_data* wrap_data=(struct wrap_plugin_EX_data*)data;
	const struct plugin_table_ex_data_desc* ex_desc= &(wrap_data->ref_plugin_table->plugin.ex_desc);
	ex_desc->free_func(wrap_data->ref_plugin_table->table_id, &(wrap_data->exdata), ex_desc->argl, ex_desc->argp);
	wrap_data->ref_plugin_table=NULL;
	free(wrap_data);
	return;
}
MESA_htable_handle wrap_plugin_EX_hash_new(long long estimate_size, Maat_plugin_EX_key2index_func_t * key2index)
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
	hargs.data_free = wrap_plugin_EX_data_free;
	hargs.data_expire_with_condition = NULL;
	key2ex_hash=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(key2ex_hash, 0);
	return key2ex_hash;
}

int plugin_EX_data_free(const struct Maat_table_desc* plugin_table, const char* line,
								MESA_htable_handle key2ex_hash, void *logger)
{
	size_t key_offset=0, key_len=0;
	const struct plugin_table_desc* plugin_desc= &(plugin_table->plugin);	
	int ret=0;
	ret=get_column_pos(line, plugin_desc->key_column, &key_offset, &key_len);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"Plugin EX data del error: cannot find column %d of %s",
								plugin_desc->key_column, line);
		return -1;
	}
	ret=MESA_htable_del(key2ex_hash, (const unsigned char*)line+key_offset, key_len, NULL);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"Plugin EX data del error: no such key %.*s of %s",
								key_len, line+key_offset, line);
		return -1;
	}	
	return 0;
}

int plugin_EX_data_new(const struct Maat_table_desc* plugin_table, const char* line,
								MESA_htable_handle key2ex_hash, void *logger)
{
	char* key=NULL;
	size_t key_offset=0, key_len=0;
	MAAT_RULE_EX_DATA exdata=NULL;
	struct wrap_plugin_EX_data* wrap_data=NULL;
	const struct plugin_table_desc* plugin_desc= &(plugin_table->plugin);
	int ret=0;
	ret=get_column_pos(line, plugin_desc->key_column, &key_offset, &key_len);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"Plugin EX data add error: cannot find column %d of %s",
								plugin_desc->key_column, line);
		return -1;
	}
	key=ALLOC(char, key_len+1);
	memcpy(key, line+key_offset, key_len);
	plugin_desc->ex_desc.new_func(plugin_table->table_id, key, line, &exdata, 
								plugin_desc->ex_desc.argl, plugin_desc->ex_desc.argp);
	wrap_data=ALLOC(struct wrap_plugin_EX_data, 1);
	wrap_data->exdata=exdata;
	wrap_data->ref_plugin_table=plugin_table;
	ret=MESA_htable_add(key2ex_hash, (const unsigned char*)line+key_offset, key_len, wrap_data);
	free(key);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"Plugin EX data add error: duplicated key %.*s of %s",
								key_len, line+key_offset, line);
		wrap_plugin_EX_data_free(wrap_data);
		return -1;
	}
	return 0;
}

struct Maat_table_runtime_manager
{
	struct Maat_table_runtime** table_rt;
	size_t n_table_rt;
};
static GIE_digest_t* create_digest_rule(unsigned int id, enum GIE_operation op,const char* digest,
						short cfds_lvl, void* tag)
{
	GIE_digest_t* rule=(GIE_digest_t*)calloc(sizeof(GIE_digest_t),1);
	int digest_len=0;
	rule->id=id;
	rule->operation=op;
	if(digest!=NULL)
	{
		digest_len=strlen(digest);
		rule->sfh=(char*)calloc(sizeof(char),digest_len+1);
		memcpy(rule->sfh,digest,digest_len);

	}
	rule->sfh_length=digest_len;
	rule->cfds_lvl=cfds_lvl;
	rule->tag=tag;
	return rule;
}
static void destroy_digest_rule(GIE_digest_t*rule)
{
	if(rule->sfh!=NULL)
	{
		free(rule->sfh);
		rule->sfh=NULL;
	}
	free(rule);
	rule=NULL;
	return;
}

static struct Maat_table_runtime* table_runtime_new(const struct Maat_table_desc* table_desc, int max_thread_num)
{

	struct Maat_table_runtime* table_rt= ALLOC(struct Maat_table_runtime, 1);
	table_rt->table_type=table_desc->table_type;
	switch(table_desc->table_type)
	{
		case TABLE_TYPE_DIGEST:
		case TABLE_TYPE_SIMILARITY:
			table_rt->similar.update_q=MESA_lqueue_create(0,0);
			break;
		case TABLE_TYPE_PLUGIN:
			table_rt->plugin.cache_lines=dynamic_array_create(1, 1024);
			if(table_desc->plugin.have_exdata)
			{
				table_rt->plugin.key2ex_hash=wrap_plugin_EX_hash_new(table_desc->plugin.estimate_size, 
										table_desc->plugin.ex_desc.key2index_func);
			}
			break;
		default:
			break;
	}

	table_rt->scan_cnt=alignment_int64_array_alloc(max_thread_num);
	table_rt->scan_cpu_time=alignment_int64_array_alloc(max_thread_num);
	table_rt->input_bytes=alignment_int64_array_alloc(max_thread_num);
	table_rt->stream_num=alignment_int64_array_alloc(max_thread_num);
	table_rt->hit_cnt=alignment_int64_array_alloc(max_thread_num);
	return table_rt;
}
static void table_runtime_free(struct Maat_table_runtime* p)
{
	long q_cnt=0,data_size=0;
	int i=0;
	UNUSED int q_ret=0;

	GIE_digest_t* digest_rule=NULL;
	if(p==NULL)
	{
		return;
	}
	switch(p->table_type)
	{
		case TABLE_TYPE_DIGEST:
		case TABLE_TYPE_SIMILARITY:
			if(p->similar.gie_handle!=NULL)
			{
				GIE_destory(p->similar.gie_handle);
			}
			if(p->similar.update_q!=NULL)
			{
				q_cnt=MESA_lqueue_get_count(p->similar.update_q);
				for(i=0;i<q_cnt;i++)
				{
					data_size=sizeof(GIE_digest_t*);
					q_ret=(MESA_queue_errno_t)MESA_lqueue_get_head(p->similar.update_q,&digest_rule,&data_size);
					assert(data_size==sizeof(void*)&&q_ret==MESA_QUEUE_RET_OK);
					destroy_digest_rule(digest_rule);
				}
				MESA_lqueue_destroy(p->similar.update_q, lqueue_destroy_cb, NULL);				
			}
			break;
		case TABLE_TYPE_PLUGIN:
			dynamic_array_destroy(p->plugin.cache_lines, free);
			p->plugin.cache_lines=NULL;
			if(p->plugin.key2ex_hash!=NULL)
			{
				MESA_htable_destroy(p->plugin.key2ex_hash, NULL);
			}
		default:
			break;
	}

	alignment_int64_array_free(p->scan_cnt);
	alignment_int64_array_free(p->scan_cpu_time);
	alignment_int64_array_free(p->input_bytes);
	alignment_int64_array_free(p->stream_num);
	alignment_int64_array_free(p->hit_cnt);
	free(p);
	return;
}

struct Maat_table_runtime_manager* Maat_table_runtime_manager_create(struct Maat_table_manager* table_manager, int max_thread_num)
{	
	const struct Maat_table_desc* table_desc=NULL;
	struct Maat_table_runtime* table_rt=NULL;
	struct Maat_table_runtime_manager* table_rt_mgr=ALLOC(struct Maat_table_runtime_manager, 1);
	size_t i=0;
	table_rt_mgr->n_table_rt=Maat_table_manager_get_size(table_manager);
	table_rt_mgr->table_rt=ALLOC(struct Maat_table_runtime*, table_rt_mgr->n_table_rt);
	for(i=0; i<table_rt_mgr->n_table_rt; i++)
	{
		table_desc=Maat_table_get_by_id_raw(table_manager, i);
		if(!table_desc)
		{
			continue;
		}
		table_rt=table_runtime_new(table_desc, max_thread_num);
		table_rt_mgr->table_rt[i]=table_rt;
	}
	return table_rt_mgr;
}
void Maat_table_rt_manager_destroy(struct Maat_table_runtime_manager* table_rt_mgr)
{
	size_t i=0;
	for(i=0; i<table_rt_mgr->n_table_rt; i++)
	{
		table_runtime_free(table_rt_mgr->table_rt[i]);
		table_rt_mgr->table_rt[i]=NULL;
	}
	free(table_rt_mgr->table_rt);
	table_rt_mgr->table_rt=NULL;
	free(table_rt_mgr);
}
struct Maat_table_runtime* Maat_table_runtime_get(struct Maat_table_runtime_manager* table_rt_mgr, int table_id)
{
	assert(table_id<(int)table_rt_mgr->n_table_rt);
	return table_rt_mgr->table_rt[table_id];
}
long long Maat_table_runtime_plugin_cached_line_count(struct Maat_table_runtime* table_rt)
{
	struct plugin_runtime* plugin_rt=&(table_rt->plugin);
	return plugin_rt->cache_line_num;
}
const char* Maat_table_runtime_plugin_get_cached_line(struct Maat_table_runtime* table_rt, long long Nth_line)
{
	const char* line=NULL;
	struct plugin_runtime* plugin_rt=&(table_rt->plugin);

	line=(const char*)dynamic_array_read(plugin_rt->cache_lines, Nth_line);
	return line;
}
MESA_htable_handle plugin_EX_htable_new(const struct Maat_table_desc* plugin_table,
								struct dynamic_array_t* lines, size_t line_cnt, void* logger)
{
	MESA_htable_handle key2ex_hash=NULL;
	size_t i=0;
	const char* line=NULL;
	const struct plugin_table_desc* plugin_desc= &(plugin_table->plugin);

	key2ex_hash=wrap_plugin_EX_hash_new(plugin_desc->estimate_size, plugin_desc->ex_desc.key2index_func);

	for(i=0; i< line_cnt; i++)
	{
		line=(const char*)dynamic_array_read(lines, i);
		plugin_EX_data_new(plugin_table, line, key2ex_hash, logger);
	}
	return key2ex_hash;
}
int Maat_table_runtime_plugin_new_ex_idx(struct Maat_table_runtime* table_rt, struct Maat_table_desc* table_desc, void* logger)
{
	assert(table_rt->plugin.key2ex_hash==NULL);
	if(table_rt->plugin.key2ex_hash)
	{
		return -1;
	}
	table_rt->plugin.key2ex_hash=plugin_EX_htable_new(table_desc, table_rt->plugin.cache_lines, 
													table_rt->plugin.cache_line_num, logger);
	return 0;
}
MAAT_PLUGIN_EX_DATA Maat_table_runtime_plugin_get_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_desc* table_desc, const char* key)
{
	struct plugin_table_desc* plugin_desc=NULL;
	struct wrap_plugin_EX_data* wrap_data=NULL;
	MAAT_RULE_EX_DATA exdata=NULL;

	plugin_desc=&(table_desc->plugin);
	if(!plugin_desc->have_exdata)
	{	
		assert(0);
		return NULL;
	}
	wrap_data=(struct wrap_plugin_EX_data*)MESA_htable_search(table_rt->plugin.key2ex_hash,
													(const unsigned char*)key, strlen(key));
	if(wrap_data!=NULL)
	{
		plugin_desc->ex_desc.dup_func(table_desc->table_id, &(exdata), &(wrap_data->exdata), 
			plugin_desc->ex_desc.argl, plugin_desc->ex_desc.argp);
	}
	return exdata;

}

void Maat_table_runtime_digest_add(struct Maat_table_runtime* table_rt, int expr_id, const char* digest, short confidence_degree, void* tag)
{
	GIE_digest_t* digest_rule=NULL;
	char *dup_digest=_maat_strdup(digest);

	if(table_rt->table_type==TABLE_TYPE_SIMILARITY)
	{
		dup_digest=str_unescape(dup_digest);
	}
	digest_rule=create_digest_rule(expr_id, GIE_INSERT_OPT,
								dup_digest,
								confidence_degree,
								tag);
	MESA_lqueue_join_tail(table_rt->similar.update_q, &digest_rule, sizeof(void*));
	return;
}
void Maat_table_runtime_digest_del(struct Maat_table_runtime* table_rt, int expr_id)
{
	GIE_digest_t* digest_rule=NULL;
	digest_rule=create_digest_rule(expr_id, GIE_DELETE_OPT	//del digest
							,NULL
							,0
							,NULL);
	MESA_lqueue_join_tail(table_rt->similar.update_q,&digest_rule, sizeof(void*));
	return;
}
int Maat_table_runtime_digest_batch_udpate(struct Maat_table_runtime* table_rt)
{
	long i=0,data_size=0;
	int ret=0;
	GIE_digest_t* digest_rule=NULL;
	GIE_digest_t** update_array=NULL;
	UNUSED	MESA_queue_errno_t q_ret=MESA_QUEUE_RET_OK; 
	

	GIE_create_para_t para;
	para.gram_value=7;
	para.position_accuracy=10;

	const long q_cnt=MESA_lqueue_get_count(table_rt->similar.update_q);
	if(q_cnt==0)
	{
		return 0;
	}
	if(table_rt->similar.gie_handle==NULL)
	{
		if(table_rt->table_type==TABLE_TYPE_SIMILARITY)
		{
			para.ED_reexamine=1;
			para.format=GIE_INPUT_FORMAT_PLAIN;
		}
		else
		{
			para.ED_reexamine=0;
			para.format=GIE_INPUT_FORMAT_SFH;
		}
		table_rt->similar.gie_handle=GIE_create(&para);
	}

	update_array=(GIE_digest_t** )calloc(sizeof(GIE_digest_t*),q_cnt);
	for(i=0;i<q_cnt;i++)
	{
		data_size=sizeof(void*);
		q_ret=(MESA_queue_errno_t)MESA_lqueue_get_head(table_rt->similar.update_q, &digest_rule, &data_size);
		assert(data_size==sizeof(void*)&&q_ret==MESA_QUEUE_RET_OK);
		update_array[i]=digest_rule;
		digest_rule=NULL;
	}
	ret=GIE_update(table_rt->similar.gie_handle, update_array, (int)q_cnt);
	for(i=0;i<q_cnt;i++)
	{
		if(update_array[i]->operation==GIE_INSERT_OPT)
		{
			table_rt->origin_rule_num++;
		}
		else
		{
			table_rt->origin_rule_num--;
		}
		destroy_digest_rule(update_array[i]);
		update_array[i]=NULL;
	}
	free(update_array);
	update_array=NULL;
	
	if(ret!=(int)q_cnt)
	{
		return -1;
	}
	return q_cnt;
}


