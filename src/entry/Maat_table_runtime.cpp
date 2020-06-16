#include "Maat_table_runtime.h"
#include "Maat_rule.h"
#include "Maat_utils.h"

#include <MESA/MESA_handle_logger.h>
#include <MESA/MESA_list_queue.h>
#include <assert.h>
#include <sys/queue.h>


int plugin_EX_data_free(const char* row, int key_column,
								MESA_htable_handle key2ex_hash, void *logger)
{
	size_t key_offset=0, key_len=0;
	int ret=0;
	ret=get_column_pos(row, key_column, &key_offset, &key_len);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"plugin/ip_plugin EX data del error: cannot find column %d of %s",
								key_column, row);
		return -1;
	}
	ret=MESA_htable_del(key2ex_hash, (const unsigned char*)row+key_offset, key_len, NULL);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"plugin/ip_plugin EX data del error: no such key %.*s of %s",
								key_len, row+key_offset, row);
		return -1;
	}	
	return 0;
}
struct ip_rule*  ip_plugin_row2ip_rule(const struct ip_plugin_table_schema* schema, const char* row)
{
	struct ip_rule* range_rule=ALLOC(struct ip_rule, 1);

	int ret[4]={0};
	size_t column_offset=0, column_len=0;
	char start_ip[128]={0}, end_ip[128]={0};
	ret[0]=get_column_pos(row, schema->row_id_column, &column_offset, &column_len);
	range_rule->rule_id=atoi(row+column_offset);
	
	ret[1]=get_column_pos(row, schema->ip_type_column, &column_offset, &column_len);
	int ip_type=atoi(row+column_offset);

	ret[2]=get_column_pos(row, schema->start_ip_column, &column_offset, &column_len);
	strncpy(start_ip, row+column_offset, MIN(column_len, sizeof(start_ip)));

	ret[3]=get_column_pos(row, schema->end_ip_column, &column_offset, &column_len);
	strncpy(end_ip, row+column_offset, MIN(column_len, sizeof(end_ip)));
	if(ret[0]<0||ret[1]<0||ret[2]<0||ret[3]<0)
	{
		free(range_rule);
		return NULL;
	}

	if(ip_type==4)
	{
		ret[0]=ip_format2range(ip_type, FORMAT_RANGE, start_ip, end_ip, &(range_rule->ipv4_rule.start_ip), &(range_rule->ipv4_rule.end_ip));
		range_rule->type=IPv4;
	}
	else if(ip_type==6)
	{
		ret[0]=ip_format2range(ip_type, FORMAT_RANGE, start_ip, end_ip, range_rule->ipv6_rule.start_ip, range_rule->ipv6_rule.end_ip);
		range_rule->type=IPv6;
	}
	else
	{
		free(range_rule);
		return NULL;
	}
	if(ret[0]<0)
	{
		free(range_rule);
		return NULL;
	}
	range_rule->user_tag=NULL;
	return range_rule;
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

static struct Maat_table_runtime* table_runtime_new(const struct Maat_table_schema* table_schema, int max_thread_num)
{

	struct Maat_table_runtime* table_rt= ALLOC(struct Maat_table_runtime, 1);
	table_rt->table_type=table_schema->table_type;
	switch(table_schema->table_type)
	{
		case TABLE_TYPE_DIGEST:
		case TABLE_TYPE_SIMILARITY:
			table_rt->similar.update_q=MESA_lqueue_create(0,0);
			break;
		case TABLE_TYPE_PLUGIN:
			table_rt->plugin.ex_data_rt=EX_data_rt_new(table_schema->table_id, 
										table_schema->plugin.estimate_size, 
										table_schema->plugin.ex_schema.key2index_func,
										NULL);
			if(table_schema->plugin.have_exdata)
			{
				EX_data_rt_set_schema(table_rt->plugin.ex_data_rt, &table_schema->plugin.ex_schema);
			}
			break;
		case TABLE_TYPE_IP_PLUGIN:
			table_rt->ip_plugin.ex_data_rt=EX_data_rt_new(table_schema->table_id, 
										table_schema->plugin.estimate_size, 
										table_schema->plugin.ex_schema.key2index_func,
										free);
			if(table_schema->ip_plugin.have_exdata)
			{			
				EX_data_rt_set_schema(table_rt->ip_plugin.ex_data_rt, &table_schema->ip_plugin.ex_schema);
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

		case TABLE_TYPE_IP_PLUGIN:
			ip_matcher_free(p->ip_plugin.ip_matcher);
			EX_data_rt_free(p->ip_plugin.ex_data_rt);
			assert(p->ip_plugin.old_ip_matcher==NULL);
			break;
		case TABLE_TYPE_PLUGIN:
			EX_data_rt_free(p->plugin.ex_data_rt);
			break;
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
	const struct Maat_table_schema* table_desc=NULL;
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
	return plugin_rt->ex_data_rt->cache_row_num;
}
const char* Maat_table_runtime_plugin_get_cached_line(struct Maat_table_runtime* table_rt, long long Nth_line)
{
	const char* line=NULL;
	struct plugin_runtime* plugin_rt=&(table_rt->plugin);

	line=(const char*)dynamic_array_read(plugin_rt->ex_data_rt->cache_rows, Nth_line);
	return line;
}
int Maat_table_runtime_plugin_commit_ex_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, void* logger)
{
	int i=0;
	const char* row=NULL;
	EX_data_rt_set_schema(table_rt->plugin.ex_data_rt, &table_schema->plugin.ex_schema);

	for(i=0; i<EX_data_rt_get_row_num(table_rt->plugin.ex_data_rt); i++)
	{
		row=EX_data_rt_get_cached_row(table_rt->plugin.ex_data_rt, i);
		Maat_table_runtime_plugin_new_row(table_rt, table_schema, row, logger);
	}
	return 0;
}
MAAT_PLUGIN_EX_DATA Maat_table_runtime_plugin_get_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* key)
{
	MAAT_RULE_EX_DATA ex_data=NULL;
	if(!table_schema->plugin.have_exdata)
	{	
		assert(0);
		return NULL;
	}
	ex_data=EX_data_rt_get_EX_data_by_key(table_rt->plugin.ex_data_rt, key, strlen(key));
	return ex_data;

}
void Maat_table_runtime_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger)
{
	int ret=0, i=0;
	size_t is_valid_offset=0, valid_len=0;
	size_t key_offset=0, key_len=0;

	struct plugin_table_schema* plugin_schema=&table_schema->plugin;
	struct plugin_runtime* plugin_rt=&table_rt->plugin;
	ret=Maat_helper_read_column(row, plugin_schema->valid_flag_column, &is_valid_offset, &valid_len);
	plugin_rt->acc_line_num++;
	if(plugin_schema->have_exdata)
	{
		ret=get_column_pos(row, plugin_schema->key_column, &key_offset, &key_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"plugin EX data process error: cannot find column %d of %s",
									plugin_schema->key_column, row);
			return;
		}
		if(atoi(row+is_valid_offset)==1)
		{
			EX_data_rt_row2EX_data(plugin_rt->ex_data_rt, row, row+key_offset, key_len, NULL, logger);
		}
		else
		{
			EX_data_rt_delete_by_row(plugin_rt->ex_data_rt, row, row+key_offset, key_len, logger);
		}
	}
	if(plugin_schema->cb_plug_cnt>0)
	{
		for(i=0; i<plugin_schema->cb_plug_cnt;i++)
		{
			plugin_schema->cb_plug[i].update(table_schema->table_id, row, plugin_schema->cb_plug[i].u_para);
		}
	}
	if(!plugin_schema->have_exdata && !plugin_schema->cb_plug_cnt)
	{
		EX_data_rt_cache_row(plugin_rt->ex_data_rt, row);
	}

	return;
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
	free(dup_digest);
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

int Maat_table_runtime_ip_plugin_rebuild_ip_matcher(struct Maat_table_runtime* table_rt)
{
	struct ip_matcher* new_ip_matcher=NULL;
	struct EX_data_container_q queue;//This is for index, no need to free.
	size_t rule_cnt=0;
	size_t i=0, mem_use=0;
	struct ip_rule *rules=NULL;
	struct EX_data_container *p=NULL;
	TAILQ_INIT(&queue);
	rule_cnt=EX_data_rt_list_all(table_rt->ip_plugin.ex_data_rt, &queue);
	rules=ALLOC(struct ip_rule, rule_cnt);
	TAILQ_FOREACH(p, &queue, entries)
	{
		rules[i]=*((struct ip_rule *)(p->user_data));
		assert(rules[i].user_tag==p||rules[i].user_tag==NULL);
		rules[i].user_tag=p;
		i++;
	}
	assert(i==rule_cnt);
	if(rule_cnt>0)
	{
		new_ip_matcher=ip_matcher_new(rules, rule_cnt, &mem_use);
		table_rt->ip_plugin.old_ip_matcher=table_rt->ip_plugin.ip_matcher;
		table_rt->ip_plugin.ip_matcher=new_ip_matcher;
	}
	free(rules);
	return 0;
}
struct ip_matcher* Maat_table_runtime_dettach_old_ip_matcher(struct Maat_table_runtime* table_rt)
{
	struct ip_matcher* old_one=table_rt->ip_plugin.old_ip_matcher;
	assert(table_rt->table_type==TABLE_TYPE_IP_PLUGIN);
	table_rt->ip_plugin.old_ip_matcher=NULL;
	return old_one;
}
void Maat_table_runtime_ip_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger)
{
	struct ip_plugin_table_schema* ip_plugin_schema=&(table_schema->ip_plugin);
	struct ip_plugin_runtime* ip_plugin_rt=&(table_rt->ip_plugin);
	size_t is_valid_offset=0, valid_len=0;
	size_t key_offset=0, key_len=0;
	struct ip_rule* ip_rule=NULL;
	int ret=0;
	
	if(ip_plugin_schema->have_exdata)
	{
		ret=Maat_helper_read_column(row, ip_plugin_schema->valid_flag_column, &is_valid_offset, &valid_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"ip_plugin EX data process error: cannot find is_valid column %d of %s",
									ip_plugin_schema->row_id_column, row);
			return;
		}
		ret=Maat_helper_read_column(row, ip_plugin_schema->row_id_column, &key_offset, &key_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"ip_plugin EX data process error: cannot find row id column %d of %s",
									ip_plugin_schema->row_id_column, row);
			return;
		}
		ip_rule=ip_plugin_row2ip_rule(ip_plugin_schema, row);
		if(ip_rule==NULL)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"ip_plugin read ip error: %s", row);
			return;

		}
		if(atoi(row+is_valid_offset)==1)//add
		{
			EX_data_rt_row2EX_data(ip_plugin_rt->ex_data_rt, row, row+key_offset, key_len, ip_rule, logger);
		}
		else
		{
			EX_data_rt_delete_by_row(ip_plugin_rt->ex_data_rt, row, row+key_offset, key_len, logger);
		}
	}
	else
	{
		EX_data_rt_cache_row(ip_plugin_rt->ex_data_rt,  row);
	}
	return;
}
int Maat_table_runtime_ip_plugin_commit_ex_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, void* logger)
{
	int i=0;
	const char* row=NULL;
	EX_data_rt_set_schema(table_rt->ip_plugin.ex_data_rt, &table_schema->ip_plugin.ex_schema);
	for(i=0; i<EX_data_rt_get_row_num(table_rt->plugin.ex_data_rt); i++)
	{
		row=EX_data_rt_get_cached_row(table_rt->plugin.ex_data_rt, i);
		Maat_table_runtime_ip_plugin_new_row(table_rt, table_schema, row, logger);
	}
	EX_data_rt_clear_row_cache(table_rt->plugin.ex_data_rt);
	Maat_table_runtime_ip_plugin_rebuild_ip_matcher(table_rt);

	return 0;
}

int Maat_table_runtime_ip_plugin_get_N_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const struct ip_data* ip, MAAT_PLUGIN_EX_DATA* ex_data_array, size_t size)
{
	struct scan_result results[size];
	int n_result=0, i=0;
	n_result=ip_matcher_match(table_rt->ip_plugin.ip_matcher, (struct ip_data*)ip, results, size);
	for(i=0; i<n_result; i++)
	{
		ex_data_array[i]=EX_data_rt_get_EX_data_by_container(table_rt->ip_plugin.ex_data_rt, (struct EX_data_container *)results[i].tag);
	}
	return n_result;
}


