#include "Maat_rule.h"
#include "Maat_utils.h"

#include <MESA/MESA_handle_logger.h>
#include <MESA/MESA_list_queue.h>
#include <assert.h>
#include <sys/queue.h>


#include "IPMatcher.h"
#include "gram_index_engine.h"
#include "FQDN_engine.h"
#include "alignment_int64.h"
#include "dynamic_array.h"
#include <MESA/MESA_htable.h>
#include <MESA/MESA_list_queue.h>

struct similar_runtime
{
	GIE_handle_t*	gie_handle;
	MESA_lqueue_head update_q;
};
struct fqdn_plugin_runtime
{
	struct FQDN_engine* fqdn_engine;
	struct FQDN_engine* new_fqdn_engine;
	struct EX_data_rt* ex_data_rt;
	int changed_flag;
};
struct plugin_runtime
{
	struct EX_data_rt* ex_data_rt;
	long long acc_line_num;
};

struct ip_plugin_runtime
{
	struct EX_data_rt* ex_data_rt;
	struct ip_matcher* ip_matcher;
	int changed_flag;
};
struct expr_runtime
{
	long long expr_rule_cnt;	//expr_type=0,1,3
	long long regex_rule_cnt;	//expr_type=2
};
struct ip_runtime
{
	long long ipv4_rule_cnt;
	long long ipv6_rule_cnt;

};
struct group2compile_runtime
{
	long long not_flag_group;
};
struct Maat_table_runtime
{
	enum MAAT_TABLE_TYPE table_type;
	long origin_rule_num;
	union
	{	
		struct similar_runtime similar;	//for digest and similarity
		struct fqdn_plugin_runtime fqdn_plugin;//for fqdn_plugin and fqdn_plugin
		struct plugin_runtime plugin;		
		struct ip_plugin_runtime ip_plugin;
		struct expr_runtime expr;
		struct ip_runtime ip;
		struct group2compile_runtime group2compile;		
		void * other;
	};
	mcore_long_t	scan_cnt;
	mcore_long_t	scan_cpu_time;	//nano
	mcore_long_t	input_bytes;
	mcore_long_t	stream_num;
	mcore_long_t	hit_cnt;
	struct Maat_garbage_bin* ref_garbage_bin;
};

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
	struct Maat_garbage_bin* ref_bin;
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
struct FQDN_rule* fqdn_rule_new(unsigned int id, const char* fqdn, size_t fqdn_len, int is_suffix_match)
{
	struct FQDN_rule* fqdn_rule=ALLOC(struct FQDN_rule, 1);
	//Todo: check FQDN format with regex ^([a-zA-Z0-9._-])+$
	if(fqdn[0]=='.')
	{
		fqdn++;
		fqdn_len--;
	}
	if(fqdn[fqdn_len]=='/')
	{
		fqdn_len--;
	}	
	fqdn_rule->FQDN=ALLOC(char, fqdn_len+1);
	memcpy(fqdn_rule->FQDN, fqdn, fqdn_len);
	fqdn_rule->len=fqdn_len;
	fqdn_rule->is_suffix_match=is_suffix_match;
	fqdn_rule->id=id;
	return fqdn_rule;
}
void fqdn_rule_free(struct FQDN_rule* fqdn_rule)
{
	assert(fqdn_rule->user_tag==NULL);
	free(fqdn_rule->FQDN);
	fqdn_rule->FQDN=NULL;
	free(fqdn_rule);
	return;
}
void _notype_fqdn_rule_free(void* p)
{
	fqdn_rule_free((struct FQDN_rule*)p);
	return;
}
static struct Maat_table_runtime* table_runtime_new(const struct Maat_table_schema* table_schema, int max_thread_num, struct Maat_garbage_bin* bin)
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
										table_schema->plugin.ex_schema.key2index_func,
										NULL,
										bin);
			if(table_schema->plugin.have_exdata)
			{
				EX_data_rt_set_schema(table_rt->plugin.ex_data_rt, &table_schema->plugin.ex_schema);
			}
			break;
		case TABLE_TYPE_IP_PLUGIN:
			table_rt->ip_plugin.ex_data_rt=EX_data_rt_new(table_schema->table_id, 									
										table_schema->ip_plugin.ex_schema.key2index_func,
										free,
										bin);
			if(table_schema->ip_plugin.have_exdata)
			{			
				EX_data_rt_set_schema(table_rt->ip_plugin.ex_data_rt, &table_schema->ip_plugin.ex_schema);
			}
			break;
		case TABLE_TYPE_FQDN_PLUGIN:
			table_rt->fqdn_plugin.ex_data_rt=EX_data_rt_new(table_schema->table_id, 									
										table_schema->fqdn_plugin.ex_schema.key2index_func,
										_notype_fqdn_rule_free,
										bin);
			if(table_schema->fqdn_plugin.have_exdata)
			{			
				EX_data_rt_set_schema(table_rt->fqdn_plugin.ex_data_rt, &table_schema->fqdn_plugin.ex_schema);
			}
			break;
		default:
			break;
	}
	table_rt->ref_garbage_bin=bin;
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
			assert(p->ip_plugin.new_ip_matcher==NULL);
			break;
		case TABLE_TYPE_FQDN_PLUGIN:
			FQDN_engine_free(p->fqdn_plugin.fqdn_engine);
			EX_data_rt_free(p->fqdn_plugin.ex_data_rt);			
			assert(p->fqdn_plugin.new_fqdn_engine==NULL);
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

struct Maat_table_runtime_manager* Maat_table_runtime_manager_create(struct Maat_table_manager* table_manager, int max_thread_num, struct Maat_garbage_bin* bin)
{	
	const struct Maat_table_schema* table_desc=NULL;
	struct Maat_table_runtime* table_rt=NULL;
	struct Maat_table_runtime_manager* table_rt_mgr=ALLOC(struct Maat_table_runtime_manager, 1);
	size_t i=0;
	table_rt_mgr->ref_bin=bin;
	table_rt_mgr->n_table_rt=Maat_table_manager_get_size(table_manager);
	table_rt_mgr->table_rt=ALLOC(struct Maat_table_runtime*, table_rt_mgr->n_table_rt);
	for(i=0; i<table_rt_mgr->n_table_rt; i++)
	{
		table_desc=Maat_table_get_by_id_raw(table_manager, i);
		if(!table_desc)
		{
			continue;
		}
		table_rt=table_runtime_new(table_desc, max_thread_num, table_rt_mgr->ref_bin);
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
	table_rt_mgr->ref_bin=NULL;
	free(table_rt_mgr);
}
struct Maat_table_runtime* Maat_table_runtime_get(struct Maat_table_runtime_manager* table_rt_mgr, int table_id)
{
	assert(table_id<(int)table_rt_mgr->n_table_rt);
	return table_rt_mgr->table_rt[table_id];
}
enum MAAT_TABLE_TYPE Maat_table_runtime_get_type(struct Maat_table_runtime* table_rt)
{
	return table_rt->table_type;
}
void Maat_table_runtime_perf_stat(struct Maat_table_runtime* p, int scan_len, struct timespec* start, struct timespec* end,int thread_num)
{
	alignment_int64_array_add(p->scan_cnt,thread_num,1);
	alignment_int64_array_add(p->input_bytes,thread_num,scan_len);
	if(start!=NULL&&end!=NULL)
	{
		alignment_int64_array_add(p->scan_cpu_time,thread_num,(end->tv_sec-start->tv_sec)*1000000000+end->tv_nsec-start->tv_nsec);
	}
	return;
}

size_t Maat_table_runtime_plugin_cached_row_count(struct Maat_table_runtime* table_rt)
{
	struct plugin_runtime* plugin_rt=&(table_rt->plugin);
	assert(table_rt->table_type==TABLE_TYPE_PLUGIN);
	return EX_data_rt_get_cached_row_num(plugin_rt->ex_data_rt);
}
const char* Maat_table_runtime_plugin_get_cached_row(struct Maat_table_runtime* table_rt, size_t Nth_row)
{
	const char* line=NULL;
	struct plugin_runtime* plugin_rt=&(table_rt->plugin);
	line=EX_data_rt_cached_row_get(plugin_rt->ex_data_rt, Nth_row);
	return line;
}
int Maat_table_runtime_plugin_commit_ex_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, void* logger)
{
	size_t i=0;
	const char* row=NULL;
	EX_data_rt_set_schema(table_rt->plugin.ex_data_rt, &table_schema->plugin.ex_schema);

	for(i=0; i<EX_data_rt_get_cached_row_num(table_rt->plugin.ex_data_rt); i++)
	{
		row=EX_data_rt_cached_row_get(table_rt->plugin.ex_data_rt, i);
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
		EX_data_rt_cache_row_put(plugin_rt->ex_data_rt, row);
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

void Maat_table_runtime_fqdn_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger)
{
	struct fqdn_plugin_table_schema* fqdn_plugin_schema=&(table_schema->fqdn_plugin);
	struct fqdn_plugin_runtime* fqdn_plugin_rt=&(table_rt->fqdn_plugin);
	size_t is_valid_offset=0, valid_len=0;
	size_t is_suffix_flag_offset=0, is_suffix_flag_len=0;
	size_t row_id_offset=0, row_id_len=0;
	size_t fqdn_offset=0, fqdn_len=0;
	struct FQDN_rule* fqdn_rule=NULL;
	int ret=0;	
	if(fqdn_plugin_schema->have_exdata)
	{
		ret=Maat_helper_read_column(row, fqdn_plugin_schema->valid_flag_column, &is_valid_offset, &valid_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"fqdn_plugin EX data process error: cannot find is_valid column %d of %s",
									fqdn_plugin_schema->valid_flag_column, row);
			return;
		}
		ret=Maat_helper_read_column(row, fqdn_plugin_schema->row_id_column, &row_id_offset, &row_id_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"fqdn_plugin EX data process error: cannot find row id column %d of %s",
									fqdn_plugin_schema->row_id_column, row);
			return;
		}
		ret=Maat_helper_read_column(row, fqdn_plugin_schema->is_suffix_flag_column, &is_suffix_flag_offset, &is_suffix_flag_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"fqdn_plugin EX data process error: cannot find is_suffix_match column %d of %s",
									fqdn_plugin_schema->is_suffix_flag_column, row);
			return;
		}
		ret=Maat_helper_read_column(row, fqdn_plugin_schema->fqdn_column, &fqdn_offset, &fqdn_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"fqdn_plugin EX data process error: cannot find fqdn column %d of %s",
									fqdn_plugin_schema->fqdn_column, row);
			return;
		}
		
		if(atoi(row+is_valid_offset)==1)//add
		{
			fqdn_rule=fqdn_rule_new((unsigned int)atoi(row+row_id_offset), row+fqdn_offset, fqdn_len, atoi(row+is_suffix_flag_offset));
			EX_data_rt_row2EX_data(fqdn_plugin_rt->ex_data_rt, row, row+row_id_offset, row_id_len, fqdn_rule, logger);
		}
		else
		{
			EX_data_rt_delete_by_row(fqdn_plugin_rt->ex_data_rt, row, row+row_id_offset, row_id_len, logger);
		}
	}
	else
	{
		EX_data_rt_cache_row_put(fqdn_plugin_rt->ex_data_rt, row);
	}
	fqdn_plugin_rt->changed_flag=1;
	return;
}

int Maat_table_runtime_fqdn_plugin_build_new_fqdn_engine(struct Maat_table_runtime* table_rt)
{
	struct FQDN_engine* new_fqdn_engine=NULL, *old_fqdn_engine=NULL;
	struct 	fqdn_plugin_runtime* fqdn_rt=&table_rt->fqdn_plugin;
	assert(table_rt->table_type==TABLE_TYPE_FQDN_PLUGIN);
	struct EX_data_container **exc_array=NULL;
	struct FQDN_rule* rules=NULL;
	size_t rule_cnt=0, i=0, ret=0;
	if(!fqdn_rt->changed_flag)
	{
		return ret;
	}

	rule_cnt=EX_data_rt_list_all_ex_container(fqdn_rt->ex_data_rt, &exc_array);
	rules=ALLOC(struct FQDN_rule, rule_cnt);
	for(i=0; i<rule_cnt; i++)
	{
		rules[i]=*((struct FQDN_rule *)(EX_data_container_get_user_data(exc_array[i])));
		assert(rules[i].user_tag==exc_array[i]||rules[i].user_tag==NULL);
		rules[i].user_tag=exc_array[i];
	}
	if(rule_cnt>0)
	{
		
		old_fqdn_engine=fqdn_rt->fqdn_engine;
		new_fqdn_engine=FQDN_engine_new(rules, rule_cnt);
		if(new_fqdn_engine)
		{
			fqdn_rt->fqdn_engine=new_fqdn_engine;
			Maat_garbage_bagging(table_rt->ref_garbage_bin, old_fqdn_engine, (void (*)(void*))FQDN_engine_free);
		}
		else
		{
			ret=-1;
		}
	}
	free(rules);
	free(exc_array);	
	table_rt->fqdn_plugin.changed_flag=0;
	return ret;
}
struct FQDN_engine* Maat_table_runtime_apply_new_fqdn_engine(struct Maat_table_runtime* table_rt)
{
	struct FQDN_engine* old_one=table_rt->fqdn_plugin.fqdn_engine;
	table_rt->fqdn_plugin.fqdn_engine=table_rt->fqdn_plugin.new_fqdn_engine;
	assert(table_rt->table_type==TABLE_TYPE_FQDN_PLUGIN);
	table_rt->fqdn_plugin.new_fqdn_engine=NULL;
	table_rt->origin_rule_num=EX_data_rt_get_ex_container_count(table_rt->fqdn_plugin.ex_data_rt);
	return old_one;
}

int Maat_table_runtime_fqdn_plugin_commit_ex_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, void* logger)
{
	size_t i=0;
	const char* row=NULL;
	struct fqdn_plugin_runtime* fqdn_plugin_rt=&(table_rt->fqdn_plugin);
	EX_data_rt_set_schema(fqdn_plugin_rt->ex_data_rt, &table_schema->fqdn_plugin.ex_schema);
	for(i=0; i<EX_data_rt_get_cached_row_num(fqdn_plugin_rt->ex_data_rt); i++)
	{
		row=EX_data_rt_cached_row_get(fqdn_plugin_rt->ex_data_rt, i);
		Maat_table_runtime_fqdn_plugin_new_row(table_rt, table_schema, row, logger);
	}
	EX_data_rt_clear_row_cache(fqdn_plugin_rt->ex_data_rt);
	Maat_table_runtime_fqdn_plugin_rebuild_fqdn_engine(table_rt);
	Maat_table_runtime_apply_new_fqdn_engine(table_rt);//returned NULL.
	return 0;
}
int Maat_table_runtime_fqdn_plugin_get_N_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* query_fqdn, MAAT_PLUGIN_EX_DATA* ex_data_array, size_t size)
{
	struct FQDN_match results[size];
	int n_result=0, i=0;
	if(table_rt->table_type!=TABLE_TYPE_FQDN_PLUGIN)
	{
		return -1;
	}
	if(!table_rt->fqdn_plugin.fqdn_engine)
	{
		return 0;
	}
	n_result=FQDN_engine_search(table_rt->fqdn_plugin.fqdn_engine, query_fqdn, strlen(query_fqdn), results, size);
	for(i=0; i<n_result; i++)
	{
		ex_data_array[i]=EX_data_rt_get_EX_data_by_container(table_rt->fqdn_plugin.ex_data_rt, (struct EX_data_container *)results[i].user_tag);
	}
	return n_result;
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
	struct ip_matcher* new_ip_matcher=NULL, *old_ip_matcher=NULL;
	size_t rule_cnt=0;
	size_t i=0, mem_use=0;
	struct ip_rule *rules=NULL;
	struct EX_data_container **exc_array=NULL;
	struct ip_plugin_runtime *ip_plugin=&(table_rt->ip_plugin);
	assert(table_rt->table_type==TABLE_TYPE_IP_PLUGIN);
	if(!ip_plugin->changed_flag)
	{
		return 0;
	}
	rule_cnt=EX_data_rt_list_all_ex_container(ip_plugin->ex_data_rt, &exc_array);
	rules=ALLOC(struct ip_rule, rule_cnt);
	for(i=0; i<rule_cnt; i++)
	{
		rules[i]=*((struct ip_rule *)(EX_data_container_get_user_data(exc_array[i])));
		assert(rules[i].user_tag==exc_array[i]||rules[i].user_tag==NULL);
		rules[i].user_tag=exc_array[i];
	}
	if(rule_cnt>0)
	{
		new_ip_matcher=ip_matcher_new(rules, rule_cnt, &mem_use);
		assert(ip_plugin->new_ip_matcher==NULL);
		old_ip_matcher=ip_plugin->ip_matcher;
		ip_plugin->ip_matcher=new_ip_matcher;
		Maat_garbage_bagging(table_rt->ref_garbage_bin, old_ip_matcher, (void (*)(void*))ip_matcher_free);
	}
	
	free(rules);
	free(exc_array);
	exc_array=NULL;
	ip_plugin->changed_flag=0;
	return 1;
}


void Maat_table_runtime_ip_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger)
{
	struct ip_plugin_table_schema* ip_plugin_schema=&(table_schema->ip_plugin);
	struct ip_plugin_runtime* ip_plugin_rt=&(table_rt->ip_plugin);
	size_t is_valid_offset=0, valid_len=0;
	size_t row_id_offset=0, row_id_len=0;
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
		ret=Maat_helper_read_column(row, ip_plugin_schema->row_id_column, &row_id_offset, &row_id_len);
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
			
			EX_data_rt_row2EX_data(ip_plugin_rt->ex_data_rt, row, row+row_id_offset, row_id_len, ip_rule, logger);
		}
		else
		{
		
			EX_data_rt_delete_by_row(ip_plugin_rt->ex_data_rt, row, row+row_id_offset, row_id_len, logger);
			free(ip_rule);
		}
	}
	else
	{
		EX_data_rt_cache_row_put(ip_plugin_rt->ex_data_rt, row);
	}
	ip_plugin_rt->changed_flag=1;
	return;
}
int Maat_table_runtime_ip_plugin_commit_ex_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, void* logger)
{
	size_t i=0;
	const char* row=NULL;
	struct ip_plugin_runtime* ip_plugin_rt=&(table_rt->ip_plugin);
	EX_data_rt_set_schema(ip_plugin_rt->ex_data_rt, &table_schema->ip_plugin.ex_schema);
	for(i=0; i<EX_data_rt_get_cached_row_num(ip_plugin_rt->ex_data_rt); i++)
	{
		row=EX_data_rt_cached_row_get(ip_plugin_rt->ex_data_rt, i);
		Maat_table_runtime_ip_plugin_new_row(table_rt, table_schema, row, logger);
	}
	EX_data_rt_clear_row_cache(ip_plugin_rt->ex_data_rt);
	Maat_table_runtime_ip_plugin_rebuild_ip_matcher(table_rt);
	return 0;
}

int Maat_table_runtime_ip_plugin_get_N_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const struct ip_data* ip, MAAT_PLUGIN_EX_DATA* ex_data_array, size_t size)
{
	struct scan_result results[size];
	int n_result=0, i=0;
	if(!table_rt->ip_plugin.ip_matcher)
	{
		return 0;
	}
	n_result=ip_matcher_match(table_rt->ip_plugin.ip_matcher, (struct ip_data*)ip, results, size);
	for(i=0; i<n_result; i++)
	{
		ex_data_array[i]=EX_data_rt_get_EX_data_by_container(table_rt->ip_plugin.ex_data_rt, (struct EX_data_container *)results[i].tag);
	}
	return n_result;
}


