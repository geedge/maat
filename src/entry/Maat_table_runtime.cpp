#include "Maat_rule.h"
#include "Maat_utils.h"
#include "Maat_table_runtime.h"
#include <MESA/MESA_handle_logger.h>
#include <assert.h>
#include <sys/queue.h>

#include "Maat_rule_internal.h"
#include "dynamic_array.h"
#include <MESA/MESA_htable.h>
#include <MESA/MESA_list_queue.h>

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
void ip_rule_free(struct ip_rule* p)
{
	free(p);
	return;
}
static int cmp_ull_p(const void *p1, const void *p2)
{
	if(* (unsigned long long*) p1 > * (unsigned long long*) p2)
	{
		return 1;
	}
	else if(* (unsigned long long*) p1 < * (unsigned long long*) p2)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}
size_t ull_dedup(unsigned long long item_ids[], size_t n_item)
{
	qsort(item_ids, n_item, sizeof(unsigned long long), cmp_ull_p);

	size_t J=0;
	for(size_t i=1; i<n_item; i++)
	{
		if(item_ids[i]!=item_ids[J]) item_ids[++J]=item_ids[i];
	}
	return J+1;
}

struct Maat_table_runtime_manager
{
	struct Maat_table_runtime** table_rt;
	size_t n_table_rt;
	struct Maat_garbage_bin* ref_bin;
};

static struct flag_rule *create_flag_rule(uint32_t region_id, uint64_t flag, uint64_t flag_mask, void *tag)
{
    struct flag_rule *rule = ALLOC(struct flag_rule, 1);

    rule->flag_rule_id = region_id;
    rule->flag = flag;
    rule->mask = flag_mask;
    rule->user_tag = tag;

    return rule;
}

static void destroy_flag_rule(struct flag_rule *rule)
{
    free(rule);
    rule=NULL;
}

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
struct FQDN_rule *fqdn_rule_new(unsigned int id, const char* fqdn, size_t fqdn_len, int is_suffix_match)
{
	struct FQDN_rule *fqdn_rule=ALLOC(struct FQDN_rule, 1);
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
void fqdn_rule_free(struct FQDN_rule *fqdn_rule)
{
	assert(fqdn_rule->user_tag==NULL);
	free(fqdn_rule->FQDN);
	fqdn_rule->FQDN=NULL;
	free(fqdn_rule);
	return;
}
struct bool_expr *bool_expr_new(unsigned int id, unsigned long long item_ids[], size_t n_item)
{
	struct bool_expr *expr=ALLOC(struct bool_expr, 1);
	expr->expr_id=id;
	size_t i=0;
	n_item=ull_dedup(item_ids, n_item);
	for(i=0; i<n_item; i++)
	{
		expr->items[i].item_id=item_ids[i];
		expr->items[i].not_flag=0;
	}
	expr->item_num=n_item;
	return expr;
}
void bool_expr_free(struct bool_expr *expr)
{
	free(expr);
	return;
}
void _notype_fqdn_rule_free(void* p)
{
	fqdn_rule_free((struct FQDN_rule*)p);
	return;
}
void rcu_free_cb(void *user_ctx, void *data)
{
    struct flag_rule *rule = (struct flag_rule *)data;
    destroy_flag_rule(rule);
}
static struct Maat_table_runtime* table_runtime_new(const struct Maat_table_schema* table_schema, int max_thread_num, struct Maat_garbage_bin* bin)
{

	struct Maat_table_runtime* table_rt= ALLOC(struct Maat_table_runtime, 1);
	table_rt->table_type=table_schema->table_type;
	switch(table_schema->table_type)
	{
        case TABLE_TYPE_FLAG:
            table_rt->flag.htable = rcu_hash_new(rcu_free_cb);
            break;
		case TABLE_TYPE_DIGEST:
		case TABLE_TYPE_SIMILARITY:
			table_rt->similar.update_q=MESA_lqueue_create(0,0);
			break;
		case TABLE_TYPE_PLUGIN:
			table_rt->plugin.ex_data_rt=EX_data_rt_new(table_schema->table_id, 
										table_schema->plugin.ex_schema.key2index_func,
										NULL);
			if(table_schema->plugin.ex_schema.set_flag)
			{
				EX_data_rt_set_schema(table_rt->plugin.ex_data_rt, &table_schema->plugin.ex_schema);
			}
			break;
		case TABLE_TYPE_IP_PLUGIN:
			table_rt->ip_plugin.ex_data_rt=EX_data_rt_new(table_schema->table_id, 									
										table_schema->ip_plugin.ex_schema.key2index_func,
										free);
			if(table_schema->ip_plugin.ex_schema.set_flag)
			{			
				EX_data_rt_set_schema(table_rt->ip_plugin.ex_data_rt, &table_schema->ip_plugin.ex_schema);
			}
			break;
		case TABLE_TYPE_FQDN_PLUGIN:
			table_rt->fqdn_plugin.ex_data_rt=EX_data_rt_new(table_schema->table_id, 									
										table_schema->fqdn_plugin.ex_schema.key2index_func,
										_notype_fqdn_rule_free);
			if(table_schema->fqdn_plugin.ex_schema.set_flag)
			{			
				EX_data_rt_set_schema(table_rt->fqdn_plugin.ex_data_rt, &table_schema->fqdn_plugin.ex_schema);
			}
			break;
		case TABLE_TYPE_BOOL_PLUGIN:
			table_rt->bool_plugin.ex_data_rt=EX_data_rt_new(table_schema->table_id, 									
										table_schema->fqdn_plugin.ex_schema.key2index_func,
										(void (*)(void*))bool_expr_free);
			if(table_schema->bool_plugin.ex_schema.set_flag)
			{			
				EX_data_rt_set_schema(table_rt->bool_plugin.ex_data_rt, &table_schema->bool_plugin.ex_schema);
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
        case TABLE_TYPE_FLAG:
            if(p->flag.htable!=NULL)
            {
                rcu_hash_free(p->flag.htable);
            }
            if (p->flag.matcher!=NULL)
            {
                flag_matcher_free(p->flag.matcher);
            }
            break;
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
			break;
		case TABLE_TYPE_FQDN_PLUGIN:
			FQDN_engine_free(p->fqdn_plugin.fqdn_engine);
			EX_data_rt_free(p->fqdn_plugin.ex_data_rt);			
			break;
        case TABLE_TYPE_BOOL_PLUGIN:
            bool_matcher_free(p->bool_plugin.matcher);
            EX_data_rt_free(p->bool_plugin.ex_data_rt);
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
		table_desc=Maat_table_manager_get_by_id_raw(table_manager, i);
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
MAAT_PLUGIN_EX_DATA Maat_table_runtime_plugin_get_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* key)
{
	MAAT_RULE_EX_DATA ex_data=NULL;
	if(!table_schema->plugin.ex_schema.set_flag)
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
	if(plugin_schema->ex_schema.set_flag)
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
	if(!plugin_schema->ex_schema.set_flag && !plugin_schema->cb_plug_cnt)
	{
		EX_data_rt_cache_row_put(plugin_rt->ex_data_rt, row);
	}

	return;
}
void Maat_table_runtime_plugin_commit_update(struct Maat_table_runtime* table_rt)
{
	EX_data_rt_update_commit(table_rt->plugin.ex_data_rt);	
	table_rt->origin_rule_num=EX_data_rt_get_ex_container_count(table_rt->plugin.ex_data_rt);
	return;
}

void Maat_table_runtime_flag_add(struct Maat_table_runtime *table_rt, int region_id, uint64_t flag, uint64_t mask, void *tag)
{
    struct flag_rule *rule = create_flag_rule(region_id, flag, mask, tag);
    rcu_hash_add(table_rt->flag.htable, (const char *)&region_id, sizeof(int), rule);
}

void Maat_table_runtime_flag_del(struct Maat_table_runtime* table_rt, int region_id)
{
    rcu_hash_del(table_rt->flag.htable, (const char *)&region_id, sizeof(int));
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
	if(fqdn_plugin_schema->ex_schema.set_flag)
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
			ret=EX_data_rt_row2EX_data(fqdn_plugin_rt->ex_data_rt, row, row+row_id_offset, row_id_len, fqdn_rule, logger);
			if(ret<0)
			{
				fqdn_rule_free(fqdn_rule);
				fqdn_rule=NULL;
			}
		}
		else
		{
			EX_data_rt_delete_by_row(fqdn_plugin_rt->ex_data_rt, row, row+row_id_offset, row_id_len, logger);
		}		
	}
	else
	{
		EX_data_rt_cache_row_put(fqdn_plugin_rt->ex_data_rt, row);
		table_rt->origin_rule_num=EX_data_rt_get_cached_row_num(fqdn_plugin_rt->ex_data_rt);
	}
	fqdn_plugin_rt->changed_flag=1;
	return;
}

int Maat_table_runtime_fqdn_plugin_commit_update(struct Maat_table_runtime* table_rt)
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
	rule_cnt=EX_data_rt_list_updating_ex_containers(fqdn_rt->ex_data_rt, &exc_array);
	rules=ALLOC(struct FQDN_rule, rule_cnt);
	for(i=0; i<rule_cnt; i++)
	{
		rules[i]=*((struct FQDN_rule *)(EX_data_container_get_user_data(exc_array[i])));
		assert(rules[i].user_tag==exc_array[i]||rules[i].user_tag==NULL);
		rules[i].user_tag=exc_array[i];
	}
	if(rule_cnt>0)
	{		
		new_fqdn_engine=FQDN_engine_new(rules, rule_cnt);
		if(!new_fqdn_engine)
		{
			ret=-1;
		}
	}
	old_fqdn_engine=fqdn_rt->fqdn_engine;	
	fqdn_rt->fqdn_engine=new_fqdn_engine;
	Maat_garbage_bagging(table_rt->ref_garbage_bin, old_fqdn_engine, (void (*)(void*))FQDN_engine_free);
	EX_data_rt_update_commit(fqdn_rt->ex_data_rt);
	table_rt->origin_rule_num=EX_data_rt_get_ex_container_count(fqdn_rt->ex_data_rt);
	
	free(rules);
	free(exc_array);	
	table_rt->fqdn_plugin.changed_flag=0;
	return ret;
}
struct EX_data_rt *Maat_table_runtime_get_EX_data_rt(struct Maat_table_runtime* table_rt)
{
	struct EX_data_rt *rt=NULL;
	
	switch(table_rt->table_type)
	{
		case	TABLE_TYPE_PLUGIN:
			rt=table_rt->plugin.ex_data_rt;
			break;
		case	TABLE_TYPE_IP_PLUGIN:
			rt=table_rt->ip_plugin.ex_data_rt;
			break;
		case	TABLE_TYPE_FQDN_PLUGIN:
			rt=table_rt->fqdn_plugin.ex_data_rt;
			break;
		case	TABLE_TYPE_BOOL_PLUGIN:
			rt=table_rt->bool_plugin.ex_data_rt;
			break;
		default:
			break;
	}
	return rt;
}
int Maat_table_runtime_commit_EX_data_schema(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, void* logger)
{
	size_t i=0;
	const char* row=NULL;
	assert(table_rt->table_type==table_schema->table_type);
	struct EX_data_rt *ex_data_rt=NULL;
	struct EX_data_schema *ex_data_schema=Maat_table_schema_get_EX_data_schema(table_schema);
	ex_data_rt=Maat_table_runtime_get_EX_data_rt(table_rt);
	EX_data_rt_set_schema(ex_data_rt, ex_data_schema);
	for(i=0; i<EX_data_rt_get_cached_row_num(ex_data_rt); i++)
	{
		row=EX_data_rt_cached_row_get(ex_data_rt, i);
		switch(table_rt->table_type)
		{
			case	TABLE_TYPE_PLUGIN:
				Maat_table_runtime_plugin_new_row(table_rt, table_schema, row, logger);
				break;
			case	TABLE_TYPE_IP_PLUGIN:
				Maat_table_runtime_ip_plugin_new_row(table_rt, table_schema, row, logger);
				break;
			case	TABLE_TYPE_FQDN_PLUGIN:
				Maat_table_runtime_fqdn_plugin_new_row(table_rt, table_schema, row, logger);				
				break;
			case	TABLE_TYPE_BOOL_PLUGIN:
				Maat_table_runtime_bool_plugin_new_row(table_rt, table_schema, row, logger);
				break;
			default:
				break;
		}
	}
	EX_data_rt_clear_row_cache(ex_data_rt);
	switch(table_rt->table_type)
	{
		case	TABLE_TYPE_PLUGIN:
			Maat_table_runtime_plugin_commit_update(table_rt);
			break;
		case	TABLE_TYPE_IP_PLUGIN:
			Maat_table_runtime_ip_plugin_commit_update(table_rt);
			break;
		case	TABLE_TYPE_FQDN_PLUGIN:
			Maat_table_runtime_fqdn_plugin_commit_update(table_rt);
			break;
		case	TABLE_TYPE_BOOL_PLUGIN:
			Maat_table_runtime_bool_plugin_commit_update(table_rt);
			break;
		default:
			break;
	}
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

void Maat_table_runtime_bool_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger)
{
	struct bool_plugin_table_schema *bool_plugin_schema=&(table_schema->bool_plugin);
	struct bool_plugin_runtime *bool_plugin_rt=&(table_rt->bool_plugin);
	size_t is_valid_offset=0, valid_len=0;
	size_t row_id_offset=0, row_id_len=0;
	size_t bool_expr_offset=0, bool_expr_len=0;
	struct bool_expr *expr=NULL;
	int ret=0;
	unsigned long long item_id[MAX_ITEMS_PER_BOOL_EXPR];
	size_t n_item=0;
	if(bool_plugin_schema->ex_schema.set_flag)
	{
		ret=Maat_helper_read_column(row, bool_plugin_schema->valid_flag_column, &is_valid_offset, &valid_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"bool_plugin EX data process error: cannot find is_valid column %d of %s",
									bool_plugin_schema->valid_flag_column, row);
			return;
		}
		ret=Maat_helper_read_column(row, bool_plugin_schema->row_id_column, &row_id_offset, &row_id_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"bool_plugin EX data process error: cannot find row id column %d of %s",
									bool_plugin_schema->row_id_column, row);
			return;
		}
		ret=Maat_helper_read_column(row, bool_plugin_schema->bool_expr_column, &bool_expr_offset, &bool_expr_len);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"bool_plugin EX data process error: cannot find bool_expr column %d of %s",
									bool_plugin_schema->bool_expr_column, row);
			return;
		}
		char *token=NULL, *sub_token=NULL, *saveptr;
		char expr_buffer[256];
		memset(expr_buffer, 0, sizeof(expr_buffer));
		memcpy(expr_buffer, row+bool_expr_offset, bool_expr_len);
		for (token = expr_buffer; ; token= NULL)
		{
			sub_token= strtok_r(token, "&", &saveptr);
			if (sub_token == NULL)
				break;
			ret=sscanf(sub_token, "%llu", item_id+n_item);
			n_item++;
			if(ret!=1||n_item>MAX_ITEMS_PER_BOOL_EXPR)
			{
				MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
										"bool_plugin EX data process error: invalid format of bool_expr column %d of %s",
										bool_plugin_schema->bool_expr_column, row);
				return;
			}
		}
		if(atoi(row+is_valid_offset)==1)//add
		{
			expr=bool_expr_new((unsigned int)atoi(row+row_id_offset), item_id, n_item);
			ret=EX_data_rt_row2EX_data(bool_plugin_rt->ex_data_rt, row, row+row_id_offset, row_id_len, expr, logger);
			if(ret<0)
			{
				bool_expr_free(expr);
				expr=NULL;
			}
		}
		else
		{
			EX_data_rt_delete_by_row(bool_plugin_rt->ex_data_rt, row, row+row_id_offset, row_id_len, logger);
		}		
	}
	else
	{
		EX_data_rt_cache_row_put(bool_plugin_rt->ex_data_rt, row);
		table_rt->origin_rule_num=EX_data_rt_get_cached_row_num(bool_plugin_rt->ex_data_rt);
	}
	bool_plugin_rt->changed_flag=1;
	return;
}
int Maat_table_runtime_bool_plugin_commit_update(struct Maat_table_runtime* table_rt)
{
	struct bool_matcher* new_bool_matcher=NULL, *old_bool_matcher=NULL;
	struct 	bool_plugin_runtime* bool_plugin_rt=&table_rt->bool_plugin;
	assert(table_rt->table_type==TABLE_TYPE_BOOL_PLUGIN);
	struct EX_data_container **exc_array=NULL;
	struct bool_expr* exprs=NULL;
	size_t expr_cnt=0, i=0, ret=0, mem_usage=0;
	if(!bool_plugin_rt->changed_flag)
	{
		return ret;
	}
	expr_cnt=EX_data_rt_list_updating_ex_containers(bool_plugin_rt->ex_data_rt, &exc_array);
	exprs=ALLOC(struct bool_expr, expr_cnt);
	for(i=0; i<expr_cnt; i++)
	{
		exprs[i]=*((struct bool_expr *)(EX_data_container_get_user_data(exc_array[i])));
		assert(exprs[i].user_tag==exc_array[i]||exprs[i].user_tag==NULL);
		exprs[i].user_tag=exc_array[i];
	}
	if(expr_cnt>0)
	{		
		new_bool_matcher=bool_matcher_new(exprs, expr_cnt, &mem_usage);
		if(!new_bool_matcher)
		{
			ret=-1;
		}
	}
	old_bool_matcher=bool_plugin_rt->matcher;	
	bool_plugin_rt->matcher=new_bool_matcher;
	Maat_garbage_bagging(table_rt->ref_garbage_bin, old_bool_matcher, (void (*)(void*))bool_matcher_free);
	EX_data_rt_update_commit(bool_plugin_rt->ex_data_rt);
	table_rt->origin_rule_num=EX_data_rt_get_ex_container_count(bool_plugin_rt->ex_data_rt);
	
	free(exprs);
	free(exc_array);	
	table_rt->fqdn_plugin.changed_flag=0;
	return ret;
}

int Maat_table_runtime_bool_plugin_get_N_ex_data(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, unsigned long long item_ids[], size_t n_item, MAAT_PLUGIN_EX_DATA* ex_data_array, size_t size)
{
	struct bool_expr_match results[size];
	int n_result=0;
	if(table_rt->table_type!=TABLE_TYPE_BOOL_PLUGIN)
	{
		return -1;
	}
	if(!table_rt->bool_plugin.matcher)
	{
		return 0;
	}
	n_item=ull_dedup(item_ids, n_item);

	n_result=bool_matcher_match(table_rt->bool_plugin.matcher,  item_ids, n_item, results, size);
	for(int i=0; i<n_result; i++)
	{
		ex_data_array[i]=EX_data_rt_get_EX_data_by_container(table_rt->bool_plugin.ex_data_rt, (struct EX_data_container *)results[i].user_tag);
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

int Maat_table_runtime_flag_commit_update(struct Maat_table_runtime *table_rt, void *logger)
{
    int ret = 0;
    void **rule_array = NULL;
    struct flag_rule *rules = NULL;
    struct flag_runtime *flag_rt = &(table_rt->flag);
    assert(table_rt->table_type==TABLE_TYPE_FLAG);

    int updating_flag = rcu_hash_is_updating(flag_rt->htable);
    if (0 == updating_flag) {
        return 0;
    }

    rcu_hash_commit(flag_rt->htable);

    size_t rule_cnt = rcu_hash_list(flag_rt->htable, &rule_array);
    MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_module,
										"new_flag_matcher commit rule_cnt:%zu", rule_cnt);
    if (rule_cnt > 0) {
        rules = ALLOC(struct flag_rule, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            rules[i] = *(struct flag_rule *)rule_array[i];
        }
    }

    struct flag_matcher *new_flag_matcher = NULL;
    struct flag_matcher *old_flag_matcher = NULL;
    
    new_flag_matcher = flag_matcher_new(rules, rule_cnt);
	if(!new_flag_matcher)
	{
		ret = -1;
	}
	
	old_flag_matcher = flag_rt->matcher;
	flag_rt->matcher = new_flag_matcher;
    
    if (old_flag_matcher != NULL) 
    {
        Maat_garbage_bagging(table_rt->ref_garbage_bin, old_flag_matcher, (void (*)(void*))flag_matcher_free);
    }
	
	table_rt->origin_rule_num=rcu_hash_count(flag_rt->htable);

    if (rules != NULL) {
        free(rules);
        rules = NULL;
    }
	
    if (rule_array != NULL) {
        free(rule_array);
	    rule_array=NULL;
    }

	return ret;
}

int Maat_table_runtime_ip_plugin_commit_update(struct Maat_table_runtime* table_rt)
{
	struct ip_matcher* new_ip_matcher=NULL, *old_ip_matcher=NULL;
	size_t rule_cnt=0;
	size_t i=0;
	struct ip_rule *rules=NULL;
	struct EX_data_container **exc_array=NULL;
	struct ip_plugin_runtime *ip_plugin=&(table_rt->ip_plugin);
	int ret=0;
	assert(table_rt->table_type==TABLE_TYPE_IP_PLUGIN);
	if(!ip_plugin->changed_flag)
	{
		return ret;
	}
	rule_cnt=EX_data_rt_list_updating_ex_containers(ip_plugin->ex_data_rt, &exc_array);
	rules=ALLOC(struct ip_rule, rule_cnt);
	for(i=0; i<rule_cnt; i++)
	{
		rules[i]=*((struct ip_rule *)(EX_data_container_get_user_data(exc_array[i])));
		assert(rules[i].user_tag==exc_array[i]||rules[i].user_tag==NULL);
		rules[i].user_tag=exc_array[i];
	}
	if(rule_cnt>0)
	{
		new_ip_matcher=ip_matcher_new(rules, rule_cnt, &ip_plugin->mem_use_by_ip_matcher);
		if(!new_ip_matcher)
		{
			ret=-1;
		}
	}
	old_ip_matcher=ip_plugin->ip_matcher;
	ip_plugin->ip_matcher=new_ip_matcher;
	Maat_garbage_bagging(table_rt->ref_garbage_bin, old_ip_matcher, (void (*)(void*))ip_matcher_free);
	EX_data_rt_update_commit(ip_plugin->ex_data_rt);
	table_rt->origin_rule_num=EX_data_rt_get_ex_container_count(ip_plugin->ex_data_rt);

	free(rules);
	free(exc_array);
	exc_array=NULL;
	ip_plugin->changed_flag=0;
	return ret;
}

void Maat_table_runtime_ip_plugin_new_row(struct Maat_table_runtime* table_rt, struct Maat_table_schema* table_schema, const char* row, void *logger)
{
	struct ip_plugin_table_schema* ip_plugin_schema=&(table_schema->ip_plugin);
	struct ip_plugin_runtime* ip_plugin_rt=&(table_rt->ip_plugin);
	size_t is_valid_offset=0, valid_len=0;
	size_t row_id_offset=0, row_id_len=0;
	struct ip_rule* ip_rule=NULL;
	int ret=0;	
	if(ip_plugin_schema->ex_schema.set_flag)
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
			ret=EX_data_rt_row2EX_data(ip_plugin_rt->ex_data_rt, row, row+row_id_offset, row_id_len, ip_rule, logger);
			if(ret<0)
			{
				ip_rule_free(ip_rule);
				ip_rule=NULL;
			}
		}
		else
		{
		
			ret=EX_data_rt_delete_by_row(ip_plugin_rt->ex_data_rt, row, row+row_id_offset, row_id_len, logger);
			ip_rule_free(ip_rule);
			ip_rule=NULL;
		}		
	}
	else
	{
		EX_data_rt_cache_row_put(ip_plugin_rt->ex_data_rt, row);
		table_rt->origin_rule_num=EX_data_rt_get_cached_row_num(ip_plugin_rt->ex_data_rt);
	}
	ip_plugin_rt->changed_flag=1;
	return;
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


