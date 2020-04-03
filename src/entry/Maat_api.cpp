#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <MESA/MESA_handle_logger.h>

#include "rulescan.h"
#include "bool_matcher.h"
#include "Maat_rule.h"
#include "Maat_rule_internal.h"
#include "Maat_utils.h"
#include "dynamic_array.h"
#include "alignment_int64.h"
#include "config_monitor.h"
#include "map_str2int.h"
#include "rulescan.h"
#include "json2iris.h"


inline void INC_SCANNER_REF(Maat_scanner*scanner,int thread_num)
{
	alignment_int64_array_add(scanner->ref_cnt, thread_num, 1);
	return;
}
inline void DEC_SCANNER_REF(Maat_scanner*scanner,int thread_num)
{

	alignment_int64_array_add(scanner->ref_cnt, thread_num, -1);
	return;
}

inline int scan_status_should_compile_NOT(struct _OUTER_scan_status_t* _mid)
{
	if( _mid &&
		_mid->is_last_region==1 &&
		_mid->inner &&
		_mid->inner->not_grp_compile_hitted_flag)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
int exprid2region_id(struct Maat_group_inner* group_rule, int expr_id, int* district_id, struct Maat_scanner* scanner)
{
	int region_id=-1;
	struct Maat_region_inner* region_rule=NULL;
	assert(group_rule->group_id>=0);
	int array_idx=(int)(long)HASH_fetch_by_id(scanner->exprid_hash, expr_id);
	pthread_mutex_lock(&(group_rule->mutex));	
	assert(array_idx<group_rule->region_boundary);
	region_rule=(struct Maat_region_inner*)dynamic_array_read(group_rule->regions, array_idx);
	if(region_rule)
	{
		assert(expr_id>=region_rule->expr_id_lb&&expr_id<=region_rule->expr_id_ub);
		region_id=region_rule->region_id;
		*district_id=region_rule->district_id;
	}
	pthread_mutex_unlock(&(group_rule->mutex));
	return region_id;
}

//return 1 if insert a unique id
//return 0 if id is duplicated
//return -1 if set is full
int insert_set_id(unsigned long long **set, size_t* size, size_t cnt, unsigned long long id)
{
	size_t i=0;
	for(i=0; i<cnt; i++)
	{
		if((*set)[i]==id)
		{
			break;
		}
	}
	if(i==cnt)
	{
		if(cnt==*size)
		{
			*size+=16;
			*set=(unsigned long long*)realloc(*set, (*size)*sizeof(unsigned long long));
		}
		(*set)[cnt]=id;
		return 1;
	}
	else
	{
		return 0;
	}
}

void fill_maat_rule(struct Maat_rule_t *rule, const struct Maat_rule_head* rule_head, const char* srv_def, int srv_def_len)
{
	memcpy(rule, rule_head, sizeof(struct Maat_rule_head));
	memcpy(rule->service_defined, srv_def, MIN(srv_def_len, MAX_SERVICE_DEFINE_LEN));
	return;
}
struct compile_sort_para
{
	double evaluation_order;
	int group_cnt;
	int compile_id;
	void* user;
};
static void compile_sort_para_set(struct compile_sort_para* para, const struct Maat_compile_group_relation* compile_relation, void* user)
{
	para->compile_id=compile_relation->compile_id;
	para->evaluation_order=compile_relation->compile->evaluation_order;
	para->group_cnt=compile_relation->group_cnt;
	para->user=user;
	return;
}
static int compile_sort_para_compare(const struct compile_sort_para* a, const struct compile_sort_para* b)
{
	//If both of compile rule's evaluation order are specified, compile rule with small evaluation order is priority.
	if(a->evaluation_order!=0 && b->evaluation_order!=0)
	{
		if(a->evaluation_order - b->evaluation_order <0)
		{
			return -1;
		}
		else if(a->evaluation_order - b->evaluation_order >0)
		{
			return 1;
		}
	}
	//If one of compile rule's evaluation order is zero, compile rule with big evaluation order is priority.
	else if(a->evaluation_order + b->evaluation_order!= 0)
	{
		return (a->evaluation_order - b->evaluation_order >0) ? -1 : 1;
	}
	//If compile rule's execute sequences are not specified or equal.
	if(a->group_cnt!=b->group_cnt)
	{
		return (a->group_cnt-b->group_cnt);
	}
	else
	{
		return (b->compile_id-a->compile_id);
	}

}
static int compare_compile_inner(const void *a, const void *b)
{
	const struct Maat_compile_group_relation *ra=*(const struct Maat_compile_group_relation **)a;
	const struct Maat_compile_group_relation *rb=*(const struct Maat_compile_group_relation **)b;
	
	struct compile_sort_para sa, sb;
	compile_sort_para_set(&sa, ra, NULL);
	compile_sort_para_set(&sb, rb, NULL);

	return compile_sort_para_compare(&sa, &sb);
}
static int compile_sort_para_compare_no_type(const void* a, const void* b)
{
	return compile_sort_para_compare((const struct compile_sort_para*) a, (const struct compile_sort_para*) b);

}
size_t Maat_rule_sort_by_evaluation_order(Maat_feather_t feather, struct Maat_rule_t* rule_array, size_t n_rule)
{
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	struct compile_sort_para sort_para[n_rule];
	struct Maat_rule_t copy_rule_array[n_rule];
	
	memcpy(copy_rule_array, rule_array, sizeof(struct Maat_rule_t)*n_rule);

	struct Maat_compile_group_relation *p=NULL;

	size_t i=0, j=0;
	for(i=0; i<n_rule; i++)
	{
		p=(struct Maat_compile_group_relation *)HASH_fetch_by_id(_feather->scanner->compile_hash, rule_array[i].config_id);
		if(p && 0==pthread_rwlock_tryrdlock(&(p->rwlock)))//rule maybe already deleted.
		{
			compile_sort_para_set(sort_para+i, p, copy_rule_array+i);
			j++;
			pthread_rwlock_unlock(&(p->rwlock));
		}
	}
	qsort(sort_para, j, sizeof(struct compile_sort_para),
			  compile_sort_para_compare_no_type);
	for(i=0; i<j; i++)
	{
		memcpy(rule_array+i, sort_para[i].user, sizeof(struct Maat_rule_t));
	}
	return j;

}
struct scan_region_hit_wraper
{
	int Nth_scan;
	void* elem_array;
	int* virtual_table_ids;
	size_t elem_size;
	size_t n_elem;
	size_t group_offset;
	size_t expr_id_offset;
	int virtual_table_id;
	int is_last_region;
};

struct scan_hit_status* scan_hit_status_new(void)
{
	struct scan_hit_status* inner_mid=NULL;
	inner_mid=ALLOC(struct scan_hit_status, 1);
	TAILQ_INIT(&inner_mid->hit_path_qhead);
	return inner_mid;
}
void scan_hit_status_free(struct scan_hit_status* p)
{
	struct Maat_hit_path_inner * tmp = TAILQ_FIRST(&p->hit_path_qhead);
	while(tmp != NULL)
	{
		TAILQ_REMOVE(&p->hit_path_qhead, tmp, entries);
		free(tmp);
		p->hit_path_cnt--;
		tmp = TAILQ_FIRST(&p->hit_path_qhead);
	}
	assert(p->hit_path_cnt==0);
	free(p->all_hit_group_array);
	p->all_hit_group_array=NULL;
	free(p);
}
void hit_path_init(struct Maat_hit_path_t* hit_path)
{
	hit_path->Nth_scan=-1;
	hit_path->region_id=-1;
	hit_path->sub_group_id=-1;
	hit_path->top_group_id=-1;
	hit_path->virtual_table_id=-1;
	hit_path->compile_id=-1;
}
size_t scan_hit_status_select_hit_path_inner(const struct hit_path_q *hit_path_qhead, struct Maat_hit_path_t* condition, 
															struct Maat_hit_path_inner* hit_paths, size_t n_path)
{
	struct Maat_hit_path_inner* p=NULL;
	size_t i=0;
	TAILQ_FOREACH(p, hit_path_qhead, entries)
	{
		if((condition->compile_id==p->path.compile_id||condition->compile_id<0)
			&& (condition->Nth_scan==p->path.Nth_scan||condition->Nth_scan<0)
			&& (condition->region_id=p->path.region_id||condition->region_id<0)
			&& (condition->sub_group_id=p->path.sub_group_id||condition->sub_group_id<0)
			&& (condition->top_group_id=p->path.top_group_id||condition->top_group_id<0))
		{
			if(i<n_path)
			{
				hit_paths[i]=*p;
				i++;
			}
			else if(hit_paths==NULL)//count only
			{
				i++;
			}
		}

	}
	return i;

}

void scan_hit_status_update_by_group(struct scan_hit_status* hit_status, struct Maat_group_inner* group_rule, int region_id, int virtual_table_id, int Nth_scan, int Nth_region_result)
{
	size_t i=0;
	int ret=0;
	struct Maat_hit_path_inner* hit_path=NULL;

	if(group_rule->top_group_cnt==0)
	{
		hit_path=ALLOC(struct Maat_hit_path_inner, 1);
		hit_path_init(&(hit_path->path));
		hit_path->Nth_hit_region=Nth_region_result;
		hit_path->path.Nth_scan=Nth_scan;
		hit_path->path.region_id=region_id;
		hit_path->path.sub_group_id=group_rule->group_id;
		hit_path->path.virtual_table_id=virtual_table_id;
		TAILQ_INSERT_TAIL(&hit_status->hit_path_qhead, hit_path, entries);
		hit_status->hit_path_cnt++;
	}
	else
	{
		for(i=0; i<group_rule->top_group_cnt; i++)
		{
			hit_path=ALLOC(struct Maat_hit_path_inner, 1);
			hit_path_init(&(hit_path->path));
			hit_path->Nth_hit_region=Nth_region_result;
			hit_path->path.Nth_scan=Nth_scan;
			hit_path->path.region_id=region_id;
			hit_path->path.sub_group_id=group_rule->group_id;
			hit_path->path.top_group_id=group_rule->top_groups[i];
			hit_path->path.virtual_table_id=virtual_table_id;
			TAILQ_INSERT_TAIL(&hit_status->hit_path_qhead, hit_path, entries);
			hit_status->hit_path_cnt++;
			ret=insert_set_id(&(hit_status->all_hit_group_array),
								&(hit_status->all_hit_group_array_sz),
								hit_status->all_hit_group_cnt,
								TO_RELATION_ID(virtual_table_id, group_rule->top_groups[i]));
			hit_status->all_hit_group_cnt+=ret;
		}
	}
	return;
}
size_t scan_hit_status_update_by_compile(struct scan_hit_status* hit_status, struct Maat_compile_group_relation* compile_rule, int Nth_scan)
{
	size_t i=0, j=0;
	struct Maat_hit_path_inner* p=NULL, *q=NULL;
	struct bool_expr a_set;
	unsigned char has_not=0;

	struct Maat_hit_path_t condition;
	size_t n_exsited_path=0;
	struct hit_path_q shared_path_qhead;
	TAILQ_INIT(&shared_path_qhead);
	make_group_set(compile_rule, &a_set, &has_not);
	for(i=0; i<a_set.item_num; i++)
	{
		TAILQ_FOREACH(p, &hit_status->hit_path_qhead, entries)
		{
			if(TO_RELATION_ID(p->path.virtual_table_id, p->path.top_group_id)==a_set.items[i].item_id
				&& p->path.compile_id!=compile_rule->compile_id)
			{
				if(p->path.compile_id<0)
				{
					p->path.compile_id=compile_rule->compile_id;
				}
				else	//current path already have a compile as endpoint, so we duplicate a new path.
				{
					condition=p->path;
					condition.compile_id=compile_rule->compile_id;
					n_exsited_path=scan_hit_status_select_hit_path_inner(&shared_path_qhead, &condition, NULL, 0);
					if(n_exsited_path==0)
					{
						q=ALLOC(struct Maat_hit_path_inner, 1);
						*q=*p;
						q->path.compile_id=compile_rule->compile_id;
						TAILQ_INSERT_TAIL(&shared_path_qhead, q, entries);
						hit_status->hit_path_cnt++;
					}
				}
				if(p->path.Nth_scan==Nth_scan && n_exsited_path==0)//Compile was satisfied by new region hits.
				{
					j++;
				}
			}		
		}
	}
	p = TAILQ_FIRST(&shared_path_qhead);
	while(p != NULL)
	{
		TAILQ_REMOVE(&shared_path_qhead, p, entries);
		TAILQ_INSERT_TAIL(&hit_status->hit_path_qhead, p, entries);
		p = TAILQ_FIRST(&shared_path_qhead);
	}	
	return j;
}

size_t scan_hit_status_read_group_ids(const struct scan_hit_status* hit_status, const unsigned long long** const grp_ids)
{
	*grp_ids=hit_status->all_hit_group_array;
	return hit_status->all_hit_group_cnt;
}


void scan_region_hit_wraper_build_with_rulescan(struct scan_region_hit_wraper* region_hit, scan_result_t* rulescan_rslt, size_t n_rslt, int is_last_region, int virtual_table_id, int Nth_scan)
{
	memset(region_hit, 0, sizeof(struct scan_region_hit_wraper));
	region_hit->elem_array=rulescan_rslt;
	region_hit->n_elem=n_rslt;
	region_hit->elem_size=sizeof(scan_result_t);
	region_hit->expr_id_offset=offsetof(scan_result_t, expr_id);
	region_hit->group_offset=offsetof(scan_result_t, tag);
	region_hit->is_last_region=is_last_region;
	region_hit->virtual_table_id=virtual_table_id;
	region_hit->Nth_scan=Nth_scan;
	region_hit->virtual_table_ids=NULL;
	return;
}
void scan_region_hit_wraper_build_with_GIE(struct scan_region_hit_wraper* region_hit, GIE_result_t* GIE_rslt, size_t n_rslt, int is_last_region, int virtual_table_id, int Nth_scan)
{
	memset(region_hit, 0, sizeof(struct scan_region_hit_wraper));
	region_hit->elem_array=GIE_rslt;
	region_hit->n_elem=n_rslt;
	region_hit->elem_size=sizeof(GIE_result_t);
	region_hit->expr_id_offset=offsetof(GIE_result_t, id);
	region_hit->group_offset=offsetof(GIE_result_t, tag);
	region_hit->is_last_region=is_last_region;
	region_hit->virtual_table_id=virtual_table_id;
	region_hit->Nth_scan=Nth_scan;
	region_hit->virtual_table_ids=NULL;
	return;
}

int region_compile(_Maat_feather_t*feather, struct scan_hit_status *_mid, const struct scan_region_hit_wraper* region_hit_wraper, struct Maat_rule_t* result, int size,int thread_num)
{
	int is_last_region=region_hit_wraper->is_last_region;
	void* region_hit=region_hit_wraper->elem_array;
	size_t region_type_size=region_hit_wraper->elem_size;
	size_t expr_id_offset=region_hit_wraper->expr_id_offset;
	size_t group_offset=region_hit_wraper->group_offset;
	size_t region_hit_num=region_hit_wraper->n_elem;

	unsigned int expr_id=0;
	int region_id=0;
	int scan_ret=0, result_cnt=0;
	int tmp=0;
	size_t i=0;
	size_t r_in_c_cnt=0;
	struct bool_matcher* bm=feather->scanner->bool_matcher_expr_compiler;
	struct Maat_group_inner* group_rule=NULL;
	struct Maat_compile_group_relation* relation_array[MAX_SCANNER_HIT_NUM];
	struct Maat_compile_group_relation* relation=NULL;
	int virtual_table_id=0;
	const unsigned long long* hit_group_ids=NULL;
	size_t hit_group_id_cnt=0;

	for(i=0;i<region_hit_num;i++)
	{
		group_rule=*(struct Maat_group_inner**)((char*)region_hit+region_type_size*i+group_offset);
		if(group_rule->group_id<0)
		{
			continue;
		}
		assert(group_rule->ref_by_children_cnt>=0);
		assert(group_rule->ref_by_parent_cnt>=0);
		expr_id=*(unsigned int*)((char*)region_hit+region_type_size*i+expr_id_offset);
		region_id=exprid2region_id(group_rule, expr_id, &tmp, feather->scanner);
		if(region_hit_wraper->virtual_table_ids)
		{
			virtual_table_id=region_hit_wraper->virtual_table_ids[i];
		}
		else
		{
			virtual_table_id=region_hit_wraper->virtual_table_id;
		}
		scan_hit_status_update_by_group(_mid, group_rule, region_id, 
									virtual_table_id, region_hit_wraper->Nth_scan, i);
	}

	if(bm)
	{
		hit_group_id_cnt=scan_hit_status_read_group_ids(_mid, &hit_group_ids);
		scan_ret=bool_matcher_match(bm, thread_num, 
								hit_group_ids, hit_group_id_cnt,
								(void **)relation_array, MAX_SCANNER_HIT_NUM);
	}
	else
	{
		scan_ret=0;
	}
	if(scan_ret>1)
	{
		qsort(relation_array, scan_ret, sizeof(struct Maat_compile_group_relation*),
			  compare_compile_inner);
	}
	for(i=0; i<(unsigned int)scan_ret&&result_cnt<size; i++)
	{
		relation=relation_array[i];
		if(relation==NULL)
		{
			continue;
		}
		assert(relation->magic_num==COMPILE_RELATION_MAGIC);
		if(0==pthread_rwlock_tryrdlock(&(relation->rwlock)))
		{
			if(relation->compile)
			{			
				if(relation->not_group_cnt>0 && !is_last_region)
				{
					_mid->not_grp_compile_hitted_flag=1;
				}
				else
				{
					r_in_c_cnt=scan_hit_status_update_by_compile(_mid, relation, region_hit_wraper->Nth_scan);
					if(r_in_c_cnt>0 ||	//compile hitted becasue of new reigon
					region_hit_num==0)	//or hit a compile that refer a NOT-logic group in previous scan.
					{
						fill_maat_rule(&(result[result_cnt]), &(relation->compile->head),
									relation->compile->service_defined, relation->compile->head.serv_def_len);
						result_cnt++;
					}
				}		
			}	
			pthread_rwlock_unlock(&(relation->rwlock));
		}		
	}	

	if(result_cnt>0)
	{
		alignment_int64_array_add(feather->hit_cnt, thread_num, 1);
	}
	if(region_hit_num==0&&result_cnt>0)
	{
		alignment_int64_array_add(feather->not_grp_hit_cnt, thread_num, 1);

	}
	return result_cnt;
}


int match_district(struct _OUTER_scan_status_t *_mid,scan_result_t *region_hit,int region_hit_num, Maat_scanner* scanner)
{
	struct Maat_group_inner* group_rule=NULL;
	int i=0;
	int district_id=-1,region_id=-1;
	int ret_region_num=region_hit_num;
	while(i<ret_region_num)
	{
		group_rule=(struct Maat_group_inner*)(region_hit[i].tag);
		region_id=exprid2region_id(group_rule, region_hit[i].expr_id,&district_id, scanner);
		if(region_id>0&&district_id!=_mid->district_id)
		{
			ret_region_num--;
			memmove(&(region_hit[i]),&(region_hit[i+1]),sizeof(scan_result_t)*(ret_region_num-i));
		}
		else
		{
			i++;
		}
	}
	return ret_region_num;
}


int fill_regex_pos(struct regex_pos_t *regex_pos,int size,rule_result_t *rs_result,const char* buff)
{
	int i=0,j=0;
	int group_num=rs_result->group_num;
	unsigned int * position=rs_result->position;
	unsigned int * length=rs_result->length;
	regex_pos->group_num=group_num;
	for(i=0;i<(int)rs_result->result_num&&i<size;i++)
	{
		if((group_num+1)*i>MAX_MATCH_POS_NUM)
		{
			break;
		}
		regex_pos[i].hitting_regex_pos=buff+position[(group_num+1)*i];
		regex_pos[i].hitting_regex_len=length[(group_num+1)*i];
		for(j=0;j<group_num&&j<MAAT_MAX_REGEX_GROUP_NUM;j++)
		{
			if((group_num+1)*i+j+1>MAAT_MAX_REGEX_GROUP_NUM)
			{
				break;
			}
			regex_pos[i].grouping_pos[j]=buff+position[(group_num+1)*i+j+1];
			regex_pos[i].grouping_len[j]=length[(group_num+1)*i+j+1];
		}
	}
	return i;
}
int fill_substr_pos(struct str_pos_t* str_pos,int size,rule_result_t *rs_result,const char* buff)
{
	int i=0;
	unsigned int * position=rs_result->position;
	unsigned int * length=rs_result->length;
	for(i=0;i<(int)rs_result->result_num&&i<size;i++)
	{
		if(i>MAX_MATCH_POS_NUM)
		{
			break;
		}
		str_pos[i].hit_pos=buff+position[i];
		str_pos[i].hit_len= length[i];
	}
	return i;
}
int hit_pos_RS2Maat(struct sub_item_pos_t* maat_sub_item,int size,rule_result_t* rs_result,int rs_cnt,const char* buff)
{
	int k=0;
	for(k=0;k<rs_cnt&&k<size;k++)
	{
		switch(rs_result[k].rule_type)
		{

			case	RULETYPE_STR:
				maat_sub_item[k].ruletype=MAAT_POSTYPE_EXPR;
				maat_sub_item[k].hit_cnt=fill_substr_pos(maat_sub_item[k].substr_pos, MAAT_MAX_HIT_POS_NUM, &(rs_result[k]),buff);
				break;
			case	RULETYPE_REG:
				maat_sub_item[k].ruletype=MAAT_POSTYPE_REGEX;
				maat_sub_item[k].hit_cnt=fill_regex_pos(maat_sub_item[k].regex_pos, MAAT_MAX_HIT_POS_NUM, &(rs_result[k]),buff);
				break;
			default:
				assert(0);

		}
	}
	return k;
}
int fill_region_hit_detail(const char* scan_buff, const scan_hit_status* _mid,
							scan_result_t *region_hit, int region_cnt,
							struct Maat_rule_t* compile, int compile_cnt,
							int Nth_scan,
							struct Maat_hit_detail_t *hit_detail, int detail_num,
							struct Maat_scanner* scanner)
{
	int i=0;
	size_t j=0;
	char r_in_c_flag[region_cnt];
	int district_id=-1; //Indifference
	memset(r_in_c_flag, 0, sizeof(r_in_c_flag));
	
	struct Maat_group_inner* group_rule=NULL;


	struct Maat_hit_path_inner hit_paths[MAX_SCANNER_HIT_NUM];
	struct Maat_hit_path_t condition;
	size_t hit_path_cnt=0;
	int Nth_hit_region=0;
	
	//for each hitted compile cfg,find its region_ids
	for(i=0; i<compile_cnt&&i<detail_num; i++)
	{
		hit_detail[i].config_id=compile[i].config_id;
		hit_path_init(&condition);
		condition.Nth_scan=Nth_scan;
		condition.compile_id=compile[i].config_id;
		hit_path_cnt=scan_hit_status_select_hit_path_inner(&_mid->hit_path_qhead, &condition, hit_paths, MAX_SCANNER_HIT_NUM);
		for(j=0; j<hit_path_cnt && j<MAAT_MAX_HIT_RULE_NUM; j++)
		{		
			Nth_hit_region=hit_paths[j].Nth_hit_region;
			hit_detail[i].region_pos[j].region_id=hit_paths[j].path.region_id;
			hit_detail[i].region_pos[j].sub_item_num=region_hit[Nth_hit_region].rnum;
			hit_pos_RS2Maat(hit_detail[i].region_pos[j].sub_item_pos, MAAT_MAX_EXPR_ITEM_NUM,
							region_hit[Nth_hit_region].result, region_hit[Nth_hit_region].rnum, scan_buff);
			r_in_c_flag[Nth_hit_region]=1;
		}
		hit_detail[i].hit_region_cnt=j;
	}
	//for each region_ids, if belongs to no compile cfg, fill hit_detail as a half hit cfg
	for(j=0; j<(size_t)region_cnt && i<detail_num; j++)
	{
		if(r_in_c_flag[j]==0)
		{
			group_rule=(struct Maat_group_inner*)(region_hit[j].tag);
	 		hit_detail[i].config_id=-2;
			hit_detail[i].hit_region_cnt=1;
			hit_detail[i].region_pos[0].region_id=exprid2region_id(group_rule, region_hit[j].expr_id, &district_id, scanner);
			hit_detail[i].region_pos[0].sub_item_num=region_hit[j].rnum;
			hit_pos_RS2Maat(hit_detail[i].region_pos[0].sub_item_pos,MAAT_MAX_EXPR_ITEM_NUM,
						region_hit[j].result, region_hit[j].rnum, scan_buff);
			i++;
		}
	}
	return i;
}

struct _OUTER_scan_status_t* _make_outer_status(_Maat_feather_t *feather, int thread_num)
{
	struct _OUTER_scan_status_t* outer_mid=NULL;
	outer_mid=(struct _OUTER_scan_status_t*)calloc(sizeof(struct _OUTER_scan_status_t),1);
	outer_mid->feather=feather;
	outer_mid->district_id=-1;
	outer_mid->thread_num=(unsigned short)thread_num;
	alignment_int64_array_add(feather->outer_mid_cnt, thread_num,1);
	return outer_mid;
}
struct _OUTER_scan_status_t* grab_mid(scan_status_t* raw_mid,_Maat_feather_t* feather,int thread_num,int is_hit_region)
{
	struct _OUTER_scan_status_t* _mid=(struct _OUTER_scan_status_t*)(*raw_mid);;
	if(_mid==NULL)
	{
		_mid=_make_outer_status(feather, thread_num);
		*raw_mid=_mid;
	}

	if(is_hit_region==1)
	{
		if(_mid->inner==NULL)
		{
			_mid->inner=scan_hit_status_new();
			alignment_int64_array_add(feather->inner_mid_cnt,thread_num,1);
		}
	}
	return _mid;
}
int detain_last_data(char* buff,int buff_size,int detained_len,const char* data,int data_len, long* cache_offset)
{
	int to_copy_size=0,foward_offset=0;
	int ret_len;
	if(data_len<=buff_size-detained_len)
	{
		to_copy_size=data_len;
		memcpy(buff+detained_len,data,data_len);
		ret_len=detained_len+data_len;
	}
	else if(data_len>buff_size-detained_len&&data_len<buff_size)
	{
		foward_offset=detained_len+data_len-buff_size;
		to_copy_size=buff_size-data_len;
		memmove(buff,buff+foward_offset,to_copy_size);
		
		memcpy(buff+to_copy_size,data,data_len);
		ret_len=buff_size;
		*cache_offset+=foward_offset;
	}
	else//data_len>=buff_size
	{
		memcpy(buff,data+data_len-buff_size,buff_size);
		ret_len=buff_size;
		*cache_offset+=(data_len-buff_size+detained_len);
	}
	return ret_len;
}
int load_maat_json_file(_Maat_feather_t* feather, const char* maat_json_fn, char* err_str, size_t err_str_sz)
{
	int ret=0;
	struct stat fstat_buf;
	char* json_buff=NULL;
	size_t buff_sz=0;

	MESA_handle_runtime_log(feather->logger, RLOG_LV_INFO, maat_module ,
					"Maat initial with JSON file %s, formating..",
					maat_json_fn);
	if(strlen(feather->decrypt_key)&&strlen(feather->decrypt_algo))
	{
		ret=decrypt_open(maat_json_fn, feather->decrypt_key, feather->decrypt_algo, (unsigned char**)&json_buff, &buff_sz, err_str, err_str_sz);
	}
	if(json_buff==NULL)//decryption failed or no decryption.
	{	
		ret=load_file_to_memory(maat_json_fn, (unsigned char**)&json_buff, &buff_sz);
	}
	ret=json2iris(json_buff,
			maat_json_fn,
			feather->compile_tn, feather->group_tn,
			NULL,
			feather->json_ctx.iris_file,
			sizeof(feather->json_ctx.iris_file),
			strlen(feather->decrypt_key)?feather->decrypt_key:NULL,
			strlen(feather->decrypt_algo)?feather->decrypt_algo:NULL,
			feather->logger);
	free(json_buff);
	json_buff=NULL;
	if(ret<0)
	{
		return -1;
	}
	strncpy(feather->json_ctx.json_file, maat_json_fn, sizeof(feather->json_ctx.json_file));
	
	ret=stat(maat_json_fn, &fstat_buf);
	feather->json_ctx.last_md5_time=fstat_buf.st_ctim;
	
	md5_file(feather->json_ctx.json_file, feather->json_ctx.effective_json_md5);
	MESA_handle_runtime_log(feather->logger,RLOG_LV_INFO, maat_module,
					"JSON file %s md5: %s, generate index file %s OK.",
					feather->json_ctx.json_file,
					feather->json_ctx.effective_json_md5,
					feather->json_ctx.iris_file);
	feather->input_mode=SOURCE_JSON_FILE;

	return 0;	
}
Maat_feather_t Maat_feather(int max_thread_num,const char* table_info_path,void* logger)
{
	if(max_thread_num<=0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_module ,
						"Invalid max_thread_num=%d."
						,max_thread_num);
		return NULL;
	}
	_Maat_feather_t* feather=ALLOC(struct _Maat_feather_t, 1);
	feather->table_mgr=Maat_table_manager_create(table_info_path, logger);
	if(feather->table_mgr==NULL)
	{
		goto failed;
	}
	Maat_table_get_compile_table_name(feather->table_mgr, feather->compile_tn, sizeof(feather->compile_tn));
	Maat_table_get_group_table_name(feather->table_mgr, feather->group_tn, sizeof(feather->group_tn));
	
	feather->logger=logger;
	feather->scan_thread_num=max_thread_num;
	feather->garbage_q=MESA_lqueue_create(0,0);
	feather->effect_interval_ms=60*1000;
	feather->scan_interval_ms=1*1000;
	feather->rule_scan_type=2;
	feather->thread_call_cnt=alignment_int64_array_alloc(max_thread_num);
	feather->outer_mid_cnt=alignment_int64_array_alloc(max_thread_num);
	feather->inner_mid_cnt=alignment_int64_array_alloc(max_thread_num);
	feather->hit_cnt=alignment_int64_array_alloc(max_thread_num);
	feather->not_grp_hit_cnt=alignment_int64_array_alloc(max_thread_num);
	feather->maat_version=0;
	feather->last_full_version=0;
	feather->base_grp_seq=0;
	feather->base_rgn_seq=0;
	feather->AUTO_NUMBERING_ON=1;
	feather->backgroud_update_enabled=1;
	snprintf(feather->decrypt_algo, sizeof(feather->decrypt_algo), "aes-256-cbc");
	snprintf(feather->foreign_cont_dir, sizeof(feather->foreign_cont_dir), "%s_files", table_info_path);
	pthread_mutex_init(&(feather->background_update_mutex),NULL);
	snprintf(feather->table_info_fn,sizeof(feather->table_info_fn),"%s",table_info_path);
	return feather;
failed:
	free(feather);
	return NULL;
}
int Maat_set_feather_opt(Maat_feather_t feather,enum MAAT_INIT_OPT type,const void* value,int size)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;	
	int intval=0,ret=-1;
	char err_str[MAX_TABLE_NAME_LEN];
	switch(type)
	{
		case MAAT_OPT_ENABLE_UPDATE:
			intval=*((int*)value);
			if(_feather->backgroud_update_enabled!=intval)
			{
				if(intval==0)
				{
					pthread_mutex_lock(&(_feather->background_update_mutex));
					MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module ,
							"Background update is disabled, current version %lld."
							,_feather->maat_version);
				}
				else
				{
					pthread_mutex_unlock(&(_feather->background_update_mutex));
					MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module ,
							"Background update is enabled, current version %lld."
							,_feather->maat_version);
				}
				_feather->backgroud_update_enabled=intval;
			}
			else
			{
				MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module ,
						"Duplicated operation, background update is ALREADY %s, current version %lld."
						,_feather->backgroud_update_enabled?"enabled":"disabled"
						,_feather->maat_version);

			}
			return 0;
		default:
			break;			
	}
	if(_feather->still_working==1)//The following options are not allowed to set after initiation;
	{
		return -2;
	}
	switch(type)
	{
		case MAAT_OPT_EFFECT_INVERVAL_MS:
			intval=*(const int*)value;
			if(size!=sizeof(int)||intval<0)
			{
				return -1;
			}
			_feather->effect_interval_ms=intval;
			break;
		case MAAT_OPT_SCANDIR_INTERVAL_MS:
			intval=*(const int*)value;
			if(size!=sizeof(int)||intval<0)
			{
				return -1;
			}
			_feather->scan_interval_ms=intval;
			break;
		case MAAT_OPT_FULL_CFG_DIR:			
			assert(_feather->input_mode==SOURCE_NONE);
			if(size>(int)sizeof(_feather->iris_ctx.full_dir))
			{
				return -1;
			}
			memcpy(_feather->iris_ctx.full_dir,(const char*)value,size);
			_feather->input_mode=SOURCE_IRIS_FILE;
			break;
		case MAAT_OPT_INC_CFG_DIR:
			if(size>(int)sizeof(_feather->iris_ctx.inc_dir))
			{
				return -1;
			}
			memcpy(_feather->iris_ctx.inc_dir,(const char*)value,size);
			break;
		case MAAT_OPT_JSON_FILE_PATH:
			assert(_feather->input_mode==SOURCE_NONE);
			ret=load_maat_json_file(_feather, (const char *)value, err_str, sizeof(err_str));
			if(ret<0)
			{
				MESA_handle_runtime_log(_feather->logger, RLOG_LV_FATAL, maat_module,
								"Load maat json file %s failed: %s.",
								(const char*)value, err_str);
				return -1;
			}

			break;
		case MAAT_OPT_STAT_ON:
			_feather->stat_on=1;
			break;
		case MAAT_OPT_PERF_ON:
			_feather->perf_on=1;
			break;
		case MAAT_OPT_STAT_FILE_PATH:
			if(size>(int)sizeof(_feather->stat_file))
			{
				return -1;
			}
			memcpy(_feather->stat_file, (const char*)value, size);
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module,
							"Maat performance statistic output to %s.",
							(const char*)value);	
			_feather->stat_on=1;
			break;
		case MAAT_OPT_SCAN_DETAIL:
			intval=*(const int*)value;
			_feather->rule_scan_type=intval;
			break;
		case MAAT_OPT_INSTANCE_NAME:
			snprintf(_feather->instance_name,
					sizeof(_feather->instance_name),
					"%s",
					(const char*)value);
			break;
		case MAAT_OPT_DECRYPT_KEY:
			if((size_t)size>sizeof(_feather->decrypt_key))
			{
				return -1;
			}
			memcpy(_feather->decrypt_key,value,size);
			break;
		case MAAT_OPT_REDIS_IP:
			assert(_feather->input_mode==SOURCE_NONE);
			if((size_t)size>sizeof(_feather->mr_ctx.redis_ip))
			{
				return -1;
			}
			memcpy(_feather->mr_ctx.redis_ip,value,size);
			_feather->input_mode=SOURCE_REDIS;
			break;
		case MAAT_OPT_REDIS_PORT:
			if((size_t)size==sizeof(unsigned short))
			{
				_feather->mr_ctx.redis_port=*((unsigned short*)value);
			}
			else if((size_t)size==sizeof(int))
			{
				_feather->mr_ctx.redis_port=*((int*)value);
			}
			else
			{
				return -1;
			}
			break;
		case MAAT_OPT_REDIS_INDEX:
			if((size_t)size!=sizeof(int))
			{
				return -1;
			}
			_feather->mr_ctx.redis_db=*((int*)value);
			break;
		case MAAT_OPT_CMD_AUTO_NUMBERING:
			if((size_t)size!=sizeof(int)||*((int*)value)>15||*((int*)value)<0)
			{
				return -1;
			}
			_feather->AUTO_NUMBERING_ON=*((int*)value);
			break;
		case MAAT_OPT_DEFERRED_LOAD:
			_feather->DEFERRED_LOAD_ON=1;
			break;
		case	MAAT_OPT_CUMULATIVE_UPDATE_OFF:
			_feather->cumulative_update_off=1;
			break;
		case MAAT_OPT_LOAD_VERSION_FROM:
			_feather->load_version_from=*((long long*)value);
			_feather->backgroud_update_enabled=1;
			pthread_mutex_lock((&_feather->background_update_mutex));
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module ,
							"Maat load version from %lld, backgroud update stopped."
							,_feather->load_version_from);
			break;
		case MAAT_OPT_ACCEPT_TAGS:
			_feather->n_tags=parse_accept_tag((const char*) value, &_feather->accept_tags, _feather->logger);
			if(_feather->n_tags==0)
			{
				return -1;
			}
			_feather->accept_tags_raw=_maat_strdup((const char*) value);
			break;
		case MAAT_OPT_FOREIGN_CONT_DIR:
			memset(_feather->foreign_cont_dir, 0, sizeof(_feather->foreign_cont_dir));
			strncpy(_feather->foreign_cont_dir, (char*)value, sizeof(_feather->foreign_cont_dir));
			if(_feather->foreign_cont_dir[strlen(_feather->foreign_cont_dir)-1]=='/')
			{
				_feather->foreign_cont_dir[strlen(_feather->foreign_cont_dir)-1]='\0';
			}
			break;
		default:
			return -1;
	}
	return 0;
}
void maat_read_full_config(_Maat_feather_t* _feather)
{
	struct source_redis_ctx* mr_ctx=NULL;
	switch(_feather->input_mode)
	{
		case SOURCE_REDIS:			
			mr_ctx=&(_feather->mr_ctx);
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module ,
								"Maat initiate from Redis %s:%hu db%d."
								,mr_ctx->redis_ip
								,mr_ctx->redis_port
								,mr_ctx->redis_db);
			mr_ctx->read_ctx=connect_redis(mr_ctx->redis_ip, mr_ctx->redis_port, mr_ctx->redis_db, _feather->logger);
			if(mr_ctx->read_ctx != NULL)
			{
				redis_monitor_traverse(_feather->maat_version,
									mr_ctx,
									maat_start_cb,
									maat_update_cb,
									maat_finish_cb,
									 _feather,
									_feather->decrypt_key,	//Not used.
									_feather);
			}
			if(_feather->update_tmp_scanner==NULL)
			{
				MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module ,
									"At initiation: no avilable rule in redis %s:%hu db%d",
									mr_ctx->redis_ip,
									mr_ctx->redis_port,
									mr_ctx->redis_db);
			}
			break;
		case SOURCE_IRIS_FILE:
			config_monitor_traverse(_feather->maat_version,
									_feather->iris_ctx.full_dir, 
									maat_start_cb,
									maat_update_cb,
									maat_finish_cb,
									_feather,
									_feather->decrypt_key,
									_feather->logger);
			if(_feather->update_tmp_scanner==NULL)
			{
				MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module ,
								"At initiation: NO effective rule in %s.",
								_feather->iris_ctx.full_dir);
			}
			break;
		case SOURCE_JSON_FILE:
			config_monitor_traverse(_feather->maat_version,
									_feather->json_ctx.iris_file, 
									maat_start_cb,
									maat_update_cb,
									maat_finish_cb,
									_feather,
									_feather->decrypt_key,
									_feather->logger);
			if(_feather->update_tmp_scanner==NULL)
			{
				MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module ,
								"At initiation: NO efffective rule in JSON generate %s.",
								_feather->json_ctx.iris_file);
			}
			break;
		default:
			break;
	}
	_feather->scanner=_feather->update_tmp_scanner;
	_feather->update_tmp_scanner=NULL;
	_feather->still_working=1;
	if(_feather->scanner!=NULL)
	{
		_feather->maat_version=_feather->scanner->version;
		_feather->last_full_version=_feather->scanner->version;
	}
	return;
}
int Maat_initiate_feather(Maat_feather_t feather)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	system_cmd_mkdir(_feather->foreign_cont_dir);
	if(_feather->DEFERRED_LOAD_ON==0)
	{
		maat_read_full_config(_feather);
	}
	if(strlen(_feather->stat_file)==0)
	{
		if(_feather->stat_on==1)
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module ,
								"At initiation: MAAT_OPT_STAT_FILE_PATH not set, TURN OFF STAT trigger.");
		}
		_feather->stat_on=0;
	}
	if(_feather->stat_on==0&&_feather->perf_on==1)
	{
		MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module ,
								"At initiation: STAT  tirigger OFF,  TURN OFF PERF trigger.");
		_feather->perf_on=0;
	}
	if(_feather->cumulative_update_off==1)
	{
		MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module ,
								"Update with cumulative version OFF.");
	}
	if(_feather->n_tags>0)
	{
		MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module ,
								"Accept tags: %s", _feather->accept_tags_raw);		
	}
	if(_feather->stat_on==1)
	{
		maat_stat_init(_feather);
	}

	pthread_create(&(_feather->cfg_mon_t), NULL, thread_rule_monitor, (void*)_feather);
	return 0;

}

Maat_feather_t Maat_summon_feather(int max_thread_num,
									const char* table_info_path,
									const char* ful_cfg_dir,
									const char* inc_cfg_dir,
									void* logger)
{
	int ret=-1;
	Maat_feather_t feather=NULL;
	feather=Maat_feather(max_thread_num,table_info_path,logger);
	if(feather==NULL)
	{
		return NULL;
	}
	ret=Maat_set_feather_opt(feather, MAAT_OPT_FULL_CFG_DIR, ful_cfg_dir, strlen(ful_cfg_dir)+1);
	if(ret<0)
	{
		goto error_out;
	}
	ret=Maat_set_feather_opt(feather, MAAT_OPT_INC_CFG_DIR, inc_cfg_dir, strlen(inc_cfg_dir)+1);
	if(ret<0)
	{
		goto error_out;
	}
	ret=Maat_initiate_feather(feather);
	if(ret<0)
	{
		goto error_out;
	}
	return feather;
	
error_out:
	Maat_burn_feather(feather);
	return NULL;


}
Maat_feather_t Maat_summon_feather_json(int max_thread_num,
									const char* table_info_path,
									const char* json_rule,
									void* logger)
{
	int ret=-1;
	Maat_feather_t feather=NULL;
	feather=Maat_feather(max_thread_num,table_info_path,logger);
	if(feather==NULL)
	{
		return NULL;
	}
	ret=Maat_set_feather_opt(feather, MAAT_OPT_JSON_FILE_PATH, json_rule, strlen(json_rule)+1);
	if(ret<0)
	{
		goto error_out;
	}
	ret=Maat_initiate_feather(feather);
	if(ret<0)
	{
		goto error_out;
	}	return feather;
	
error_out:

	Maat_burn_feather(feather);
	return NULL;

}

void Maat_burn_feather(Maat_feather_t feather)
{
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	_feather->still_working=0;//destroy will proceed in thread_rule_monitor
	void* ret=NULL;
	pthread_join(_feather->cfg_mon_t, &ret);
	return;
}
int Maat_table_register(Maat_feather_t feather,const char* table_name)
{
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	return Maat_table_get_id_by_name(_feather->table_mgr, table_name);
}
int Maat_table_callback_register(Maat_feather_t feather,short table_id,
									Maat_start_callback_t *start,//MAAT_RULE_UPDATE_TYPE_*,u_para
									Maat_update_callback_t *update,//table line ,u_para
									Maat_finish_callback_t *finish,//u_para
									void* u_para)
{
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	int i=0,ret=0;
	
	pthread_mutex_lock(&(_feather->background_update_mutex));
	ret=Maat_table_add_callback_func(_feather->table_mgr, table_id, start, update, finish, u_para);
	if(ret<0)
	{
		pthread_mutex_unlock(&(_feather->background_update_mutex));
		return -1;
	}
	if(!_feather->scanner)
	{
		pthread_mutex_unlock(&(_feather->background_update_mutex));
		return 1;
	}
	const char* line=NULL;
	struct Maat_table_runtime* table_rt=NULL;
	table_rt=Maat_table_runtime_get(_feather->scanner->table_rt_mgr, table_id);
	long long line_cnt=Maat_table_runtime_plugin_cached_line_count(table_rt);
		
	if(line_cnt>0)
	{
		if(start!=NULL)
		{
			start(MAAT_RULE_UPDATE_TYPE_FULL,u_para);
		}
		for(i=0; i<line_cnt; i++)
		{
			line=Maat_table_runtime_plugin_get_cached_line(table_rt, i);
			if(line==NULL)
			{
				break;
			}
			update(table_id,line,u_para);
		}
		if(finish!=NULL)
		{
			finish(u_para);
		}
	}
	pthread_mutex_unlock(&(_feather->background_update_mutex));
	return 1;
}

void rule_ex_data_new_cb(const uchar * key, uint size, void * data, void * user)
{
	struct compile_ex_data_idx *ex_desc=(struct compile_ex_data_idx*)user;
	struct Maat_compile_group_relation *relation=(struct Maat_compile_group_relation *)data;
	struct Maat_compile_rule* compile_rule=relation->compile;
	MAAT_RULE_EX_DATA ad=NULL;
	
	if(compile_rule==NULL|| compile_rule->ref_table->table_id!=ex_desc->table_id)
	{
		return;
	}
	
	pthread_rwlock_wrlock(&(relation->rwlock));
	ad=rule_ex_data_new(&(relation->compile->head),
						relation->compile->service_defined,
						ex_desc);
	compile_rule->ads[ex_desc->idx]=ad;
	pthread_rwlock_unlock(&(relation->rwlock));
	return;
}
int Maat_rule_get_ex_new_index(Maat_feather_t feather, const char* compile_table_name,
										 Maat_rule_EX_new_func_t *new_func,
										 Maat_rule_EX_free_func_t* free_func,
										 Maat_rule_EX_dup_func_t* dup_func,
										 long argl, void *argp)
{
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	int idx=-1;
	
	if(new_func==NULL || free_func==NULL || dup_func==NULL)
	{
		return -1;
	}
	pthread_mutex_lock(&(_feather->background_update_mutex));
	idx=Maat_table_new_compile_rule_ex_index(_feather->table_mgr, compile_table_name,
											 new_func,
											 free_func,
											 dup_func,
											 argl, argp);

	if(idx<0)
	{
		pthread_mutex_unlock(&(_feather->background_update_mutex));
		return -1;
	}
	struct compile_ex_data_idx* compile_ex_desc=Maat_table_get_compile_rule_ex_desc(_feather->table_mgr, compile_table_name, idx);
	
	if(_feather->scanner!=NULL)
	{
		MESA_htable_iterate(_feather->scanner->compile_hash, rule_ex_data_new_cb, compile_ex_desc);
	}

	pthread_mutex_unlock(&(_feather->background_update_mutex));
	return idx;

}
MAAT_RULE_EX_DATA Maat_rule_get_ex_data(Maat_feather_t feather, const struct Maat_rule_t* rule, int idx)
{
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	struct Maat_compile_group_relation *relation=NULL;
	struct Maat_compile_rule* compile=NULL;
	const struct compile_table_schema* compile_desc=NULL;
	const struct compile_ex_data_idx* ex_desc=NULL;
	MAAT_RULE_EX_DATA ad=NULL;
	
	relation=(struct Maat_compile_group_relation *)HASH_fetch_by_id(_feather->scanner->compile_hash, rule->config_id);
	if(relation==NULL||relation->compile==NULL)
	{
		return NULL;
	}
	pthread_rwlock_rdlock(&(relation->rwlock));
	compile=relation->compile;
	compile_desc=&(compile->ref_table->compile);
	assert(idx<compile_desc->ex_data_num);	
	ex_desc=compile_desc->ex_desc+idx;
	ex_desc->dup_func(ex_desc->idx, &ad, compile->ads+idx, ex_desc->argl,ex_desc->argp);
	pthread_rwlock_unlock(&(relation->rwlock));		
	return ad;
}

int Maat_plugin_EX_register(Maat_feather_t feather, int table_id,
										Maat_plugin_EX_new_func_t* new_func,
										Maat_plugin_EX_free_func_t* free_func,
										Maat_plugin_EX_dup_func_t* dup_func,
										Maat_plugin_EX_key2index_func_t* key2index_func,
										long argl, void *argp)

{
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	int idx=-1;

	if(new_func==NULL || free_func==NULL || dup_func==NULL )
	{
		assert(0);
		MESA_handle_runtime_log(_feather->logger, RLOG_LV_FATAL, maat_module, "%s failed: invalid paramter", __FUNCTION__);
		return -1;
	}
	pthread_mutex_lock(&(_feather->background_update_mutex));

	idx=Maat_table_plugin_new_ex_index(_feather->table_mgr, table_id,
										new_func,
										free_func,
										dup_func,
										key2index_func,
										argl, argp);
	if(idx<0)
	{	
		pthread_mutex_unlock(&(_feather->background_update_mutex));
		return -1;
	}
	struct Maat_table_schema *table_desc=Maat_table_get_scan_by_id(_feather->table_mgr, table_id, TABLE_TYPE_PLUGIN, NULL);
	struct Maat_table_runtime* table_rt=NULL;	


	if(_feather->scanner!=NULL)
	{
		table_rt=Maat_table_runtime_get(_feather->scanner->table_rt_mgr, table_id);
		Maat_table_runtime_plugin_new_ex_idx(table_rt, table_desc, _feather->logger);
	}
	pthread_mutex_unlock(&(_feather->background_update_mutex));

	return 0;
}
MAAT_PLUGIN_EX_DATA Maat_plugin_get_EX_data(Maat_feather_t feather, int table_id, const char* key)
{
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct Maat_table_schema *table_desc=NULL;
	struct Maat_table_runtime *table_rt=NULL;
	MAAT_RULE_EX_DATA exdata=NULL;
	if(_feather->scanner==NULL)
	{
		return NULL;
	}
	table_desc=Maat_table_get_scan_by_id(_feather->table_mgr, table_id, TABLE_TYPE_PLUGIN, NULL);
	table_rt=Maat_table_runtime_get(_feather->scanner->table_rt_mgr, table_id);
	exdata=Maat_table_runtime_plugin_get_ex_data(table_rt, table_desc, key);
	return exdata;
}

int Maat_full_scan_string_detail(Maat_feather_t feather,int table_id
						,enum MAAT_CHARSET charset,const char* data,int data_len
						,struct Maat_rule_t*result,int rule_num,struct Maat_hit_detail_t *hit_detail,int detail_num
						,int* detail_ret,scan_status_t* mid,int thread_num)
{
	int region_ret=0,compile_ret=0,hit_region_cnt=0;
	unsigned int sub_type=0;
	int virtual_table_id=0;
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _OUTER_scan_status_t* _mid=(struct _OUTER_scan_status_t*)(*mid);

	scan_result_t *region_result=NULL;
	struct Maat_table_schema *p_table=NULL;
	struct expr_table_schema* expr_desc=NULL;
	struct timespec start,end;
	Maat_scanner* my_scanner=NULL;

	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
	_mid=grab_mid(mid,_feather, thread_num, 0);
	_mid->scan_cnt++;
	if(data==NULL||data_len<=0)
	{
		return -1;
	}
	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}

	p_table=Maat_table_get_scan_by_id(_feather->table_mgr, table_id, TABLE_TYPE_EXPR, &virtual_table_id);
	if(p_table==NULL)
	{
		_feather->scan_err_cnt++;
		return -1;
	}
	expr_desc=&(p_table->expr);
	if(p_table->table_type==TABLE_TYPE_EXPR_PLUS&&(_mid==NULL||_mid->is_set_district!=1))
	{
		_feather->scan_err_cnt++;
		return -1;
	}
	if(expr_desc->do_charset_merge==1)
	{
		sub_type=make_sub_type(p_table->table_id, CHARSET_NONE,0);
	}
	else
	{
		sub_type=make_sub_type(p_table->table_id, charset,0);
	}
	alignment_int64_array_add(_feather->thread_call_cnt, thread_num, 1);
	scan_data_t scan_data;
	scan_data.text_data.text=data;
	scan_data.text_data.tlen=data_len;
	scan_data.text_data.toffset=0;

	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(my_scanner->table_rt_mgr, p_table->table_id);
	if(table_rt->origin_rule_num==0)
	{
		return 0;
	}
	assert(thread_num<_feather->scan_thread_num);
	region_result=my_scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*thread_num;
	
	INC_SCANNER_REF(my_scanner, thread_num);
	if(table_rt->expr.expr_rule_cnt>0)
	{
		scan_data.rule_type=RULETYPE_STR;
		scan_data.sub_type=sub_type;
		region_ret=rulescan_search(my_scanner->region, thread_num, &scan_data, region_result, MAX_SCANNER_HIT_NUM);
		if(region_ret>0)
		{
			hit_region_cnt+=region_ret;
		}
	}
	if(table_rt->expr.regex_rule_cnt>0)
	{
		scan_data.rule_type=RULETYPE_REG;
		scan_data.sub_type=make_sub_type(p_table->table_id, CHARSET_NONE,0);
		region_ret=rulescan_search(my_scanner->region, thread_num, &scan_data, region_result+hit_region_cnt, MAX_SCANNER_HIT_NUM-hit_region_cnt);
		if(region_ret>0)
		{
			hit_region_cnt+=region_ret;
		}

	}
	if(hit_region_cnt>0&&p_table->table_type==TABLE_TYPE_EXPR_PLUS)
	{
		hit_region_cnt=match_district(_mid,region_result,hit_region_cnt, my_scanner);
	}
	if(hit_region_cnt>0 || scan_status_should_compile_NOT(_mid))
	{
		if(hit_region_cnt>0)
		{
			alignment_int64_array_add(table_rt->hit_cnt, thread_num, 1);
		}
		_mid=grab_mid(mid, _feather, thread_num, 1);
		struct scan_region_hit_wraper region_hit_wraper;
		scan_region_hit_wraper_build_with_rulescan(&region_hit_wraper, region_result, hit_region_cnt, 
												_mid->is_last_region, virtual_table_id, _mid->scan_cnt);
		compile_ret=region_compile(_feather,_mid->inner,
									&region_hit_wraper,
									result, rule_num,
									thread_num);
		assert(_mid->is_last_region<2);
		if(_mid->is_last_region==1)
		{
			_mid->is_last_region=2;
		}
		if(hit_region_cnt>0&&hit_detail!=NULL&&_feather->rule_scan_type!=0)
		{
			*detail_ret=fill_region_hit_detail(data, _mid->inner,										
											region_result, hit_region_cnt,
											result, compile_ret,
											_mid->scan_cnt,
											hit_detail, detail_num, my_scanner);
		}
	}
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&end);
		maat_stat_table(table_rt, data_len, &start, &end, thread_num);
	}
	else
	{
		maat_stat_table(table_rt, data_len, NULL, NULL, thread_num);
	}
	DEC_SCANNER_REF(my_scanner, thread_num);
	if(compile_ret==0&&hit_region_cnt>0)
	{
		return -2;
	}
	return compile_ret;
}
int Maat_full_scan_string(Maat_feather_t feather,int table_id
						,enum MAAT_CHARSET charset,const char* data,int data_len
						,struct Maat_rule_t*result,int* found_pos,int rule_num
						,scan_status_t* mid,int thread_num)
{
	int detail_ret=0,compile_ret=0;
	compile_ret=Maat_full_scan_string_detail(feather,table_id,
											charset, data,data_len,
											result, rule_num,
											NULL, 0, &detail_ret,mid,thread_num);
	return compile_ret;
}
int Maat_scan_intval(Maat_feather_t feather,int table_id
						,unsigned int intval
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t *mid,int thread_num)
{
	int region_ret=0,compile_ret=0;
	struct _OUTER_scan_status_t* _mid=NULL;
	scan_data_t intval_scan_data;
	scan_result_t *region_result=NULL;
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct Maat_scanner* my_scanner=NULL;

	Maat_table_schema* p_table=NULL;
	struct timespec start,end;
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
	_mid=grab_mid(mid, _feather, thread_num, 0);
	_mid->scan_cnt++;

	int virtual_table_id=0;
	p_table=Maat_table_get_scan_by_id(_feather->table_mgr, table_id, TABLE_TYPE_INTERVAL, &virtual_table_id);
	if(p_table==NULL)
	{
		_feather->scan_err_cnt++;
		return -1;
	}
	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(my_scanner->table_rt_mgr, p_table->table_id);
	if(table_rt->origin_rule_num==0)
	{
		return 0;
	}
	intval_scan_data.rule_type=RULETYPE_INT;
	intval_scan_data.sub_type=make_sub_type(p_table->table_id, CHARSET_NONE, 0);
	intval_scan_data.int_data=intval;

	alignment_int64_array_add(_feather->thread_call_cnt, thread_num, 1);

	region_result=my_scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*thread_num;
	
	INC_SCANNER_REF(my_scanner,thread_num);
	region_ret=rulescan_search(my_scanner->region, thread_num, &intval_scan_data, region_result, MAX_SCANNER_HIT_NUM);
	if(region_ret<0)
	{
		DEC_SCANNER_REF(my_scanner, thread_num);
		_feather->scan_err_cnt++;
		return -1;
	}
	else if(region_ret>0 || scan_status_should_compile_NOT(_mid))
	{
		if(region_ret>0)
		{
			alignment_int64_array_add(table_rt->hit_cnt, thread_num,1);
		}
		_mid=grab_mid(mid, _feather, thread_num, 1);
		struct scan_region_hit_wraper region_hit_wraper;
		scan_region_hit_wraper_build_with_rulescan(&region_hit_wraper, region_result, region_ret,
											_mid->is_last_region, virtual_table_id, _mid->scan_cnt);
		compile_ret=region_compile(_feather,_mid->inner,
									&region_hit_wraper,
									result, rule_num,
									thread_num);
		assert(_mid->is_last_region<2);
		if(_mid->is_last_region==1)
		{
			_mid->is_last_region=2;
		}
	}
	
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&end);
		maat_stat_table(table_rt, 0, &start, &end, thread_num);
	}
	else
	{
		maat_stat_table(table_rt, 0, NULL, NULL, thread_num);
	}
	DEC_SCANNER_REF(my_scanner,thread_num);

	if(compile_ret==0&&region_ret>0)
	{
		return -2;
	}
	return compile_ret;

}

int Maat_similar_scan_string(Maat_feather_t feather,int table_id
						,const char* data,int data_len
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t* mid,int thread_num)
{
	int hit_region_cnt=0,compile_ret=0;
	struct _OUTER_scan_status_t* _mid=NULL;
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct Maat_scanner* my_scanner=NULL;
	Maat_table_schema* p_table=NULL;
	struct timespec start,end;
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
	_mid=grab_mid(mid, _feather, thread_num, 0);
	_mid->scan_cnt++;
	
	int virtual_table_id=0;
	p_table=Maat_table_get_scan_by_id(_feather->table_mgr, table_id, TABLE_TYPE_SIMILARITY, &virtual_table_id);
	if(p_table==NULL)
	{
		_feather->scan_err_cnt++;
		return -1;
	}
	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}
	GIE_result_t* region_result=my_scanner->gie_rslt_buff+MAX_SCANNER_HIT_NUM*thread_num;

	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(my_scanner->table_rt_mgr, p_table->table_id);
	if(table_rt->origin_rule_num==0)
	{
		return 0;
	}
	GIE_handle_t* gie_handle=table_rt->similar.gie_handle;	
	INC_SCANNER_REF(my_scanner,thread_num);
	alignment_int64_array_add(_feather->thread_call_cnt, thread_num, 1);
	
	hit_region_cnt=GIE_query(gie_handle, data, data_len, region_result, MAX_SCANNER_HIT_NUM);
	if(hit_region_cnt<0)
	{
		DEC_SCANNER_REF(my_scanner, thread_num);
		_feather->scan_err_cnt++;
		return -1;
	}
	else if(hit_region_cnt>0 || scan_status_should_compile_NOT(_mid))
	{
		alignment_int64_array_add(table_rt->hit_cnt, thread_num,1);
		_mid=grab_mid(mid, _feather, thread_num, 1);
		struct scan_region_hit_wraper region_hit_wraper;
		scan_region_hit_wraper_build_with_GIE(&region_hit_wraper, region_result, hit_region_cnt, 
										_mid->is_last_region, virtual_table_id, _mid->scan_cnt);		
		compile_ret=region_compile(_feather,_mid->inner,
									&region_hit_wraper,
									result, rule_num,
									thread_num);
		assert(_mid->is_last_region<2);
		if(_mid->is_last_region==1)
		{
			_mid->is_last_region=2;
		}
	}
	
	DEC_SCANNER_REF(my_scanner,thread_num);
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&end);
		maat_stat_table(table_rt,0,&start, &end,thread_num);
	}
	else
	{
		maat_stat_table(table_rt,0,NULL, NULL,thread_num);
	}
	if(compile_ret==0&&hit_region_cnt>0)
	{
		return -2;
	}
	return compile_ret;

}
static int ip_scan_data_set(scan_data_t* scan_data, const struct ipaddr* addr, unsigned short int proto, enum MAAT_TABLE_CHILD_TYPE child_type, int table_id)
{
	memset(scan_data, 0, sizeof(scan_data_t));
	scan_data->sub_type=make_sub_type(table_id, CHARSET_NONE, 0);
	switch(addr->addrtype)
	{
		case ADDR_TYPE_IPV4:
			scan_data->rule_type=RULETYPE_IPv4;
			scan_data->ipv4_data.proto=proto;
			switch(child_type)
			{
				case CHILD_TABLE_TYPE_SOURCE_IP:
					scan_data->ipv4_data.saddr=ntohl(addr->v4->saddr);
					scan_data->ipv4_data.sport=ntohs(addr->v4->source);
					break;
				case CHILD_TABLE_TYPE_DESTINATION_IP:
					scan_data->ipv4_data.saddr=ntohl(addr->v4->daddr);
					scan_data->ipv4_data.sport=ntohs(addr->v4->dest);
					break;
				case CHILD_TABLE_TYPE_SESSION:
					scan_data->ipv4_data.saddr=ntohl(addr->v4->saddr);
					scan_data->ipv4_data.sport=ntohs(addr->v4->source);
					scan_data->ipv4_data.daddr=ntohl(addr->v4->daddr);
					scan_data->ipv4_data.dport=ntohs(addr->v4->dest);
					break;
				default:
					assert(0);
					return -1;
			}
			break;
		case ADDR_TYPE_IPV6:
			scan_data->rule_type=RULETYPE_IPv6;
			scan_data->ipv6_data.proto=proto;
			switch(child_type)
			{
				case CHILD_TABLE_TYPE_SOURCE_IP:
					memcpy(scan_data->ipv6_data.saddr, addr->v6->saddr, sizeof(scan_data->ipv6_data.saddr));
					ipv6_ntoh(scan_data->ipv6_data.saddr);
					scan_data->ipv6_data.sport=ntohs(addr->v6->source);
					break;
				case CHILD_TABLE_TYPE_DESTINATION_IP:
					memcpy(scan_data->ipv6_data.saddr, addr->v6->daddr, sizeof(scan_data->ipv6_data.saddr));
					ipv6_ntoh(scan_data->ipv6_data.saddr);
					scan_data->ipv6_data.sport=ntohs(addr->v6->dest);
					break;
				case CHILD_TABLE_TYPE_SESSION:
					memcpy(scan_data->ipv6_data.saddr, addr->v6->saddr, sizeof(scan_data->ipv6_data.saddr));
					ipv6_ntoh(scan_data->ipv6_data.saddr);
					scan_data->ipv6_data.sport=ntohs(addr->v6->source);
					
					memcpy(scan_data->ipv6_data.daddr, addr->v6->daddr, sizeof(scan_data->ipv6_data.daddr));
					ipv6_ntoh(scan_data->ipv6_data.daddr);
					scan_data->ipv6_data.dport=ntohs(addr->v6->dest);
					break;
				default:
					assert(0);
					return -1;
					break;
			}	
			break;
		default:
			return -1;
	}
	return 0;
}
static int IP_composition_scan(const struct ipaddr* addr, unsigned short int proto, Maat_table_schema* parent_table, enum MAAT_TABLE_CHILD_TYPE child_type,
						scan_result_t *region_result, unsigned int result_num,
						int* virtual_table_id,
						rule_scanner_t ip_scanner, struct Maat_table_manager* table_mgr, struct Maat_table_runtime_manager* table_rt_mgr,
						int thread_num)
{
	int child_table_id=0;

	if(child_type==CHILD_TABLE_TYPE_NONE)
	{
		child_table_id=parent_table->table_id;
		child_type=CHILD_TABLE_TYPE_SESSION;
	}
	else
	{
		child_table_id=Maat_table_get_child_id(parent_table, child_type);
	}
	if(child_table_id<0)
	{
		return 0;
	}

	Maat_table_schema* real_table=Maat_table_get_scan_by_id(table_mgr, child_table_id, TABLE_TYPE_IP, virtual_table_id);
	if(real_table==NULL)
	{
		return 0;
	}
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(table_rt_mgr, real_table->table_id);
	if(table_rt->origin_rule_num==0)
	{
		return 0;
	}
	if(table_rt->ip.ipv4_rule_cnt==0&&addr->addrtype==ADDR_TYPE_IPV4)
	{
		return 0;
	}
	if(table_rt->ip.ipv6_rule_cnt==0&&addr->addrtype==ADDR_TYPE_IPV6)
	{
		return 0;
	}
	scan_data_t scan_data;
	int ret=ip_scan_data_set(&scan_data, addr, proto, child_type, real_table->table_id);
	if(ret<0)
	{
		return -1;
	}
	int region_ret=rulescan_search(ip_scanner, thread_num, &scan_data, region_result, result_num);
	if(region_ret>0)
	{
		alignment_int64_array_add(table_rt->hit_cnt, thread_num, 1);
	}
	return region_ret;
}

int Maat_scan_proto_addr(Maat_feather_t feather,int table_id
						,struct ipaddr* addr,unsigned short int proto
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t *mid,int thread_num)

{
	int region_ret=0, compile_ret=0;
	struct _OUTER_scan_status_t* _mid=NULL;
	scan_result_t *region_result=NULL;
	Maat_table_schema* p_table=NULL;
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct Maat_scanner* my_scanner=NULL;
	struct timespec start,end;
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
	_mid=grab_mid(mid, _feather, thread_num, 0);
	_mid->scan_cnt++;
	int virtual_table_id=0;
	p_table=Maat_table_get_by_id_raw(_feather->table_mgr, table_id);
	if(p_table==NULL)
	{
		_feather->scan_err_cnt++;
		return -1;
	}

	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(my_scanner->table_rt_mgr, table_id);	

	region_result=my_scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*thread_num;
	int region_hit_cnt=0;
	int region_rslt_virtual_table_id[MAX_SCANNER_HIT_NUM];
	alignment_int64_array_add(_feather->thread_call_cnt, thread_num, 1);
	INC_SCANNER_REF(my_scanner, thread_num);

	if(p_table->table_type==TABLE_TYPE_COMPOSITION)
	{
		enum MAAT_TABLE_CHILD_TYPE childs[3]={CHILD_TABLE_TYPE_SOURCE_IP, CHILD_TABLE_TYPE_DESTINATION_IP, CHILD_TABLE_TYPE_SESSION};
		for(int i=0; i<3; i++)
		{
			region_ret=IP_composition_scan(addr, proto, p_table, childs[i], 
								region_result+region_hit_cnt, MAX_SCANNER_HIT_NUM-region_hit_cnt, &virtual_table_id,
								my_scanner->region, _feather->table_mgr, _feather->scanner->table_rt_mgr, thread_num);
			if(region_ret<0)
			{
				_feather->scan_err_cnt++;
			}
			else if(region_ret>0)
			{
				for(int j=0; j<region_ret; j++)
				{
					region_rslt_virtual_table_id[region_hit_cnt++]=virtual_table_id;
				}
			}
		}
	}
	else
	{
		region_ret=IP_composition_scan(addr, proto, p_table, CHILD_TABLE_TYPE_NONE, 
						region_result+region_hit_cnt, MAX_SCANNER_HIT_NUM-region_hit_cnt, &virtual_table_id,
						my_scanner->region, _feather->table_mgr, _feather->scanner->table_rt_mgr, thread_num);
		if(region_ret<0)
		{
			_feather->scan_err_cnt++;
		}
		else if(region_ret>0)
		{
			region_hit_cnt+=region_ret;
		}

	}
	
	struct scan_region_hit_wraper region_hit_wraper;
	if(region_hit_cnt>0 || scan_status_should_compile_NOT(_mid) )
	{
		_mid=grab_mid(mid, _feather, thread_num, 1);
		scan_region_hit_wraper_build_with_rulescan(&region_hit_wraper, region_result, region_hit_cnt,
												_mid->is_last_region, virtual_table_id, _mid->scan_cnt);
		if(p_table->table_type==TABLE_TYPE_COMPOSITION)
		{
			region_hit_wraper.virtual_table_ids=region_rslt_virtual_table_id;
		}
		compile_ret=region_compile(_feather,_mid->inner,
									&region_hit_wraper,
									result, rule_num,
									thread_num);
		assert(_mid->is_last_region<2);
		if(_mid->is_last_region==1)
		{
			_mid->is_last_region=2;
		}
	}
	DEC_SCANNER_REF(my_scanner,thread_num);
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&end);
		maat_stat_table(table_rt, 0, &start, &end, thread_num);
	}
	else
	{
		maat_stat_table(table_rt, 0, NULL, NULL, thread_num);
	}
	if(compile_ret==0&&region_hit_cnt>0)
	{
		return -2;
	}
	return compile_ret;
}
int Maat_scan_addr(Maat_feather_t feather,int table_id
						,struct ipaddr* addr
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t *mid,int thread_num)
{
	int compile_ret=0;
	compile_ret=Maat_scan_proto_addr(feather,table_id,
								addr, 0,
								result, rule_num,
								mid,thread_num);
	return compile_ret;
}
stream_para_t Maat_stream_scan_string_start(Maat_feather_t feather,int table_id,int thread_num)
{
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct Maat_scanner* scanner=NULL;

	struct Maat_table_schema *p_table=NULL;
	int virtual_table_id=0;
	assert(thread_num<_feather->scan_thread_num);
	p_table=Maat_table_get_scan_by_id(_feather->table_mgr, table_id, TABLE_TYPE_EXPR, &virtual_table_id);
	if(p_table==NULL)
	{
		_feather->scan_err_cnt++;
		return NULL;
	}
	
	struct expr_table_schema* expr_desc=&(p_table->expr);
	struct _stream_para_t* sp=ALLOC(struct _stream_para_t ,1);
	scanner=_feather->scanner;
	sp->feather=_feather;
	sp->p_real_table=p_table;
	sp->virtual_table_id=virtual_table_id;
	sp->version=_feather->maat_version;
	sp->process_offset=0;
	sp->rs_stream_para=NULL;
	if(scanner==NULL)
	{
		return sp;
	}
	
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, sp->p_real_table->table_id);
	if(table_rt->origin_rule_num==0)
	{
		return sp;
	}
	INC_SCANNER_REF(scanner, thread_num);

	sp->thread_num=thread_num;
	sp->max_cross_size=expr_desc->cross_cache_size;
	sp->caching_size=0;
	sp->scan_buff=NULL;
	sp->last_cache=NULL;
	if(expr_desc->do_charset_merge==1)
	{
		sp->do_merge=1;
	}
	if(table_rt->expr.expr_rule_cnt>0)
	{
		sp->do_expr=1;
	}
	if(table_rt->expr.regex_rule_cnt>0)
	{
		sp->do_regex=1;
	}
	alignment_int64_array_add(table_rt->stream_num,thread_num,1);
	sp->rs_stream_para=rulescan_startstream(_feather->scanner->region,thread_num);
	return sp;
}

int Maat_stream_scan_string_detail(stream_para_t* stream_para
									,enum MAAT_CHARSET charset,const char* data,int data_len
									,struct Maat_rule_t*result,int rule_num,struct Maat_hit_detail_t *hit_detail,int detail_num
									,int* detail_ret,scan_status_t* mid)
{
	struct _stream_para_t* sp=(struct _stream_para_t*)(*stream_para);
	struct Maat_scanner* scanner=sp->feather->scanner;

	int sub_type=0;
	int region_ret=0,hit_region_cnt=0,compile_ret=0;
	struct _OUTER_scan_status_t* _mid=NULL;
	scan_result_t *region_result;
	scan_data_t region_scan_data;
	struct timespec start,end;
	if(sp->feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC, &start);
	}
	_mid=grab_mid(mid, sp->feather, sp->thread_num, 0);
	_mid->scan_cnt++;
	if(data==NULL||data_len<=0||scanner==NULL)
	{
		return 0;
	}
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, sp->p_real_table->table_id);


	if(sp->version!=sp->feather->maat_version)
	{
		return 0;
	}
	//table rule num is already  in Maat_stream_scan_string_start


	if(sp->p_real_table->table_type==TABLE_TYPE_EXPR_PLUS&&(_mid==NULL||_mid->is_set_district!=1))
	{
		sp->feather->scan_err_cnt++;
		return -1;
	}
	alignment_int64_array_add(sp->feather->thread_call_cnt, sp->thread_num, 1);
	region_result=scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*sp->thread_num;
	*detail_ret=0;
	if(sp->do_merge==1)
	{
		sub_type=make_sub_type(sp->p_real_table->table_id, CHARSET_NONE, 0);
	}
	else
	{
		sub_type=make_sub_type(sp->p_real_table->table_id, charset, 0);
	}
	if(sp->max_cross_size>0&&sp->caching_size>0)
	{
		if(sp->scan_buff!=NULL)
		{
			free(sp->scan_buff);
			sp->scan_buff=NULL;
		}
		sp->scan_buff=ALLOC(char, sp->caching_size+data_len);
		memcpy(sp->scan_buff,sp->last_cache,sp->caching_size);
		memcpy(sp->scan_buff+sp->caching_size,data,data_len);
		region_scan_data.text_data.text=sp->scan_buff;
		region_scan_data.text_data.tlen=sp->caching_size+data_len;
	}
	else
	{
		region_scan_data.text_data.text=data;
		region_scan_data.text_data.tlen=data_len;
	}
	region_scan_data.text_data.toffset=(int)MIN(0xffffffff/2, sp->process_offset);//longger then int
	if(sp->last_cache==NULL&&sp->max_cross_size>0)
	{
		assert(sp->caching_size==0);
		sp->last_cache=ALLOC(char, sp->max_cross_size);
	}
	if(sp->max_cross_size>0)
	{
		sp->caching_size=detain_last_data(sp->last_cache,sp->max_cross_size,sp->caching_size,data,data_len,&(sp->process_offset));
	}
	else
	{
		sp->process_offset+=data_len;
	}
	if(sp->do_expr==1)
	{
		region_scan_data.rule_type=RULETYPE_STR;
		region_scan_data.sub_type=sub_type;
		region_ret=rulescan_searchstream(sp->rs_stream_para, &region_scan_data, region_result, MAX_SCANNER_HIT_NUM);
		if(region_ret<0)
		{
			sp->feather->scan_err_cnt++;
			return -1;
		}
		else if(region_ret>0)
		{
			hit_region_cnt+=region_ret;
		}
	}
	if(sp->do_regex==1)
	{
		region_scan_data.rule_type=RULETYPE_REG;
		region_scan_data.sub_type=make_sub_type(sp->p_real_table->table_id, CHARSET_NONE,0);
		region_ret=rulescan_searchstream(sp->rs_stream_para, &region_scan_data, region_result+hit_region_cnt, MAX_SCANNER_HIT_NUM-hit_region_cnt);
		if(region_ret<0)
		{
			sp->feather->scan_err_cnt++;
			return -1;
		}
		else if(region_ret>0)
		{
			hit_region_cnt+=region_ret;
		}
	}
	if(hit_region_cnt>0&&sp->p_real_table->table_type==TABLE_TYPE_EXPR_PLUS)
	{
		hit_region_cnt=match_district(_mid, region_result, hit_region_cnt, scanner);	
	}
	if(hit_region_cnt>0 || scan_status_should_compile_NOT(_mid))
	{
		if(hit_region_cnt>0)
		{
			alignment_int64_array_add(table_rt->hit_cnt, sp->thread_num,1);
		}
		_mid=grab_mid(mid, sp->feather,sp->thread_num, 1);
		struct scan_region_hit_wraper region_hit_wraper;
		scan_region_hit_wraper_build_with_rulescan(&region_hit_wraper, region_result, hit_region_cnt, 
										_mid->is_last_region, sp->virtual_table_id, _mid->scan_cnt);

		compile_ret=region_compile(sp->feather,_mid->inner,
							&region_hit_wraper,
							result, rule_num,
							sp->thread_num);
		assert(_mid->is_last_region<2);
		if(_mid->is_last_region==1)
		{
			_mid->is_last_region=2;
		}
		if(hit_detail!=NULL&&sp->feather->rule_scan_type!=0)
		{
			if(sp->scan_buff!=NULL)
			{
				*detail_ret=fill_region_hit_detail(sp->scan_buff, _mid->inner,
												region_result, hit_region_cnt,
												result, compile_ret,
												_mid->scan_cnt,
												hit_detail, detail_num, scanner);
			}
			else
			{
				*detail_ret=fill_region_hit_detail(data, _mid->inner,
												region_result, hit_region_cnt,
												result, compile_ret,
												_mid->scan_cnt,
												hit_detail, detail_num, scanner);
			}
		}
	}
	if(*detail_ret==0)
	{
		free(sp->scan_buff);
		sp->scan_buff=NULL;
	}
	if(sp->feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&end);
		maat_stat_table(table_rt,data_len,&start, &end,sp->thread_num);
	}
	else
	{
		maat_stat_table(table_rt,data_len,NULL, NULL,sp->thread_num);
	}
	if(compile_ret==0&&hit_region_cnt>0)
	{
		return -2;
	}
	return compile_ret;
}
int Maat_stream_scan_string(stream_para_t* stream_para
									,enum MAAT_CHARSET charset,const char* data,int data_len
									,struct Maat_rule_t*result,int* found_pos,int rule_num
									,scan_status_t* mid)

{

	int compile_ret=0;
	int detail_ret=0;
	compile_ret=Maat_stream_scan_string_detail(stream_para, charset,data,data_len,
										result,rule_num, NULL, 0,&detail_ret,mid);
	return compile_ret;
}
void Maat_stream_scan_string_end(stream_para_t* stream_para)
{
	struct _stream_para_t* sp=(struct _stream_para_t*)(*stream_para);
	struct Maat_scanner* scanner=sp->feather->scanner;
	struct Maat_table_runtime* table_rt=NULL;
	if(scanner!=NULL)
	{
		table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, sp->p_real_table->table_id);
		alignment_int64_array_add(table_rt->stream_num, sp->thread_num, -1);

	}
	if(sp->rs_stream_para!=NULL)
	{
		if(scanner!=NULL&&sp->version>=sp->feather->last_full_version)
		{
			
			DEC_SCANNER_REF(scanner, sp->thread_num);
			rulescan_endstream(sp->rs_stream_para);
		}
		else
		{
			rulescan_endstream_simple(sp->rs_stream_para);
			sp->feather->zombie_rs_stream--;
		}
		sp->rs_stream_para=NULL;
	}
	if(sp->last_cache!=NULL)
	{
		free(sp->last_cache);
		sp->last_cache=NULL;
		sp->caching_size=0;
	}
	if(sp->scan_buff!=NULL)
	{
		free(sp->scan_buff);
		sp->scan_buff=NULL;
	}
	free(sp);
	*stream_para=NULL;
	return;
}

stream_para_t Maat_stream_scan_digest_start(Maat_feather_t feather,int table_id,unsigned long long total_len,int thread_num)
{
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct Maat_scanner* scanner=NULL;
	sfh_instance_t * tmp_fuzzy_handle=NULL;
	struct Maat_table_schema *p_table=NULL;
	int virtual_table_id=0;
	p_table=Maat_table_get_scan_by_id(_feather->table_mgr, table_id, TABLE_TYPE_DIGEST, &virtual_table_id);
	if(p_table==NULL)
	{
		_feather->scan_err_cnt++;
		return NULL;
	}	
	struct _stream_para_t* sp=ALLOC(struct _stream_para_t, 1);
	scanner=_feather->scanner;
	sp->feather=_feather;
	sp->p_real_table=p_table;
	sp->virtual_table_id=virtual_table_id;
	sp->version=_feather->maat_version;
	sp->process_offset=0;
	if(scanner==NULL)
	{
		return sp;
	}
	struct Maat_table_runtime* table_rt=Maat_table_runtime_get(scanner->table_rt_mgr, table_id);
	tmp_fuzzy_handle=SFH_instance(total_len);
	if(tmp_fuzzy_handle==NULL)
	{
		_feather->scan_err_cnt++;
		return NULL;
	}
	INC_SCANNER_REF(scanner, thread_num);

	sp->thread_num=thread_num;
	sp->total_len=total_len;
	sp->fuzzy_hash_handle=tmp_fuzzy_handle;
	pthread_mutex_init(&(sp->fuzzy_mutex),NULL);
	alignment_int64_array_add(table_rt->stream_num,thread_num,1);
	return sp;
}

inline int REACH_QUERY_THRESH(unsigned long long total_len,unsigned long long acc_len,unsigned char* query_point,int point_size)
{
	const unsigned long long QUERY_MIN_RATE=(3);	//30%
//	const unsigned long long QUERY_MIN_LEN=(1024*1024*4);
//do query every 10 percent since 30%, e.g. 0.3/0.4/0.5/.../1.0
	unsigned long long rate=(acc_len*10)/total_len;
//	if(acc_len>QUERY_MIN_LEN)
//	{
//		return 1;
//	}
	//TODO use a more thorough strategy.
	if(total_len==0)
	{
		return 1;
	}
	if(rate>(unsigned long long)(point_size+QUERY_MIN_RATE))
	{
		return 0;
	}
	if(rate>=QUERY_MIN_RATE&&query_point[rate-QUERY_MIN_RATE]==0)
	{
		query_point[rate-QUERY_MIN_RATE]=1;
		return 1;
	}
	return 0;
}
int Maat_stream_scan_digest(stream_para_t * stream_para, const char * data, int data_len, unsigned long long offset, struct Maat_rule_t * result, int rule_num, scan_status_t * mid)
{
	struct _stream_para_t* sp=(struct _stream_para_t*)(*stream_para);
	int do_query=0;
	int hit_region_cnt=0,compile_ret=0;
	struct _OUTER_scan_status_t* _mid=NULL;

	struct timespec start, end;
	if(sp->feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
	_mid=grab_mid(mid, sp->feather, sp->thread_num, 0);
	_mid->scan_cnt++;

	if(data==NULL||data_len<=0)
	{
		return 0;
	}
	if(sp->feather->scanner==NULL)
	{
		return 0;
	}
	GIE_result_t* region_result=sp->feather->scanner->gie_rslt_buff+MAX_SCANNER_HIT_NUM*sp->thread_num;

	struct Maat_table_runtime *table_rt=Maat_table_runtime_get(sp->feather->scanner->table_rt_mgr, sp->p_real_table->table_id);
	GIE_handle_t* GIE_handle=table_rt->similar.gie_handle;
	unsigned long long digest_len=0;
	char* digest_buff=NULL;

	alignment_int64_array_add(sp->feather->thread_call_cnt, sp->thread_num, 1);
	pthread_mutex_lock(&(sp->fuzzy_mutex));
	sp->process_offset+=SFH_feed(sp->fuzzy_hash_handle, data, (unsigned int)data_len,offset);
	pthread_mutex_unlock(&(sp->fuzzy_mutex));
	do_query=REACH_QUERY_THRESH(sp->total_len, sp->process_offset, sp->query_point,8);
	if(do_query==0)
	{
		goto fast_out;
	}
	pthread_mutex_lock(&(sp->fuzzy_mutex));
	digest_len=SFH_status(sp->fuzzy_hash_handle, HASH_LENGTH);
	pthread_mutex_unlock(&(sp->fuzzy_mutex));
	if(digest_len==0)
	{
		goto fast_out;
	}
	digest_buff=ALLOC(char, digest_len);
	pthread_mutex_lock(&(sp->fuzzy_mutex));
	SFH_digest(sp->fuzzy_hash_handle,digest_buff, digest_len);
	pthread_mutex_unlock(&(sp->fuzzy_mutex));

	if(GIE_handle!=NULL)
	{
		hit_region_cnt=GIE_query(GIE_handle, digest_buff,(int)strlen(digest_buff), region_result, MAX_SCANNER_HIT_NUM);
	}

	free(digest_buff);
	digest_buff=NULL;
	if(hit_region_cnt<0)//error occurs
	{
		sp->feather->scan_err_cnt++;
		compile_ret=-1;
        goto fast_out;
	}
	if(hit_region_cnt>0 || scan_status_should_compile_NOT(_mid))
	{	
		if(hit_region_cnt>0)
		{
			alignment_int64_array_add(table_rt->hit_cnt, sp->thread_num, 1);
		}
		_mid=grab_mid(mid,sp->feather, sp->thread_num,1);
		struct scan_region_hit_wraper region_hit_wraper;
		scan_region_hit_wraper_build_with_GIE(&region_hit_wraper, region_result, hit_region_cnt, 
											_mid->is_last_region, sp->virtual_table_id, _mid->scan_cnt);
		compile_ret=region_compile(sp->feather,_mid->inner,
								&region_hit_wraper,
								result, rule_num,
								sp->thread_num);
		assert(_mid->is_last_region<2);
		if(_mid->is_last_region==1)
		{
			_mid->is_last_region=2;
		}
	}
fast_out:
	if(sp->feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&end);
		maat_stat_table(table_rt, data_len, &start, &end, sp->thread_num);
	}
	else
	{
		maat_stat_table(table_rt, data_len, NULL, NULL, sp->thread_num);
	}
	if(compile_ret==0&&hit_region_cnt>0)
	{
		return -2;
	}
	return compile_ret;
}
void Maat_stream_scan_digest_end(stream_para_t* stream_para)
{
	struct _stream_para_t* sp=(struct _stream_para_t*)(*stream_para);
	struct Maat_scanner* scanner=sp->feather->scanner;
	struct Maat_table_runtime *table_rt=Maat_table_runtime_get(sp->feather->scanner->table_rt_mgr, sp->p_real_table->table_id);
	alignment_int64_array_add(table_rt->stream_num, sp->thread_num,-1);
	if(scanner!=NULL)
	{
		if(sp->version==sp->feather->maat_version)
		{
			DEC_SCANNER_REF(scanner, sp->thread_num);
		}		
	}
	SFH_release(sp->fuzzy_hash_handle);
	pthread_mutex_destroy(&(sp->fuzzy_mutex));
	assert(sp->last_cache==NULL);
	assert(sp->scan_buff==NULL);
	free(sp);
	*stream_para=NULL;

	return;
}
int Maat_read_rule(Maat_feather_t feather, const struct Maat_rule_t* rule, enum MAAT_RULE_OPT type, void* value, int size)
{
	int ret=0;
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	struct Maat_compile_group_relation *compile_inner=NULL;
	switch(type)
	{
		case	MAAT_RULE_SERV_DEFINE:
			compile_inner=(struct Maat_compile_group_relation *)HASH_fetch_by_id(_feather->scanner->compile_hash, rule->config_id);
			if(compile_inner==NULL)
			{
				ret=0;
			}
			else
			{
				pthread_rwlock_rdlock(&(compile_inner->rwlock));
				ret=MIN(size,compile_inner->compile->head.serv_def_len);
				memcpy(value,compile_inner->compile->service_defined,ret);
				pthread_rwlock_unlock(&(compile_inner->rwlock));
			}
			break;
		default:
			ret=-1;
	}
	return ret;
}
int Maat_set_scan_status(Maat_feather_t feather,scan_status_t* mid,enum MAAT_SCAN_OPT type,const void* value,int size)
{
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _OUTER_scan_status_t* _mid=NULL;
	int map_ret=-1;
	if(_feather->scanner==NULL)
	{
		return 0;
	}
	_mid=grab_mid(mid,_feather, 0, 0);
	if(_mid==NULL)
	{
		_mid=_make_outer_status(_feather,0);
		*mid=_mid;
	}
	switch(type)
	{
		case	MAAT_SET_SCAN_DISTRICT:
			if(value==NULL||size<=0)
			{
				_feather->scan_err_cnt++;
				return -1;
			}
			map_ret=map_unNullstr2int(_feather->scanner->district_map,(const char*)value,size,&(_mid->district_id));
			if(map_ret<0)
			{
				//May be the district is not effected yet.
				_mid->district_id=-1;
			}
			_mid->is_set_district=1;
			break;
		case	MAAT_SET_SCAN_LAST_REGION:
			assert(_mid->is_last_region==0);
			_mid->is_last_region=1;
			break;
		default:
			_feather->scan_err_cnt++;
			return -1;
			break;
	}
	return 0;
}
int Maat_get_scan_status(Maat_feather_t feather, scan_status_t* mid, enum MAAT_SCAN_OPT type, void* value, int size)
{
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _OUTER_scan_status_t* _mid=NULL;
	struct Maat_hit_path_t* paths;
	struct Maat_hit_path_t condition;
	struct Maat_hit_path_inner *path_inner;
	size_t n_read=0, i=0;
	int ret=0;
	_mid=grab_mid(mid, _feather, 0, 0);

	if(_mid->inner==NULL)
	{
		return 0;
	}
	switch(type)
	{
		case	MAAT_GET_SCAN_HIT_PATH:
			if(value==NULL||size<=0||size%sizeof(struct Maat_hit_path_t)!=0)
			{
				return -1;
			}
			paths=(struct Maat_hit_path_t*)value;
			n_read=size/sizeof(struct Maat_hit_path_t);
			path_inner=ALLOC(struct Maat_hit_path_inner, n_read);
			hit_path_init(&condition);
			n_read=scan_hit_status_select_hit_path_inner(&_mid->inner->hit_path_qhead, &condition, path_inner, n_read);
			for(i=0; i<n_read; i++)
			{
				paths[i]=path_inner[i].path;
			}
			free(path_inner);
			ret=n_read;
			break;
		default:
			return -1;
	}
	return ret;
}

int Maat_read_state(Maat_feather_t feather, enum MAAT_STATE_OPT  type, void* value, int size)
{
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	int * int_val=(int *)value;
	long long* longlong_val=(long long*)value;
	switch(type)
	{
		case MAAT_STATE_VERSION:
			if(size!=sizeof(long long))
			{
				return -1;
			}
			if(_feather->new_version!=-1)
			{
				*longlong_val=_feather->new_version;
			}
			else
			{
				*longlong_val=_feather->maat_version;
			}
			break;
		case MAAT_STATE_LAST_UPDATING_TABLE:
			*int_val=Maat_table_manager_is_last_plugin_table_updating(_feather->table_mgr);
			break;
		case MAAT_STATE_IN_UPDATING:
			if(size!=sizeof(int))
			{
				return -1;
			}
			if(0==pthread_mutex_trylock(&(_feather->background_update_mutex)))
			{
				*int_val=0;
				pthread_mutex_unlock(&(_feather->background_update_mutex));
			}
			else
			{
				*int_val=1;
			}
		default:
			return -1;
			break;
	}
	return 0;
}

void Maat_clean_status(scan_status_t* mid)
{
	struct _OUTER_scan_status_t* _mid=NULL;
	if(*mid==NULL)
	{
		return;
	}
	_mid=(struct _OUTER_scan_status_t*)(*mid);
	alignment_int64_array_add(_mid->feather->outer_mid_cnt,_mid->thread_num,-1);
	if(_mid->inner!=NULL)
	{
		scan_hit_status_free(_mid->inner);
		_mid->inner=NULL;
		alignment_int64_array_add(_mid->feather->inner_mid_cnt, _mid->thread_num, -1);
	}
	_mid->feather=NULL;
	free(_mid);
	*mid=NULL;
	return;
}

int Maat_helper_read_column(const char* line, int Nth_column, size_t *column_offset, size_t *column_len)
{
	return get_column_pos(line, Nth_column, column_offset, column_len);
}

