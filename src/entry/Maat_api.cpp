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

struct Maat_table_desc * acqurie_table(struct _Maat_feather_t* _feather,int table_id,enum MAAT_TABLE_TYPE expect_type)
{
	struct Maat_table_desc *p_table=NULL;
	if(table_id>MAX_TABLE_NUM)
	{
		return NULL;
	}
	if(_feather->p_table_info[table_id]==NULL)
	{
		return NULL;
	}
	p_table=_feather->p_table_info[table_id];
	if(p_table==NULL)
	{
		return NULL;
	}
	if(p_table->table_type!=expect_type)
	{
		if(expect_type!=TABLE_TYPE_EXPR||
			p_table->table_type!=TABLE_TYPE_EXPR_PLUS)
		{
			return NULL;
		}
	}
	return p_table;
}
inline void INC_SCANNER_REF(Maat_scanner_t*scanner,int thread_num)
{
	alignment_int64_array_add(scanner->ref_cnt, thread_num, 1);
	return;
}
inline void DEC_SCANNER_REF(Maat_scanner_t*scanner,int thread_num)
{

	alignment_int64_array_add(scanner->ref_cnt, thread_num, -1);
	return;
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
		free(_mid->inner->hitted_group_id);
		free(_mid->inner);
		alignment_int64_array_add(_mid->feather->inner_mid_cnt,_mid->thread_num,-1);
	}
	_mid->feather=NULL;
	free(_mid);
	*mid=NULL;
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
size_t pickup_hit_region_from_compile(struct bool_expr *compile_hit, 
						const unsigned long long* hitted_id, size_t hit_cnt, int* region_pos, size_t size)
{
	size_t i=0, j=0;
	size_t k=0;
	for(i=0;i<hit_cnt;i++)
	{
		for(j=0; j<compile_hit->item_num; j++)
		{
			if(hitted_id[i]==compile_hit->items[j].item_id)
			{
				region_pos[k]=i;
				k++;
				assert(k<size);
			}
		}
	}
	return k;
}
void fill_maat_rule(struct Maat_rule_t *rule, const struct _head_Maat_rule* rule_head, const char* srv_def, int srv_def_len)
{
	memcpy(rule, rule_head, sizeof(struct _head_Maat_rule));
	memcpy(rule->service_defined, srv_def, MIN(srv_def_len,MAX_SERVICE_DEFINE_LEN));
	return;
}
static int compare_compile_id(const void *a, const void *b)
{
	struct Maat_rule_t *ra=(struct Maat_rule_t *)a;
	struct Maat_rule_t *rb=(struct Maat_rule_t *)b;

	return (rb->config_id-ra->config_id);
}

int region_compile(_Maat_feather_t*feather,struct _INNER_scan_status_t *_mid,int is_last_region,void* region_hit,int region_type_size,int group_offset,int region_hit_num,struct Maat_rule_t* result,_compile_result_t *rs_result, int size,int thread_num)
{

	int scan_ret=0,result_cnt=0;
	int ret=0,i=0;
	size_t r_in_c_cnt=0;
	int shortcut_avilable_cnt=0;
	unsigned char has_not_flag=0;
	struct bool_matcher* bm=feather->scanner->bool_matcher_expr_compiler;
	struct Maat_group_inner* group_rule=NULL;
	struct Maat_compile_inner* array_mi_rule[MAX_SCANNER_HIT_NUM];
	struct Maat_compile_inner* _mi_rule=NULL;
	int region_pos[MAX_SCANNER_HIT_NUM];
	_mid->cur_hit_cnt=0;
	for(i=0;i<region_hit_num;i++)
	{
		group_rule=*(struct Maat_group_inner**)((char*)region_hit+region_type_size*i+group_offset);
		if(group_rule->group_id<0)
		{
			continue;
		}
		if(group_rule->compile_shortcut!=NULL&&group_rule->ref_cnt==1&&shortcut_avilable_cnt<MAX_SCANNER_HIT_NUM)
		{			
			array_mi_rule[shortcut_avilable_cnt]=(struct Maat_compile_inner*)(group_rule->compile_shortcut);
			shortcut_avilable_cnt++;
		}
		_mid->cur_hit_id[_mid->cur_hit_cnt]=group_rule->group_id;
		_mid->cur_hit_cnt++;
		ret=insert_set_id(&(_mid->hitted_group_id),
									&(_mid->hit_group_size),
									_mid->hit_group_cnt,
									group_rule->group_id);
		_mid->hit_group_cnt+=ret;
	}
	if((region_hit_num>0 &&shortcut_avilable_cnt==region_hit_num) || 
		shortcut_avilable_cnt==MAX_SCANNER_HIT_NUM)
	{
		//short cut for rules contains one group
		scan_ret=shortcut_avilable_cnt;
		alignment_int64_array_add(feather->orphan_group_saving, thread_num, 1);
	}
	else if(0&&shortcut_avilable_cnt==0&&region_hit_num==1&&_mid->hit_group_cnt==1&&is_last_region==1)
	{
		//This shortcut is NO longger valid after bool macher support NOT-logic.
		//short cut for last scan and combination rules
		//region_hit_num==1 :  for current scan hitted rules, one and each other group may statisfy a compile rule.
		//_mid->hit_group_cnt==1: With pre scan hitted group rules, one group may staisfy a compile rule
		scan_ret=0;
	}
	else
	{
		scan_ret=bool_matcher_match(bm, thread_num, 
										_mid->hitted_group_id, _mid->hit_group_cnt,
										(void **)array_mi_rule, MAX_SCANNER_HIT_NUM);
	}
	for(i=0;i<scan_ret&&result_cnt<size;i++)
	{
		_mi_rule=array_mi_rule[i];
		if(_mi_rule==NULL)
		{
			continue;
		}
		
		if(0==pthread_rwlock_tryrdlock(&(_mi_rule->rwlock)))
		{
			if(_mi_rule->is_valid==1)
			{			
				if(_mi_rule->not_group_cnt>0 && !is_last_region)
				{
					_mid->not_grp_compile_hitted_flag=1;
				}
				else
				{
	   				make_group_set(_mi_rule, &(rs_result[result_cnt].group_set), &has_not_flag);
					r_in_c_cnt=pickup_hit_region_from_compile(&(rs_result[result_cnt].group_set), _mid->cur_hit_id, _mid->cur_hit_cnt,
												region_pos, MAX_SCANNER_HIT_NUM);
					if(r_in_c_cnt>0 ||			//compile config hitted becasue of new reigon
						_mid->cur_hit_cnt==0)	//or ever hit a compile that refer a NOT-logic group
					{
						fill_maat_rule(&(result[result_cnt]), &(_mi_rule->db_c_rule->m_rule_head),
									_mi_rule->db_c_rule->service_defined ,_mi_rule->db_c_rule->m_rule_head.serv_def_len);
						rs_result[result_cnt].compile_id=_mi_rule->compile_id;
						result_cnt++;
					}
				}		
			}	
			pthread_rwlock_unlock(&(_mi_rule->rwlock));
		}		
	}	
	if(result_cnt>0)
	{
		qsort(result, result_cnt, sizeof(struct Maat_rule_t),
                  compare_compile_id);
		alignment_int64_array_add(feather->hit_cnt,thread_num,1);
	}
	if(region_hit_num==0&&result_cnt>0)
	{
		alignment_int64_array_add(feather->not_grp_hit_cnt, thread_num, 1);

	}
	return result_cnt;
}

int exprid2region_id(struct Maat_group_inner* group_rule,int expr_id,int* district_id)
{
	int i=0,region_id=-1;
	struct Maat_region_inner* region_rule=NULL;
	assert(group_rule->group_id>=0);
	pthread_mutex_lock(&(group_rule->mutex));
	for(i=0;i<group_rule->region_boundary;i++)
	{
		region_rule=(struct Maat_region_inner*)dynamic_array_read(group_rule->regions, i);
		if(region_rule==NULL)
		{
			continue;
		}
		if(expr_id>=region_rule->expr_id_lb&&expr_id<=region_rule->expr_id_ub)
		{
			region_id=region_rule->region_id;
			*district_id=region_rule->district_id;
			break;
		}
	}
	pthread_mutex_unlock(&(group_rule->mutex));
	return region_id;
}
int match_district(struct _OUTER_scan_status_t *_mid,scan_result_t *region_hit,int region_hit_num)
{
	struct Maat_group_inner* group_rule=NULL;
	int i=0;
	int district_id=-1,region_id=-1;
	int ret_region_num=region_hit_num;
	while(i<ret_region_num)
	{
		group_rule=(struct Maat_group_inner*)(region_hit[i].tag);
		region_id=exprid2region_id(group_rule, region_hit[i].expr_id,&district_id);
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
int fill_region_hit_detail(const char* scan_buff,const _INNER_scan_status_t* _mid,
							scan_result_t *region_hit,int region_cnt,
							_compile_result_t *compile_hit,int compile_cnt,
							struct Maat_hit_detail_t *hit_detail,int detail_num)
{
	int i=0,j=0,k=0;
	char r_in_c_flag[region_cnt];
	int region_pos[MAX_SCANNER_HIT_NUM],pos=0;
	int r_in_c_cnt=0;
	int region_id=-1;
	int district_id=-1; //Indifferenc
	memset(r_in_c_flag,0,sizeof(r_in_c_flag));
	memset(region_pos,0,sizeof(region_pos));
	
	struct Maat_group_inner* group_rule=NULL;
	//for each hitted compile cfg,find its region_ids
	for(i=0;i<compile_cnt&&i<detail_num;i++)
	{
		hit_detail[i].config_id=compile_hit[i].compile_id;
		r_in_c_cnt=pickup_hit_region_from_compile(&(compile_hit[i].group_set), _mid->cur_hit_id, _mid->cur_hit_cnt,
												region_pos, MAX_SCANNER_HIT_NUM);
		assert(r_in_c_cnt>0);//previous hitted compile was elimited in region_compile
		for(j=0,k=0;j<r_in_c_cnt&&k<MAAT_MAX_HIT_RULE_NUM;j++)
		{
			pos=region_pos[j];
			r_in_c_flag[pos]=1;
			group_rule=(struct Maat_group_inner*)(region_hit[pos].tag);
			region_id=exprid2region_id(group_rule,region_hit[pos].expr_id,&district_id);
			if(region_id<0)
			{
				continue;
			}
			hit_detail[i].region_pos[k].region_id=region_id;
			hit_detail[i].region_pos[k].sub_item_num=region_hit[pos].rnum;
			hit_pos_RS2Maat(hit_detail[i].region_pos[k].sub_item_pos,MAAT_MAX_EXPR_ITEM_NUM,
							region_hit[pos].result, region_hit[pos].rnum,scan_buff);
			k++;
		}		
		hit_detail[i].hit_region_cnt=k;

	}
	//for each region_ids, if belongs to no compile cfg, fill hit_detail as a half hit cfg
	for(k=0,j=i;k<region_cnt&&j<region_cnt&&j<detail_num;k++)
	{
		if(r_in_c_flag[k]==0)
		{
			group_rule=(struct Maat_group_inner*)(region_hit[k].tag);
	 		hit_detail[j].config_id=-2;
			hit_detail[j].hit_region_cnt=1;
			hit_detail[j].region_pos[0].region_id=exprid2region_id(group_rule,region_hit[k].expr_id,&district_id);
			hit_detail[j].region_pos[0].sub_item_num=region_hit[k].rnum;
			hit_pos_RS2Maat(hit_detail[j].region_pos[0].sub_item_pos,MAAT_MAX_EXPR_ITEM_NUM,
						region_hit[k].result,region_hit[k].rnum,scan_buff);
			j++;
		}
	}
	return j;
}
struct _INNER_scan_status_t* _make_inner_status(void)
{
	struct _INNER_scan_status_t* inner_mid=NULL;
	inner_mid=ALLOC(struct _INNER_scan_status_t, 1);
	inner_mid->cur_hit_cnt=0;
	inner_mid->hit_group_cnt=0;
	inner_mid->hit_group_size=4;
	inner_mid->hitted_group_id= ALLOC(unsigned long long, inner_mid->hit_group_size);
	return inner_mid;
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
	struct _OUTER_scan_status_t* _mid=NULL;
	if(*raw_mid!=NULL)
	{
		_mid=(struct _OUTER_scan_status_t*)(*raw_mid);
	}
	if(is_hit_region==1)
	{
		if(_mid==NULL)
		{
			_mid=_make_outer_status(feather,thread_num);
			*raw_mid=_mid;
		}
		if(_mid->inner==NULL)
		{
			_mid->inner=_make_inner_status();
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
	feather->table_cnt=read_table_description(feather->p_table_info, MAX_TABLE_NUM,table_info_path,max_thread_num,logger);
	feather->map_tablename2id=map_create();
	int i=0,j=0,ret=0;
	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		if(feather->p_table_info[i]!=NULL)
		{
			if(feather->p_table_info[i]->table_type==TABLE_TYPE_GROUP)
			{
				feather->GROUP_MODE_ON=1;
				strncpy(feather->group_tn,feather->p_table_info[i]->table_name[0],sizeof(feather->group_tn));
			}
			if(feather->p_table_info[i]->table_type==TABLE_TYPE_COMPILE)
			{
				strncpy(feather->compile_tn,feather->p_table_info[i]->table_name[0],sizeof(feather->compile_tn));
			}
			for(j=0;j<feather->p_table_info[i]->conj_cnt;j++)
			{
				ret=map_register(feather->map_tablename2id,feather->p_table_info[i]->table_name[j],feather->p_table_info[i]->table_id);
				if(ret<0)
				{
					MESA_handle_runtime_log(feather->logger,RLOG_LV_FATAL,maat_module ,
									"Duplicate table name %s of table id %d"
									,feather->p_table_info[i]->table_name[j]
									,feather->p_table_info[i]->table_id);
					continue;
				}
			}
		}
	}
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
	feather->orphan_group_saving=alignment_int64_array_alloc(max_thread_num);
	feather->not_grp_hit_cnt=alignment_int64_array_alloc(max_thread_num);
	feather->maat_version=0;
	feather->last_full_version=0;
	feather->base_grp_seq=0;
	feather->base_rgn_seq=0;
	feather->AUTO_NUMBERING_ON=1;
	feather->backgroud_update_enabled=1;
	feather->foreign_cont_linger=0;
	snprintf(feather->foreign_cont_dir, sizeof(feather->foreign_cont_dir), "%s_files", table_info_path);
	pthread_mutex_init(&(feather->background_update_mutex),NULL);
	snprintf(feather->table_info_fn,sizeof(feather->table_info_fn),"%s",table_info_path);
	return feather;
}
int Maat_set_feather_opt(Maat_feather_t feather,enum MAAT_INIT_OPT type,const void* value,int size)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;	
	struct stat attrib;
	int intval=0,ret=-1;
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
			ret=json2iris((const char*)value
				,_feather->compile_tn,_feather->group_tn
				,NULL
				,_feather->json_ctx.iris_file
				,sizeof(_feather->json_ctx.iris_file)
				,_feather->logger);
			if(ret<0)
			{
				return -1;
			}
			memcpy(_feather->json_ctx.json_file, value, size);
			stat(_feather->json_ctx.json_file, &attrib);
			_feather->json_ctx.last_md5_time=attrib.st_ctime;

			md5_file(_feather->json_ctx.json_file, _feather->json_ctx.effective_json_md5);
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module ,
							"Maat initial with JSON file %s md5: %s, generate index file %s OK.",
							_feather->json_ctx.json_file,
							_feather->json_ctx.effective_json_md5,
							_feather->json_ctx.iris_file);
			_feather->input_mode=SOURCE_JSON_FILE;
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
			memcpy(_feather->stat_file,(const char*)value,size);
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module ,
							"Maat performance statistic output to %s."
							,(const char*)value);	
			_feather->stat_on=1;
			break;
		case MAAT_OPT_SCAN_DETAIL:
			intval=*(const int*)value;
			_feather->rule_scan_type=intval;
			break;
		case MAAT_OPT_INSTANCE_NAME:
			snprintf(_feather->instance_name
					,sizeof(_feather->instance_name)
					,"%s",
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
							"Maat load version from %lld, stops backgroud update."
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
		case MAAT_OPT_FOREIGN_CONT_LINGER:
			_feather->foreign_cont_linger=*(int*)value;
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
	int table_id=-1,ret=0;
	ret=map_str2int(_feather->map_tablename2id, table_name, &table_id);
	if(ret>0)
	{
		return table_id;
	}
	else
	{
		return -1;
	}
}
int Maat_table_callback_register(Maat_feather_t feather,short table_id,
									Maat_start_callback_t *start,//MAAT_RULE_UPDATE_TYPE_*,u_para
									Maat_update_callback_t *update,//table line ,u_para
									Maat_finish_callback_t *finish,//u_para
									void* u_para)
{
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	int idx=0,i=0;
	struct Maat_table_desc *p_table=_feather->p_table_info[table_id];
	struct plugin_table_desc *plugin_desc=&(p_table->plugin);
	struct plugin_runtime* plugin_aux=NULL;
	const char* lines=NULL;
	if(p_table==NULL)
	{
		return -1;
	}
	if(p_table->table_type!=TABLE_TYPE_PLUGIN)
	{
		return -1;
	}
	//plugin table register blocks background update.
	pthread_mutex_lock(&(_feather->background_update_mutex));
	idx=plugin_desc->cb_plug_cnt;
	if(idx==MAX_PLUGIN_PER_TABLE)
	{
		pthread_mutex_unlock(&(_feather->background_update_mutex));
		return -1;
	}
	plugin_desc->cb_plug_cnt++;
	plugin_desc->cb_plug[idx].start=start;
	plugin_desc->cb_plug[idx].update=update;
	plugin_desc->cb_plug[idx].finish=finish;
	plugin_desc->cb_plug[idx].u_para=u_para;
	if(_feather->scanner==NULL)
	{
		pthread_mutex_unlock(&(_feather->background_update_mutex));
		return 1;
	}
	plugin_aux = &(_feather->scanner->table_rt[table_id]->plugin);
	if(plugin_aux->cache_line_num>0)
	{
		if(start!=NULL)
		{
			start(MAAT_RULE_UPDATE_TYPE_FULL,u_para);
		}
		for(i=0;i<plugin_aux->cache_line_num;i++)
		{
			lines=(const char*)dynamic_array_read(plugin_aux->cache_lines,i);
			if(lines==NULL)
			{
				break;
			}
			update(table_id,lines,u_para);
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
	struct Maat_compile_inner *compile_inner=(struct Maat_compile_inner *)data;
	MAAT_RULE_EX_DATA ad=NULL;
	
	if(compile_inner->ref_table==NULL || compile_inner->ref_table->table_id!=ex_desc->table_id || compile_inner->db_c_rule==NULL)
	{
		return;
	}
	pthread_rwlock_wrlock(&(compile_inner->rwlock));
	ad=rule_ex_data_new(&(compile_inner->db_c_rule->m_rule_head),
						compile_inner->db_c_rule->service_defined,
						ex_desc);
	compile_inner->ads[ex_desc->idx]=ad;
	pthread_rwlock_unlock(&(compile_inner->rwlock));
	return;
}
int Maat_rule_get_ex_new_index(Maat_feather_t feather, const char* compile_table_name,
										 Maat_rule_EX_new_func_t *new_func,
										 Maat_rule_EX_free_func_t* free_func,
										 Maat_rule_EX_dup_func_t* dup_func,
										 long argl, void *argp)
{
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	int table_id=-1,ret=0, idx=-1;
	ret=map_str2int(_feather->map_tablename2id, compile_table_name, &table_id);
	if(ret<0)
	{
		return -1;
	}
	struct Maat_table_desc *p_table=_feather->p_table_info[table_id];
	if(p_table->table_type!=TABLE_TYPE_COMPILE || new_func==NULL || free_func==NULL || dup_func==NULL)
	{
		return -1;
	}
	struct compile_table_desc* compile_desc=&(p_table->compile);
	pthread_mutex_lock(&(_feather->background_update_mutex));
	if(compile_desc->ex_data_num==MAX_COMPILE_EX_DATA_NUM)
	{
		ret=-1;
		goto failed;
	}
	idx=compile_desc->ex_data_num;
	compile_desc->ex_desc[idx].idx=idx;
	compile_desc->ex_desc[idx].table_id=table_id;
	compile_desc->ex_desc[idx].argl=argl;
	compile_desc->ex_desc[idx].argp=argp;
	compile_desc->ex_desc[idx].new_func=new_func;
	compile_desc->ex_desc[idx].free_func=free_func;
	compile_desc->ex_desc[idx].dup_func=dup_func;

	compile_desc->ex_data_num++;
	if(_feather->scanner!=NULL)
	{
		MESA_htable_iterate(_feather->scanner->compile_hash, rule_ex_data_new_cb, compile_desc->ex_desc+idx);
	}
failed:
	pthread_mutex_unlock(&(_feather->background_update_mutex));
	return idx;

}
MAAT_RULE_EX_DATA Maat_rule_get_ex_data(Maat_feather_t feather, const struct Maat_rule_t* rule, int idx)
{
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	struct Maat_compile_inner *compile_inner=NULL;
	const struct compile_table_desc* compile_desc=NULL;
	const struct compile_ex_data_idx* ex_desc=NULL;
	MAAT_RULE_EX_DATA ad=NULL;
	
	compile_inner=(struct Maat_compile_inner *)HASH_fetch_by_id(_feather->scanner->compile_hash, rule->config_id);
	if(compile_inner==NULL)
	{
		return NULL;
	}
	pthread_rwlock_rdlock(&(compile_inner->rwlock));
	compile_desc=&(compile_inner->ref_table->compile);
	assert(idx<compile_desc->ex_data_num);	
	ex_desc=compile_desc->ex_desc+idx;
	ex_desc->dup_func(ex_desc->idx, &ad, compile_inner->ads+idx, ex_desc->argl,ex_desc->argp);
	pthread_rwlock_unlock(&(compile_inner->rwlock));		
	return ad;
}
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
	hargs.thread_safe=0;
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
int Maat_plugin_EX_register(Maat_feather_t feather, int table_id,
										Maat_plugin_EX_new_func_t* new_func,
										Maat_plugin_EX_free_func_t* free_func,
										Maat_plugin_EX_dup_func_t* dup_func,
										Maat_plugin_EX_key2index_func_t* key2index_func,
										long argl, void *argp)

{
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct Maat_table_desc *table_desc=_feather->p_table_info[table_id];
	struct plugin_table_desc* plugin_desc=&(table_desc->plugin);
	struct Maat_table_runtime* table_rt=NULL;	
	if(new_func==NULL || free_func==NULL || dup_func==NULL )
	{
		assert(0);
		MESA_handle_runtime_log(_feather->logger, RLOG_LV_FATAL, maat_module, "%s failed: invalid paramter", __FUNCTION__);
		return -1;
	}
	if(table_desc->table_type!=TABLE_TYPE_PLUGIN ||	plugin_desc->have_exdata
		|| plugin_desc->key_column==0 || plugin_desc->valid_flag_column==0)
	{
		assert(0);
		MESA_handle_runtime_log(_feather->logger, RLOG_LV_FATAL, maat_module, 
			"%s failed: key or valid flag column  are not specified", __FUNCTION__);
		return -1;
	}
		
	pthread_mutex_lock(&(_feather->background_update_mutex));

	plugin_desc->ex_desc.new_func=new_func;
	plugin_desc->ex_desc.free_func=free_func;
	plugin_desc->ex_desc.dup_func=dup_func;
	plugin_desc->ex_desc.key2index_func=key2index_func;//Set but not used.
	plugin_desc->ex_desc.argl=argl;
	plugin_desc->ex_desc.argp=argp;
	plugin_desc->have_exdata=1;
	if(_feather->scanner!=NULL)
	{
		table_rt=_feather->scanner->table_rt[table_id];
		assert(table_rt->plugin.key2ex_hash==NULL);
		table_rt->plugin.key2ex_hash=plugin_EX_htable_new(table_desc, table_rt->plugin.cache_lines, 
														table_rt->plugin.cache_line_num, _feather->logger);
	}
	pthread_mutex_unlock(&(_feather->background_update_mutex));

	return 0;
}
MAAT_PLUGIN_EX_DATA Maat_plugin_get_EX_data(Maat_feather_t feather, int table_id, const char* key)
{
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct Maat_table_desc *table_desc=_feather->p_table_info[table_id];
	struct Maat_table_runtime *table_rt= NULL;
	struct plugin_table_desc* plugin_desc=&(table_desc->plugin);
	struct wrap_plugin_EX_data* wrap_data=NULL;
	MAAT_RULE_EX_DATA exdata=NULL;
	if(table_desc->table_type!=TABLE_TYPE_PLUGIN || plugin_desc->have_exdata==0)
	{
		assert(0);
		return NULL;
	}
	if(_feather->scanner==NULL)
	{
		return NULL;
	}
	table_rt= _feather->scanner->table_rt[table_id];
	pthread_rwlock_rdlock(&table_rt->plugin.rwlock);
	wrap_data=(struct wrap_plugin_EX_data*)MESA_htable_search(table_rt->plugin.key2ex_hash,
													(const unsigned char*)key, strlen(key));
	if(wrap_data!=NULL)
	{
		plugin_desc->ex_desc.dup_func(table_id, &(exdata), &(wrap_data->exdata), 
			plugin_desc->ex_desc.argl, plugin_desc->ex_desc.argp);
	}
	pthread_rwlock_unlock(&table_rt->plugin.rwlock);
	return exdata;
}

int Maat_full_scan_string_detail(Maat_feather_t feather,int table_id
						,enum MAAT_CHARSET charset,const char* data,int data_len
						,struct Maat_rule_t*result,int rule_num,struct Maat_hit_detail_t *hit_detail,int detail_num
						,int* detail_ret,scan_status_t* mid,int thread_num)
{
	int region_ret=0,compile_ret=0,hit_region_cnt=0;
	unsigned int sub_type=0;
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _OUTER_scan_status_t* _mid=(struct _OUTER_scan_status_t*)(*mid);

	scan_result_t *region_result=NULL;
	_compile_result_t compile_result[rule_num];//dynamic array
	struct Maat_table_desc *p_table=NULL;
	struct expr_table_desc* expr_desc=NULL;
	struct timespec start,end;
	Maat_scanner_t* my_scanner=NULL;
	if(data==NULL||data_len<=0)
	{
		return 0;
	}
	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
	_mid=grab_mid(mid,_feather, thread_num, 0);
	p_table=acqurie_table(_feather, table_id,TABLE_TYPE_EXPR);
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
		sub_type=make_sub_type(table_id,CHARSET_NONE,0);
	}
	else
	{
		sub_type=make_sub_type(table_id,charset,0);
	}
	alignment_int64_array_add(_feather->thread_call_cnt, thread_num, 1);
	scan_data_t scan_data;
	scan_data.text_data.text=data;
	scan_data.text_data.tlen=data_len;
	scan_data.text_data.toffset=0;

	struct Maat_table_runtime* table_rt=my_scanner->table_rt[table_id];
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
		scan_data.sub_type=make_sub_type(table_id,CHARSET_NONE,0);
		region_ret=rulescan_search(my_scanner->region, thread_num, &scan_data, region_result+hit_region_cnt, MAX_SCANNER_HIT_NUM-hit_region_cnt);
		if(region_ret>0)
		{
			hit_region_cnt+=region_ret;
		}

	}
	if(hit_region_cnt>0&&p_table->table_type==TABLE_TYPE_EXPR_PLUS)
	{
		hit_region_cnt=match_district(_mid,region_result,hit_region_cnt);
	}
	if(hit_region_cnt>0 || scan_status_should_compile_NOT(_mid))
	{
		if(hit_region_cnt>0)
		{
			alignment_int64_array_add(table_rt->hit_cnt, thread_num, 1);
		}
		_mid=grab_mid(mid,_feather,thread_num, 1);
		compile_ret=region_compile(_feather,_mid->inner,
									_mid->is_last_region,
									region_result,sizeof(scan_result_t),offsetof(scan_result_t, tag),
									hit_region_cnt,
									result,compile_result,rule_num,
									thread_num);
		assert(_mid->is_last_region<2);
		if(_mid->is_last_region==1)
		{
			_mid->is_last_region=2;
		}
		if(hit_region_cnt>0&&hit_detail!=NULL&&_feather->rule_scan_type!=0)
		{
			*detail_ret=fill_region_hit_detail(data,_mid->inner,										
											region_result,hit_region_cnt,
											compile_result,compile_ret, 
											hit_detail,detail_num);
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
	_compile_result_t compile_result[rule_num];
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct Maat_scanner_t* my_scanner=NULL;
	intval_scan_data.rule_type=RULETYPE_INT;
	intval_scan_data.sub_type=make_sub_type(table_id,CHARSET_NONE, 0);
	intval_scan_data.int_data=intval;
	Maat_table_desc* p_table=NULL;
	struct timespec start,end;
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
	p_table=acqurie_table(_feather,table_id,TABLE_TYPE_INTERVAL);
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
	struct Maat_table_runtime* table_rt=my_scanner->table_rt[table_id];
	if(table_rt->origin_rule_num==0)
	{
		return 0;
	}
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
		compile_ret=region_compile(_feather,_mid->inner,
									_mid->is_last_region,
									region_result,sizeof(scan_result_t),offsetof(scan_result_t, tag),
									region_ret,
									result,compile_result,rule_num,
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

int Maat_scan_proto_addr(Maat_feather_t feather,int table_id
						,struct ipaddr* addr,unsigned short int proto
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t *mid,int thread_num)
{
	int region_ret=0,compile_ret=0;
	struct _OUTER_scan_status_t* _mid=NULL;
	scan_data_t ip_scan_data;
	scan_result_t *region_result=NULL;
	_compile_result_t compile_result[rule_num];
	Maat_table_desc* p_table=NULL;
	
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct Maat_scanner_t* my_scanner=NULL;
	struct timespec start,end;
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
	p_table=acqurie_table(_feather, table_id, TABLE_TYPE_IP);
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
	struct Maat_table_runtime* table_rt=my_scanner->table_rt[table_id];
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
	alignment_int64_array_add(_feather->thread_call_cnt, thread_num, 1);

	ip_scan_data.rule_type=RULETYPE_IPv4;
	ip_scan_data.sub_type=make_sub_type(table_id,CHARSET_NONE, 0);
	switch(addr->addrtype)
	{
		case ADDR_TYPE_IPV4:
			ip_scan_data.ipv4_data.saddr=ntohl(addr->v4->saddr);
			ip_scan_data.ipv4_data.daddr=ntohl(addr->v4->daddr);
			ip_scan_data.ipv4_data.sport=ntohs(addr->v4->source);
			ip_scan_data.ipv4_data.dport=ntohs(addr->v4->dest);
			ip_scan_data.ipv4_data.proto=proto;
			break;
		case ADDR_TYPE_IPV6:
			ip_scan_data.rule_type=RULETYPE_IPv6;
			memcpy(ip_scan_data.ipv6_data.saddr,addr->v6->saddr,sizeof(ip_scan_data.ipv6_data.saddr));
			ipv6_ntoh(ip_scan_data.ipv6_data.saddr);
			memcpy(ip_scan_data.ipv6_data.daddr,addr->v6->daddr,sizeof(ip_scan_data.ipv6_data.daddr));
			ipv6_ntoh(ip_scan_data.ipv6_data.daddr);
			ip_scan_data.ipv6_data.sport=ntohs(addr->v6->source);
			ip_scan_data.ipv6_data.dport=ntohs(addr->v6->dest);
			ip_scan_data.ipv6_data.proto=proto;
			break;
		default:
			_feather->scan_err_cnt++;
			return -1;
			break;
	}

	
	region_result=my_scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*thread_num;
	INC_SCANNER_REF(my_scanner,thread_num);
	region_ret=rulescan_search(my_scanner->region, thread_num, &ip_scan_data, region_result, MAX_SCANNER_HIT_NUM);
	if(region_ret<0)
	{
		DEC_SCANNER_REF(my_scanner,thread_num);
		_feather->scan_err_cnt++;
		return -1;
	}
	else if(region_ret>0 || scan_status_should_compile_NOT(_mid) )
	{
		if(region_ret>0)
		{
			alignment_int64_array_add(table_rt->hit_cnt, thread_num,1);
		}
		_mid=grab_mid(mid, _feather, thread_num, 1);
		
		compile_ret=region_compile(_feather,_mid->inner,
									_mid->is_last_region,
									region_result,sizeof(scan_result_t),offsetof(scan_result_t, tag),
									region_ret,
									result,compile_result,rule_num,
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
	if(compile_ret==0&&region_ret>0)
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
	struct Maat_scanner_t* scanner=NULL;

	struct Maat_table_desc *p_table=NULL;
	assert(thread_num<_feather->scan_thread_num);
	p_table=acqurie_table(_feather, table_id, TABLE_TYPE_EXPR);
	if(p_table==NULL)
	{
		_feather->scan_err_cnt++;
		return NULL;
	}
	
	struct expr_table_desc* expr_desc=&(p_table->expr);
	struct _stream_para_t* sp=ALLOC(struct _stream_para_t ,1);
	scanner=_feather->scanner;
	sp->feather=_feather;
	sp->version=_feather->maat_version;
	sp->process_offset=0;
	sp->rs_stream_para=NULL;
	if(scanner==NULL)
	{
		return sp;
	}
	struct Maat_table_runtime* table_rt=scanner->table_rt[table_id];
	if(table_rt->origin_rule_num==0)
	{
		return sp;
	}
	INC_SCANNER_REF(scanner, thread_num);

	sp->table_id=table_id;
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
	struct Maat_scanner_t* scanner=sp->feather->scanner;

	int sub_type=0;
	int region_ret=0,hit_region_cnt=0,compile_ret=0;
	struct _OUTER_scan_status_t* _mid=NULL;
	scan_result_t *region_result;
	_compile_result_t compile_result[rule_num];//dynamic array
	scan_data_t region_scan_data;
	Maat_table_desc* p_table=NULL;
	struct timespec start,end;	
	if(data==NULL||data_len<=0||scanner==NULL)
	{
		return 0;
	}	
	struct Maat_table_runtime* table_rt=scanner->table_rt[sp->table_id];
	if(sp->feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
	_mid=grab_mid(mid, sp->feather, sp->thread_num,0);

	if(sp->version!=sp->feather->maat_version)
	{
		return 0;
	}
	p_table=sp->feather->p_table_info[sp->table_id];
	//table rule num is already judged in Maat_stream_scan_string_start


	if(p_table->table_type==TABLE_TYPE_EXPR_PLUS&&(_mid==NULL||_mid->is_set_district!=1))
	{
		sp->feather->scan_err_cnt++;
		return -1;
	}
	alignment_int64_array_add(sp->feather->thread_call_cnt, sp->thread_num, 1);
	region_result=scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*sp->thread_num;
	*detail_ret=0;
	if(sp->do_merge==1)
	{
		sub_type=make_sub_type(sp->table_id,CHARSET_NONE,0);
	}
	else
	{
		sub_type=make_sub_type(sp->table_id,charset,0);
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
		region_scan_data.sub_type=make_sub_type(sp->table_id,CHARSET_NONE,0);
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
	if(hit_region_cnt>0&&p_table->table_type==TABLE_TYPE_EXPR_PLUS)
	{
		hit_region_cnt=match_district(_mid,region_result,hit_region_cnt);	
	}
	if(hit_region_cnt>0 || scan_status_should_compile_NOT(_mid))
	{
		if(hit_region_cnt>0)
		{
			alignment_int64_array_add(table_rt->hit_cnt, sp->thread_num,1);
		}
		_mid=grab_mid(mid, sp->feather,sp->thread_num, 1);
		compile_ret=region_compile(sp->feather,_mid->inner,
							_mid->is_last_region,
							region_result,sizeof(scan_result_t),offsetof(scan_result_t, tag),
							hit_region_cnt,
							result,compile_result,rule_num,
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
				*detail_ret=fill_region_hit_detail(sp->scan_buff,_mid->inner,
												region_result,hit_region_cnt,
												compile_result,compile_ret,
												hit_detail,detail_num);
			}
			else
			{
				*detail_ret=fill_region_hit_detail(data,_mid->inner,
												region_result,hit_region_cnt,
												compile_result,compile_ret,
												hit_detail,detail_num);
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
	struct Maat_scanner_t* scanner=sp->feather->scanner;
	struct Maat_table_runtime* table_rt=NULL;
	if(scanner!=NULL)
	{
		table_rt=scanner->table_rt[sp->table_id];
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
	struct Maat_scanner_t* scanner=NULL;
	sfh_instance_t * tmp_fuzzy_handle=NULL;
	struct Maat_table_desc *p_table=NULL;
	p_table=acqurie_table(_feather, table_id, TABLE_TYPE_DIGEST);
	if(p_table==NULL)
	{
		_feather->scan_err_cnt++;
		return NULL;
	}	
	struct _stream_para_t* sp=ALLOC(struct _stream_para_t, 1);
	scanner=_feather->scanner;
	sp->feather=_feather;
	sp->version=_feather->maat_version;
	sp->process_offset=0;
	if(scanner==NULL)
	{
		return sp;
	}
	struct Maat_table_runtime* table_rt=scanner->table_rt[table_id];
	tmp_fuzzy_handle=SFH_instance(total_len);
	if(tmp_fuzzy_handle==NULL)
	{
		_feather->scan_err_cnt++;
		return NULL;
	}
	INC_SCANNER_REF(scanner, thread_num);

	sp->table_id=table_id;
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
	GIE_result_t query_result[MAX_SCANNER_HIT_NUM];
	int hit_region_cnt=0,compile_ret=0;
	_compile_result_t compile_result[rule_num];//dynamic array	
	if(data==NULL||data_len<=0)
	{
		return 0;
	}
	if(sp->feather->scanner==NULL)
	{
		return 0;
	}
	struct Maat_table_runtime *table_rt=sp->feather->scanner->table_rt[sp->table_id];
	GIE_handle_t* GIE_handle=table_rt->similar.gie_handle;
	unsigned long long digest_len=0;
	char* digest_buff=NULL;
	struct _OUTER_scan_status_t* _mid=NULL;
	struct timespec start,end;
	if(sp->feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
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
		hit_region_cnt=GIE_query(GIE_handle, digest_buff,(int)strlen(digest_buff), query_result, MAX_SCANNER_HIT_NUM);
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
		compile_ret=region_compile(sp->feather,_mid->inner,
								_mid->is_last_region,
								query_result,sizeof(GIE_result_t),offsetof(GIE_result_t, tag),
								hit_region_cnt,
								result,compile_result,rule_num,
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
	struct Maat_scanner_t* scanner=sp->feather->scanner;
	struct Maat_table_runtime *table_rt=sp->feather->scanner->table_rt[sp->table_id];
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
	struct Maat_compile_inner *compile_inner=NULL;
	switch(type)
	{
		case	MAAT_RULE_SERV_DEFINE:
			compile_inner=(struct Maat_compile_inner *)HASH_fetch_by_id(_feather->scanner->compile_hash, rule->config_id);
			if(compile_inner==NULL)
			{
				ret=0;
			}
			else
			{
				pthread_rwlock_rdlock(&(compile_inner->rwlock));
				ret=MIN(size,compile_inner->db_c_rule->m_rule_head.serv_def_len);
				memcpy(value,compile_inner->db_c_rule->service_defined,ret);
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
int Maat_similar_scan_string(Maat_feather_t feather,int table_id
						,const char* data,int data_len
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t* mid,int thread_num)
{
	int hit_region_cnt=0,compile_ret=0;
	struct _OUTER_scan_status_t* _mid=NULL;
	GIE_result_t region_result[MAX_SCANNER_HIT_NUM];
	_compile_result_t compile_result[rule_num];
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct Maat_scanner_t* my_scanner=NULL;
	Maat_table_desc* p_table=NULL;
	struct timespec start,end;
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
	p_table=acqurie_table(_feather,table_id,TABLE_TYPE_SIMILARITY);
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
	struct Maat_table_runtime* table_rt=my_scanner->table_rt[table_id];
	if(table_rt->origin_rule_num==0)
	{
		return 0;
	}
	GIE_handle_t* gie_handle=table_rt->similar.gie_handle;	
	INC_SCANNER_REF(my_scanner,thread_num);
	alignment_int64_array_add(_feather->thread_call_cnt, thread_num, 1);
	
	hit_region_cnt=GIE_query(gie_handle, data, data_len,region_result, MAX_SCANNER_HIT_NUM);
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
		compile_ret=region_compile(_feather,_mid->inner,
									_mid->is_last_region,
									region_result,sizeof(GIE_result_t),offsetof(GIE_result_t, tag),
									hit_region_cnt,
									result,compile_result,rule_num,
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
int Maat_read_state(Maat_feather_t feather,enum MAAT_STATE_OPT  type, void* value,int size)
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
			*int_val=_feather->is_last_plugin_table_updating;
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

int Maat_helper_read_column(const char* line, int Nth_column, size_t *column_offset, size_t *column_len)
{
	return get_column_pos(line, Nth_column, column_offset, column_len);
}

