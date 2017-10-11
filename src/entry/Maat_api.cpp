#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <MESA/MESA_handle_logger.h>

#include "rulescan.h"
#include "UniversalBoolMatch.h"
#include "Maat_rule.h"
#include "Maat_rule_internal.h"
#include "dynamic_array.h"
#include "aligment_int64.h"
#include "config_monitor.h"
#include "map_str2int.h"
#include "rulescan.h"
#include "json2iris.h"

struct _Maat_table_info_t * acqurie_table(struct _Maat_feather_t* _feather,int table_id,enum MAAT_TABLE_TYPE expect_type)
{
	struct _Maat_table_info_t *p_table=NULL;
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
inline void INC_SCANNER_REF(_Maat_scanner_t*scanner,int thread_num)
{
	aligment_int64_array_add(scanner->ref_cnt, thread_num, 1);
	return;
}
inline void DEC_SCANNER_REF(_Maat_scanner_t*scanner,int thread_num)
{

	aligment_int64_array_add(scanner->ref_cnt, thread_num, -1);
	return;
}

//return 1 if insert a unique id
//return 0 if id is duplicated
//return -1 if set is full
int insert_set_id(unsigned int **set,int* size,int cnt,unsigned int id)
{
	int i=0;
	for(i=0;i<cnt;i++)
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
			*set=(unsigned int*)realloc(*set,(*size)*sizeof(unsigned int));
		}
		(*set)[cnt]=id;
		return 1;
	}
	else
	{
		return 0;
	}
}
int pickup_hit_region_from_compile(universal_bool_expr_t *compile_hit,const unsigned int* hitted_id,int hit_cnt,int* region_pos,int size)
{
	int i=0,j=0;
	int k=0;
	for(i=0;i<hit_cnt;i++)
	{
		for(j=0;j<(int)(compile_hit->bool_item_num);j++)
		{
			if(hitted_id[i]==compile_hit->bool_item_ids[j])
			{
				region_pos[k]=i;
				k++;
			}
		}
	}
	return k;
}
int region_compile(_Maat_feather_t*feather,struct _INNER_scan_status_t *_mid,int is_last_region,void* region_hit,int region_type_size,int group_offset,int region_hit_num,struct Maat_rule_t* result,_compile_result_t *rs_result, int size,int thread_num)
{

	int scan_ret=0,result_cnt=0;
	int ret=0,i=0;
	int r_in_c_cnt=0;
	int shortcut_avilable_cnt=0;
	void* bool_matcher=feather->scanner->expr_compiler;
	struct _Maat_group_inner_t* group_rule=NULL;
	struct _Maat_compile_inner_t* array_mi_rule[MAX_SCANNER_HIT_NUM];
	struct _Maat_compile_inner_t* _mi_rule=NULL;
	int region_pos[MAX_SCANNER_HIT_NUM];
	_mid->cur_hit_cnt=0;
	for(i=0;i<region_hit_num;i++)
	{
		group_rule=*(struct _Maat_group_inner_t**)((char*)region_hit+region_type_size*i+group_offset);
		if(group_rule->group_id<0)
		{
			continue;
		}
		if(group_rule->compile_shortcut!=NULL&&group_rule->ref_cnt==1&&shortcut_avilable_cnt<MAX_SCANNER_HIT_NUM)
		{			
			array_mi_rule[shortcut_avilable_cnt]=(struct _Maat_compile_inner_t*)(group_rule->compile_shortcut);
			shortcut_avilable_cnt++;
		}
		_mid->cur_hit_id[_mid->cur_hit_cnt]=group_rule->group_id;
		_mid->cur_hit_cnt++;
		ret=insert_set_id(&(_mid->hitted_group_id),
									&(_mid->hit_group_size),
									_mid->hit_group_cnt,
									(unsigned int)group_rule->group_id);
		_mid->hit_group_cnt+=ret;
	}
	if(shortcut_avilable_cnt==region_hit_num||shortcut_avilable_cnt==MAX_SCANNER_HIT_NUM)
	{
		//short cut for rules contains one group
		scan_ret=shortcut_avilable_cnt;
		aligment_int64_array_add(feather->orphan_group_saving, thread_num, 1);
	}
	else if(shortcut_avilable_cnt==0&&region_hit_num==1&&_mid->hit_group_cnt==1&&is_last_region==1)
	{
		//short cut for last scan and combination rules
		//region_hit_num==1 :  for current scan hitted rules, one and each other group may statisfy a compile rule.
		//_mid->hit_group_cnt==1: With pre scan hitted group rules, one group may staisfy a compile rule
		scan_ret=0;
		aligment_int64_array_add(feather->last_region_saving, thread_num, 1);
	}
	else
	{
		scan_ret=boolexpr_match(bool_matcher,thread_num, 
										_mid->hitted_group_id,_mid->hit_group_cnt,
										(void **)array_mi_rule, MAX_SCANNER_HIT_NUM);
	}
	for(i=0;i<scan_ret&&result_cnt<size;i++)
	{
		_mi_rule=array_mi_rule[i];
		if(_mi_rule==NULL||_mi_rule->db_c_rule==NULL)
		{
			continue;
		}
		
		if(0==pthread_rwlock_tryrdlock(&(_mi_rule->rwlock)))
		{
			make_group_set(_mi_rule,&(rs_result[result_cnt].group_set));
			r_in_c_cnt=pickup_hit_region_from_compile(&(rs_result[result_cnt].group_set),_mid->cur_hit_id,_mid->cur_hit_cnt,
										region_pos, MAX_SCANNER_HIT_NUM);
			if(r_in_c_cnt>0)//compile config hitted becasue of new reigon
			{
				memcpy(&(result[result_cnt]),&(_mi_rule->db_c_rule->m_rule_head),sizeof(struct _head_Maat_rule_t));
				memcpy(result[result_cnt].service_defined
						,_mi_rule->db_c_rule->service_defined
						,_mi_rule->db_c_rule->m_rule_head.serv_def_len);
				rs_result[result_cnt].compile_id=_mi_rule->compile_id;
				result_cnt++;
			}
			pthread_rwlock_unlock(&(_mi_rule->rwlock));
		}		
	}	
	if(result_cnt>0)
	{
		aligment_int64_array_add(feather->hit_cnt,thread_num,1);
	}
	return result_cnt;
}

int exprid2region_id(struct _Maat_group_inner_t* group_rule,int expr_id,int* district_id)
{
	int i=0,region_id=-1;
	struct _Maat_region_inner_t* region_rule=NULL;
	assert(group_rule->group_id>=0);
	pthread_mutex_lock(&(group_rule->mutex));
	for(i=0;i<group_rule->region_boundary;i++)
	{
		region_rule=(struct _Maat_region_inner_t*)dynamic_array_read(group_rule->regions, i);
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
	struct _Maat_group_inner_t* group_rule=NULL;
	int i=0;
	int district_id=-1,region_id=-1;
	int ret_region_num=region_hit_num;
	while(i<ret_region_num)
	{
		group_rule=(struct _Maat_group_inner_t*)(region_hit[i].tag);
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
	
	struct _Maat_group_inner_t* group_rule=NULL;
	//for each hitted compile cfg,find its region_ids
	for(i=0;i<compile_cnt&&i<detail_num;i++)
	{
		hit_detail[i].config_id=compile_hit[i].compile_id;
		r_in_c_cnt=pickup_hit_region_from_compile(&(compile_hit[i].group_set),_mid->cur_hit_id,_mid->cur_hit_cnt,
												region_pos, MAX_SCANNER_HIT_NUM);
		assert(r_in_c_cnt>0);//previous hitted compile was elimited in region_compile
		for(j=0,k=0;j<r_in_c_cnt&&k<MAAT_MAX_HIT_RULE_NUM;j++)
		{
			pos=region_pos[j];
			r_in_c_flag[pos]=1;
			group_rule=(struct _Maat_group_inner_t*)(region_hit[pos].tag);
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
			group_rule=(struct _Maat_group_inner_t*)(region_hit[k].tag);
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
	inner_mid=(struct _INNER_scan_status_t*)calloc(sizeof(struct _INNER_scan_status_t),1);
	inner_mid->cur_hit_cnt=0;
	inner_mid->hit_group_cnt=0;
	inner_mid->hit_group_size=4;
	inner_mid->hitted_group_id=(unsigned int*)malloc(sizeof(unsigned int)*inner_mid->hit_group_size);
	return inner_mid;
}
struct _OUTER_scan_status_t* _make_outer_status(_Maat_feather_t *feather,int thread_num)
{
	struct _OUTER_scan_status_t* outer_mid=NULL;
	outer_mid=(struct _OUTER_scan_status_t*)calloc(sizeof(struct _OUTER_scan_status_t),1);
	outer_mid->feather=feather;
	outer_mid->district_id=-1;
	outer_mid->thread_num=(unsigned short)thread_num;
	aligment_int64_array_add(feather->outer_mid_cnt, thread_num,1);
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
			aligment_int64_array_add(feather->inner_mid_cnt,thread_num,1);
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
	_Maat_feather_t* feather=(_Maat_feather_t*)calloc(sizeof(struct _Maat_feather_t),1);
	feather->table_cnt=read_table_info(feather->p_table_info, MAX_TABLE_NUM,table_info_path,max_thread_num,logger);
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
	feather->thread_call_cnt=aligment_int64_array_alloc(max_thread_num);
	feather->outer_mid_cnt=aligment_int64_array_alloc(max_thread_num);
	feather->inner_mid_cnt=aligment_int64_array_alloc(max_thread_num);
	feather->hit_cnt=aligment_int64_array_alloc(max_thread_num);
	feather->orphan_group_saving=aligment_int64_array_alloc(max_thread_num);
	feather->last_region_saving=aligment_int64_array_alloc(max_thread_num);
	feather->maat_version=0;
	feather->last_full_version=0;
	feather->base_grp_seq=0;
	feather->base_rgn_seq=0;
	feather->redis_index=0;
	feather->AUTO_NUMBERING_ON=1;
	feather->connect_timeout.tv_sec=0;
	feather->connect_timeout.tv_usec=100*1000; // 100 ms
	pthread_mutex_init(&(feather->plugin_table_reg_mutex),NULL);
	pthread_mutex_init(&(feather->redis_write_lock),NULL);
	snprintf(feather->table_info_fn,sizeof(feather->table_info_fn),"%s",table_info_path);
	return feather;
}
int Maat_set_feather_opt(Maat_feather_t feather,enum MAAT_INIT_OPT type,const void* value,int size)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	int intval=0,ret=-1;
	if(_feather->still_working==1)// not allowed set after Maat_initiate_feather;
	{
		return -2;
	}
	switch(type)
	{
		case MAAT_OPT_EFFECT_INVERVAL_MS:
			intval=*(const int*)value;
			if(size!=sizeof(int)||intval<=0)
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
			if(size>(int)sizeof(_feather->full_dir))
			{
				return -1;
			}
			memcpy(_feather->full_dir,(const char*)value,size);
			break;
		case MAAT_OPT_INC_CFG_DIR:
			if(size>(int)sizeof(_feather->inc_dir))
			{
				return -1;
			}
			memcpy(_feather->inc_dir,(const char*)value,size);
			break;
		case MAAT_OPT_JSON_FILE_PATH:
			ret=json2iris((const char*)value
				,_feather->compile_tn,_feather->group_tn
				,_feather->full_dir
				,sizeof(_feather->full_dir),_feather->logger);
			if(ret<0)
			{
				return -1;
			}
			memcpy(_feather->inc_dir,_feather->full_dir,sizeof(_feather->inc_dir));
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module ,
							"Maat initial with JSON file %s,generate index file %s OK."
							,(const char*)value
							,_feather->full_dir);
			break;
		case MAAT_OPT_STAT_ON:
			_feather->stat_on=1;
			_feather->stat_handle=FS_create_handle();
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
			if((size_t)size>sizeof(_feather->redis_ip))
			{
				return -1;
			}
			memcpy(_feather->redis_ip,value,size);
			break;
		case MAAT_OPT_REDIS_PORT:
			if((size_t)size==sizeof(unsigned short))
			{
				_feather->redis_port=*((unsigned short*)value);
			}
			else if((size_t)size==sizeof(int))
			{
				_feather->redis_port=*((int*)value);
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
			_feather->redis_index=*((int*)value);
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
		default:
			return -1;
	}
	return 0;
}
void maat_read_full_config(_Maat_feather_t* _feather)
{
	redisReply* reply=NULL;
	if(strlen(_feather->redis_ip)>0&&_feather->redis_port!=0)
	{
		_feather->REDIS_MODE_ON=1;
		MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_module ,
							"Maat initiate from Redis %s:%hu db%d."
							,_feather->redis_ip
							,_feather->redis_port
							,_feather->redis_index);
		_feather->redis_read_ctx=redisConnectWithTimeout(_feather->redis_ip,_feather->redis_port,_feather->connect_timeout);
		if(_feather->redis_read_ctx==NULL)
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module 
								,"Redis connect %s:%d failed."
								,_feather->redis_ip,_feather->redis_port);
		}
		else
		{
			redisEnableKeepAlive(_feather->redis_read_ctx);
			reply=_wrap_redisCommand(_feather->redis_read_ctx, "select %d",_feather->redis_index);
			freeReplyObject(reply);
			redis_monitor_traverse(_feather->maat_version
								,_feather->redis_read_ctx
								,maat_start_cb
								,maat_update_cb
								,maat_finish_cb
								, _feather
								,_feather->decrypt_key	//Not used.
								,_feather);
		}
	}
	else
	{
		if(strlen(_feather->full_dir)==0)
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module ,
								"At initiation: NO FULL_CFG_DIR or JSON_FILE_PATH. ");
		
			return;
		}
		config_monitor_traverse(_feather->maat_version,
								_feather->full_dir, 
								maat_start_cb,
								maat_update_cb,
								maat_finish_cb,
								_feather,
								_feather->decrypt_key,
								_feather->logger);
	}
	if(_feather->update_tmp_scanner==NULL)
	{
		if(_feather->REDIS_MODE_ON==1)
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module ,
							"At initiation: no avilable rule in redis in %s:%hu"
							,_feather->redis_ip
							,_feather->redis_port);

		}
		else
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module ,
							"At initiation: no valid index file in %s",_feather->full_dir);
		}
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
	if(_feather->DEFERRED_LOAD_ON==0)
	{
		maat_read_full_config(_feather);
	}
	if(strlen(_feather->stat_file)==0)
	{
		if(_feather->stat_on==1)
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module ,
								"At initiation: MAAT_OPT_STAT_FILE_PATH not set,TURN OFF STAT trigger.");
		}
		_feather->stat_on=0;
	}
	if(_feather->stat_on==0&&_feather->perf_on==1)
	{
		MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module ,
								"At initiation: STAT  tirigger OFF,  TURN OFF PERF trigger.");
		_feather->perf_on=0;
	}
	maat_stat_init(_feather);

	pthread_t cfg_mon_t;
	pthread_create(&cfg_mon_t, NULL, thread_rule_monitor, (void*)_feather);
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
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	_feather->still_working=0;//destroy will proceed in thread_rule_monitor
	return;
}
int Maat_table_register(Maat_feather_t feather,const char* table_name)
{
	struct _Maat_feather_t *_feather=(struct _Maat_feather_t *)feather;
	int table_id=-1,ret=0;
	ret=map_str2int(_feather->map_tablename2id, table_name,&table_id);
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
	_Maat_table_info_t *p_table=_feather->p_table_info[table_id];
	const char* lines=NULL;
	if(p_table==NULL)
	{
		return -1;
	}
	if(p_table->table_type!=TABLE_TYPE_PLUGIN)
	{
		return -1;
	}
	pthread_mutex_lock(&(_feather->plugin_table_reg_mutex));
	idx=p_table->cb_info->cb_plug_cnt;
	if(idx==MAX_PLUGING_NUM)
	{
		pthread_mutex_unlock(&(_feather->plugin_table_reg_mutex));
		return -1;
	}
	p_table->cb_info->cb_plug_cnt++;
	p_table->cb_info->cb_plug[idx].start=start;
	p_table->cb_info->cb_plug[idx].update=update;
	p_table->cb_info->cb_plug[idx].finish=finish;
	p_table->cb_info->cb_plug[idx].u_para=u_para;
	if(p_table->cb_info->cache_line_num>0)
	{
		if(start!=NULL)
		{
			start(MAAT_RULE_UPDATE_TYPE_FULL,u_para);
		}
		for(i=0;i<p_table->cb_info->cache_line_num;i++)
		{
			lines=(const char*)dynamic_array_read(p_table->cb_info->cache_lines,i);
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
	pthread_mutex_unlock(&(_feather->plugin_table_reg_mutex));
	return 1;
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
	struct _Maat_table_info_t *p_table=NULL;
	struct timespec start,end;
	_Maat_scanner_t* my_scanner=NULL;
	if(data==NULL||data_len<=0)
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

	if(p_table->cfg_num==0)
	{
		return 0;
	}
	if(p_table->table_type==TABLE_TYPE_EXPR_PLUS&&(_mid==NULL||_mid->is_set_district!=1))
	{
		_feather->scan_err_cnt++;
		return -1;
	}
	if(p_table->do_charset_merge==1)
	{
		sub_type=make_sub_type(table_id,CHARSET_NONE,0);
	}
	else
	{
		sub_type=make_sub_type(table_id,charset,0);
	}
	aligment_int64_array_add(_feather->thread_call_cnt, thread_num, 1);
	scan_data_t scan_data;
	scan_data.text_data.text=data;
	scan_data.text_data.tlen=data_len;
	scan_data.text_data.toffset=0;
	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}
	struct _region_stat_t * region_stat=NULL;
	region_stat=&(my_scanner->region_counter[p_table->table_id]);
	if(region_stat->cfg_num==0)
	{
		return 0;
	}
	assert(thread_num<_feather->scan_thread_num);
	region_result=my_scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*thread_num;
	
	INC_SCANNER_REF(my_scanner, thread_num);
	if(region_stat->expr_rule_cnt>0)
	{
		scan_data.rule_type=RULETYPE_STR;
		scan_data.sub_type=sub_type;
		region_ret=rulescan_search(my_scanner->region, thread_num, &scan_data, region_result, MAX_SCANNER_HIT_NUM);
		if(region_ret>0)
		{
			hit_region_cnt+=region_ret;
		}
	}
	if(region_stat->regex_rule_cnt>0)
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
	if(hit_region_cnt>0)
	{
		aligment_int64_array_add(p_table->hit_cnt, thread_num,1);
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
		if(hit_detail!=NULL&&_feather->rule_scan_type!=0)
		{
			*detail_ret=fill_region_hit_detail(data,_mid->inner,										
											region_result,hit_region_cnt,
											compile_result,compile_ret, 
											hit_detail,detail_num);
		}
	}
	DEC_SCANNER_REF(my_scanner, thread_num);
	if(_feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&end);
		maat_stat_table(p_table,data_len,&start, &end,thread_num);
	}
	else
	{
		maat_stat_table(p_table,data_len,NULL, NULL,thread_num);
	}

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
	struct _Maat_scanner_t* my_scanner=NULL;
	intval_scan_data.rule_type=RULETYPE_INT;
	intval_scan_data.sub_type=make_sub_type(table_id,CHARSET_NONE, 0);
	intval_scan_data.int_data=intval;
	_Maat_table_info_t* p_table=NULL;
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
	if(p_table->cfg_num==0)
	{
		return 0;
	}
	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}
	struct _region_stat_t * region_stat=NULL;
	region_stat=&(my_scanner->region_counter[p_table->table_id]);
	if(region_stat->cfg_num==0)
	{
		return 0;
	}
	aligment_int64_array_add(_feather->thread_call_cnt, thread_num, 1);

	region_result=my_scanner->region_rslt_buff+MAX_SCANNER_HIT_NUM*thread_num;
	
	INC_SCANNER_REF(my_scanner,thread_num);
	region_ret=rulescan_search(my_scanner->region, thread_num, &intval_scan_data, region_result, MAX_SCANNER_HIT_NUM);
	if(region_ret<0)
	{
		DEC_SCANNER_REF(my_scanner, thread_num);
		_feather->scan_err_cnt++;
		return -1;
	}
	else if(region_ret>0)
	{
		aligment_int64_array_add(p_table->hit_cnt, thread_num,1);
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
		maat_stat_table(p_table,0,&start, &end,thread_num);
	}
	else
	{
		maat_stat_table(p_table,0,NULL, NULL,thread_num);
	}
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
	_Maat_table_info_t* p_table=NULL;
	
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _Maat_scanner_t* my_scanner=NULL;
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
	if(p_table->cfg_num==0)
	{
		return 0;
	}
	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}
	struct _region_stat_t * region_stat=NULL;
	region_stat=&(my_scanner->region_counter[p_table->table_id]);
	if(region_stat->cfg_num==0)
	{
		return 0;
	}
	if(region_stat->ipv4_rule_cnt==0&&addr->addrtype==ADDR_TYPE_IPV4)
	{
		return 0;
	}
	if(region_stat->ipv6_rule_cnt==0&&addr->addrtype==ADDR_TYPE_IPV6)
	{
		return 0;
	}
	aligment_int64_array_add(_feather->thread_call_cnt, thread_num, 1);

	ip_scan_data.rule_type=RULETYPE_IPv4;
	ip_scan_data.sub_type=make_sub_type(table_id,CHARSET_NONE, 0);
	switch(addr->addrtype)
	{
		case ADDR_TYPE_IPV4:
			ip_scan_data.ipv4_data.saddr=ntohl(addr->paddr.v4->saddr);
			ip_scan_data.ipv4_data.daddr=ntohl(addr->paddr.v4->daddr);
			ip_scan_data.ipv4_data.sport=ntohs(addr->paddr.v4->source);
			ip_scan_data.ipv4_data.dport=ntohs(addr->paddr.v4->dest);
			ip_scan_data.ipv4_data.proto=proto;
			break;
		case ADDR_TYPE_IPV6:
			ip_scan_data.rule_type=RULETYPE_IPv6;
			memcpy(ip_scan_data.ipv6_data.saddr,addr->paddr.v6->saddr,sizeof(ip_scan_data.ipv6_data.saddr));
			ipv6_ntoh(ip_scan_data.ipv6_data.saddr);
			memcpy(ip_scan_data.ipv6_data.daddr,addr->paddr.v6->daddr,sizeof(ip_scan_data.ipv6_data.daddr));
			ipv6_ntoh(ip_scan_data.ipv6_data.daddr);
			ip_scan_data.ipv6_data.sport=ntohs(addr->paddr.v6->source);
			ip_scan_data.ipv6_data.dport=ntohs(addr->paddr.v6->dest);
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
	else if(region_ret>0)
	{
		aligment_int64_array_add(p_table->hit_cnt, thread_num,1);
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
		maat_stat_table(p_table,0,&start, &end,thread_num);
	}
	else
	{
		maat_stat_table(p_table,0,NULL, NULL,thread_num);
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
	struct _Maat_scanner_t* scanner=NULL;

	struct _Maat_table_info_t *p_table=NULL;
	assert(thread_num<_feather->scan_thread_num);
	p_table=acqurie_table(_feather, table_id, TABLE_TYPE_EXPR);
	if(p_table==NULL)
	{
		_feather->scan_err_cnt++;
		return NULL;
	}
	if(p_table->quick_expr_switch==1)
	{
		_feather->scan_err_cnt++;
		return NULL;
	}
	struct _stream_para_t* sp=(struct _stream_para_t*)calloc(sizeof(struct _stream_para_t),1);
	scanner=_feather->scanner;
	sp->feather=_feather;
	sp->version=_feather->maat_version;
	sp->process_offset=0;
	sp->rs_stream_para=NULL;
	if(scanner==NULL)
	{
		return sp;
	}
	struct _region_stat_t * region_stat=NULL;
	region_stat=&(scanner->region_counter[p_table->table_id]);
	INC_SCANNER_REF(scanner, thread_num);

	sp->table_id=table_id;
	sp->thread_num=thread_num;
	sp->max_cross_size=p_table->cross_cache_size;
	sp->caching_size=0;
	sp->scan_buff=NULL;
	sp->last_cache=NULL;
	if(p_table->do_charset_merge==1)
	{
		sp->do_merge=1;
	}
	if(region_stat->expr_rule_cnt>0)
	{
		sp->do_expr=1;
	}
	if(region_stat->regex_rule_cnt>0)
	{
		sp->do_regex=1;
	}
	aligment_int64_array_add(p_table->stream_num,thread_num,1);
	sp->rs_stream_para=rulescan_startstream(_feather->scanner->region,thread_num);
	return sp;
}

int Maat_stream_scan_string_detail(stream_para_t* stream_para
									,enum MAAT_CHARSET charset,const char* data,int data_len
									,struct Maat_rule_t*result,int rule_num,struct Maat_hit_detail_t *hit_detail,int detail_num
									,int* detail_ret,scan_status_t* mid)
{
	struct _stream_para_t* sp=(struct _stream_para_t*)(*stream_para);
	struct _Maat_scanner_t* scanner=sp->feather->scanner;

	int sub_type=0;
	int region_ret=0,hit_region_cnt=0,compile_ret=0;
	struct _OUTER_scan_status_t* _mid=NULL;
	scan_result_t *region_result;
	_compile_result_t compile_result[rule_num];//dynamic array
	scan_data_t region_scan_data;
	_Maat_table_info_t* p_table=NULL;
	struct timespec start,end;	
	if(data==NULL||data_len<=0)
	{
		return 0;
	}
	if(sp->feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}
	_mid=grab_mid(mid, sp->feather, sp->thread_num,0);

	if(scanner==NULL)
	{
		return 0;
	}
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
	aligment_int64_array_add(sp->feather->thread_call_cnt, sp->thread_num, 1);
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
		sp->scan_buff=(char*)malloc(sp->caching_size+data_len);
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
		sp->last_cache=(char*)malloc(sizeof(char)*sp->max_cross_size);
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
	if(hit_region_cnt>0)
	{
		aligment_int64_array_add(p_table->hit_cnt, sp->thread_num,1);
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
		maat_stat_table(sp->feather->p_table_info[sp->table_id],data_len,&start, &end,sp->thread_num);
	}
	else
	{
		maat_stat_table(sp->feather->p_table_info[sp->table_id],data_len,NULL, NULL,sp->thread_num);
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
	struct _Maat_scanner_t* scanner=sp->feather->scanner;
	struct _Maat_table_info_t * p_table=sp->feather->p_table_info[sp->table_id];
	aligment_int64_array_add(p_table->stream_num,sp->thread_num,-1);
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
	struct _Maat_scanner_t* scanner=NULL;
	sfh_instance_t * tmp_fuzzy_handle=NULL;
	struct _Maat_table_info_t *p_table=NULL;
	p_table=acqurie_table(_feather, table_id, TABLE_TYPE_DIGEST);
	if(p_table==NULL)
	{
		_feather->scan_err_cnt++;
		return NULL;
	}
	tmp_fuzzy_handle=SFH_instance(total_len);
	if(tmp_fuzzy_handle==NULL)
	{
		_feather->scan_err_cnt++;
		return NULL;
	}
	struct _stream_para_t* sp=(struct _stream_para_t*)calloc(sizeof(struct _stream_para_t),1);
	scanner=_feather->scanner;
	sp->feather=_feather;
	sp->version=_feather->maat_version;
	sp->process_offset=0;
	if(scanner==NULL)
	{
		return sp;
	}
	INC_SCANNER_REF(scanner, thread_num);
	sp->table_id=table_id;
	sp->thread_num=thread_num;
	sp->total_len=total_len;
	sp->fuzzy_hash_handle=tmp_fuzzy_handle;
	pthread_mutex_init(&(sp->fuzzy_mutex),NULL);
	aligment_int64_array_add(p_table->stream_num,thread_num,1);
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
	GIE_handle_t* GIE_handle=sp->feather->scanner->gie_aux[sp->table_id].gie_handle;
	unsigned long long digest_len=0;
	char* digest_buff=NULL;
	struct _OUTER_scan_status_t* _mid=NULL;
	struct timespec start,end;
	if(sp->feather->perf_on==1)
	{
		clock_gettime(CLOCK_MONOTONIC,&start);
	}

	aligment_int64_array_add(sp->feather->thread_call_cnt, sp->thread_num, 1);
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
	digest_buff=(char*)malloc(sizeof(char)*digest_len);
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
	if(hit_region_cnt>0)
	{
		sp->feather->p_table_info[sp->table_id]->hit_cnt++;
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
		maat_stat_table(sp->feather->p_table_info[sp->table_id],data_len,&start, &end,sp->thread_num);
	}
	else
	{
		maat_stat_table(sp->feather->p_table_info[sp->table_id],data_len,NULL, NULL,sp->thread_num);
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
	struct _Maat_scanner_t* scanner=sp->feather->scanner;
	struct _Maat_table_info_t * p_table=sp->feather->p_table_info[sp->table_id];
	aligment_int64_array_add(p_table->stream_num,sp->thread_num,-1);
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
	int region_ret=0,compile_ret=0;
	struct _OUTER_scan_status_t* _mid=NULL;
	GIE_result_t region_result[MAX_SCANNER_HIT_NUM];
	_compile_result_t compile_result[rule_num];
	struct _Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _Maat_scanner_t* my_scanner=NULL;
	_Maat_table_info_t* p_table=NULL;
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
	if(p_table->cfg_num==0)
	{
		return 0;
	}
	my_scanner=_feather->scanner;
	if(my_scanner==NULL)
	{
		return 0;
	}
	GIE_handle_t* gie_handle=my_scanner->gie_aux[table_id].gie_handle;
	struct _region_stat_t * region_stat=NULL;
	region_stat=&(my_scanner->region_counter[p_table->table_id]);
	if(region_stat->cfg_num==0)
	{
		return 0;
	}
	aligment_int64_array_add(_feather->thread_call_cnt, thread_num, 1);
	
	INC_SCANNER_REF(my_scanner,thread_num);
	region_ret=GIE_query(gie_handle, data, data_len,region_result, MAX_SCANNER_HIT_NUM);
	if(region_ret<0)
	{
		DEC_SCANNER_REF(my_scanner, thread_num);
		_feather->scan_err_cnt++;
		return -1;
	}
	else if(region_ret>0)
	{
		aligment_int64_array_add(p_table->hit_cnt, thread_num,1);
		_mid=grab_mid(mid, _feather, thread_num, 1);
		compile_ret=region_compile(_feather,_mid->inner,
									_mid->is_last_region,
									region_result,sizeof(GIE_result_t),offsetof(GIE_result_t, tag),
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
		maat_stat_table(p_table,0,&start, &end,thread_num);
	}
	else
	{
		maat_stat_table(p_table,0,NULL, NULL,thread_num);
	}
	if(compile_ret==0&&region_ret>0)
	{
		return -2;
	}
	return compile_ret;

}
void Maat_clean_status(scan_status_t* mid)
{
	struct _OUTER_scan_status_t* _mid=NULL;
	if(*mid==NULL)
	{
		return;
	}
	_mid=(struct _OUTER_scan_status_t*)(*mid);
	aligment_int64_array_add(_mid->feather->outer_mid_cnt,_mid->thread_num,-1);
	if(_mid->inner!=NULL)
	{
		free(_mid->inner->hitted_group_id);
		free(_mid->inner);
		aligment_int64_array_add(_mid->feather->inner_mid_cnt,_mid->thread_num,-1);
	}
	_mid->feather=NULL;
	free(_mid);
	*mid=NULL;
	return;
}
