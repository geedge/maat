#include "Maat_command.h"
#include "Maat_rule.h"
#include "Maat_rule_internal.h"
#include "config_monitor.h"
#include "map_str2int.h"
#include "hiredis.h"
#include <MESA/MESA_handle_logger.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>

const char* maat_redis_monitor="MAAT_REDIS_MONITOR";
const char* maat_redis_command="MAAT_REDIS_COMMAND";

const char* rm_key_prefix[2]={"OBSOLETE_RULE","EFFECTIVE_RULE"};

const int MAAT_REDIS_SYNC_TIME=30*60;

struct serial_rule_t		//rm= Redis Maat
{
	enum MAAT_OPERATION op;//0: delete, 1: add.
	int rule_id;
	char table_name[256];
	char* table_line;
};

struct _Maat_cmd_inner_t
{
	struct Maat_command_t cmd;
	enum MAAT_OPERATION op;
	int ref_cnt;
	int region_size[MAX_EXPR_ITEM_NUM];
	struct _Maat_cmd_inner_t* next;
};
enum MAAT_TABLE_TYPE type_region2table(const struct Maat_region_t* p)
{
	enum MAAT_TABLE_TYPE ret=TABLE_TYPE_IP;
	switch(p->region_type)
	{
		case REGION_IP:
			ret=TABLE_TYPE_IP;
			break;
		case REGION_EXPR:
			if(p->expr_rule.district==NULL)
			{
				ret=TABLE_TYPE_EXPR;
			}
			else
			{
				ret=TABLE_TYPE_EXPR_PLUS;
			}
			break;
		case REGION_INTERVAL:
			ret=TABLE_TYPE_INTERVAL;
			break;
		case REGION_DIGEST:
			ret=TABLE_TYPE_DIGEST;
			break;
		case REGION_SIMILARITY:
			ret=TABLE_TYPE_SIMILARITY;
			break;
		default:
			assert(0);
	}
	return ret;
}
void invalidate_line(char* line, enum MAAT_TABLE_TYPE type,int valid_column_seq)
{
	unsigned int offset=0;
	unsigned int i=0,j=0;
	switch(type)
	{
		case	TABLE_TYPE_EXPR:
			offset=7;
			break;
		case	TABLE_TYPE_IP:
			offset=14;
			break;
		case	TABLE_TYPE_COMPILE:
			offset=8;
			break;
		case	TABLE_TYPE_PLUGIN:
			if(valid_column_seq<0)
			{
				return;
			}
			offset=(unsigned int)valid_column_seq;
			break;
		case	TABLE_TYPE_INTERVAL:
			offset=5;
			break;
		case	TABLE_TYPE_DIGEST:
			offset=6;
			break;
		case	TABLE_TYPE_EXPR_PLUS:
			offset=8;
			break;
		case	TABLE_TYPE_GROUP:
			offset=3;
			break;
		default:
			assert(0);
	}
	for(i=0;i<strlen(line);i++)
	{
		if(line[i]==' '||line[i]=='\t')
		{
			j++;
		}
		if(j==offset)
		{
			break;
		}
	}
	assert(i<strlen(line));
	assert(line[i]=='1');
	line[i]='0';
	return;
}
void serialize_region(const struct Maat_region_t* p,int group_id, char* buff,int size)
{
	int ret=0;
	switch(p->region_type)
	{
		case REGION_IP:
			ret=snprintf(buff,size,"%d\t%d\t%d\t%s\t%s\t%hu\t%hu\t%s\t%s\t%hu\t%hu\t%d\t%d\t1"
													,p->region_id
													,group_id
													,p->ip_rule.addr_type
													,p->ip_rule.src_ip
													,p->ip_rule.mask_src_ip
													,p->ip_rule.src_port
													,p->ip_rule.mask_src_port
													,p->ip_rule.dst_ip
													,p->ip_rule.mask_dst_ip
													,p->ip_rule.dst_port
													,p->ip_rule.mask_dst_port
													,p->ip_rule.protocol
													,p->ip_rule.direction);	
			break;
		case REGION_EXPR:
			if(p->expr_rule.district==NULL)
			{
				ret=snprintf(buff,size,"%d\t%d\t%s\t%d\t%d\t%d\t1"
													,p->region_id
													,group_id
													,p->expr_rule.keywords
													,p->expr_rule.expr_type
													,p->expr_rule.match_method
													,p->expr_rule.hex_bin);	
			}
			else	//expr_plus
			{
				ret=snprintf(buff,size,"%d\t%d\t%s\t%s\t%d\t%d\t%d\t1"
													,p->region_id
													,group_id
													,p->expr_rule.keywords
													,p->expr_rule.district
													,p->expr_rule.expr_type
													,p->expr_rule.match_method
													,p->expr_rule.hex_bin);	
			}
			break;
		case REGION_INTERVAL:
			ret=snprintf(buff,size,"%d\t%d\t%u\t%u\t1"
													,p->region_id
													,group_id
													,p->interval_rule.low_boundary
													,p->interval_rule.up_boundary);
			break;
		case REGION_DIGEST:
			ret=snprintf(buff,size,"%d\t%d\t%llu\t%s\t%hd\t1"
													,p->region_id
													,group_id
													,p->digest_rule.orgin_len
													,p->digest_rule.digest_string
													,p->digest_rule.confidence_degree);
			break;
		case REGION_SIMILARITY://not support yet
			assert(0);
			break;
		default:
			assert(0);
	}
	assert(ret<size);
	return;
}
void empty_serial_rules(struct serial_rule_t* rule)
{
	if(rule->table_line!=NULL)
	{
		free(rule->table_line);
		rule->table_line=NULL;
	}
	memset(rule,0,sizeof(struct serial_rule_t));
	return;
}
void set_serial_rule(struct serial_rule_t* rule,enum MAAT_OPERATION op,int rule_id,const char* table_name,const char* line)
{
	rule->op=op;
	rule->rule_id=rule_id;
	assert(strlen(table_name)<sizeof(rule->table_name));
	memcpy(rule->table_name,table_name,strlen(table_name));
	if(line!=NULL)
	{
		rule->table_line=_maat_strdup(line);
	}
	return;
}
int get_rm_key_list(unsigned int version,redisContext *c,struct serial_rule_t** list,void* logger, unsigned int* new_version,int *update_type)
{
	redisReply* reply=NULL,*tmp_reply=NULL;
	char err_buff[256];
	char op_str[4];
	long long version_in_redis=0,nearest_rule_version=0;
	int ret=0,retry=0;
	unsigned int i=0;
	struct serial_rule_t *s_rule=NULL;


	while(retry<1)
	{
		reply=(redisReply*)redisCommand(c, "GET MAAT_VERSION");
		if(reply!=NULL)
		{
			break;
		}
		if(c->err==REDIS_ERR_EOF)
		{
			__redis_strerror_r(errno,err_buff,sizeof(err_buff));
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
									"GET MAAT_VERSION failed %s. Reconnecting...",err_buff);
			ret=redisReconnect(c);
			retry++;
			continue;
		}
		else
		{
			__redis_strerror_r(errno,err_buff,sizeof(err_buff));
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
									"GET MAAT_VERSION failed %s.",err_buff);
			return 0;
		}	
	}
	assert(reply->type==REDIS_REPLY_STRING);
	version_in_redis=atoll(reply->str);
	assert(version_in_redis>=version);
	freeReplyObject(reply);
	if(version_in_redis==version)
	{		
		return 0;
	}
	*new_version=version_in_redis;
	
	if(version==0)
	{
		goto FULL_UPDATE;
	}

	
	//Returns all the elements in the sorted set at key with a score that version < score <= version_in_redis.
	//The elements are considered to be ordered from low to high scores(version).
	reply=(redisReply*)redisCommand(c, "ZRANGE MAAT_UPDATE_STATUS (%d %d",version,version_in_redis);
	if(reply==NULL)
	{
		__redis_strerror_r(errno,err_buff,sizeof(err_buff));
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
								"GET MAAT_UPDATE_STATUS failed %s.",err_buff);
		return 0;
	}	
	assert(reply->type==REDIS_REPLY_ARRAY);
	tmp_reply=(redisReply*)redisCommand(c, "ZRANK MAAT_UPDATE_STATUS %s",reply->element[0]->str);
	nearest_rule_version=tmp_reply->integer;
	freeReplyObject(tmp_reply);
	tmp_reply=NULL;
	if(nearest_rule_version!=version+1)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
								"Noncontinuous VERSION Redis: %lld MAAT: %d.",tmp_reply->integer,version);

		goto FULL_UPDATE;
	}
	else
	{
		MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
								"Inc Update form version %d to %lld.",version,version_in_redis);
	}
	s_rule=(struct serial_rule_t*)calloc(reply->elements,sizeof(struct serial_rule_t));
	for(i=0;i<reply->elements;i++)
	{
		assert(reply->element[i]->type==REDIS_REPLY_STRING);
		ret=sscanf(reply->element[i]->str,"%[^:]:%[^,],%d",op_str,s_rule[i].table_name,&(s_rule[i].rule_id));
		assert(ret==3);
		if(strncmp(op_str,"ADD",strlen("ADD"))==0)
		{
			s_rule[i].op=MAAT_OP_ADD;
		}
		else if(strncmp(op_str,"DEL",strlen("DEL"))==0)
		{
			s_rule[i].op=MAAT_OP_DEL;
		}
		else
		{
			assert(0);
		}
	}
	*list=s_rule;
	*update_type=CM_UPDATE_TYPE_INC;
	freeReplyObject(reply);
	return i;
FULL_UPDATE:
	MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
								"Initiate full udpate from version %d to %lld.",version,version_in_redis);
	reply=(redisReply*)redisCommand(c, "KEYS EFFECTIVE_RULE:*");
	assert(reply->type==REDIS_REPLY_ARRAY);
	s_rule=(struct serial_rule_t*)calloc(reply->elements,sizeof(struct serial_rule_t));
	for(i=0;i<reply->elements;i++)
	{
		assert(reply->element[i]->type==REDIS_REPLY_STRING);
		ret=sscanf(reply->element[i]->str,"%*[^:]:%[^,],%d",s_rule[i].table_name,&(s_rule[i].rule_id));
		s_rule[i].op=MAAT_OP_ADD;
		assert(ret==2);	
	}
	*list=s_rule;
	*update_type=CM_UPDATE_TYPE_FULL;

	freeReplyObject(reply);
	reply=NULL;
	return i;
}
int _wrap_redisGetReply(redisContext *c, redisReply **reply)
{
	return redisGetReply(c, (void **)reply);
}
redisReply *_wrap_redisCommand(redisContext *c, const char *format, ...)
{
    va_list ap;
    void *reply = NULL;
    va_start(ap,format);
    reply = redisvCommand(c,format,ap);
    va_end(ap);
    return (redisReply *)reply;
}
int calculate_serial_rule_num(struct _Maat_cmd_inner_t* _cmd,int * new_region_cnt, int* new_group_cnt)
{
	int serial_num=0;
	int i=0;
	struct Maat_command_t* cmd=&(_cmd->cmd);
	serial_num++;//compile rule
	for(i=0;i<cmd->group_num;i++)
	{
		serial_num++;
		if(cmd->groups[i].regions==NULL)
		{
			continue;
		}
		if(_cmd->op==MAAT_OP_ADD)
		{
			*new_region_cnt+=cmd->groups[i].region_num;
			(*new_group_cnt)++;
		}
	}
	return serial_num;
}
int reconstruct_cmd(struct _Maat_feather_t *feather, struct _Maat_cmd_inner_t* _cmd)
{
	int i=0,j=0,grp_idx=0;
	struct Maat_command_t* cmd=&(_cmd->cmd);
	struct Maat_group_t* group_cmd=NULL;
	struct Maat_region_t* region_cmd=NULL;

	struct _Maat_compile_inner_t *compile_inner=NULL;
	struct _Maat_group_inner_t* group_inner=NULL;
	struct _Maat_region_inner_t* region_inner=NULL;
	void* logger=feather->logger;
	
	int config_id=cmd->compile.config_id;
	compile_inner=(struct _Maat_compile_inner_t *)HASH_fetch_by_id(feather->scanner->compile_hash, config_id);
	if(compile_inner==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_redis_command 
							,"config %d not exist."
							,config_id);
		return -1;
	}
	cmd->group_num=compile_inner->group_cnt;
	assert(cmd->groups==NULL);
	cmd->groups=(struct Maat_group_t*)calloc(sizeof(struct Maat_group_t),cmd->group_num);
	for(i=0;i<compile_inner->group_boundary;i++)
	{
		group_inner=(struct _Maat_group_inner_t*)dynamic_array_read(compile_inner->groups,i);
		if(group_inner==NULL)
		{
			continue;
		}
		group_cmd=&(cmd->groups[grp_idx]);
		group_cmd->group_id=group_inner->group_id;
		
		if(group_inner->ref_cnt>0)
		{
			continue;
		}
		group_cmd->region_num=group_inner->region_cnt;
		group_cmd->regions=(struct Maat_region_t*)calloc(sizeof(struct Maat_region_t),group_cmd->region_num);
		for(j=0;j<group_inner->region_boundary;j++)
		{
			region_inner=(struct _Maat_region_inner_t*)dynamic_array_read(group_inner->regions,i);
			if(region_inner==NULL)
			{
				continue;
			}
			region_cmd=&(group_cmd->regions[group_cmd->region_num]);
			region_cmd->table_name=_maat_strdup(feather->p_table_info[region_inner->table_id]->table_name[0]);
			region_cmd->region_id=region_inner->table_id;
			//NOTICE: region_type only avilable when OP_ADD, 
			region_cmd->region_type=REGION_EXPR;
			group_cmd->region_num++;
		}
		grp_idx++;
	}
	return 0;
}

int build_serial_rule(_Maat_feather_t *feather,struct _Maat_cmd_inner_t* _cmd,struct serial_rule_t* list, int size)
{
	struct Maat_group_t* p_group=NULL;
	struct Maat_region_t* p_region=NULL;
	struct Maat_rule_t* p_m_rule=NULL;
	struct Maat_command_t* cmd=&(_cmd->cmd);
	enum MAAT_OPERATION op=_cmd->op;

	int rule_num=0,i=0,j=0;
	p_m_rule=&(cmd->compile);
	char line[1024];
	if(op==MAAT_OP_ADD)
	{
		snprintf(line,sizeof(line),"%d\t%d\t%hhd\t%hhd\t%hhd\t0\t%s\t1\t%d",p_m_rule->config_id
														,p_m_rule->service_id
														,p_m_rule->action
														,p_m_rule->do_blacklist
														,p_m_rule->do_log
														,p_m_rule->service_defined
														,cmd->group_num);
		set_serial_rule(list+rule_num,MAAT_OP_ADD,cmd->compile.config_id,feather->compile_tn,line);

	}
	else
	{
		set_serial_rule(list+rule_num,MAAT_OP_DEL,cmd->compile.config_id,feather->compile_tn,NULL);
	}
	rule_num++;
	for(i=0;cmd->group_num;i++)
	{		
		p_group=&(cmd->groups[i]);
		if(op==MAAT_OP_ADD)
		{
			p_group->group_id=feather->base_grp_seq;
			feather->base_grp_seq++;
			snprintf(line,sizeof(line),"%d\t%d\t1",p_group->group_id
												,p_m_rule->config_id);
			set_serial_rule(list+rule_num,MAAT_OP_ADD,p_group->group_id,feather->group_tn,line);
		}
		else
		{
			set_serial_rule(list+rule_num,MAAT_OP_DEL,p_group->group_id,feather->group_tn,NULL);
		}
		rule_num++;
		if(p_group->regions==NULL)//group reuse.
		{
			continue;
		}
		for(j=0;j<p_group->region_num;j++)
		{
			p_region=&(p_group->regions[j]);
			if(op==MAAT_OP_ADD)
			{
				p_region->region_id=feather->base_rgn_seq;
				feather->base_rgn_seq++;
				serialize_region(p_region, p_group->group_id, line, sizeof(line));
				set_serial_rule(list+rule_num,MAAT_OP_ADD
								,p_region->region_id,p_region->table_name,line);
			}
			else
			{
				set_serial_rule(list+rule_num,MAAT_OP_DEL
								,p_region->region_id,p_region->table_name,NULL);

			}
			rule_num++;
		}
	}
	assert(rule_num<size);
	return rule_num;
}
int mr_transaction_success(redisReply* data_reply)
{
	unsigned int i=0;
	for(i=0;i<data_reply->elements;i++)
	{
		if(data_reply->element[i]->type==REDIS_REPLY_NIL)
		{
			return 0;
		}
	}
	return 1;
}
int fix_table_name(_Maat_feather_t* feather,struct Maat_command_t* cmd)
{
	int i=0,j=0,ret=0;
	const char *table_name=NULL;
	int table_id=0;
	struct Maat_group_t* p_group=NULL;
	struct Maat_region_t* p_region=NULL;
	enum MAAT_TABLE_TYPE table_type;
	for(i=0;i<cmd->group_num;i++)
	{
		p_group=&(cmd->groups[i]);
		for(j=0;j<p_group->region_num;j++)
		{
			p_region=&(p_group->regions[j]);
			table_name=p_region->table_name;
			ret=map_str2int(feather->map_tablename2id, table_name, &table_id);
			if(ret<0)
			{
				MESA_handle_runtime_log(feather->logger,RLOG_LV_FATAL,maat_module 
									,"Unknown table %s of Maat_command_t[%d]->group[%d]->region[%d]."
									,table_name,cmd->compile.config_id,i,j);

				return -1;
			}
			table_type=type_region2table(p_region);
			if(table_type!=feather->p_table_info[i]->table_type)
			{
				MESA_handle_runtime_log(feather->logger,RLOG_LV_FATAL,maat_module 
									,"Table %s not support region type %d of Maat_command_t[%d]->group[%d]->region[%d]."
									,table_name
									,p_region->region_type
									,cmd->compile.config_id,i,j);
				return -1;
			}
			free((char*)p_region->table_name);
			p_region->table_name=_maat_strdup(feather->p_table_info[i]->table_name[0]);
		}
	}
	return 0;
}

void redis_monitor_traverse(unsigned int version,redisContext *c,
							void (*start)(unsigned int ,int ,void*),//vesion,CM_UPDATE_TYPE_*,u_para
							void (*update)(const char* ,const char*,void* ),//table name ,line ,u_para
							void (*finish)(void*),//u_para
							void* u_para,
							const unsigned char* dec_key,
							_Maat_feather_t* feather)
{
	redisReply* data_reply=NULL;
	unsigned int rule_num=0,i=0;
	int table_id=0;
	int ret=0;
	char redis_cmd[256];
	struct serial_rule_t* rule_list=NULL;
	int update_type=0;
	unsigned int new_version=0;
	enum MAAT_TABLE_TYPE table_type;
	void* logger=feather->logger;
	rule_num=get_rm_key_list(version, c, &rule_list, logger,&new_version, &update_type);
	if(rule_num==0)
	{
		return;
	}
	for(i=0;i<rule_num;i++)
	{
		snprintf(redis_cmd,sizeof(redis_cmd),"GET %s:%s,%d",rm_key_prefix[rule_list[i].op]
											,rule_list[i].table_name
											,rule_list[i].rule_id);
		ret=redisAppendCommand(c, redis_cmd);
		assert(ret==REDIS_OK);
	}
	start(new_version,update_type,u_para);
	for(i=0;i<rule_num;i++)
	{
		ret=_wrap_redisGetReply(c,&data_reply);
		assert(ret==REDIS_OK);
		if(rule_list[i].op==MAAT_OP_DEL)
		{
			ret=map_str2int(feather->map_tablename2id,rule_list[i].table_name,&table_id);
			if(ret<0)//Unrecognized table.
			{
				continue;
			}
			table_type=feather->p_table_info[table_id]->table_type;
			invalidate_line(data_reply->str,table_type,feather->p_table_info[table_id]->valid_flag_column);
		}
		update(rule_list[i].table_name,data_reply->str,u_para);
		freeReplyObject(data_reply);
	}
	finish(u_para);
	// no need to calll empty_serial_rules
	free(rule_list);
	rule_list=NULL;
	return;
}

void Maat_copy_region(struct Maat_region_t* dst,const struct Maat_region_t* src)
{
	memcpy(dst,src,sizeof(struct Maat_region_t));
	if(src->table_name!=NULL)
	{
		dst->table_name=_maat_strdup(src->table_name);
	}
	switch(dst->region_type)
	{
		case REGION_IP:
			dst->ip_rule.src_ip=_maat_strdup(src->ip_rule.src_ip);
			dst->ip_rule.mask_src_ip=_maat_strdup(src->ip_rule.mask_src_ip);
			dst->ip_rule.dst_ip=_maat_strdup(src->ip_rule.dst_ip);
			dst->ip_rule.mask_src_ip=_maat_strdup(src->ip_rule.mask_src_ip);
			break;
		case REGION_EXPR:
			dst->expr_rule.keywords=_maat_strdup(src->expr_rule.keywords);
			dst->expr_rule.district=_maat_strdup(src->expr_rule.district);
			break;
		case REGION_INTERVAL:
			break;
		case REGION_DIGEST:
			dst->digest_rule.digest_string=_maat_strdup(src->digest_rule.digest_string);
			break;
		case REGION_SIMILARITY:
			assert(0);
			break;
		default:
			assert(0);
	}
	return;
}
void Maat_empty_region(struct Maat_region_t* p)
{
	free((char*)p->table_name);
	p->table_name=NULL;
	switch(p->region_type)
	{
		case REGION_IP:
			free((char*)p->ip_rule.src_ip);
			free((char*)p->ip_rule.mask_src_ip);
			free((char*)p->ip_rule.dst_ip);
			free((char*)p->ip_rule.mask_src_ip);
			break;
		case REGION_EXPR:
			free((char*)p->expr_rule.keywords);
			free((char*)p->expr_rule.district);
			break;
		case REGION_INTERVAL:
			break;
		case REGION_DIGEST:
			free((char*)p->digest_rule.digest_string);
			break;
		case REGION_SIMILARITY:
			assert(0);
			break;
		default:
			assert(0);
	}
	memset(p,0,sizeof(struct Maat_region_t));
	return;

}
struct Maat_command_t* Maat_create_comand(const struct Maat_rule_t* rule, int group_num)
{
	int i=0;
	struct _Maat_cmd_inner_t* _cmd=(struct _Maat_cmd_inner_t*)calloc(sizeof(struct _Maat_cmd_inner_t),1);
	memcpy(&(_cmd->cmd.compile),rule,sizeof(_cmd->cmd.compile));
	_cmd->ref_cnt=1;
	_cmd->cmd.group_num=group_num;
	_cmd->cmd.groups=(struct Maat_group_t*)calloc(sizeof(struct Maat_group_t),group_num);
	for(i=0;i<group_num;i++)
	{
		_cmd->cmd.groups[i].regions=(struct Maat_region_t*)calloc(sizeof(struct Maat_region_t),1);
		_cmd->region_size[i]=1;
	}
	return (struct Maat_command_t*)_cmd;
}
void Maat_cmd_set_group(struct Maat_command_t* cmd,int which_group,const char* group_name)
{
	assert(which_group<cmd->group_num);

	if(cmd->groups[which_group].group_name!=NULL)
	{
		free(cmd->groups[which_group].group_name);
	}
	cmd->groups[which_group].group_name=_maat_strdup(group_name);
	
	return;
}
void Maat_cmd_add_region(struct Maat_command_t* cmd,int which_group,const struct Maat_region_t* region)
{
	struct _Maat_cmd_inner_t* _cmd=(struct _Maat_cmd_inner_t*)cmd;
	struct Maat_region_t* dst=NULL;
	struct Maat_group_t* p_group=NULL;
	p_group=&(cmd->groups[which_group]);
	assert(which_group<cmd->group_num);
	assert(region->table_name!=NULL);
	if(p_group->region_num==_cmd->region_size[which_group])
	{
		_cmd->region_size[which_group]*=2;
		p_group->regions=(struct Maat_region_t*)realloc(p_group->regions,sizeof(struct Maat_region_t)*_cmd->region_size[which_group]);
	}
	dst=&(p_group->regions[p_group->region_num]);
	p_group->region_num++;
	Maat_copy_region(dst, region);
	return;
}

void Maat_free_command(struct Maat_command_t* cmd)
{
	struct _Maat_cmd_inner_t* _cmd=(struct _Maat_cmd_inner_t*)cmd;
	int i=0,j=0;
	_cmd->ref_cnt--;
	if(_cmd->ref_cnt>0)
	{
		return;
	}
	for(i=0;i<cmd->group_num;i++)
	{
		for(j=0;j<cmd->groups[i].region_num;j++)
		{
			Maat_empty_region(&(cmd->groups[i].regions[j]));
		}
		free(cmd->groups[i].group_name);
		free(cmd->groups[i].regions);
		cmd->groups[i].regions=NULL;
	}
	free(cmd->groups);
	cmd->groups=NULL;
	_cmd->next=NULL;
	free(_cmd);
	return;
}
int Maat_format_command(struct Maat_command_t* rule, char* buffer, int size)
{
	//TODO
	return 0;
}
int Maat_command(Maat_feather_t feather,struct Maat_command_t* raw_rule,enum MAAT_OPERATION op)
{
	int ret=0;
	ret=Maat_append_command(feather,raw_rule,op);
	if(ret<0)
	{
		return ret;
	}
	ret=Maat_commit_command(feather);
	return ret;
}

int Maat_append_command(Maat_feather_t feather,struct Maat_command_t* cmd,enum MAAT_OPERATION op)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _Maat_cmd_inner_t* _cmd=(struct _Maat_cmd_inner_t*)cmd;
	int ret=0;
	_cmd->op=op;
	assert(op==MAAT_OP_DEL||op==MAAT_OP_ADD);
	if(op==MAAT_OP_DEL)
	{
		ret=reconstruct_cmd(_feather, _cmd);
	}
	else
	{
		ret=fix_table_name(_feather, cmd);
	}
	if(ret<0)
	{
		return -1;
	}
	_cmd->ref_cnt++;
	if(_feather->cmd_q_cnt==0)
	{
		assert(_feather->cmd_qtail==NULL);
		assert(_feather->cmd_qtail==_feather->cmd_qhead);
		_feather->cmd_qhead=_feather->cmd_qtail=_cmd;
	}
	else
	{
		_feather->cmd_qtail->next=_cmd;
		_feather->cmd_qtail=_cmd;
	}
	_feather->cmd_q_cnt++;
	return 0;
}

int Maat_commit_command(Maat_feather_t feather)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;

	int ret=0,i=0,retry=0,append_cmd_cnt=0;
	long long maat_redis_version=0;
	int new_region_num=0,new_group_num=0;
	int serial_rule_num=0,serial_rule_idx=0;
	struct _Maat_cmd_inner_t* p=NULL,*n=NULL;

	redisContext* ctx=NULL;
	redisReply* data_reply=NULL;

	struct serial_rule_t* s_rule=NULL;

	if(_feather->redis_write_ctx==NULL)
	{
		_feather->redis_write_ctx=redisConnectWithTimeout(_feather->redis_ip, _feather->redis_port,_feather->connect_timeout);
		if(_feather->redis_write_ctx==NULL)
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module 
								,"Redis connect %s:%d failed when appending command."
								,_feather->redis_ip,_feather->redis_port);
			ret=-1;
			goto error_out;
		}
	}
	ctx=_feather->redis_write_ctx;

	for(i=0,p=_feather->cmd_qhead;i<_feather->cmd_q_cnt;i++)
	{
		p=p->next;
		serial_rule_num+=calculate_serial_rule_num(p, &new_region_num, &new_group_num);
	}

	data_reply=_wrap_redisCommand(ctx,"INCRBY SEQUENCE_REGION %d",new_region_num); 
	assert(data_reply->type==REDIS_REPLY_INTEGER);
	_feather->base_rgn_seq=data_reply->integer-new_region_num;
	freeReplyObject(data_reply);
	
	data_reply=_wrap_redisCommand(ctx,"INCRBY SEQUENCE_GROUP %d",new_group_num); 
	assert(data_reply->type==REDIS_REPLY_INTEGER);
	_feather->base_rgn_seq=data_reply->integer-new_group_num;
	freeReplyObject(data_reply);
	
	s_rule=(struct serial_rule_t*)calloc(sizeof(struct serial_rule_t),serial_rule_num);

	for(i=0,p=_feather->cmd_qhead;i<_feather->cmd_q_cnt;i++)
	{
		p=p->next;
		serial_rule_idx+=build_serial_rule(_feather,p,s_rule, serial_rule_num-serial_rule_idx);
	}
	assert(serial_rule_idx==serial_rule_num);
	
	while(1)
	{
		data_reply=_wrap_redisCommand(ctx, "WATCH MAAT_VERSION");
		freeReplyObject(data_reply);
		data_reply=_wrap_redisCommand(ctx, "GET MAAT_VERSION");
		freeReplyObject(data_reply);
		maat_redis_version=atoll(data_reply->str);
		maat_redis_version++;
  		data_reply=_wrap_redisCommand(ctx,"MULTI");
		freeReplyObject(data_reply);
		for(i=0;i<serial_rule_num;i++)
		{
			if(s_rule[i].op==MAAT_OP_ADD)
			{
				redisAppendCommand(ctx,"SET %s:%s,%d \"%s\"",rm_key_prefix[MAAT_OP_ADD]
													,s_rule[i].table_name
													,s_rule[i].rule_id
													,s_rule[i].table_line);
				append_cmd_cnt++;
				//NX: Don't update already exisiting elements. Always add new elements.
				redisAppendCommand(ctx,"ZADD NX ADD,%s,%d %d",s_rule[i].table_name
													,s_rule[i].rule_id
													,maat_redis_version);
				append_cmd_cnt++;
			}
			else
			{
				
				redisAppendCommand(ctx,"RENAME %s:%s,%d %s:%s,%d"
														,rm_key_prefix[MAAT_OP_ADD]
														,s_rule[i].table_name
														,s_rule[i].rule_id
														,rm_key_prefix[MAAT_OP_DEL]
														,s_rule[i].table_name
														,s_rule[i].rule_id
														);
				append_cmd_cnt++;
				redisAppendCommand(ctx,"EXPIRE %s:%s,%d %d",rm_key_prefix[MAAT_OP_DEL]
														,s_rule[i].table_name
														,s_rule[i].rule_id
														,MAAT_REDIS_SYNC_TIME);
				append_cmd_cnt++;
				//NX: Don't update already exisiting elements. Always add new elements.
				redisAppendCommand(ctx,"ZADD NX DEL,%s,%d %d",s_rule[i].table_name
														,s_rule[i].rule_id
														,maat_redis_version);
				append_cmd_cnt++;
			}
		}
		redisAppendCommand(ctx,"INCRBY MAAT_VERSION 1"); 
		append_cmd_cnt++;
		redisAppendCommand(ctx,"EXEC");
		append_cmd_cnt++;
		for(i=0;i<append_cmd_cnt;i++)
		{
			_wrap_redisGetReply(ctx, &data_reply);
			if(1==mr_transaction_success(data_reply))
			{
				freeReplyObject(data_reply);
				break;
			}
			else
			{
				retry++;
				assert(retry<5);
				freeReplyObject(data_reply);
			}
		}
	}
	_feather->cmd_acc_num+=_feather->cmd_q_cnt;
error_out:
	p=_feather->cmd_qhead;
	for(i=0;i<_feather->cmd_q_cnt;i++)
	{
		n=p->next;
		Maat_free_command((struct Maat_command_t* )p);
		p=n;
	}
	_feather->cmd_qhead=_feather->cmd_qtail=NULL;
	_feather->cmd_q_cnt=0;
	
	for(i=0;i<serial_rule_num;i++)
	{
		empty_serial_rules(s_rule+i);
	}
	free(s_rule);
	return ret;
}

