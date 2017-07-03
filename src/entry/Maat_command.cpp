#include "Maat_command.h"
#include "config_monitor.h"
#include "hiredis.h"
#include <errno.h>
#include <pthread.h>
#include <assert.h>

const char* maat_redis_monitor="MAAT_REDIS_MONITOR";
const char* maat_redis_command="MAAT_REDIS_COMMAND";

const char* rm_key_prefix[2]={"OBSOLETE_RULE","EFFECTIVE_RULE"};
const char* redis_OK_reply="+OK\r\n";
const char* PREFIX_COMPILE_INDEX="INDEX_COMPILE";
const char* PREFIX_GROUP_INDEX="INDEX_GROUP";
const char* PREFIX_REGION_INDEX="INDEX_REGION";


struct serial_rule_t		//rm= Redis Maat
{
	int op;//0: delete, 1: add.
	int rule_id;
	enum MAAT_TABLE_TYPE table_type;
	char* table_name[256];
	char* table_line;
};

struct _Maat_cmd_t
{
	struct Maat_command_t cmd;
	enum MAAT_OPERATION op;
	int ref_cnt;
	int group_ref_cnt[MAAT_MAX_EXPR_ITEM_NUM];
	int group_rgn_cnt[MAAT_MAX_EXPR_ITEM_NUM];
	struct _Maat_cmd_t* next;
};
enum MAAT_TABLE_TYPE region_table_type(const struct Maat_region_t* p)
{
	enum MAAT_TABLE_TYPE ret=0;
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
void free_serial_rules(void* p)
{
	struct serial_rule_t* rule=(struct serial_rule_t*)p;
	if(rule->table_line!=NULL)
	{
		free(rule->table_line);
		rule->table_line=NULL;
	}
	free(rule);
	return;
}
void set_serial_rule(struct serial_rule_t* rule,enum MAAT_OPERATION op,enum MAAT_TABLE_TYPE table_type,int id,const char* table_name,const char* line)
{
	rule->op=op;
	rule->rule_id=id;
	rule->table_type=table_type;
	assert(srtlen(table_name)<sizeof(rule->table_name));
	memcpy(rule->table_name,table_name,strlen(table_name));
	if(line!=NULL)
	{
		rule->table_line=_maat_strdup(line);
	}
	return;
}
int get_rm_key_list(unsigned int version,redisContext *c,struct serial_rule_t** list,void* logger, unsigned int* new_version,int *update_type)
{
	redisReply* ctrl_reply=NULL,*data_reply=NULL;
	char err_buff[256];
	char op_str[4],table_name[256];
	int rule_id;
	long long version_in_redis=0;
	int i=0,ret=0,retry=0;
	struct serial_rule_t *p_rm_rule=NULL;

	if(version==0)
	{
		goto FULL_UPDATE;
	}
	while(retry<1)
	{
		ctrl_reply=(redisReply*)redisCommand(c, "GET MAAT_VERSION");
		if(ctrl_reply!=NULL)
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

	assert(ctrl_reply->type==REDIS_REPLY_INTEGER);
	assert(ctrl_reply->integer>=version);
	if(ctrl_reply->integer==version)
	{
		freeReplyObject(ctrl_reply);
		return 0;
	}
	version_in_redis=ctrl_reply->integer;
	*new_version=version_in_redis;
	freeReplyObject(ctrl_reply);
	//Returns all the elements in the sorted set at key with a score that version < score <= version_in_redis.
	//The elements are considered to be ordered from low to high scores(version).
	ctrl_reply=(redisReply*)redisCommand(c, "ZRANGE MAAT_UPDATE_STATUS (%d %d",version,version_in_redis);
	if(ctrl_reply==NULL)
	{
		__redis_strerror_r(errno,err_buff,sizeof(err_buff));
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
								"GET MAAT_UPDATE_STATUS failed %s.",err_buff);
		return 0;
	}	
	assert(ctrl_reply->type==REDIS_REPLY_ARRAY);
	data_reply=(redisReply*)redisCommand(c, "ZRANK MAAT_UPDATE_STATUS %s",ctrl_reply->element[0]->str);
	if(data_reply->integer!=version+1)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
								"Noncontinuous VERSION Redis: %lld MAAT: %d.",data_reply->integer,version);
		freeReplyObject(data_reply);
		data_reply=NULL;
		goto FULL_UPDATE;
	}
	else
	{
		MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
								"Inc Update form version %d to %lld.",version,version_in_redis);

	}
	freeReplyObject(data_reply);
	data_reply=NULL;
	p_rm_rule=(struct serial_rule_t*)calloc(ctrl_reply->elements,sizeof(struct serial_rule_t));
	for(i=0;i<ctrl_reply->elements;i++)
	{
		assert(ctrl_reply->element[i]->type==REDIS_REPLY_STRING);
		ret=sscanf(ctrl_reply->element[i]->str,"%s,%s,%d",op_str,p_rm_rule.table_name,&(p_rm_rule[i].rule_id));
		assert(ret==3);
		if(strncmp(op_str,"ADD")==0)
		{
			p_rm_rule[i].op=1;
		}
		else if(strncmp(op_str,"DEL")==0)
		{
			p_rm_rule[i].op=0;
		}
		else
		{
			assert(0);
		}
	}
	*list=p_rm_rule;
	*update_type=CM_UPDATE_TYPE_INC;
	freeReplyObject(ctrl_reply);
	return i;
FULL_UPDATE:
	MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
								"Initiate full udpate from version %d to %lld.",version,version_in_redis);
	data_reply=(redisReply*)redisCommand(c, "KEYS EFFECTIVE_RULE:*");
	assert(data_reply->type==REDIS_REPLY_ARRAY);
	p_rm_rule=(struct serial_rule_t*)calloc(ctrl_reply->elements,sizeof(struct serial_rule_t));
	for(i=0;i<data_reply->elements;i++)
	{
		assert(ctrl_reply->element[i]->type==REDIS_REPLY_STRING);
		ret=sscanf(ctrl_reply->element[i]->str,"EFFECTIVE_RULE:%s,%d",p_rm_rule[i].table_name,&(p_rm_rule[i].rule_id));
		p_rm_rule[i].op=1;
		assert(ret==2);	
	}
	*list=p_rm_rule;
	*update_type=CM_UPDATE_TYPE_FULL;
	freeReplyObject(ctrl_reply);
	ctrl_reply=NULL;
	freeReplyObject(data_reply);
	data_reply=NULL;
	return i;
}
void redis_monitor_traverse(unsigned int version,redisContext *c,
							void (*start)(unsigned int ,int ,void*),//vesion,CM_UPDATE_TYPE_*,u_para
							void (*update)(const char* ,const char*,void* ),//table name ,line ,u_para
							void (*finish)(void*),//u_para
							void* u_para,
							const unsigned char* dec_key,
							void* logger)
{
	redisReply* ctrl_reply=NULL,*data_reply=NULL;
	int rule_num=0,i=0;
	int ret=0;
	struct serial_rule_t* rule_list=NULL;
	int update_type=0;
	unsigned int new_version=0;
	rule_num=get_rm_key_list(version, c, &rule_list, logger,&new_version, &update_type);
	if(rule_num==0)
	{
		return;
	}
	for(i=0;i<rule_num;i++)
	{
		ret=redisAppendCommand(c, "GET %s:%s,%d",rm_key_prefix[rule_list[i].op]
											,rule_list[i].table_name
											,rule_list[i].rule_id);
		assert(ret==REDIS_OK);
	}
	ret=redisGetReply(c,&data_reply);
	assert(data_reply->elements==rule_num);
	start(new_version,update_type);
	for(i=0;i<data_reply->elements;i++)
	{
		update(rule_list[i].table_name,data_reply->element[i].str,u_para);
	}
	finish(u_para);
	freeReplyObject(data_reply);
	free(rule_list);
	rule_list=NULL;
	return;
}
struct Maat_command_t* Maat_create_comand(const struct Maat_rule_t* rule, int group_num)
{
	struct _Maat_cmd_t* _cmd=(struct _Maat_cmd_t*)calloc(sizeof(struct _Maat_cmd_t),1);
	memcpy(&(_cmd->cmd.compile),rule,sizeof(_cmd->cmd.compile));
	_cmd->ref_cnt=1;
	_cmd->cmd.group_num=group_num;
	_cmd->cmd.groups=(struct Maat_group_t*)calloc(sizeof(struct Maat_group_t),group_num);

	return (struct Maat_command_t*)_cmd;
}
void Maat_cmd_set_group(struct Maat_command_t* cmd,int which_group,int region_num,const char* table_name,const char* group_name)
{
	assert(which_group<cmd->group_num);
	if(table_name!=NULL)
	{
		if(cmd->groups[which_group].table_name!=NULL)
		{
			free(cmd->groups[which_group].table_name);
		}
		cmd->groups[which_group].table_name=_maat_strdup(table_name);
	}
	if(group_name!=NULL)
	{
		if(cmd->groups[which_group].group_name!=NULL)
		{
			free(cmd->groups[which_group].group_name);
		}
		cmd->groups[which_group].group_name=_maat_strdup(group_name);
	}
	cmd->groups->regions=(struct Maat_region_t*)calloc(sizeof(struct Maat_region_t),region_num);
	cmd->groups->region_num=region_num;
	return;
}
void Maat_copy_region(struct Maat_region_t* dst,const struct Maat_region_t* src)
{
	memcpy(dst,src,sizeof(struct Maat_region_t));
	if(src->table_name!=NULL)
	{
		dst->table_name=_maat_strdup(src->table_name)
	}
	switch(dst->region_type)
	{
		case REGION_IP:
			dst->addr_rule.src_ip=_maat_strdup(src->addr_rule.src_ip);
			dst->addr_rule.mask_src_ip=_maat_strdup(src->addr_rule.mask_src_ip);
			dst->addr_rule.dst_ip=_maat_strdup(src->addr_rule.dst_ip);
			dst->addr_rule.mask_src_ip=_maat_strdup(src->addr_rule.mask_src_ip);
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
	free(p->table_name);
	p->table_name=NULL;
	switch(p->region_type)
	{
		case REGION_IP:
			free(p->addr_rule.src_ip);
			free(p->addr_rule.mask_src_ip);
			free(p->addr_rule.dst_ip);
			free(p->addr_rule.mask_src_ip);
			break;
		case REGION_EXPR:
			free(p->expr_rule.keywords);
			free(p->expr_rule.district);
			break;
		case REGION_INTERVAL:
			break;
		case REGION_DIGEST:
			free(p->digest_rule.digest_string);
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
void Maat_cmd_set_region(struct Maat_command_t* cmd,int which_group,int which_region,const struct Maat_region_t* region)
{
	struct Maat_region_t* p=NULL;
	assert(which_group<cmd->group_num);
	assert(which_region<cmd->groups[which_group].region_num);
	assert(region->table_name!=NULL);
	p=&(cmd->groups[which_group].regions[which_region]);
	Maat_copy_region(p, region);
	return;
}

void Maat_free_command(struct Maat_command_t* cmd)
{
	struct _Maat_cmd_t* _cmd=(struct _Maat_cmd_t*)cmd;
	int i=0,j=0;
	_cmd->ref_cnt--;
	if(_cmd->ref_cnt>0)
	{
		return;
	}
	for(i=0;i<_cmd->cmd.group_num;i++)
	{
		for(j=0;j<cmd.groups[i].region_num;j++)
		{
			Maat_empty_region(&(cmd.groups[i].regions[j]));
		}
		free(cmd.groups[i].table_name);
		free(cmd.groups[i].group_name);
		free(cmd.groups[i].regions);
		cmd.groups[i].regions=NULL;
	}
	free(_cmd->cmd.groups);
	_cmd->cmd.groups=NULL;
	_cmd->next=NULL;
	free(_cmd);
	return;
}
int Maat_format_command(struct Maat_command_t* rule, char* buffer, int size)
{

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
//functioned as strdup, for dictator compatible.
char* _maat_strdup(const char* s)
{
	char*d=NULL;
	if(s==NULL)
	{
		return NULL;
	}
	d=(char*)malloc(strlen(s)+1);
	memcpy(d,s,strlen(s)+1));
	return d;
}
void Maat_append_command(Maat_feather_t feather,struct Maat_command_t* cmd,enum MAAT_OPERATION op)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _Maat_cmd_t* _cmd=(struct _Maat_cmd_t*)cmd;
	_cmd->ref_cnt++;
	_cmd->op=op;
	assert(op==MAAT_OP_DEL||op==MAAT_OP_ADD);
	if(cmd->table_name==NULL)
	{
		cmd->table_name=_maat_strdup(_feather->compile_tn);
	}
	if(_feather->cmd_num==0)
	{
		assert(_feather->cmd_qtail==_feather->cmd_qhead==NULL);
		_feather->cmd_qhead=_feather->cmd_qtail=_cmd;
	}
	else
	{
		_feather->cmd_qtail->next=_cmd;
		_feather->cmd_qtail=_cmd;
	}
	_feather->cmd_num++;
	return;
}
//TODO: support plugin rule command.
void invalidate_line(char* line, enum MAAT_TABLE_TYPE type)
{
	int offset=0;
	int i=0,j=0;
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
			assert(0);
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
int calculate_serial_rule_num(struct Maat_command_t* cmd)
{
	int serial_num=0;
	int i=0,j=0;
	serial_num++;//compile rule
	for(i=0;i<cmd->group_num;i++)
	{
		serial_num++;
		for(j=0;j<cmd->groups[i].region_num;j++)
		{
			serial_num++;
		}
	}
	return serial_num;
}
int reconstruct_cmd(redisContext *ctx,struct _Maat_cmd_t* _cmd,void* logger)
{
	int redis_ret=REDIS_ERR,ret=0;
	int i=0,j=0,grp_idx=0;
	redisReply* compile_reply=NULL,*group_reply=NULL,*region_reply=NULL;
	long long group_ref_cnt=0;
	char table_name[MAX_TABLE_NAME_LEN];
	struct Maat_command_t* cmd=&(_cmd->cmd);
	struct Maat_group_t* p_group=NULL;
	struct Maat_region_t* p_region=NULL;


	int config_id=cmd->compile.config_id;
	compile_reply=redisCommand(ctx,"HKEYS %s:%d",PREFIX_COMPILE_INDEX,config_id);
	if(compile_reply==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_redis_command 
							,"%s:%d not found."
							,PREFIX_COMPILE_INDEX,config_id);
		return -1;
	}
	cmd->group_num=compile_reply->elements;
	assert(cmd->compile.declare_grp_num==cmd->group_num);
	assert(cmd->groups==NULL);
	cmd->groups=calloc(sizeof(struct Maat_group_t),cmd->group_num);
	for(i=0;i<compile_reply->elements;i++)
	{
		if(strncmp(compile_reply->element[i].str,"GROUP:",strlen("GROUP:"))!=0)
		{
			continue;
		}
		p_group=&(cmd->groups[grp_idx]);
		ret=sscanf(compile_reply->element[i].str,"GROUP:%s,%d",table_name,&(p_group->group_id));
		assert(ret==2);
		p_group->table_name=_maat_strdup(table_name);
		
		group_reply=redisCommand(ctx,"HINCRBY %s:%s,%d REF_CNT -1",PREFIX_GROUP_INDEX
													,p_group->table_name
													,p_group->group_id);
		freeReplyObject(group_reply);
		group_reply=redisCommand(ctx,"HGET %s:%s,%d REF_CNT",PREFIX_GROUP_INDEX
													,p_group->table_name
													,p_group->group_id);
		group_ref_cnt=group_reply->integer;
		freeReplyObject(group_reply);
		_cmd->group_ref_cnt[grp_idx]=group_ref_cnt;
		grp_idx++;
		if(group_ref_cnt>0)
		{
			continue;
		}
		group_reply=redisCommand(ctx,"HKEYS %s:%s,%d",PREFIX_GROUP_INDEX
													,p_group->table_name
													,p_group->group_id);
		p_group->region_num=group_reply->elements;
		p_group->regions=(struct Maat_region_t*)calloc(sizeof(struct Maat_region_t),p_group->region_num);
		for(j=0;j<group_reply->elements;j++)
		{
			if(strncmp(group_reply->element[j].str,"REGION:",strlen("REGION:"))!=0)
			{
				continue;
			}
			p_region=&(p_group->regions[p_group->region_num]);
			ret=sscanf(group_reply->element[j].str,"REGION:%s,%d",table_name,&(p_region->region_id));
			assert(ret==2);
			p_region->table_name=_maat_strdup(table_name);
			region_reply=redisCommand(ctx,"HGET %s %s,%d",PREFIX_REGION_INDEX
														,p_region->table_name
														,p_region->region_id);
			p_region->region_type=region_reply->integer;
			p_group->region_num++;
			
			freeReplyObject(region_reply);
		}
		freeReplyObject(group_reply);
		group_reply=NULL;
	}
	freeReplyObject(compile_reply);
	compile_reply=NULL;
	return 0;
}

int build_serial_rule_from_redis(redisContext *ctx,struct Maat_command_t* cmd,struct serial_rule_t* list, int size)
{
	struct Maat_group_t* p_group=NULL;
	struct Maat_region_t* p_region=NULL;
	enum MAAT_TABLE_TYPE table_type=0;
	redisReply* data_reply=NULL;
	int rule_num=0;
	int i=0,j=0;
	data_reply=redisCommand(ctx,"GET %s:%s,%d",rm_key_prefix[MAAT_OP_ADD]
												,cmd->table_name
												,cmd->compile.config_id);
	invalidate_line(data_reply->str, TABLE_TYPE_COMPILE);
	set_serial_rule(list+rule_num,MAAT_OP_DEL,TABLE_TYPE_COMPILE,cmd->compile.config_id,cmd->table_name,data_reply->str);
	rule_num++;
	freeReplyObject(data_reply);
	for(i=0;i<cmd->group_num;i++)
	{
		p_group=&(cmd->groups[i]);
		data_reply=redisCommand(ctx,"GET %s:%s,%d",rm_key_prefix[MAAT_OP_ADD]
												,p_group->table_name
												,p_group->group_id);
		invalidate_line(data_reply->str, TABLE_TYPE_GROUP);
		set_serial_rule(list+rule_num,MAAT_OP_DEL,TABLE_TYPE_GROUP,p_group->group_id,p_group->table_name,data_reply->str);		
		rule_num++;
		freeReplyObject(data_reply);
		for(j=0;j<p_group->region_num;j++)
		{
			p_region=&(p_group->regions[j]);
			data_reply=redisCommand(ctx,"GET %s:%s,%d",rm_key_prefix[MAAT_OP_ADD]
													,p_region->table_name
													,p_region->region_id);
			table_type=region_table_type(p_region);
			invalidate_line(data_reply->str, table_type);
			set_serial_rule(list+rule_num,MAAT_OP_DEL,p_region->region_id,p_region->table_name,data_reply->str);		
			rule_num++;
			freeReplyObject(data_reply);
		}
	}
	assert(rule_num<size);
	return 0;
}
int build_serial_rule_from_cmd(struct Maat_command_t* cmd,struct serial_rule_t* list, int size)
{
	struct Maat_group_t* p_group=NULL;
	struct Maat_region_t* p_region=NULL;
	struct Maat_rule_t* p_m_rule=NULL;
	redisReply* data_reply=NULL;
	int rule_num=0,i=0;
	p_m_rule=&(cmd->compile);
	char line[1024];
	snprintf(line,sizeof(line),"%d\t%d\t%hhd\t%hhd\t%hhd\t0\t%s\t1\t%d",p_m_rule->config_id
													,p_m_rule->service_id
													,p_m_rule->action
													,p_m_rule->do_blacklist
													,p_m_rule->do_log
													,p_m_rule->service_defined
													,p_m_rule->declare_grp_num);
	set_serial_rule(list+rule_num,MAAT_OP_ADD,cmd->compile.config_id,cmd->table_name,line);
	rule_num++;
	data_reply=redisCommand(ctx,"GET %s:%s,%d",rm_key_prefix[MAAT_OP_ADD]
												,cmd->table_name
												,cmd->compile.config_id);
	return 0;
}
int mr_transaction_success(redisReply* data_reply)
{
	int i=0;
	for(i=0;i<data_reply->elements;i++)
	{
		if(data_reply->element[i].type==REDIS_REPLY_NIL)
		{
			return 0;
		}
	}
	return 1;
}
const int MAAT_REDIS_SYNC_TIME=30*60;
int del_cmd_from_redis(redisContext *ctx,struct _Maat_cmd_t* _cmd,void* logger)
{
	int serial_num=0;
	int i=0;
	int retry=0,ret=0;
	long long maat_redis_version=0,group_num=0;
	struct serial_rule_t *s_rule=NULL;
	struct Maat_command_t* cmd=&(_cmd->cmd);
	int redis_ret=REDIS_ERR,ret=0;
	redisReply* data_reply=NULL;
	reconstruct_cmd(ctx, _cmd, logger);
	serial_num=calculate_serial_rule_num(cmd);
	s_rule=(struct serial_rule_t*)calloc(sizeof(struct serial_rule_t),serial_num);
	ret=build_serial_rule_from_redis(ctx, cmd, s_rule, serial_num);

	
	retry=0;
	while(1)
	{
	
		data_reply=redisCommand(ctx, "WATCH MAAT_VERSION");
		freeReplyObject(data_reply);
		data_reply=redisCommand(ctx, "GET MAAT_VERSION");
		freeReplyObject(data_reply);
		maat_redis_version=data_reply->integer;
		maat_redis_version++;
  		data_reply=redisCommand(ctx,"MULTI");
		freeReplyObject(data_reply);
		for(i=0;i<serial_num;i++)
		{
			data_reply=redisCommand(ctx,"DEL %s:%s,%d",rm_key_prefix[MAAT_OP_ADD]
													,s_rule[i].table_name
													,s_rule[i].rule_id);
			freeReplyObject(data_reply);
			
			data_reply=redisCommand(ctx,"SET %s:%s,%d \"%s\"",rm_key_prefix[MAAT_OP_DEL]
													,s_rule[i].table_name
													,s_rule[i].rule_id
													,s_rule[i].table_line);
			freeReplyObject(data_reply);
			data_reply=redisCommand(ctx,"EXPIRE %s:%s,%d %d",rm_key_prefix[MAAT_OP_DEL]
													,s_rule[i].table_name
													,s_rule[i].rule_id
													,MAAT_REDIS_SYNC_TIME);
			freeReplyObject(data_reply);
			//NX: Don't update already exisiting elements. Always add new elements.
			data_reply=redisCommand(ctx,"ZADD NX DEL,%s,%d %d",s_rule[i].table_name
													,s_rule[i].rule_id
													,maat_redis_version);
			freeReplyObject(data_reply);


			data_reply=redisCommand(ctx,"INCRBY MAAT_VERSION 1");
			freeReplyObject(data_reply);
		}

		data_reply=redisCommand(ctx,"EXEC");
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
	for(i=0;i<serial_num;i++)
	{
		free_serial_rules(s_rule+i);
		s_rule[i]=NULL;
	}
	free(s_rule);
}
int add_cmd_to_redis(redisContext *ctx,struct _Maat_cmd_t* _cmd,void* logger)
{
	int ret=0,retry=0,i=0;
	redisReply* data_reply=NULL;
	long long maat_redis_version=0;
	struct Maat_command_t* cmd=&(_cmd->cmd);
	struct serial_rule_t *s_rule=NULL;
	int serial_num=calculate_serial_rule_num(cmd);
	s_rule=(struct serial_rule_t*)calloc(sizeof(struct serial_rule_t),serial_num);
	ret=build_serial_rule_from_cmd(ctx, cmd, s_rule, serial_num);

	retry=0;
	while(1)
	{
	
		data_reply=redisCommand(ctx, "WATCH MAAT_VERSION");
		freeReplyObject(data_reply);
		data_reply=redisCommand(ctx, "GET MAAT_VERSION");
		freeReplyObject(data_reply);
		maat_redis_version=data_reply->integer;
		maat_redis_version++;
  		data_reply=redisCommand(ctx,"MULTI");
		freeReplyObject(data_reply);
		for(i=0;i<serial_num;i++)
		{
			data_reply=redisCommand(ctx,"SET %s:%s,%d \"%s\"",rm_key_prefix[MAAT_OP_ADD]
													,s_rule[i].table_name
													,s_rule[i].rule_id
													,s_rule[i].table_line);
			freeReplyObject(data_reply);

			//NX: Don't update already exisiting elements. Always add new elements.
			data_reply=redisCommand(ctx,"ZADD NX ADD,%s,%d %d",s_rule[i].table_name
													,s_rule[i].rule_id
													,maat_redis_version);
			freeReplyObject(data_reply);			
		}

		data_reply=redisCommand(ctx,"EXEC");
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
	for(i=0;i<serial_num;i++)
	{
		free_serial_rules(s_rule+i);
		s_rule[i]=NULL;
	}
	free(s_rule);

}
int Maat_commit_command(Maat_feather_t feather)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	redisReply* reply=NULL;
	struct serial_rule_t* update_status=NULL;
	int status_cnt=0;
	struct timeval timeout;
	timeout.tv_sec=0;
	timeout.tv_usec=100*1000; // 100 ms
	int ret=0,i=0,redis_ret=REDIS_ERR,retry=0;
	long long maat_redis_version=0,region_seq=0,group_seq=0;
	struct _Maat_cmd_t* p=NULL,*n=NULL;
	if(_feather->redis_write_ctx==NULL)
	{
		_feather->redis_write_ctx=redisConnectWithTimeout(_feather->redis_ip, _feather->redis_port,timeout);
		if(_feather->redis_write_ctx==NULL)
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_module 
								,"Redis connect %s:%d failed when appending command."
								,_feather->redis_ip,_feather->redis_port);
			ret=-1;
			goto error_out;
		}
	}
	p=feather->cmd_qhead;
	for(i=0;i<feather->cmd_num;i++)
	{
		p=p->next;
		if(p->op==MAAT_OP_DEL)
		{
			del_cmd_from_redis(_feather->redis_write_ctx, p, _feather->logger);
		}
		else
		{
			add_cmd_to_redis(_feather->redis_write_ctx, p, _feather->logger);
		}
	}
error_out:
	p=_feather->cmd_qhead;
	for(i=0;i<_feather->cmd_num;i++)
	{
		n=p->next;
		Maat_free_command((struct Maat_command_t* )p);
		p=n;
	}
	_feather->cmd_qhead=_feather->cmd_qtail=NULL;
	_feather->cmd_num=0;
	return ret;
}

