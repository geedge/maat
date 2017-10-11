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

#define maat_redis_monitor	(module_name_str("MAAT_REDIS_MONITOR"))
#define maat_command (module_name_str("MAAT_COMMAND"))

const char* rm_key_prefix[2]={"OBSOLETE_RULE","EFFECTIVE_RULE"};
const char* rm_status_sset="MAAT_UPDATE_STATUS";
const char* rm_expire_sset="MAAT_EXPIRE_TIMER";
const char* rm_label_sset="MAAT_LABEL_INDEX";
const char* rm_version_sset="MAAT_VERSION_TIMER";
const static int MAAT_REDIS_SYNC_TIME=30*60;



struct _Maat_cmd_inner_t
{
	struct Maat_cmd_t cmd;
	enum MAAT_OPERATION op;
	int ref_cnt;
	int region_size[MAX_EXPR_ITEM_NUM];
	struct _Maat_cmd_inner_t* next;
};
int _wrap_redisGetReply(redisContext *c, redisReply **reply)
{
	return redisGetReply(c, (void **)reply);
}
redisReply *_wrap_redisCommand(redisContext *c, const char *format, ...)
{
	va_list ap;
	void *reply = NULL;
	int ret=0,retry=0;
	while(reply==NULL&&retry<2)
	{
		va_start(ap,format);
		reply = redisvCommand(c,format,ap);
		va_end(ap);
		if(reply==NULL)
		{
			ret=redisReconnect(c);
			retry++;
        		if(ret==REDIS_OK)
			{
				break;
			}
		}
	}
	return (redisReply *)reply;
}
int connect_redis_for_write(_Maat_feather_t * feather)
{
	int ret=0;
	redisReply* reply=NULL;
	assert(feather->redis_write_ctx==NULL);
	feather->redis_write_ctx=redisConnectWithTimeout(feather->redis_ip, feather->redis_port,feather->connect_timeout);
	if(feather->redis_write_ctx==NULL)
	{
		MESA_handle_runtime_log(feather->logger,RLOG_LV_FATAL,maat_module 
				,"Redis connect %s:%d for write failed."
				,feather->redis_ip,feather->redis_port);
		ret=-1;
	}
	else
	{
		reply=_wrap_redisCommand(feather->redis_write_ctx, "select %d",feather->redis_index);
		freeReplyObject(reply);
	}
	return ret;
}
long long read_redis_integer(const redisReply* reply)
{
	switch(reply->type)
	{
		case REDIS_REPLY_INTEGER:
			return reply->integer;
			break;
		case REDIS_REPLY_ARRAY:
			assert(reply->element[0]->type==REDIS_REPLY_INTEGER);
			return reply->element[0]->integer;
			break;
		case REDIS_REPLY_STRING:
			return atoll(reply->str);
			break;
		default:
			assert(0);
			break;
	}	
	return 0;
}
long long redis_server_time(redisContext* ctx)
{
	long long server_time=0;
	redisReply* data_reply=NULL;
	data_reply=_wrap_redisCommand(ctx,"TIME"); 
	assert(data_reply->type==REDIS_REPLY_ARRAY);
	server_time=atoll(data_reply->element[0]->str);
	freeReplyObject(data_reply);
	return server_time;
}
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
int get_valid_flag_offset(const char* line, enum MAAT_TABLE_TYPE type,int valid_column_seq)
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
				return -1;
			}
			offset=(unsigned int)valid_column_seq;
			break;
		case	TABLE_TYPE_INTERVAL:
			offset=5;
			break;
		case	TABLE_TYPE_DIGEST:
			offset=6;
			break;
		case	TABLE_TYPE_SIMILARITY:
			offset=5;
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
		if(j==offset-1)
		{
			break;
		}
	}
	i++;
	if(i>=strlen(line)||line[i]!='1')
	{
		return -1;
	}
	return i;
}
int invalidate_line(char* line, enum MAAT_TABLE_TYPE type,int valid_column_seq)
{
	int i=0;
	i=get_valid_flag_offset(line, type,valid_column_seq);
	if(i<0)
	{
		return -1;
	}
	line[i]='0';
	return 0;
}
int del_rule_from_redis(redisContext* ctx, struct serial_rule_t* s_rule, long long new_version)
{
	int append_cmd_cnt=0;
	redisAppendCommand(ctx,"RENAME %s:%s,%d %s:%s,%d"
			,rm_key_prefix[MAAT_OP_ADD]
			,s_rule->table_name
			,s_rule->rule_id
			,rm_key_prefix[MAAT_OP_DEL]
			,s_rule->table_name
			,s_rule->rule_id
			);
	append_cmd_cnt++;
	redisAppendCommand(ctx,"EXPIRE %s:%s,%d %d",rm_key_prefix[MAAT_OP_DEL]
			,s_rule->table_name
			,s_rule->rule_id
			,MAAT_REDIS_SYNC_TIME);
	append_cmd_cnt++;
	//NX: Don't update already exisiting elements. Always add new elements.
	redisAppendCommand(ctx,"ZADD %s NX %d DEL,%s,%d",rm_status_sset
			,new_version
			,s_rule->table_name
			,s_rule->rule_id);
	append_cmd_cnt++;

	// Try to remove from expiration sorted set, no matter wheather it exists or not.
	redisAppendCommand(ctx,"ZREM %s %s,%d",rm_expire_sset
			,s_rule->table_name
			,s_rule->rule_id);
	append_cmd_cnt++;

	redisAppendCommand(ctx,"ZREM %s %d",rm_label_sset
			,s_rule->rule_id);
	append_cmd_cnt++;

	return 	append_cmd_cnt;
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
		case REGION_SIMILARITY:
			ret=snprintf(buff,size,"%d\t%d\t%s\t%hd\t1"
					,p->region_id
					,group_id
					,p->similarity_rule.target
					,p->similarity_rule.threshold);
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
void set_serial_rule(struct serial_rule_t* rule,enum MAAT_OPERATION op,int rule_id,int label_id,const char* table_name,const char* line, long long timeout)
{
	rule->op=op;
	rule->rule_id=rule_id;
	rule->label_id=label_id;
	rule->timeout=timeout;
	assert(strlen(table_name)<sizeof(rule->table_name));
	memset(rule->table_name, 0, sizeof(rule->table_name));	
	memcpy(rule->table_name,table_name,strlen(table_name));
	if(line!=NULL)
	{
		rule->table_line=_maat_strdup(line);
	}
	return;
}
int _wrap_redisReconnect(redisContext* c, void*logger)
{
	int ret=0;
	ret=redisReconnect(c);
	if(ret==REDIS_OK)
	{
	
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,"Reconnect success.");
		return 0;
	}
	else
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,"Reconnect failed.");
		return -1;
	}
}
int get_rm_key_list(unsigned int version,redisContext *c,struct serial_rule_t** list,void* logger, unsigned int* new_version,int *update_type)
{
	redisReply* reply=NULL,*sub_reply=NULL,*tmp_reply=NULL;
	char err_buff[256];
	char op_str[4];
	long long version_in_redis=0,nearest_rule_version=0;
	int ret=0;
	unsigned int i=0,full_idx =0,append_cmd_cnt=0;
	struct serial_rule_t *s_rule=NULL;

	reply=(redisReply*)redisCommand(c, "GET MAAT_VERSION");
	if(reply!=NULL)
	{

		if(reply->type==REDIS_REPLY_NIL||reply->type==REDIS_REPLY_ERROR)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,"GET MAAT_VERSION failed, maybe Redis is busy.");
			freeReplyObject(reply);
			reply=NULL;
			return -1;
		}
	}
	else
	{
		memset(err_buff,0,sizeof(err_buff));
		__redis_strerror_r(errno,err_buff,sizeof(err_buff));
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
				"GET MAAT_VERSION failed %s. Reconnecting...",err_buff);
		_wrap_redisReconnect(c,logger);
		return -1;
	}
	version_in_redis=read_redis_integer(reply);
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
	if(version_in_redis<version)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
				"VERSION roll back MAAT: %d -> Redis: %lld.",version,version_in_redis);
		goto FULL_UPDATE;
	}


	//Returns all the elements in the sorted set at key with a score that version < score <= version_in_redis.
	//The elements are considered to be ordered from low to high scores(version).
	reply=(redisReply*)redisCommand(c, "ZRANGEBYSCORE %s (%d %d",rm_status_sset,version,version_in_redis);
	if(reply==NULL)
	{
		__redis_strerror_r(errno,err_buff,sizeof(err_buff));
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
				"GET %s failed %s.",rm_status_sset,err_buff);
		return -1;
	}	
	assert(reply->type==REDIS_REPLY_ARRAY);
	if(reply->elements==0)
	{
		//a duplicate rule_id would induce this error.
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,"Got nothing after ZRANGEBYSCORE %s (%d %d",rm_status_sset,version,version_in_redis);
		freeReplyObject(reply);
		return -1;
	}
	tmp_reply=_wrap_redisCommand(c, "ZSCORE %s %s",rm_status_sset,reply->element[0]->str);
	if(tmp_reply->type!=REDIS_REPLY_STRING)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
					"ZSCORE %s %s failed Version: %d->%d",rm_status_sset,reply->element[0]->str,version, version_in_redis);
		free(tmp_reply);
		free(reply);
		goto FULL_UPDATE;

	}
	nearest_rule_version=read_redis_integer(tmp_reply);
	freeReplyObject(tmp_reply);
	tmp_reply=NULL;
	if(nearest_rule_version!=version+1)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
				"Noncontinuous VERSION Redis: %lld MAAT: %d.",nearest_rule_version,version);

		goto FULL_UPDATE;
	}
	MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
			"Inc Update form version %d to %lld (%lld entries).",version,version_in_redis,reply->elements);

	s_rule=(struct serial_rule_t*)calloc(reply->elements,sizeof(struct serial_rule_t));
	for(i=0;i<reply->elements;i++)
	{
		assert(reply->element[i]->type==REDIS_REPLY_STRING);
		ret=sscanf(reply->element[i]->str,"%[^,],%[^,],%d",op_str,s_rule[i].table_name,&(s_rule[i].rule_id));
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
	append_cmd_cnt=0;
	ret=redisAppendCommand(c, "MULTI");
	append_cmd_cnt++;
	ret=redisAppendCommand(c, "GET MAAT_VERSION");
	append_cmd_cnt++;
	ret=redisAppendCommand(c, "KEYS EFFECTIVE_RULE:*");
	append_cmd_cnt++;
	//consume reply "OK" and "QUEUED".
	for(i=0;i<append_cmd_cnt;i++)
	{
		_wrap_redisGetReply(c, &reply);
		freeReplyObject(reply);
		reply=NULL;
	}
	reply=_wrap_redisCommand(c,"EXEC");
	if(reply==NULL)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
				"Redis Communication error: %s.",c->errstr);
		return -1;
	}
	assert(reply->type==REDIS_REPLY_ARRAY);
	*new_version=read_redis_integer(reply->element[0]);
	sub_reply=reply->element[1];
	assert(sub_reply->type==REDIS_REPLY_ARRAY);
	s_rule=(struct serial_rule_t*)calloc(sub_reply->elements,sizeof(struct serial_rule_t));
	for(full_idx=0;full_idx<sub_reply->elements;full_idx++)
	{
		assert(sub_reply->element[full_idx]->type==REDIS_REPLY_STRING);
		ret=sscanf(sub_reply->element[full_idx]->str,"%*[^:]:%[^,],%d",s_rule[full_idx].table_name,&(s_rule[full_idx].rule_id));
		s_rule[full_idx].op=MAAT_OP_ADD;
		assert(ret==2);	
	}
	freeReplyObject(reply);
	*list=s_rule;
	*update_type=CM_UPDATE_TYPE_FULL;

	return full_idx ;
}

int _get_maat_redis_value(redisContext *c,struct serial_rule_t* rule_list,int rule_num,void* logger)
{
	int i=0,ret=0,failed_cnt=0,idx=0;
	int error_happened=0;
	int *retry_ids=(int*)malloc(sizeof(int)*rule_num);
	char redis_cmd[256];
	redisReply* reply=NULL;
	for(i=0;i<rule_num;i++)
	{
		snprintf(redis_cmd,sizeof(redis_cmd),"GET %s:%s,%d",rm_key_prefix[rule_list[i].op]
				,rule_list[i].table_name
				,rule_list[i].rule_id);
		ret=redisAppendCommand(c, redis_cmd);
		assert(ret==REDIS_OK);
	}
	for(i=0;i<rule_num;i++)
	{
		ret=_wrap_redisGetReply(c,&reply);
		if(reply->type==REDIS_REPLY_STRING)
		{
			rule_list[i].table_line=_maat_strdup(reply->str);
		}
		else
		{
			if(reply->type==REDIS_REPLY_NIL)
			{
				retry_ids[failed_cnt]=i;
				failed_cnt++;
			}
			else
			{
				MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_redis_monitor
						,"Redis GET %s:%s,%d failed",rm_key_prefix[rule_list[i].op]
						,rule_list[i].table_name
						,rule_list[i].rule_id);
				error_happened=1;
			}
		}
		freeReplyObject(reply);
	}
	if(error_happened==1)
	{
		free(retry_ids);
		return -1;
	}
	
	for(i=0;i<failed_cnt;i++)
	{
		idx=retry_ids[i];
		snprintf(redis_cmd,sizeof(redis_cmd),"GET %s:%s,%d",rm_key_prefix[MAAT_OP_DEL]
				,rule_list[idx].table_name
				,rule_list[idx].rule_id);
		reply=_wrap_redisCommand(c, redis_cmd);
		assert(reply->type==REDIS_REPLY_STRING);
		rule_list[idx].table_line=_maat_strdup(reply->str);
		freeReplyObject(reply);
	}
	free(retry_ids);
	return 0;
}
int get_maat_redis_value(redisContext *c,struct serial_rule_t* rule_list,int rule_num,void* logger,int print_process)
{
	int max_redis_batch=4*1024,batch_cnt=0;
	int success_cnt=0,ret=0;
	int next_print=10;
	while(success_cnt<rule_num)
	{
		batch_cnt=MIN(rule_num-success_cnt,max_redis_batch);
		ret=_get_maat_redis_value(c,rule_list+success_cnt,batch_cnt,logger);
		if(ret<0)
		{
			return -1;
		}
		else
		{
			success_cnt+=batch_cnt;
		}
		if(print_process==1)
		{
			if((success_cnt*100)/rule_num>next_print)
			{
				printf(" >%d%%",next_print);
				next_print+=10;
			}
		}
	}
	if(print_process==1)
	{
		printf(" >100%%\n");
	}
	return 0;
}
int calculate_serial_rule_num(struct _Maat_cmd_inner_t* _cmd,int * new_region_cnt, int* new_group_cnt)
{
	int serial_num=0;
	int i=0;
	struct Maat_cmd_t* cmd=&(_cmd->cmd);
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
		//for MAAT_OP_DEL, if the group's refcnt>1, group->region_num=0.
		//so it's OK to add.
		serial_num+=cmd->groups[i].region_num;
	}
	return serial_num;
}
int reconstruct_cmd(struct _Maat_feather_t *feather, struct _Maat_cmd_inner_t* _cmd)
{
	int i=0,j=0,grp_idx=0;
	struct Maat_cmd_t* cmd=&(_cmd->cmd);
	struct Maat_group_t* group_cmd=NULL;
	struct Maat_region_t* region_cmd=NULL;

	struct _Maat_compile_inner_t *compile_inner=NULL;
	struct _Maat_group_inner_t* group_inner=NULL;
	struct _Maat_region_inner_t* region_inner=NULL;
	void* logger=feather->logger;

	int config_id=cmd->compile.config_id;
	if(feather->scanner==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_command 
				,"MAAT not ready.");
		return -1;
	}
	compile_inner=(struct _Maat_compile_inner_t *)HASH_fetch_by_id(feather->scanner->compile_hash, config_id);
	if(compile_inner==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_command 
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

		if(group_inner->ref_cnt>1)
		{
			continue;
		}
		group_cmd->region_num=group_inner->region_cnt;
		group_cmd->regions=(struct Maat_region_t*)calloc(sizeof(struct Maat_region_t),group_cmd->region_num);
		for(j=0;j<group_inner->region_boundary;j++)
		{
			region_inner=(struct _Maat_region_inner_t*)dynamic_array_read(group_inner->regions,j);
			if(region_inner==NULL)
			{
				continue;
			}
			region_cmd=&(group_cmd->regions[j]);
			region_cmd->table_name=_maat_strdup(feather->p_table_info[region_inner->table_id]->table_name[0]);
			region_cmd->region_id=region_inner->region_id;
			//NOTICE: region_type only avilable when OP_ADD, 
			region_cmd->region_type=REGION_EXPR;
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
	struct Maat_cmd_t* cmd=&(_cmd->cmd);
	enum MAAT_OPERATION op=_cmd->op;

	int rule_num=0,i=0,j=0;
	p_m_rule=&(cmd->compile);
	char line[1024];
	time_t timeout=0;
	if(_cmd->cmd.expire_after>0)
	{
		timeout=feather->server_time+_cmd->cmd.expire_after;
	}
	if(op==MAAT_OP_ADD)
	{
		snprintf(line,sizeof(line),"%d\t%d\t%hhd\t%hhd\t%hhd\t0\t%s\t1\t%d",p_m_rule->config_id
				,p_m_rule->service_id
				,p_m_rule->action
				,p_m_rule->do_blacklist
				,p_m_rule->do_log
				,p_m_rule->service_defined
				,cmd->group_num);
		set_serial_rule(list+rule_num,MAAT_OP_ADD,cmd->compile.config_id,cmd->label_id,feather->compile_tn,line,timeout);

	}
	else
	{
		set_serial_rule(list+rule_num,MAAT_OP_DEL,cmd->compile.config_id,cmd->label_id,feather->compile_tn,NULL,timeout);
	}
	rule_num++;
	for(i=0;i<cmd->group_num;i++)
	{		
		p_group=&(cmd->groups[i]);
		if(op==MAAT_OP_ADD)
		{
			if(feather->AUTO_NUMBERING_ON==1)
			{
				p_group->group_id=feather->base_grp_seq;
				feather->base_grp_seq++;
			}
			snprintf(line,sizeof(line),"%d\t%d\t1",p_group->group_id
					,p_m_rule->config_id);
			set_serial_rule(list+rule_num,MAAT_OP_ADD,p_group->group_id,0,feather->group_tn,line,timeout);
		}
		else
		{
			set_serial_rule(list+rule_num,MAAT_OP_DEL,p_group->group_id,0,feather->group_tn,NULL,0);
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
				if(feather->AUTO_NUMBERING_ON==1)
				{
					p_region->region_id=feather->base_rgn_seq;
					feather->base_rgn_seq++;
				}
				serialize_region(p_region, p_group->group_id, line, sizeof(line));
				set_serial_rule(list+rule_num,MAAT_OP_ADD
						,p_region->region_id,0,p_region->table_name,line,timeout);
			}
			else
			{
				set_serial_rule(list+rule_num,MAAT_OP_DEL
						,p_region->region_id,0,p_region->table_name,NULL,0);

			}
			rule_num++;
		}
	}
	assert(rule_num<=size);
	return rule_num;
}
int mr_transaction_success(redisReply* data_reply)
{
	if(data_reply->type==REDIS_REPLY_NIL)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}
int mr_operation_success(redisReply* data_reply)
{
	if(data_reply->type==REDIS_REPLY_INTEGER&&data_reply->integer==0)
	{
		return 0;
	}
	return 1;
}

#define	REDIS_OP_PER_SRULE	8
int _exec_serial_rule(redisContext* ctx,struct serial_rule_t* s_rule,int serial_rule_num, long long server_time, void* logger)
{
	int i=0,j=0,ret=0;
	long long maat_redis_version=0;
	redisReply* data_reply=NULL;
	int redis_transaction_success=1;
	data_reply=_wrap_redisCommand(ctx, "WATCH MAAT_VERSION");
	freeReplyObject(data_reply);
	data_reply=_wrap_redisCommand(ctx, "GET MAAT_VERSION");
	maat_redis_version=read_redis_integer(data_reply);
	maat_redis_version++;
	freeReplyObject(data_reply);
	data_reply=_wrap_redisCommand(ctx,"MULTI");
	freeReplyObject(data_reply);
	int max_append_cnt=serial_rule_num*REDIS_OP_PER_SRULE+4;
	int append_cmd_cnt=0;
	int *pipeline_seq=(int*)calloc(sizeof(int),max_append_cnt);
	assert(server_time>0);
	for(i=0;i<serial_rule_num;i++)
	{
		if(s_rule[i].op==MAAT_OP_ADD)
		{
			redisAppendCommand(ctx,"SET %s:%s,%d %s",rm_key_prefix[MAAT_OP_ADD]
					,s_rule[i].table_name
					,s_rule[i].rule_id
					,s_rule[i].table_line);
			pipeline_seq[append_cmd_cnt]=i;
			append_cmd_cnt++;
			//NX: Don't update already exisiting elements. Always add new elements.
			redisAppendCommand(ctx,"ZADD %s NX %lld ADD,%s,%d",rm_status_sset
					,maat_redis_version
					,s_rule[i].table_name
					,s_rule[i].rule_id);
			pipeline_seq[append_cmd_cnt]=i;
			append_cmd_cnt++;
			if(s_rule[i].timeout>0)
			{
				redisAppendCommand(ctx,"ZADD %s NX %lld %s,%d",rm_expire_sset
						,s_rule[i].timeout
						,s_rule[i].table_name
						,s_rule[i].rule_id);
				pipeline_seq[append_cmd_cnt]=i;
				append_cmd_cnt++;
			}
			if(s_rule[i].label_id>0)
			{
				redisAppendCommand(ctx,"ZADD %s NX %d %d",rm_label_sset
						,s_rule[i].label_id
						,s_rule[i].rule_id);
				pipeline_seq[append_cmd_cnt]=i;
				append_cmd_cnt++;
			}
		}
		else
		{
			ret=del_rule_from_redis(ctx,s_rule+i,maat_redis_version);
			for(j=0;j<ret;j++)
			{
				pipeline_seq[append_cmd_cnt+j]=i;
			}
			append_cmd_cnt+=ret;
			
		}

	}
	redisAppendCommand(ctx,"INCRBY MAAT_VERSION 1"); 
	append_cmd_cnt++;
	redisAppendCommand(ctx,"ZADD %s NX %d %d",rm_version_sset,server_time,maat_redis_version); 
	append_cmd_cnt++;
	redisAppendCommand(ctx,"EXEC");
	append_cmd_cnt++;
	redis_transaction_success=1;
	for(i=0;i<append_cmd_cnt;i++)
	{
		_wrap_redisGetReply(ctx, &data_reply);
		if(0==mr_transaction_success(data_reply))
		{
			redis_transaction_success=0;
		}
		if(0==mr_operation_success(data_reply))
		{
			j=pipeline_seq[i];
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_command 
					,"exec rule %s, %d failed, content %s, rule id maybe conflicts.", s_rule[j].rule_id, s_rule[j].table_name, s_rule[j].table_line);			
		}
		freeReplyObject(data_reply);
	}
	free(pipeline_seq);
	return redis_transaction_success;
}
int exec_serial_rule(redisContext* ctx,struct serial_rule_t* s_rule,int serial_rule_num, long long server_time, void* logger)
{
	int max_redis_batch=1*1024,batch_cnt=0;
	int success_cnt=0,ret=0;
	while(success_cnt<serial_rule_num)
	{
		batch_cnt=MIN(serial_rule_num-success_cnt,max_redis_batch);
		ret=_exec_serial_rule(ctx,s_rule+success_cnt,batch_cnt, server_time,logger);
		if(ret==1)
		{
			success_cnt+=batch_cnt;
		}
		else
		{
			break;
		}
	}
	return success_cnt;
}

int fix_table_name(_Maat_feather_t* feather,struct Maat_cmd_t* cmd)
{
	int i=0,j=0,ret=0;
	const char *table_name=NULL;
	int table_id=0;
	struct Maat_group_t* p_group=NULL;
	struct Maat_region_t* p_region=NULL;
	enum MAAT_TABLE_TYPE table_type;

	struct _Maat_compile_inner_t *compile_rule=NULL;
	if(feather->scanner!=NULL)
	{
		compile_rule=(struct _Maat_compile_inner_t*)HASH_fetch_by_id(feather->scanner->compile_hash, cmd->compile.config_id);
		if(compile_rule!=NULL)
		{
			MESA_handle_runtime_log(feather->logger,RLOG_LV_FATAL,maat_module 
					,"Maat rule %d already exisits.",cmd->compile.config_id);
			return -1;
		}
	}
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
						,"Unknown table %s of Maat_cmd_t[%d]->group[%d]->region[%d]."
						,table_name,cmd->compile.config_id,i,j);

				return -1;
			}
			table_type=type_region2table(p_region);
			if(table_type!=feather->p_table_info[table_id]->table_type)
			{
				MESA_handle_runtime_log(feather->logger,RLOG_LV_FATAL,maat_module 
						,"Table %s not support region type %d of Maat_cmd_t[%d]->group[%d]->region[%d]."
						,table_name
						,p_region->region_type
						,cmd->compile.config_id,i,j);
				return -1;
			}
			free((char*)p_region->table_name);
			p_region->table_name=_maat_strdup(feather->p_table_info[table_id]->table_name[0]);
		}
	}
	return 0;
}
void check_maat_expiration(redisContext *ctx, void *logger)
{
	unsigned int i=0,s_rule_num=0;
	int ret=0;
	int success_cnt=0;
	redisReply* data_reply=NULL;
	struct serial_rule_t* s_rule=NULL;
	long long server_time=0;

	server_time=redis_server_time(ctx);

	data_reply=_wrap_redisCommand(ctx, "ZRANGEBYSCORE %s -inf %lld",rm_expire_sset,server_time);
	if(data_reply->type!=REDIS_REPLY_ARRAY||data_reply->elements==0)
	{
		freeReplyObject(data_reply);
		return;
	}
	s_rule_num=data_reply->elements;
	s_rule=(struct serial_rule_t*)calloc(sizeof(struct serial_rule_t),s_rule_num);
	for(i=0;i<s_rule_num;i++)
	{
		s_rule[i].op=MAAT_OP_DEL;
		ret=sscanf(data_reply->element[i]->str,"%[^,],%d",s_rule[i].table_name,&(s_rule[i].rule_id));
		assert(ret==2);
	}
	freeReplyObject(data_reply);
	success_cnt=exec_serial_rule(ctx,s_rule, s_rule_num,server_time, logger);

	if(success_cnt==(int)s_rule_num)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_redis_monitor
				,"Succesfully expired %d rules in Redis.", s_rule_num);
	}
	else
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_redis_monitor 
				,"Failed to expired %d/%d rules in Redis, try later.", s_rule_num-success_cnt,s_rule_num);
	}

	free(s_rule);
	return;
}
void cleanup_update_status(redisContext *ctx, void *logger)
{
	redisReply* reply=NULL,*sub_reply=NULL;
	int append_cmd_cnt=0,i=0;
	long long server_time=0, version_upper_bound=0,version_lower_bound=0,version_num=0,entry_num=0;

	server_time=redis_server_time(ctx);

	reply=_wrap_redisCommand(ctx,"MULTI");
	freeReplyObject(reply);
	redisAppendCommand(ctx, "ZRANGEBYSCORE %s -inf %lld",rm_version_sset,server_time-MAAT_REDIS_SYNC_TIME);
	append_cmd_cnt++;
	redisAppendCommand(ctx, "ZREMRANGEBYSCORE %s -inf %lld",rm_version_sset,server_time-MAAT_REDIS_SYNC_TIME);
	append_cmd_cnt++;
	//consume reply "OK" and "QUEUED".
	for(i=0;i<append_cmd_cnt;i++)
	{
		_wrap_redisGetReply(ctx, &reply);
		freeReplyObject(reply);
		reply=NULL;
	}
	reply=_wrap_redisCommand(ctx,"EXEC");
	assert(reply->type==REDIS_REPLY_ARRAY);
	sub_reply=reply->element[0];
	assert(sub_reply->type==REDIS_REPLY_ARRAY);
	version_num=sub_reply->elements;
	if(version_num==0)
	{
		freeReplyObject(reply);	
		return;
	}
	version_lower_bound=read_redis_integer(sub_reply->element[0]);
	version_upper_bound=read_redis_integer(sub_reply->element[sub_reply->elements-1]);
	freeReplyObject(reply);	

	//To deal with maat_version reset to 0, do NOT use -inf as lower bound intentionally.
	reply=_wrap_redisCommand(ctx,"ZREMRANGEBYSCORE %s %lld %lld",rm_status_sset,version_lower_bound,version_upper_bound);
	entry_num=read_redis_integer(reply);
	freeReplyObject(reply);	

	MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_redis_monitor 
			,"Clean up update status from version %lld to %lld (%lld versions, %lld entries)."
			,version_lower_bound
			,version_upper_bound
			,version_num
			,entry_num);

}
void redis_monitor_traverse(unsigned int version,redisContext *c,
		void (*start)(unsigned int ,int ,void*),//vesion,CM_UPDATE_TYPE_*,u_para
		int (*update)(const char* ,const char*,void* ),//table name ,line ,u_para
		void (*finish)(void*),//u_para
		void* u_para,
		const unsigned char* dec_key,
		_Maat_feather_t* feather)
{
	int table_id=0,i=0,rule_num=0;
	int ret=0;
	struct serial_rule_t* rule_list=NULL;
	int update_type=CM_UPDATE_TYPE_INC;
	unsigned int new_version=0;
	enum MAAT_TABLE_TYPE table_type;
	void* logger=feather->logger;
	if(feather->redis_write_ctx!=NULL)//authorized to write
	{
		//For thread safe, deliberately use redis_read_ctx but not redis_write_ctx.
		check_maat_expiration(feather->redis_read_ctx, logger);
		cleanup_update_status(feather->redis_read_ctx, logger);
	}
	rule_num=get_rm_key_list(version, c, &rule_list, logger,&new_version, &update_type);
	if(rule_num<0||(rule_num==0&&update_type==CM_UPDATE_TYPE_INC))//error or nothing changed
	{
		return;
	}
	if(rule_num>0)
	{
		ret=get_maat_redis_value(c,rule_list,rule_num, logger,0);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_redis_monitor,"Get Redis value failed, abandon update.");
			goto clean_up;
		}
	}
	start(new_version,update_type,u_para);
	for(i=0;i<rule_num;i++)
	{
		ret=map_str2int(feather->map_tablename2id,rule_list[i].table_name,&table_id);
		if(ret<0)//Unrecognized table.
		{
			continue;
		}
		table_type=feather->p_table_info[table_id]->table_type;
		if(rule_list[i].op==MAAT_OP_DEL)
		{
			ret=invalidate_line(rule_list[i].table_line,table_type,feather->p_table_info[table_id]->valid_flag_column);
			if(ret<0)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_redis_monitor,"Invaid format %s ."
										,rule_list[i].table_line);
				continue;
			}
		}
		update(rule_list[i].table_name,rule_list[i].table_line,u_para);
	}
	finish(u_para);
clean_up:
	for(i=0;i<rule_num;i++)
	{
		empty_serial_rules(rule_list+i);
	}
	free(rule_list);
	rule_list=NULL;
	return;
}

void _maat_copy_region(struct Maat_region_t* dst,const struct Maat_region_t* src)
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
			dst->ip_rule.mask_dst_ip=_maat_strdup(src->ip_rule.mask_dst_ip);
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
			dst->similarity_rule.target=_maat_strdup(src->similarity_rule.target);
			break;
		default:
			assert(0);
	}
	return;
}
void _maat_empty_region(struct Maat_region_t* p)
{
	free((char*)p->table_name);
	p->table_name=NULL;
	switch(p->region_type)
	{
		case REGION_IP:
			free((char*)p->ip_rule.src_ip);
			free((char*)p->ip_rule.mask_src_ip);
			free((char*)p->ip_rule.dst_ip);
			free((char*)p->ip_rule.mask_dst_ip);
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
			free((char*)p->similarity_rule.target);
			break;
		default:
			assert(0);
	}
	memset(p,0,sizeof(struct Maat_region_t));
	return;

}
struct Maat_cmd_t* Maat_create_cmd(const struct Maat_rule_t* rule, int group_num)
{
	int i=0;
	struct _Maat_cmd_inner_t* _cmd=(struct _Maat_cmd_inner_t*)calloc(sizeof(struct _Maat_cmd_inner_t),1);
	memcpy(&(_cmd->cmd.compile),rule,sizeof(_cmd->cmd.compile));
	_cmd->ref_cnt=1;
	_cmd->cmd.group_num=group_num;
	if(group_num>0)
	{
		_cmd->cmd.groups=(struct Maat_group_t*)calloc(sizeof(struct Maat_group_t),group_num);
	}
	else
	{
		_cmd->cmd.groups=NULL;
	}
	for(i=0;i<group_num;i++)
	{
		_cmd->cmd.groups[i].regions=(struct Maat_region_t*)calloc(sizeof(struct Maat_region_t),1);
		_cmd->region_size[i]=1;
	}
	return (struct Maat_cmd_t*)_cmd;
}
int Maat_cmd_set_group(Maat_feather_t feather,int group_id, const struct Maat_region_t* region, enum MAAT_OPERATION op)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	if(_feather->AUTO_NUMBERING_ON==1)
	{
		return -1;
	}
	//struct _Maat_group_inner_t* group_inner=NULL;
	//group_inner=(struct _Maat_group_inner_t*)HASH_fetch_by_id(_feather->scanner->group_hash, group_id);
	//NOT implemented yet.
	assert(0);
	return 0;
}
int Maat_cmd_set_lines(Maat_feather_t feather,const struct Maat_line_t** line_rule, int line_num ,enum MAAT_OPERATION op)
{
	int i=0;
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	int ret=0, table_id=0,retry=0,success_cnt=0;
	struct serial_rule_t *s_rule=NULL;
	long long server_time=0,absolute_expire_time=0;
	server_time=redis_server_time(_feather->redis_write_ctx);
	s_rule=(struct serial_rule_t *)calloc(sizeof(struct serial_rule_t),line_num);
	for(i=0;i<line_num;i++)
	{
		ret=map_str2int(_feather->map_tablename2id, line_rule[i]->table_name, &table_id);
		if(ret<0)
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_command 
					,"Command set line id %d failed: unknown table %s."
					, line_rule[i]->rule_id
					, line_rule[i]->table_name);
			ret=-1;
			goto error_out;
		}
		if(TABLE_TYPE_PLUGIN!=_feather->p_table_info[table_id]->table_type)
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_command 
					,"Command set line id %d failed: table %s is not a plugin table."
					, line_rule[i]->rule_id
					, line_rule[i]->table_name);
			ret=-1;
			goto error_out;
		}
		ret=get_valid_flag_offset(line_rule[i]->table_line
			, _feather->p_table_info[table_id]->table_type
			, _feather->p_table_info[table_id]->valid_flag_column);
		if(ret<0||
			(op==MAAT_OP_ADD&&line_rule[i]->table_line[ret]!='1'))
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_command 
					,"Command set line id %d failed: illegal valid flag."
					, line_rule[i]->rule_id);
			ret=-1;
			goto error_out;
		}
		if(line_rule[i]->expire_after>0)
		{
			absolute_expire_time=server_time+line_rule[i]->expire_after;
		}
		set_serial_rule(s_rule+i, op,line_rule[i]->rule_id,line_rule[i]->label_id,line_rule[i]->table_name,line_rule[i]->table_line, absolute_expire_time);
	}
	ret=0;
	while(success_cnt<line_num)
	{
		success_cnt+=exec_serial_rule(_feather->redis_write_ctx,s_rule+success_cnt, line_num-success_cnt,server_time,_feather->logger);
		retry++;
	}
	if(retry>10)
	{
		MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_command 
				,"Command set line id %d success after retry %d times."
				, line_rule[0]->rule_id
				);
	}
error_out:
	for(i=0;i<line_num;i++)
	{
		empty_serial_rules(s_rule+i);
	}
	free(s_rule);
	return ret;
}

int Maat_cmd_set_line(Maat_feather_t feather,const struct Maat_line_t* line_rule, enum MAAT_OPERATION op)
{
	int ret=0;
	ret=Maat_cmd_set_lines(feather,&line_rule, 1, op);
	return ret;
}
void Maat_add_region2cmd(struct Maat_cmd_t* cmd,int which_group,const struct Maat_region_t* region)
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
	_maat_copy_region(dst, region);
	return;
}

void Maat_free_cmd(struct Maat_cmd_t* cmd)
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
			_maat_empty_region(&(cmd->groups[i].regions[j]));
		}
		free(cmd->groups[i].regions);
		cmd->groups[i].regions=NULL;
	}
	free(cmd->groups);
	cmd->groups=NULL;
	_cmd->next=NULL;
	free(_cmd);
	return;
}
int Maat_format_cmd(struct Maat_cmd_t* rule, char* buffer, int size)
{
	//TODO
	return 0;
}
int Maat_cmd(Maat_feather_t feather,struct Maat_cmd_t* raw_rule,enum MAAT_OPERATION op)
{
	int ret=0;
	ret=Maat_cmd_append(feather,raw_rule,op);
	if(ret<0)
	{
		return ret;
	}
	ret=Maat_cmd_commit(feather);
	return ret;
}

int Maat_cmd_append(Maat_feather_t feather,struct Maat_cmd_t* cmd,enum MAAT_OPERATION op)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	struct _Maat_cmd_inner_t* _cmd=(struct _Maat_cmd_inner_t*)cmd;
	int ret=0;
	_cmd->op=op;
	assert(op==MAAT_OP_DEL||op==MAAT_OP_ADD);
	assert(_cmd->next==NULL);
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

int Maat_cmd_commit(Maat_feather_t feather)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;

	int ret=0,i=0,retry=0;
	int new_region_num=0,new_group_num=0;
	int serial_rule_num=0,serial_rule_idx=0;
	int transection_success=1;
	struct _Maat_cmd_inner_t* p=NULL,*n=NULL;

	redisContext* ctx=NULL;
	redisReply* data_reply=NULL;

	struct serial_rule_t* s_rule=NULL;
	if(_feather->REDIS_MODE_ON==0)
	{
		return -1;
	}
	if(_feather->cmd_q_cnt==0)
	{
		return 0;
	}
	if(_feather->redis_write_ctx==NULL)
	{
		ret=connect_redis_for_write(_feather);
		if(ret!=0)
		{
			goto error_out;
		}
	}
	ctx=_feather->redis_write_ctx;
	for(i=0,p=_feather->cmd_qhead;i<_feather->cmd_q_cnt;i++)
	{
		serial_rule_num+=calculate_serial_rule_num(p, &new_region_num, &new_group_num);
		p=p->next;
	}
	_feather->server_time=redis_server_time(ctx);

	if(_feather->AUTO_NUMBERING_ON==1)
	{
		data_reply=_wrap_redisCommand(ctx,"INCRBY SEQUENCE_REGION %d",new_region_num); 
		assert(data_reply->type==REDIS_REPLY_INTEGER);
		_feather->base_rgn_seq=data_reply->integer-new_region_num;
		freeReplyObject(data_reply);

		data_reply=_wrap_redisCommand(ctx,"INCRBY SEQUENCE_GROUP %d",new_group_num); 
		assert(data_reply->type==REDIS_REPLY_INTEGER);
		_feather->base_grp_seq=data_reply->integer-new_group_num;
		freeReplyObject(data_reply);
	}
	s_rule=(struct serial_rule_t*)calloc(sizeof(struct serial_rule_t),serial_rule_num);

	for(i=0,p=_feather->cmd_qhead;i<_feather->cmd_q_cnt;i++)
	{
		serial_rule_idx+=build_serial_rule(_feather,p,s_rule, serial_rule_num-serial_rule_idx);
		p=p->next;
	}
	assert(serial_rule_idx==serial_rule_num);
	transection_success=0;
	while(transection_success<serial_rule_num)
	{
		transection_success+=exec_serial_rule(ctx, s_rule+transection_success,serial_rule_num-transection_success,_feather->server_time,_feather->logger);
		if(transection_success<serial_rule_num)
		{
			retry++;
		}
	}
	if(retry>5)
	{
		MESA_handle_runtime_log(_feather->logger,RLOG_LV_INFO,maat_command
                                ,"MAAT retry for %d times.", retry);
	}
	_feather->cmd_acc_num+=_feather->cmd_q_cnt;
error_out:
	p=_feather->cmd_qhead;
	for(i=0;i<_feather->cmd_q_cnt;i++)
	{
		n=p->next;
		Maat_free_cmd((struct Maat_cmd_t* )p);
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
long long Maat_cmd_incrby(Maat_feather_t feather,const char* key, int increment)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	redisReply* data_reply=NULL;
	long long result=0;
	int ret=0;
	if(_feather->redis_write_ctx==NULL)
	{
		ret=connect_redis_for_write(_feather);
		if(ret!=0)
		{
			return -1;
		}
	}
	data_reply=_wrap_redisCommand(_feather->redis_write_ctx,"INCRBY %s %d", key, increment); 
	assert(data_reply->type==REDIS_REPLY_INTEGER);
	result=data_reply->integer;
	freeReplyObject(data_reply);
	return result;		
}
int Maat_cmd_select(Maat_feather_t feather, int label_id, int * output_ids, unsigned int size)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	redisReply* data_reply=NULL;
	unsigned int i=0;
	int ret=0;
	if(_feather->redis_write_ctx==NULL)
	{
		ret=connect_redis_for_write(_feather);
		if(ret!=0)
		{
			return -1;
		}
	}
	data_reply=_wrap_redisCommand(_feather->redis_write_ctx,"ZRANGEBYSCORE %s %d %d"
			,rm_label_sset
			,label_id
			,label_id);
	for(i=0;i<data_reply->elements&&i<size;i++)
	{
		output_ids[i]=atoi(data_reply->element[i]->str);
	}
	freeReplyObject(data_reply);
	return i;
}

