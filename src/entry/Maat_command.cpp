#include "Maat_command.h"
#include "Maat_rule.h"
#include "Maat_rule_internal.h"
#include "Maat_utils.h"
#include "config_monitor.h"
#include "map_str2int.h"
#include "hiredis.h"
#include <MESA/MESA_handle_logger.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>
#include <unistd.h>

#define maat_redis_monitor	(module_name_str("MAAT_REDIS_MONITOR"))
#define maat_command (module_name_str("MAAT_COMMAND"))
const time_t MAAT_REDIS_RECONNECT_INTERVAL=5;
const char* mr_key_prefix[2]={"OBSOLETE_RULE","EFFECTIVE_RULE"};
const char* mr_status_sset="MAAT_UPDATE_STATUS";
const char* mr_expire_sset="MAAT_EXPIRE_TIMER";
const char* mr_label_sset="MAAT_LABEL_INDEX";
const char* mr_version_sset="MAAT_VERSION_TIMER";
const char* mr_expire_lock="EXPIRE_OP_LOCK";
const long	mr_expire_lock_timeout=300*1000;
const static int MAAT_REDIS_SYNC_TIME=30*60;
const char* mr_op_str[]={"DEL","ADD","RENEW_TIMEOUT"};
const char* foreign_source_prefix="redis://";
const char* foreign_key_prefix="__FILE_";



int _wrap_redisGetReply(redisContext *c, redisReply **reply)
{
	return redisGetReply(c, (void **)reply);
}
redisReply *_wrap_redisCommand(redisContext *c, const char *format, ...)
{
	va_list ap;
	void *reply = NULL;
	int ret=REDIS_ERR, retry=0;
	while(reply==NULL&&retry<2&&ret!=REDIS_OK)
	{
		va_start(ap,format);
		reply = redisvCommand(c,format,ap);
		va_end(ap);
		if(reply==NULL)
		{
			ret=redisReconnect(c);
			retry++;
		}
	}
	return (redisReply *)reply;
}
redisContext * connect_redis(const char*redis_ip, int redis_port, int redis_db, void* logger)
{
	struct timeval connect_timeout;
	connect_timeout.tv_sec=0;
	connect_timeout.tv_usec=100*1000; // 100 ms
	redisReply* reply=NULL;

	redisContext * ctx;
	ctx=redisConnectWithTimeout(redis_ip, redis_port,connect_timeout);
	if(ctx==NULL||ctx->err)
	{
		if(logger==NULL)
		{
			printf("Unable to connect redis server %s:%d db%d, error: %s\n",
								redis_ip, redis_port, redis_db, ctx==NULL ? "Unknown" : ctx->errstr);

		}
		else
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
							"Unable to connect redis server %s:%d db%d, error: %s",
							redis_ip, redis_port, redis_db, ctx==NULL ? "Unknown" : ctx->errstr);
		}
		if(ctx!=NULL) redisFree(ctx);
		return NULL;
	}
	redisEnableKeepAlive(ctx);
	reply=_wrap_redisCommand(ctx, "select %d",redis_db);
	freeReplyObject(reply);

	return ctx;

}

int connect_redis_for_write(struct source_redis_ctx* mr_ctx, void* logger)
{
	assert(mr_ctx->write_ctx==NULL);
	mr_ctx->write_ctx=connect_redis(mr_ctx->redis_ip, mr_ctx->redis_port, mr_ctx->redis_db, logger);
	if(mr_ctx->write_ctx==NULL)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}
redisContext* get_redis_ctx_for_write(struct _Maat_feather_t * feather)
{
	int ret=0;
	if(feather->mr_ctx.write_ctx==NULL)
	{
		ret=connect_redis_for_write(&(feather->mr_ctx), feather->logger);
		if(ret!=0)
		{
			return NULL;
		}
	}
	return feather->mr_ctx.write_ctx;
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
			return -1;
			break;
	}	
	return 0;
}
long long redis_server_time(redisContext* ctx)
{
	long long server_time=0;
	redisReply* data_reply=NULL;
	data_reply=_wrap_redisCommand(ctx,"TIME"); 
	if(data_reply->type==REDIS_REPLY_ARRAY)
	{
		server_time=atoll(data_reply->element[0]->str);
		freeReplyObject(data_reply);
	}
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
 	size_t offset=0, len=0;
	unsigned int column_seq=0, ret=0;
 	switch(type)
	{
		case	TABLE_TYPE_EXPR:
			column_seq=7;
			break;
		case	TABLE_TYPE_IP:
			column_seq=14;
			break;
		case	TABLE_TYPE_IP_PLUS:
			column_seq=18;
			break;
		case	TABLE_TYPE_COMPILE:
			column_seq=8;
			break;
		case	TABLE_TYPE_PLUGIN:
			if(valid_column_seq<0)
			{
				return -1;
			}
			column_seq=(unsigned int)valid_column_seq;
			break;
		case	TABLE_TYPE_INTERVAL:
			column_seq=5;
			break;
		case	TABLE_TYPE_DIGEST:
			column_seq=6;
			break;
		case	TABLE_TYPE_SIMILARITY:
			column_seq=5;
			break;
		case	TABLE_TYPE_EXPR_PLUS:
			column_seq=8;
			break;
		case	TABLE_TYPE_GROUP2COMPILE:
		case	TABLE_TYPE_GROUP2GROUP:
			column_seq=3;
			break;
		default:
			assert(0);
	}
	
	ret=get_column_pos(line, column_seq, &offset, &len);
	if(ret<0||offset>=strlen(line)||(line[offset]!='1'&&line[offset]!='0'))// 0 is also a valid value for some non-MAAT producer.
	{
		return -1;
	}
	return offset;
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

void serialize_group2group(enum MAAT_OPERATION op, const struct Maat_cmd_group2group* g2g, char* buff, size_t sz)
{
	snprintf(buff, sz, "%d\t%d\t%d", g2g->group_id, 
									g2g->superior_group_id,
									op);
	return;
}
void serialize_group2compile(enum MAAT_OPERATION op, const struct Maat_cmd_group2compile* g2c, char* buff, size_t sz)
{
	snprintf(buff, sz, "%d\t%d\t%d\t%d\t%s\t%d", g2c->group_id,
								g2c->compile_id,
								op,
								g2c->not_flag,
								g2c->virtual_table_name?g2c->virtual_table_name:"null",
								g2c->clause_index);
	return;
}
void serialize_compile(const struct Maat_rule_t* p_m_rule, const char* huge_service_defined, int clause_num, enum MAAT_OPERATION op, char* buff, size_t sz)
{
	if(op==MAAT_OP_RENEW_TIMEOUT) op=MAAT_OP_ADD;
	const char* service_define=huge_service_defined?huge_service_defined:(strlen(p_m_rule->service_defined)?p_m_rule->service_defined:"null");

	snprintf(buff, sz, "%d\t%d\t%hhu\t%hhu\t%hhu\t0\t%s\t%d\t%d", 
		p_m_rule->config_id,
		p_m_rule->service_id,
		p_m_rule->action,
		p_m_rule->do_blacklist,
		p_m_rule->do_log,
		service_define,
		op,
		clause_num);
	return;
}
void serialize_region(const struct Maat_cmd_region* p, int group_id, char* buff, size_t sz)
{
	UNUSED size_t ret=0;
	switch(p->region_type)
	{
		case REGION_IP:
			ret=snprintf(buff,sz,"%d\t%d\t%d\t%s\t%s\t%hu\t%hu\t%s\t%s\t%hu\t%hu\t%d\t%d\t1",
					p->region_id,
					group_id,
					p->ip_rule.addr_type,
					p->ip_rule.src_ip,
					p->ip_rule.mask_src_ip,
					p->ip_rule.src_port,
					p->ip_rule.mask_src_port,
					p->ip_rule.dst_ip,
					p->ip_rule.mask_dst_ip,
					p->ip_rule.dst_port,
					p->ip_rule.mask_dst_port,
					p->ip_rule.protocol,
					p->ip_rule.direction);	
			break;
		case REGION_EXPR:
			if(p->expr_rule.district==NULL)
			{
				ret=snprintf(buff,sz,"%d\t%d\t%s\t%d\t%d\t%d\t1",
						p->region_id,
						group_id,
						p->expr_rule.keywords,
						p->expr_rule.expr_type,
						p->expr_rule.match_method,
						p->expr_rule.hex_bin);	
			}
			else	//expr_plus
			{
				ret=snprintf(buff,sz,"%d\t%d\t%s\t%s\t%d\t%d\t%d\t1",
						p->region_id,
						group_id,
						p->expr_rule.district,
						p->expr_rule.keywords,
						p->expr_rule.expr_type,
						p->expr_rule.match_method,
						p->expr_rule.hex_bin);	
			}
			break;
		case REGION_INTERVAL:
			ret=snprintf(buff,sz,"%d\t%d\t%u\t%u\t1",
					p->region_id,
					group_id,
					p->interval_rule.low_boundary,
					p->interval_rule.up_boundary);
			break;
		case REGION_DIGEST:
			ret=snprintf(buff,sz,"%d\t%d\t%llu\t%s\t%hd\t1",
					p->region_id,
					group_id,
					p->digest_rule.orgin_len,
					p->digest_rule.digest_string,
					p->digest_rule.confidence_degree);
			break;
		case REGION_SIMILARITY:
			ret=snprintf(buff,sz,"%d\t%d\t%s\t%hd\t1",
					p->region_id,
					group_id,
					p->similarity_rule.target,
					p->similarity_rule.threshold);
			break;
		default:
			assert(0);
	}
	assert(ret<sz);
	return;
}
void empty_serial_rules(struct serial_rule_t* rule)
{
	if(rule->table_line!=NULL)
	{
		free(rule->table_line);
	}
	if(rule->n_foreign>0)
	{
		for(int i=0; i<rule->n_foreign; i++)
		{
			free(rule->f_keys[i].filename);
			free(rule->f_keys[i].key);
		}
		free(rule->f_keys);
	}
	memset(rule,0,sizeof(struct serial_rule_t));
	return;
}
void set_serial_rule(struct serial_rule_t* rule, enum MAAT_OPERATION op, unsigned long rule_id,int label_id,const char* table_name,const char* line, long long timeout)
{
	memset(rule, 0, sizeof(struct serial_rule_t));
	rule->op=op;
	rule->rule_id=rule_id;
	rule->label_id=label_id;
	rule->timeout=timeout;
	assert(strlen(table_name)<sizeof(rule->table_name));
	strncpy(rule->table_name, table_name, sizeof(rule->table_name));
	if(line!=NULL)
	{
		rule->table_line=_maat_strdup(line);
	}
	return;
}
int get_inc_key_list(long long instance_version, long long target_version, redisContext *c, struct serial_rule_t** list,void* logger)
{
	redisReply* reply=NULL,*tmp_reply=NULL;
	char err_buff[256],	op_str[4];
	int rule_num=0;
	UNUSED int ret=0;
	unsigned int  i=0, j=0;
	long long nearest_rule_version;
	struct serial_rule_t *s_rule=NULL;
	
	//Returns all the elements in the sorted set at key with a score that instance_version < score <= redis_version.
	//The elements are considered to be ordered from low to high scores(instance_version).
	reply=(redisReply*)redisCommand(c, "ZRANGEBYSCORE %s (%lld %lld",mr_status_sset,instance_version,target_version);

	if(reply==NULL)
	{
		__redis_strerror_r(errno,err_buff,sizeof(err_buff)-1);
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
				"GET %s failed %s.",mr_status_sset,err_buff);
		return -1;
	}	
	assert(reply->type==REDIS_REPLY_ARRAY);
	rule_num=reply->elements;
	if(reply->elements==0)
	{
		freeReplyObject(reply);
		return 0;
	}

	tmp_reply=_wrap_redisCommand(c, "ZSCORE %s %s",mr_status_sset,reply->element[0]->str);
	if(tmp_reply->type!=REDIS_REPLY_STRING)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
					"ZSCORE %s %s failed Version: %lld->%lld",mr_status_sset,reply->element[0]->str,instance_version, target_version);
		freeReplyObject(tmp_reply);
		freeReplyObject(reply);
		return -1;
	}
	nearest_rule_version=read_redis_integer(tmp_reply);
	freeReplyObject(tmp_reply);
	tmp_reply=NULL;
	if(nearest_rule_version<0)
	{
		return -1;
	}
	if(nearest_rule_version!=instance_version+1)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
				"Noncontinuous VERSION Redis: %lld MAAT: %lld.",nearest_rule_version,instance_version);
	}
	s_rule=(struct serial_rule_t*)calloc(reply->elements,sizeof(struct serial_rule_t));
	for(i=0, j=0;i<reply->elements;i++)
	{
		assert(reply->element[i]->type==REDIS_REPLY_STRING);
		ret=sscanf(reply->element[i]->str,"%[^,],%[^,],%lu",op_str,s_rule[j].table_name,&(s_rule[j].rule_id));
		if(ret!=3||s_rule[i].rule_id<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
					"Invalid Redis Key: %s",reply->element[i]->str);
			continue;
		}
		if(strncmp(op_str,"ADD",strlen("ADD"))==0)
		{
			s_rule[j].op=MAAT_OP_ADD;
		}
		else if(strncmp(op_str,"DEL",strlen("DEL"))==0)
		{
			s_rule[j].op=MAAT_OP_DEL;
		}
		else
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
					"Invalid Redis Key: %s",reply->element[i]->str);
			continue;
		}
		j++;
	}	
	rule_num=j;
	*list=s_rule;
	freeReplyObject(reply);
	return rule_num;
}
struct s_rule_array_t
{
	int cnt;
	int size;
	struct serial_rule_t* array;
};
void save_serial_rule_cb(const uchar * key, uint size, void * data, void * user)
{
	struct s_rule_array_t* array=(struct s_rule_array_t*)user;
	int i=array->cnt;
	memcpy(&(array->array[i]),data,sizeof(struct serial_rule_t));
	array->array[i].op=MAAT_OP_ADD;
	return;
}
int recovery_history_version(const struct serial_rule_t* current, int current_num, const struct serial_rule_t* changed, int changed_num, struct serial_rule_t** history_result)
{
	int i=0,ret=0;
	unsigned int history_num=0;
	int hash_slot_size=1;
	MESA_htable_handle htable=NULL;
	MESA_htable_create_args_t hargs;
	struct s_rule_array_t tmp_array;
	char hkey[256+20];
	int tmp=current_num+changed_num;
	for(;tmp>0;tmp=tmp/2)
	{
		hash_slot_size*=2;
	}

	memset(&hargs,0,sizeof(hargs));
	hargs.thread_safe=0;
	hargs.hash_slot_size = hash_slot_size;
	hargs.max_elem_num = 0;
	hargs.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	hargs.expire_time = 0;
	hargs.key_comp = NULL;
	hargs.key2index = NULL;
	hargs.recursive = 1;
	hargs.data_free = NULL;//data is an reference, no need to free.
	hargs.data_expire_with_condition = NULL;
	htable=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(htable, 0);

	for(i=0;i<current_num;i++)
	{
		snprintf(hkey,sizeof(hkey),"%ld,%s",current[i].rule_id,current[i].table_name);
		ret=MESA_htable_add(htable, (uchar*)hkey, strlen(hkey), current+i);
		assert(ret>0);
	}

	for(i=changed_num-1;i>=0;i--)
	{
		snprintf(hkey,sizeof(hkey),"%ld,%s",changed[i].rule_id,changed[i].table_name);
		if(changed[i].op==MAAT_OP_ADD)//newly added rule is need to delete from current, so that history version can be recovered.
		{
			ret=MESA_htable_del(htable, (uchar*)hkey, strlen(hkey), NULL);
		}
		else
		{
			ret=MESA_htable_add(htable, (uchar*)hkey, strlen(hkey),changed+i);
		}
		if(ret<0)//failed
		{
			goto error_out;
		}
	}
	history_num=MESA_htable_get_elem_num(htable);
	tmp_array.cnt=0;
	tmp_array.size=history_num;
	tmp_array.array=(struct serial_rule_t*)calloc(history_num,sizeof(struct serial_rule_t));
	MESA_htable_iterate(htable, save_serial_rule_cb, &tmp_array);
	*history_result=tmp_array.array;
	ret=history_num;
error_out:
	MESA_htable_destroy(htable, NULL);
	return ret;
}
int get_rm_key_list(redisContext *c, long long instance_version, long long desired_version, long long* new_version, struct serial_rule_t** list,int *update_type, void* logger, int cumulative_off)
{
	redisReply* reply=NULL,*sub_reply=NULL;
	char err_buff[256];
	long long redis_version=0,target_version=0;
	int rule_num=0, changed_rule_num=0;
	int ret=0;
	unsigned int i=0,full_idx =0,append_cmd_cnt=0;
	struct serial_rule_t *s_rule_array=NULL, *changed_rule_array=NULL, *history_rule_array=NULL;

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
		memset(err_buff, 0, sizeof(err_buff));
		__redis_strerror_r(errno, err_buff, sizeof(err_buff)-1);
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
				"GET MAAT_VERSION failed %s.",err_buff);
		return -1;
	}
	redis_version=read_redis_integer(reply);
	if(redis_version<0)
	{
		if(reply->type==REDIS_REPLY_ERROR)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
			"Redis Communication error: %s.",reply->str);
		}
		return -1;
	}
	freeReplyObject(reply);
	if(redis_version==instance_version)
	{		
		return 0;
	}

	if(instance_version==0||desired_version!=0)
	{
		goto FULL_UPDATE;
	}
	if(redis_version<instance_version)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
				"VERSION roll back MAAT: %lld -> Redis: %lld.",instance_version,redis_version);
		goto FULL_UPDATE;
	}
	if(redis_version>instance_version&&cumulative_off==1)
	{
		target_version=instance_version;
	}
	else
	{
		target_version=redis_version-1;
	}
	do{
		target_version++;
		rule_num=get_inc_key_list(instance_version, target_version, c, &s_rule_array,logger);
		if(rule_num>0)
		{
			break;
		}
		else if(rule_num<0)
		{
			goto FULL_UPDATE;
		}
		else
		{
			//ret=0, nothing to do.
		}
		
	}while(rule_num==0&&target_version<=redis_version&&cumulative_off==1);
	if(rule_num==0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_DEBUG, maat_redis_monitor,"Got nothing after ZRANGEBYSCORE %s (%lld %lld, cumulative %s"
							,mr_status_sset,instance_version,target_version-1,cumulative_off==1?"OFF":"ON");
		return 0;
	}
	MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
			"Inc Update from instance_version %lld to %lld (%d entries).",instance_version,target_version,rule_num);
	*list=s_rule_array;
	*update_type=CM_UPDATE_TYPE_INC;
	*new_version=target_version;
	return rule_num;

FULL_UPDATE:
	MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
			"Initiate full udpate from instance_version %d to %lld.",instance_version,desired_version==0?redis_version:desired_version);
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
	if(reply->type!=REDIS_REPLY_ARRAY)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
				"Invalid Redis Key List type %d", sub_reply->type);
		freeReplyObject(reply);
		reply=NULL;
		return -1;
	}
	*new_version=read_redis_integer(reply->element[0]);
	sub_reply=reply->element[1];
	if(sub_reply->type!=REDIS_REPLY_ARRAY)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
				"Invalid Redis Key List type %d", sub_reply->type);
		freeReplyObject(reply);
		reply=NULL;
		return -1;
	}

	s_rule_array=(struct serial_rule_t*)calloc(sub_reply->elements,sizeof(struct serial_rule_t));
	for(i=0, full_idx=0; i<sub_reply->elements; i++)
	{
		if(sub_reply->element[i]->type!=REDIS_REPLY_STRING)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
											"Invalid Redis Key Type: %d", sub_reply->element[i]->type);
			continue;
		}
		ret=sscanf(sub_reply->element[i]->str,"%*[^:]:%[^,],%ld",s_rule_array[full_idx].table_name,&(s_rule_array[full_idx].rule_id));
		s_rule_array[full_idx].op=MAAT_OP_ADD;
		if(ret!=2||s_rule_array[full_idx].rule_id<0||strlen(s_rule_array[full_idx].table_name)==0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
			"Invalid Redis Key Format: %s", sub_reply->element[i]->str);
			continue;
		}
		full_idx++;
	}
	rule_num=full_idx;
	freeReplyObject(reply);
	if(desired_version!=0)
	{
		changed_rule_num=get_inc_key_list(desired_version, redis_version, c, &changed_rule_array, logger);
		if(changed_rule_num<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
					"Recover history version %lld faild where as redis version is %lld.", desired_version, redis_version);
		}
		else if(changed_rule_num==0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
					"Nothing to recover from history version %lld to redis version is %lld.", desired_version, redis_version);
		}
		else
		{
			ret=recovery_history_version(s_rule_array, full_idx, changed_rule_array, changed_rule_num, &history_rule_array);
			if(ret>0)
			{
				free(s_rule_array);
				s_rule_array=history_rule_array;
				rule_num=ret;
				*new_version=desired_version;
				MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
					"Successfully recovered from history version %lld to redis version is %lld.", desired_version, redis_version);
			}
		}		
		free(changed_rule_array);
	}
	*list=s_rule_array;
	*update_type=CM_UPDATE_TYPE_FULL;
	MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor,
				"Full update %d keys of version %lldd.", rule_num, new_version);

	return rule_num ;
}

int _get_maat_redis_value(redisContext *c,struct serial_rule_t* rule_list,int rule_num,void* logger)
{
	int i=0,failed_cnt=0,idx=0;
	UNUSED int ret=0;
	int error_happened=0;
	int *retry_ids=(int*)malloc(sizeof(int)*rule_num);
	char redis_cmd[256];
	redisReply* reply=NULL;
	for(i=0;i<rule_num;i++)
	{
		snprintf(redis_cmd,sizeof(redis_cmd),"GET %s:%s,%ld",mr_key_prefix[rule_list[i].op]
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
						,"Redis GET %s:%s,%d failed",mr_key_prefix[rule_list[i].op]
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
		snprintf(redis_cmd,sizeof(redis_cmd),"GET %s:%s,%ld",mr_key_prefix[MAAT_OP_DEL]
				,rule_list[idx].table_name
				,rule_list[idx].rule_id);
		ret=redisAppendCommand(c, redis_cmd);
	}
	for(i=0;i<failed_cnt;i++)
	{
		idx=retry_ids[i];
		ret=_wrap_redisGetReply(c,&reply);
		if(reply->type==REDIS_REPLY_STRING)
		{
			rule_list[idx].table_line=_maat_strdup(reply->str);
		}
		else if(reply->type==REDIS_REPLY_ERROR)//Deal with Redis response: "Loading Redis is loading the database in memory" 
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_redis_monitor
					,"redis command %s error, reply type=%d, error str=%s",redis_cmd, reply->type, reply->str);
		}
		else	//Handle type "nil"
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_redis_monitor
					,"redis command %s failed, reply type=%d",redis_cmd, reply->type);
		}
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

int redlock_try_lock(redisContext *ctx, const char* lock_name, long long expire)
{
	redisReply* reply=NULL;
	int ret=0;
	reply=_wrap_redisCommand(ctx,"SET %s locked NX PX %lld", lock_name, expire);
	if(reply->type==REDIS_REPLY_NIL)
	{
		ret=0;
	}
	else
	{
		ret=1;
	}
	freeReplyObject(reply);
	return ret;
}
void redlock_unlock(redisContext * ctx, const char * lock_name)
{
	redisReply* reply=NULL;
	reply=_wrap_redisCommand(ctx,"DEL %s", lock_name);
	freeReplyObject(reply);

}
#define	POSSIBLE_REDIS_REPLY_SIZE	2
struct expected_reply
{
	int srule_seq;
	int possible_reply_num;
	redisReply possible_replies[POSSIBLE_REDIS_REPLY_SIZE];
};
void expected_reply_add(struct expected_reply* expected, int srule_seq, int type, long long integer)
{
	int i=expected->possible_reply_num;
	assert(i<POSSIBLE_REDIS_REPLY_SIZE);
	expected->srule_seq=srule_seq;
	expected->possible_replies[i].type=type;
	expected->possible_replies[i].integer=integer;
	expected->possible_reply_num++;
}
int mr_operation_success(redisReply* actual_reply, struct expected_reply* expected)
{
	int i=0;
	if(expected->possible_replies[0].type!=actual_reply->type)
	{
		return 0;
	}
	for(i=0; i< expected->possible_reply_num; i++)
	{
		if(expected->possible_replies[i].type==REDIS_REPLY_INTEGER &&
			expected->possible_replies[i].type==actual_reply->type &&
			expected->possible_replies[i].integer==actual_reply->integer)
		{
			return 1;
		}
		if(expected->possible_replies[i].type==REDIS_REPLY_STATUS &&
			expected->possible_replies[i].type==actual_reply->type &&
			0==strcasecmp(actual_reply->str, "OK"))
		{
			return 1;
		}
	}
	return 0;

}

long long _exec_serial_rule_begin(redisContext* ctx,int rule_num, int renew_rule_num,int *renew_allowed, long long *transaction_version)
{
	int ret=-1;
	redisReply* data_reply=NULL;
	if(renew_rule_num>0)
	{
		while(0==redlock_try_lock(ctx, mr_expire_lock, mr_expire_lock_timeout))
		{
			usleep(1000);
		}
		*renew_allowed=1;
	}
	if(rule_num>renew_rule_num)
	{
		data_reply=_wrap_redisCommand(ctx, "INCRBY MAAT_PRE_VER 1");
		*transaction_version=read_redis_integer(data_reply);
		freeReplyObject(data_reply);
		if(*transaction_version<0)
		{
			return -1;
		}
	}
	if(*renew_allowed==1||rule_num>renew_rule_num)
	{
		data_reply=_wrap_redisCommand(ctx,"MULTI");
		freeReplyObject(data_reply);
		ret=0;
	}
	return ret;
}
//parameters: 4 keys: MAAT_VERSION MAAT_UPDATE_STATUS MAAT_VERSION_TIMER MAAT_TRANSACTION_xx, 1 args: SERVER_TIME
const char* lua_exec_done=
"local maat_version=redis.call(\'incrby\', KEYS[1], 1);"
"local transaction=redis.call(\'lrange\', KEYS[4], 0, -1);"
"for k,v in pairs(transaction) do"
"	redis.call(\'zadd\', KEYS[2], maat_version, v);"
"end;"
"redis.call(\'del\', KEYS[4]);"
"redis.call(\'zadd\', KEYS[3], ARGV[1], maat_version);"
"return maat_version;";
redisReply* _exec_serial_rule_end(redisContext* ctx, const char* transaction_list, long long server_time, int renew_allowed, struct expected_reply* expect_reply,  unsigned int *cnt)
{
	redisReply* data_reply=NULL;
	if(renew_allowed==1)
	{
		redlock_unlock(ctx, mr_expire_lock);
		expect_reply[*cnt].srule_seq=-1;
		(*cnt)++;
	}
	if(strlen(transaction_list)>0)
	{
		data_reply=_wrap_redisCommand(ctx, "eval %s 4 MAAT_VERSION %s %s %s %lld",
											lua_exec_done,
											mr_status_sset,
											mr_version_sset,
											transaction_list,
											server_time);
		freeReplyObject(data_reply);
		expected_reply_add(expect_reply+*cnt, -1, REDIS_REPLY_INTEGER, 0);
		(*cnt)++;
	}
	data_reply=_wrap_redisCommand(ctx,"EXEC");
	return data_reply;
}

void _exec_serial_rule(redisContext* ctx,	const char* transaction_list, struct serial_rule_t* s_rule, unsigned int rule_num,  struct expected_reply* expect_reply, unsigned int *cnt, int offset,int renew_allowed)
{
	redisReply* data_reply=NULL;
	unsigned int append_cmd_cnt=0, i=0;
	for(i=0;i<rule_num;i++)
	{
		switch(s_rule[i].op)
		{
			case MAAT_OP_ADD:
				redisAppendCommand(ctx,"SET %s:%s,%lu %s",
						mr_key_prefix[MAAT_OP_ADD],
						s_rule[i].table_name,
						s_rule[i].rule_id,
						s_rule[i].table_line);
				expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_STATUS, 0);
				(*cnt)++;
				append_cmd_cnt++;
				//Allowing add duplicated members for rule id recycling.
				redisAppendCommand(ctx,"RPUSH %s ADD,%s,%lu",
						transaction_list,
						s_rule[i].table_name,
						s_rule[i].rule_id);
				expected_reply_add(expect_reply+*cnt, -1, REDIS_REPLY_INTEGER, 0);
				(*cnt)++;
				append_cmd_cnt++;
				if(s_rule[i].timeout>0)
				{
					redisAppendCommand(ctx,"ZADD %s %lld %s,%lu",
							mr_expire_sset,
							s_rule[i].timeout,
							s_rule[i].table_name,
							s_rule[i].rule_id);
					expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_INTEGER, 1);
					expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_INTEGER, 0);
					(*cnt)++;
					append_cmd_cnt++;
				}
				if(s_rule[i].label_id>0)
				{
					redisAppendCommand(ctx,"ZADD %s %d %s,%lu",
							mr_label_sset,
							s_rule[i].label_id,
							s_rule[i].table_name,
							s_rule[i].rule_id);
					expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_INTEGER, 1);
					expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_INTEGER, 0);

					(*cnt)++;

					append_cmd_cnt++;
				}
				break;
			case MAAT_OP_DEL:
				redisAppendCommand(ctx,"RENAME %s:%s,%lu %s:%s,%lu",
						mr_key_prefix[MAAT_OP_ADD],
						s_rule[i].table_name,
						s_rule[i].rule_id,
						mr_key_prefix[MAAT_OP_DEL],
						s_rule[i].table_name,
						s_rule[i].rule_id
						);
				expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_STATUS, 0);
				(*cnt)++;
				append_cmd_cnt++;
				
				redisAppendCommand(ctx,"EXPIRE %s:%s,%lu %d",
						mr_key_prefix[MAAT_OP_DEL],
						s_rule[i].table_name,
						s_rule[i].rule_id,
						MAAT_REDIS_SYNC_TIME);		
				expected_reply_add(expect_reply+*cnt, i+offset, REDIS_REPLY_INTEGER, 1);
				(*cnt)++;
				append_cmd_cnt++;
				
				//NX: Don't update already exisiting elements. Always add new elements.
				redisAppendCommand(ctx,"RPUSH %s DEL,%s,%lu",
						transaction_list,
						s_rule[i].table_name,
						s_rule[i].rule_id);
				expected_reply_add(expect_reply+*cnt, -1, REDIS_REPLY_INTEGER, 0);
				(*cnt)++;
				append_cmd_cnt++;
				
				// Try to remove from expiration sorted set, no matter wheather it exists or not.
				redisAppendCommand(ctx,"ZREM %s %s,%lu",
						mr_expire_sset,
						s_rule[i].table_name,
						s_rule[i].rule_id);
				expected_reply_add(expect_reply+*cnt, -1, REDIS_REPLY_INTEGER, 0);
				(*cnt)++;
				append_cmd_cnt++;
				
				// Try to remove from label sorted set, no matter wheather it exists or not.
				redisAppendCommand(ctx,"ZREM %s %s,%lu",
						mr_label_sset,
						s_rule[i].table_name,
						s_rule[i].rule_id);
				expected_reply_add(expect_reply+*cnt, -1, REDIS_REPLY_INTEGER, 0);
				(*cnt)++;
				append_cmd_cnt++;
				break;
			case	MAAT_OP_RENEW_TIMEOUT:
				if(renew_allowed!=1)
				{
					continue;
				}
				//s_rule[i].timeout>0 was checked by caller.
				redisAppendCommand(ctx,"ZADD %s %lld %s,%lu",
						mr_expire_sset,
						s_rule[i].timeout,
						s_rule[i].table_name,
						s_rule[i].rule_id);
				expected_reply_add(expect_reply+*cnt, -1, REDIS_REPLY_INTEGER, 0);
				(*cnt)++;
				append_cmd_cnt++;
								
				break;
			default:
				assert(0);
				break;
		}
	}
	for(i=0;i<append_cmd_cnt;i++)
	{
		_wrap_redisGetReply(ctx, &data_reply);
		freeReplyObject(data_reply);
	}
	return;
}

int exec_serial_rule(redisContext* ctx,struct serial_rule_t* s_rule, unsigned int serial_rule_num, long long server_time, void* logger)
{
	unsigned int max_redis_batch=1*1024, batch_cnt=0;
	int renew_allowed=0,last_failed=-1;
	redisReply*transaction_reply=NULL,*p=NULL;
	unsigned int i=0, rule_seq=0;

	unsigned int multi_cmd_cnt=0, success_cnt=0;
	const int MAX_REDIS_OP_PER_SRULE=8;
	unsigned int max_multi_cmd_num=MAX_REDIS_OP_PER_SRULE*serial_rule_num+2;// 2 for operation in _exec_serial_rule_end()
	char transaction_list[MAX_TABLE_NAME_LEN*2]={0};
	struct expected_reply *expected_reply=(struct expected_reply*)calloc(sizeof(struct expected_reply), max_multi_cmd_num);
	long long transaction_version=0, transaction_finished_version=0;
	int renew_num=0,ret=0;
	for(i=0;i<serial_rule_num;i++)
	{
		if(s_rule[i].op==MAAT_OP_RENEW_TIMEOUT)
		{
			renew_num++;
		}
	}

	ret=_exec_serial_rule_begin(ctx, serial_rule_num, renew_num, &renew_allowed, &transaction_version);
	if(ret!=0)//Preconditions for transaction are not satisfied.
	{
		success_cnt=-1;
		goto error_out;
	}
	if(transaction_version>0)
	{
		snprintf(transaction_list, sizeof(transaction_list), "MAAT_TRANSACTION_%lld", transaction_version);
	}
	while(success_cnt<serial_rule_num)
	{
		batch_cnt=MIN(serial_rule_num-success_cnt, max_redis_batch);
		_exec_serial_rule(ctx, transaction_list, s_rule+success_cnt, batch_cnt, expected_reply, &multi_cmd_cnt,success_cnt,renew_allowed);
		assert(multi_cmd_cnt<max_multi_cmd_num);
		success_cnt+=batch_cnt;
	}
	transaction_reply=_exec_serial_rule_end(ctx, transaction_list, server_time, renew_allowed, expected_reply, &multi_cmd_cnt);
	if(1==mr_transaction_success(transaction_reply))
	{
		assert(transaction_reply->elements==multi_cmd_cnt);
		for(i=0;i<multi_cmd_cnt;i++)
		{
			p=transaction_reply->element[i];
			//failed is acceptable
			//or transaciton is success
			//or continuation of last failed
			if(expected_reply[i].srule_seq==-1||1==mr_operation_success(p, expected_reply+i)||last_failed==expected_reply[i].srule_seq)
			{
				continue;
			}
			rule_seq=expected_reply[i].srule_seq;
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_command,
					"%s %s %d failed, rule id maybe conflict or not exist.",
					mr_op_str[s_rule[rule_seq].op],
					s_rule[rule_seq].table_name,s_rule[rule_seq].rule_id);
			success_cnt--;
			last_failed=rule_seq;
		}
	}
	else
	{
		success_cnt=-1;
	}
	if(transaction_version>0)
	{
		transaction_finished_version=read_redis_integer(transaction_reply->element[multi_cmd_cnt-1]);
		MESA_handle_runtime_log(logger, RLOG_LV_DEBUG, maat_command,
							"Redis transaction MAAT_PRE_VER = %lld , MAAT_VERSION = %lld ",
							transaction_version,
							transaction_finished_version);
	}

	freeReplyObject(transaction_reply);
	
error_out:
	if(renew_num>0&&renew_allowed!=1)
	{
		for(i=0;i<(unsigned int)serial_rule_num;i++)
		{
			if(s_rule[i].op==MAAT_OP_RENEW_TIMEOUT)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_command 
						,"%s %s %d is not allowed due to lock contention.",mr_op_str[MAAT_OP_RENEW_TIMEOUT]
						, s_rule[i].table_name,s_rule[i].rule_id);
			}
		}
		if(success_cnt>0)
		{
			success_cnt-=renew_num;
		}
	}
	free(expected_reply);
	return success_cnt;
}


void check_maat_expiration(redisContext *ctx, void *logger)
{
	unsigned int i=0,s_rule_num=0;
	UNUSED int ret=0;
	int success_cnt=0;
	redisReply* data_reply=NULL;
	struct serial_rule_t* s_rule=NULL;
	long long server_time=0;

	server_time=redis_server_time(ctx);
	if(!server_time)
	{
		return;
	}
	data_reply=_wrap_redisCommand(ctx, "ZRANGEBYSCORE %s -inf %lld",mr_expire_sset,server_time);
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
		ret=sscanf(data_reply->element[i]->str,"%[^,],%ld",s_rule[i].table_name,&(s_rule[i].rule_id));
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
				,"Failed to expired %d of %d rules in Redis, try later.", s_rule_num-success_cnt,s_rule_num);
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
	if(!server_time)
	{
		return;
	}
	reply=_wrap_redisCommand(ctx,"MULTI");
	freeReplyObject(reply);
	redisAppendCommand(ctx, "ZRANGEBYSCORE %s -inf %lld",mr_version_sset,server_time-MAAT_REDIS_SYNC_TIME);
	append_cmd_cnt++;
	redisAppendCommand(ctx, "ZREMRANGEBYSCORE %s -inf %lld",mr_version_sset,server_time-MAAT_REDIS_SYNC_TIME);
	append_cmd_cnt++;
	//consume reply "OK" and "QUEUED".
	for(i=0;i<append_cmd_cnt;i++)
	{
		_wrap_redisGetReply(ctx, &reply);
		freeReplyObject(reply);
		reply=NULL;
	}
	reply=_wrap_redisCommand(ctx,"EXEC");
	if(reply->type!=REDIS_REPLY_ARRAY)
	{
		goto error_out;
	}
	sub_reply=reply->element[0];
	if(sub_reply->type!=REDIS_REPLY_ARRAY)
	{
		goto error_out;
	}
	version_num=sub_reply->elements;
	if(version_num==0)
	{
		goto error_out;
	}
	version_lower_bound=read_redis_integer(sub_reply->element[0]);
	version_upper_bound=read_redis_integer(sub_reply->element[sub_reply->elements-1]);
	freeReplyObject(reply);	

	//To deal with maat_version reset to 0, do NOT use -inf as lower bound intentionally.
	reply=_wrap_redisCommand(ctx,"ZREMRANGEBYSCORE %s %lld %lld",mr_status_sset,version_lower_bound,version_upper_bound);
	entry_num=read_redis_integer(reply);
	freeReplyObject(reply);	

	MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_redis_monitor 
			,"Clean up update status from version %lld to %lld (%lld versions, %lld entries)."
			,version_lower_bound
			,version_upper_bound
			,version_num
			,entry_num);
	return;
	
error_out:
	freeReplyObject(reply);	
	return;	
}
const char* find_Nth_column(const char* line, int Nth, int* column_len)
{
	int i=0, j=0;
	int start=0, end=0;
	for(i=0;i<(int)strlen(line);i++)
	{
		if(line[i]!=' '&&line[i]!='\t')
		{
			continue;
		}
		j++;
		if(j==Nth-1)
		{
			start=i+1;
		}
		if(j==Nth)
		{
			end=i;
			break;
		}
	}
	if(start==end)
	{
		return NULL;
	}
	if(end==0)
	{
		end=i;
	}
	*column_len=end-start;
	return line+start;
}
char* get_foreign_cont_filename(const char* table_name, int rule_id, const char* foreign_key, const char* dir)
{
	char* filename=NULL;
	char buffer[512];
	snprintf(buffer, sizeof(buffer),"%s/%s-%d-%s",dir, table_name, rule_id, foreign_key);
	filename=(char*)calloc(sizeof(char), strlen(buffer)+1);
	memcpy(filename, buffer, strlen(buffer));
	return filename;
}
void rewrite_table_line_with_foreign(struct serial_rule_t*p)
{
	int origin_column_size=0;
	const char* origin_column=NULL, *pos_origin_line=NULL;
	char* pos_rewrite_line=NULL;
	char* rewrite_line=NULL;
	size_t fn_size=0;
	int i=0;
	for(i=0; i<p->n_foreign; i++)
	{
		fn_size+=strlen(p->f_keys[i].filename);
	}
	
	rewrite_line=(char*)calloc(sizeof(char), strlen(p->table_line)+fn_size);
	pos_origin_line=p->table_line;
	pos_rewrite_line=rewrite_line;
	
	for(i=0; i<p->n_foreign; i++)
	{
		origin_column=find_Nth_column(p->table_line, p->f_keys[i].column, &origin_column_size);
		strncat(pos_rewrite_line, pos_origin_line, origin_column-pos_origin_line);
		pos_rewrite_line+=origin_column-pos_origin_line;
		pos_origin_line=origin_column+origin_column_size;
		
		strncat(pos_rewrite_line, p->f_keys[i].filename, strlen(p->f_keys[i].filename));
		pos_rewrite_line+=strlen(p->f_keys[i].filename);
	}
	strncat(pos_rewrite_line, pos_origin_line, strlen(p->table_line)-(pos_origin_line-p->table_line));
	
	free(p->table_line);
	p->table_line=rewrite_line;
	return;
}
void _get_foregin_keys(struct serial_rule_t* p_rule, int* foreign_columns, int n_foreign, const char* dir, void* logger)
{
	int i=0;
	const char* p_foreign=NULL;
	int foreign_key_size=0;
	p_rule->n_foreign=n_foreign;
	p_rule->f_keys=ALLOC(struct foreign_key, n_foreign);
	for(i=0; i<n_foreign; i++)
	{
		p_foreign=find_Nth_column(p_rule->table_line, foreign_columns[i], &foreign_key_size);
		if(p_foreign==NULL)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_redis_monitor
									, "Get %s,%d foreign keys failed: No %dth column."
									, p_rule->table_name, p_rule->rule_id, foreign_columns[i]);
			break;
		}
		if(0!=strncmp(p_foreign, foreign_source_prefix, strlen(foreign_source_prefix)))
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_redis_monitor
									,"Get %s,%d foreign key failed: Invalid source prefix %s."
									, p_rule->table_name, p_rule->rule_id, p_foreign);
			break;
		}
		p_rule->f_keys[i].column=foreign_columns[i];
		foreign_key_size=foreign_key_size-strlen(foreign_source_prefix);
		p_foreign+=strlen(foreign_source_prefix);
		if(0!=strncmp(p_foreign, foreign_key_prefix, strlen(foreign_key_prefix)))
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_redis_monitor
								,"%s,%d foreign key prefix %s is discouraged."
								,p_rule->table_name, p_rule->rule_id, p_foreign);
		}
		p_rule->f_keys[i].key=(char*)calloc(sizeof(char),foreign_key_size+1);
		memcpy(p_rule->f_keys[i].key, p_foreign, foreign_key_size);
		p_rule->f_keys[i].filename=get_foreign_cont_filename(p_rule->table_name, p_rule->rule_id, p_rule->f_keys[i].key, dir);
	}
	if(i!=n_foreign)
	{
		p_rule->n_foreign=0;
		free(p_rule->f_keys);
		p_rule->f_keys=NULL;
		p_rule->with_error=1;
	}
}
int get_foreign_keys_define(redisContext *ctx, struct serial_rule_t* rule_list, int rule_num, _Maat_feather_t* feather, const char* dir,void *logger)
{
	int i=0;
	int rule_with_foreign_key=0;
	struct Maat_table_schema* p_table=NULL;
	struct plugin_table_schema* plugin_desc=NULL;
	for(i=0; i<rule_num; i++)
	{
		if(rule_list[i].table_line==NULL)
		{
			continue;
		}
		p_table=Maat_table_get_desc_by_name(feather->table_mgr, rule_list[i].table_name);
		if(!p_table||p_table->table_type!=TABLE_TYPE_PLUGIN)
		{
			continue;
		}
		plugin_desc= &(p_table->plugin);
		if(plugin_desc->n_foreign==0)
		{
			continue;
		}
		_get_foregin_keys(rule_list+i, plugin_desc->foreign_columns, plugin_desc->n_foreign, dir, logger);
		rule_with_foreign_key++;
	}
	return rule_with_foreign_key;
}
int get_foreign_keys_by_prefix(redisContext *ctx, struct serial_rule_t* rule_list, int rule_num, const char* dir,void *logger)
{
	int i=0, j=0, foreign_key_size=0;
	int rule_with_foreign_key=0;
	const char* p_foreign=NULL;

	int n_foreign=0;
	int foreign_columns[MAX_FOREIGN_CLMN_NUM];
	for(i=0; i<rule_num; i++)
	{
		j=1;
		n_foreign=0;
		do{
			p_foreign=find_Nth_column(rule_list[i].table_line, j, &foreign_key_size);			
			if(p_foreign!=NULL&&foreign_key_size>(int)strlen(foreign_source_prefix)&&0==strncmp(p_foreign,foreign_source_prefix, strlen(foreign_source_prefix)))
			{
				foreign_columns[n_foreign]=j;
				n_foreign++;
			}
			j++;
		}while(p_foreign!=NULL&&n_foreign<MAX_FOREIGN_CLMN_NUM);
		if(n_foreign>0)
		{
			_get_foregin_keys(rule_list+i, foreign_columns, n_foreign,dir,logger);
			rule_with_foreign_key++;
		}
	}
	return rule_with_foreign_key;
}

struct foreign_conts_track
{
	int rule_idx;
	int foreign_idx;
};
void _get_foreign_conts(redisContext *ctx, struct serial_rule_t* rule_list, int rule_num, int print_fn, void *logger)
{
	int i=0, j=0;
	UNUSED int ret=0;
	int key_num=0;
	struct foreign_conts_track* track=ALLOC(struct foreign_conts_track, rule_num*MAX_FOREIGN_CLMN_NUM); 
	char redis_cmd[256];
	redisReply* reply=NULL;
	struct serial_rule_t*p=NULL;
	FILE* fp=NULL;
	struct stat file_info;

	for(i=0;i<rule_num;i++)
	{
		p=rule_list+i;
		if(p->n_foreign==0)
		{
			continue;
		}
		if(p->op==MAAT_OP_DEL)
		{
			for(j=0; j<rule_list[i].n_foreign; j++)
			{
				//ret=system_cmd_rm(rule_list[i].f_keys[j].filename);
				ret=remove(rule_list[i].f_keys[j].filename);
				if(ret==-1)
				{
					MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_module,
							"Foreign content file %s remove failed.",
							rule_list[i].f_keys[j].filename);
				}
			}
		}	
		else
		{
			for(j=0; j<p->n_foreign; j++)
			{
				ret=stat(p->f_keys[j].filename, &file_info);
				if(ret==0)
				{
					continue;
				}
				snprintf(redis_cmd,sizeof(redis_cmd),"GET %s", p->f_keys[j].key);
				ret=redisAppendCommand(ctx, redis_cmd);
				track[key_num].rule_idx=i;
				track[key_num].foreign_idx=j;
				key_num++;
				assert(ret==REDIS_OK);
			}
		}
	}
	for(i=0;i<key_num;i++)
	{
		ret=_wrap_redisGetReply(ctx,&reply);
		if(reply->type!=REDIS_REPLY_STRING)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor
					,"Get %s,%d foreign key %s content failed."
					,rule_list[track[i].rule_idx].table_name
					,rule_list[track[i].rule_idx].rule_id
					,rule_list[track[i].rule_idx].f_keys[track[i].foreign_idx].key);
			continue;
		}
		else
		{
			p=rule_list+track[i].rule_idx;
			fp=fopen(p->f_keys[track[i].foreign_idx].filename, "w");
			if(fp==NULL)
			{
				MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor
										, "Write foreign content failed: fopen %s error."
										, p->f_keys[track[i].foreign_idx]);
			}
			else
			{
				fwrite(reply->str, 1, reply->len, fp);
				fclose(fp);
				fp=NULL;
				if(print_fn==1)
				{
					printf("Written foreign content %s\n",p->f_keys[track[i].foreign_idx].filename);
				}
			}
		}
		freeReplyObject(reply);
	}
	free(track);
	return;
}
void get_foreign_conts(redisContext *ctx, struct serial_rule_t* rule_list, int rule_num, int print_fn, void *logger)
{
	int max_redis_batch=4*1024,batch_cnt=0;
	int success_cnt=0;
	while(success_cnt<rule_num)
	{
		batch_cnt=MIN(rule_num-success_cnt,max_redis_batch);
		_get_foreign_conts(ctx,rule_list+success_cnt,batch_cnt,print_fn,logger);
		success_cnt+=batch_cnt;	
	}
	return;
}

void redis_monitor_traverse(long        long version, struct source_redis_ctx* mr_ctx,
		void (*start)(long long,int ,void*),//vesion,CM_UPDATE_TYPE_*,u_para
		int (*update)(const char* ,const char*,void* ),//table name ,line ,u_para
		void (*finish)(void*),//u_para
		void* u_para,
		const char* dec_key,
		_Maat_feather_t* feather)
{
	int table_id=0, i=0, rule_num=0, empty_value_num=0, valid_column=-1;
	int ret=0;
	struct serial_rule_t* rule_list=NULL;
	int update_type=CM_UPDATE_TYPE_INC;
	long long new_version=0;
	enum MAAT_TABLE_TYPE table_type;
	struct Maat_table_schema* table_desc=NULL;
	const struct plugin_table_schema* plugin_desc=NULL;
	void* logger=feather->logger;

	if(mr_ctx->write_ctx!=NULL&&mr_ctx->write_ctx->err==0)//authorized to write
	{
		//For thread safe, deliberately use redis_read_ctx but not redis_write_ctx.
		if(1==redlock_try_lock(mr_ctx->read_ctx, mr_expire_lock, mr_expire_lock_timeout))
		{
			check_maat_expiration(mr_ctx->read_ctx, logger);
			cleanup_update_status(mr_ctx->read_ctx, logger);
			redlock_unlock(mr_ctx->read_ctx, mr_expire_lock);
		}
	}
	if(mr_ctx->read_ctx==NULL||mr_ctx->read_ctx->err)
	{
		if(time(NULL)-mr_ctx->last_reconnect_time < MAAT_REDIS_RECONNECT_INTERVAL)
		{
			return;
		}
		mr_ctx->last_reconnect_time=time(NULL);
		if(mr_ctx->read_ctx!=NULL)
		{
			redisFree(mr_ctx->read_ctx);
		}
		MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_redis_monitor, "Reconnecting...");
		mr_ctx->read_ctx=connect_redis(mr_ctx->redis_ip, mr_ctx->redis_port, mr_ctx->redis_db, feather->logger);
		if(mr_ctx->read_ctx==NULL)
		{
			return;
		}
	}
	
	rule_num=get_rm_key_list(mr_ctx->read_ctx, version, feather->load_version_from, &new_version, &rule_list, &update_type, logger, feather->cumulative_update_off);
	if(rule_num<0)//redis communication error
	{
		return;
	}
	feather->load_version_from=0;//only valid for one time.
	if(rule_num==0&&update_type==CM_UPDATE_TYPE_INC)//error or nothing changed
	{
		return;
	}
	if(rule_num>0)
	{
		ret=get_maat_redis_value(mr_ctx->read_ctx, rule_list, rule_num, logger, 0);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_redis_monitor,"Get Redis value failed, abandon update.");
			goto clean_up;
		}
		for(i=0;i<rule_num;i++)
		{
			if(rule_list[i].table_line==NULL)
			{
				empty_value_num++;
			}
		}
		if(empty_value_num==rule_num)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_redis_monitor,"All %d rules are empty, abandon update.",empty_value_num);
			goto clean_up;
		}
		if(empty_value_num>0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_redis_monitor,"%d of %d rules are empty.",empty_value_num,rule_num);
		}
		ret=get_foreign_keys_define(mr_ctx->read_ctx, rule_list, rule_num, feather, feather->foreign_cont_dir, logger);
		if(ret>0)
		{
			get_foreign_conts(mr_ctx->read_ctx, rule_list, rule_num, 0, logger);
		}
	}
	start(new_version,update_type,u_para);
	MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_redis_monitor,"Start %s update: %lld -> %lld (%d entries).",
								update_type==CM_UPDATE_TYPE_INC?"INC":"FULL",version,new_version,rule_num);
	for(i=0;i<rule_num;i++)
	{
		if(rule_list[i].table_line==NULL||rule_list[i].with_error==1)
		{
			continue;
		}
		table_id=Maat_table_get_id_by_name(feather->table_mgr, rule_list[i].table_name);
		if(table_id<0)//Unrecognized table.
		{
			continue;
		}
		table_type=Maat_table_get_type_by_id(feather->table_mgr, table_id);
		if(rule_list[i].op==MAAT_OP_DEL)
		{
			if(table_type==TABLE_TYPE_PLUGIN)
			{
				table_desc=Maat_table_get_scan_by_id(feather->table_mgr, table_id, TABLE_TYPE_PLUGIN, NULL);
				plugin_desc=&(table_desc->plugin);
				valid_column=plugin_desc->valid_flag_column;
			}
			else
			{
				valid_column=-1;
			}
			ret=invalidate_line(rule_list[i].table_line, table_type, valid_column);
			if(ret<0)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_redis_monitor,"Invaid format %s ."
										,rule_list[i].table_line);
				continue;
			}
		}
		if(rule_list[i].n_foreign>0)
		{
			rewrite_table_line_with_foreign(rule_list+i);
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
int Maat_command_raw_set_lines(Maat_feather_t feather,const struct Maat_cmd_line** line_rule, size_t n_line ,enum MAAT_OPERATION op)
{
	size_t i=0;
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	int ret=0, table_id=0,success_cnt=0;
	struct serial_rule_t *s_rule=NULL;
	long long server_time=0,absolute_expire_time=0;
	redisContext* write_ctx=get_redis_ctx_for_write(_feather);
	if(write_ctx==NULL)
	{
		return -1;
	}
	server_time=redis_server_time(write_ctx);
	if(!server_time)
	{
		return -1;
	}
	s_rule=ALLOC(struct serial_rule_t, n_line);
	for(i=0;i<n_line;i++)
	{
		table_id=Maat_table_get_id_by_name(_feather->table_mgr, line_rule[i]->table_name);
		if(table_id<0)
		{
			MESA_handle_runtime_log(_feather->logger, RLOG_LV_FATAL, maat_command,
					"Command raw set line id %d failed: unknown table %s.",
					line_rule[i]->rule_id,
					line_rule[i]->table_name);
			ret=-1;
			goto error_out;
		}
		if(op==MAAT_OP_RENEW_TIMEOUT)
		{
			assert(line_rule[i]->expire_after>0);
		}
		if(line_rule[i]->expire_after>0)
		{
			absolute_expire_time=server_time+line_rule[i]->expire_after;
		}
		set_serial_rule(s_rule+i, op,line_rule[i]->rule_id,line_rule[i]->label_id, line_rule[i]->table_name,
						line_rule[i]->table_line, absolute_expire_time);
	}
	success_cnt=exec_serial_rule(write_ctx,s_rule, n_line,server_time,_feather->logger);
	if(success_cnt<0||(size_t)success_cnt!=n_line)//error
	{
		ret=-1;
		goto error_out;
	}
	ret=success_cnt;
	_feather->line_cmd_acc_num+=success_cnt;

error_out:
	for(i=0;i<n_line;i++)
	{
		empty_serial_rules(s_rule+i);
	}
	free(s_rule);
	return ret;

}
int Maat_cmd_set_lines(Maat_feather_t feather,const struct Maat_cmd_line** line_rule, int line_num ,enum MAAT_OPERATION op)
{
	int i=0, j=0;
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	int ret=0, table_id=0,success_cnt=0;
	struct serial_rule_t *s_rule=NULL;
	struct Maat_table_schema* p_table=NULL;
	struct plugin_table_schema* plugin_desc=NULL;
	long long server_time=0,absolute_expire_time=0;
	const char* p_foreign=NULL;	
	int foreign_key_size=0;
	redisContext* write_ctx=get_redis_ctx_for_write(_feather);
	if(write_ctx==NULL)
	{
		return -1;
	}
	server_time=redis_server_time(write_ctx);
	if(!server_time)
	{
		return -1;
	}
	s_rule=(struct serial_rule_t *)calloc(sizeof(struct serial_rule_t),line_num);
	for(i=0;i<line_num;i++)
	{
		table_id=Maat_table_get_id_by_name(_feather->table_mgr, line_rule[i]->table_name);
		if(table_id<0)
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_command 
					,"Command set line id %d failed: unknown table %s."
					, line_rule[i]->rule_id
					, line_rule[i]->table_name);
			ret=-1;
			goto error_out;
		}
		p_table=Maat_table_get_scan_by_id(_feather->table_mgr, table_id, TABLE_TYPE_PLUGIN, NULL);
		if(!p_table)
		{
			MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_command 
					,"Command set line id %d failed: table %s is not a plugin table."
					, line_rule[i]->rule_id
					, line_rule[i]->table_name);
			ret=-1;
			goto error_out;
		}
		plugin_desc=&(p_table->plugin);
		if(op==MAAT_OP_ADD)
		{
			ret=get_valid_flag_offset(line_rule[i]->table_line
				, p_table->table_type
				, plugin_desc->valid_flag_column);
			if(ret<0||
				(op==MAAT_OP_ADD&&line_rule[i]->table_line[ret]!='1'))
			{
				MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_command 
						,"Command set line %s %d failed: illegal valid flag."
						, line_rule[i]->table_name, line_rule[i]->rule_id);
				ret=-1;
				goto error_out;
			}
		}
		if(op==MAAT_OP_RENEW_TIMEOUT)
		{
			assert(line_rule[i]->expire_after>0);
		}
		if(line_rule[i]->expire_after>0)
		{
			absolute_expire_time=server_time+line_rule[i]->expire_after;
		}
		if(plugin_desc->n_foreign>0)
		{
			for(j=0;j<plugin_desc->n_foreign;j++)
			{
				p_foreign=find_Nth_column(line_rule[i]->table_line, plugin_desc->foreign_columns[j], &foreign_key_size);
				if(p_foreign==NULL)
				{
					MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL, maat_command
											, "Command set line %s %d failed: No %dth column."
											, line_rule[i]->table_name, line_rule[i]->rule_id
											, plugin_desc->foreign_columns[j]);
					ret=-1;
					goto error_out;
				}
				if(0!=strncmp(p_foreign, foreign_source_prefix, strlen(foreign_source_prefix)))
				{
					MESA_handle_runtime_log(_feather->logger,RLOG_LV_FATAL,maat_redis_monitor
											,"Command set line %s %d failed: Source prefix %s is mandatory."
											, line_rule[i]->table_name, line_rule[i]->rule_id, foreign_source_prefix);
					ret=-1;
					goto error_out;
				}
			}

		}
		set_serial_rule(s_rule+i, op,line_rule[i]->rule_id,line_rule[i]->label_id, line_rule[i]->table_name,
						line_rule[i]->table_line, absolute_expire_time);
	}
	success_cnt=exec_serial_rule(write_ctx,s_rule, line_num,server_time,_feather->logger);
	if(success_cnt<0||success_cnt!=line_num)//error
	{
		ret=-1;
		goto error_out;
	}
	ret=success_cnt;
	_feather->line_cmd_acc_num+=success_cnt;

error_out:
	for(i=0;i<line_num;i++)
	{
		empty_serial_rules(s_rule+i);
	}
	free(s_rule);
	return ret;
}

int Maat_cmd_set_line(Maat_feather_t feather,const struct Maat_cmd_line* line_rule, enum MAAT_OPERATION op)
{
	int ret=0;
	ret=Maat_cmd_set_lines(feather,&line_rule, 1, op);
	return ret;
}
int Maat_cmd_set_file(Maat_feather_t feather,const char* key, const char* value, size_t size, enum MAAT_OPERATION op)
{
	struct _Maat_feather_t* _feather=(struct _Maat_feather_t*)feather;
	redisContext* ctx=_feather->mr_ctx.write_ctx;
	if(ctx==NULL)
	{
		MESA_handle_runtime_log(_feather->logger, RLOG_LV_FATAL, maat_command, "%s failed: Redis is not connected.", __FUNCTION__);
		return -1;
	}
	const char *arg_vec[3];
	size_t len_vec[3];
	arg_vec[0] = "SET";
	len_vec[0] = strlen("SET");

	arg_vec[1] = key;
	len_vec[1] = strlen(key);

	arg_vec[2] = value;
	len_vec[2] = size;

	redisReply *reply=NULL;
	if(0!=strncmp(key, foreign_key_prefix, strlen(foreign_key_prefix)))
	{
		MESA_handle_runtime_log(_feather->logger, RLOG_LV_FATAL, maat_command, "Invalid File key, prefix %s is mandatory.", foreign_key_prefix);
		return -1;
	}
	switch(op)
	{
		case MAAT_OP_ADD:
			reply= (redisReply *)redisCommandArgv(ctx, sizeof(arg_vec) / sizeof(arg_vec[0]), arg_vec, len_vec);
			break;
		case MAAT_OP_DEL:	
			reply=_wrap_redisCommand(ctx,"EXPIRE %s %d", key, MAAT_REDIS_SYNC_TIME);
			break;
		default:
			return -1;
			break;
	}
	if(reply==NULL||reply->type==REDIS_REPLY_NIL||reply->type==REDIS_REPLY_ERROR)
	{
		MESA_handle_runtime_log(_feather->logger, RLOG_LV_FATAL, maat_command,"Set file failed, maybe Redis is busy.");
		freeReplyObject(reply);
		reply=NULL;
		return -1;		
	}
	freeReplyObject(reply);
	return 1;
}

long long Maat_cmd_incrby(Maat_feather_t feather,const char* key, int increment)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	redisReply* data_reply=NULL;
	long long result=0;
	redisContext* write_ctx=get_redis_ctx_for_write(_feather);
	
	if(write_ctx==NULL)
	{
		return -1;
	}
	data_reply=_wrap_redisCommand(write_ctx,"INCRBY %s %d", key, increment); 
	if(data_reply->type==REDIS_REPLY_INTEGER)
	{
		result=data_reply->integer;
	}
	else
	{
		result=-1;
	}
	freeReplyObject(data_reply);
	return result;		
}
int Maat_command_get_new_group_id(Maat_feather_t feather)
{
	int group_id=0;
	group_id=(int) Maat_cmd_incrby(feather, mr_group_id_var, 1);
	return group_id;
}
int Maat_command_get_new_region_id(Maat_feather_t feather)
{
	int region_id=0;
	region_id=(int) Maat_cmd_incrby(feather, mr_region_id_var, 1);
	return region_id;
}

void Maat_cmd_key_free(struct Maat_cmd_key**keys, int size)
{
	int i=0;
	struct Maat_cmd_key* p=*keys;
	for(i=0; i<size; i++, p++)
	{
		free(p->table_name);
		p->table_name=NULL;
		p->rule_id=0;
	}
	free(*keys);
	*keys=NULL;
	return;
}

int Maat_cmd_key_select(Maat_feather_t feather, int label_id, struct Maat_cmd_key** keys)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	redisReply* data_reply=NULL;
	char* tmp=NULL;
	unsigned int i=0;
	struct Maat_cmd_key* result=NULL;
	int result_cnt=0;
	redisContext* write_ctx=get_redis_ctx_for_write(_feather);
	if(write_ctx==NULL)
	{
		return -1;
	}

	data_reply=_wrap_redisCommand(write_ctx,"ZRANGEBYSCORE %s %d %d",
					mr_label_sset,
					label_id,
					label_id);
	result_cnt=data_reply->elements;
	result=ALLOC(struct Maat_cmd_key, data_reply->elements);
	for(i=0;i<data_reply->elements;i++)
	{
		result[i].table_name=_maat_strdup(data_reply->element[i]->str);
		tmp=strchr(result[i].table_name, ',');
		if(tmp!=NULL)
		{
			*tmp='\0';
			tmp++;
			result[i].rule_id=atoi(tmp);
		}
		else// old version compatible
		{
			result[i].rule_id=atoi(result[i].table_name);
			free(result[i].table_name);
			result[i].table_name=NULL;
		}
	}
	freeReplyObject(data_reply);
	*keys=result;
	return result_cnt;	
}

int redis_flush_DB(redisContext* ctx, int db_index, void* logger)
{
	redisReply* data_reply=NULL;
	long long maat_redis_version=0, dbsize=0;
	int append_cmd_cnt=0, i=0;
	int redis_transaction_success=1;

	data_reply=_wrap_redisCommand(ctx, "WATCH MAAT_VERSION");
	freeReplyObject(data_reply);
	data_reply=_wrap_redisCommand(ctx, "GET MAAT_VERSION");
	if(data_reply->type==REDIS_REPLY_NIL)
	{
		maat_redis_version=0;
	}
	else
	{
		maat_redis_version=read_redis_integer(data_reply);
		maat_redis_version++;
		freeReplyObject(data_reply);
	}
	data_reply=_wrap_redisCommand(ctx, "DBSIZE");
	dbsize=read_redis_integer(data_reply);
	freeReplyObject(data_reply);
	
	data_reply=_wrap_redisCommand(ctx,"MULTI");
	freeReplyObject(data_reply);
	
	redisAppendCommand(ctx,"FLUSHDB");
	append_cmd_cnt++;
	redisAppendCommand(ctx,"SET MAAT_VERSION %lld",maat_redis_version);
	append_cmd_cnt++;
	redisAppendCommand(ctx,"SET MAAT_PRE_VER %lld",maat_redis_version);
	append_cmd_cnt++;
	redisAppendCommand(ctx,"SET %s 1", mr_region_id_var);
	append_cmd_cnt++;
	redisAppendCommand(ctx,"SET %s 1", mr_group_id_var);
	append_cmd_cnt++;
	redisAppendCommand(ctx,"EXEC");
	append_cmd_cnt++;
	for(i=0;i<append_cmd_cnt;i++)
	{
		_wrap_redisGetReply(ctx, &data_reply);
		if(0==mr_transaction_success(data_reply))
		{
			redis_transaction_success=0;
		}
		freeReplyObject(data_reply);
	}
	if(redis_transaction_success==1)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_command 
				,"FlushDB %d, MAAT_VERSION=%llu, DBSize=%llu."
				,db_index, (maat_redis_version==0)?0:(maat_redis_version-1),dbsize
				);
	}
	return redis_transaction_success;
}
TAILQ_HEAD(serial_rule_q, serial_rule_t);

struct Maat_command_batch
{
	int batch_size;
	serial_rule_q queue;
	struct _Maat_feather_t * feather;
	long long server_time;
};
struct Maat_command_batch* Maat_command_batch_new(Maat_feather_t feather)
{	
	struct Maat_command_batch* batch=ALLOC(struct Maat_command_batch, 1);
	TAILQ_INIT(&batch->queue);
	batch->feather=(struct _Maat_feather_t *)feather;
	redisContext* write_ctx=get_redis_ctx_for_write(batch->feather);
	if(write_ctx==NULL)
	{
		free(batch);
		return NULL;
	}
	batch->server_time=redis_server_time(write_ctx);
	if(!batch->server_time)
	{
		free(batch);
		return NULL;
	}
	return batch;
}

int Maat_command_batch_set_region(struct Maat_command_batch* batch,  enum MAAT_OPERATION op, const struct Maat_cmd_region* region, int group_id)
{
	struct serial_rule_t* s_rule=ALLOC(struct serial_rule_t, 1);
	long long absolute_expire_time=0;
	char line[MAX_TABLE_LINE_SIZE];
	
	serialize_region(region, group_id, line, sizeof(line));

	set_serial_rule(s_rule, op, region->region_id, 0, region->table_name,
					line, absolute_expire_time);
	TAILQ_INSERT_TAIL(&batch->queue, s_rule, entries);
	batch->batch_size++;
	return 0;

}
#define TO_GROUP2X_KEY(group_id, parent_id)	((unsigned long)group_id<<32|parent_id)

int Maat_command_batch_set_group2group(struct Maat_command_batch* batch, enum MAAT_OPERATION op, const struct Maat_cmd_group2group* g2g)
{
	struct serial_rule_t* s_rule=ALLOC(struct serial_rule_t, 1);
	long long absolute_expire_time=0;
	char line[MAX_TABLE_LINE_SIZE];

	serialize_group2group(op, g2g, line, sizeof(line));

	set_serial_rule(s_rule, op, TO_GROUP2X_KEY(g2g->group_id, g2g->superior_group_id), 0, g2g->table_name,
					line, absolute_expire_time);

	TAILQ_INSERT_TAIL(&batch->queue, s_rule, entries);
	batch->batch_size++;
	return 0;
}
int Maat_command_batch_set_group2compile(struct Maat_command_batch* batch, enum MAAT_OPERATION op, const struct Maat_cmd_group2compile* g2c)
{
	struct serial_rule_t* s_rule=ALLOC(struct serial_rule_t, 1);
	long long absolute_expire_time=0;
	char line[MAX_TABLE_LINE_SIZE];

	serialize_group2compile(op, g2c, line, sizeof(line));
	set_serial_rule(s_rule, op, TO_GROUP2X_KEY(g2c->group_id, g2c->compile_id), 0, g2c->table_name,
					line, absolute_expire_time);
	TAILQ_INSERT_TAIL(&batch->queue, s_rule, entries);
	batch->batch_size++;
	return 0;
}
int Maat_command_batch_set_compile(struct Maat_command_batch* batch, enum MAAT_OPERATION op, const struct Maat_rule_t* compile, const char* table_name, const char * huge_service_defined, int clause_num, int label_id, int expire_after)
{

	struct serial_rule_t* s_rule=ALLOC(struct serial_rule_t, 1);
	long long absolute_expire_time=0;
	char line[MAX_TABLE_LINE_SIZE];
	serialize_compile(compile, huge_service_defined, clause_num, op, line, sizeof(line));

	if(expire_after>0)
	{
		absolute_expire_time=batch->server_time+expire_after;
	}
	set_serial_rule(s_rule, op, compile->config_id, label_id, table_name,
					line, absolute_expire_time);

	TAILQ_INSERT_TAIL(&batch->queue, s_rule, entries);
	batch->batch_size++;
	return 0;
}
int Maat_command_batch_commit(struct Maat_command_batch* batch)
{
	struct serial_rule_t* s_rule_array=ALLOC(struct serial_rule_t, batch->batch_size);
	int i=0;
	redisContext* write_ctx=get_redis_ctx_for_write(batch->feather);
	struct serial_rule_t * tmp = TAILQ_FIRST(&batch->queue);
	
	while(tmp != NULL)
	{
		TAILQ_REMOVE(&batch->queue, tmp, entries);
		memcpy(s_rule_array+i, tmp, sizeof(*tmp));
		free(tmp);
		tmp = TAILQ_FIRST(&batch->queue);
		i++;
	}
	assert(i==batch->batch_size);
	exec_serial_rule(write_ctx, s_rule_array, batch->batch_size, batch->server_time, batch->feather->logger);
	for(i=0; i<batch->batch_size; i++)
	{
		empty_serial_rules(s_rule_array+i);
	}
	free(s_rule_array);	
	free(batch);
	return i;
}

int Maat_command_raw_set_compile(Maat_feather_t feather, enum MAAT_OPERATION op, const struct Maat_rule_t* compile, const char* table_name, const char * huge_service_defined, int clause_num,  int label_id, int expire_after)
{
	struct Maat_command_batch* batch=NULL;
	batch=Maat_command_batch_new(feather);
	Maat_command_batch_set_compile(batch, op, compile, table_name, huge_service_defined, clause_num, label_id, expire_after);
	Maat_command_batch_commit(batch);
	return 0;
}
int Maat_command_raw_set_region(Maat_feather_t feather,  enum MAAT_OPERATION op, const struct Maat_cmd_region* region, int group_id)
{
	struct Maat_command_batch* batch=NULL;
	batch=Maat_command_batch_new(feather);
	Maat_command_batch_set_region(batch, op, region, group_id);
	Maat_command_batch_commit(batch);
	return 0;
}
int Maat_command_raw_set_group2compile(Maat_feather_t feather, enum MAAT_OPERATION op, const struct Maat_cmd_group2compile* g2c)
{
	struct Maat_command_batch* batch=NULL;
	batch=Maat_command_batch_new(feather);
	Maat_command_batch_set_group2compile(batch, op, g2c);
	Maat_command_batch_commit(batch);
	return 0;
}
int Maat_command_raw_set_group2group(Maat_feather_t feather, enum MAAT_OPERATION op, const struct Maat_cmd_group2group* g2g)
{

	struct Maat_command_batch* batch=NULL;
	batch=Maat_command_batch_new(feather);
	Maat_command_batch_set_group2group(batch, op, g2g);
	Maat_command_batch_commit(batch);
	return 0;
}

int Maat_cmd_flushDB(Maat_feather_t feather)
{
	_Maat_feather_t* _feather=(_Maat_feather_t*)feather;
	int ret=0;
	redisContext* write_ctx=get_redis_ctx_for_write(_feather);
	if(write_ctx==NULL)
	{
		return -1;
	}
	do
	{
		ret=redis_flush_DB(_feather->mr_ctx.write_ctx, _feather->mr_ctx.redis_db, _feather->logger);
	}while(ret==0);
	return 0;
}

