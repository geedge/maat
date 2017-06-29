#include "hiredis.h"
#include <errno.h>

const char* maat_redis_monitor="MAAT_REDIS_MONITOR";
void redis_monitor_traverse(unsigned int version,redisContext *c,
							void (*start)(unsigned int ,int ,void*),//vesion,CM_UPDATE_TYPE_*,u_para
							void (*update)(const char* ,const char*,void* ),//table name ,line ,u_para
							void (*finish)(void*),//u_para
							void* u_para,
							const unsigned char* dec_key,
							void* logger)
{
	redisReply* ctrl_reply=NULL;
	char err_buff[256];
	long long redis_maat_version=0;
	ctrl_reply=(redisReply*)redisCommand(c, "GET MAAT_VERSION");
	if(ctrl_reply==NULL)
	{
		__redis_strerror_r(errno,err_buff,sizeof(err_buff));
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
								"GET MAAT_VERSION failed %s.",err_buff);
		return;
	}
	assert(ctrl_reply->type==REDIS_REPLY_INTEGER);
	assert(ctrl_reply->integer>=version);
	if(ctrl_reply->integer==version)
	{
		freeReplyObject(ctrl_reply);
		return;
	}
	redis_maat_version=ctrl_reply->integer;
	freeReplyObject(ctrl_reply);
	ctrl_reply=(redisReply*)redisCommand(c, "GET MAAT_UPDATE_STATUS");
	if(ctrl_reply==NULL)
	{
		__redis_strerror_r(errno,err_buff,sizeof(err_buff));
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_redis_monitor,
								"GET MAAT_UPDATE_STATUS failed %s.",err_buff);
		return;
	}	
	assert(ctrl_reply->type==REDIS_REPLY_ARRAY);
}

