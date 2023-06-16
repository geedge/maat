/*
**********************************************************************************************
*	File: maat_command.c
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "maat_utils.h"
#include "maat_command.h"
#include "maat_rule.h"
#include "hiredis/hiredis.h"
#include "maat_config_monitor.h"

#define MODULE_MAAT_COMMAND	 module_name_str("maat.command")

extern const char *foreign_source_prefix;
extern const char *foreign_key_prefix;
extern const char *mr_key_prefix;

extern const char *mr_expire_lock;
extern const long mr_expire_lock_time;

extern const char *mr_status_sset;
extern const char *mr_version_sset;
extern const char *mr_label_sset;

extern const int MAAT_REDIS_SYNC_TIME;

redisReply *maat_cmd_wrap_redis_command(redisContext *c, const char *format, ...)
{
	va_list ap;
	void *reply = NULL;
	int ret = REDIS_ERR;
    int retry = 0;

	while (reply == NULL && retry < 2 && ret != REDIS_OK) {
		va_start(ap,format);
		reply = redisvCommand(c,format,ap);
		va_end(ap);
		if (NULL == reply) {
			ret = redisReconnect(c);
			retry++;
		}
	}

	return (redisReply *)reply;
}

redisContext *maat_cmd_connect_redis(const char *redis_ip, int redis_port,
                                     int redis_db, struct log_handle *logger)
{
	struct timeval connect_timeout;
	connect_timeout.tv_sec = 0;
	connect_timeout.tv_usec = 100 * 1000; // 100 ms

	redisContext *c = redisConnectWithTimeout(redis_ip, redis_port, connect_timeout);
	if (NULL == c || c->err) {
        if (NULL == logger) {
            printf("Unable to connect redis server %s:%d db%d, error: %s",
				   redis_ip, redis_port, redis_db, c == NULL ? "Unknown" : c->errstr);
        } else {
            log_error(logger, MODULE_MAAT_COMMAND, 
                      "[%s:%d] Unable to connect redis server %s:%d db%d, error: %s",
				      __FUNCTION__, __LINE__, redis_ip, redis_port, redis_db, 
                      c == NULL ? "Unknown" : c->errstr);
        }
		
		if (c != NULL) {
            redisFree(c);
        }
		return NULL;
	}

	redisEnableKeepAlive(c);
	redisReply *reply = maat_cmd_wrap_redis_command(c, "select %d", redis_db);
	freeReplyObject(reply);
	reply = NULL;

	return c;
}

long long maat_cmd_read_redis_integer(const redisReply *reply)
{
	switch (reply->type) {
		case REDIS_REPLY_INTEGER:
			return reply->integer;
			break;
		case REDIS_REPLY_ARRAY:
			assert(reply->element[0]->type == REDIS_REPLY_INTEGER);
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

int redis_flushDB(redisContext *ctx, int db_index, struct log_handle *logger)
{
	long long maat_redis_version = 0;
	
	redisReply *data_reply = maat_cmd_wrap_redis_command(ctx, "WATCH MAAT_VERSION");
	freeReplyObject(data_reply);
	data_reply = NULL;

	data_reply = maat_cmd_wrap_redis_command(ctx, "GET MAAT_VERSION");
	if (data_reply->type == REDIS_REPLY_NIL) {
		maat_redis_version = 0;
	} else {
		maat_redis_version = maat_cmd_read_redis_integer(data_reply);
		maat_redis_version++;
		freeReplyObject(data_reply);
		data_reply = NULL;
	}

	data_reply = maat_cmd_wrap_redis_command(ctx, "DBSIZE");
	long long dbsize = maat_cmd_read_redis_integer(data_reply);
	freeReplyObject(data_reply);
	data_reply = NULL;

	data_reply = maat_cmd_wrap_redis_command(ctx, "MULTI");
	freeReplyObject(data_reply);
	data_reply = NULL;
	
    int append_cmd_cnt = 0;
	redisAppendCommand(ctx, "FLUSHDB");
	append_cmd_cnt++;
	redisAppendCommand(ctx, "SET MAAT_VERSION %lld", maat_redis_version);
	append_cmd_cnt++;
	redisAppendCommand(ctx, "SET MAAT_PRE_VER %lld", maat_redis_version);
	append_cmd_cnt++;
	redisAppendCommand(ctx, "SET %s 1", mr_region_id_var);
	append_cmd_cnt++;
	redisAppendCommand(ctx, "SET %s 1", mr_group_id_var);
	append_cmd_cnt++;
	redisAppendCommand(ctx, "EXEC");
	append_cmd_cnt++;

    int ret = 0;
    int redis_transaction_success = 1;
	for (int i = 0; i < append_cmd_cnt; i++) {
		ret = maat_cmd_wrap_redis_get_reply(ctx, &data_reply);
		if (ret == REDIS_OK) {
			if (data_reply->type == REDIS_REPLY_NIL) {
				redis_transaction_success = 0;
			}
			freeReplyObject(data_reply);
			data_reply = NULL;
		}
	}

	if (redis_transaction_success == 1) {
		log_info(logger, MODULE_MAAT_COMMAND,
				 "FlushDB %d, MAAT_VERSION:%llu, DBSize:%llu.",
                 db_index, (maat_redis_version == 0)?0:(maat_redis_version-1),dbsize);
	}

	return redis_transaction_success;
}

static int connect_redis_for_write(struct source_redis_ctx *redis_ctx,
                                   struct log_handle *logger)
{
	assert(redis_ctx->write_ctx == NULL);
	redis_ctx->write_ctx = maat_cmd_connect_redis(redis_ctx->redis_ip, 
                                                  redis_ctx->redis_port,
                                                  redis_ctx->redis_db, logger);
	if (NULL == redis_ctx->write_ctx) {
		return -1;
	} else {
		return 0;
	}
}

redisContext *get_redis_ctx_for_write(struct maat *maat_inst)
{
	if (NULL == maat_inst->opts.redis_ctx.write_ctx) {
		int ret = connect_redis_for_write(&(maat_inst->opts.redis_ctx),
                                          maat_inst->logger);
		if (ret != 0) {
			return NULL;
		}
	}
	return maat_inst->opts.redis_ctx.write_ctx;
}

int maat_cmd_flushDB(struct maat *maat_inst)
{
	int ret = 0;

	redisContext *write_ctx = get_redis_ctx_for_write(maat_inst);
	if (NULL == write_ctx) {
		return -1;
	}

	do {
		ret = redis_flushDB(maat_inst->opts.redis_ctx.write_ctx,
                             maat_inst->opts.redis_ctx.redis_db,
                             maat_inst->logger);
	} while(0 == ret);
	
    return 0;
}

void maat_cmd_clear_rule_cache(struct serial_rule *s_rule)
{
	if (s_rule->table_line != NULL) {
		FREE(s_rule->table_line);
	}

	if (s_rule->n_foreign > 0) {
		for (int i = 0; i < s_rule->n_foreign; i++) {
			FREE(s_rule->f_keys[i].filename);
			FREE(s_rule->f_keys[i].key);
		}

		FREE(s_rule->f_keys);
	}

	memset(s_rule, 0, sizeof(struct serial_rule));
}

void maat_cmd_set_serial_rule(struct serial_rule *rule, enum maat_operation op,
                              long long rule_id, const char *table_name,
                              const char *line, long long timeout)
{
	memset(rule, 0, sizeof(struct serial_rule));
    rule->op = op;
	rule->rule_id = rule_id;
	rule->timeout = timeout;
	assert(strlen(table_name) < sizeof(rule->table_name));
	strncpy(rule->table_name, table_name, sizeof(rule->table_name));
	if (line != NULL) {
		rule->table_line = maat_strdup(line);
	}
}

int maat_cmd_get_valid_flag_offset(const char *line, int column_seq)
{	
    size_t offset = 0;
    size_t len = 0;

	int ret = get_column_pos(line, column_seq, &offset, &len);
    // 0 is also a valid value for some non-MAAT producer.
	if (ret < 0 || offset >= strlen(line) || (line[offset] != '1' && 
        line[offset] != '0')) {
		return -1;
	}

	return offset;
}

long long maat_cmd_redis_server_time_s(redisContext *c)
{
	long long server_time = 0;

	redisReply *data_reply = maat_cmd_wrap_redis_command(c, "TIME"); 
	if (data_reply->type == REDIS_REPLY_ARRAY) {
		server_time = atoll(data_reply->element[0]->str);
		freeReplyObject(data_reply);
		data_reply = NULL;
	}

	return server_time;
}

const char *maat_cmd_find_Nth_column(const char *line, int Nth, int *column_len)
{
    size_t i = 0;
	int j = 0;
	size_t start=0, end=0;
	size_t line_len = strlen(line);

	for (i = 0; i < line_len; i++) {
		if (line[i] != ' ' && line[i] != '\t') {
			continue;
		}

		j++;
		if (j == Nth - 1) {
			start = i + 1;
		}

		if(j == Nth) {
			end = i;
			break;
		}
	}

	if (start == end) {
		return NULL;
	}

	if (end == 0) {
		end = i;
	}

	*column_len = end - start;

	return line + start;
}

int maat_cmd_wrap_redis_get_reply(redisContext *c, redisReply **reply)
{
	return redisGetReply(c, (void **)reply);
}

int maat_cmd_set_line(struct maat *maat_inst, const struct maat_cmd_line *line_rule)
{
    int i = 0;
	int ret = 0;
	long long absolute_expire_time = 0;

	redisContext *write_ctx = get_redis_ctx_for_write(maat_inst);
	if (NULL == write_ctx) {
		return -1;
	}

	long long server_time = maat_cmd_redis_server_time_s(write_ctx);
	if(!server_time) {
		return -1;
	}

	struct serial_rule *s_rule = ALLOC(struct serial_rule, 1);

    int table_id = table_manager_get_table_id(maat_inst->tbl_mgr, line_rule->table_name);
    if (table_id < 0) {
        log_error(maat_inst->logger, MODULE_MAAT_COMMAND, 
                  "[%s:%d] Command set line id %lld failed: unknown table %s", 
                  __FUNCTION__, __LINE__, line_rule->rule_id, line_rule->table_name);
        FREE(s_rule);
        return -1;
    }

    int valid_column = table_manager_get_valid_column(maat_inst->tbl_mgr, table_id);
    if (valid_column < 0) {
        log_error(maat_inst->logger, MODULE_MAAT_COMMAND,
                  "[%s:%d] Command set line id %lld failed: table %s is not a plugin or ip_plugin table",
                  __FUNCTION__, __LINE__, line_rule->rule_id, line_rule->table_name);
        FREE(s_rule);
        return -1;
    }
   
    int valid_offset = maat_cmd_get_valid_flag_offset(line_rule->table_line, valid_column);
    if (valid_offset < 0) {
        log_error(maat_inst->logger, MODULE_MAAT_COMMAND,
                  "[%s:%d] Command set line id %lld failed: table %s valid_offset error",
                  __FUNCTION__, __LINE__, line_rule->rule_id, line_rule->table_name);
        FREE(s_rule);
        return -1;
    }

    int is_valid = atoi(line_rule->table_line + valid_offset);
    if (line_rule->expire_after > 0) {
        absolute_expire_time = server_time + line_rule->expire_after;
    }

    maat_cmd_set_serial_rule(s_rule + i, (enum maat_operation)is_valid, line_rule->rule_id,
                             line_rule->table_name, line_rule->table_line, absolute_expire_time);

    int success_cnt = maat_cmd_write_rule(write_ctx, s_rule, 1, server_time, maat_inst->logger);
	if (success_cnt != 1) {
		ret = -1;
		goto error_out;
	}

	ret = success_cnt;
	maat_inst->stat->line_cmd_acc_num += success_cnt;

error_out:
	maat_cmd_clear_rule_cache(s_rule);
	FREE(s_rule);

	return ret;
}

int maat_cmd_set_file(struct maat *maat_inst, const char *key, const char *value, 
                      size_t size, enum maat_operation op)
{
	redisContext *ctx = maat_inst->opts.redis_ctx.write_ctx;
	if (NULL == ctx) {
		log_error(maat_inst->logger, MODULE_MAAT_COMMAND, 
                  "[%s:%d] failed: Redis is not connected.", 
                  __FUNCTION__, __LINE__);
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

	redisReply *reply = NULL;
	if (0 != strncmp(key, foreign_key_prefix, strlen(foreign_key_prefix))) {
		log_error(maat_inst->logger, MODULE_MAAT_COMMAND, 
                 "Invalid File key, prefix %s is mandatory.", foreign_key_prefix);
		return -1;
	}

	switch (op) {
		case MAAT_OP_ADD:
			reply = (redisReply *)redisCommandArgv(ctx, sizeof(arg_vec) / sizeof(arg_vec[0]),
                                                   arg_vec, len_vec);
			break;
		case MAAT_OP_DEL:	
			reply = maat_cmd_wrap_redis_command(ctx, "EXPIRE %s %d", key, MAAT_REDIS_SYNC_TIME);
			break;
		default:
			return -1;
			break;
	}

	if (NULL == reply || reply->type == REDIS_REPLY_NIL || reply->type == REDIS_REPLY_ERROR) {
		log_error(maat_inst->logger, MODULE_MAAT_COMMAND, 
                  "Set file failed, maybe Redis is busy.");
		freeReplyObject(reply);
		reply = NULL;
		return -1;		
	}

	freeReplyObject(reply);
	reply = NULL;
	return 1;
}

long long maat_cmd_incrby(struct maat *maat_inst, const char *key, int increment)
{
	long long result = 0;

	redisContext *write_ctx = get_redis_ctx_for_write(maat_inst);
	if (NULL == write_ctx) {
		return -1;
	}

	redisReply *data_reply = maat_cmd_wrap_redis_command(write_ctx, "INCRBY %s %d", key, increment); 
	if (data_reply->type == REDIS_REPLY_INTEGER) {
		result = data_reply->integer;
	} else {
		result = -1;
	}

	freeReplyObject(data_reply);
	data_reply = NULL;
    
	return result;		
}

long long maat_cmd_get_config_version(struct maat *maat_inst)
{
    long long new_version = -1;

    if (maat_inst->new_version != INVALID_VERSION) {
        new_version = maat_inst->new_version;
    } else {
        new_version = maat_inst->maat_version;
    }

    return new_version;
}

int maat_cmd_config_is_updating(struct maat *maat_inst)
{
    int ret = 0;

    if (0 == pthread_mutex_trylock(&(maat_inst->background_update_mutex))) {
        ret = 0;
        pthread_mutex_unlock(&(maat_inst->background_update_mutex));
    } else {
        ret = 1;
    }

    return ret;
}

char *maat_cmd_str_escape(char *dst, int size, const char *src)
{
    int i = 0, j = 0;
	int len = strlen(src);

	for (i = 0, j = 0; i < len && j < size; i++) {
		switch (src[i]) {
			case '&':
				dst[j] = '\\';
				dst[j+1] = '&';
				j += 2;
				break;
			case ' ':
				dst[j] = '\\';
				dst[j+1] = 'b';//space,0x20;
				j += 2;
				break;
			case '\\':
				dst[j] = '\\';
				dst[j+1] = '\\';
				j += 2;
				break;
			default:
				dst[j] = src[i];
				j++;	//undo the followed i++
				break;
		}
	}
	dst[j] = '\0';

	return dst;
}
