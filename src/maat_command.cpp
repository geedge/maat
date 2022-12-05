/*
**********************************************************************************************
*	File: maat_command.cpp
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "utils.h"
#include "maat_utils.h"
#include "maat_command.h"
#include "maat_rule.h"
#include "hiredis/hiredis.h"
#include "maat_config_monitor.h"
#include "maat_table_schema.h"

extern const char *foreign_source_prefix;
extern const char *mr_key_prefix;

extern const char *mr_expire_lock;
extern const long mr_expire_lock_time;

extern const char *mr_status_sset;
extern const char *mr_version_sset;
extern const char *mr_label_sset;

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

redisContext *maat_cmd_connect_redis(const char *redis_ip, int redis_port, int redis_db)
{
	struct timeval connect_timeout;
	connect_timeout.tv_sec = 0;
	connect_timeout.tv_usec = 100 * 1000; // 100 ms

	redisContext *c = redisConnectWithTimeout(redis_ip, redis_port, connect_timeout);
	if (NULL == c || c->err) {
		fprintf(stderr, "Unable to connect redis server %s:%d db%d, error: %s\n",
						redis_ip, redis_port, redis_db, c == NULL ? "Unknown" : c->errstr);
		
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

struct s_rule_array
{
	int cnt;
	int size;
	struct serial_rule *array;
};

void save_serial_rule(void *data, void *user)
{
	struct s_rule_array *array = (struct s_rule_array *)user;
	int i = array->cnt;
	memcpy(&(array->array[i]), data, sizeof(struct serial_rule));
	array->array[i].op = MAAT_OP_ADD;
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

int connect_redis_for_write(struct source_redis_ctx *mr_ctx)
{
	assert(mr_ctx->write_ctx == NULL);
	mr_ctx->write_ctx = maat_cmd_connect_redis(mr_ctx->redis_ip, mr_ctx->redis_port, mr_ctx->redis_db);
	if (NULL == mr_ctx->write_ctx) {
		return -1;
	} else {
		return 0;
	}
}

redisContext *get_redis_ctx_for_write(struct maat *maat_instance)
{
	if (NULL == maat_instance->mr_ctx.write_ctx) {
		int ret = connect_redis_for_write(&(maat_instance->mr_ctx));
		if(ret!=0)
		{
			return NULL;
		}
	}
	return maat_instance->mr_ctx.write_ctx;
}

void maat_cmd_set_serial_rule(struct serial_rule *rule, enum maat_operation op, unsigned long rule_id, 
                              const char *table_name, const char *line, long long timeout)
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

int maat_cmd_get_valid_flag_offset(const char *line, enum table_type table_type, int valid_column_seq)
{
	int column_seq = 0;

 	switch (table_type) {
		case TABLE_TYPE_EXPR:
			column_seq = 7;
			break;
		case TABLE_TYPE_IP:
			column_seq = 14;
			break;
		case TABLE_TYPE_IP_PLUS:
			column_seq = 18;
			break;
		case TABLE_TYPE_COMPILE:
			column_seq = 8;
			break;
		case TABLE_TYPE_PLUGIN:
		case TABLE_TYPE_IP_PLUGIN:
		case TABLE_TYPE_FQDN_PLUGIN:
		case TABLE_TYPE_BOOL_PLUGIN:
			if (valid_column_seq < 0) {
				return -1;
			}

			column_seq = valid_column_seq;
			break;
		case TABLE_TYPE_INTERVAL:
			column_seq = 5;
			break;
		case TABLE_TYPE_INTERVAL_PLUS:
			column_seq = 6;
			break;
		case TABLE_TYPE_DIGEST:
			column_seq = 6;
			break;
		case TABLE_TYPE_SIMILARITY:
			column_seq = 5;
			break;
		case TABLE_TYPE_EXPR_PLUS:
			column_seq = 8;
			break;
		case TABLE_TYPE_GROUP2COMPILE:
		case TABLE_TYPE_GROUP2GROUP:
			column_seq = 3;
			break;
		default:
			assert(0);
	}
	
    size_t offset = 0;
    size_t len = 0;
	int ret = get_column_pos(line, column_seq, &offset, &len);
    // 0 is also a valid value for some non-MAAT producer.
	if (ret < 0 || offset >= strlen(line) || (line[offset] != '1' && line[offset] != '0')) {
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

int maat_cmd_wrap_redis_get_reply(redisContext *c, redisReply **reply)
{
	return redisGetReply(c, (void **)reply);
}

int maat_cmd_set_line(struct maat *maat_instance, const struct maat_cmd_line *line_rule)
{
    int i = 0;
	int ret = 0;
	long long absolute_expire_time = 0;

	redisContext *write_ctx = get_redis_ctx_for_write(maat_instance);
	if (NULL == write_ctx) {
		return -1;
	}

	long long server_time = maat_cmd_redis_server_time_s(write_ctx);
	if(!server_time) {
		return -1;
	}

	struct serial_rule *s_rule = ALLOC(struct serial_rule, 1);

    int table_id = table_schema_manager_get_table_id(maat_instance->table_schema_mgr, line_rule->table_name);
    if (table_id < 0) {
        fprintf(stderr, "Command set line id %d failed: unknown table %s\n", line_rule->rule_id, line_rule->table_name);
        FREE(s_rule);
        return -1;
    }

    struct table_schema *table_schema = table_schema_get(maat_instance->table_schema_mgr, table_id);
    if (!table_schema) {
        FREE(s_rule);
        return -1;
    }

    int valid_flag_column = table_schema_get_valid_flag_column(table_schema);
    if (valid_flag_column < 0) {
        fprintf(stderr, "Command set line id %d failed: table %s is not a plugin or ip_plugin table\n",
                        line_rule->rule_id, line_rule->table_name);
        FREE(s_rule);
        return -1;
    }

    enum table_type table_type = table_schema_get_table_type(table_schema);
    int is_valid = maat_cmd_get_valid_flag_offset(line_rule->table_line, table_type, valid_flag_column);

    if (line_rule->expire_after > 0) {
        absolute_expire_time = server_time + line_rule->expire_after;
    }

    maat_cmd_set_serial_rule(s_rule + i, (enum maat_operation)is_valid, line_rule->rule_id, line_rule->table_name,
                             line_rule->table_line, absolute_expire_time);

    int success_cnt = maat_cmd_write_rule(write_ctx, s_rule, 1, server_time);
	if (success_cnt != 1) {
		ret = -1;
		goto error_out;
	}

	ret = success_cnt;
	maat_instance->line_cmd_acc_num += success_cnt;

error_out:
	maat_cmd_clear_rule_cache(s_rule);
	FREE(s_rule);

	return ret;
}