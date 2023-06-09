/*
**********************************************************************************************
*	File: maat_command.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_COMMAND_H_
#define _MAAT_COMMAND_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <limits.h>
#include <sys/queue.h>

#include "maat.h"
#include "maat_table.h"
#include "log/log.h"
#include "uthash/uthash.h"
#include "hiredis/hiredis.h"
#include "maat_limits.h"

enum maat_operation {
	MAAT_OP_DEL = 0,
	MAAT_OP_ADD,
	MAAT_OP_RENEW_TIMEOUT	//Rule expire time is changed to now+cmd->expire_after
};

struct maat_cmd_line {
	const char *table_name;
	const char *table_line;
	long long rule_id;		// for MAAT_OP_DEL, only rule_id and table_name are necessary.
	int expire_after;	//expired after $timeout$ seconds, set to 0 for never timeout.
};

struct foreign_key {
	int column;
	char *key;
    size_t key_len;
	char *filename;
};

//rm= Redis Maat
struct serial_rule {
	enum maat_operation op;//0: delete, 1: add.
	long long rule_id;
	long long timeout;			// absolute unix time.
	char table_name[MAX_NAME_STR_LEN];
	char *table_line;
	int n_foreign;
	struct foreign_key *f_keys;
    redisContext *ref_ctx;
	TAILQ_ENTRY(serial_rule) entries;
    UT_hash_handle hh;
};

/**
 * @brief write one line to redis
 * 
 * @retval 
 *      success: number of successfully updated rule.
 *      failed: -1
*/
int maat_cmd_set_line(struct maat *maat_instance, const struct maat_cmd_line *line_rule);

int maat_cmd_set_file(struct maat *maat_instance, const char *key, const char *value, 
                      size_t size, enum maat_operation op);
                      
long long maat_cmd_incrby(struct maat *maat_instance, const char *key, int increment);

long long maat_cmd_get_config_version(struct maat *maat_instance);

/* True(1), False(0) */
int maat_cmd_config_is_updating(struct maat *maat_instance);

char *maat_cmd_str_escape(char *dst, int size, const char *src);

int maat_cmd_flushDB(struct maat *maat_instance);

/* maat command API for internal */
redisContext *maat_cmd_connect_redis(const char *redis_ip, int redis_port,
                                     int redis_db, struct log_handle *logger);

redisReply *maat_cmd_wrap_redis_command(redisContext *c, const char *format, ...);

int maat_cmd_wrap_redis_get_reply(redisContext *c, redisReply **reply);

long long maat_cmd_redis_server_time_s(redisContext *c);

long long maat_cmd_read_redis_integer(const redisReply *reply);

int maat_cmd_get_valid_flag_offset(const char *line, int column_seq);

const char *maat_cmd_find_Nth_column(const char *line, int Nth, int *column_len);

int maat_cmd_write_rule(redisContext *c, struct serial_rule *s_rule, 
                        size_t serial_rule_num, long long server_time, 
                        struct log_handle *logger);

void maat_cmd_clear_rule_cache(struct serial_rule *s_rule);

int maat_cmd_get_redis_value(redisContext *c, struct serial_rule *rule_list, 
                             int rule_num, int print_process, struct log_handle *logger);

int maat_cmd_get_foreign_keys_by_prefix(redisContext *ctx, struct serial_rule *rule_list, 
                                        int rule_num, const char* dir, struct log_handle *logger);

void maat_cmd_get_foreign_conts(redisContext *c, struct serial_rule *rule_list, 
                                int rule_num, int print_fn, struct log_handle *logger);

void maat_cmd_rewrite_table_line_with_foreign(struct serial_rule *s_rule);

void maat_cmd_set_serial_rule(struct serial_rule *rule, enum maat_operation op,
                              long long rule_id, const char *table_name,
                              const char *line, long long timeout);
            
int maat_cmd_get_rm_key_list(redisContext *c, long long instance_version, 
                             long long desired_version, long long *new_version, 
                             struct table_manager *tbl_mgr, struct serial_rule **list, 
                             int *update_type, int cumulative_off, struct log_handle *logger);

#ifdef __cplusplus
}
#endif

#endif