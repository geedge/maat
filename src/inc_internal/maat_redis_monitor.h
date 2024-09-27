/*
**********************************************************************************************
*	File: maat_redis_monitor.h
*   Description: maat redis monitor api
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-11-29
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_REDIS_MONITOR_H_
#define _MAAT_REDIS_MONITOR_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <sys/queue.h>

#include "log/log.h"
#include "hiredis/hiredis.h"
#include "maat_command.h"
#include "maat_limits.h"
#include "uthash/uthash.h"

struct foreign_key {
	char *key;
    size_t key_len;
	char *filename;
};

//rm= Redis Maat
struct serial_rule {
	enum maat_operation op;//0: delete, 1: add.
	char rule_uuid_str[UUID_STR_LEN];
	long long timeout;			// absolute unix time.
	char table_name[MAX_NAME_STR_LEN];
	char *table_line;
	int n_foreign;
	struct foreign_key *f_keys;
    redisContext *ref_ctx;
	TAILQ_ENTRY(serial_rule) entries;
    UT_hash_handle hh;
};

void maat_clear_rule_cache(struct serial_rule *s_rule);

void maat_set_serial_rule(struct serial_rule *rule, enum maat_operation op,
                          const char *rule_uuid_str, const char *table_name,
                          const char *line, long long timeout);

redisContext *maat_connect_redis(const char *redis_ip, int redis_port,
                                 int redis_db, struct log_handle *logger);

redisReply *maat_wrap_redis_command(redisContext *c, struct log_handle *logger,
                                    const char *format, ...);

int maat_wrap_redis_get_reply(redisContext *c, redisReply **reply);

long long maat_redis_server_time_s(redisContext *c);

long long maat_read_redis_integer(const redisReply *reply);

int maat_get_valid_flag_offset(const char *line, int column_seq);

int maat_cmd_write_rule(redisContext *c, struct serial_rule *s_rule, 
                        size_t serial_rule_num, long long server_time, 
                        struct log_handle *logger);

int maat_get_redis_value(redisContext *c, struct serial_rule *rule_list, 
                         int rule_num, int print_process, struct log_handle *logger);

int maat_get_foreign_keys_by_prefix(redisContext *ctx, struct serial_rule *rule_list, 
                                    int rule_num, const char *dir, struct log_handle *logger);

void maat_get_foreign_conts(redisContext *c, struct serial_rule *rule_list, 
                            int rule_num, int print_fn, struct log_handle *logger);

void maat_rewrite_table_line_with_foreign(struct serial_rule *s_rule);

int maat_get_rm_key_list(redisContext *c, long long instance_version, 
                         long long *new_version, struct table_manager *tbl_mgr,
                         struct serial_rule **list, int *update_type,
                         struct log_handle *logger);

void redis_monitor_traverse(long long version, struct source_redis_ctx *mr_ctx,
							void (*start_fn)(long long, int, void *),
							int (*update_fn)(const char *, const char *, void *, enum maat_operation),
							void (*finish_fn)(void *), void *u_param);

#ifdef __cplusplus
}
#endif

#endif