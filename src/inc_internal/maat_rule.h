/*
**********************************************************************************************
*	File: maat_rule.h
*   Description: maat rule entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_RULE_H_
#define _MAAT_RULE_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/queue.h>
#include <openssl/md5.h>

#include "log/log.h"
#include "hiredis/hiredis.h"
#include "uthash/uthash.h"
#include "maat_table_schema.h"
#include "maat_command.h"

struct maat_runtime {
    /* maat_runtime can be created and destroy dynamic, so need version info */
    long long version;

    time_t last_update_time;

    struct table_runtime_manager *table_rt_mgr;
    size_t max_table_num;
    
    size_t max_thread_num;
    uint32_t rule_num;
};

enum data_source {
    DATA_SOURCE_NONE = 0,
    DATA_SOURCE_REDIS,
    DATA_SOURCE_IRIS_FILE,
    DATA_SOURCE_JSON_FILE
};

struct source_iris_ctx {
    char inc_idx_dir[NAME_MAX];
    char full_idx_dir[NAME_MAX];
};

struct source_json_ctx
{
	char json_file[NAME_MAX];
	char iris_file[NAME_MAX];
	char effective_json_md5[MD5_DIGEST_LENGTH*2+1];
	struct timespec last_md5_time;
};

struct source_redis_ctx
{
	redisContext *read_ctx;
	redisContext *write_ctx;
	char redis_ip[64];
	uint16_t redis_port;
	int redis_db;
	time_t last_reconnect_time;
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
	unsigned long rule_id;
	long long timeout;			// absolute unix time.
	char table_name[NAME_MAX];
	char *table_line;
	int n_foreign;
	struct foreign_key *f_keys;
	TAILQ_ENTRY(serial_rule) entries;
    UT_hash_handle hh;
};

#define	POSSIBLE_REDIS_REPLY_SIZE	2
struct expected_reply {
	int s_rule_seq;
	int possible_reply_num;
	redisReply possible_replies[POSSIBLE_REDIS_REPLY_SIZE];
};

struct maat {
    char instance_name[NAME_MAX];

    struct maat_runtime *maat_rt;
    struct maat_runtime *creating_maat_rt;

    struct table_schema_manager *table_schema_mgr;

    enum data_source input_mode;
    union {
        struct source_iris_ctx iris_ctx;
        struct source_json_ctx json_ctx;
        struct source_redis_ctx mr_ctx;
    };
    
    struct log_handle *logger;
    int deferred_load;

    int is_running;
    pthread_mutex_t background_update_mutex;
    int nr_worker_thread;
    
    long long maat_version;
    long long last_full_version;
    pthread_t cfg_mon_thread;

    int rule_effect_interval_ms;
    int rule_update_checking_interval_ms;
    int gc_timeout_ms; //garbage collection timeout_ms;

    int cumulative_update_off; //Default: cumulative update on

    struct maat_garbage_bin *garbage_bin;

    char compile_tn[NAME_MAX];
    char group_tn[NAME_MAX];
	char group2compile_tn[NAME_MAX];
	char group2group_tn[NAME_MAX];

    char decrypt_key[NAME_MAX];
	char decrypt_algo[NAME_MAX];
    int maat_json_is_gzipped;

    long long load_specific_version;  //Default: Load the Latest. Only valid in redis mode, and maybe failed for too old
    char foreign_cont_dir[NAME_MAX];

    /* statistics */
    long long line_cmd_acc_num;
};

void maat_start_cb(long long new_version, int update_type, void *u_para);

int maat_update_cb(const char *table_name, const char *line, void *u_para);

void maat_finish_cb(void *u_para);

void *rule_monitor_loop(void *arg);

void maat_read_full_config(struct maat *maat_instance);

/* maat command API for internal */
redisContext *maat_cmd_connect_redis(const char *redis_ip, int redis_port, int redis_db, struct log_handle *logger);

redisReply *maat_cmd_wrap_redis_command(redisContext *c, const char *format, ...);

int maat_cmd_wrap_redis_get_reply(redisContext *c, redisReply **reply);

long long maat_cmd_redis_server_time_s(redisContext *c);

long long maat_cmd_read_redis_integer(const redisReply *reply);

int maat_cmd_get_valid_flag_offset(const char *line, enum table_type table_type, int valid_column_seq);

const char *maat_cmd_find_Nth_column(const char *line, int Nth, int *column_len);

int maat_cmd_write_rule(redisContext *c, struct serial_rule *s_rule, size_t serial_rule_num, 
                        long long server_time, struct log_handle *logger);

void maat_cmd_clear_rule_cache(struct serial_rule *s_rule);

int maat_cmd_get_rm_key_list(redisContext *c, long long instance_version, long long desired_version, 
                             long long *new_version, struct table_schema_manager* table_schema_mgr, 
                             struct serial_rule **list, int *update_type, int cumulative_off,
                             struct log_handle *logger);

int maat_cmd_get_redis_value(redisContext *c, struct serial_rule *rule_list, int rule_num, int print_process,
                             struct log_handle *logger);

int maat_cmd_get_foreign_keys_by_prefix(redisContext *ctx, struct serial_rule *rule_list, int rule_num, 
                                        const char *dir, struct log_handle *logger);

void maat_cmd_get_foreign_conts(redisContext *ctx, struct serial_rule *rule_list, int rule_num, int print_fn,
                                struct log_handle *logger);

void maat_cmd_rewrite_table_line_with_foreign(struct serial_rule *s_rule);

void maat_cmd_set_serial_rule(struct serial_rule *rule, enum maat_operation op, unsigned long rule_id, 
                              const char *table_name, const char *line, long long timeout);

#ifdef __cpluscplus
}
#endif

#endif