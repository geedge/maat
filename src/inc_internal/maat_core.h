/*
**********************************************************************************************
*	File: maat_core.h
*   Description: maat rule entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_CORE_H_
#define _MAAT_CORE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stddef.h>
#include <linux/limits.h>
#include <sys/time.h>
#include <pthread.h>
#include <dirent.h>
#include <openssl/md5.h>

#include "log/log.h"
#include "fieldstat/fieldstat_easy.h"
#include "maat_command.h"
#include "maat_limits.h"
#include "maat.h"
#include "maat_kv.h"
#include "maat_table.h"
#include "maat_attribute.h"
#include "maat_stat.h"
#include "hiredis/hiredis.h"

#define MAX_TABLE_NUM	1024

#define	DISTRICT_ANY	   -1
#define	DISTRICT_UNKNOWN   -2

#define MAX_DISTRICT_STR_LEN   128
#define INVALID_VERSION    -1

#define mr_region_id_var "SEQUENCE_REGION"
#define mr_object_id_var	 "SEQUENCE_OBJECT"

enum tag_match {
    TAG_MATCH_ERR = -1,
    TAG_MATCH_UNMATCHED,
    TAG_MATCH_MATCHED
};

struct maat_item {
	long long item_id;
	long long object_id;
};

struct maat_runtime {
    /* maat_runtime can be created and destroy dynamic, so need version info */
    long long version;
    time_t last_update_time;

    long long *ref_cnt;
    struct table_manager *ref_tbl_mgr; //share with maat instance
    size_t max_table_num;
    
    long long rule_num;
    struct maat_kv_store *sequence_map;

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

struct rule_tag {
	char *tag_name;
	char *tag_val;
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

struct source_json_ctx {
	char json_file[NAME_MAX];
	char iris_file[NAME_MAX];
	char effective_json_md5[MD5_DIGEST_LENGTH*2+1];
	struct timespec last_md5_time;
};

struct source_redis_ctx {
	redisContext *read_ctx;
	redisContext *write_ctx;
	char redis_ip[64];
	uint16_t redis_port;
	int redis_db;
	time_t last_reconnect_time;
};

struct maat_options {
    char inst_name[MAX_INSTANCE_NAME_LEN + 1];
    char foreign_cont_dir[NAME_MAX];
    char decrypt_algo[MAX_KEYWORDS_STR_LEN];
    char decrypt_key[MAX_KEYWORDS_STR_LEN];
    char log_path[PATH_MAX];
    int log_level;
    size_t log_file_max_size_mb;
    char stat_file[NAME_MAX];
    size_t nr_worker_thread;
    char *accept_tags;

    int stat_on;
    int perf_on;
    int hit_path_on;
    int hit_object_on;
    int deferred_load_on;

    int maat_json_is_gzipped;
    
    int gc_timeout_ms;
    int rule_update_checking_interval_ms;

    enum maat_expr_engine expr_engine;
    enum data_source input_mode;
    union {
        struct source_iris_ctx iris_ctx;
        struct source_json_ctx json_ctx;
        struct source_redis_ctx redis_ctx;
    };
};

struct maat_stat {
    char stat_file[PATH_MAX];
    struct fieldstat_easy *fs_handle;
    int g_metric_id[MAX_MAAT_STAT_NUM];
	int fs_column_id[MAX_MAAT_STAT_NUM];
    char tag_value[MAX_TABLE_NUM][MAX_NAME_STR_LEN];
    char sum_tag[MAX_NAME_STR_LEN];
    struct log_handle *logger;
    struct table_manager *ref_tbl_mgr;
    struct maat_garbage_bin *ref_garbage_bin;
    size_t nr_worker_thread;
    int cmd_q_cnt;
    
    long long *thread_call_cnt;
    long long *stream_cnt;
    long long *hit_rule_cnt;
    long long *maat_state_cnt;
    long long *rule_state_cnt;
    long long *maat_state_free_cnt;
    long long *maat_state_free_bytes;

    long long scan_err_cnt;
    long long zombie_rs_stream;
    long long line_cmd_acc_num;
};

struct maat {
    struct maat_runtime *maat_rt;
    struct maat_runtime *creating_maat_rt;
    struct table_manager *tbl_mgr;
    struct maat_options opts;

    long long maat_version;
    long long last_full_version;
    /* internal state */
    long long new_version;

    int is_running;
    int thread_counter;
    pthread_t cfg_mon_thread;
    pthread_mutex_t background_update_mutex;

    struct log_handle *logger;
    struct maat_garbage_bin *garbage_bin;

    /* statistics */
    struct maat_stat *stat;
};

struct maat_state {
	struct maat *maat_inst;
    struct rule_compile_state *rule_compile_state;
    int Nth_scan;
    int district_id; //-1: Any District; -2: Unkonwn District;
	uint16_t thread_id;
    int16_t rule_table_id;
	uint8_t district_flag;
    uint8_t logic_negate_option;
};

int my_scandir(const char *dir, struct dirent ***namelist,
              int(*filter)(const struct dirent *),
              int(*compar)(const void *, const void *));

void *rule_monitor_loop(void *arg);

long long maat_runtime_get_sequence(struct maat_runtime *maat_rt, const char *key);

void maat_read_full_config(struct maat *maat_instance);

void garbage_ip_matcher_free(void *ip_matcher, void *arg);

void garbage_interval_matcher_free(void *ip_matcher, void *arg);

void garbage_bool_matcher_free(void *bool_matcher, void *arg);

void garbage_maat_kv_store_free(void *kv_store, void *arg);

#ifdef __cplusplus
}
#endif

#endif
