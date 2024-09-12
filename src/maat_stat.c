/*
**********************************************************************************************
*	File: maat_stat.c
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>
#include <math.h>

#include "maat_utils.h"
#include "maat_stat.h"
#include "fieldstat/fieldstat_easy.h"
#include "alignment.h"
#include "maat_ip.h"
#include "maat_rule.h"
#include "maat_object.h"
#include "maat_plugin.h"
#include "maat_expr.h"

#define MODULE_MAAT_STAT	 module_name_str("maat.stat")

enum MAAT_FS_STATUS {
	STATUS_VERSION = 0,
	STATUS_THREAD_NUM,
	STATUS_TABLE_NUM,
	STATUS_PLUGIN_CACHE_NUM,
	STATUS_PLUGIN_ACC_NUM,
    STATUS_CONDITION_REF_NOT_NUM,
    STATUS_OBJECT_REF_EXCL_NUM, //object reference exclude object num
    STATUS_HIT_RULE_NUM,
	STATUS_MAAT_STATE_NUM,
    STATUS_MAAT_PER_STATE_MEM,
    STATUS_RULE_STATE_NUM,
	STATUS_GARBAGE_QUEUE_LEN,
	STATUS_UPDATE_ERR_CNT,
	STATUS_SCAN_ERR_CNT,
	STATUS_STREAM_NUM,
    STATUS_ZOMBIE_STREAM_NUM,
	STATUS_CMD_LINE_NUM
};

enum MAAT_FS_COLUMN {
	COLUMN_RULE_NUM = 0,
	COLUMN_REGEX_NUM,
	COLUMN_SCAN_TIMES,    //the times of scan
    COLUMN_HIT_TIMES,     //the times of hit item
	COLUMN_SCAN_BYTES,
	COLUMN_SCAN_CPU_TIME, //microseconds
	COLUMN_HIT_ITEM_NUM,
	COLUMN_HIT_PAT_NUM    //the number of hit pattern(only valid for expr/expr_plus table)
};

const char *column_name[] = {
    "rule", "reg/v6", "scan_times", "hit_times",
    "scan_bytes", "scan_cpu_time(ns)", "hit_item_num", "hit_pat_num"};

static void fs_global_metric_register(struct maat_stat *stat)
{
    stat->g_metric_id[STATUS_VERSION] =
        fieldstat_easy_register_counter(stat->fs_handle, "version");

    stat->g_metric_id[STATUS_THREAD_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "thread_num");

    stat->g_metric_id[STATUS_TABLE_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "table_num");

    stat->g_metric_id[STATUS_PLUGIN_CACHE_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "plug_cached_num");

    stat->g_metric_id[STATUS_PLUGIN_ACC_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "plug_acc_num");

    stat->g_metric_id[STATUS_CONDITION_REF_NOT_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "NOT_condition_num");

    stat->g_metric_id[STATUS_OBJECT_REF_EXCL_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "excl_grp");

    stat->g_metric_id[STATUS_GARBAGE_QUEUE_LEN] =
        fieldstat_easy_register_counter(stat->fs_handle, "garbage_queue_len");

    stat->g_metric_id[STATUS_HIT_RULE_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "hit_rule_num");

    stat->g_metric_id[STATUS_MAAT_STATE_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "state_num");

    stat->g_metric_id[STATUS_MAAT_PER_STATE_MEM] =
        fieldstat_easy_register_counter(stat->fs_handle, "per_state_mem(B)");

    stat->g_metric_id[STATUS_RULE_STATE_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "rule_state_num");

    stat->g_metric_id[STATUS_STREAM_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "stream_num");

    stat->g_metric_id[STATUS_ZOMBIE_STREAM_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "z_stream_num");

    stat->g_metric_id[STATUS_UPDATE_ERR_CNT] =
        fieldstat_easy_register_counter(stat->fs_handle, "update_error");

    stat->g_metric_id[STATUS_SCAN_ERR_CNT] =
        fieldstat_easy_register_counter(stat->fs_handle, "scan_error");

    stat->g_metric_id[STATUS_CMD_LINE_NUM] =
        fieldstat_easy_register_counter(stat->fs_handle, "line_cmd/s");
}

static void fs_table_column_register(struct maat_stat *stat)
{
    size_t column_num = sizeof(column_name) / sizeof(column_name[0]);

    assert(column_num <= MAX_MAAT_STAT_NUM);

    for (size_t i = 0; i < column_num; i++) {
        stat->fs_column_id[i] =
            fieldstat_easy_register_counter(stat->fs_handle, column_name[i]);
    }
}

static void fs_table_row_register(struct maat_stat *stat)
{
    //In fieldstat4, row is the tag
    size_t max_table_cnt = table_manager_table_size(stat->ref_tbl_mgr);
    memcpy(stat->sum_tag, "Sum", strlen("Sum"));

    for (size_t i = 0; i < max_table_cnt; i++) {
        const char *table_name =
            table_manager_get_table_name(stat->ref_tbl_mgr, i);
        if (NULL == table_name) {
            continue;
        }
        memcpy(stat->tag_value[i], table_name,
               MIN(strlen(table_name), sizeof(stat->tag_value[i])));
    }
}

struct maat_stat *maat_stat_new(const char *stat_file, size_t max_thread_num,
                                struct log_handle *logger)
{
    struct maat_stat *stat = ALLOC(struct maat_stat, 1);

    size_t str_len = MIN(sizeof(stat->stat_file), strlen(stat_file));
    memcpy(stat->stat_file, stat_file, str_len);

    stat->nr_worker_thread = max_thread_num;
    stat->logger = logger;
    stat->stream_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->thread_call_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->hit_rule_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->maat_state_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->rule_state_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->maat_state_free_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->maat_state_free_bytes = alignment_int64_array_alloc(max_thread_num);

    return stat;
}

void maat_stat_free(struct maat_stat *stat)
{
    if (NULL == stat) {
        return;
    }

    if (stat->stream_cnt != NULL) {
        alignment_int64_array_free(stat->stream_cnt);
        stat->stream_cnt = NULL;
    }

    if (stat->thread_call_cnt != NULL) {
        alignment_int64_array_free(stat->thread_call_cnt);
        stat->thread_call_cnt = NULL;
    }

    if (stat->hit_rule_cnt != NULL) {
        alignment_int64_array_free(stat->hit_rule_cnt);
        stat->hit_rule_cnt = NULL;
    }

    if (stat->maat_state_cnt != NULL) {
        alignment_int64_array_free(stat->maat_state_cnt);
        stat->maat_state_cnt = NULL;
    }

    if (stat->rule_state_cnt != NULL) {
        alignment_int64_array_free(stat->rule_state_cnt);
        stat->rule_state_cnt = NULL;
    }

    if (stat->maat_state_free_cnt != NULL) {
        alignment_int64_array_free(stat->maat_state_free_cnt);
        stat->maat_state_free_cnt = NULL;
    }

    if (stat->maat_state_free_bytes != NULL) {
        alignment_int64_array_free(stat->maat_state_free_bytes);
        stat->maat_state_free_bytes = NULL;
    }

    if (stat->fs_handle != NULL) {
        fieldstat_easy_free(stat->fs_handle);
        stat->fs_handle = NULL;
    }

    FREE(stat);
}

int maat_stat_init(struct maat_stat *stat, const char *stat_name, struct table_manager *tbl_mgr,
                   struct maat_garbage_bin *garbage_bin)
{
    if (NULL == stat || NULL == tbl_mgr) {
        return -1;
    }

    const char *instance_name = stat_name == NULL ? "maat_stat" : stat_name;
	stat->fs_handle = fieldstat_easy_new(1, instance_name, NULL, 0);
    if (NULL == stat->fs_handle) {
        log_fatal(stat->logger, MODULE_MAAT_STAT,
                  "fieldstat_easy_new failed.");
        return -1;
    }

    stat->ref_tbl_mgr = tbl_mgr;
    stat->ref_garbage_bin = garbage_bin;

    fs_global_metric_register(stat);
    fs_table_column_register(stat);
    fs_table_row_register(stat);

    fieldstat_easy_enable_auto_output(stat->fs_handle, stat->stat_file, 2);

    return 0;
}

static void fs_table_row_refresh(struct maat_stat *stat, int perf_on)
{
    long long plugin_cache_num = 0, plugin_rule_num = 0;
    long long total_rule_num = 0, total_scan_bytes = 0, total_update_err = 0;
    long long total_scan_times = 0, total_hit_times = 0, total_scan_cpu_time = 0;
    long long total_regv6_num = 0, total_hit_item_num = 0, total_hit_pattern_num = 0;
    long long g2c_not_condition_num = 0, g2g_excl_rule_num = 0;
    struct field cell_tag = {
        .key = "TBL",
        .type = FIELD_VALUE_CSTRING
    };

    size_t max_table_count = table_manager_table_size(stat->ref_tbl_mgr);

    for (size_t i = 0; i < max_table_count; i++) {
        long long regex_rule_num = 0;
        long long ipv6_rule_num = 0;

        void *schema = table_manager_get_schema(stat->ref_tbl_mgr, i);
        if (NULL == schema) {
            continue;
        }

        enum table_type table_type =
            table_manager_get_table_type(stat->ref_tbl_mgr, i);
        assert(table_type != TABLE_TYPE_INVALID);

        void *runtime = table_manager_get_runtime(stat->ref_tbl_mgr, i);

        switch (table_type) {
            case TABLE_TYPE_PLUGIN:
                plugin_cache_num += plugin_runtime_cached_row_count(runtime);
                plugin_rule_num += plugin_runtime_rule_count(runtime);
                break;
            case TABLE_TYPE_OBJECT2OBJECT:
                g2g_excl_rule_num += object2object_runtime_exclude_rule_count(runtime);
                break;
            case TABLE_TYPE_EXPR:
            case TABLE_TYPE_EXPR_PLUS:
                regex_rule_num = expr_runtime_regex_rule_count(runtime);
                break;
            case TABLE_TYPE_IP:
                ipv6_rule_num = ip_runtime_ipv6_rule_count(runtime);
                break;
            default:
                break;
        }

        long long rule_num =
            table_manager_runtime_rule_count(stat->ref_tbl_mgr, i);
        cell_tag.value_str = stat->tag_value[i];
        fieldstat_easy_counter_set(stat->fs_handle, 0,
                                   stat->fs_column_id[COLUMN_RULE_NUM],
                                   &cell_tag, 1, rule_num);
        
        long long scan_times =
            table_manager_runtime_scan_times(stat->ref_tbl_mgr, i);
        fieldstat_easy_counter_set(stat->fs_handle, 0,
                                   stat->fs_column_id[COLUMN_SCAN_TIMES],
                                   &cell_tag, 1, scan_times);
        
        long long hit_times =
            table_manager_runtime_hit_times(stat->ref_tbl_mgr, i);
        fieldstat_easy_counter_set(stat->fs_handle, 0,
                                   stat->fs_column_id[COLUMN_HIT_TIMES],
                                   &cell_tag, 1, hit_times);

        long long scan_bytes =
            table_manager_runtime_scan_bytes(stat->ref_tbl_mgr, i);
        fieldstat_easy_counter_set(stat->fs_handle, 0,
                                   stat->fs_column_id[COLUMN_SCAN_BYTES],
                                   &cell_tag, 1, scan_bytes);

        long long hit_item_num =
            table_manager_runtime_hit_item_num(stat->ref_tbl_mgr, i);

        fieldstat_easy_counter_set(stat->fs_handle, 0,
                                   stat->fs_column_id[COLUMN_HIT_ITEM_NUM],
                                   &cell_tag, 1, hit_item_num); 
        
        total_regv6_num += regex_rule_num;
        total_regv6_num += ipv6_rule_num;
        total_rule_num += rule_num;
        
        total_scan_times += scan_times;
        total_hit_times += hit_times;
        total_scan_bytes += scan_bytes;
        total_hit_item_num += hit_item_num;
        total_update_err +=
            table_manager_runtime_update_err_count(stat->ref_tbl_mgr, i);

        if (table_type == TABLE_TYPE_EXPR ||
            table_type == TABLE_TYPE_EXPR_PLUS) {
            fieldstat_easy_counter_set(stat->fs_handle, 0,
                                       stat->fs_column_id[COLUMN_REGEX_NUM],
                                       &cell_tag, 1, regex_rule_num);

            long long hit_pattern_num = expr_runtime_hit_pattern_num(runtime);
            fieldstat_easy_counter_set(stat->fs_handle, 0,
                                       stat->fs_column_id[COLUMN_HIT_PAT_NUM],
                                       &cell_tag, 1, hit_pattern_num);
            total_hit_pattern_num += hit_pattern_num;
        }

        if (table_type == TABLE_TYPE_IP) {
            fieldstat_easy_counter_set(stat->fs_handle, 0,
                                       stat->fs_column_id[COLUMN_REGEX_NUM],
                                       &cell_tag, 1, ipv6_rule_num);
        }

        if (table_type == TABLE_TYPE_PLUGIN ||
            table_type == TABLE_TYPE_IP_PLUGIN ||
            table_type == TABLE_TYPE_IPPORT_PLUGIN ||
            table_type == TABLE_TYPE_BOOL_PLUGIN ||
            table_type == TABLE_TYPE_FQDN_PLUGIN) {
            continue;
        }

        if (1 == perf_on) {
            long long scan_cpu_time =
                table_manager_runtime_scan_cpu_time(stat->ref_tbl_mgr, i);

            fieldstat_easy_counter_set(stat->fs_handle, 0,
                                       stat->fs_column_id[COLUMN_SCAN_CPU_TIME],
                                       &cell_tag, 1, scan_cpu_time); 
        }
    }

    cell_tag.value_str = stat->sum_tag;
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->fs_column_id[COLUMN_RULE_NUM],
                               &cell_tag, 1, total_rule_num);
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->fs_column_id[COLUMN_REGEX_NUM],
                               &cell_tag, 1, total_regv6_num); 
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->fs_column_id[COLUMN_SCAN_TIMES],
                               &cell_tag, 1, total_scan_times);
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->fs_column_id[COLUMN_HIT_TIMES],
                               &cell_tag, 1, total_hit_times);
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->fs_column_id[COLUMN_HIT_ITEM_NUM],
                               &cell_tag, 1, total_hit_item_num);
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->fs_column_id[COLUMN_HIT_PAT_NUM],
                               &cell_tag, 1, total_hit_pattern_num);
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->fs_column_id[COLUMN_SCAN_BYTES],
                               &cell_tag, 1, total_scan_bytes);
    if (1 == perf_on) {
        fieldstat_easy_counter_set(stat->fs_handle, 0,
                                   stat->fs_column_id[COLUMN_SCAN_CPU_TIME],
                                   &cell_tag, 1, total_scan_cpu_time);
    }

    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_UPDATE_ERR_CNT],
                               NULL, 0, total_update_err); 

    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_SCAN_ERR_CNT],
                               NULL, 0, stat->scan_err_cnt);  

    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_PLUGIN_CACHE_NUM],
                               NULL, 0, plugin_cache_num); 
                                  
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_PLUGIN_ACC_NUM],
                               NULL, 0, plugin_rule_num); 
                            
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_CONDITION_REF_NOT_NUM],
                               NULL, 0, g2c_not_condition_num); 

    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_OBJECT_REF_EXCL_NUM],
                               NULL, 0, g2g_excl_rule_num); 

}

void maat_stat_refresh(struct maat_stat *stat, struct table_manager *tbl_mgr,
                      long long maat_version, int perf_on)
{
    if (NULL == stat || NULL == stat->fs_handle) {
        return;
    }

    long long active_thread_num =
        alignment_int64_array_cnt(stat->thread_call_cnt, stat->nr_worker_thread);

    long long stream_num =
        alignment_int64_array_sum(stat->stream_cnt, stat->nr_worker_thread);

    long long hit_rule_num =
        alignment_int64_array_sum(stat->hit_rule_cnt, stat->nr_worker_thread);

    long long maat_state_num =
        alignment_int64_array_sum(stat->maat_state_cnt, stat->nr_worker_thread);

    long long rule_state_num =
        alignment_int64_array_sum(stat->rule_state_cnt, stat->nr_worker_thread);

    long long maat_state_free_num =
        alignment_int64_array_sum(stat->maat_state_free_cnt, stat->nr_worker_thread);

    long long maat_state_free_bytes =
        alignment_int64_array_sum(stat->maat_state_free_bytes, stat->nr_worker_thread);

    size_t table_num = table_manager_table_num(stat->ref_tbl_mgr);
    size_t garbage_q_len = maat_garbage_bin_get_size(stat->ref_garbage_bin);

    long long per_state_mem = 0;
    if (maat_state_free_num != 0) {
        per_state_mem = maat_state_free_bytes / maat_state_free_num;
    }

    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_VERSION],
                               NULL, 0, maat_version); 
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_THREAD_NUM],
                               NULL, 0, active_thread_num); 
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_TABLE_NUM],
                               NULL, 0, table_num); 
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_HIT_RULE_NUM],
                               NULL, 0, hit_rule_num); 
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_MAAT_STATE_NUM],
                               NULL, 0, maat_state_num); 
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_MAAT_PER_STATE_MEM],
                               NULL, 0, per_state_mem); 
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_RULE_STATE_NUM],
                               NULL, 0, rule_state_num); 
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_CMD_LINE_NUM],
                               NULL, 0, stat->line_cmd_acc_num); 
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_GARBAGE_QUEUE_LEN],
                               NULL, 0, garbage_q_len); 
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_STREAM_NUM],
                               NULL, 0, stream_num); 
    fieldstat_easy_counter_set(stat->fs_handle, 0,
                               stat->g_metric_id[STATUS_ZOMBIE_STREAM_NUM],
                               NULL, 0, stat->zombie_rs_stream); 

    fs_table_row_refresh(stat, perf_on);
}