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

#include "maat_utils.h"
#include "maat_stat.h"
#include "fieldstat.h"
#include "alignment.h"
#include "maat_ip.h"
#include "maat_compile.h"
#include "maat_group.h"
#include "maat_plugin.h"
#include "maat_expr.h"

#define MODULE_MAAT_STAT	 module_name_str("maat.stat")

enum MAAT_FS_STATUS {
	STATUS_VERSION = 0,
	STATUS_THRED_NUM,
	STATUS_TABLE_NUM,
	STATUS_PLUGIN_CACHE_NUM,
	STATUS_PLUGIN_ACC_NUM,
	STATUS_GROUP_REF_NUM,
    STATUS_GROUP_REF_NOT_NUM,
    STATUS_GROUP_REF_EXCL_NUM, //group reference exclude group num
	STATUS_COMPILE_RULE_NUM,
	STATUS_MAAT_STATE_NUM,
    STATUS_MAAT_STATE_FREE_NUM,
    STATUS_MAAT_STATE_FREE_BYTES,
    STATUS_COMPILE_STATE_NUM,
	STATUS_GARBAGE_QSIZE,
	STATUS_TOTAL_SCAN_BYTES,
	STATUS_TOTAL_SCAN_CNT,
	STATUS_UPDATE_ERR_CNT,
	STATUS_ICONV_ERR_CNT,
	STATUS_SCAN_ERR_CNT,
	STATUS_ZOMBIE_RS_STREAM,
    STATUS_NOT_GROUP_HIT,
	STATUS_CMD_LINE_NUM
};

enum MAAT_FS_COLUMN {
	COLUMN_RULE_NUM = 0,
	COLUMN_REGEX_NUM,
	COLUMN_STREAM_NUM,
	COLUMN_SCAN_CNT,
	COLUMN_SCAN_BYTES,
	COLUMN_CPU_TIME, //microseconds
	COLUMN_HIT_CNT,
    COLUMN_SCAN_BPS, //scan bytes per second
    COLUMN_SCAN_TPS, //scan times per second
    COLUMN_HIT_RATE  //scan hit rate(hit_cnt/scan_cnt)
};

const char *common_column_name[] = {"rule", "reg/v6", "stream", "scan_cnt", "scan_bytes",
                                    "scan_cpu_time", "hit_cnt", "IN_Bps", "IN_Tps", "hit_rate"};

enum field_type common_column_type[] = {
    FIELD_TYPE_GAUGE,
    FIELD_TYPE_GAUGE,
    FIELD_TYPE_GAUGE,
    FIELD_TYPE_GAUGE,
    FIELD_TYPE_GAUGE,
    FIELD_TYPE_GAUGE,
    FIELD_TYPE_GAUGE,
    FIELD_TYPE_GAUGE,
    FIELD_TYPE_GAUGE,
    FIELD_TYPE_GAUGE
};

#define	MAX_CONJ_NAME_LEN	22
void maat_fieldstat_register(struct maat_stat *stat)
{
    stat->fs_status_id[STATUS_VERSION] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE,
                                                            "version", NULL, 0);
    stat->fs_status_id[STATUS_THRED_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                              "threads", NULL, 0);
    stat->fs_status_id[STATUS_TABLE_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                              "tables", NULL, 0);
    stat->fs_status_id[STATUS_PLUGIN_CACHE_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                     "plug_cached", NULL, 0);
    stat->fs_status_id[STATUS_PLUGIN_ACC_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                   "plug_acc", NULL, 0);
    stat->fs_status_id[STATUS_GROUP_REF_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                  "group", NULL, 0);
    stat->fs_status_id[STATUS_GROUP_REF_NOT_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                      "not_grp", NULL, 0);
    stat->fs_status_id[STATUS_GROUP_REF_EXCL_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                      "excl_grp", NULL, 0);
    stat->fs_status_id[STATUS_COMPILE_RULE_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                     "compile", NULL, 0);
    stat->fs_status_id[STATUS_GARBAGE_QSIZE] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                  "garbage_num", NULL, 0);
    stat->fs_status_id[STATUS_MAAT_STATE_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                  "maat_state", NULL, 0);
    stat->fs_status_id[STATUS_MAAT_STATE_FREE_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                        "maat_state_free_cnt", NULL, 0);
    stat->fs_status_id[STATUS_MAAT_STATE_FREE_BYTES] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                          "maat_state_free_bytes", NULL, 0);
    stat->fs_status_id[STATUS_COMPILE_STATE_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                     "maat_compile_state", NULL, 0);
    stat->fs_status_id[STATUS_ZOMBIE_RS_STREAM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                     "z_stream", NULL, 0);
    stat->fs_status_id[STATUS_NOT_GROUP_HIT] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                  "nt_grp_hit", NULL, 0);
    stat->fs_status_id[STATUS_TOTAL_SCAN_BYTES] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                   "scan_bytes", NULL, 0);
    stat->fs_status_id[STATUS_TOTAL_SCAN_CNT] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                  "scan_times", NULL, 0);
    stat->fs_status_id[STATUS_UPDATE_ERR_CNT] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                   "update_error", NULL, 0);
    stat->fs_status_id[STATUS_SCAN_ERR_CNT] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                 "scan_error", NULL, 0);
    stat->fs_status_id[STATUS_CMD_LINE_NUM] = fieldstat_register(stat->fs_handle, FIELD_TYPE_GAUGE, 
                                                                 "line_cmd/s", NULL, 0);
}

int maat_fieldstat_table_row_register(struct maat_stat *stat, struct table_manager *tbl_mgr,
                                       int table_id)
{
    size_t max_table_cnt = table_manager_table_size(tbl_mgr);
    int ret = fieldstat_register_table_row(stat->fs_handle, table_id, "Sum", NULL, 0,
                                           stat->total_stat_id);
    if (ret < 0) {
        log_error(stat->logger, MODULE_MAAT_STAT, "fieldstat_register_table_row Sum failed.");
        return -1;
    }

    ret = fieldstat_set_metric_ratio_para(stat->fs_handle, stat->total_stat_id[COLUMN_SCAN_BPS],
                                          stat->total_stat_id[COLUMN_SCAN_BYTES],
                                          stat->total_stat_id[COLUMN_CPU_TIME], 1000000000);
    if (ret < 0) {
        log_error(stat->logger, MODULE_MAAT_STAT, "fieldstat set IN_Bps for Sum failed.");
        return -1;
    }

    ret = fieldstat_set_metric_ratio_para(stat->fs_handle, stat->total_stat_id[COLUMN_SCAN_TPS],
                                          stat->total_stat_id[COLUMN_SCAN_CNT],
                                          stat->total_stat_id[COLUMN_CPU_TIME], 1000000000);
    if (ret < 0) {
        log_error(stat->logger, MODULE_MAAT_STAT, "fieldstat set IN_Tps for Sum failed.");
        return -1;
    }

    ret = fieldstat_set_metric_ratio_para(stat->fs_handle, stat->total_stat_id[COLUMN_HIT_RATE],
                                          stat->total_stat_id[COLUMN_HIT_CNT],
                                          stat->total_stat_id[COLUMN_SCAN_CNT], 1);
    if (ret < 0) {
        log_error(stat->logger, MODULE_MAAT_STAT, "fieldstat set hit_rate for Sum failed.");
        return -1;
    }

    for (size_t i = 0; i < max_table_cnt; i++) {
        void *schema = table_manager_get_schema(tbl_mgr, i);
        if (NULL == schema) {
            continue;
        }

        enum table_type table_type = table_manager_get_table_type(tbl_mgr, i);
        if (table_type == TABLE_TYPE_VIRTUAL) {
            continue;
        }
        
        const char *table_name = table_manager_get_table_name(tbl_mgr, i);
        assert(table_name != NULL);

        ret = fieldstat_register_table_row(stat->fs_handle, table_id, table_name, NULL, 0,
                                           stat->fs_column_id[i]);
        if (ret < 0) {
            log_error(stat->logger, MODULE_MAAT_STAT,
                      "fieldstat_register_table_row %s failed.", table_name);
            return -1;
        }

        ret = fieldstat_set_metric_ratio_para(stat->fs_handle, stat->fs_column_id[i][COLUMN_SCAN_BPS],
                                              stat->fs_column_id[i][COLUMN_SCAN_BYTES],
                                              stat->fs_column_id[i][COLUMN_CPU_TIME], 1000000000);
        if (ret < 0) {
            log_error(stat->logger, MODULE_MAAT_STAT,
                      "fieldstat set IN_Bps for %s failed.", table_name);
            return -1;
        }

        ret = fieldstat_set_metric_ratio_para(stat->fs_handle, stat->fs_column_id[i][COLUMN_SCAN_TPS],
                                              stat->fs_column_id[i][COLUMN_SCAN_CNT],
                                              stat->fs_column_id[i][COLUMN_CPU_TIME], 1000000000);
        if (ret < 0) {
            log_error(stat->logger, MODULE_MAAT_STAT,
                      "fieldstat set IN_Tps for %s failed.", table_name);
            return -1;
        }

        ret = fieldstat_set_metric_ratio_para(stat->fs_handle, stat->fs_column_id[i][COLUMN_HIT_RATE],
                                              stat->fs_column_id[i][COLUMN_HIT_CNT],
                                              stat->fs_column_id[i][COLUMN_SCAN_CNT], 1);
        if (ret < 0) {
            log_error(stat->logger, MODULE_MAAT_STAT,
                      "fieldstat set hit_rate for %s failed.", table_name);
            return -1;
        }
    }

    return 0; 
}

struct maat_stat *maat_stat_new(const char *stat_file, size_t max_thread_num,
                                struct log_handle *logger)
{
    struct maat_stat *stat = ALLOC(struct maat_stat, 1);

    size_t str_len = MIN(sizeof(stat->stat_file), strlen(stat_file));
    memcpy(stat->stat_file, stat_file, str_len);

    stat->nr_worker_thread = max_thread_num;
    stat->logger = logger;
    stat->thread_call_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->hit_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->not_grp_hit_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->maat_state_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->maat_compile_state_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->maat_state_free_cnt = alignment_int64_array_alloc(max_thread_num);
    stat->maat_state_free_bytes = alignment_int64_array_alloc(max_thread_num);

    return stat;
}

void maat_stat_free(struct maat_stat *stat)
{
    if (NULL == stat) {
        return;
    }

    if (stat->thread_call_cnt != NULL) {
        alignment_int64_array_free(stat->thread_call_cnt);
        stat->thread_call_cnt = NULL;
    }

    if (stat->hit_cnt != NULL) {
        alignment_int64_array_free(stat->hit_cnt);
        stat->hit_cnt = NULL;
    }

    if (stat->not_grp_hit_cnt != NULL) {
        alignment_int64_array_free(stat->not_grp_hit_cnt);
        stat->not_grp_hit_cnt = NULL;
    }

    if (stat->maat_state_cnt != NULL) {
        alignment_int64_array_free(stat->maat_state_cnt);
        stat->maat_state_cnt = NULL;
    }

    if (stat->maat_compile_state_cnt != NULL) {
        alignment_int64_array_free(stat->maat_compile_state_cnt);
        stat->maat_compile_state_cnt = NULL;
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
        fieldstat_instance_free(stat->fs_handle);
        stat->fs_handle = NULL;
    }

    FREE(stat);
}

int maat_stat_init(struct maat_stat *stat, struct table_manager *tbl_mgr, 
                    struct maat_garbage_bin *garbage_bin)
{
    if (NULL == stat || NULL == tbl_mgr || NULL == garbage_bin) {
        return -1;
    }

    const char *instance_name = "maat_stat";
	stat->fs_handle = fieldstat_instance_new(instance_name);
    if (NULL == stat->fs_handle) {
        log_error(stat->logger, MODULE_MAAT_STAT, "fieldstat_instance_new failed.");
        return -1;
    }

    int ret = fieldstat_set_local_output(stat->fs_handle, stat->stat_file, "default");
    if (ret < 0) {
        log_error(stat->logger, MODULE_MAAT_STAT, "fieldstat_set_local_output failed.");
        return -1;
    }

    ret = fieldstat_disable_background_thread(stat->fs_handle);
    if (ret < 0) {
        log_error(stat->logger, MODULE_MAAT_STAT,
                  "fieldstat_disable_background_thread failed.");
        return -1;
    }

    maat_fieldstat_register(stat);

    stat->ref_tbl_mgr = tbl_mgr;
    stat->ref_garbage_bin = garbage_bin;
    size_t n_column = sizeof(common_column_name) / sizeof(common_column_name[0]);
    int fs_table_id = fieldstat_register_table(stat->fs_handle, instance_name, 
                                               common_column_name, common_column_type, 
                                               n_column);
    if (fs_table_id < 0) {
        log_error(stat->logger, MODULE_MAAT_STAT, "fieldstat_register_table failed.");
        return -1;
    }

    ret = maat_fieldstat_table_row_register(stat, tbl_mgr, fs_table_id);
    if (ret < 0) {
        return -1;
    }

    fieldstat_instance_start(stat->fs_handle);

    return 0;
}

void maat_fieldstat_table_row_output(struct maat_stat *stat, int perf_on)
{
    long long plugin_cache_num = 0, plugin_rule_num = 0, g2c_not_group_num = 0;
    long long compile_rule_num = 0, g2c_rule_num = 0, g2g_rule_num = 0;
    long long total_rule_num = 0, total_stream_num = 0, total_input_bytes = 0;
    long long total_scan_cnt = 0, total_scan_cpu_time = 0, total_regex_num = 0;
    long long total_ipv6_num = 0, total_hit_cnt = 0, total_update_err = 0;
    long long g2g_excl_rule_num = 0;
    size_t max_table_count = table_manager_table_size(stat->ref_tbl_mgr);

    for (size_t i = 0; i < max_table_count; i++) {
        long long regex_rule_num = 0;
        long long ipv6_rule_num = 0;
        void *schema = table_manager_get_schema(stat->ref_tbl_mgr, i);
        if (NULL == schema) {
            continue;
        }

        enum table_type table_type = table_manager_get_table_type(stat->ref_tbl_mgr, i);
        assert(table_type != TABLE_TYPE_INVALID);

        void *runtime = table_manager_get_runtime(stat->ref_tbl_mgr, i);

        switch (table_type) {
            case TABLE_TYPE_PLUGIN:
                plugin_cache_num += plugin_runtime_cached_row_count(runtime);
                plugin_rule_num += plugin_runtime_rule_count(runtime);
                break;
            case TABLE_TYPE_COMPILE:
                compile_rule_num += compile_runtime_rule_count(runtime);
                break;
            case TABLE_TYPE_GROUP2COMPILE:
                g2c_rule_num += group2compile_runtime_rule_count(runtime);
                g2c_not_group_num += group2compile_runtime_not_group_count(runtime);
                break;
            case TABLE_TYPE_GROUP2GROUP:
                g2g_rule_num += group2group_runtime_rule_count(runtime);
                g2g_excl_rule_num += group2group_runtime_exclude_rule_count(runtime);
                break;
            case TABLE_TYPE_EXPR:
            case TABLE_TYPE_EXPR_PLUS:
                regex_rule_num = expr_runtime_regex_rule_count(runtime);
                break;
            case TABLE_TYPE_IP_PLUS:
                ipv6_rule_num = ip_runtime_ipv6_rule_count(runtime);
                break;
            default:
                break;
        }

        if (table_type == TABLE_TYPE_PLUGIN || table_type == TABLE_TYPE_VIRTUAL) {
            continue;
        }

        total_regex_num += regex_rule_num;
        total_ipv6_num += ipv6_rule_num;

        long long rule_num = table_manager_runtime_rule_count(stat->ref_tbl_mgr, i);
        fieldstat_value_set(stat->fs_handle, stat->fs_column_id[i][COLUMN_RULE_NUM], rule_num);
        total_rule_num += rule_num;

        if (table_type == TABLE_TYPE_EXPR || table_type == TABLE_TYPE_EXPR_PLUS) {
            fieldstat_value_set(stat->fs_handle, stat->fs_column_id[i][COLUMN_REGEX_NUM],
                                regex_rule_num);
            long long stream_num = expr_runtime_stream_num(runtime);
            fieldstat_value_set(stat->fs_handle, stat->fs_column_id[i][COLUMN_STREAM_NUM],
                                stream_num);
            total_stream_num += stream_num;

            long long input_bytes = expr_runtime_scan_bytes(runtime);
            fieldstat_value_set(stat->fs_handle, stat->fs_column_id[i][COLUMN_SCAN_BYTES],
                                input_bytes);
            total_input_bytes += input_bytes;
        }

        if (table_type == TABLE_TYPE_IP_PLUS) {
            fieldstat_value_set(stat->fs_handle, stat->fs_column_id[i][COLUMN_REGEX_NUM],
                                ipv6_rule_num);
        }

        if (1 == perf_on) {
            long long scan_cpu_time = table_manager_runtime_scan_cpu_time(stat->ref_tbl_mgr, i);
            fieldstat_value_set(stat->fs_handle, stat->fs_column_id[i][COLUMN_CPU_TIME],
                                scan_cpu_time);
            total_scan_cpu_time += scan_cpu_time;
        }

        long long scan_cnt = table_manager_runtime_scan_count(stat->ref_tbl_mgr, i);
        fieldstat_value_set(stat->fs_handle, stat->fs_column_id[i][COLUMN_SCAN_CNT], scan_cnt);
        total_scan_cnt += scan_cnt;

        long long hit_cnt = table_manager_runtime_hit_count(stat->ref_tbl_mgr, i);
        fieldstat_value_set(stat->fs_handle, stat->fs_column_id[i][COLUMN_HIT_CNT], hit_cnt);
        total_hit_cnt += hit_cnt;

        total_update_err += table_manager_runtime_update_err_count(stat->ref_tbl_mgr, i);
    }

    fieldstat_value_set(stat->fs_handle, stat->total_stat_id[COLUMN_RULE_NUM],
                        total_rule_num);
    fieldstat_value_set(stat->fs_handle, stat->total_stat_id[COLUMN_REGEX_NUM],
                        total_regex_num);
    fieldstat_value_set(stat->fs_handle, stat->total_stat_id[COLUMN_STREAM_NUM],
                        total_stream_num);
    fieldstat_value_set(stat->fs_handle, stat->total_stat_id[COLUMN_SCAN_CNT],
                        total_scan_cnt);
    fieldstat_value_set(stat->fs_handle, stat->total_stat_id[COLUMN_SCAN_BYTES],
                        total_input_bytes);

    if (1 == perf_on) {
        fieldstat_value_set(stat->fs_handle, stat->total_stat_id[COLUMN_CPU_TIME],
                            total_scan_cpu_time);
    }

    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_TOTAL_SCAN_BYTES],
                        total_input_bytes);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_TOTAL_SCAN_CNT],
                        total_scan_cnt);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_UPDATE_ERR_CNT],
                        total_update_err);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_SCAN_ERR_CNT],
                        stat->scan_err_cnt);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_ZOMBIE_RS_STREAM],
                        stat->zombie_rs_stream);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_PLUGIN_CACHE_NUM],
                        plugin_cache_num);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_PLUGIN_ACC_NUM],
                        plugin_rule_num);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_GROUP_REF_NUM],
                        g2c_rule_num);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_GROUP_REF_NOT_NUM],
                        g2c_not_group_num);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_GROUP_REF_EXCL_NUM],
                        g2g_excl_rule_num);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_COMPILE_RULE_NUM],
                        compile_rule_num);
}

void maat_stat_output(struct maat_stat *stat, long long maat_version, int perf_on)
{
    if (NULL == stat) {
        return;
    }

    long long active_thread_num = alignment_int64_array_cnt(stat->thread_call_cnt, 
                                                            stat->nr_worker_thread);
    long long maat_state_cnt = alignment_int64_array_sum(stat->maat_state_cnt,
                                                         stat->nr_worker_thread);
    long long maat_state_free_cnt = alignment_int64_array_sum(stat->maat_state_free_cnt,
                                                              stat->nr_worker_thread);
    long long maat_state_free_bytes = alignment_int64_array_sum(stat->maat_state_free_bytes,
                                                                stat->nr_worker_thread);
    long long maat_compile_state_cnt = alignment_int64_array_sum(stat->maat_compile_state_cnt,
                                                                 stat->nr_worker_thread);
    long long not_grp_hit_cnt = alignment_int64_array_sum(stat->not_grp_hit_cnt,
                                                          stat->nr_worker_thread);
    size_t table_cnt = table_manager_table_count(stat->ref_tbl_mgr);
    size_t garbage_q_len = maat_garbage_bin_get_size(stat->ref_garbage_bin);

    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_VERSION],
                        maat_version);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_THRED_NUM],
                        active_thread_num);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_TABLE_NUM],
                        table_cnt);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_MAAT_STATE_NUM],
                        maat_state_cnt);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_MAAT_STATE_FREE_NUM],
                        maat_state_free_cnt);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_MAAT_STATE_FREE_BYTES],
                        maat_state_free_bytes);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_COMPILE_STATE_NUM],
                        maat_compile_state_cnt);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_NOT_GROUP_HIT],
                        not_grp_hit_cnt);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_CMD_LINE_NUM],
                        stat->line_cmd_acc_num);
    fieldstat_value_set(stat->fs_handle, stat->fs_status_id[STATUS_GARBAGE_QSIZE],
                        garbage_q_len);

    maat_fieldstat_table_row_output(stat, perf_on);

	fieldstat_passive_output(stat->fs_handle);
}