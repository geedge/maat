/*
**********************************************************************************************
*	File: maat_table.h
*   Description: maat table schema and runtime
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_TABLE_H_
#define _MAAT_TABLE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <cJSON/cJSON.h>

#include "maat.h"
#include "log/log.h"
#include "maat_garbage_collection.h"

enum table_type {
    TABLE_TYPE_INVALID = -1,
    TABLE_TYPE_FLAG = 0,
    TABLE_TYPE_FLAG_PLUS,
	TABLE_TYPE_EXPR,
    TABLE_TYPE_EXPR_PLUS,
    TABLE_TYPE_IP,
    TABLE_TYPE_INTERVAL,
    TABLE_TYPE_INTERVAL_PLUS,
    TABLE_TYPE_PLUGIN,
    TABLE_TYPE_IP_PLUGIN,
    TABLE_TYPE_IPPORT_PLUGIN,
    TABLE_TYPE_FQDN_PLUGIN,
    TABLE_TYPE_BOOL_PLUGIN,
    //above are physical table
    TABLE_TYPE_ATTRIBUTE,
    TABLE_TYPE_RULE,
    TABLE_TYPE_OBJECT2OBJECT,
	TABLE_TYPE_OBJECT2RULE,
    TABLE_TYPE_MAX
};

struct table_manager;

struct table_manager *
table_manager_create(const char *table_info_path, const char *accept_tags,
                     enum maat_expr_engine expr_engine, struct maat_garbage_bin *garbage_bin,
                     struct log_handle *logger);
int table_manager_runtime_create(struct table_manager *tbl_mgr, size_t max_thread_num,
                                 struct maat_garbage_bin *garbage_bin);

void table_manager_runtime_destroy(struct table_manager *tbl_mgr);
void table_manager_destroy(struct table_manager *tbl_mgr);

size_t table_manager_table_size(struct table_manager *tbl_mgr);
size_t table_manager_table_num(struct table_manager *tbl_mgr);

int table_manager_get_table_id(struct table_manager *tbl_mgr, const char *table_name);
/**
 * @brief get table_name's all conjunction parents' table_id
 * 
 * for example: "table_id": 1,
 *              "table_name":"RULE_CONJ"
 *              "db_tables":["RULE_DEFAULT", "RULE_ALIAS"]
 * 
 *              "table_id": 2,
 *              "table_name": "RULE_PLUGIN",
 *              "db_tables": ["RULE_DEFAULT"]
 * 
 *   so RULE_DEFAULT has two conjunction parents whose table_id is 1 and 2.
*/
int table_manager_get_conj_parent_table_ids(struct table_manager *tbl_mgr, const char *table_name,
                                            long long *table_ids_array, size_t n_table_ids_array);

const char *table_manager_get_table_name(struct table_manager *tbl_mgr,
                                         int table_id);

const char *table_manager_get_table_schema_tag(struct table_manager *tbl_mgr, int table_id);

enum table_type table_manager_get_table_type(struct table_manager *tbl_mgr, int table_id);

int table_manager_get_default_rule_table_id(struct table_manager *tbl_mgr);
int table_manager_get_object2object_table_id(struct table_manager *tbl_mgr);

int table_manager_get_valid_column(struct table_manager *tbl_mgr, int table_id);

enum maat_expr_engine table_manager_get_expr_engine(struct table_manager *tbl_mgr);

size_t table_manager_accept_tags_count(struct table_manager *tbl_mgr);
int table_manager_accept_tags_match(struct table_manager *tbl_mgr, const char *tags);

void *table_manager_get_schema(struct table_manager *tbl_mgr, int table_id);
void *table_manager_get_runtime(struct table_manager *tbl_mgr, int table_id);
void *table_manager_get_updating_runtime(struct table_manager *tbl_mgr, int table_id);

int table_manager_update_runtime(struct table_manager *tbl_mgr, const char *table_name, 
                                 int table_id, const char *line, int update_type);

void table_manager_commit_runtime(struct table_manager *tbl_mgr, int table_id, 
                                  int update_type, long long maat_rt_version);

long long table_manager_runtime_rule_count(struct table_manager *tbl_mgr, int table_id);

long long table_manager_runtime_scan_times(struct table_manager *tbl_mgr, int table_id);

long long table_manager_runtime_scan_bytes(struct table_manager *tbl_mgr, int table_id);

long long table_manager_runtime_hit_times(struct table_manager *tbl_mgr, int table_id);

long long table_manager_runtime_scan_cpu_time(struct table_manager *tbl_mgr, int table_id);

long long table_manager_runtime_hit_item_num(struct table_manager *tbl_mgr, int table_id);

long long table_manager_runtime_update_err_count(struct table_manager *tbl_mgr,
                                                 int table_id);

#ifdef __cplusplus
}
#endif

#endif