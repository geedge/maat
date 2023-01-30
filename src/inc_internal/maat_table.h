/*
**********************************************************************************************
*	File: maat_table.h
*   Description: maat table schema and runtime
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_TABLE_H_
#define _MAAT_TABLE_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stddef.h>
#include <cJSON/cJSON.h>

enum table_type {
    TABLE_TYPE_INVALID = -1,
	TABLE_TYPE_EXPR = 0,
    TABLE_TYPE_EXPR_PLUS,
    TABLE_TYPE_IP_PLUS,
    TABLE_TYPE_INTERVAL,
    TABLE_TYPE_INTERVAL_PLUS,
    TABLE_TYPE_DIGEST,
    TABLE_TYPE_SIMILARITY,
    TABLE_TYPE_CONJUNCTION,
    TABLE_TYPE_PLUGIN,
    TABLE_TYPE_IP_PLUGIN,
    TABLE_TYPE_FQDN_PLUGIN,
    TABLE_TYPE_BOOL_PLUGIN,
    //above are physical table
    TABLE_TYPE_VIRTUAL,
    TABLE_TYPE_COMPILE,
    TABLE_TYPE_GROUP2GROUP,
	TABLE_TYPE_GROUP2COMPILE,
    TABLE_TYPE_MAX
};

struct table_manager;

struct table_manager *table_manager_create(const char *table_info_path, const char *accept_tags,
                                           struct log_handle *logger);
int table_manager_init(struct table_manager *tbl_mgr, struct maat_garbage_bin *garbage_bin);
int table_manager_deinit(struct table_manager *tbl_mgr);
void table_manager_destroy(struct table_manager *tbl_mgr);

size_t table_manager_table_count(struct table_manager *tbl_mgr);
int table_manager_get_table_id(struct table_manager *tbl_mgr, const char *name);
enum table_type table_manager_get_table_type(struct table_manager *tbl_mgr, int table_id);
int table_manager_get_valid_column(struct table_manager *tbl_mgr, int table_id);
int table_manager_accept_tags_match(const char *tags);

void *table_manager_get_schema(struct table_manager *tbl_mgr, int table_id);

void *table_manager_get_runtime(struct table_manager *tbl_mgr, int table_id);
void table_manager_update_runtime(struct table_manager *tbl_mgr, int table_id, const char *line);
void table_manager_commit_runtime(struct table_manager *tbl_mgr, int table_id);

#ifdef __cpluscplus
}
#endif

#endif