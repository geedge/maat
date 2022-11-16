/*
**********************************************************************************************
*	File: maat_table_schema.h
*   Description: maat table schema entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_TABLE_SCHEMA_H_
#define _MAAT_TABLE_SCHEMA_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stddef.h>

#include "sds/sds.h"

enum maat_table_type {
	TABLE_TYPE_EXPR = 0,
    TABLE_TYPE_IP_PLUGIN,
	TABLE_TYPE_MAX
};

struct maat_table_schema;
struct maat_table_manager;
struct maat_table_item;

struct maat_table_manager *maat_table_manager_create(sds table_info_path);
void maat_table_manager_destroy(struct maat_table_manager *table_mgr);

int maat_table_manager_get_table_id(struct maat_table_manager* table_mgr, sds table_name);
enum maat_table_type maat_table_manager_get_table_type(struct maat_table_manager *table_mgr, int id);

size_t maat_table_manager_get_size(struct maat_table_manager* table_mgr);

struct maat_table_item *maat_table_line_to_item(sds line, struct maat_table_schema *table_schema);

#ifdef __cpluscplus
}
#endif

#endif