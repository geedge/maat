/*
**********************************************************************************************
*	File: maat_table_runtime.h
*   Description: maat table runtime entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_TABLE_RUNTIME_H_
#define _MAAT_TABLE_RUNTIME_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include "maat_table_schema.h"
#include "maat_garbage_collection.h"

struct maat_table_item;
struct maat_table_runtime;
struct maat_table_runtime_manager;

struct maat_table_runtime_manager *maat_table_runtime_manager_create(struct maat_table_manager *table_mgr, int max_thread_num, struct maat_garbage_bin* bin);

void maat_table_runtime_manager_destroy(struct maat_table_runtime_manager *table_rt_mgr);

struct maat_table_runtime *maat_table_runtime_get(struct maat_table_runtime_manager *table_rt_mgr, int table_id);

enum maat_table_type maat_table_runtime_get_type(struct maat_table_runtime* table_rt);

void maat_table_runtime_item_add(struct maat_table_runtime *table_rt, struct maat_table_item *table_item);

#ifdef __cpluscplus
}
#endif

#endif