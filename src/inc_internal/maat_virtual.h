/*
**********************************************************************************************
*	File: maat_virtual.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_VIRTUAL_H_
#define _MAAT_VIRTUAL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "cJSON/cJSON.h"
#include "maat_table.h"

void *virtual_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                         const char *table_name, struct log_handle *logger);

void virtual_schema_free(void *virtual_schema);

int vtable_get_physical_table_id(struct table_manager *tbl_mgr, int vtable_id);

#ifdef __cplusplus
}
#endif

#endif