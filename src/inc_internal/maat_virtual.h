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

enum scan_type {
    SCAN_TYPE_INVALID = -1,
	SCAN_TYPE_NONE = 0,
	SCAN_TYPE_PLUGIN,
	SCAN_TYPE_IP_PLUGIN,
	SCAN_TYPE_FQDN_PLUGIN,
	SCAN_TYPE_BOOL_PLUGIN,
	SCAN_TYPE_IP,
	SCAN_TYPE_INTERVAL,
	SCAN_TYPE_STRING,
    SCAN_TYPE_FLAG,
	SCAN_TYPE_MAX
};

void *virtual_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                         const char *table_name, struct log_handle *logger);

void virtual_schema_free(void *virtual_schema);

int virtual_table_get_physical_table_id(void *virtual_schema);

#ifdef __cplusplus
}
#endif

#endif