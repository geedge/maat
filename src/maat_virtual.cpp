/*
**********************************************************************************************
*	File: maat_virtual.cpp
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "cJSON/cJSON.h"
#include "maat_kv.h"
#include "maat_utils.h"
#include "log/log.h"
#include "maat_virtual.h"
#include "maat_rule.h"
#include "maat_table.h"

#define MODULE_VIRTUAL	 module_name_str("maat.virtual")

struct virtual_schema {
	int physical_table_id[SCAN_TYPE_MAX];
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

void *virtual_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                         const char *table_name, struct log_handle *logger)
{
    cJSON *item = cJSON_GetObjectItem(json, "physical_table");
    if (NULL == item || item->type != cJSON_Array) {
        log_error(logger, MODULE_VIRTUAL, 
                  "virtual table %s has no physical_table column", table_name);
        return NULL;
    }

    struct virtual_schema *vt_schema = ALLOC(struct virtual_schema, 1);
    vt_schema->ref_tbl_mgr = tbl_mgr;
   
    int cnt = cJSON_GetArraySize(item);
    for (int i = 0; i < cnt; i++) {
        cJSON *tmp_item = cJSON_GetArrayItem(item, i);
        if (tmp_item != NULL && tmp_item->type == cJSON_String) {
            int table_id = table_manager_get_table_id(tbl_mgr, tmp_item->valuestring);
            /* physical table should already exist */
            if (table_id < 0) {
                log_error(logger, MODULE_VIRTUAL, "table:%s is not registered",
                            tmp_item->valuestring);
                FREE(vt_schema);
                return NULL;
            }

            enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
            assert(table_type != TABLE_TYPE_INVALID);
            enum scan_type scan_type = maat_table_get_scan_type(table_type);
            assert(scan_type != SCAN_TYPE_INVALID);
            vt_schema->physical_table_id[scan_type]= table_id;
        }
    }

    return vt_schema;
}

void virtual_schema_free(void *virtual_schema)
{
    FREE(virtual_schema);
}

int virtual_table_get_physical_table_id(void *virtual_schema, enum scan_type type)
{
    if (NULL == virtual_schema) {
        return -1;
    }

    struct virtual_schema *schema = (struct virtual_schema *)virtual_schema;
    return schema->physical_table_id[type];
}