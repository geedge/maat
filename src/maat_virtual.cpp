/*
**********************************************************************************************
*	File: maat_virtual.cpp
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include "cJSON/cJSON.h"
#include "maat_kv.h"
#include "utils.h"
#include "maat_utils.h"
#include "log/log.h"
#include "maat_virtual.h"

#define MODULE_VIRTUAL	 module_name_str("maat.virtual")

struct virtual_schema {
	int physical_table_id[SCAN_TYPE_MAX];
};

void *virtual_schema_new(cJSON *json, const char *table_name, struct log_handle *logger)
{
    //size_t read_cnt = 0;

    cJSON *item = cJSON_GetObjectItem(json, "physical_table");
    if (NULL == item || item->type != cJSON_Array) {
        log_error(logger, MODULE_VIRTUAL, "virtual table %s has no physical_table column", table_name);
        return NULL;
    }

    struct virtual_schema *vt_schema = ALLOC(struct virtual_schema, 1);
    return vt_schema;
#if 0
    struct virtual_schema *vt_schema = ALLOC(struct virtual_schema, 1);
    int cnt = cJSON_GetArraySize(item);
    for (int i = 0; i < cnt; i++) {
        cJSON *tmp_item = cJSON_GetArrayItem(item, i);
        if (tmp_item != NULL && tmp_item->type == cJSON_String) {
            int table_id = -1;
            /* physical table should already exist */
            int ret = maat_kv_read(tablename2id_map, tmp_item->valuestring, &table_id);
			if (ret < 0) {
				return -1;		
			}

            enum scan_type table_scan_type = table_schema_get_scan_type(table_array[table_id]);
            vt_schema->physical_table_id[table_scan_type]= table_id;
        }
    }

    if (read_cnt < 3) {
        FREE(vt_schema);
        return NULL;
    }

    return vt_schema;
#endif
}

void virtual_schema_free(void *virtual_schema)
{
    FREE(virtual_schema);
}