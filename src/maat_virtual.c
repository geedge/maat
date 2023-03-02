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

#include "maat_kv.h"
#include "maat_utils.h"
#include "log/log.h"
#include "maat_virtual.h"
#include "maat_rule.h"
#include "maat_table.h"

#define MODULE_VIRTUAL	 module_name_str("maat.virtual")

struct virtual_schema {
    char physical_tables[MAX_PHYSICAL_TABLE_NUM][NAME_MAX];
    size_t n_physical_table;
    int table_id;
    struct table_manager *ref_tbl_mgr;
};

void *virtual_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                         const char *table_name, struct log_handle *logger)
{
    struct virtual_schema *schema = ALLOC(struct virtual_schema, 1);
    schema->ref_tbl_mgr = tbl_mgr;
   
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (NULL == item || item->type != cJSON_Number) {
        log_error(logger, MODULE_VIRTUAL, 
                  "[%s:%d] virtual table %s has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }
    schema->table_id = item->valueint;

    item = cJSON_GetObjectItem(json, "physical_table");
    if (NULL == item || item->type != cJSON_Array) {
        log_error(logger, MODULE_VIRTUAL, 
                  "[%s:%d] virtual table %s has no physical_table column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    int cnt = cJSON_GetArraySize(item);
    for (int i = 0; i < cnt; i++) {
        cJSON *tmp_item = cJSON_GetArrayItem(item, i);
        if (tmp_item != NULL && tmp_item->type == cJSON_String) {
           memcpy(schema->physical_tables[i], tmp_item->valuestring, 
                  strlen(tmp_item->valuestring));
        }
    }
    schema->n_physical_table = cnt;

    return schema;
error:
    FREE(schema);
    return NULL;
}

void virtual_schema_free(void *virtual_schema)
{
    FREE(virtual_schema);
}

int virtual_table_get_id(void *virtual_schema)
{
    if (NULL == virtual_schema) {
        return -1;
    }

    struct virtual_schema *schema = (struct virtual_schema *)virtual_schema;
    return schema->table_id;
}

size_t virtual_table_get_physical_table_id(void *virtual_schema, int physical_table_ids[])
{
    if (NULL == virtual_schema) {
        return 0;
    }

    struct virtual_schema *schema = (struct virtual_schema *)virtual_schema;

    for (size_t i = 0; i < schema->n_physical_table; i++) {
        int table_id = table_manager_get_table_id(schema->ref_tbl_mgr, schema->physical_tables[i]);
        physical_table_ids[i] = table_id;
    }
    
    return schema->n_physical_table;
}