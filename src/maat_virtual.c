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
    char physical_table[NAME_MAX];
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
    if (NULL == item || item->type != cJSON_String) {
        log_error(logger, MODULE_VIRTUAL, 
                  "[%s:%d] virtual table %s has no physical_table column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    memcpy(schema->physical_table, item->valuestring, strlen(item->valuestring));
   
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

int virtual_table_get_physical_table_id(void *virtual_schema)
{
    if (NULL == virtual_schema) {
        return 0;
    }

    struct virtual_schema *schema = (struct virtual_schema *)virtual_schema;

    return table_manager_get_table_id(schema->ref_tbl_mgr, schema->physical_table);
}