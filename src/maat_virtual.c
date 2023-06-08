/*
**********************************************************************************************
*	File: maat_virtual.c
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
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
    int vtable_id;
    int physical_table_id;
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
                  "[%s:%d] virtual table:<%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }
    schema->vtable_id = item->valueint;

    item = cJSON_GetObjectItem(json, "physical_table");
    if (NULL == item || item->type != cJSON_String) {
        log_error(logger, MODULE_VIRTUAL, 
                  "[%s:%d] virtual table:<%s> schema has no physical_table column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    schema->physical_table_id = table_manager_get_table_id(tbl_mgr, item->valuestring);
    if (schema->physical_table_id < 0) {
        log_error(logger, MODULE_VIRTUAL, 
                  "[%s:%d] virtual table:<%s>'s physical table:<%s> unregistered.",
                  __FUNCTION__, __LINE__, table_name, item->valuestring);
        goto error;
    }

    return schema;
error:
    FREE(schema);
    return NULL;
}

void virtual_schema_free(void *virtual_schema)
{
    FREE(virtual_schema);
}

static int virtual_table_get_physical_table_id(void *virtual_schema)
{
    if (NULL == virtual_schema) {
        return 0;
    }

    struct virtual_schema *schema = (struct virtual_schema *)virtual_schema;

    return schema->physical_table_id;
}

int vtable_get_physical_table_id(struct table_manager *tbl_mgr, int table_id)
{
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);

    if (table_type != TABLE_TYPE_VIRTUAL) {
        return -1;
    }

    // find physical table id
    void *virtual_schema = table_manager_get_schema(tbl_mgr, table_id);
    assert(virtual_schema != NULL);
    return virtual_table_get_physical_table_id(virtual_schema);
}