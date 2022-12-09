/*
**********************************************************************************************
*	File: maat_table_schema.cpp
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "utils.h"
#include "log/log.h"
#include "maat_utils.h"
#include "maat_table_schema.h"
#include "maat_kv.h"
#include "cJSON/cJSON.h"
#include "adapter_hs.h"
#include "maat_ex_data.h"

#define MODULE_TABLE_SCHEMA	 module_name_str("maat.table_schema")

#define MAX_TABLE_LINE_SIZE  (1024 * 16)
#define	MAX_FOREIGN_CLMN_NUM 8
#define	MAX_CONJUNCTION_TABLE_NUM 8

struct expr_table_schema {
	int item_id_column;
    int group_id_column;
	int district_column;
	int keywords_column;
	int expr_type_column;
    int match_method_column;
    int is_hexbin_column;
	int is_valid_column;  /* valid means add, invalid means delete */
    enum hs_scan_mode scan_mode; /* adapter_hs scan mode */
};

struct ip_table_schema {
    int item_id_column;
    int group_id_column;
    int addr_type_column;
    int sip_column;
    int sip_mask_column;
    int sport_column;
    int sport_mask_column;
    int dip_column;
    int dip_mask_column;
    int dport_column;
    int dport_mask_column;
    int proto_column;
    int direction_column;
    int is_valid_column;
};

struct ip_plus_table_schema {
    int item_id_column;
    int group_id_column;
    int addr_type_column;
    int saddr_format_column;
    int sip1_column;
    int sip2_column;
    int sport_format_column;
    int sport1_column;
    int sport2_column;
    int daddr_format_column;
    int dip1_column;
    int dip2_column;
    int dport_format_column;
    int dport1_column;
    int dport2_column;
    int proto_column;
    int direction_column;
    int is_valid_column;
};

#define	MAX_PLUGIN_PER_TABLE 32
struct plugin_table_schema {
    int item_id_column;
    int key_column;
    int is_valid_column;
    int rule_tag_column;
    int n_foreign;
    int foreign_columns[MAX_FOREIGN_CLMN_NUM];
    size_t cb_plug_cnt;
    struct plugin_table_callback_schema cb_plug[MAX_PLUGIN_PER_TABLE];
    struct ex_data_schema ex_schema;
};

struct ip_plugin_table_schema {
    int item_id_column;
	int ip_type_column;
	int start_ip_column;
	int end_ip_column;
	int is_valid_column;
	int rule_tag_column;
	int have_exdata;
	struct ex_data_schema ex_schema;
};

struct virtual_table_schema {
	int physical_table_id[SCAN_TYPE_MAX];
};

struct composition_table_schema
{	
	int component_table_id[COMPOSITION_TYPE_MAX];
};

struct table_schema {
    int table_id;
    int conj_cnt;
    int updating_name;
    char table_name[MAX_CONJUNCTION_TABLE_NUM][NAME_MAX];
    enum table_type table_type;
    union {
        struct expr_table_schema expr;
        struct ip_table_schema ip;
        struct ip_plus_table_schema ip_plus;
        struct plugin_table_schema plugin;
        struct ip_plugin_table_schema ip_plugin;
        struct virtual_table_schema virtual_table;
        struct composition_table_schema composition;
    };
};

struct table_schema_manager {
    struct table_schema *schema_table[MAX_TABLE_NUM];
    size_t n_schema_table;
    size_t n_active_plugin_table;
    struct maat_kv_store *tablename2id_map;
    struct log_handle *logger;
};

struct table_schema *table_schema_new(void)
{
    struct table_schema *ptable = ALLOC(struct table_schema, 1);
    ptable->conj_cnt = 1;

    return ptable;
}

void table_schema_free(struct table_schema *ptable)
{
    FREE(ptable);
}

int read_expr_table_schema(cJSON *root, struct table_schema *ptable,
                            struct maat_kv_store* reserved_word_map,
                            struct log_handle *logger)
{
    int read_cnt = 0;
    cJSON *json = NULL;

    json = cJSON_GetObjectItem(root, "table_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->table_id = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "table_name");
    if (json != NULL && json->type == cJSON_String) {
        if (strlen(json->valuestring) >= NAME_MAX) {
            log_error(logger, MODULE_TABLE_SCHEMA, "expr table name %s length too long", 
                                                    json->valuestring);
            return -1;
        }
        memcpy(ptable->table_name[0], json->valuestring, strlen(json->valuestring));
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "scan_mode");
    if (json != NULL && json->type == cJSON_String) {
        int ret = maat_kv_read(reserved_word_map, json->valuestring, (int*)&(ptable->expr.scan_mode));
        if (ret < 0) {
            log_error(logger, MODULE_TABLE_SCHEMA, "scan_mode %s illegal", json->valuestring);
            return -1;
        }
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "item_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->expr.item_id_column = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "group_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->expr.group_id_column = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "custom");
    if (json == NULL || json->type != cJSON_Object) {
        log_error(logger, MODULE_TABLE_SCHEMA, "table %s has no custom column", 
                                                ptable->table_name[0]);
        return -1;
    }

    cJSON *item = cJSON_GetObjectItem(json, "keywords");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.keywords_column = item->valueint;
        read_cnt++;
    }

    if (ptable->table_type == TABLE_TYPE_EXPR_PLUS) {
        item = cJSON_GetObjectItem(json, "district");
        if (item != NULL && item->type == cJSON_Number) {
            ptable->expr.district_column = item->valueint;
            read_cnt++;
        }
    }

    item = cJSON_GetObjectItem(json, "expr_type");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.expr_type_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "match_method");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.match_method_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "is_hexbin");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.is_hexbin_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "is_valid");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.is_valid_column = item->valueint;
        read_cnt++;
    }

    if (read_cnt < 10) {
        return -1;
    }
    
    return 0;  
}
#if 0
int read_ip_table_schema(cJSON *root, struct table_schema *ptable, struct log_handle *logger)
{
     size_t read_cnt = 0;
    cJSON *json = NULL;

    json = cJSON_GetObjectItem(root, "table_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->table_id = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "table_name");
    if (json != NULL && json->type == cJSON_String) {
        if (strlen(json->valuestring) >= NAME_MAX) {
            log_error(logger, MODULE_TABLE_SCHEMA, "ip table name %s length too long", 
                                                    json->valuestring);
            return -1;
        }
        memcpy(ptable->table_name[0], json->valuestring, strlen(json->valuestring));
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "item_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->ip.item_id_column = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "group_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->ip.group_id_column = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "custom");
    if (NULL == json || json->type != cJSON_Object) {
        log_error(logger, MODULE_TABLE_SCHEMA, "ip table %s has no custom column", 
                                                ptable->table_name[0]);
        return -1;
    }

    cJSON *item = cJSON_GetObjectItem(json, "addr_type");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.addr_type_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "sip");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.sip_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "sip_mask");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.sip_mask_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "sport");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.sport_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "sport_mask");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.sport_mask_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "dip");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.dip_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "dip_mask");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.dip_mask_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "dport");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.dport_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "dport_mask");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.dport_mask_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "proto");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.proto_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "direction");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.direction_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "is_valid");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip.is_valid_column = item->valueint;
        read_cnt++;
    }

    if (read_cnt < 16) {
        return -1;
    }

    return 0;
}
#endif
int read_ip_plus_table_schema(cJSON *root, struct table_schema *ptable,
                              struct log_handle *logger)
{
     size_t read_cnt = 0;
    cJSON *json = NULL;

    json = cJSON_GetObjectItem(root, "table_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->table_id = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "table_name");
    if (json != NULL && json->type == cJSON_String) {
        if (strlen(json->valuestring) >= NAME_MAX) {
            log_error(logger, MODULE_TABLE_SCHEMA, "ip_plus table name %s length too long", 
                                                    json->valuestring);
            return -1;
        }
        memcpy(ptable->table_name[0], json->valuestring, strlen(json->valuestring));
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "item_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->ip_plus.item_id_column = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "group_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->ip_plus.group_id_column = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "custom");
    if (NULL == json || json->type != cJSON_Object) {
        log_error(logger, MODULE_TABLE_SCHEMA, "ip_plus table %s has no custom column", 
                                                ptable->table_name[0]);
        return -1;
    }

    cJSON *item = cJSON_GetObjectItem(json, "addr_type");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.addr_type_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "saddr_format");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.saddr_format_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "sip1");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.sip1_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "sip2");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.sip2_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "sport_format");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.sport_format_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "sport1");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.sport1_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "sport2");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.sport2_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "daddr_format");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.daddr_format_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "dip1");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.dip1_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "dip2");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.dip2_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "dport_format");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.dport_format_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "dport1");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.dport1_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "dport2");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.dport2_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "proto");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.proto_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "direction");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.direction_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "is_valid");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plus.is_valid_column = item->valueint;
        read_cnt++;
    }

    if (read_cnt < 20) {
        return -1;
    }

    return 0;
}

int read_virtual_table_schema(cJSON *root, struct table_schema **table_array, 
                              struct table_schema *ptable, 
                              struct maat_kv_store *tablename2id_map,
                              struct log_handle *logger)
{
    size_t read_cnt = 0;
    cJSON *json = NULL;

    json = cJSON_GetObjectItem(root, "table_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->table_id = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "table_name");
    if (json != NULL && json->type == cJSON_String) {
        if (strlen(json->valuestring) >= NAME_MAX) {
            log_error(logger, MODULE_TABLE_SCHEMA, "virtual table name %s length too long", 
                                                    json->valuestring);
            return -1;
        }
        memcpy(ptable->table_name[0], json->valuestring, strlen(json->valuestring));
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "physical_table");
    if (NULL == json || json->type != cJSON_Array) {
        log_error(logger, MODULE_TABLE_SCHEMA, "virtual table %s has no physical_table column", 
                                                ptable->table_name[0]);
        return -1;
    }
    read_cnt++;

    int cnt = cJSON_GetArraySize(json);
    for (int i = 0; i < cnt; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        if (item != NULL && item->type == cJSON_String) {
            int table_id = -1;
            /* physical table should already exist */
            int ret = maat_kv_read(tablename2id_map, item->valuestring, &table_id);
			if (ret < 0) {
				return -1;		
			}

            enum scan_type table_scan_type = table_schema_get_scan_type(table_array[table_id]);
            ptable->virtual_table.physical_table_id[table_scan_type]= table_id;
        }
    }

    if (read_cnt < 3) {
        return -1;
    }

    return 0;
}

int read_composition_table_schema(cJSON *root, struct table_schema *ptable, 
                                  struct maat_kv_store *tablename2id_map,
                                  struct log_handle *logger)
{
     size_t read_cnt = 0;
    cJSON *json = NULL;

    json = cJSON_GetObjectItem(root, "table_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->table_id = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "table_name");
    if (json != NULL && json->type == cJSON_String) {
        if (strlen(json->valuestring) >= NAME_MAX) {
            log_error(logger, MODULE_TABLE_SCHEMA, "composition table name %s length too long", 
                                                    json->valuestring);
            return -1;
        }
        memcpy(ptable->table_name[0], json->valuestring, strlen(json->valuestring));
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "composition_table");
    if (NULL == json || json->type != cJSON_Object) {
        log_error(logger, MODULE_TABLE_SCHEMA, "table %s has no composition_table column", 
                                                ptable->table_name[0]);
        return -1;
    }
    read_cnt++;

    int ret = 0;
    struct composition_table_schema *composition_schema = &(ptable->composition);
    cJSON *item = cJSON_GetObjectItem(json, "source");
    if (item != NULL && item->type == cJSON_String) {
        /* physical table should already exist */
        ret = maat_kv_read(tablename2id_map, item->valuestring, &composition_schema->component_table_id[COMPOSITION_TYPE_SIP]);
        if (ret < 0) {
            log_error(logger, MODULE_TABLE_SCHEMA, 
                      "Child table %s of table %s (id=%d) are not defined",
                      item->valuestring, ptable->table_name[0], ptable->table_id);
            return -1;
        }
    }

    item = cJSON_GetObjectItem(json, "dest");
    if (item != NULL && item->type == cJSON_String) {
        /* physical table should already exist */
        ret = maat_kv_read(tablename2id_map, item->valuestring, &composition_schema->component_table_id[COMPOSITION_TYPE_DIP]);
        if (ret < 0) {
            log_error(logger, MODULE_TABLE_SCHEMA, 
                      "Child table %s of table %s (id=%d) are not defined",
                      item->valuestring, ptable->table_name[0], ptable->table_id);
            return -1;
        }
    }

    item = cJSON_GetObjectItem(json, "session");
    if (item != NULL && item->type == cJSON_String) {
        /* physical table should already exist */
        ret = maat_kv_read(tablename2id_map, item->valuestring, &composition_schema->component_table_id[COMPOSITION_TYPE_SESSION]);
        if (ret < 0) {
            log_error(logger, MODULE_TABLE_SCHEMA, 
                      "Child table %s of table %s (id=%d) are not defined",
                      item->valuestring, ptable->table_name[0], ptable->table_id);
            return -1;
        }
    }

    if (read_cnt < 3) {
        return -1;
    }
    
    return 0;
}

static int read_integer_array(char *string, int *array, int size)
{
    int i = 0;
	char *token = NULL, *sub_token = NULL, *saveptr;
	
	for (i = 0, token = string; i < size; token= NULL, i++) {
		sub_token = strtok_r(token, ",", &saveptr);
		if (sub_token == NULL) {
            break;
        }
		
		sscanf(sub_token, "%d", array + i);
	}

	return i;
}

int read_plugin_table_schema(cJSON *root, struct table_schema *ptable, struct log_handle *logger)
{
    size_t read_cnt = 0;
    cJSON *json = NULL;

    json = cJSON_GetObjectItem(root, "table_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->table_id = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "table_name");
    if (json != NULL && json->type == cJSON_String) {
        if (strlen(json->valuestring) >= NAME_MAX) {
            log_error(logger, MODULE_TABLE_SCHEMA, "plugin table name %s length too long", 
                                                    json->valuestring);
            return -1;
        }
        memcpy(ptable->table_name[0], json->valuestring, strlen(json->valuestring));
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "item_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->plugin.item_id_column = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "custom");
    if (json == NULL || json->type != cJSON_Object) {
        log_error(logger, MODULE_TABLE_SCHEMA, "table %s has no custom column", 
                                                ptable->table_name[0]);
        return -1;
    }

    cJSON *item = cJSON_GetObjectItem(json, "key");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->plugin.key_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "is_valid");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->plugin.is_valid_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "tag");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->plugin.rule_tag_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "foreign");
    if (item != NULL) {
        read_cnt++;
        if (item->type == cJSON_String) {
            ptable->plugin.n_foreign = read_integer_array(item->valuestring, 
                                            ptable->plugin.foreign_columns, 
                                            MAX_FOREIGN_CLMN_NUM);
        } else if (item->type == cJSON_Array) {
            ptable->plugin.n_foreign = cJSON_GetArraySize(item);
            for (int i = 0; i < ptable->plugin.n_foreign; i++) {
                cJSON *foreign_item = cJSON_GetArrayItem(item, i);
                assert(foreign_item->type == cJSON_Number);
                ptable->plugin.foreign_columns[i] = foreign_item->valueint;
            }
        }
    }

    if (read_cnt < 7) {
        return -1;
    }
    
    return 0; 
}

int read_ip_plugin_table_schema(cJSON *root, struct table_schema *ptable, struct log_handle *logger)
{
    size_t read_cnt = 0;
    cJSON *json = NULL;

    json = cJSON_GetObjectItem(root, "table_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->table_id = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "table_name");
    if (json != NULL && json->type == cJSON_String) {
        if (strlen(json->valuestring) >= NAME_MAX) {
            log_error(logger, MODULE_TABLE_SCHEMA, "ip_plugin table name %s length too long", 
                                                    json->valuestring);
            return -1;
        }
        memcpy(ptable->table_name[0], json->valuestring, strlen(json->valuestring));
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "item_id");
    if (json != NULL && json->type == cJSON_Number) {
        ptable->ip_plugin.item_id_column = json->valueint;
        read_cnt++;
    }

    json = cJSON_GetObjectItem(root, "custom");
    if (NULL == json || json->type != cJSON_Object) {
        log_error(logger, MODULE_TABLE_SCHEMA, "table %s has no custom column", 
                                                ptable->table_name[0]);
        return -1;
    }

    cJSON *item = cJSON_GetObjectItem(json, "ip_type");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plugin.ip_type_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "start_ip");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plugin.start_ip_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "end_ip");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plugin.end_ip_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "is_valid");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plugin.is_valid_column = item->valueint;
        read_cnt++;
    }

    if (read_cnt < 7) {
        return -1;
    }
    
    return 0;
}

int table_schema_populate(cJSON *json, struct table_schema **table_array, 
                          struct table_schema *ptable,
                          struct maat_kv_store *reserved_word_map, 
                          struct maat_kv_store *tablename2id_map,
                          struct log_handle *logger)
{
    int ret = -1;
    cJSON *item = NULL;

    item = cJSON_GetObjectItem(json, "table_type");
    if (item != NULL && item->type == cJSON_String) {
        ret = maat_kv_read(reserved_word_map, item->valuestring, (int*)&(ptable->table_type));
        if (ret < 0) {
            log_error(logger, MODULE_TABLE_SCHEMA, "table_type %s is illegal", 
                                                    item->valuestring);
            return -1;
        }
    }
   
    switch (ptable->table_type) {
    case TABLE_TYPE_EXPR:
    case TABLE_TYPE_EXPR_PLUS:
        ret = read_expr_table_schema(json, ptable, reserved_word_map, logger);
        if (ret < 0) {
            return -1;
        }
        break;
    /* TODO: delete
    case TABLE_TYPE_IP:
        ret = read_ip_table_schema(json, ptable);
        if (ret < 0) {
            return -1;
        }
        break; */
    case TABLE_TYPE_IP_PLUS:
        ret = read_ip_plus_table_schema(json, ptable, logger);
        if (ret < 0) {
            return -1;
        }
        break;
    case TABLE_TYPE_PLUGIN:
        ret = read_plugin_table_schema(json, ptable, logger);
        if (ret < 0) {
            return -1;
        }
        break;
    case TABLE_TYPE_IP_PLUGIN:
        ret = read_ip_plugin_table_schema(json, ptable, logger);
        if (ret < 0) {
            return -1;
        }
        break;
    case TABLE_TYPE_VIRTUAL:
        ret = read_virtual_table_schema(json, table_array, ptable, tablename2id_map, logger);
        if (ret < 0) {
            return -1;
        }
        break;
    case TABLE_TYPE_COMPOSITION:
        ret = read_composition_table_schema(json, ptable, tablename2id_map, logger);
        if (ret < 0) {
            return -1;
        }
        break;
    default:
        break;
    }
    
    return 0;
}

struct table_schema_manager *
table_schema_manager_create(const char *table_info_path, struct log_handle *logger)
{
    unsigned char *json_buff = NULL;
    size_t json_buff_sz = 0;

    if (NULL == table_info_path) {
        return NULL;
    }

    int ret = load_file_to_memory(table_info_path, &json_buff, &json_buff_sz);
    if (ret < 0) {
        log_error(logger, MODULE_TABLE_SCHEMA, "Maat read table info %s error.", table_info_path);
        return NULL;
    }

    cJSON *root = NULL;
    root = cJSON_Parse((const char *)json_buff);
	if (!root) {
        log_error(logger, MODULE_TABLE_SCHEMA, "Error before: %-200.200s", cJSON_GetErrorPtr());
        FREE(json_buff);
        return NULL;
    }

    int json_array_size = cJSON_GetArraySize(root);
    if (json_array_size <= 0) {
        log_error(logger, MODULE_TABLE_SCHEMA, "invalid json content in %s", table_info_path);
        free(json_buff);
        return NULL;
    }
    
    struct maat_kv_store* reserved_word_map = maat_kv_store_new();
    /* register table type reserved word */
    maat_kv_register(reserved_word_map, "expr", TABLE_TYPE_EXPR);
    maat_kv_register(reserved_word_map, "expr_plus", TABLE_TYPE_EXPR_PLUS);
    //maat_kv_register(reserved_word_map, "ip", TABLE_TYPE_IP);
    maat_kv_register(reserved_word_map, "ip_plus", TABLE_TYPE_IP_PLUS);
    maat_kv_register(reserved_word_map, "plugin", TABLE_TYPE_PLUGIN);
    maat_kv_register(reserved_word_map, "ip_plugin", TABLE_TYPE_IP_PLUGIN);
    maat_kv_register(reserved_word_map, "virtual", TABLE_TYPE_VIRTUAL);
    maat_kv_register(reserved_word_map, "composition", TABLE_TYPE_COMPOSITION);

    maat_kv_register(reserved_word_map, "block", HS_SCAN_MODE_BLOCK);
    maat_kv_register(reserved_word_map, "stream", HS_SCAN_MODE_STREAM);

    struct table_schema_manager *table_schema_mgr = ALLOC(struct table_schema_manager, 1);
    table_schema_mgr->logger = logger;
    struct table_schema **table_array = table_schema_mgr->schema_table;
    table_schema_mgr->tablename2id_map = maat_kv_store_new();

    struct table_schema *conj_table = NULL;
    for (int i = 0; i < json_array_size; i++) {
        cJSON *json = cJSON_GetArrayItem(root, i);
       
        if (json != NULL && json->type == cJSON_Object) {
            struct table_schema *ptable = table_schema_new();
            int ret = table_schema_populate(json, table_array, ptable, reserved_word_map, 
                                            table_schema_mgr->tablename2id_map, logger);
            if (ret < 0) {
                log_error(logger, MODULE_TABLE_SCHEMA, 
                          "Maat populate table info error, table_id:%d", ptable->table_id);
                goto free_table;
            }

            if (ptable->table_id >= MAX_TABLE_NUM) {
                log_error(logger, MODULE_TABLE_SCHEMA, 
                          "Maat read table info %s:%d error: table id %u > %d",
                          table_info_path, i, ptable->table_id, MAX_TABLE_NUM);
                goto free_table;
            }

            ret = maat_kv_register(table_schema_mgr->tablename2id_map, ptable->table_name[0], ptable->table_id);
            if (ret < 0) {
                log_error(logger, MODULE_TABLE_SCHEMA, 
                          "Duplicate table %s of table id %d", 
                          ptable->table_name[0], ptable->table_id);
                goto free_table;
            }

            if (table_array[ptable->table_id] != NULL) {
                conj_table = table_array[ptable->table_id];
                if (conj_table->conj_cnt == MAX_CONJUNCTION_TABLE_NUM) {
                    log_error(logger, MODULE_TABLE_SCHEMA, 
                              "Maat read table info %s error: reach table_id %d conjunction upper limit",
                              table_info_path, ptable->table_id);
                    goto free_table;
                }
                memcpy(conj_table->table_name[conj_table->conj_cnt], ptable->table_name[0], NAME_MAX);
                conj_table->conj_cnt++;
                log_info(logger, MODULE_TABLE_SCHEMA, 
                         "Maat read table info %s: conjunction %s with %s (id=%d,total=%d)",
                         table_info_path, ptable->table_name[0], conj_table->table_name[0],
                         conj_table->table_id, conj_table->conj_cnt);
                goto free_table;
            }

            table_array[ptable->table_id] = ptable;
            table_schema_mgr->n_schema_table++;
            continue;
        free_table:
            table_schema_free(ptable);
            ptable = NULL;
        }
    }
	
    maat_kv_store_free(reserved_word_map);
    FREE(json_buff);

    return table_schema_mgr;
}

void table_schema_manager_destroy(struct table_schema_manager *table_schema_mgr)
{
    if (NULL == table_schema_mgr) {
        return;
    }

	for (size_t i = 0; i < MAX_TABLE_NUM; i++) {
		if (NULL == table_schema_mgr->schema_table[i]) {
			continue;
		}
		table_schema_free(table_schema_mgr->schema_table[i]);
		table_schema_mgr->schema_table[i] = NULL;
	}

	maat_kv_store_free(table_schema_mgr->tablename2id_map);
	FREE(table_schema_mgr);
}

int table_schema_manager_get_table_id(struct table_schema_manager* table_schema_mgr, const char *table_name)
{
    if (NULL == table_schema_mgr || NULL == table_name) {
        return -1;
    }

    int table_id = -1;

	int ret = maat_kv_read(table_schema_mgr->tablename2id_map, table_name, &table_id);
	if (ret > 0) {
		return table_id;
	} else {
		return -1;
	}
}

int table_schema_manager_get_child_table_id(struct table_schema_manager *table_schema_mgr, int parent_table_id, 
                                            enum table_composition_type type)
{
	struct table_schema* table_schema = table_schema_get(table_schema_mgr, parent_table_id);
	if (table_schema->table_type != TABLE_TYPE_COMPOSITION) {
		return -1;
	}

	return table_schema->composition.component_table_id[type];
}

enum table_type table_schema_manager_get_table_type(struct table_schema_manager *table_schema_mgr, int id)
{
    if (NULL == table_schema_mgr) {
        return TABLE_TYPE_MAX;
    }

    if (table_schema_mgr->schema_table[id] == NULL) {
        return TABLE_TYPE_MAX;
    }

    return table_schema_mgr->schema_table[id]->table_type;
}

size_t table_schema_manager_get_size(struct table_schema_manager* table_schema_mgr)
{
    return MAX_TABLE_NUM;
}

void table_schema_manager_all_plugin_cb_start(struct table_schema_manager *table_schema_mgr, int update_type)
{
    if (NULL == table_schema_mgr) {
        return;
    }

    struct table_schema *ptable = NULL;
    struct plugin_table_schema *plugin_schema = NULL;

    for (size_t i = 0; i < MAX_TABLE_NUM; i++) {
		ptable = table_schema_mgr->schema_table[i];
        if (NULL == ptable) {
            continue;
        }

		plugin_schema = &(ptable->plugin);
		if (ptable->table_type != TABLE_TYPE_PLUGIN || 0 == plugin_schema->cb_plug_cnt) {
			continue;
		}

		table_schema_mgr->n_active_plugin_table++;
		for (size_t j = 0; j < plugin_schema->cb_plug_cnt; j++) {
			if (plugin_schema->cb_plug[j].start != NULL) {
				plugin_schema->cb_plug[j].start(update_type, plugin_schema->cb_plug[j].u_para);
			}
		}
	}
}

void table_schema_manager_all_plugin_cb_finish(struct table_schema_manager* table_schema_mgr)
{
    if (NULL == table_schema_mgr) {
        return;
    }

    struct table_schema *ptable = NULL;
    struct plugin_table_schema *plugin_schema = NULL;

    for (size_t i = 0; i < MAX_TABLE_NUM; i++) {
        ptable = table_schema_mgr->schema_table[i];
        if (NULL == ptable) {
            continue;
        }
        
        if (ptable->table_type != TABLE_TYPE_PLUGIN) {
            continue;
        }

        plugin_schema = &(ptable->plugin);
        for (size_t j = 0; j < plugin_schema->cb_plug_cnt; j++) {
            if (plugin_schema->cb_plug[j].finish != NULL) {
                plugin_schema->cb_plug[j].finish(plugin_schema->cb_plug[j].u_para);
            }
        }
    }
    table_schema_mgr->n_active_plugin_table = 0;
}

enum expr_type int_to_expr_type(int expr_type)
{
    enum expr_type type = EXPR_TYPE_MAX;

    switch (expr_type) {
    case 0:
        type = EXPR_TYPE_STRING;
        break;
    case 1:
        type = EXPR_TYPE_AND;
        break;
    case 2:
        type = EXPR_TYPE_REGEX;
        break;
    default:
        break;
    }

    return type;
}

enum match_method int_to_match_method_type(int match_method_type)
{
    enum match_method type = MATCH_METHOD_MAX;

    switch (match_method_type) {
    case 0:
        type = MATCH_METHOD_SUB;
        break;
    case 1:
        type = MATCH_METHOD_RIGHT;
        break;
    case 2:
        type = MATCH_METHOD_LEFT;
        break;
    case 3:
        type = MATCH_METHOD_COMPLETE;
        break;
    default:
        break;
    }

    return type;
}

struct table_schema *table_schema_get(struct table_schema_manager *table_schema_mgr, int table_id)
{
    if ((NULL == table_schema_mgr) || (table_id < 0)) {
        return NULL;
    }

    return table_schema_mgr->schema_table[table_id];
}

struct table_schema *table_schema_get_by_scan_type(struct table_schema_manager *table_schema_mgr, 
                                                   int table_id, enum scan_type scan_type, int *virtual_table_id)
{
    enum scan_type table_scan_type;
	struct table_schema **pptable = table_schema_mgr->schema_table;
	size_t n_table = MAX_TABLE_NUM;

	if ((unsigned int)table_id > n_table) {
		return NULL;
	}

	if (NULL == pptable[table_id]) {
		return NULL;
	}

	struct table_schema *ptable = pptable[table_id];
	if (NULL == ptable) {
		return NULL;
	}

    struct table_schema *p_physical_table = NULL;
	if (ptable->table_type == TABLE_TYPE_VIRTUAL) {
		p_physical_table = pptable[ptable->virtual_table.physical_table_id[scan_type]];
		*virtual_table_id = table_id;
	} else {
		p_physical_table = ptable;
		if(virtual_table_id) {
            *virtual_table_id = 0;
        }
	}

	table_scan_type = table_schema_get_scan_type(p_physical_table);
	if (table_scan_type != scan_type) {
			return NULL;	
	}

	return p_physical_table;
}

enum table_type table_schema_get_table_type(struct table_schema *table_schema)
{
    if (NULL == table_schema) {
        return TABLE_TYPE_MAX;
    }   

    return table_schema->table_type;
}

int table_schema_get_table_id(struct table_schema *table_schema)
{
    if (NULL == table_schema) {
        return -1;
    }

    return table_schema->table_id;
}

enum scan_type table_schema_get_scan_type(struct table_schema *table_schema)
{
    enum scan_type ret = SCAN_TYPE_INVALID;

    if (NULL == table_schema) {
        return ret;
    }

	switch (table_schema->table_type) {
		case TABLE_TYPE_EXPR:
		case TABLE_TYPE_EXPR_PLUS:
		case TABLE_TYPE_SIMILARITY:
		case TABLE_TYPE_DIGEST:
			ret = SCAN_TYPE_STRING;
			break;
		case TABLE_TYPE_INTERVAL:
		case TABLE_TYPE_INTERVAL_PLUS:
			ret = SCAN_TYPE_INTERVAL;
			break;
		//case TABLE_TYPE_IP:
		case TABLE_TYPE_IP_PLUS:
		case TABLE_TYPE_COMPOSITION:
			ret = SCAN_TYPE_IP;
			break;
		case TABLE_TYPE_PLUGIN:
			ret = SCAN_TYPE_PLUGIN;
			break;
		case TABLE_TYPE_IP_PLUGIN:
			ret = SCAN_TYPE_IP;
			break;
		case TABLE_TYPE_FQDN_PLUGIN:
			ret = SCAN_TYPE_FQDN_PLUGIN;
			break;
		case TABLE_TYPE_BOOL_PLUGIN:
			ret = SCAN_TYPE_BOOL_PLUGIN;
			break;
		case TABLE_TYPE_COMPILE:			
			ret = SCAN_TYPE_NONE;
			break;
		default:
			break;
	}

	return ret;
}

int table_schema_get_valid_flag_column(struct table_schema *table_schema)
{
	int valid_flag_column = -1;

    if (NULL == table_schema) {
        return valid_flag_column;
    }

	switch (table_schema->table_type) {
        case TABLE_TYPE_EXPR:
            valid_flag_column = table_schema->expr.is_valid_column;
            break;
		case TABLE_TYPE_PLUGIN:
			valid_flag_column = table_schema->plugin.is_valid_column;
			break;
		case TABLE_TYPE_IP_PLUGIN:
			valid_flag_column = table_schema->ip_plugin.is_valid_column;
			break;
            /*
		case TABLE_TYPE_FQDN_PLUGIN:
			valid_flag_column = table_schema->fqdn_plugin.valid_flag_column;
			break;
		case TABLE_TYPE_BOOL_PLUGIN:
			valid_flag_column = table_schema->bool_plugin.valid_flag_column;
			break;*/
		default:
			valid_flag_column = -1;
			break;
	}

	return valid_flag_column;
}

void table_schema_set_updating_name(struct table_schema *table_schema, const char *table_name)
{
    if (NULL == table_schema) {
        return;
    }
    
    int i = 0;
	for (i = 0; i < table_schema->conj_cnt; i++) {
		if (0 == strcmp(table_schema->table_name[i], table_name)) {
			table_schema->updating_name = i;
		}
	}
	assert(i <= table_schema->conj_cnt);
}

int populate_expr_table_item(const char *line, struct expr_table_schema *expr_schema, 
                             struct table_item *table_item, const char *table_name,
                             struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    struct expr_item *expr_item = &(table_item->expr_item);

    int ret = get_column_pos(line, expr_schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    expr_item->item_id = atoi(line + column_offset);

    ret = get_column_pos(line, expr_schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    expr_item->group_id = atoi(line + column_offset);

    if (table_item->table_type == TABLE_TYPE_EXPR_PLUS) {
        ret = get_column_pos(line, expr_schema->district_column, &column_offset, &column_len);
        if (ret < 0) {
            return -1;
        }

        if (column_len >= MAX_DISTRICT_STR) {
            log_error(logger, MODULE_TABLE_SCHEMA, 
                      "update error: expr table[%s]:item_id[%d] district length too long",
                      table_name, expr_item->item_id);
            return -1;
        }
        memcpy(expr_item->district, (line + column_offset), column_len);
    }

    ret = get_column_pos(line, expr_schema->keywords_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }

    if (column_len >= MAX_KEYWORDS_STR) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                      "update error: expr table[%s]:item_id[%d] keywords length too long",
                      table_name, expr_item->item_id);
        return -1;
    }
    memcpy(expr_item->keywords, (line + column_offset), column_len);

    ret = get_column_pos(line, expr_schema->expr_type_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    
    int expr_type = atoi(line + column_offset);
    expr_item->expr_type = int_to_expr_type(expr_type);

    ret = get_column_pos(line, expr_schema->match_method_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    
    int match_method_type = atoi(line + column_offset);
    expr_item->match_method = int_to_match_method_type(match_method_type);

    ret = get_column_pos(line, expr_schema->is_hexbin_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    int db_hexbin = atoi(line + column_offset);
    switch (db_hexbin) {
        case 0:
            expr_item->is_hexbin = FALSE;
            expr_item->is_case_sensitive = FALSE;
            break;
        case 1:
            expr_item->is_hexbin = TRUE;
            expr_item->is_case_sensitive = TRUE;
            break;
        case 2:
            expr_item->is_hexbin = FALSE;
            expr_item->is_case_sensitive = TRUE;
            break;
        default:
            log_error(logger, MODULE_TABLE_SCHEMA, 
                      "update error: expr table[%s]:item_id[%d] invalid hexbin value:%d",
                      table_name, expr_item->item_id, db_hexbin);
            return -1;
    }
    ret = get_column_pos(line, expr_schema->is_valid_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    expr_item->is_valid = atoi(line + column_offset);
    
    return 0;
}

int populate_ip_plus_table_item(const char *line, struct ip_plus_table_schema *ip_plus_schema, 
                           struct table_item *table_item, const char *table_name,
                           struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    struct ip_plus_item *ip_plus_item = &(table_item->ip_plus_item);
    
    int ret = get_column_pos(line, ip_plus_schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    ip_plus_item->item_id = atoi(line + column_offset);

    ret = get_column_pos(line, ip_plus_schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    ip_plus_item->group_id = atoi(line + column_offset);

    ret = get_column_pos(line, ip_plus_schema->addr_type_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    ip_plus_item->addr_type = atoi(line + column_offset);
    if (ip_plus_item->addr_type != 4 && ip_plus_item->addr_type != 6) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "update error: ip_plus table[%s]:item_id[%d] invalid addr type:%d",
                  table_name, ip_plus_item->item_id, ip_plus_item->addr_type);
        return -1;
    }

    char saddr_format[16] = {0};
    char sport_format[16] = {0};
    char sip1_str[40] = {0};
    char sip2_str[40] = {0};
    uint16_t sport1 = 0;
    uint16_t sport2 = 0;

    ret = get_column_pos(line, ip_plus_schema->saddr_format_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    memcpy(saddr_format, (line + column_offset), column_len);
    if (IP_FORMAT_UNKNOWN == ip_format_str2int(saddr_format)) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "update error: ip_plus table[%s]:item_id[%d] invalid saddr_format, should be range/mask/CIDR",
                  table_name, ip_plus_item->item_id);
        return -1;
    }

    ret = get_column_pos(line, ip_plus_schema->sip1_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    memcpy(sip1_str, (line + column_offset), column_len);

    ret = get_column_pos(line, ip_plus_schema->sip2_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    memcpy(sip2_str, (line + column_offset), column_len);

    ret = get_column_pos(line, ip_plus_schema->sport_format_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    memcpy(sport_format, (line + column_offset), column_len);
    if (IP_FORMAT_UNKNOWN == ip_format_str2int(sport_format)) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "update error: ip_plus table[%s]:item_id[%d] invalid sport_format, should be range/mask/CIDR",
                  table_name, ip_plus_item->item_id);
        return -1;
    }

    ret = get_column_pos(line, ip_plus_schema->sport1_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    sport1 = atoi(line + column_offset);

    ret = get_column_pos(line, ip_plus_schema->sport2_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    sport2 = atoi(line + column_offset);

    uint16_t protocol = 0;
    uint16_t direction = 0;
    if (4 == ip_plus_item->addr_type) {
        ret = ip_format2range(ip_plus_item->addr_type, ip_format_str2int(saddr_format), sip1_str, sip2_str, 
                              &ip_plus_item->ipv4.min_sip, &ip_plus_item->ipv4.max_sip);
        if (ret < 0) {
            return -1;
        }

        if(IP_FORMAT_MASK == ip_format_str2int(sport_format)) {
            ip_plus_item->ipv4.min_sport = sport1 & sport2;
            ip_plus_item->ipv4.max_sport = sport1 | ~sport2;
        } else {
            ip_plus_item->ipv4.min_sport = sport1;
			ip_plus_item->ipv4.max_sport = sport2;
        }

        ret = get_column_pos(line, ip_plus_schema->proto_column, &column_offset, &column_len);
        if (ret < 0) {
            return -1;
        }
        ip_plus_item->ipv4.proto = atoi(line + column_offset);
        protocol = ip_plus_item->ipv4.proto;

        ret = get_column_pos(line, ip_plus_schema->direction_column, &column_offset, &column_len);
        if (ret < 0) {
            return -1;
        }
        ip_plus_item->ipv4.direction = atoi(line + column_offset);
        direction = ip_plus_item->ipv4.direction;
    } else {
        //ipv6
        ret = ip_format2range(ip_plus_item->addr_type, IP_FORMAT_MASK, sip1_str, sip2_str, 
                              ip_plus_item->ipv6.min_sip, ip_plus_item->ipv6.max_sip);
        if (ret < 0) {
            return -1;
        }

        if(IP_FORMAT_MASK == ip_format_str2int(sport_format)) {
            ip_plus_item->ipv6.min_sport = sport1 & sport2;
            ip_plus_item->ipv6.max_sport = sport1 | ~sport2;
        } else {
            ip_plus_item->ipv6.min_sport = sport1;
			ip_plus_item->ipv6.max_sport = sport2;
        }

        ret = get_column_pos(line, ip_plus_schema->proto_column, &column_offset, &column_len);
        if (ret < 0) {
            return -1;
        }
        ip_plus_item->ipv6.proto = atoi(line + column_offset);
        protocol = ip_plus_item->ipv6.proto;

        ret = get_column_pos(line, ip_plus_schema->direction_column, &column_offset, &column_len);
        if (ret < 0) {
            return -1;
        }
        ip_plus_item->ipv6.direction = atoi(line + column_offset);
        direction = ip_plus_item->ipv6.direction;
    }

    if (protocol > 65535 || protocol < 0) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "update error: ip_plus table[%s]:item_id[%d] invalid protocol:%d",
                  table_name, ip_plus_item->item_id, protocol);
        return -1;
    }

    if (direction != 0 && direction != 1) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "update error: ip_plus table[%s]:item_id[%d] invalid direction:%d",
                  table_name, ip_plus_item->item_id, direction);
        return -1;
    }

    ret = get_column_pos(line, ip_plus_schema->is_valid_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    ip_plus_item->is_valid = atoi(line + column_offset);

    return 0;
}

int populate_plugin_table_item(const char *line, struct plugin_table_schema *plugin_schema, 
                               struct table_item *table_item, const char *table_name,
                               struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    struct plugin_item *plugin_item = &(table_item->plugin_item);

    int ret = get_column_pos(line, plugin_schema->key_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }

    if (column_len > MAX_KEYWORDS_STR) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "update error: plugin table[%s]: key:%s length:%zu too long, exceed %d",
                  table_name, (line + column_offset), column_len, MAX_KEYWORDS_STR);
        return -1;
    }
    memcpy(plugin_item->key, (line + column_offset), column_len);
    plugin_item->key_len = column_len;

    ret = get_column_pos(line, plugin_schema->is_valid_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    plugin_item->is_valid = atoi(line + column_offset);

    return 0;
}

int populate_ip_plugin_table_item(const char *line, struct ip_plugin_table_schema *ip_plugin_schema, 
                                  struct table_item *table_item, const char *table_name,
                                  struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    struct ip_plugin_item *ip_plugin_item = &(table_item->ip_plugin_item);
    
    int ret = get_column_pos(line, ip_plugin_schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    ip_plugin_item->item_id = atoi(line + column_offset);

    ret = get_column_pos(line, ip_plugin_schema->is_valid_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "update error: ip_plugin table[%s]:item_id[%d] not found is_valid value",
                  table_name, ip_plugin_item->item_id);
        return -1;
    }
    ip_plugin_item->is_valid = atoi(line + column_offset);

    ret = get_column_pos(line, ip_plugin_schema->ip_type_column, &column_offset, &column_len);
    if (ret < 0) {
        return -1;
    }
    ip_plugin_item->ip_type = atoi(line + column_offset);
    if (ip_plugin_item->ip_type != 4 && ip_plugin_item->ip_type != 6) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "update error: ip_plugin table[%s]:item_id[%d] ip_type[%d] invalid",
                  table_name, ip_plugin_item->item_id, ip_plugin_item->ip_type);
        return -1;
    }

    ret = get_column_pos(line, ip_plugin_schema->start_ip_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "update error: ip_plugin table[%s]:item_id[%d] no found start_ip value",
                  table_name, ip_plugin_item->item_id, ip_plugin_item->start_ip);
        return -1;
    }
    strncpy(ip_plugin_item->start_ip, line + column_offset, MIN(column_len, sizeof(ip_plugin_item->start_ip)));
    
    ret = get_column_pos(line, ip_plugin_schema->end_ip_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "update error: ip_plugin table[%s]:item_id[%d] no found end_ip value",
                  table_name, ip_plugin_item->item_id, ip_plugin_item->end_ip);
        return -1;
    }
    strncpy(ip_plugin_item->end_ip, line + column_offset, MIN(column_len, sizeof(ip_plugin_item->end_ip)));

    return 0;
}

struct table_item *
table_schema_line_to_item(const char *line, struct table_schema *table_schema, struct log_handle *logger)
{
    if (NULL == line || NULL == table_schema) {
        return NULL;
    }

    int ret = -1;
    struct table_item *table_item = ALLOC(struct table_item, 1);

    switch (table_schema->table_type) {
    case TABLE_TYPE_EXPR:
    case TABLE_TYPE_EXPR_PLUS:
        table_item->table_type = table_schema->table_type;
        ret = populate_expr_table_item(line, &table_schema->expr, table_item,
                                       table_schema->table_name[table_schema->updating_name], logger);
        if (ret < 0) {
            log_error(logger, MODULE_TABLE_SCHEMA, 
                      "abandon config: invalid format of expr table %s:%s",
                      table_schema->table_name[table_schema->updating_name], line);
            goto error;
        }
        break;
    case TABLE_TYPE_IP_PLUS:
        table_item->table_type = table_schema->table_type;
        ret = populate_ip_plus_table_item(line, &table_schema->ip_plus, table_item,
                                          table_schema->table_name[table_schema->updating_name], logger);
        if (ret < 0) {
            log_error(logger, MODULE_TABLE_SCHEMA, 
                      "abandon config: invalid format of ip_plus table %s:%s",
                      table_schema->table_name[table_schema->updating_name], line);
            goto error;
        }
        break;
    case TABLE_TYPE_PLUGIN:
        table_item->table_type = TABLE_TYPE_PLUGIN;
        ret = populate_plugin_table_item(line, &table_schema->plugin, table_item,
                                         table_schema->table_name[table_schema->updating_name], logger);
        if (ret < 0) {
            log_error(logger, MODULE_TABLE_SCHEMA, 
                      "abandon config: invalid format of plugin table %s:%s",
                      table_schema->table_name[table_schema->updating_name], line);
            goto error;
        }
        break;
    case TABLE_TYPE_IP_PLUGIN:
        table_item->table_type = TABLE_TYPE_IP_PLUGIN;
        ret = populate_ip_plugin_table_item(line, &table_schema->ip_plugin, table_item,
                                            table_schema->table_name[table_schema->updating_name], logger);
        if (ret < 0) {
            log_error(logger, MODULE_TABLE_SCHEMA, 
                      "abandon config: invalid format of ip_plugin table %s:%s",
                      table_schema->table_name[table_schema->updating_name], line);
            goto error;
        }
        break;
    default:
        break;
    }
    return table_item;
error:
    FREE(table_item);
    return NULL;
}

enum hs_scan_mode expr_table_schema_get_scan_mode(struct table_schema *table_schema)
{
    if (NULL == table_schema) {
        return HS_SCAN_MODE_MAX;
    }

    if (table_schema->table_type != TABLE_TYPE_EXPR) {
        return HS_SCAN_MODE_MAX;
    }

    return table_schema->expr.scan_mode;
}

int plugin_table_schema_set_ex_data_schema(struct table_schema *table_schema,
									        maat_plugin_ex_new_func_t *new_func,
									        maat_plugin_ex_free_func_t *free_func,
									        maat_plugin_ex_dup_func_t *dup_func,
									        long argl, void *argp,
                                            struct log_handle *logger)
{
    if (NULL == table_schema || NULL == new_func || NULL == free_func || NULL == dup_func) {
        assert(0);
        log_error(logger, MODULE_TABLE_SCHEMA, "%s failed: invalid parameter", __FUNCTION__);
        return -1;
    }

    struct ex_data_schema *ex_schema = plugin_table_schema_get_ex_data_schema(table_schema);
    if (NULL == ex_schema) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "Error: %s, target table is not a valid plugin table", __FUNCTION__);
        return -1;
    }

    if (ex_schema->set_flag) {
        assert(0);
        log_error(logger, MODULE_TABLE_SCHEMA, "Error: %s, EX data schema already registed", 
                                                __FUNCTION__);
        return -1;
    }

    ex_schema->new_func = new_func;
    ex_schema->free_func = free_func;
    ex_schema->dup_func = dup_func;
    ex_schema->argl = argl;
    ex_schema->argp = argp;
    ex_schema->set_flag = 1;

    return 0;
}

struct ex_data_schema *plugin_table_schema_get_ex_data_schema(struct table_schema *table_schema)
{
    if (NULL == table_schema) {
        return NULL;
    }

    struct ex_data_schema *ex_schema = NULL;

    switch (table_schema->table_type) {
        case TABLE_TYPE_PLUGIN:
            ex_schema = &(table_schema->plugin.ex_schema);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ex_schema = &(table_schema->ip_plugin.ex_schema);
            break;
        default:
            break;
    }

    return ex_schema;
}

int plugin_table_schema_ex_data_schema_flag(struct table_schema *table_schema)
{
    if (NULL == table_schema) {
        return -1;
    }

    struct ex_data_schema *ex_schema = NULL;

    switch (table_schema->table_type) {
        case TABLE_TYPE_PLUGIN:
            ex_schema = &(table_schema->plugin.ex_schema);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ex_schema = &(table_schema->ip_plugin.ex_schema);
            break;
        default:
            break;
    }

    return ex_schema->set_flag;
}

int plugin_table_schema_add_callback(struct table_schema_manager* table_schema_mgr, int table_id,
							         maat_start_callback_t *start,
							         maat_update_callback_t *update,
							         maat_finish_callback_t *finish,
							         void *u_para, struct log_handle *logger)
{
    if ((NULL == table_schema_mgr) || (table_id < 0)) {
        return -1;
    }

	struct table_schema *ptable = table_schema_get(table_schema_mgr, table_id);
    if (NULL == ptable) {
        log_error(logger, MODULE_TABLE_SCHEMA, 
                  "table_id:%d unregistered, can't add callback func", table_id);
		return -1;
	}

    switch (ptable->table_type) {
        case TABLE_TYPE_EXPR:
        case TABLE_TYPE_EXPR_PLUS:
        case TABLE_TYPE_IP_PLUS:
            log_error(logger, MODULE_TABLE_SCHEMA, "table_id: %d is not plugin type", table_id);
            return -1;
        default:
            break;
    }

	struct plugin_table_schema *plugin_schema = &(ptable->plugin);
	size_t idx = plugin_schema->cb_plug_cnt;
	if (idx == MAX_PLUGIN_PER_TABLE) {
        log_error(logger, MODULE_TABLE_SCHEMA, "the plugin number of table_id: %d exceed maxium:%d", 
                                                ptable->table_id, MAX_PLUGIN_PER_TABLE);
		return -1;
	}

	plugin_schema->cb_plug_cnt++;
	plugin_schema->cb_plug[idx].start = start;
	plugin_schema->cb_plug[idx].update = update;
	plugin_schema->cb_plug[idx].finish = finish;
	plugin_schema->cb_plug[idx].u_para = u_para;

	return 0;
}

size_t plugin_table_schema_callback_count(struct table_schema *table_schema)
{
    if (NULL == table_schema) {
        return 0;
    }

    if (table_schema->table_type == TABLE_TYPE_PLUGIN) {
        return table_schema->plugin.cb_plug_cnt;
    } else {
        return 0;
    }
}

void plugin_table_schema_all_cb_update(struct table_schema* table_schema, const char *row)
{
    if (NULL == table_schema || NULL == row) {
        return;
    }

    struct plugin_table_schema *plugin_schema = NULL;

    switch (table_schema->table_type) {
        case TABLE_TYPE_EXPR:
        case TABLE_TYPE_EXPR_PLUS:
        case TABLE_TYPE_IP_PLUGIN:
            break;
        case TABLE_TYPE_PLUGIN:
            plugin_schema = &(table_schema->plugin);
            if (plugin_schema->cb_plug_cnt > 0) {
                for (size_t i = 0; i < plugin_schema->cb_plug_cnt; i++) {
                    plugin_schema->cb_plug[i].update(table_schema->table_id, row, plugin_schema->cb_plug[i].u_para);
                }
            }
            break;
       default:
            break;
    }
}

int plugin_table_schema_get_foreign_column(struct table_schema *table_schema, int *foreign_columns)
{
    if (NULL == table_schema) {
        return -1;
    }

    if (table_schema->table_type != TABLE_TYPE_PLUGIN) {
        return 0;
    }

    int n_foreign = table_schema->plugin.n_foreign;
    for (int i = 0; i < n_foreign; i++) {
        foreign_columns[i] = table_schema->plugin.foreign_columns[i];
    }

    return n_foreign;
}