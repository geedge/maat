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

#include "maat_utils.h"
#include "maat_table_schema.h"
#include "maat_kv.h"
#include "cJSON.h"
#include "adapter_hs.h"
#include "maat_ex_data.h"


#define MAX_TABLE_NUM 256
#define MAX_TABLE_LINE_SIZE (1024 * 16)
#define MAX_ITEM_STR 64

struct expr_item {
    int item_id;
    int group_id;
    char district[MAX_ITEM_STR]; //128
    char keywords[MAX_ITEM_STR]; //1k
    char expr_type[MAX_ITEM_STR];//enum
    char match_method[MAX_ITEM_STR]; //enum
    int is_hexbin;
    int case_sensitive;
    int is_valid;
   
     //rule_tag; 只存在schema里
	//int have_exdata;
    //struct ex_data *ex_data; //hash表
};

struct ip_plugin_item {
    int row_id;
	int ip_type;
	int start_ip;
	int end_ip;
	int valid_flag;
	int rule_tag;
	int have_exdata;
	struct ex_data *ex_data;
};

struct maat_table_item {
    enum maat_table_type table_type;
    union {
        struct expr_item expr_item;
        struct ip_plugin_item ip_plugin_item;
    };
};

struct expr_table_schema {
	int item_id_column;
    int group_id_column;
	int district_column;
	int keywords_column;
	int expr_type_column;
    int match_method_column;
    int is_hexbin_column;
    int case_sensitive_column;
    /* valid means add, invalid means delete */
	int is_valid_column;
	int have_exdata;
	struct ex_data_schema *ex_schema;
};

struct ip_plugin_table_schema {
    int row_id_column;
	int ip_type_column;
	int start_ip_column;
	int end_ip_column;
	int valid_flag_column;
	int rule_tag_column;
	int have_exdata;
	struct ex_data_schema *ex_schema;
};

struct maat_table_schema {
    int table_id;
    sds table_name;
    enum maat_table_type table_type;
    union {
        struct expr_table_schema expr;
        struct ip_plugin_table_schema ip_plugin;
    };
};

struct maat_table_manager {
    struct maat_table_schema *schema_table[MAX_TABLE_NUM];
    size_t n_schema_table;

    struct maat_kv_store *tablename2id_map;
};

struct maat_table_schema *table_schema_new(void)
{
    struct maat_table_schema *ptable = ALLOC(struct maat_table_schema, 1);

    return ptable;
}

void table_schema_free(struct maat_table_schema *ptable)
{
    free(ptable);
}

int read_expr_table_schema(cJSON *root, struct maat_table_schema *ptable)
{
    int read_cnt = 0;
    cJSON *item = NULL;

    item = cJSON_GetObjectItem(root, "table_id");
    if (item != NULL && item->type == cJSON_String) {
        ptable->table_id = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "table_name");
    if (item != NULL && item->type == cJSON_String) {
        memcpy(ptable->table_name, item->valuestring, strlen(item->valuestring));
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "item_id");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.item_id_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "group_id");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.group_id_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "district");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.district_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "keywords");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.keywords_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "expr_type");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.expr_type_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "match_method");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.match_method_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "is_hexbin");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.is_hexbin_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "case_sensitive");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.case_sensitive_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "is_valid");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->expr.is_valid_column = item->valueint;
        read_cnt++;
    }

    if (read_cnt < 10) {
        return -1;
    } else {
        return 0;
    }
}

int read_ip_plugin_table_schema(cJSON *root, struct maat_table_schema *ptable)
{
    int read_cnt = 0;
    cJSON *item = NULL;

    item = cJSON_GetObjectItem(root, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->table_id = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "table_name");
    if (item != NULL && item->type == cJSON_String) {
        memcpy(ptable->table_name, item->valuestring, strlen(item->valuestring));
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "row_id");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plugin.row_id_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "ip_type");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plugin.ip_type_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "start_ip");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plugin.start_ip_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "end_ip");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plugin.end_ip_column = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(root, "valid");
    if (item != NULL && item->type == cJSON_Number) {
        ptable->ip_plugin.valid_flag_column = item->valueint;
        read_cnt++;
    }

    if (read_cnt < 7) {
        return -1;
    } else {
        return 0;
    }
}

int table_schema_populate(const char *line, struct maat_table_schema *ptable,
                          struct maat_kv_store* reserved_word_map)
{
    int ret = -1;
    int read_cnt = 0;
    cJSON *root = NULL;
    cJSON *item = NULL;
    sds copy_line = sdsnew(line);
    sds table_type_str = NULL;

    root = cJSON_Parse(copy_line);
    if (NULL == root) {
        goto next;
    }

    item = cJSON_GetObjectItem(root, "table_type");
    if (item != NULL && item->type == cJSON_String) {
        table_type_str = sdsnew(item->valuestring);
        read_cnt++;
    }

    ret = maat_kv_read(reserved_word_map, table_type_str, (int*)&(ptable->table_type));
    if (ret < 0) {
        goto next;
    }

    switch (ptable->table_type) {
    case TABLE_TYPE_EXPR:
        ret = read_expr_table_schema(root, ptable);
        if (ret < 0) {
            goto next;
        }
        break;
    case TABLE_TYPE_IP_PLUGIN:
        ret = read_ip_plugin_table_schema(root, ptable);
        if (ret < 0) {
            goto next;
        }
        break;
    default:
        break;
    }

next:
    cJSON_Delete(root);
    sdsfree(copy_line);
    if (table_type_str != NULL) {
        sdsfree(table_type_str);
    }
    
    return ret;
}

struct maat_table_manager *maat_table_manager_create(sds table_info_path)
{
    FILE *fp = fopen(table_info_path, "r");
    if (NULL == fp) {
        fprintf(stderr,"Maat read table info %s error.\n",table_info_path);
        //log_error()
        return NULL;
    }

	struct maat_kv_store* reserved_word_map = maat_kv_store_new();
    /* register table type reserved word */
    maat_kv_register(reserved_word_map, "expr", TABLE_TYPE_EXPR);
    maat_kv_register(reserved_word_map, "ip_plugin", TABLE_TYPE_IP_PLUGIN);

    int i = 0;
    char line[MAX_TABLE_LINE_SIZE] = {0};
    struct maat_table_manager *table_mgr = ALLOC(struct maat_table_manager, 1);
    struct maat_table_schema **pptable = table_mgr->schema_table;
    table_mgr->tablename2id_map = maat_kv_store_new();

    while (NULL != fgets(line, sizeof(line), fp)) {
        i++;

        if (line[0] == '#' || line[0] == ' ' || line[0] == '\t') {
            continue;
        }

        struct maat_table_schema *table_schema = table_schema_new();
        int ret = table_schema_populate(line, table_schema, reserved_word_map);
        if (ret < 0) {
            fprintf(stderr, "Maat read table info %s line %d error: illegal table schema.\n", 
                    table_info_path, i);
            //log_error()
            goto error;
        }

        if (table_schema->table_id >= MAX_TABLE_NUM) {
            fprintf(stderr,"Maat read table info %s:%d error: table id %uh > %zu.\n",
                    table_info_path, i, table_schema->table_id, MAX_TABLE_NUM);
            goto error;
        }

        ret = maat_kv_register(table_mgr->tablename2id_map, table_schema->table_name, table_schema->table_id);
        if (ret < 0) {
            //log_error("Duplicate table %s of table id %d", table_schema->table_name, table_schema->table_id);
            goto error;
        }

        pptable[table_schema->table_id] = table_schema;
        table_mgr->n_schema_table++;
        continue;
    error:
        table_schema_free(table_schema);
    }
    maat_kv_store_free(reserved_word_map);

    return table_mgr;
}

void maat_table_manager_destroy(struct maat_table_manager *table_mgr)
{
	for (size_t i = 0; i < MAX_TABLE_NUM; i++) {
		if (NULL == table_mgr->schema_table[i]) {
			continue;
		}
		table_schema_free(table_mgr->schema_table[i]);
		table_mgr->schema_table[i] = NULL;
	}

	maat_kv_store_free(table_mgr->tablename2id_map);
	free(table_mgr);
}

int maat_table_manager_get_table_id(struct maat_table_manager* table_mgr, sds table_name)
{
    int table_id = -1;

	int ret=maat_kv_read(table_mgr->tablename2id_map, table_name, &table_id);
	if (ret > 0) {
		return table_id;
	} else {
		return -1;
	}
}

enum maat_table_type maat_table_manager_get_table_type(struct maat_table_manager *table_mgr, int id)
{
    if (table_mgr->schema_table[id] == NULL) {
        return TABLE_TYPE_MAX;
    }

    return table_mgr->schema_table[id]->table_type;
}

size_t maat_table_manager_get_size(struct maat_table_manager* table_mgr)
{
    return table_mgr->n_schema_table;
}

int populate_expr_table_item(sds line, struct expr_table_schema *expr_schema, struct expr_item *expr_item)
{
    size_t column_offset = 0;
    size_t column_len = 0;

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

}

int populate_ip_plugin_table_item(sds line, struct ip_plugin_table_schema *ip_plugin_schema, struct ip_plugin_item *ip_plugin_item)
{
    return 0;
}

struct maat_table_item *
maat_table_line_to_item(sds line, struct maat_table_schema *table_schema)
{
    int ret = -1;
    struct maat_table_item *table_item = ALLOC(struct maat_table_item, 1);

    switch (table_schema->table_type)
    {
    case TABLE_TYPE_EXPR:
        table_item->table_type = TABLE_TYPE_EXPR;
        ret = populate_expr_table_item(line, &table_schema->expr, &table_item->expr_item);
        if (ret < 0) {
            goto error;
        }
        break;
    case TABLE_TYPE_IP_PLUGIN:
        table_item->table_type = TABLE_TYPE_IP_PLUGIN;
        ret = populate_ip_plugin_table_item(line, &table_schema->ip_plugin, &table_item->ip_plugin_item);
        if (ret < 0) {
            goto error;
        }
        break;
    default:
        break;
    }
    return table_item;
error:
    free(table_item);
    return NULL;
}

