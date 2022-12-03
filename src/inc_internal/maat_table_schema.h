/*
**********************************************************************************************
*	File: maat_table_schema.h
*   Description: maat table schema entry
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_TABLE_SCHEMA_H_
#define _MAAT_TABLE_SCHEMA_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stddef.h>

#include "maat/maat.h"
#include "adapter_hs.h"

#define MAX_TABLE_NUM    256
#define MAX_DISTRICT_STR 128
#define MAX_IP_STR       128
#define MAX_KEYWORDS_STR 1024
#define	MAX_FOREIGN_CLMN_NUM 8

enum table_type {
	TABLE_TYPE_EXPR = 0,
    TABLE_TYPE_EXPR_PLUS,
    TABLE_TYPE_IP,
    TABLE_TYPE_IP_PLUS,
    TABLE_TYPE_INTERVAL,
    TABLE_TYPE_INTERVAL_PLUS,
    TABLE_TYPE_DIGEST,
    TABLE_TYPE_SIMILARITY,
    TABLE_TYPE_PLUGIN,
    TABLE_TYPE_IP_PLUGIN,
    TABLE_TYPE_FQDN_PLUGIN,
    TABLE_TYPE_BOOL_PLUGIN,
    //above are physical table
    TABLE_TYPE_VIRTUAL,
    TABLE_TYPE_COMPOSITION,
    TABLE_TYPE_COMPILE,
    TABLE_TYPE_GROUP,
    TABLE_TYPE_GROUP2GROUP,
	TABLE_TYPE_GROUP2COMPILE,
	TABLE_TYPE_MAX
};

enum expr_type {
    EXPR_TYPE_STRING = 0,
	EXPR_TYPE_AND,
    EXPR_TYPE_REGEX,
    EXPR_TYPE_MAX
};

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
	SCAN_TYPE_MAX
};

enum match_method {
    MATCH_METHOD_SUB = 0,
	MATCH_METHOD_RIGHT,
	MATCH_METHOD_LEFT,
	MATCH_METHOD_COMPLETE,
    MATCH_METHOD_MAX
};

struct expr_item {
    int item_id;
    int group_id;
    char district[MAX_DISTRICT_STR];
    char keywords[MAX_KEYWORDS_STR];
    enum expr_type expr_type;
    enum match_method match_method;
    int is_hexbin;
    int is_case_sensitive;
    int is_valid;
};

struct plugin_item {
    char key[MAX_KEYWORDS_STR];
    size_t key_len;
    int is_valid;
};

struct ip_plugin_item {
    int item_id;
	int ip_type;
	char start_ip[MAX_IP_STR];
	char end_ip[MAX_IP_STR];
	int is_valid;
	int rule_tag;
	int have_exdata;
	void *ex_data;
};

struct table_item {
    enum table_type table_type;
    union {
        struct expr_item expr_item;
        struct plugin_item plugin_item;
        struct ip_plugin_item ip_plugin_item;
    };
};

struct plugin_table_callback_schema
{
	maat_start_callback_t 	*start;
	maat_update_callback_t	*update;
	maat_finish_callback_t	*finish;
	void* u_para;
};

struct ex_data_schema
{
	maat_plugin_ex_new_func_t *new_func;
	maat_plugin_ex_free_func_t *free_func;
	maat_plugin_ex_dup_func_t *dup_func;
	//Maat_plugin_EX_key2index_func_t* key2index_func;
	long argl;
	void *argp;
    int set_flag;
};

struct table_schema;
struct table_schema_manager;

/* table schema manager API */
struct table_schema_manager *table_schema_manager_create(const char *table_info_path);
void table_schema_manager_destroy(struct table_schema_manager *table_schema_mgr);

int table_schema_manager_get_table_id(struct table_schema_manager* table_schema_mgr, const char *table_name);
enum table_type table_schema_manager_get_table_type(struct table_schema_manager *table_schema_mgr, int table_id);

size_t table_schema_manager_get_size(struct table_schema_manager* table_schema_mgr);

void table_schema_manager_all_plugin_cb_start(struct table_schema_manager* table_schema_mgr, int update_type);
void table_schema_manager_all_plugin_cb_finish(struct table_schema_manager* table_schema_mgr);

/* table schema generic API */
struct table_schema *table_schema_get(struct table_schema_manager *table_schema_mgr, int table_id);

struct table_schema *table_schema_get_by_scan_type(struct table_schema_manager *table_schema_mgr, 
                                                   int table_id, enum scan_type type, int *virtual_table_id);

enum table_type table_schema_get_table_type(struct table_schema *table_schema);

int table_schema_get_table_id(struct table_schema *table_schema);

enum scan_type table_schema_get_scan_type(struct table_schema *table_schema);

struct table_item *table_schema_line_to_item(const char *line, struct table_schema *table_schema);

int table_schema_get_valid_flag_column(struct table_schema *table_schema);

/* expr table schema API */
enum hs_scan_mode expr_table_schema_get_scan_mode(struct table_schema *table_schema);

/* plugin table schema API */
int plugin_table_schema_set_ex_data_schema(struct table_schema *table_schema,
									        maat_plugin_ex_new_func_t *new_func,
									        maat_plugin_ex_free_func_t *free_func,
									        maat_plugin_ex_dup_func_t *dup_func,
									        long argl, void *argp);

struct ex_data_schema *plugin_table_schema_get_ex_data_schema(struct table_schema *table_schema);
/**
 * @brief if plugin table schema's ex data schema set
 * 
 * @retval 1(already Set) 0(Not set yet)
*/
int plugin_table_schema_ex_data_schema_flag(struct table_schema *table_schema);

int plugin_table_schema_add_callback(struct table_schema_manager* table_schema_mgr, int table_id,
							         maat_start_callback_t *start,//MAAT_RULE_UPDATE_TYPE_*,u_para
							         maat_update_callback_t *update,//table line ,u_para
							         maat_finish_callback_t *finish,//u_para
							        void *u_para);
/**
 * @brief the number of callback function stored in plugin table schema
*/
size_t plugin_table_schema_callback_count(struct table_schema *table_schema);

void plugin_table_schema_all_cb_update(struct table_schema *table_schema, const char *row);

int plugin_table_schema_get_foreign_column(struct table_schema *table_schema, int *foreign_columns);

#ifdef __cpluscplus
}
#endif

#endif