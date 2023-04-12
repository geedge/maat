/*
**********************************************************************************************
*	File: maat_table.cpp
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <linux/limits.h>
#include <assert.h>

#include "log/log.h"
#include "maat_utils.h"
#include "maat_table.h"
#include "maat_rule.h"
#include "maat_kv.h"
#include "maat_expr.h"
#include "maat_ip.h"
#include "maat_compile.h"
#include "maat_group.h"
#include "maat_flag.h"
#include "maat_plugin.h"
#include "maat_ip_plugin.h"
#include "maat_bool_plugin.h"
#include "maat_fqdn_plugin.h"
#include "maat_interval.h"
#include "maat_virtual.h"

#define MODULE_TABLE  module_name_str("maat.table")

struct table_item {
    enum table_type table_type;
    void *custom_item;
};

struct maat_table {
    int table_id;
    char table_name[NAME_MAX];
    enum table_type table_type;
    int valid_column;
    void *schema;
    void *runtime;
};

struct table_manager {
    struct maat_table *tbl[MAX_TABLE_NUM];
    size_t n_table;

    struct rule_tag *accept_tags;
    size_t n_accept_tag;

    int default_compile_table_id;
    int g2g_table_id;
    struct maat_kv_store *tablename2id_map;

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

struct table_operations {
    enum table_type type;
    void *(*new_schema)(cJSON *json, struct table_manager *tbl_mgr, 
                        const char *table_name, struct log_handle *logger);
    void (*free_schema)(void *schema);

    void *(*new_runtime)(void *schema, int max_thread_num, 
                         struct maat_garbage_bin *garbage_bin,
                         struct log_handle *logger);
    void (*free_runtime)(void *runtime);

    int (*update_runtime)(void *runtime, void *schema, const char *table_name,
                          const char *line, int valid_column);
    int (*commit_runtime)(void *runtime, const char *table_name);

    long long (*runtime_rule_count)(void *runtime);
};

struct table_operations table_ops[TABLE_TYPE_MAX] = {
    {
        .type = TABLE_TYPE_FLAG,
        .new_schema = flag_schema_new,
        .free_schema = flag_schema_free,
        .new_runtime = flag_runtime_new,
        .free_runtime = flag_runtime_free,
        .update_runtime = flag_runtime_update,
        .commit_runtime = flag_runtime_commit,
        .runtime_rule_count = flag_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_FLAG_PLUS,
        .new_schema = flag_schema_new,
        .free_schema = flag_schema_free,
        .new_runtime = flag_runtime_new,
        .free_runtime = flag_runtime_free,
        .update_runtime = flag_runtime_update,
        .commit_runtime = flag_runtime_commit,
        .runtime_rule_count = flag_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_EXPR,
        .new_schema = expr_schema_new,
        .free_schema = expr_schema_free,
        .new_runtime = expr_runtime_new,
        .free_runtime = expr_runtime_free,
        .update_runtime = expr_runtime_update,
        .commit_runtime = expr_runtime_commit,
        .runtime_rule_count = expr_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_EXPR_PLUS,
        .new_schema = expr_schema_new,
        .free_schema = expr_schema_free,
        .new_runtime = expr_runtime_new,
        .free_runtime = expr_runtime_free,
        .update_runtime = expr_runtime_update,
        .commit_runtime = expr_runtime_commit,
        .runtime_rule_count = expr_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_IP_PLUS,
        .new_schema = ip_schema_new,
        .free_schema = ip_schema_free,
        .new_runtime = ip_runtime_new,
        .free_runtime = ip_runtime_free,
        .update_runtime = ip_runtime_update,
        .commit_runtime = ip_runtime_commit,
        .runtime_rule_count = ip_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_INTERVAL,
        .new_schema = interval_schema_new,
        .free_schema = interval_schema_free,
        .new_runtime = interval_runtime_new,
        .free_runtime = interval_runtime_free,
        .update_runtime = interval_runtime_update,
        .commit_runtime = interval_runtime_commit,
        .runtime_rule_count = interval_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_INTERVAL_PLUS,
        .new_schema = interval_schema_new,
        .free_schema = interval_schema_free,
        .new_runtime = interval_runtime_new,
        .free_runtime = interval_runtime_free,
        .update_runtime = interval_runtime_update,
        .commit_runtime = interval_runtime_commit,
        .runtime_rule_count = interval_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_PLUGIN,
        .new_schema = plugin_schema_new,
        .free_schema = plugin_schema_free,
        .new_runtime = plugin_runtime_new,
        .free_runtime = plugin_runtime_free,
        .update_runtime = plugin_runtime_update,
        .commit_runtime = plugin_runtime_commit,
        .runtime_rule_count = plugin_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_IP_PLUGIN,
        .new_schema = ip_plugin_schema_new,
        .free_schema = ip_plugin_schema_free,
        .new_runtime = ip_plugin_runtime_new,
        .free_runtime = ip_plugin_runtime_free,
        .update_runtime = ip_plugin_runtime_update,
        .commit_runtime = ip_plugin_runtime_commit,
        .runtime_rule_count = ip_plugin_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_FQDN_PLUGIN,
        .new_schema = fqdn_plugin_schema_new,
        .free_schema = fqdn_plugin_schema_free,
        .new_runtime = fqdn_plugin_runtime_new,
        .free_runtime = fqdn_plugin_runtime_free,
        .update_runtime = fqdn_plugin_runtime_update,
        .commit_runtime = fqdn_plugin_runtime_commit,
        .runtime_rule_count = fqdn_plugin_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_BOOL_PLUGIN,
        .new_schema = bool_plugin_schema_new,
        .free_schema = bool_plugin_schema_free,
        .new_runtime = bool_plugin_runtime_new,
        .free_runtime = bool_plugin_runtime_free,
        .update_runtime = bool_plugin_runtime_update,
        .commit_runtime = bool_plugin_runtime_commit,
        .runtime_rule_count = bool_plugin_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_VIRTUAL,
        .new_schema = virtual_schema_new,
        .free_schema = virtual_schema_free,
        .new_runtime = NULL,
        .free_runtime = NULL,
        .update_runtime = NULL,
        .commit_runtime = NULL
    },
    {
        .type = TABLE_TYPE_COMPOSITION,
        .new_schema = NULL,
        .free_schema = NULL,
        .new_runtime = NULL,
        .free_runtime = NULL,
        .update_runtime = NULL,
        .commit_runtime = NULL
    },
    {
        .type = TABLE_TYPE_COMPILE,
        .new_schema = compile_schema_new,
        .free_schema = compile_schema_free,
        .new_runtime = compile_runtime_new,
        .free_runtime = compile_runtime_free,
        .update_runtime = compile_runtime_update,
        .commit_runtime = compile_runtime_commit,
        .runtime_rule_count = compile_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_GROUP2GROUP,
        .new_schema = group2group_schema_new,
        .free_schema = group2group_schema_free,
        .new_runtime = group2group_runtime_new,
        .free_runtime = group2group_runtime_free,
        .update_runtime = group2group_runtime_update,
        .commit_runtime = group2group_runtime_commit,
        .runtime_rule_count = group2group_runtime_rule_count
    },
    {
        .type = TABLE_TYPE_GROUP2COMPILE,
        .new_schema = group2compile_schema_new,
        .free_schema = group2compile_schema_free,
        .new_runtime = group2compile_runtime_new,
        .free_runtime = group2compile_runtime_free,
        .update_runtime = group2compile_runtime_update,
        .commit_runtime = NULL,
        .runtime_rule_count = group2compile_runtime_rule_count
    }
};

void *maat_table_schema_new(cJSON *json, const char *table_name, 
                            enum table_type table_type, 
                            struct table_manager *tbl_mgr, 
                            struct log_handle *logger)
{
    void *schema = NULL;

    if (table_ops[table_type].new_schema != NULL) {
        schema = table_ops[table_type].new_schema(json, tbl_mgr, table_name, logger);
    }

    return schema;
}

void maat_table_schema_free(void *schema, enum table_type table_type)
{
    if (NULL == schema) {
        return;
    }

    if (table_ops[table_type].free_schema != NULL) {
        table_ops[table_type].free_schema(schema);
    }
}

static void register_reserved_word(struct maat_kv_store *reserved_word_map)
{
    maat_kv_register(reserved_word_map, "compile", TABLE_TYPE_COMPILE);
    maat_kv_register(reserved_word_map, "group2compile", TABLE_TYPE_GROUP2COMPILE);
    maat_kv_register(reserved_word_map, "group2group", TABLE_TYPE_GROUP2GROUP);
    maat_kv_register(reserved_word_map, "flag", TABLE_TYPE_FLAG);
    maat_kv_register(reserved_word_map, "flag_plus", TABLE_TYPE_FLAG_PLUS);
    maat_kv_register(reserved_word_map, "expr", TABLE_TYPE_EXPR);
    maat_kv_register(reserved_word_map, "expr_plus", TABLE_TYPE_EXPR_PLUS);
    maat_kv_register(reserved_word_map, "intval", TABLE_TYPE_INTERVAL);
    maat_kv_register(reserved_word_map, "intval_plus", TABLE_TYPE_INTERVAL_PLUS);
    maat_kv_register(reserved_word_map, "ip_plus", TABLE_TYPE_IP_PLUS);
    maat_kv_register(reserved_word_map, "plugin", TABLE_TYPE_PLUGIN);
    maat_kv_register(reserved_word_map, "ip_plugin", TABLE_TYPE_IP_PLUGIN);
    maat_kv_register(reserved_word_map, "bool_plugin", TABLE_TYPE_BOOL_PLUGIN);
    maat_kv_register(reserved_word_map, "fqdn_plugin", TABLE_TYPE_FQDN_PLUGIN);
    maat_kv_register(reserved_word_map, "virtual", TABLE_TYPE_VIRTUAL);
    maat_kv_register(reserved_word_map, "composition", TABLE_TYPE_COMPOSITION);
}

static int register_tablename2id(cJSON *json, struct maat_kv_store *tablename2id_map, 
                                  struct log_handle *logger)
{
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (NULL == item || item->type != cJSON_Number) {
        return -1;
    }
    int table_id = item->valueint;

    item = cJSON_GetObjectItem(json, "db_tables");
    if (item != NULL && item->type != cJSON_Array) {
        log_error(logger, MODULE_TABLE, 
                  "[%s:%d] table(table_id:%d) has db_tables, but format is invalid, should be array", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }
   
    if (item != NULL) {
        int n_table_name = cJSON_GetArraySize(item);

        for (int i = 0; i < n_table_name; i++) {
            cJSON *tmp_item = cJSON_GetArrayItem(item, i);
            if (NULL == tmp_item || tmp_item->type != cJSON_String) {
                log_error(logger, MODULE_TABLE,
                          "[%s:%d] table(table_id:%d) db_tables element format invalid, should be string",
                          __FUNCTION__, __LINE__, table_id);
                return -1;
            }

            if (strlen(tmp_item->valuestring) >= NAME_MAX) {
                log_error(logger, MODULE_TABLE,
                          "[%s:%d] table(table_id:%d) db_tables element string %s length too long",
                          __FUNCTION__, __LINE__, table_id, tmp_item->valuestring);
                return -1;
            }

            maat_kv_register(tablename2id_map, tmp_item->valuestring, table_id);
            log_info(logger, MODULE_TABLE, "table_name[%s] -> table_id:[%d]",
                     tmp_item->valuestring, table_id);
        }
    }

    item = cJSON_GetObjectItem(json, "table_name");
    if (NULL == item || item->type != cJSON_String) {
        log_error(logger, MODULE_TABLE, 
                  "[%s:%d] table(table_id:%d) has no table_name", 
                  __FUNCTION__, __LINE__, table_id);
        return -1;
    }

    if (strlen(item->valuestring) >= NAME_MAX) {
        log_error(logger, MODULE_TABLE,
                  "[%s:%d] table(table_id:%d) table_name %s length too long",
                  __FUNCTION__, __LINE__, table_id, item->valuestring);
        return -1;
    }

    maat_kv_register(tablename2id_map, item->valuestring, table_id);
    log_info(logger, MODULE_TABLE, "table_name[%s] -> table_id:[%d]",
             item->valuestring, table_id);

    return 0;
}

struct maat_table *maat_table_new(cJSON *json, struct maat_kv_store *reserved_word_map,
                                  struct log_handle *logger)
{
    struct maat_table *ptable = ALLOC(struct maat_table, 1);

    int ret = -1;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (NULL == item || item->type != cJSON_Number) {
        goto error;
    }

    if (item->valueint >= MAX_TABLE_NUM) {
        log_error(logger, MODULE_TABLE,
                  "[%s:%d] table(table_id:%d) exceed maxium %d", 
                  __FUNCTION__, __LINE__, MAX_TABLE_NUM);
        goto error;
    }
    ptable->table_id = item->valueint;

    item = cJSON_GetObjectItem(json, "table_name");
    // already validate in register_tablename2id
    if (item->type == cJSON_Array) {
        cJSON *tmp_item = cJSON_GetArrayItem(item, 0);
        memcpy(ptable->table_name, tmp_item->valuestring, strlen(tmp_item->valuestring));
    } else {
        //cJSON_String
        memcpy(ptable->table_name, item->valuestring, strlen(item->valuestring));
    }

    item = cJSON_GetObjectItem(json, "table_type");
    if (NULL == item || item->type != cJSON_String) {
        log_error(logger, MODULE_TABLE, 
                 "[%s:%d] table:%s has no table_type column", 
                 __FUNCTION__, __LINE__, ptable->table_name);
        goto error;
    }

    ret = maat_kv_read(reserved_word_map, item->valuestring, (long long *)&(ptable->table_type));
    if (ret < 0) {
        log_error(logger, MODULE_TABLE, 
                  "[%s:%d] table:%s table_type %s is illegal", 
                  __FUNCTION__, __LINE__, ptable->table_name, item->valuestring);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "valid_column");
    if (NULL == item || item->type != cJSON_Number) {
        if (ptable->table_type != TABLE_TYPE_VIRTUAL) {
            log_error(logger, MODULE_TABLE, 
                      "[%s:%d] table:%s has no valid column", 
                      __FUNCTION__, __LINE__, ptable->table_name);
            goto error;
        }
    } else {
        ptable->valid_column = item->valueint;
    }
    
    return ptable;
error:
    FREE(ptable);
    return NULL;
}

void maat_table_runtime_free(void *runtime, enum table_type table_type)
{
    if (NULL == runtime) {
        return;
    }

    if (table_ops[table_type].free_runtime != NULL) {
        table_ops[table_type].free_runtime(runtime);
    }
}

void maat_table_free(struct maat_table *maat_tbl)
{
    if (NULL == maat_tbl) {
        return;
    }

    if (maat_tbl->schema != NULL) {
        maat_table_schema_free(maat_tbl->schema, maat_tbl->table_type);
        maat_tbl->schema = NULL;
    }

    if (maat_tbl->runtime != NULL) {
        maat_table_runtime_free(maat_tbl->runtime, maat_tbl->table_type);
        maat_tbl->runtime = NULL;
    }

    FREE(maat_tbl);
}

struct table_manager *
table_manager_create(const char *table_info_path, const char *accept_tags,
                     struct maat_garbage_bin *garbage_bin, struct log_handle *logger)
{
    if (NULL == table_info_path) {
        return NULL;
    }

    unsigned char *json_buff = NULL;
    size_t json_buff_sz = 0;
    int ret = load_file_to_memory(table_info_path, &json_buff, &json_buff_sz);
    if (ret < 0) {
        log_error(logger, MODULE_TABLE, 
                  "[%s:%d] Maat read table info %s error.",
                  __FUNCTION__, __LINE__, table_info_path);
        return NULL;
    }

    cJSON *root = NULL;
    cJSON *json = NULL;
    root = cJSON_Parse((const char *)json_buff);
	if (!root) {
        log_error(logger, MODULE_TABLE, 
                  "[%s:%d] error message: %-200.200s", 
                  __FUNCTION__, __LINE__, cJSON_GetErrorPtr());
        FREE(json_buff);
        return NULL;
    }

    int json_array_size = cJSON_GetArraySize(root);
    if (json_array_size <= 0) {
        log_error(logger, MODULE_TABLE, 
                  "[%s:%d] invalid json content in %s", 
                  __FUNCTION__, __LINE__, table_info_path);
        FREE(json_buff);
        cJSON_Delete(root);
        return NULL;
    }
    
    struct table_manager *tbl_mgr = ALLOC(struct table_manager, 1);
    tbl_mgr->n_accept_tag = parse_accept_tag(accept_tags, &tbl_mgr->accept_tags, logger);
    tbl_mgr->logger = logger;
    tbl_mgr->tablename2id_map = maat_kv_store_new();
    tbl_mgr->ref_garbage_bin = garbage_bin;

    for (int i = 0; i < json_array_size; i++) {
        json = cJSON_GetArrayItem(root, i);

        if (json != NULL && json->type == cJSON_Object) {
            ret = register_tablename2id(json, tbl_mgr->tablename2id_map, logger);
            if (ret < 0) {
                log_error(logger, MODULE_TABLE, 
                          "[%s:%d] register_tablename2id failed", __FUNCTION__, __LINE__);
                FREE(json_buff);
                cJSON_Delete(root);
                table_manager_destroy(tbl_mgr);
                return NULL;
            }
        }
    }

    int default_compile_table_id = -1;
    int g2g_table_id = -1;
    struct maat_kv_store *reserved_word_map = maat_kv_store_new();
    register_reserved_word(reserved_word_map);

    for (int i = 0; i < json_array_size; i++) {
        json = cJSON_GetArrayItem(root, i);
       
        if (json != NULL && json->type == cJSON_Object) {
            struct maat_table *maat_tbl = maat_table_new(json, reserved_word_map, logger);
            if (NULL == maat_tbl) {
                ret = -1;
                goto next;
            }

            maat_tbl->schema = maat_table_schema_new(json, maat_tbl->table_name, 
                                                     maat_tbl->table_type, tbl_mgr, logger);
            if (NULL == maat_tbl->schema) {
                log_error(logger, MODULE_TABLE, 
                          "[%s:%d] Maat table schema new failed, table_name:%s", 
                          __FUNCTION__, __LINE__, maat_tbl->table_name);
                ret = -1;
                goto next;
            }
            log_info(logger, MODULE_TABLE, "successfully register table[%s]->table_id:%d",
                     maat_tbl->table_name, maat_tbl->table_id);
                     
            if (maat_tbl->table_type == TABLE_TYPE_COMPILE) {
                if (default_compile_table_id < 0) {
                    default_compile_table_id = maat_tbl->table_id;
                } else if (maat_tbl->table_id < default_compile_table_id) {
                    default_compile_table_id = maat_tbl->table_id;
                }
            }

            if (maat_tbl->table_type == TABLE_TYPE_GROUP2GROUP) { 
                g2g_table_id = maat_tbl->table_id;
            }

            tbl_mgr->tbl[maat_tbl->table_id] = maat_tbl;
            tbl_mgr->n_table++;
        }
    }

    tbl_mgr->default_compile_table_id = default_compile_table_id;
    tbl_mgr->g2g_table_id = g2g_table_id;

    log_info(logger, MODULE_TABLE, "default compile table id: %d", default_compile_table_id);
    log_info(logger, MODULE_TABLE, "group2group table id: %d", g2g_table_id);
next:
    FREE(json_buff);
    maat_kv_store_free(reserved_word_map);
    cJSON_Delete(root);

    if (ret < 0) {
        table_manager_destroy(tbl_mgr);
        return NULL;
    }

    return tbl_mgr;
}

void *maat_table_runtime_new(void *schema, enum table_type table_type,
                             int max_thread_num, struct maat_garbage_bin *garbage_bin,
                             struct log_handle *logger)
{
    void *runtime = NULL;

    if (table_ops[table_type].new_runtime != NULL) {
        runtime = table_ops[table_type].new_runtime(schema, max_thread_num, garbage_bin, logger);
    }

    return runtime;
}

void garbage_maat_table_runtime_free(void *runtime, void *arg)
{
    enum table_type type = *(enum table_type *)arg;
    maat_table_runtime_free(runtime, type);
}

int table_manager_runtime_create(struct table_manager *tbl_mgr, int max_thread_num,
                                 struct maat_garbage_bin *garbage_bin)
{
     if (NULL == tbl_mgr) {
        return -1;
    }

    assert(tbl_mgr->n_table != 0);

    size_t i = 0;
    enum table_type table_type = TABLE_TYPE_INVALID;

    for (i = 0; i < MAX_TABLE_NUM; i++) {
        void *schema = table_manager_get_schema(tbl_mgr, i);
        if (NULL == schema) {
            continue;
        }
     
        table_type = table_manager_get_table_type(tbl_mgr, i);
        void *runtime = table_manager_get_runtime(tbl_mgr, i);
        tbl_mgr->tbl[i]->runtime = maat_table_runtime_new(schema, table_type, max_thread_num,
                                                          garbage_bin, tbl_mgr->logger);
        if (runtime != NULL) {
            enum table_type *arg = ALLOC(enum table_type, 1);
            *arg = table_type;
            maat_garbage_bagging(garbage_bin, runtime, arg, garbage_maat_table_runtime_free);
        }
    }

    /* group2compile runtime depends on associated compile runtime,
       must make sure associated compile runtime already exist */
    for (i = 0; i < MAX_TABLE_NUM; i++) {
        void *runtime = table_manager_get_runtime(tbl_mgr, i);
        if (NULL == runtime) {
            continue;
        }

        table_type = table_manager_get_table_type(tbl_mgr, i);
        if (table_type != TABLE_TYPE_GROUP2COMPILE) {
            continue;
        }

        
        void *schema = table_manager_get_schema(tbl_mgr, i);
        int associated_compile_table_id = group2compile_associated_compile_table_id(schema);
        void *compile_rt = table_manager_get_runtime(tbl_mgr, associated_compile_table_id);
        int g2g_group_id = table_manager_get_group2group_table_id(tbl_mgr);
        void *g2g_rt = table_manager_get_runtime(tbl_mgr, g2g_group_id);
        group2compile_runtime_init(runtime, compile_rt, g2g_rt);
    }

    return 0;
}

void table_manager_runtime_destroy(struct table_manager *tbl_mgr)
{
    if (NULL == tbl_mgr) {
        return;
    }
    
	for(size_t i = 0; i < MAX_TABLE_NUM; i++) {
        void *runtime = table_manager_get_runtime(tbl_mgr, i);
        if (runtime != NULL) {
            enum table_type table_type = table_manager_get_table_type(tbl_mgr, i);
            assert(table_type != TABLE_TYPE_INVALID);
		    maat_table_runtime_free(runtime, table_type);
            tbl_mgr->tbl[i]->runtime = NULL;
        }
	}
}

void table_manager_destroy(struct table_manager *tbl_mgr)
{
    if (NULL == tbl_mgr) {
        return;
    }

    size_t i = 0;

	for (i = 0; i < MAX_TABLE_NUM; i++) {
        maat_table_free(tbl_mgr->tbl[i]);
        tbl_mgr->tbl[i] = NULL;
	}

    if (tbl_mgr->accept_tags != NULL) {
        for (i = 0; i < tbl_mgr->n_accept_tag; i++) {
            if (tbl_mgr->accept_tags[i].tag_name != NULL) {
                FREE(tbl_mgr->accept_tags[i].tag_name);
            }
            
            if (tbl_mgr->accept_tags[i].tag_val != NULL) {
                FREE(tbl_mgr->accept_tags[i].tag_val);
            }
        }
        FREE(tbl_mgr->accept_tags);
    }

    if (tbl_mgr->tablename2id_map != NULL) {
        maat_kv_store_free(tbl_mgr->tablename2id_map);
        tbl_mgr->tablename2id_map = NULL;
    }

	FREE(tbl_mgr);
}

size_t table_manager_table_count(struct table_manager *tbl_mgr)
{
    return MAX_TABLE_NUM;
}

int table_manager_get_table_id(struct table_manager *tbl_mgr, const char *name)
{
    if (NULL == tbl_mgr || NULL == name) {
        return -1;
    }

    long long table_id = -1;
    int ret = maat_kv_read(tbl_mgr->tablename2id_map, name, &table_id);
	if (ret < 0) {
        log_error(tbl_mgr->logger, MODULE_TABLE, 
                  "[%s:%d] table:%s is not registered", 
                  __FUNCTION__, __LINE__, name);
		return -1;
	}

    return (int)table_id;
}

enum table_type table_manager_get_table_type(struct table_manager *tbl_mgr, int table_id)
{
    if (NULL == tbl_mgr || table_id < 0 || table_id >= MAX_TABLE_NUM) {
        return TABLE_TYPE_INVALID;
    }

    if (NULL == tbl_mgr->tbl[table_id]) {
        return TABLE_TYPE_INVALID;
    }

    return tbl_mgr->tbl[table_id]->table_type;
}

int table_manager_get_defaut_compile_table_id(struct table_manager *tbl_mgr)
{
    return tbl_mgr->default_compile_table_id;
}

int table_manager_get_group2group_table_id(struct table_manager *tbl_mgr)
{
    return tbl_mgr->g2g_table_id;
}

void *table_manager_get_schema(struct table_manager *tbl_mgr, int table_id)
{
    if (NULL == tbl_mgr || table_id < 0 || table_id >= MAX_TABLE_NUM) {
        return NULL;
    }

    if (NULL == tbl_mgr->tbl[table_id]) {
        return NULL;
    }
    
    return tbl_mgr->tbl[table_id]->schema;
}

struct ex_data_schema *
table_manager_get_table_ex_data_schema(struct table_manager *tbl_mgr, int table_id)
{
    return NULL;
}

int table_manager_get_valid_column(struct table_manager *tbl_mgr, int table_id)
{
    if (NULL == tbl_mgr || table_id < 0 || table_id >= MAX_TABLE_NUM) {
        return -1;
    }

    if (NULL == tbl_mgr->tbl[table_id]) {
        return -1;
    }

    return tbl_mgr->tbl[table_id]->valid_column;
}

size_t table_manager_accept_tags_count(struct table_manager *tbl_mgr)
{
    return tbl_mgr->n_accept_tag;
}

int table_manager_accept_tags_match(struct table_manager *tbl_mgr, const char *tags)
{
    return compare_accept_tag(tags, tbl_mgr->accept_tags, tbl_mgr->n_accept_tag);
}

void *table_manager_get_runtime(struct table_manager *tbl_mgr, int table_id)
{
    if (NULL == tbl_mgr || (table_id < 0) || (table_id >= MAX_TABLE_NUM)) {
        return NULL;
    }

    if (NULL == tbl_mgr->tbl[table_id]) {
        return NULL;
    }

	return tbl_mgr->tbl[table_id]->runtime;
}

int table_manager_update_runtime(struct table_manager *tbl_mgr, const char *table_name,
                                 int table_id, const char *line)
{
    void *schema = table_manager_get_schema(tbl_mgr, table_id);
    if (NULL == schema) {
        return -1;
    }

    void *runtime = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == runtime) {
        return -1;
    }

    int valid_column = table_manager_get_valid_column(tbl_mgr, table_id);
    if (valid_column < 0) {
        log_error(tbl_mgr->logger, MODULE_TABLE, 
                  "[%s:%d] table:%s has no valid column, can't update runtime",
                  __FUNCTION__, __LINE__, table_name);
        return -1;
    }

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_INVALID) {
        log_error(tbl_mgr->logger, MODULE_TABLE, 
                  "[%s:%d] table:%s table_type is invalid, can't update runtime",
                  __FUNCTION__, __LINE__, table_name);
        return -1;
    }

    if (NULL == table_ops[table_type].update_runtime) {
        log_error(tbl_mgr->logger, MODULE_TABLE, 
                  "[%s:%d] table:%s has no update_runtime function, can't update runtime",
                  __FUNCTION__, __LINE__, table_name);
        return -1;
    }
    
    return table_ops[table_type].update_runtime(runtime, schema, table_name, 
                                                line, valid_column);
}

void table_manager_commit_runtime(struct table_manager *tbl_mgr, int table_id)
{
    void *runtime = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == runtime) {
        return;
    }

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_INVALID) {
        log_error(tbl_mgr->logger, MODULE_TABLE, 
                  "[%s:%d] table(table_id:%d) table_type is invalid, can't commit runtime",
                  __FUNCTION__, __LINE__, table_id);
        return;
    }

    struct maat_table *ptable = tbl_mgr->tbl[table_id];
    if ( table_ops[table_type].commit_runtime != NULL) {
        table_ops[table_type].commit_runtime(runtime, ptable->table_name);;
    }
}

long long table_manager_runtime_rule_count(struct table_manager *tbl_mgr, int table_id)
{
    void *runtime = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == runtime) {
        return 0;
    }

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_INVALID) {
        log_error(tbl_mgr->logger, MODULE_TABLE, 
                  "[%s:%d] table(table_id:%d) table_type is invalid, can't update runtime",
                  __FUNCTION__, __LINE__, table_id);
        return 0;
    }

    return table_ops[table_type].runtime_rule_count(runtime);
}