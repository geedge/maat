/*
**********************************************************************************************
*	File: maat_table.cpp
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <limits.h>
#include <assert.h>

#include "log/log.h"
#include "maat_utils.h"
#include "maat_table.h"
#include "maat_rule.h"
#include "maat_garbage_collection.h"
#include "maat_kv.h"
#include "maat_expr.h"
#include "maat_ip.h"
#include "maat_compile.h"
#include "maat_group.h"
#include "maat_plugin.h"
#include "maat_ip_plugin.h"

#define MODULE_TABLE	 module_name_str("maat.table")

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
    int n_accept_tag;

    struct maat_kv_store *tablename2id_map;
    struct log_handle *logger;
};

struct table_operations {
    enum table_type type;
    void *(*new_schema)(cJSON *json, const char *table_name, struct log_handle *logger);
    void (*free_schema)(void *schema);

    void *(*new_runtime)(void *schema, struct maat_garbage_bin *garbage_bin, struct log_handle *logger);
    void (*free_runtime)(void *runtime);

    int (*update_runtime)(void *runtime, void *schema, const char *line, int valid_column);
    int (*commit_runtime)(void *runtime);
};

struct table_operations table_ops[TABLE_TYPE_MAX] = {
    {
        .type = TABLE_TYPE_EXPR,
        .new_schema = expr_schema_new,
        .free_schema = expr_schema_free,
        .new_runtime = expr_runtime_new,
        .free_runtime = expr_runtime_free,
        .update_runtime = expr_runtime_update,
        .commit_runtime = expr_runtime_commit
    },
    {
        .type = TABLE_TYPE_EXPR_PLUS,
        .new_schema = expr_schema_new,
        .free_schema = expr_schema_free,
        .new_runtime = expr_runtime_new,
        .free_runtime = expr_runtime_free,
        .update_runtime = expr_runtime_update,
        .commit_runtime = expr_runtime_commit
    },
    {
        .type = TABLE_TYPE_IP_PLUS,
        .new_schema = ip_plus_schema_new,
        .free_schema = ip_plus_schema_free,
        .new_runtime = ip_plus_runtime_new,
        .free_runtime = ip_plus_runtime_free,
        .update_runtime = ip_plus_runtime_update,
        .commit_runtime = ip_plus_runtime_commit
    },
    {
        .type = TABLE_TYPE_INTERVAL,
        .new_schema = NULL,
        .free_schema = NULL,
        .new_runtime = NULL,
        .free_runtime = NULL,
        .update_runtime = NULL,
        .commit_runtime = NULL
    },
    {
        .type = TABLE_TYPE_INTERVAL_PLUS,
        .new_schema = NULL,
        .free_schema = NULL,
        .new_runtime = NULL,
        .free_runtime = NULL,
        .update_runtime = NULL,
        .commit_runtime = NULL
    },
    {
        .type = TABLE_TYPE_DIGEST,
        .new_schema = NULL,
        .free_schema = NULL,
        .new_runtime = NULL,
        .free_runtime = NULL,
        .update_runtime = NULL,
        .commit_runtime = NULL
    },
    {
        .type = TABLE_TYPE_SIMILARITY,
        .new_schema = NULL,
        .free_schema = NULL,
        .new_runtime = NULL,
        .free_runtime = NULL,
        .update_runtime = NULL,
        .commit_runtime = NULL
    },
    {   
        .type = TABLE_TYPE_CONJUNCTION,
        .new_schema = NULL,
        .free_schema = NULL,
        .new_runtime = NULL,
        .free_runtime = NULL,
        .update_runtime = NULL,
        .commit_runtime = NULL
    },
    {
        .type = TABLE_TYPE_PLUGIN,
        .new_schema = plugin_schema_new,

    },
    {
        .type = TABLE_TYPE_IP_PLUGIN,
        .new_schema = ip_plugin_schema_new,
        .free_schema = ip_plugin_schema_free,
        .new_runtime = ip_plugin_runtime_new,
        .free_runtime = ip_plugin_runtime_free,
        .update_runtime = ip_plugin_runtime_update,
        .commit_runtime = ip_plugin_runtime_commit
    },
    {
        .type = TABLE_TYPE_FQDN_PLUGIN,
        .new_schema = NULL,
        .free_schema = NULL,
        .new_runtime = NULL,
        .free_runtime = NULL,
        .update_runtime = NULL,
        .commit_runtime = NULL
    },
    {
        .type = TABLE_TYPE_BOOL_PLUGIN,
        .new_schema = NULL,
        .free_schema = NULL,
        .new_runtime = NULL,
        .free_runtime = NULL,
        .update_runtime = NULL,
        .commit_runtime = NULL
    },
    {
        .type = TABLE_TYPE_VIRTUAL,
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
        .commit_runtime = compile_runtime_commit
    },
    {
        .type = TABLE_TYPE_GROUP2COMPILE,
        .new_schema = group2compile_schema_new,
        .free_schema = group2compile_schema_free,
        .new_runtime = NULL,
        .free_runtime = NULL,
        .update_runtime = group2compile_runtime_update,
        .commit_runtime = NULL
    },
    {
        .type = TABLE_TYPE_GROUP2GROUP,
        .new_schema = group2group_schema_new,
        .free_schema = group2group_schema_free,
        .new_runtime = group2group_runtime_new,
        .free_runtime = group2group_runtime_free,
        .update_runtime = group2group_runtime_update,
        .commit_runtime = group2group_runtime_commit
    }
};

void *maat_table_schema_new(cJSON *json, const char *table_name, enum table_type table_type)
{
    void *schema = NULL;

    if (table_ops[table_type].new_schema != NULL) {
        schema = table_ops[table_type].new_schema(json, table_name, logger);
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
    maat_kv_register(reserved_word_map, "expr", TABLE_TYPE_EXPR);
    maat_kv_register(reserved_word_map, "expr_plus", TABLE_TYPE_EXPR_PLUS);
    maat_kv_register(reserved_word_map, "ip_plus", TABLE_TYPE_IP_PLUS);
    maat_kv_register(reserved_word_map, "plugin", TABLE_TYPE_PLUGIN);
    maat_kv_register(reserved_word_map, "ip_plugin", TABLE_TYPE_IP_PLUGIN);
    maat_kv_register(reserved_word_map, "virtual", TABLE_TYPE_VIRTUAL);
}

static void register_tablename2id(cJSON *json, struct maat_kv_store *tablename2id_map, 
                                  struct log_handle *logger)
{
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (NULL == item || item->type != cJSON_Number) {
        return;
    }
    int table_id = item->valueint;

    item = cJSON_GetObjectItem(json, "table_name");
    if (NULL == item || item->type != cJSON_String) {
        log_error(logger, MODULE_TABLE, 
                  "table(table_id:%d) has no table name", table_id);
        return;
    }

    if (strlen(item->valuestring) >= NAME_MAX) {
        log_error(logger, MODULE_TABLE_SCHEMA,
                  "table(table_id:%d) name %s length too long", table_id, item->valuestring);
        return;
    }
    
    maat_kv_register(tablename2id_map, item->valuestring, table_id);
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
                  "table(table_id:%d) exceed maxium %d", MAX_TABLE_NUM);
        goto error;
    }
    ptable->table_id = item->valueint;

    item = cJSON_GetObjectItem(json, "table_name");
    if (NULL == item || item->type != cJSON_String) {
        log_error(logger, MODULE_TABLE, 
                  "table(table_id:%d) has no table name", ptable->table_id);
        goto error;
    }

    if (strlen(item->valuestring) >= NAME_MAX) {
        log_error(logger, MODULE_TABLE,
                  "table(table_id:%d) name %s length too long", 
                  ptable->table_id, item->valuestring);
        goto error;
    }
    memcpy(ptable->table_name, item->valuestring, strlen(item->valuestring));

    item = cJSON_GetObjectItem(json, "table_type");
    if (NULL == item || item->type != cJSON_String) {
        goto error;
    }

    ret = maat_kv_read(reserved_word_map, item->valuestring, (int*)&(ptable->table_type));
    if (ret < 0) {
        log_error(logger, MODULE_TABLE, "table_type %s is illegal", item->valuestring);
        goto error;
    }

    item = cJSON_GetObjectItem(json, "valid_column");
    if (NULL == item && item->type != cJSON_Number) {
        goto error;
    }
    ptable->valid_column = item->valueint;
    
    return ptable;
error:
    FREE(ptable);
    return NULL;
}

void maat_table_free(struct maat_table *maat_tbl)
{
    if (NULL == maat_tbl) {
        return;
    }

    if (maat_tbl->schema != NULL) {
        maat_table_schema_free(maat_tbl->schema);
        maat_tbl->schema = NULL;
    }

    if (maat_tbl->runtime != NULL) {
        maat_table_runtime_free(maat_tbl->runtime);
        maat_tbl->runtime = NULL;
    }

    FREE(maat_tbl);
}

struct table_manager *table_manager_create(const char *table_info_path, const char *accept_tags,
                                           struct log_handle *logger)
{
    if (NULL == table_info_path) {
        return NULL;
    }

    unsigned char *json_buff = NULL;
    size_t json_buff_sz = 0;
    int ret = load_file_to_memory(table_info_path, &json_buff, &json_buff_sz);
    if (ret < 0) {
        log_error(logger, MODULE_TABLE, "Maat read table info %s error.", table_info_path);
        return NULL;
    }

    cJSON *root = NULL;
    cJSON *json = NULL;
    root = cJSON_Parse((const char *)json_buff);
	if (!root) {
        log_error(logger, MODULE_TABLE, "Error before: %-200.200s", cJSON_GetErrorPtr());
        FREE(json_buff);
        return NULL;
    }

    int json_array_size = cJSON_GetArraySize(root);
    if (json_array_size <= 0) {
        log_error(logger, MODULE_TABLE, "invalid json content in %s", table_info_path);
        free(json_buff);
        return NULL;
    }
    
    struct maat_kv_store *reserved_word_map = maat_kv_store_new();
    register_reserved_word(reserved_word_map);

    struct table_manager *tbl_mgr = ALLOC(struct table_manager, 1);
    tbl_mgr->n_accept_tag = parse_accept_tag(accept_tags, &tbl_mgr->accept_tags, logger);
    tbl_mgr->logger = logger;
    tbl_mgr->tablename2id_map = maat_kv_store_new();

    int default_compile_table_id = MAX_TABLE_NUM;

    for (int i = 0; i < json_array_size; i++) {
        json = cJSON_GetArrayItem(root, i);

        if (json != NULL && json->type == cJSON_Object) {
            register_tablename2id(json, tbl_mgr->tablename2id_map, logger);
        }
    }

    for (int i = 0; i < json_array_size; i++) {
        json = cJSON_GetArrayItem(root, i);
       
        if (json != NULL && json->type == cJSON_Object) {
            struct maat_table *maat_tbl = maat_table_new(json, reserved_word_map, logger);
            if (NULL == maat_tbl) {
                log_error(logger, MODULE_TABLE, "Maat table new failed.");
                continue;
            }

            maat_tbl->schema = maat_table_schema_new(json, maat_tbl->table_name, maat_tbl->table_type);
            if (NULL == maat_tbl->schema) {
                log_error(logger, MODULE_TABLE, "Maat table schema new failed, table_name:%d", 
                          maat_tbl->table_name);
                maat_table_free(maat_tbl);
                continue;
            }

            if (maat_tbl->table_type == TABLE_TYPE_COMPILE) {
                if (maat_tbl->table_id < default_compile_table_id) {
                    default_compile_table_id = maat_tbl->table_id;
                }
            }

            tbl_mgr->tbl[maat_tbl->table_id] = maat_tbl;
            tbl_mgr->n_table++;
        }
    }
	
    assert(default_compile_table_id != MAX_TABLE_NUM);
    tbl_mgr->default_compile_table_id = default_compile_table_id;
    log_info(logger, MODULE_TABLE, "default compile table id: %d", default_compile_table_id);

    maat_kv_store_free(reserved_word_map);
    cJSON_Delete(root);
    FREE(json_buff);

    return tbl_mgr;
}

void *maat_table_runtime_new(void *schema, enum table_type table_type,
                             struct maat_garbage_bin *garbage_bin,
                             struct log_handle *logger)
{
    void *runtime = NULL;

    if (table_ops[table_type].new_runtime != NULL) {
        runtime = table_ops[table_type].new_runtime(schema, garbage_bin, logger);
    }

    return runtime;

    #if 0
    switch (table_rt->table_type) {
        case TABLE_TYPE_COMPILE:
            break;
        case TABLE_TYPE_GROUP2COMPILE:
            break;
        case TABLE_TYPE_GROUP2GROUP:
            table_rt->custom_rt = group2group_runtime_new(logger);
            table_rt->g2g_rt.group_topo = maat_group_topology_new(logger);
            break;
        case TABLE_TYPE_EXPR:
            table_rt->expr_rt.htable = rcu_hash_new(expr_ex_data_free);
            table_rt->expr_rt.scan_mode = expr_table_schema_get_scan_mode(table_schema);
            break;
        case TABLE_TYPE_IP_PLUS:
            table_rt->ip_plus_rt.ex_data_rt = ex_data_runtime_new(table_id, ex_data_container_free);
            ex_container_ctx = ALLOC(struct ex_container_ctx, 1);
            ex_container_ctx->custom_data_free = free;
            //ex_data_runtime_set_ex_container_ctx(ex_data_rt, ex_container_ctx);
            break;
        case TABLE_TYPE_PLUGIN:
            table_rt->plugin_rt.ex_data_rt = ex_data_runtime_new(table_id, ex_data_container_free);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            table_rt->ip_plugin_rt.ex_data_rt = ex_data_runtime_new(table_id, ex_data_container_free);
            ex_container_ctx = ALLOC(struct ex_container_ctx, 1);
            ex_container_ctx->custom_data_free = free;
            //ex_data_runtime_set_ex_container_ctx(ex_data_rt, ex_container_ctx);
            break;
        default:
            break;
    }
    #endif
}


void maat_table_runtime_free(void *runtime, enum table_type table_type)
{
    if (NULL == runtime) {
        return;
    }

    table_ops[table_type].free_runtime(runtime);
#if 0
    switch (table_rt->table_type) {
        case TABLE_TYPE_COMPILE:
            bool_matcher_free(table_rt->compile_rt.bm);
            maat_compile_hash_free(&(table_rt->compile_rt.compile_hash));
            break;
        case TABLE_TYPE_GROUP2COMPILE:
            break;
        case TABLE_TYPE_GROUP2GROUP:
            maat_group_topology_free(table_rt->g2g_rt.group_topo);
            break;
        case TABLE_TYPE_EXPR:
            adapter_hs_destroy(table_rt->expr_rt.hs);
            rcu_hash_free(table_rt->expr_rt.htable);
            break;
        case TABLE_TYPE_PLUGIN:
            ex_data_runtime_free(table_rt->plugin_rt.ex_data_rt);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ip_matcher_free(table_rt->ip_plugin_rt.ip_matcher);
            ex_data_runtime_free(table_rt->ip_plugin_rt.ex_data_rt);
            break;
        default:
            break;
    }
#endif
}

int table_manager_init(struct table_manager *tbl_mgr, struct maat_garbage_bin *garbage_bin)
{
     if (NULL == tbl_mgr) {
        return -1;
    }

    assert(tbl_mgr->n_table != 0);

    size_t i = 0;
    int g2g_group_id = MAX_TABLE_NUM;
    enum table_type table_type = TABLE_TYPE_MAX;

    for (i = 0; i < MAX_TABLE_NUM; i++) {
        void *schema = table_manager_get_schema(tbl_mgr, i);
        if (NULL == schema) {
            continue;
        }
     
        table_type = table_manager_get_table_type(tbl_mgr, i);
        if (table_type == TABLE_TYPE_GROUP2GROUP) {
            g2g_group_id = i;
        }

        tbl_mgr->tbl[i]->runtime = maat_table_runtime_new(schema, table_type, garbage_bin, logger);
    }

    assert(g2g_group_id != MAX_TABLE_NUM);

    /* group2compile runtime depends on associated compile runtime,
       must make sure associated compile runtime already exist */
    for (i = 0; i < MAX_TABLE_NUM; i++) {
        void *runtime = tbl_mgr->tbl[i]->runtime;
        if (NULL == runtime) {
            continue;
        }

        table_type = table_manager_get_table_type(tbl_mgr, i);
        if (table_type != TABLE_TYPE_GROUP2COMPILE) {
            continue;
        }

        
        void *schema = table_manager_get_schema(tbl_mgr, i);
        //int associated_compile_table_id = table_schema_get_associated_table_id(table_schema);
        //TODO: by luis
        int associated_compile_table_id = -1;
        void *compile_rt = table_manager_get_runtime(tbl_mgr, associated_compile_table_id);
        void *g2g_rt = table_manager_get_runtime(tbl_mgr, g2g_group_id);
        
        table_rt->g2c_rt.ref_compile_rt = &(compile_table_rt->compile_rt);
        table_rt->g2c_rt.ref_g2g_rt = &(g2g_table_rt->g2g_rt);
        assert(table_rt->g2c_rt.ref_compile_rt != NULL);
        assert(table_rt->g2c_rt.ref_g2g_rt != NULL);
    }

    return 0;
}

void table_manager_deinit(struct table_manager *tbl_mgr)
{
    if (NULL == tbl_mgr) {
        return;
    }
    
	for(size_t i = 0; i < MAX_TABLE_NUM; i++) {
		maat_table_runtime_free(tbl_mgr->tbl[i]->runtime, tbl_mgr->tbl[i]->table_type);
		tbl_mgr->tbl[i]->runtime = NULL;
	}
}

void table_manager_destroy(struct table_manager *tbl_mgr)
{
    if (NULL == tbl_mgr) {
        return;
    }

	for (size_t i = 0; i < MAX_TABLE_NUM; i++) {
        assert(NULL == tbl_mgr->tbl[i]->runtime);

		if (NULL == tbl_mgr->tbl[i]->schema) {
			continue;
		}

		table_schema_free(tbl_mgr->tbl[i]->schema);
		tbl_mgr->tbl[i]->schema = NULL;
	}

	maat_kv_store_free(tbl_mgr->tablename2id_map);
	FREE(tbl_mgr);
}

size_t table_manager_table_count(struct table_manager *tbl_mgr)
{
    return MAX_TABLE_NUM;
}

int table_manager_get_table_id(struct table_manager *tbl_mgr, const char *name)
{

}

enum table_type table_manager_get_table_type(struct table_manager *tbl_mgr, int table_id)
{

}

int table_manager_get_logger(struct table_manager *tbl_mgr)
{

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

struct ex_data_schema *table_manager_get_table_ex_data_schema(struct table_manager *tbl_mgr, int table_id)
{
    
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

int table_manager_accept_tags_match(struct table_manager *tbl_mgr, const char *tags)
{

}

void *table_manager_get_runtime(struct table_manager *tbl_mgr, int table_id)
{
    if (NULL == tbl_mgr || (table_id < 0) || (table_id >= MAX_TABLE_NUM)) {
        return NULL;
    }

    assert(table_id < (int)tbl_mgr->n_table);

    if (NULL == tbl_mgr->tbl[table_id]) {
        return NULL;
    }

	return tbl_mgr->tbl[table_id]->runtime;
}

int table_manager_update_runtime(struct table_manager *tbl_mgr, int table_id, const char *line)
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
        return -1;
    }

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_MAX) {
        return -1;
    }

    if (NULL == table_ops[table_type].update_runtime) {
        return -1;
    }

    return table_ops[table_type].update_runtime(runtime, schema, line, valid_column);

    #if 0
    switch (table_rt->table_type) {
        case TABLE_TYPE_COMPILE:
            ret = compile_runtime_update(table_rt->custom_rt, table_item->custom_item, table_schema, table_name, table_rt->ref_garbage_bin, logger);
            break;
        case TABLE_TYPE_GROUP2COMPILE:
            ret = group2compile_runtime_update(table_rt->custom_rt, table_item->custom_item, table_name, table_rt->ref_garbage_bin, logger);
            break;
        case TABLE_TYPE_GROUP2GROUP:
            ret = group2group_runtime_update(table_rt->custom_rt, table_item->custom_item, table_name, logger);
            break;
        case TABLE_TYPE_EXPR:
            ret = expr_runtime_update(table_rt->custom_rt, table_item->custom_item, table_name, table_rt->ref_garbage_bin, logger);
            break;
        case TABLE_TYPE_IP_PLUS:
            ret = ip_plus_runtime_update(table_rt->custom_rt, table_item->custom_item, table_name, table_rt->ref_garbage_bin, logger);
            break;
        case TABLE_TYPE_PLUGIN:
            ret = plugin_runtime_update(table_rt->custom_rt, table_item->custom_item, table_schema, table_name, row, logger);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            ret = ip_plugin_runtime_update(table_rt->custom_rt, table_item->custom_item, table_schema, table_name, row, logger);
            break;
        default:
            break;
    }

    if (ret < 0) {
        return;
    }
    #endif
#if 0
    if (is_valid == 0) {
        table_rt->rule_num--;
    } else {
        table_rt->rule_num++;
    }
#endif
}

void table_manager_commit_runtime(struct table_manager *tbl_mgr, int table_id)
{
    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_MAX) {
        return;
    }

    void *runtime = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == runtime) {
        return;
    }

    table_ops[table_type].commit_runtime(runtime);
}