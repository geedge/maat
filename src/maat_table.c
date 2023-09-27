/*
**********************************************************************************************
*	File: maat_table.c
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
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
#include "maat_ipport_plugin.h"
#include "maat_bool_plugin.h"
#include "maat_fqdn_plugin.h"
#include "maat_interval.h"
#include "maat_virtual.h"

#define MODULE_TABLE  module_name_str("maat.table")

struct maat_table {
    int table_id;
    char table_name[MAX_NAME_STR_LEN];
    enum table_type table_type;
    int valid_column;
    void *schema;
    void *runtime;
    void *updating_runtime;
};

struct table_manager {
    struct maat_table *tbl[MAX_TABLE_NUM];
    size_t n_table;

    struct rule_tag *accept_tags;
    size_t n_accept_tag;

    enum maat_expr_engine expr_engine;
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

    void *(*new_runtime)(void *schema, size_t max_thread_num,
                         struct maat_garbage_bin *garbage_bin, 
                         struct log_handle *logger);

    void (*free_runtime)(void *runtime);

    int (*update_runtime)(void *runtime, void *schema, const char *table_name,
                          const char *line, int valid_column);

    int (*commit_runtime)(void *runtime, const char *table_name, 
                          long long maat_rt_version);

    long long (*rule_count)(void *runtime);

    long long (*scan_count)(void *runtime);

    long long (*scan_cpu_time)(void *runtime);

    long long (*hit_count)(void *runtime);

    long long (*update_err_count)(void *runtime);
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
        .rule_count = flag_runtime_rule_count,
        .scan_count = flag_runtime_scan_count,
        .scan_cpu_time = flag_runtime_scan_cpu_time,
        .hit_count = flag_runtime_hit_count,
        .update_err_count = flag_runtime_update_err_count
    },
    {
        .type = TABLE_TYPE_FLAG_PLUS,
        .new_schema = flag_schema_new,
        .free_schema = flag_schema_free,
        .new_runtime = flag_runtime_new,
        .free_runtime = flag_runtime_free,
        .update_runtime = flag_runtime_update,
        .commit_runtime = flag_runtime_commit,
        .rule_count = flag_runtime_rule_count,
        .scan_count = flag_runtime_scan_count,
        .scan_cpu_time = flag_runtime_scan_cpu_time,
        .hit_count = flag_runtime_hit_count,
        .update_err_count = flag_runtime_update_err_count
    },
    {
        .type = TABLE_TYPE_EXPR,
        .new_schema = expr_schema_new,
        .free_schema = expr_schema_free,
        .new_runtime = expr_runtime_new,
        .free_runtime = expr_runtime_free,
        .update_runtime = expr_runtime_update,
        .commit_runtime = expr_runtime_commit,
        .rule_count = expr_runtime_rule_count,
        .scan_count = expr_runtime_scan_count,
        .scan_cpu_time = expr_runtime_scan_cpu_time,
        .hit_count = expr_runtime_hit_count,
        .update_err_count = expr_runtime_update_err_count
    },
    {
        .type = TABLE_TYPE_EXPR_PLUS,
        .new_schema = expr_schema_new,
        .free_schema = expr_schema_free,
        .new_runtime = expr_runtime_new,
        .free_runtime = expr_runtime_free,
        .update_runtime = expr_runtime_update,
        .commit_runtime = expr_runtime_commit,
        .rule_count = expr_runtime_rule_count,
        .scan_count = expr_runtime_scan_count,
        .scan_cpu_time = expr_runtime_scan_cpu_time,
        .hit_count = expr_runtime_hit_count,
        .update_err_count = expr_runtime_update_err_count
    },
    {
        .type = TABLE_TYPE_IP_PLUS,
        .new_schema = ip_schema_new,
        .free_schema = ip_schema_free,
        .new_runtime = ip_runtime_new,
        .free_runtime = ip_runtime_free,
        .update_runtime = ip_runtime_update,
        .commit_runtime = ip_runtime_commit,
        .rule_count = ip_runtime_rule_count,
        .scan_count = ip_runtime_scan_count,
        .scan_cpu_time = ip_runtime_scan_cpu_time,
        .hit_count = ip_runtime_hit_count,
        .update_err_count = ip_runtime_update_err_count
    },
    {
        .type = TABLE_TYPE_INTERVAL,
        .new_schema = interval_schema_new,
        .free_schema = interval_schema_free,
        .new_runtime = interval_runtime_new,
        .free_runtime = interval_runtime_free,
        .update_runtime = interval_runtime_update,
        .commit_runtime = interval_runtime_commit,
        .rule_count = interval_runtime_rule_count,
        .scan_count = interval_runtime_scan_count,
        .scan_cpu_time = interval_runtime_scan_cpu_time,
        .hit_count = interval_runtime_hit_count,
        .update_err_count = interval_runtime_update_err_cnt
    },
    {
        .type = TABLE_TYPE_INTERVAL_PLUS,
        .new_schema = interval_schema_new,
        .free_schema = interval_schema_free,
        .new_runtime = interval_runtime_new,
        .free_runtime = interval_runtime_free,
        .update_runtime = interval_runtime_update,
        .commit_runtime = interval_runtime_commit,
        .rule_count = interval_runtime_rule_count,
        .scan_count = interval_runtime_scan_count,
        .scan_cpu_time = interval_runtime_scan_cpu_time,
        .hit_count = interval_runtime_hit_count,
        .update_err_count = interval_runtime_update_err_cnt
    },
    {
        .type = TABLE_TYPE_PLUGIN,
        .new_schema = plugin_schema_new,
        .free_schema = plugin_schema_free,
        .new_runtime = plugin_runtime_new,
        .free_runtime = plugin_runtime_free,
        .update_runtime = plugin_runtime_update,
        .commit_runtime = plugin_runtime_commit,
        .rule_count = plugin_runtime_rule_count,
        .update_err_count = plugin_runtime_update_err_count
    },
    {
        .type = TABLE_TYPE_IP_PLUGIN,
        .new_schema = ip_plugin_schema_new,
        .free_schema = ip_plugin_schema_free,
        .new_runtime = ip_plugin_runtime_new,
        .free_runtime = ip_plugin_runtime_free,
        .update_runtime = ip_plugin_runtime_update,
        .commit_runtime = ip_plugin_runtime_commit,
        .rule_count = ip_plugin_runtime_rule_count,
        .update_err_count = ip_plugin_runtime_update_err_count
    },
    {
        .type = TABLE_TYPE_IPPORT_PLUGIN,
        .new_schema = ipport_plugin_schema_new,
        .free_schema = ipport_plugin_schema_free,
        .new_runtime = ipport_plugin_runtime_new,
        .free_runtime = ipport_plugin_runtime_free,
        .update_runtime = ipport_plugin_runtime_update,
        .commit_runtime = ipport_plugin_runtime_commit,
        .rule_count = ipport_plugin_runtime_rule_count,
        .update_err_count = ipport_plugin_runtime_update_err_count
    },
    {
        .type = TABLE_TYPE_FQDN_PLUGIN,
        .new_schema = fqdn_plugin_schema_new,
        .free_schema = fqdn_plugin_schema_free,
        .new_runtime = fqdn_plugin_runtime_new,
        .free_runtime = fqdn_plugin_runtime_free,
        .update_runtime = fqdn_plugin_runtime_update,
        .commit_runtime = fqdn_plugin_runtime_commit,
        .rule_count = fqdn_plugin_runtime_rule_count,
        .update_err_count = fqdn_plugin_runtime_update_err_count
    },
    {
        .type = TABLE_TYPE_BOOL_PLUGIN,
        .new_schema = bool_plugin_schema_new,
        .free_schema = bool_plugin_schema_free,
        .new_runtime = bool_plugin_runtime_new,
        .free_runtime = bool_plugin_runtime_free,
        .update_runtime = bool_plugin_runtime_update,
        .commit_runtime = bool_plugin_runtime_commit,
        .rule_count = bool_plugin_runtime_rule_count,
        .update_err_count = bool_plugin_runtime_update_err_count
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
        .type = TABLE_TYPE_COMPILE,
        .new_schema = compile_schema_new,
        .free_schema = compile_schema_free,
        .new_runtime = compile_runtime_new,
        .free_runtime = compile_runtime_free,
        .update_runtime = compile_runtime_update,
        .commit_runtime = compile_runtime_commit,
        .rule_count = compile_runtime_rule_count,
        .update_err_count = compile_runtime_update_err_count
    },
    {
        .type = TABLE_TYPE_GROUP2GROUP,
        .new_schema = group2group_schema_new,
        .free_schema = group2group_schema_free,
        .new_runtime = group2group_runtime_new,
        .free_runtime = group2group_runtime_free,
        .update_runtime = group2group_runtime_update,
        .commit_runtime = group2group_runtime_commit,
        .rule_count = group2group_runtime_rule_count,
        .update_err_count = group2group_runtime_update_err_count
    },
    {
        .type = TABLE_TYPE_GROUP2COMPILE,
        .new_schema = group2compile_schema_new,
        .free_schema = group2compile_schema_free,
        .new_runtime = group2compile_runtime_new,
        .free_runtime = group2compile_runtime_free,
        .update_runtime = group2compile_runtime_update,
        .commit_runtime = NULL,
        .rule_count = group2compile_runtime_rule_count,
        .update_err_count = group2compile_runtime_update_err_count
    }
};

//@param value is a JSON, like {"tags":[{"tag":"location","value":"北京/朝阳/华严北里/甲22号},{"tag":"isp","value":"电信"}]}
static size_t parse_accept_tag(const char *value, struct rule_tag **result,
                               struct log_handle *logger)
{
    if (NULL == value || NULL == result || NULL == logger) {
        return 0;
    }

	cJSON *json = cJSON_Parse(value);
	if (!json) {
		log_error(logger, MODULE_TABLE,
				 "[%s:%d] parse accept tag Error before: %-200.200s", 
                 __FUNCTION__, __LINE__, cJSON_GetErrorPtr());
		return 0;
	}

	cJSON *tag = NULL, *tmp = NULL;
	cJSON *array = cJSON_GetObjectItem(json, "tags");
	int n_tag = cJSON_GetArraySize(array);
	struct rule_tag *p = ALLOC(struct rule_tag, n_tag);

	for (int i = 0; i < n_tag; i++) {
		tag = cJSON_GetArrayItem(array, i);
		tmp = cJSON_GetObjectItem(tag, "tag");
		p[i].tag_name = maat_strdup(tmp->valuestring);
		tmp = cJSON_GetObjectItem(tag, "value");
		p[i].tag_val = maat_strdup(tmp->valuestring);
	}

	cJSON_Delete(json);
	*result = p;
	return n_tag;
}

static int compare_each_tag(cJSON *tag_obj, const struct rule_tag *accept_tags,
                            size_t n_accept_tag)
{
    if (NULL == tag_obj || NULL == accept_tags) {
        return TAG_MATCH_ERR;
    }

	cJSON *tab_name_obj = cJSON_GetObjectItem(tag_obj, "tag");
	if (NULL == tab_name_obj || tab_name_obj->type != cJSON_String) {
		return TAG_MATCH_ERR;
	}

	const char *tag_name = tab_name_obj->valuestring;
	cJSON *tag_vals_array = cJSON_GetObjectItem(tag_obj, "value");
	if (NULL == tag_vals_array || tag_vals_array->type != cJSON_Array) {
		return TAG_MATCH_ERR;
	}

    int name_matched = 0;
	int n_val = cJSON_GetArraySize(tag_vals_array);
	for (size_t i = 0; i < n_accept_tag; i++) {
		if (0 != strcmp(accept_tags[i].tag_name, tag_name)) {
			continue;
		}
		name_matched++;

		for (int j = 0; j < n_val; j++) {
			cJSON *tag_val_obj = cJSON_GetArrayItem(tag_vals_array, j);
			if (NULL == tag_val_obj || tag_val_obj->type != cJSON_String) {
				return TAG_MATCH_ERR;
			}

			const char *tag_val = tag_val_obj->valuestring;
			// compare a/b/c with a/b/c/d is a miss.
			if (strlen(accept_tags[i].tag_val) < strlen(tag_val)) {
				continue;
			}

			// compare a1a2/b1/c1 with a1a2/b/ is a miss.
			//make sure the overlap is ended with a '/' 
            if (0 == strncmp(accept_tags[i].tag_val, tag_val, strlen(tag_val)) &&
				(strlen(accept_tags[i].tag_val) == strlen(tag_val) || 
                 accept_tags[i].tag_val[strlen(tag_val)] == '/')) {
				return TAG_MATCH_MATCHED;
			}
		}
	}

	//no matched name is considered as a 
	if (name_matched > 0) {
		return TAG_MATCH_UNMATCHED;
	} else {
		return TAG_MATCH_MATCHED;
	}
}

//@param tag_set likes [{"tag":"location","value":["北京/朝阳/华严北里","上海/浦东/陆家嘴"]},{"tag":"isp","value":["电信","移动"]}]
static int compare_each_tag_set(cJSON *tag_set, const struct rule_tag *accept_tags,
                                size_t n_accept_tag)
{
	int matched = 0;

	int n_tag = cJSON_GetArraySize(tag_set);
	for (int i = 0; i < n_tag; i++) {
		cJSON *tag_obj = cJSON_GetArrayItem(tag_set, i);
		if (NULL == tag_obj || tag_obj->type != cJSON_Object) {
			return TAG_MATCH_ERR;
		}

		int ret = compare_each_tag(tag_obj,  accept_tags, n_accept_tag);
		if (ret < 0) {
			return TAG_MATCH_ERR;
		}

		if(1 == ret) {
			matched++;
		}
	}

	if (matched == n_tag) {
		return TAG_MATCH_MATCHED;
	} else {
		return TAG_MATCH_UNMATCHED;
	}
}

//@param value {"tag_sets":[[{"tag":"location","value":["北京/朝阳/华严北里","上海/浦东/陆家嘴"]},
//{"tag":"isp","value":["电信","移动"]}],[{"tag":"location","value":["北京"]},{"tag":"isp","value":["联通"]}]]}
//@return 1 on match, 0 on not match, -1 on error.
static int compare_accept_tag(const char *value, const struct rule_tag *accept_tags,
                              size_t n_accept_tag)
{
	int ret = TAG_MATCH_ERR;
    int n_set = 0;
    cJSON *tag_set = NULL;
    cJSON *tag_set_array = NULL;
    
	cJSON *root = cJSON_Parse(value);
	if (NULL == root) {
		goto error;
	}

	tag_set_array = cJSON_GetObjectItem(root, "tag_sets");
	if (NULL == tag_set_array || tag_set_array->type != cJSON_Array) {
		goto error;
	}

	n_set = cJSON_GetArraySize(tag_set_array);
	for (int i = 0; i < n_set; i++) {
		tag_set = cJSON_GetArrayItem(tag_set_array, i);
		if (NULL == tag_set || tag_set->type != cJSON_Array) {
			goto error;
		}

		ret = compare_each_tag_set(tag_set, accept_tags, n_accept_tag);
        //match or error occurs.
		if (ret != TAG_MATCH_UNMATCHED) {
			break;
		}
	}

error:
	cJSON_Delete(root);
	return ret;
}

static void *maat_table_schema_new(cJSON *json, const char *table_name,
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

static void maat_table_schema_free(void *schema, enum table_type table_type)
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
    maat_kv_register(reserved_word_map, "ipport_plugin", TABLE_TYPE_IPPORT_PLUGIN);
    maat_kv_register(reserved_word_map, "bool_plugin", TABLE_TYPE_BOOL_PLUGIN);
    maat_kv_register(reserved_word_map, "fqdn_plugin", TABLE_TYPE_FQDN_PLUGIN);
    maat_kv_register(reserved_word_map, "virtual", TABLE_TYPE_VIRTUAL);
}

static struct maat_table *
maat_table_new(cJSON *json, struct maat_kv_store *reserved_word_map,
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
        memcpy(ptable->table_name, tmp_item->valuestring,
                strlen(tmp_item->valuestring));
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

    ret = maat_kv_read(reserved_word_map, item->valuestring,
                      (long long *)&(ptable->table_type));
    if (ret < 0) {
        log_error(logger, MODULE_TABLE, 
                  "[%s:%d] table:%s table_type %s is illegal", 
                  __FUNCTION__, __LINE__, ptable->table_name,
                  item->valuestring);
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

static void maat_table_runtime_free(void *runtime, enum table_type table_type)
{
    if (NULL == runtime) {
        return;
    }

    if (table_ops[table_type].free_runtime != NULL) {
        table_ops[table_type].free_runtime(runtime);
    }
}

static void maat_table_free(struct maat_table *maat_tbl)
{
    if (NULL == maat_tbl) {
        return;
    }

    if (maat_tbl->runtime != NULL) {
        maat_table_runtime_free(maat_tbl->runtime, maat_tbl->table_type);
        maat_tbl->runtime = NULL;
    }

    if (maat_tbl->updating_runtime != NULL) {
        maat_table_runtime_free(maat_tbl->updating_runtime, maat_tbl->table_type);
        maat_tbl->updating_runtime = NULL;
    }
    
    if (maat_tbl->schema != NULL) {
        maat_table_schema_free(maat_tbl->schema, maat_tbl->table_type);
        maat_tbl->schema = NULL;
    }
    
    FREE(maat_tbl);
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
                  "[%s:%d] table(table_id:%d) has db_tables, but format is invalid"
                  ", should be array", __FUNCTION__, __LINE__, table_id);
        return -1;
    }
   
    int ret = 0;
    long long tmp_table_id = 0;
    if (item != NULL) {
        int n_table_name = cJSON_GetArraySize(item);

        for (int i = 0; i < n_table_name; i++) {
            cJSON *tmp_item = cJSON_GetArrayItem(item, i);
            if (NULL == tmp_item || tmp_item->type != cJSON_String) {
                log_error(logger, MODULE_TABLE,
                          "[%s:%d] table(table_id:%d) db_tables element format invalid"
                          ", should be string", __FUNCTION__, __LINE__, table_id);
                return -1;
            }

            if (strlen(tmp_item->valuestring) >= NAME_MAX) {
                log_error(logger, MODULE_TABLE,
                          "[%s:%d] table(table_id:%d) db_tables string %s length "
                          "exceed maxium:%d", __FUNCTION__, __LINE__, table_id,
                          tmp_item->valuestring, NAME_MAX);
                return -1;
            }

            ret = maat_kv_read(tablename2id_map, tmp_item->valuestring, &tmp_table_id);
            if (ret > 0 && tmp_table_id != table_id) {
                log_error(logger, MODULE_TABLE,
                          "[%s:%d] table:<%s>(table_id:%lld) has already been registered"
                          ", can't register again", __FUNCTION__, __LINE__,
                          tmp_item->valuestring, tmp_table_id);
                return -1;
            }

            maat_kv_register(tablename2id_map, tmp_item->valuestring, table_id);
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

    ret = maat_kv_read(tablename2id_map, item->valuestring, &tmp_table_id);
    if (ret > 0 && tmp_table_id != table_id) {
        log_error(logger, MODULE_TABLE,
                  "[%s:%d] table:<%s>(table_id:%lld) has already been registered,"
                  " can't register again", __FUNCTION__, __LINE__, item->valuestring,
                  tmp_table_id);
        return -1;
    }

    maat_kv_register(tablename2id_map, item->valuestring, table_id);

    return 0;
}

struct table_manager *
table_manager_create(const char *table_info_path, const char *accept_tags,
                     enum maat_expr_engine expr_engine, struct maat_garbage_bin *garbage_bin,
                     struct log_handle *logger)
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
    tbl_mgr->expr_engine = expr_engine;
    tbl_mgr->ref_garbage_bin = garbage_bin;

    for (int i = 0; i < json_array_size; i++) {
        json = cJSON_GetArrayItem(root, i);

        if (json != NULL && json->type == cJSON_Object) {
            ret = register_tablename2id(json, tbl_mgr->tablename2id_map, logger);
            if (ret < 0) {
                log_error(logger, MODULE_TABLE, 
                          "[%s:%d] register_tablename2id failed",
                          __FUNCTION__, __LINE__);
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

            if (maat_tbl->table_type == TABLE_TYPE_VIRTUAL) {
                int phy_table_id = vtable_get_physical_table_id(tbl_mgr, maat_tbl->table_id);
                log_info(logger, MODULE_TABLE,
                         "successfully register virtual table[%s]->vtable_id:%d,"
                         " physical_table_id:%d", maat_tbl->table_name, maat_tbl->table_id,
                         phy_table_id);
            } else {
                log_info(logger, MODULE_TABLE,
                         "successfully register physical table[%s]->table_id:%d",
                         maat_tbl->table_name, maat_tbl->table_id);
            }
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

static void *maat_table_runtime_new(void *schema, enum table_type table_type,
                                    size_t max_thread_num,
                                    struct maat_garbage_bin *garbage_bin,
                                    struct log_handle *logger)
{
    void *runtime = NULL;

    if (table_ops[table_type].new_runtime != NULL) {
        runtime = table_ops[table_type].new_runtime(schema, max_thread_num,
                                                    garbage_bin, logger);
    }

    return runtime;
}

static void garbage_maat_table_runtime_free(void *runtime, void *arg)
{
    enum table_type type = *(enum table_type *)arg;
    maat_table_runtime_free(runtime, type);
}

int table_manager_runtime_create(struct table_manager *tbl_mgr, size_t max_thread_num,
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
     
        assert(tbl_mgr->tbl[i]->updating_runtime == NULL);
        table_type = table_manager_get_table_type(tbl_mgr, i);
        assert(table_type != TABLE_TYPE_INVALID);
        tbl_mgr->tbl[i]->updating_runtime = maat_table_runtime_new(schema, table_type, max_thread_num,
                                                                    garbage_bin, tbl_mgr->logger);
    }

    /* group2compile runtime depends on associated compile runtime,
       must make sure associated compile runtime already exist */
    for (i = 0; i < MAX_TABLE_NUM; i++) {
        table_type = table_manager_get_table_type(tbl_mgr, i);
        if (table_type != TABLE_TYPE_GROUP2COMPILE) {
            continue;
        }

        void *schema = table_manager_get_schema(tbl_mgr, i);
        if (NULL == schema) {
            log_error(tbl_mgr->logger, MODULE_TABLE, 
                      "[%s:%d] group2compile table(table_id:%d) schema is null",
                      __FUNCTION__, __LINE__, i);
            continue;
        }

        void *g2c_updating_rt = table_manager_get_updating_runtime(tbl_mgr, i);
        if (NULL == g2c_updating_rt) {
            continue;
        }

        int asso_compile_table_id = group2compile_associated_compile_table_id(schema);
        void *compile_updating_rt = table_manager_get_updating_runtime(tbl_mgr, asso_compile_table_id);
        group2compile_runtime_init(g2c_updating_rt, compile_updating_rt);
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

size_t table_manager_table_size(struct table_manager *tbl_mgr)
{
    return MAX_TABLE_NUM;
}

size_t table_manager_table_count(struct table_manager *tbl_mgr)
{
    if (NULL == tbl_mgr) {
        return 0;
    }

    return tbl_mgr->n_table;
}

int table_manager_get_table_id(struct table_manager *tbl_mgr, const char *name)
{
    if (NULL == tbl_mgr || NULL == name) {
        return -1;
    }

    long long table_id = -1;
    int ret = maat_kv_read(tbl_mgr->tablename2id_map, name, &table_id);
	if (ret < 0) {
		return -1;
	}

    return (int)table_id;
}

const char *table_manager_get_table_name(struct table_manager *tbl_mgr, int table_id)
{
    if (NULL == tbl_mgr || table_id < 0) {
        return NULL;
    }

    if (NULL == tbl_mgr->tbl[table_id]) {
        return NULL;
    }

    return tbl_mgr->tbl[table_id]->table_name;
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

int table_manager_get_default_compile_table_id(struct table_manager *tbl_mgr)
{
    if (NULL == tbl_mgr) {
        return -1;
    }

    return tbl_mgr->default_compile_table_id;
}

int table_manager_get_group2group_table_id(struct table_manager *tbl_mgr)
{
    if (NULL == tbl_mgr) {
        return -1;
    }

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

enum maat_expr_engine table_manager_get_expr_engine(struct table_manager *tbl_mgr)
{
    if (NULL == tbl_mgr) {
        return MAAT_EXPR_ENGINE_HS;
    }

    return tbl_mgr->expr_engine;
}

size_t table_manager_accept_tags_count(struct table_manager *tbl_mgr)
{
    if (NULL == tbl_mgr) {
        return -1;
    }

    return tbl_mgr->n_accept_tag;
}

int table_manager_accept_tags_match(struct table_manager *tbl_mgr, const char *tags)
{
    if (NULL == tbl_mgr) {
        return -1;
    }
    
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

void *table_manager_get_updating_runtime(struct table_manager *tbl_mgr, int table_id)
{
    if (NULL == tbl_mgr || (table_id < 0) || (table_id >= MAX_TABLE_NUM)) {
        return NULL;
    }

    if (NULL == tbl_mgr->tbl[table_id]) {
        return NULL;
    }

	return tbl_mgr->tbl[table_id]->updating_runtime;
}

int table_manager_update_runtime(struct table_manager *tbl_mgr, const char *table_name,
                                 int table_id, const char *line, int update_type)
{
    void *schema = table_manager_get_schema(tbl_mgr, table_id);
    if (NULL == schema) {
        return -1;
    }

    void *runtime = NULL;
    if (update_type == MAAT_UPDATE_TYPE_FULL) {
        runtime = table_manager_get_updating_runtime(tbl_mgr, table_id);
    } else {
        runtime = table_manager_get_runtime(tbl_mgr, table_id);
    }
  
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

void table_commit_updating_runtime(struct table_manager *tbl_mgr, int table_id, 
                                   long long maat_rt_version)
{
    void *updating_rt = table_manager_get_updating_runtime(tbl_mgr, table_id);
    if (NULL == updating_rt) {
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
        table_ops[table_type].commit_runtime(updating_rt, ptable->table_name, maat_rt_version);
    }

    void *runtime = table_manager_get_runtime(tbl_mgr, table_id);
    tbl_mgr->tbl[table_id]->runtime = updating_rt;
    
    if (runtime != NULL) {
        enum table_type *arg = ALLOC(enum table_type, 1);
        *arg = table_type;
        maat_garbage_bagging(tbl_mgr->ref_garbage_bin, runtime, arg, 
                             garbage_maat_table_runtime_free);
    }

    tbl_mgr->tbl[table_id]->updating_runtime = NULL;
}

void table_commit_runtime(struct table_manager *tbl_mgr, int table_id, 
                          long long maat_rt_version)
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
    if (table_ops[table_type].commit_runtime != NULL) {
        table_ops[table_type].commit_runtime(runtime, ptable->table_name, maat_rt_version);
    }
}

void table_manager_commit_runtime(struct table_manager *tbl_mgr, int table_id,
                                  int update_type, long long maat_rt_version)
{
    if (NULL == tbl_mgr || table_id < 0) {
        return;
    }

    if (update_type == MAAT_UPDATE_TYPE_FULL) {
        table_commit_updating_runtime(tbl_mgr, table_id, maat_rt_version);
    } else {
        table_commit_runtime(tbl_mgr, table_id, maat_rt_version);
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

    if (NULL == table_ops[table_type].rule_count) {
        return 0;
    }

    return table_ops[table_type].rule_count(runtime);
}

long long table_manager_runtime_scan_count(struct table_manager *tbl_mgr, int table_id)
{
    void *runtime = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == runtime) {
        return 0;
    }

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_INVALID) {
        log_error(tbl_mgr->logger, MODULE_TABLE, 
                  "[%s:%d] table(table_id:%d) table_type is invalid, can't get scan count",
                  __FUNCTION__, __LINE__, table_id);
        return 0;
    }

    if (NULL == table_ops[table_type].scan_count) {
        return 0;
    }

    return table_ops[table_type].scan_count(runtime);
}

long long table_manager_runtime_scan_cpu_time(struct table_manager *tbl_mgr, int table_id)
{
    void *runtime = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == runtime) {
        return 0;
    }

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_INVALID) {
        log_error(tbl_mgr->logger, MODULE_TABLE, 
                  "[%s:%d] table(table_id:%d) table_type is invalid, can't get scan cpu time",
                  __FUNCTION__, __LINE__, table_id);
        return 0;
    }

    if (NULL == table_ops[table_type].scan_cpu_time) {
        return 0;
    }

    return table_ops[table_type].scan_cpu_time(runtime);
}

long long table_manager_runtime_hit_count(struct table_manager *tbl_mgr, int table_id)
{
    void *runtime = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == runtime) {
        return 0;
    }

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_INVALID) {
        log_error(tbl_mgr->logger, MODULE_TABLE, 
                  "[%s:%d] table(table_id:%d) table_type is invalid, can't get hit count",
                  __FUNCTION__, __LINE__, table_id);
        return 0;
    }

    if (NULL == table_ops[table_type].hit_count) {
        return 0;
    }

    return table_ops[table_type].hit_count(runtime);
}

long long table_manager_runtime_update_err_count(struct table_manager *tbl_mgr, int table_id)
{
    void *runtime = table_manager_get_runtime(tbl_mgr, table_id);
    if (NULL == runtime) {
        return 0;
    }

    enum table_type table_type = table_manager_get_table_type(tbl_mgr, table_id);
    if (table_type == TABLE_TYPE_INVALID) {
        log_error(tbl_mgr->logger, MODULE_TABLE, 
                  "[%s:%d] table(table_id:%d) table_type is invalid, can't get hit count",
                  __FUNCTION__, __LINE__, table_id);
        return 0;
    }

    if (NULL == table_ops[table_type].update_err_count) {
        return 0;
    }

    return table_ops[table_type].update_err_count(runtime);
}