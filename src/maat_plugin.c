/*
**********************************************************************************************
*	File: maat_plugin.cpp
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "log/log.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "maat_plugin.h"
#include "maat_ex_data.h"
#include "maat_limits.h"
#include "maat_table.h"

#define MODULE_PLUGIN	 module_name_str("maat.plugin")

struct plugin_callback_schema {
	maat_start_callback_t *start;
	maat_update_callback_t *update;
	maat_finish_callback_t *finish;
	void *u_para;
};

struct plugin_runtime {
    long long acc_line_num;
    struct ex_data_runtime *ex_data_rt;

    uint32_t rule_num;
    uint32_t updating_rule_num;

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

#define	MAX_PLUGIN_PER_TABLE 32
struct plugin_schema {
    int key_column;
    int rule_tag_column;
    int n_foreign;
    int foreign_columns[MAX_FOREIGN_CLMN_NUM];
    size_t cb_cnt;
    struct plugin_callback_schema cb[MAX_PLUGIN_PER_TABLE];
    struct ex_data_schema *ex_schema;
    int table_id; //ugly
    struct table_manager *ref_tbl_mgr;

    unsigned long long update_err_cnt;
    unsigned long long unmatch_tag_cnt;
};

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

void *plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                        const char *table_name, struct log_handle *logger)
{
    struct plugin_schema *schema = ALLOC(struct plugin_schema, 1);

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (NULL == item || item->type != cJSON_Number) {
        log_error(logger, MODULE_PLUGIN, 
                  "plugin table %s has no table_id column", table_name);
        goto error;
    }
    schema->table_id = item->valueint;

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_PLUGIN, 
                  "plugin table %s has no custom column", table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "key");
    if (NULL == custom_item || custom_item->type != cJSON_Number) {
        log_error(logger, MODULE_PLUGIN, 
                  "plugin table: %s has no key column", table_name);
        goto error;
    }
    schema->key_column = custom_item->valueint;
    
    custom_item = cJSON_GetObjectItem(item, "tag");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->rule_tag_column = custom_item->valueint;
    }

    custom_item = cJSON_GetObjectItem(item, "foreign");
    if (custom_item != NULL) {
        if (custom_item->type == cJSON_String) {
            schema->n_foreign = read_integer_array(custom_item->valuestring, 
                                                    schema->foreign_columns, 
                                                    MAX_FOREIGN_CLMN_NUM);
        } else if (custom_item->type == cJSON_Array) {
            schema->n_foreign = cJSON_GetArraySize(custom_item);
            for (int i = 0; i < schema->n_foreign; i++) {
                cJSON *foreign_item = cJSON_GetArrayItem(custom_item, i);
                assert(foreign_item->type == cJSON_Number);
                schema->foreign_columns[i] = foreign_item->valueint;
            }
        }
    }

    schema->ref_tbl_mgr = tbl_mgr;
    return schema;
error:
    FREE(schema);
    return NULL;
}

void plugin_schema_free(void *plugin_schema)
{
    if (NULL == plugin_schema) {
        return;
    }

    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    if (schema->ex_schema != NULL) {
        ex_data_schema_free(schema->ex_schema);
        schema->ex_schema = NULL;
    }

    FREE(schema);
}

int plugin_table_add_callback(void *plugin_schema, int table_id,
                              maat_start_callback_t *start,
						      maat_update_callback_t *update,
							  maat_finish_callback_t *finish,
							  void *u_para, struct log_handle *logger)
{
    if (NULL == plugin_schema) {
        return -1;
    }

    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    size_t idx = schema->cb_cnt;

	if (idx == MAX_PLUGIN_PER_TABLE) {
        log_error(logger, MODULE_PLUGIN, 
                  "the plugin number of table_id: %d exceed maxium:%d", 
                  table_id, MAX_PLUGIN_PER_TABLE);
		return -1;
	}

	schema->cb_cnt++;
	schema->cb[idx].start = start;
	schema->cb[idx].update = update;
	schema->cb[idx].finish = finish;
	schema->cb[idx].u_para = u_para;

    return 0;
}

void plugin_table_all_callback_start(struct plugin_schema *plugin_schema, int update_type)
{
    for (size_t i = 0; i < plugin_schema->cb_cnt; i++) {
        if (plugin_schema->cb[i].start != NULL) {
            plugin_schema->cb[i].start(update_type, plugin_schema->cb[i].u_para);
        }
    }
}

void plugin_table_all_callback_finish(struct plugin_schema *plugin_schema)
{
    for (size_t i = 0; i < plugin_schema->cb_cnt; i++) {
        if (plugin_schema->cb[i].finish != NULL) {
            plugin_schema->cb[i].finish(plugin_schema->cb[i].u_para);
        }
    }
}

int plugin_table_get_foreign_column(struct plugin_schema *plugin_schema, 
                                    int *foreign_columns)
{
    if (NULL == plugin_schema) {
        return -1;
    }

    int n_foreign = plugin_schema->n_foreign;
    for (int i = 0; i < n_foreign; i++) {
        foreign_columns[i] = plugin_schema->foreign_columns[i];
    }

    return n_foreign;
}

void plugin_table_set_ex_data_schema(void *plugin_schema, 
                                    maat_plugin_ex_new_func_t *new_func,
							        maat_plugin_ex_free_func_t *free_func,
							        maat_plugin_ex_dup_func_t *dup_func,
							        long argl, void *argp,
                                    struct log_handle *logger)
{
    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    
    schema->ex_schema = ex_data_schema_new(new_func, free_func, dup_func, argl, argp);
}

struct ex_data_schema *plugin_table_get_ex_data_schema(void *plugin_schema)
{
    if (NULL == plugin_schema) {
        return NULL;
    }

    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    return schema->ex_schema;
}

void *plugin_runtime_new(void *plugin_schema, int max_thread_num, 
                         struct maat_garbage_bin *garbage_bin,
                         struct log_handle *logger)
{
    if (NULL == plugin_schema) {
        return NULL;
    }

    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    struct plugin_runtime *plugin_rt = ALLOC(struct plugin_runtime, 1);
    plugin_rt->ex_data_rt = ex_data_runtime_new(schema->table_id, 
                                                ex_data_container_free, logger);
    plugin_rt->ref_garbage_bin = garbage_bin;
    plugin_rt->logger = logger;

    return plugin_rt;
}

void plugin_runtime_free(void *plugin_runtime)
{
    if (NULL == plugin_runtime) {
        return;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    if (plugin_rt->ex_data_rt != NULL) {
        ex_data_runtime_free(plugin_rt->ex_data_rt);
        plugin_rt->ex_data_rt = NULL;
    }

    FREE(plugin_rt);
}

int plugin_runtime_update_row(struct plugin_runtime *plugin_rt, 
                              struct plugin_schema *plugin_schema, 
                              const char *row, char *key, size_t key_len, 
                              int is_valid)
{
    int ret = -1;
    struct ex_data_schema *ex_schema = plugin_schema->ex_schema;

    /* already set plugin_table_schema's ex_data_schema */
    if (ex_schema != NULL) {
        if (is_valid == 0) {
            // delete
            ret = ex_data_runtime_del_ex_container(plugin_rt->ex_data_rt, key, key_len);
            if (ret < 0) {
                return -1;
            }
        } else {
            // add
            void *ex_data = ex_data_runtime_row2ex_data(plugin_rt->ex_data_rt, row, key, key_len);
            struct ex_data_container *ex_container = ex_data_container_new(ex_data, NULL);
            ret = ex_data_runtime_add_ex_container(plugin_rt->ex_data_rt, key, key_len, ex_container);
            if (ret < 0) {
                return -1;
            }
        }
    }

    /* plugin table schema has callback */
    size_t cb_count = plugin_schema->cb_cnt;
    if (cb_count > 0) {
        for (size_t i = 0; i < cb_count; i++) {
            plugin_schema->cb[i].update(plugin_schema->table_id, row, plugin_schema->cb[i].u_para);
        }
    }
    
    if ((NULL == ex_schema) && (0 == cb_count)) {
        ex_data_runtime_cache_row_put(plugin_rt->ex_data_rt, row);
    }

    return 0;
}

int plugin_accept_tag_match(struct plugin_schema *schema, const char *line,
                            struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);

    if (schema->rule_tag_column > 0 && n_tag > 0) {
        int ret = get_column_pos(line, schema->rule_tag_column, &column_offset, &column_len);
        if (ret < 0) {
            log_error(logger, MODULE_PLUGIN,
                      "plugin table(table_id:%d) has no rule_tag, line:%s",
                      schema->table_id, line);
            schema->update_err_cnt++;
            return TAG_MATCH_ERR;
        }

        if (column_len > 2) {
            char *tag_str = ALLOC(char, column_len + 1);
            memcpy(tag_str, (line + column_offset), column_len);
            ret = table_manager_accept_tags_match(schema->ref_tbl_mgr, tag_str);
            FREE(tag_str);
            if (TAG_MATCH_ERR == ret) {
                log_error(logger, MODULE_PLUGIN,
                          "plugin table(table_id:%d) has invalid tag format, line:%s",
                          schema->table_id, line);
                schema->update_err_cnt++;
                return TAG_MATCH_ERR;
            }

            if (TAG_MATCH_UNMATCHED == ret) {
                schema->unmatch_tag_cnt++;
                return TAG_MATCH_UNMATCHED;
            }
        }
    }

    return TAG_MATCH_MATCHED;
}

int plugin_runtime_update(void *plugin_runtime, void *plugin_schema, 
                          const char *line, int valid_column)
{
    if (NULL == plugin_runtime || NULL == plugin_schema ||
        NULL == line) {
        return -1;
    }

    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    }

    int ret = plugin_accept_tag_match(schema, line, plugin_rt->logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        return -1;
    }

    long long item_id = get_column_value(line, schema->key_column);
    char *key = (char *)&item_id;
    ret = plugin_runtime_update_row(plugin_rt, schema, line, key, sizeof(long long), is_valid);
    if (ret < 0) {
        schema->update_err_cnt++;
        return -1;
    }
    plugin_rt->acc_line_num++;

    return 0;
}

int plugin_runtime_commit(void *plugin_runtime, const char *table_name)
{
    if (NULL == plugin_runtime) {
        return -1;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    ex_data_runtime_commit(plugin_rt->ex_data_rt);

    return 0;
}

struct ex_data_runtime *plugin_runtime_get_ex_data_rt(void *plugin_runtime)
{
    if (NULL == plugin_runtime) {
        return NULL;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    return plugin_rt->ex_data_rt;
}

size_t plugin_runtime_cached_row_count(void *plugin_runtime)
{
    if (NULL == plugin_runtime) {
        return 0;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    if (NULL == plugin_rt->ex_data_rt) {
        return 0;
    }

    return ex_data_runtime_cached_row_count(plugin_rt->ex_data_rt);
}

const char *plugin_runtime_cached_row_get(void *plugin_runtime, size_t index)
{
    if (NULL == plugin_runtime) {
        return NULL;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    if (NULL == plugin_rt->ex_data_rt) {
        return NULL;
    }

    return ex_data_runtime_cached_row_get(plugin_rt->ex_data_rt, index);
}

void *plugin_runtime_get_ex_data(void *plugin_runtime, void *plugin_schema, const char *key)
{
    if (NULL == plugin_runtime || NULL == plugin_schema) {
        return NULL;
    }

    struct plugin_runtime *plugin_rt = (struct plugin_runtime *)plugin_runtime;
    struct plugin_schema *schema = (struct plugin_schema *)plugin_schema;
    if (NULL == schema->ex_schema) {
        return NULL;
    }

    return ex_data_runtime_get_ex_data_by_key(plugin_rt->ex_data_rt, key, strlen(key));
}