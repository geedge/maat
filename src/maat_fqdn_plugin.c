/*
**********************************************************************************************
*	File: maat_fqdn_plugin.cpp
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "maat_fqdn_plugin.h"
#include "maat_ex_data.h"
#include "fqdn_engine.h"
#include "log/log.h"
#include "maat_utils.h"
#include "maat_table.h"
#include "maat_rule.h"
#include "maat_garbage_collection.h"

#define MODULE_FQDN_PLUGIN	 module_name_str("maat.bool_plugin")

struct fqdn_plugin_schema {
    int item_id_column;
    int suffix_flag_column;
    int fqdn_column;
    int rule_tag_column;
    struct ex_data_schema *ex_schema;
    int table_id;
    struct table_manager *ref_tbl_mgr;

    unsigned long long update_err_cnt;
    unsigned long long unmatch_tag_cnt;
};

struct fqdn_plugin_item {
    uint64_t item_id;
    int suffix_flag;

};

struct fqdn_plugin_runtime {
    struct FQDN_engine *engine;
    struct ex_data_runtime *ex_data_rt;

    uint32_t rule_num;
    uint32_t updating_rule_num;

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;
};

void *fqdn_plugin_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                             const char *table_name, struct log_handle *logger)
{
    size_t read_cnt = 0;
    struct fqdn_plugin_schema *schema = ALLOC(struct fqdn_plugin_schema, 1);

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
   if (item != NULL && item->type == cJSON_Number) {
        schema->table_id = item->valueint;
        read_cnt++;
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (NULL == item || item->type != cJSON_Object) {
        log_error(logger, MODULE_FQDN_PLUGIN, 
                  "table %s has no custom column", table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->item_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "suffix_match_method");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->suffix_flag_column = custom_item->valueint;
        read_cnt++;
    }

    // rule_tag is optional
    custom_item = cJSON_GetObjectItem(item, "fqdn");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->fqdn_column = custom_item->valueint;
        read_cnt++;
    }

    // rule_tag is optional
    custom_item = cJSON_GetObjectItem(item, "rule_tag");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        schema->rule_tag_column = custom_item->valueint;
    }

    schema->ref_tbl_mgr = tbl_mgr;

    if (read_cnt < 4) {
        goto error;
    }
    
    return schema;
error:
    FREE(schema);
    return NULL;
}

void fqdn_plugin_schema_free(void *fqdn_plugin_schema)
{
    if (NULL == fqdn_plugin_schema) {
        return;
    }
    struct fqdn_plugin_schema *schema = (struct fqdn_plugin_schema *)fqdn_plugin_schema;
    if (schema->ex_schema != NULL) {
        ex_data_schema_free(schema->ex_schema);
        schema->ex_schema = NULL;
    }

    FREE(schema);
}

/* fqdn plugin table ex data API */
struct ex_data_schema *fqdn_plugin_table_get_ex_data_schema(void *fqdn_plugin_schema)
{
    if (NULL == fqdn_plugin_schema) {
        return NULL;
    }

    struct fqdn_plugin_schema *schema = (struct fqdn_plugin_schema *)fqdn_plugin_schema;

    return schema->ex_schema;
}

int fqdn_plugin_table_set_ex_data_schema(void *fqdn_plugin_schema, 
                                         maat_plugin_ex_new_func_t *new_func,
							             maat_plugin_ex_free_func_t *free_func,
							             maat_plugin_ex_dup_func_t *dup_func,
							             long argl, void *argp,
                                         struct log_handle *logger)
{
    if (NULL == fqdn_plugin_schema) {
        return -1;
    }

    struct fqdn_plugin_schema *schema = (struct fqdn_plugin_schema *)fqdn_plugin_schema;
    if (schema->ex_schema != NULL) {
        assert(0);
        log_error(logger, MODULE_FQDN_PLUGIN,
                  "Error: %s, EX data schema already registed", __FUNCTION__);
        return -1;
    }

    schema->ex_schema = ex_data_schema_new(new_func, free_func, dup_func, argl, argp);

    return 0;
}

void *fqdn_plugin_runtime_new(void *fqdn_plugin_schema, int max_thread_num,
                              struct maat_garbage_bin *garbage_bin,
                              struct log_handle *logger)
{
    if (NULL == fqdn_plugin_schema) {
        return NULL;
    }

    struct fqdn_plugin_schema *schema = (struct fqdn_plugin_schema *)fqdn_plugin_schema;
    struct fqdn_plugin_runtime *fqdn_plugin_rt = ALLOC(struct fqdn_plugin_runtime, 1);

    fqdn_plugin_rt->ex_data_rt = ex_data_runtime_new(schema->table_id, ex_data_container_free, 
                                                     logger);
    fqdn_plugin_rt->ref_garbage_bin = garbage_bin;
    fqdn_plugin_rt->logger = logger;

    return fqdn_plugin_rt;
}

void fqdn_plugin_runtime_free(void *fqdn_plugin_runtime)
{
    if (NULL == fqdn_plugin_runtime) {
        return;
    }

    struct fqdn_plugin_runtime *fqdn_plugin_rt = (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;
    if (fqdn_plugin_rt->engine != NULL) {
        FQDN_engine_free(fqdn_plugin_rt->engine);
        fqdn_plugin_rt->engine = NULL;
    }

    if (fqdn_plugin_rt->ex_data_rt != NULL) {
        ex_data_runtime_free(fqdn_plugin_rt->ex_data_rt);
        fqdn_plugin_rt->ex_data_rt = NULL;
    }

    FREE(fqdn_plugin_rt);
}

int fqdn_plugin_accept_tag_match(struct fqdn_plugin_schema *schema, const char *line,
                                 struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    size_t n_tag = table_manager_accept_tags_count(schema->ref_tbl_mgr);

    if (schema->rule_tag_column > 0 && n_tag > 0) {
        int ret = get_column_pos(line, schema->rule_tag_column, 
                                 &column_offset, &column_len);
        if (ret < 0) {
            log_error(logger, MODULE_FQDN_PLUGIN,
                      "fqdn_plugin table(table_id:%d) has no rule_tag, line:%s",
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
                log_error(logger, MODULE_FQDN_PLUGIN,
                          "fqdn_plugin table(table_id:%d) has invalid tag format, line:%s",
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

struct fqdn_plugin_item *
fqdn_plugin_item_new(const char *line, struct fqdn_plugin_schema *schema,
                     struct log_handle *logger)
{
     int ret = fqdn_plugin_accept_tag_match(schema, line, logger);
    if (ret == TAG_MATCH_UNMATCHED) {
        return NULL;
    }

    size_t column_offset = 0;
    size_t column_len = 0;
    struct fqdn_plugin_item *item = ALLOC(struct fqdn_plugin_item, 1);

    ret = get_column_pos(line, schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_FQDN_PLUGIN, 
                  "fqdn_plugin table(table_id:%d) line:%s has no item_id column",
                  schema->table_id, line);
        goto error;
    }
    item->item_id = atoll(line + column_offset);

    ret = get_column_pos(line, schema->suffix_flag_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_FQDN_PLUGIN, 
                  "fqdn_plugin table(table_id:%d) line:%s has no suffix_match_method column",
                  schema->table_id, line);
        goto error;
    }
    item->suffix_flag = atoi(line + column_offset);

    ret = get_column_pos(line, schema->fqdn_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_FQDN_PLUGIN, 
                  "fqdn_plugin table(table_id:%d) line:%s has no fqdn column",
                  schema->table_id, line);
        goto error;
    }

    return item;
error:
    FREE(item);
    return NULL;
}

struct FQDN_rule *fqdn_rule_new(unsigned int id, const char* fqdn, size_t fqdn_len, int is_suffix_match)
{
	struct FQDN_rule *fqdn_rule=ALLOC(struct FQDN_rule, 1);
	//Todo: check FQDN format with regex ^([a-zA-Z0-9._-])+$
	if(fqdn[0]=='.')
	{
		fqdn++;
		fqdn_len--;
	}
	if(fqdn[fqdn_len]=='/')
	{
		fqdn_len--;
	}	
	fqdn_rule->FQDN=ALLOC(char, fqdn_len+1);
	memcpy(fqdn_rule->FQDN, fqdn, fqdn_len);
	fqdn_rule->len=fqdn_len;
	fqdn_rule->is_suffix_match=is_suffix_match;
	fqdn_rule->id=id;
	return fqdn_rule;
}

int fqdn_plugin_runtime_update_row(struct fqdn_plugin_runtime *rt, 
                                   struct fqdn_plugin_schema *schema,
                                   const char *row, char *key, size_t key_len, 
                                   struct FQDN_rule *rule, int is_valid)
{
    return 0;
}

int fqdn_plugin_runtime_update(void *fqdn_plugin_runtime, void *fqdn_plugin_schema, 
                               const char *line, int valid_column)
{
    if (NULL == fqdn_plugin_runtime || NULL == fqdn_plugin_schema || 
        NULL == line) {
        return -1;
    }

    struct fqdn_plugin_item *item = NULL;
    struct FQDN_rule *rule = NULL;
    struct fqdn_plugin_schema *schema = (struct fqdn_plugin_schema *)fqdn_plugin_schema;
    struct fqdn_plugin_runtime *fqdn_plugin_rt = (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;
    long long item_id = get_column_value(line, schema->item_id_column);
    if (item_id < 0) {
        return -1;
    }

    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    }

    if (schema->ex_schema != NULL) {
        if (1 == is_valid) {
            // add
            item = fqdn_plugin_item_new(line, schema, fqdn_plugin_rt->logger);
            if (NULL == item) {
                return -1;
            }

            //rule = fqdn_rule_new(line, schema, fqdn_plugin_rt->logger);
            assert(rule != NULL);
            //fqdn_plugin_item_free(item);
        }

        char *key = (char *)&item_id;
        int ret = fqdn_plugin_runtime_update_row(fqdn_plugin_rt, schema, line, key,
                                                 sizeof(uint64_t), rule, is_valid);
        if (ret < 0) {
            if (item != NULL) {
                FREE(item);
            }
            return -1;
        } else {
            if (0 == is_valid) {
                fqdn_plugin_rt->rule_num--;
            } else {
                fqdn_plugin_rt->rule_num++;
            }
        }
    } else {
        //ex_schema not set
        ex_data_runtime_cache_row_put(fqdn_plugin_rt->ex_data_rt, line);
        fqdn_plugin_rt->rule_num = ex_data_runtime_cached_row_count(fqdn_plugin_rt->ex_data_rt);
    }

    return 0;
}

int fqdn_plugin_runtime_commit(void *fqdn_plugin_runtime, const char *table_name)
{
     if (NULL == fqdn_plugin_runtime) {
        return -1;
    }

    int ret = 0;
    struct ex_data_container **ex_container = NULL;
    struct fqdn_plugin_runtime *fqdn_plugin_rt = (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;
    struct ex_data_runtime *ex_data_rt = fqdn_plugin_rt->ex_data_rt;

    size_t rule_cnt = ex_data_runtime_list_updating_ex_container(ex_data_rt, &ex_container);
    if (0 == rule_cnt) {
        FREE(ex_container);
        return 0;
    }

    struct FQDN_rule *rules = ALLOC(struct FQDN_rule, rule_cnt);

    for (size_t i = 0; i < rule_cnt; i++) {
        rules[i] = *(struct FQDN_rule *)ex_container[i]->custom_data;
        assert(rules[i].user_tag == ex_container[i] || NULL == rules[i].user_tag);
        rules[i].user_tag = ex_container[i];
    }

    struct FQDN_engine *new_fqdn_engine = NULL;
    struct FQDN_engine *old_fqdn_engine = NULL;

    log_info(fqdn_plugin_rt->logger, MODULE_FQDN_PLUGIN,
             "table[%s] committing %zu fqdn_plugin rules for rebuilding FQDN engine", 
             table_name, rule_cnt);

    new_fqdn_engine = FQDN_engine_new(rules, rule_cnt);
    if (NULL == new_fqdn_engine) {
        log_error(fqdn_plugin_rt->logger, MODULE_FQDN_PLUGIN,
                  "table[%s] rebuild FQDN engine failed when update %zu fqdn_plugin rules",
                  table_name, rule_cnt);
        ret = -1;
    }

    old_fqdn_engine = fqdn_plugin_rt->engine;
    fqdn_plugin_rt->engine = new_fqdn_engine;
    maat_garbage_bagging(fqdn_plugin_rt->ref_garbage_bin, old_fqdn_engine, 
                        (void (*)(void*))FQDN_engine_free);
    ex_data_runtime_commit(ex_data_rt);

    FREE(rules);
    FREE(ex_container);

    return ret;
}

struct ex_data_runtime *fqdn_plugin_runtime_get_ex_data_rt(void *fqdn_plugin_runtime)
{
    if (NULL == fqdn_plugin_runtime) {
        return NULL;
    }

    struct fqdn_plugin_runtime *fqdn_plugin_rt = (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;

    return fqdn_plugin_rt->ex_data_rt;
}


int fqdn_plugin_runtime_get_ex_data(void *fqdn_plugin_runtime, const char *query_fqdn, 
                                    void **ex_data_array, size_t n_ex_data)
{
    if (NULL == fqdn_plugin_runtime) {
        return -1;
    }

    struct fqdn_plugin_runtime *fqdn_plugin_rt = (struct fqdn_plugin_runtime *)fqdn_plugin_runtime;
    if (NULL == fqdn_plugin_rt->engine) {
        log_info(fqdn_plugin_rt->logger, MODULE_FQDN_PLUGIN, 
                 "fqdn_engine is NULL, can't get ex data");
        return 0;
    }

    struct FQDN_match results[n_ex_data];
	memset(results, 0, sizeof(results));

	int n_result = FQDN_engine_search(fqdn_plugin_rt->engine, query_fqdn, strlen(query_fqdn), results, n_ex_data);
	for (int i = 0; i < n_result; i++) {
		ex_data_array[i] = ex_data_runtime_get_ex_data_by_container(fqdn_plugin_rt->ex_data_rt, 
                                                                    (struct ex_data_container *)results[i].user_tag);
	}

	return n_result;
}