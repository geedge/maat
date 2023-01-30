/*
**********************************************************************************************
*	File: maat_expr.cpp
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <string.h>
#include <assert.h>

#include "utils.h"
#include "maat_expr.h"
#include "adapter_hs.h"
#include "maat_utils.h"
#include "maat_kv.h"
#include "maat_limits.h"
#include "rcu_hash.h"
#include "maat_rule.h"
#include "maat_garbage_collection.h"

#define MAX_DISTRICT_STR     128

#define MODULE_EXPR	 module_name_str("maat.expr")

struct expr_schema {
	int item_id_column;
    int group_id_column;
	int district_column;
	int keywords_column;
	int expr_type_column;
    int match_method_column;
    int is_hexbin_column;
    enum hs_scan_mode scan_mode; /* adapter_hs scan mode */
};

enum expr_type {
    EXPR_TYPE_STRING = 0,
	EXPR_TYPE_AND,
    EXPR_TYPE_REGEX,
    EXPR_TYPE_MAX
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
};

struct expr_runtime {
    enum hs_scan_mode scan_mode;
    struct adapter_hs *hs;
    struct adapter_hs_stream *hs_stream;
    struct rcu_hash_table *htable;
    struct group2group_runtime *ref_g2g_rt;

    uint32_t rule_num;
    uint32_t updating_rule_num;
    struct maat_item *item_hash;
    void (*item_user_data_free)(void *);

    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;

    // long long *scan_cnt;
    // long long *hit_cnt;
    // long long *not_grp_hit_cnt;
    // long long *stream_num;
};

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

struct expr_item *expr_item_new(const char *line, struct expr_schema *expr_schema,
                                struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    int db_hexbin = -1;
    int expr_type = -1;
    int match_method_type = -1;
    struct expr_item *expr_item = ALLOC(struct expr_item, 1);

    int ret = get_column_pos(line, expr_schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        goto error;
    }
    expr_item->item_id = atoi(line + column_offset);

    ret = get_column_pos(line, expr_schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        goto error;
    }
    expr_item->group_id = atoi(line + column_offset);

    //TODO
    #if 0
    if (table_item->table_type == TABLE_TYPE_EXPR_PLUS) {
        ret = get_column_pos(line, expr_schema->district_column, &column_offset, &column_len);
        if (ret < 0) {
            return -1;
        }

        if (column_len >= MAX_DISTRICT_STR) {
            log_error(logger, MODULE_EXPR, 
                      "update error: expr table[%s]:item_id[%d] district length too long",
                      table_name, expr_item->item_id);
            return -1;
        }
        memcpy(expr_item->district, (line + column_offset), column_len);
    }
    #endif
    ret = get_column_pos(line, expr_schema->keywords_column, &column_offset, &column_len);
    if (ret < 0) {
        goto error;
    }

    if (column_len >= MAX_KEYWORDS_STR) {
        log_error(logger, MODULE_EXPR, 
                      "update error: expr table[%s]:item_id[%d] keywords length too long",
                      table_name, expr_item->item_id);
        goto error;
    }
    memcpy(expr_item->keywords, (line + column_offset), column_len);

    ret = get_column_pos(line, expr_schema->expr_type_column, &column_offset, &column_len);
    if (ret < 0) {
        goto error;
    }
    
    expr_type = atoi(line + column_offset);
    expr_item->expr_type = int_to_expr_type(expr_type);

    ret = get_column_pos(line, expr_schema->match_method_column, &column_offset, &column_len);
    if (ret < 0) {
        goto error;
    }
    
    match_method_type = atoi(line + column_offset);
    expr_item->match_method = int_to_match_method_type(match_method_type);

    ret = get_column_pos(line, expr_schema->is_hexbin_column, &column_offset, &column_len);
    if (ret < 0) {
        goto error;
    }
    db_hexbin = atoi(line + column_offset);

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
            log_error(logger, MODULE_EXPR, 
                      "update error: expr table[%s]:item_id[%d] invalid hexbin value:%d",
                      table_name, expr_item->item_id, db_hexbin);
            goto error;
    }
    
    return expr_item;
error:
    FREE(expr_item);
    return NULL;
}

void expr_item_free(struct expr_item *expr_item)
{
    FREE(expr_item);
}

void *expr_schema_new(cJSON *json, const char *table_name, struct log_handle *logger)
{
    int read_cnt = 0;
	struct expr_schema *expr_schema = ALLOC(struct expr_schema, 1);
	struct maat_kv_store *scan_mode_map = maat_kv_store_new();

    maat_kv_register(scan_mode_map, "block", HS_SCAN_MODE_BLOCK);
    maat_kv_register(scan_mode_map, "stream", HS_SCAN_MODE_STREAM);

    int ret = -1;
    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_EXPR, "table %s has no custom column", table_name);
        goto error;
    }

	custom_item = cJSON_GetObjectItem(item, "scan_mode");
	if (custom_item != NULL && custom_item->type == cJSON_String) {
		ret = maat_kv_read(scan_mode_map, custom_item->valuestring, (int*)&(expr_schema->scan_mode));
        if (ret < 0) {
            log_error(logger, MODULE_EXPR, "scan_mode %s illegal", custom_item->valuestring);
            goto error;
        }
        read_cnt++;
	}

	custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->item_id_column = custom_item->valueint;
        read_cnt++;
    }

	custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->group_id_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "keywords");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->keywords_column = custom_item->valueint;
        read_cnt++;
    }

	custom_item = cJSON_GetObjectItem(item, "district");
	if (custom_item != NULL && custom_item->type == cJSON_Number) {
		expr_schema->district_column = custom_item->valueint;
		read_cnt++;
	}

	custom_item = cJSON_GetObjectItem(item, "expr_type");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->expr_type_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "match_method");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->match_method_column = custom_item->valueint;
        read_cnt++;
    }

    custom_item = cJSON_GetObjectItem(item, "is_hexbin");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->is_hexbin_column = custom_item->valueint;
        read_cnt++;
    }

    if (read_cnt < 8) {
		goto error;
    }
	
    maat_kv_store_free(scan_mode_map);
    return expr_schema;
error:
    maat_kv_store_free(scan_mode_map);
    FREE(expr_schema);
    return NULL;
}

void expr_schema_free(void *expr_schema)
{
    FREE(expr_schema);
}

void *expr_runtime_new(void *expr_schema, struct maat_garbage_bin *garbage_bin,
                       struct log_handle *logger)
{
    if (NULL == expr_schema) {
        return NULL;
    }

    struct expr_schema *schema = (struct expr_schema *)expr_schema;
    struct expr_runtime *expr_rt = ALLOC(struct expr_runtime, 1);

    expr_rt->htable = rcu_hash_new(expr_ex_data_free);
    expr_rt->scan_mode = schema->scan_mode;
    expr_rt->item_user_data_free = maat_item_inner_free;
    expr_rt->ref_garbage_bin = garbage_bin;
    expr_rt->logger = logger;

    // expr_rt->scan_cnt = alignment_int64_array_alloc(max_thread_num);
    // expr_rt->hit_cnt = alignment_int64_array_alloc(max_thread_num);
    // expr_rt->not_grp_hit_cnt = alignment_int64_array_alloc(max_thread_num);
    // expr_rt->stream_num = alignment_int64_array_alloc(max_thread_num);

    return expr_rt;
}

void expr_runtime_free(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    if (expr_rt->hs != NULL) {
        adapter_hs_destroy(expr_rt->hs);
        expr_rt->hs = NULL;
    }

    if (expr_rt->hs_stream != NULL) {
        adapter_hs_stream_close(expr_rt->hs_stream);
        expr_rt->hs_stream = NULL;
    }

    if (expr_rt->htable != NULL) {
        rcu_hash_free(expr_rt->htable);
        expr_rt->htable = NULL;
    }

    struct maat_item *item = NULL, *tmp = NULL;
    HASH_ITER(hh, expr_rt->item_hash, item, tmp) {
        HASH_DELETE(hh, expr_rt->item_hash, item);
        maat_item_free(item, expr_rt->item_user_data_free);
    }
    FREE(expr_rt);
}

int expr_runtime_update_row(struct expr_runtime *expr_rt, char *key, size_t key_len, 
                             and_expr_t *expr_rule, int is_valid, struct log_handle *logger)
{
    void *data = NULL;

    if (0 == is_valid) {
        //delete
        data = rcu_hash_find(expr_rt->htable, key, key_len);
        if (NULL == data) {
            log_error(logger, MODULE_EXPR, 
                      "the key of expr rule not exist, can't be deleted, expr_id:%d", expr_rule->expr_id);
            return -1;
        }
        rcu_hash_del(expr_rt->htable, key, key_len);
    } else {
        //add
        data = rcu_hash_find(expr_rt->htable, key, key_len);
        if (data != NULL) {
            log_error(logger, MODULE_EXPR,
                      "the key of expr rule already exist, can't be added, expr_id:%d", expr_rule->expr_id);
            return -1;
        }
        rcu_hash_add(expr_rt->htable, key, key_len, (void *)expr_rule);
    }

    return 0;
}

and_expr_t *expr_item_to_expr_rule(struct expr_item *expr_item, struct log_handle *logger)
{
    size_t i = 0;
    size_t sub_expr_cnt = 0;
    char *pos = NULL;
    char *saveptr = NULL;
    char *sub_key_array[MAAT_MAX_EXPR_ITEM_NUM];
    and_expr_t *expr_rule = ALLOC(and_expr_t, 1);

    switch (expr_item->expr_type) {
        case EXPR_TYPE_AND:
        case EXPR_TYPE_REGEX:
            for (i = 0, pos = expr_item->keywords; ; i++, pos = NULL) {
                char *tmp = strtok_r_esc(pos, '&', &saveptr);
                if (NULL == tmp) {
                    break;
                }

                if (i >= MAAT_MAX_EXPR_ITEM_NUM) {
                    log_error(logger, MODULE_TABLE_RUNTIME, "expr item_id:%d too many patterns", 
                                                            expr_item->item_id);
                    return NULL;
                }

                sub_key_array[i] = tmp;
                if (expr_item->expr_type == EXPR_TYPE_REGEX) {
                    sub_key_array[i] = str_unescape_and(sub_key_array[i]);
                } else {
                    sub_key_array[i] = str_unescape(sub_key_array[i]);
                }
            }
            sub_expr_cnt = i;
            break;
        case EXPR_TYPE_STRING:
            sub_expr_cnt = 1;
            sub_key_array[0] = expr_item->keywords;
            sub_key_array[0] = str_unescape(sub_key_array[0]);
            break;
        default:
            break;
    }

    for (i = 0; i < sub_expr_cnt; i++) {
        expr_rule->expr_id = expr_item->item_id;
        expr_rule->patterns[i].pat = ALLOC(char, strlen(sub_key_array[i]));
        memcpy(expr_rule->patterns[i].pat, sub_key_array[i], strlen(sub_key_array[i]));
        expr_rule->patterns[i].pat_len = strlen(sub_key_array[i]);
        expr_rule->patterns[i].type = expr_type2pattern_type(expr_item->expr_type);
    }
    expr_rule->n_patterns = sub_expr_cnt;
    
    return expr_rule;
}

int expr_runtime_update(void *expr_runtime, void *expr_schema, const char *line, int valid_column)
{
    if (NULL == expr_runtime || NULL == expr_schema) {
        return -1;
    }

    int ret = -1;
    struct maat_item_inner *u_para = NULL;
    struct maat_item *item = NULL;
    and_expr_t *expr_rule = NULL;
    struct expr_schema *schema = (struct expr_schema *)expr_schema;
    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;

    int item_id = get_column_value(line, schema->item_id_column);
    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        return -1;
    } else if (0 == is_valid) {
        //delete
        HASH_FIND_INT(expr_rt->item_hash, &item_id, item);
        if (NULL == item) {
            return -1;
        }
        
        u_para = (struct maat_item_inner *)item->user_data;
        item->user_data = NULL;
        
	    if (NULL == u_para) {
		    return -1;
	    }

        HASH_DELETE(hh, expr_rt->item_hash, item);
        maat_garbage_bagging(expr_rt->ref_garbage_bin, u_para, (void (*)(void *))maat_item_inner_free);
    } else {
        //add
        HASH_FIND_INT(expr_rt->item_hash, &item_id, item);
        if (item) {
            log_error(expr_rt->logger, MODULE_EXPR, 
                      "expr runtime add item %d to item_hash failed, already exist", item_id);
            return -1;
        }

        struct expr_item *expr_item = expr_item_new(line, schema, expr_rt->logger);
        if (NULL == expr_item) {
            log_error(expr_rt->logger, MODULE_EXPR, "expr line %s to item failed", line);
            return -1;
        }

        // TODO: by luis
        //int district_id = get_district_id(maat_rt, expr_item->district);
        int district_id = -1;
        u_para = maat_item_inner_new(expr_item->group_id, item_id, district_id);
        item = maat_item_new(item_id, group_id, u_para);
        HASH_ADD_INT(expr_rt->item_hash, item_id, item);

        expr_rule = expr_item_to_expr_rule(expr_item, expr_rt->logger);
        expr_item_free(expr_item);
        if (NULL == expr_rule) {
            log_error(expr_rt->logger, MODULE_EXPR, "transform expr table:%s item to expr_rule failed, item_id:%d",
                      table_name, item_id);
            return -1;
        }
    }

    char *key = (char *)&item_id;
    ret = expr_runtime_update_row(expr_rt, key, sizeof(int), expr_rule, is_valid, expr_rt->logger);
    if (ret < 0) {
        if (expr_rule != NULL) {
            expr_rule_free(expr_rule);
        }
        return -1;
    } else {
        if (0 == is_valid) {
            expr_rt->rule_num--;
        } else {
            expr_rt->rule_num++;
        }
    }

    return 0;
}

int expr_runtime_commit(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return -1;
    }

    int ret = 0;
    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    void **ex_data_array = NULL;

    size_t rule_cnt = rcu_hash_list_updating_data(expr_rt->htable, &ex_data_array);
    if (0 == rule_cnt) {
        FREE(ex_data_array);
        return 0;
    }

    and_expr_t *rules = ALLOC(and_expr_t, rule_cnt);

    for (size_t i = 0; i < rule_cnt; i++) {
        rules[i] = *(and_expr_t *)ex_data_array[i];
    }

    struct adapter_hs *new_adapter_hs = NULL;
    struct adapter_hs *old_adapter_hs = NULL;

    log_info(expr_rt->logger, MODULE_EXPR,
             "committing %zu expr rules for rebuilding adapter_hs engine", rule_cnt);
    new_adapter_hs = adapter_hs_initialize(expr_rt->scan_mode, nr_worker_thread, rules, rule_cnt, expr_rt->logger);
    if (NULL == new_adapter_hs) {
        log_error(expr_rt->logger, MODULE_EXPR,
                  "rebuild adapter_hs engine failed when update %zu expr rules", rule_cnt);
        ret = -1;
    }

    old_adapter_hs = expr_rt->hs;
    expr_rt->hs = new_adapter_hs;

    maat_garbage_bagging(table_rt->ref_garbage_bin, old_adapter_hs, (void (*)(void*))adapter_hs_destroy);
    rcu_hash_commit(expr_rt->htable);
    expr_rt->rule_num = rcu_hash_count(expr_rt->htable);
    rule_cnt = rcu_hash_updating_count(expr_rt->htable);
    assert(rule_cnt == 0);
    
    FREE(rules);
    FREE(ex_data_array);

    return ret;
}

int expr_runtime_updating_flag(struct expr_runtime *expr_rt)
{
    return rcu_hash_updating_flag(expr_rt->htable);
}

void expr_rule_free(and_expr_t *expr_rule)
{
    if (NULL == expr_rule) {
        return;
    }

    for (size_t i = 0; i < expr_rule->n_patterns; i++) {
        FREE(expr_rule->patterns[i].pat);
    }

    FREE(expr_rule);
}

void expr_ex_data_free(void *user_ctx, void *data)
{
    and_expr_t *expr_rule = (and_expr_t *)data;
    expr_rule_free(expr_rule);
}

int expr_runtime_scan_string(struct expr_runtime *expr_rt, int thread_id, const char *data, size_t data_len, 
                              int group_id_array[], size_t n_group_id_array, int virtual_table_id, struct maat_state *state)
{
    if (NULL == table_rt) {
        return -1;
    }

    int hit_item_ids[MAX_SCANNER_HIT_ITEM_NUM] = {-1};
    size_t n_hit_item = 0;
    int ret = adapter_hs_scan(table_rt->expr_rt.hs, thread_id, data, data_len, hit_item_ids, &n_hit_item);
    if (ret < 0) {
        return -1;
    }
    if (n_hit_item > MAX_SCANNER_HIT_ITEM_NUM) {
        n_hit_item = MAX_SCANNER_HIT_ITEM_NUM;
    }

    struct maat_compile_state *compile_state = state->compile_mid;
    //tranform item_id to group_id
    struct maat_item *item = NULL;
    size_t n_group_id = 0;
    size_t i = 0;
    for (i = 0; i < n_hit_item; i++) {
        HASH_FIND_INT(table_rt->item_hash, &(hit_item_ids[i]), item);
        assert(item != NULL);
        if (!item) {
            // should not come here
            continue;
        }

        if (n_group_id >= n_group_id_array) {
            n_group_id = n_group_id_array;
            //Prevent group_id_array out of bounds
        } else {
            group_id_array[n_group_id++] = item->group_id;
        }
        
        maat_compile_state_update_hit_path(compile_state, hit_item_ids[i], item->group_id, virtual_table_id, state->scan_cnt, i);
    }

    // literal_id{group_id,vt_id} to clause_id
    // STEP 1: get compile table runtime
    int compile_table_id = -1;
    if (state->compile_table_id == -1) {
        compile_table_id = state->maat_instance->default_compile_table_id;
    } else {
        compile_table_id = state->compile_table_id;
    }
    struct maat_runtime *maat_rt = state->maat_instance->maat_rt;
    struct table_runtime *compile_table_rt = table_manager_get_runtime(maat_rt->tbl_mgr, compile_table_id);
    assert(compile_table_rt->table_type == TABLE_TYPE_COMPILE);
    
    // STEP 2: get the specified compile table's hit clause_id array by literal_id
    for (i = 0; i < n_group_id; i++) {
        maat_compile_state_update_hit_clause(compile_state, &(compile_table_rt->compile_rt.compile_hash), group_id_array[i], virtual_table_id);
    }

    return n_group_id;
}

void expr_runtime_stream_open(struct expr_runtime *expr_rt, int thread_id)
{
    if (NULL == table_rt) {
        return;
    }

    struct adapter_hs_stream *hs_stream = adapter_hs_stream_open(table_rt->expr_rt.hs, thread_id);
    table_rt->expr_rt.hs_stream = hs_stream;
}

int expr_runtime_scan_stream(struct expr_runtime *expr_rt, const char *data, size_t data_len,
                              int result[], size_t *n_result)
{
    if (NULL == table_rt) {
        return -1;
    }

    return adapter_hs_scan_stream(table_rt->expr_rt.hs_stream, data, data_len, result, n_result);
}

void expr_runtime_stream_close(struct expr_runtime *expr_rt)
{
    if (table_rt != NULL) {
        adapter_hs_stream_close(table_rt->expr_rt.hs_stream);
        table_rt->expr_rt.hs_stream = NULL;
    }
}
