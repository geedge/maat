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
#include <ctype.h>

#include "maat_expr.h"
#include "adapter_hs.h"
#include "maat_utils.h"
#include "maat_kv.h"
#include "maat_limits.h"
#include "rcu_hash.h"
#include "maat_rule.h"
#include "maat_compile.h"
#include "maat_group.h"
#include "alignment.h"
#include "maat_garbage_collection.h"

#define MODULE_EXPR	 module_name_str("maat.expr")

struct expr_schema {
	int item_id_column;
    int group_id_column;
	int district_column;
	int keywords_column;
	int expr_type_column;
    int match_method_column;
    int is_hexbin_column;
    int table_id; //ugly
    struct table_manager *ref_tbl_mgr;
};

enum expr_type {
    EXPR_TYPE_INVALID = -1,
    EXPR_TYPE_STRING = 0,
	EXPR_TYPE_AND,
    EXPR_TYPE_REGEX,
    EXPR_TYPE_OFFSET,
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
    long long item_id;
    long long group_id;
    long long district_id;
    char keywords[MAX_KEYWORDS_STR];
    enum expr_type expr_type;
    enum hs_match_mode match_mode;
    int is_hexbin;
    int is_case_sensitive;
};

struct expr_runtime {
    struct adapter_hs *hs;
    struct rcu_hash_table *htable;      // store hs_expr rule for rebuild adapter_hs instance
    struct rcu_hash_table *item_htable; // store this expr table's all maat_item which will be used in expr_runtime_scan

    uint32_t rule_num;
    int n_worker_thread;
    struct maat_garbage_bin *ref_garbage_bin;
    struct log_handle *logger;

    long long *scan_cnt;
    long long *hit_cnt;
    // long long *stream_num;
};

enum expr_type int_to_expr_type(int expr_type)
{
    enum expr_type type = EXPR_TYPE_INVALID;

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
    case 3:
        type = EXPR_TYPE_OFFSET;
        break;
    default:
        break;
    }

    return type;
}

enum hs_match_mode int_to_match_mode(int match_method)
{
    enum hs_match_mode mode = HS_MATCH_MODE_INVALID;

    switch (match_method) {
    case 0:
        mode = HS_MATCH_MODE_SUB;
        break;
    case 1:
        mode = HS_MATCH_MODE_SUFFIX;
        break;
    case 2:
        mode = HS_MATCH_MODE_PREFIX;
        break;
    case 3:
        mode = HS_MATCH_MODE_EXACTLY;
        break;
    default:
        break;
    }

    return mode;
}

struct expr_item *expr_item_new(const char *line, struct expr_schema *expr_schema,
                                struct log_handle *logger)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    int db_hexbin = -1;
    int expr_type = -1;
    int match_method_type = -1;
    enum table_type table_type = TABLE_TYPE_INVALID;
    struct expr_item *expr_item = ALLOC(struct expr_item, 1);

    int ret = get_column_pos(line, expr_schema->item_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] expr table(table_id:%d) line:%s has no item_id",
                  __FUNCTION__, __LINE__, expr_schema->table_id, line);
        goto error;
    }
    expr_item->item_id = atoll(line + column_offset);

    ret = get_column_pos(line, expr_schema->group_id_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] expr table(table_id:%d) line:%s has no group_id",
                  __FUNCTION__, __LINE__, expr_schema->table_id, line);
        goto error;
    }
    expr_item->group_id = atoll(line + column_offset);

    table_type = table_manager_get_table_type(expr_schema->ref_tbl_mgr, expr_schema->table_id);
    if (table_type == TABLE_TYPE_EXPR_PLUS) {
        ret = get_column_pos(line, expr_schema->district_column, &column_offset, &column_len);
        if (ret < 0) {
            goto error;
        }

        if (column_len >= MAX_DISTRICT_STR) {
            log_error(logger, MODULE_EXPR, 
                      "[%s:%d] expr table(table_id:%d) line:%s district length too long",
                      __FUNCTION__, __LINE__, expr_schema->table_id, line);
            goto error;
        }

        char district[MAX_DISTRICT_STR] = {0};
        memcpy(district, (line + column_offset), column_len);
        assert(strlen(district) > 0);
        str_unescape(district);
        expr_item->district_id = table_manager_get_district_id(expr_schema->ref_tbl_mgr, district);
    } else {
        expr_item->district_id = DISTRICT_ANY;
    }

    ret = get_column_pos(line, expr_schema->expr_type_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] expr table(table_id:%d) line:%s has no expr_type",
                  __FUNCTION__, __LINE__, expr_schema->table_id, line);
        goto error;
    }
    
    expr_type = atoi(line + column_offset);
    expr_item->expr_type = int_to_expr_type(expr_type);
    if (expr_item->expr_type == EXPR_TYPE_INVALID) {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] expr table(table_id:%d) line:%s has invalid expr_type",
                 __FUNCTION__, __LINE__, expr_schema->table_id, line);
        goto error;
    }

    ret = get_column_pos(line, expr_schema->match_method_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] expr table(table_id:%d) line:%s has no match_method",
                  __FUNCTION__, __LINE__, expr_schema->table_id, line);
        goto error;
    }
    
    match_method_type = atoi(line + column_offset);
    expr_item->match_mode = int_to_match_mode(match_method_type);
    if (expr_item->match_mode == HS_MATCH_MODE_INVALID) {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] expr table(table_id:%d) line:%s has invalid match_method",
                  __FUNCTION__, __LINE__, expr_schema->table_id, line);
        goto error;
    }

    ret = get_column_pos(line, expr_schema->is_hexbin_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] expr table(table_id:%d) line:%s has no is_hexbin",
                  __FUNCTION__, __LINE__, expr_schema->table_id, line);
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
                      "[%s:%d] expr table(table_id:%d) line:%s has invalid hexbin value:%d",
                      __FUNCTION__, __LINE__, expr_schema->table_id, line, db_hexbin);
            goto error;
    }
    
    ret = get_column_pos(line, expr_schema->keywords_column, &column_offset, &column_len);
    if (ret < 0) {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] expr table(table_id:%d) line:%s has no keywords",
                  __FUNCTION__, __LINE__, expr_schema->table_id, line);
        goto error;
    }

    if (column_len >= MAX_KEYWORDS_STR) {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] expr table(table_id:%d) line:%s keywords length too long",
                  __FUNCTION__, __LINE__, expr_schema->table_id, line);
        goto error;
    }
    memcpy(expr_item->keywords, (line + column_offset), column_len);

    return expr_item;
error:
    FREE(expr_item);
    return NULL;
}

void expr_item_free(struct expr_item *expr_item)
{
    FREE(expr_item);
}

void *expr_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                      const char *table_name, struct log_handle *logger)
{
    char table_type[NAME_MAX] = {0};
	struct expr_schema *expr_schema = ALLOC(struct expr_schema, 1);

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        expr_schema->table_id = item->valueint;
    } else {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] table %s has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    /* table_type already validate in maat_table_new() */
    item = cJSON_GetObjectItem(json, "table_type");
    memcpy(table_type, item->valuestring, strlen(item->valuestring));

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] table %s has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

	custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->item_id_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] table %s has no item_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

	custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->group_id_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] table %s has no group_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "keywords");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->keywords_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] table %s has no keywords column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    /* expr_plus has district */
    if (strcmp(table_type, "expr_plus") == 0) {
        custom_item = cJSON_GetObjectItem(item, "district");
        if (custom_item != NULL && custom_item->type == cJSON_Number) {
            expr_schema->district_column = custom_item->valueint;
        } else {
            log_error(logger, MODULE_EXPR, 
                  "[%s:%d] expr_plus table %s has no district column", 
                  __FUNCTION__, __LINE__, table_name);
            goto error;
        }
    }

    custom_item = cJSON_GetObjectItem(item, "expr_type");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->expr_type_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] table %s has no expr_type column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "match_method");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->match_method_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] table %s has no match_method column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "is_hexbin");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->is_hexbin_column = custom_item->valueint;
    } else {
        log_error(logger, MODULE_EXPR, 
                  "[%s:%d] table %s has no is_hexbin column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    expr_schema->ref_tbl_mgr = tbl_mgr;
	
    return expr_schema;
error:
    FREE(expr_schema);
    return NULL;
}

void expr_schema_free(void *expr_schema)
{
    FREE(expr_schema);
}

void expr_rule_free(struct hs_expr *expr_rule)
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
    struct hs_expr *expr_rule = (struct hs_expr *)data;
    expr_rule_free(expr_rule);
}

void expr_maat_item_free(void *user_ctx, void *data)
{
    struct maat_item *item = (struct maat_item *)data;
    maat_item_free(item);
}

void *expr_runtime_new(void *expr_schema, int max_thread_num, 
                       struct maat_garbage_bin *garbage_bin,
                       struct log_handle *logger)
{
    if (NULL == expr_schema) {
        return NULL;
    }

    struct expr_runtime *expr_rt = ALLOC(struct expr_runtime, 1);

    expr_rt->htable = rcu_hash_new(expr_ex_data_free);
    expr_rt->item_htable = rcu_hash_new(expr_maat_item_free);
    expr_rt->n_worker_thread = max_thread_num;
    expr_rt->ref_garbage_bin = garbage_bin;
    expr_rt->logger = logger;

    expr_rt->hit_cnt = alignment_int64_array_alloc(max_thread_num);
    expr_rt->scan_cnt = alignment_int64_array_alloc(max_thread_num);

    return expr_rt;
}

void expr_runtime_free(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    if (expr_rt->hs != NULL) {
        adapter_hs_free(expr_rt->hs);
        expr_rt->hs = NULL;
    }

    // if (expr_rt->hs_stream != NULL) {
    //     adapter_hs_stream_close(expr_rt->hs_stream);
    //     expr_rt->hs_stream = NULL;
    // }

    if (expr_rt->htable != NULL) {
        rcu_hash_free(expr_rt->htable);
        expr_rt->htable = NULL;
    }

    if (expr_rt->item_htable != NULL) {
        rcu_hash_free(expr_rt->item_htable);
        expr_rt->item_htable = NULL;
    }

    if (expr_rt->hit_cnt != NULL) {
        alignment_int64_array_free(expr_rt->hit_cnt);
        expr_rt->hit_cnt = NULL;
    }

    if (expr_rt->scan_cnt != NULL) {
        alignment_int64_array_free(expr_rt->scan_cnt);
        expr_rt->scan_cnt = NULL;
    }

    FREE(expr_rt);
}

int expr_runtime_update_row(struct expr_runtime *expr_rt, char *key, size_t key_len, 
                            long long item_id, struct hs_expr *expr_rule, int is_valid)
{
    int ret = -1;

    if (0 == is_valid) {
        //delete
        rcu_hash_del(expr_rt->htable, key, key_len);
    } else {
        //add
        ret = rcu_hash_add(expr_rt->htable, key, key_len, (void *)expr_rule);
        if (ret < 0) {
            log_error(expr_rt->logger, MODULE_EXPR,
                      "[%s:%d] expr rule(rule_id:%lld) added to expr runtime htable failed", 
                      __FUNCTION__, __LINE__, item_id);
            return -1;
        }
    }

    return 0;
}

enum hs_pattern_type expr_type2pattern_type(enum expr_type expr_type)
{
    enum hs_pattern_type pattern_type = HS_PATTERN_TYPE_MAX;

    switch (expr_type) {
        case EXPR_TYPE_STRING:
        case EXPR_TYPE_AND:
        case EXPR_TYPE_OFFSET:
            pattern_type = HS_PATTERN_TYPE_STR;
            break;
        case EXPR_TYPE_REGEX:
            pattern_type = HS_PATTERN_TYPE_REG;
            break;
        default:
            break;
    }

    return pattern_type;
}

static int convertHextoint(char srctmp)
{
	if (isdigit(srctmp)) {
		return srctmp - '0';
	} else {
		char temp = toupper(srctmp);
		temp = temp - 'A' + 10;
		return temp;
	}
}

static size_t hex2bin(char *hex, int hex_len, char *binary, size_t size)
{
	size_t resultlen = 0;
	int high,low;
	for (int i = 0; i < hex_len && size > resultlen; i += 2, resultlen++) {
		high = convertHextoint(hex[i]);
		low = convertHextoint(hex[i+1]);
		binary[resultlen] = high * 16 + low;
	}

	size = resultlen;
	binary[resultlen] = '\0';

	return resultlen;
}

#define MAAT_MAX_EXPR_ITEM_NUM	8
struct hs_expr *expr_item_to_expr_rule(struct expr_item *expr_item, void *user_data,
                                   struct log_handle *logger)
{
    size_t i = 0;
    size_t sub_expr_cnt = 0;
    char *pos = NULL;
    char *tmp = NULL;
    char *saveptr = NULL;
    char *sub_key_array[MAAT_MAX_EXPR_ITEM_NUM];
    int key_left_offset[MAAT_MAX_EXPR_ITEM_NUM];
    int key_right_offset[MAAT_MAX_EXPR_ITEM_NUM];

    /* -1 means offset no limit, As long as the pattern appears in the scan data, it will hit */
    memset(key_left_offset, -1, sizeof(key_left_offset));
    memset(key_right_offset, -1, sizeof(key_right_offset));

    struct hs_expr *expr_rule = ALLOC(struct hs_expr, 1);

    switch (expr_item->expr_type) {
        case EXPR_TYPE_AND:
        case EXPR_TYPE_REGEX:
            for (i = 0, pos = expr_item->keywords; ; i++, pos = NULL) {
                tmp = strtok_r_esc(pos, '&', &saveptr);
                if (NULL == tmp) {
                    break;
                }

                if (i >= MAAT_MAX_EXPR_ITEM_NUM) {
                    log_error(logger, MODULE_EXPR,
                              "[%s:%d]abandon config expr_item(item_id:%d) too many patterns", 
                              __FUNCTION__, __LINE__, expr_item->item_id);
                    goto error;
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
        case EXPR_TYPE_OFFSET:
            for (i = 0, pos = expr_item->keywords; ; i++, pos = NULL) {
                tmp = strtok_r_esc(pos, '&', &saveptr);
                if (NULL == tmp) {
                    break;
                }

                if (i >= MAAT_MAX_EXPR_ITEM_NUM) {
                    log_error(logger, MODULE_EXPR,
                              "[%s:%d]abandon config expr_item(item_id:%d) too many patterns", 
                              __FUNCTION__, __LINE__, expr_item->item_id);
                    goto error;
                }

                sub_key_array[i] = tmp;
                sscanf(sub_key_array[i], "%d-%d:", &(key_left_offset[i]),&(key_right_offset[i]));
				if (!(key_left_offset[i] >= 0 && key_right_offset[i] > 0 
                      && key_left_offset[i] <= key_right_offset[i])) {
					log_error(logger, MODULE_EXPR,
							 "[%s:%d]abandon config expr_item(item_id:%d) has invalid offset.",
                             __FUNCTION__, __LINE__, expr_item->item_id);
                    goto error;
				}

				sub_key_array[i] = (char *)memchr(sub_key_array[i], ':', strlen(sub_key_array[i]));
				if (NULL == sub_key_array[i]) {
					log_error(logger, MODULE_EXPR,
							"[%s:%d]abandon config expr_item(item_id:%d) has invalid offset keyword format.",
                            __FUNCTION__, __LINE__, expr_item->item_id);
                    goto error;
				}

				sub_key_array[i]++;//jump over ':'
				sub_key_array[i] = str_unescape(sub_key_array[i]);
            }
            sub_expr_cnt = i;
            break;
        case EXPR_TYPE_STRING:
            sub_expr_cnt = 1;
            sub_key_array[0] = expr_item->keywords;
            sub_key_array[0] = str_unescape(sub_key_array[0]);
            break;
        default:
            log_error(logger, MODULE_EXPR, 
                      "[%s:%d]abandon config expr_item(item_id:%lld) has invalid expr type=%d",
                      __FUNCTION__, __LINE__, expr_item->item_id, expr_item->expr_type);
            goto error;
    }

    for (i = 0; i < sub_expr_cnt; i++) {
        size_t region_str_len = 0;
        char *region_string = NULL;
        size_t sub_key_len = 0;

        if (FALSE == expr_item->is_case_sensitive) {
            // insensitive
            expr_rule->patterns[i].case_sensitive = HS_CASE_INSESITIVE;
        }

        expr_rule->patterns[i].pattern_type = expr_type2pattern_type(expr_item->expr_type);

        if (TRUE == expr_item->is_hexbin && expr_rule->patterns[i].pattern_type != HS_PATTERN_TYPE_REG) {
            region_str_len = strlen(sub_key_array[i]) * 8 + 1;
			region_string = ALLOC(char, region_str_len);
			region_str_len = hex2bin(sub_key_array[i], strlen(sub_key_array[i]), region_string, region_str_len);
        }

        if (region_string != NULL) {
            expr_rule->patterns[i].pat = ALLOC(char, region_str_len + 1);
            memcpy(expr_rule->patterns[i].pat, region_string, region_str_len);
            expr_rule->patterns[i].pat_len = region_str_len;
            FREE(region_string);
        } else {
            sub_key_len = strlen(sub_key_array[i]);
            expr_rule->patterns[i].pat = ALLOC(char, sub_key_len + 1);
            memcpy(expr_rule->patterns[i].pat, sub_key_array[i], sub_key_len);
            expr_rule->patterns[i].pat_len = sub_key_len;
        }

        expr_rule->patterns[i].match_mode = expr_item->match_mode;
        if (expr_rule->patterns[i].match_mode == HS_MATCH_MODE_SUB) {
            expr_rule->patterns[i].start_offset = key_left_offset[i];
            expr_rule->patterns[i].end_offset = key_right_offset[i];
        }
    }
    expr_rule->expr_id = expr_item->item_id;
    expr_rule->user_tag = user_data;
    expr_rule->n_patterns = sub_expr_cnt;
    
    //mytest
    // printf("expr_rule->expr_id:%u\n", expr_rule->expr_id);
    // printf("expr_rule->n_patterns:%zu\n", expr_rule->n_patterns);
    // for (size_t i = 0; i < expr_rule->n_patterns; i++) {
    //     printf("expr_rule->patterns[%zu].pat:%s\n", i, expr_rule->patterns[i].pat);
    //     printf("expr_rule->patterns[%zu].pat_len:%zu\n", i, expr_rule->patterns[i].pat_len);
    //     printf("expr_rule->patterns[%zu].l_offset:%d\n", i, expr_rule->patterns[i].l_offset);
    //     printf("expr_rule->patterns[%zu].r_offset:%d\n", i, expr_rule->patterns[i].r_offset);
    // }
    return expr_rule;
error:
    FREE(expr_rule);
    return NULL;
}

int expr_runtime_update(void *expr_runtime, void *expr_schema, 
                        const char *line, int valid_column)
{
    if (NULL == expr_runtime || NULL == expr_schema ||
        NULL == line) {
        return -1;
    }

    int ret = -1;
    struct maat_item_inner *u_para = NULL;
    struct maat_item *item = NULL;
    struct hs_expr *expr_rule = NULL;
    struct expr_schema *schema = (struct expr_schema *)expr_schema;
    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;

    long long item_id = get_column_value(line, schema->item_id_column);
    if (item_id < 0) {
        return -1;
    }

    int is_valid = get_column_value(line, valid_column);
    //printf("<expr_runtime_update> item_id:%lld is_valid:%d\n", item_id, is_valid);
    if (is_valid < 0) {
        return -1;
    } else if (0 == is_valid) {
        //delete
        rcu_hash_del(expr_rt->item_htable, (char *)&item_id, sizeof(item_id));
    } else {
        //add
        struct expr_item *expr_item = expr_item_new(line, schema, expr_rt->logger);
        if (NULL == expr_item) {
            return -1;
        }

        u_para = maat_item_inner_new(expr_item->group_id, item_id, expr_item->district_id);
        item = maat_item_new(item_id, expr_item->group_id, u_para, maat_item_inner_free);
        ret = rcu_hash_add(expr_rt->item_htable, (char *)&item_id, sizeof(item_id), item);
        if (ret < 0) {
            log_error(expr_rt->logger, MODULE_EXPR, 
                      "[%s:%d] expr runtime add item(item_id:%lld) to item_htable failed", 
                      __FUNCTION__, __LINE__, item_id);
            expr_item_free(expr_item);
            maat_item_free(item);
            return -1;
        }

        expr_rule = expr_item_to_expr_rule(expr_item, u_para, expr_rt->logger);
        expr_item_free(expr_item);
        if (NULL == expr_rule) {
            log_error(expr_rt->logger, MODULE_EXPR, 
                      "[%s:%d] transform expr table(table_id:%d) item(item_id:%lld) to expr_rule failed",
                      __FUNCTION__, __LINE__, schema->table_id, item_id);
            return -1;
        }
    }

    char *key = (char *)&item_id;
    ret = expr_runtime_update_row(expr_rt, key, sizeof(item_id), item_id, 
                                  expr_rule, is_valid);
    if (ret < 0) {
        if (expr_rule != NULL) {
            expr_rule_free(expr_rule);
        }
        return -1;
    }

    return 0;
}

int expr_runtime_commit(void *expr_runtime, const char *table_name)
{
    if (NULL == expr_runtime) {
        return -1;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;

    int updating_flag = rcu_hash_is_updating(expr_rt->htable);
    if (0 == updating_flag) {
        return 0;
    }

    rcu_hash_commit(expr_rt->htable);

    struct hs_expr *rules = NULL;
    void **ex_data_array = NULL;
    size_t rule_cnt = rcu_hash_list(expr_rt->htable, &ex_data_array);
    
    if (rule_cnt > 0) {
        rules = ALLOC(struct hs_expr, rule_cnt);
        for (size_t i = 0; i < rule_cnt; i++) {
            rules[i] = *(struct hs_expr *)ex_data_array[i];
        }
    }

    log_info(expr_rt->logger, MODULE_EXPR,
             "table[%s] committing %zu expr rules for rebuilding adapter_hs engine", 
             table_name, rule_cnt);

    int ret = 0;
    struct adapter_hs *new_adapter_hs = NULL;
    struct adapter_hs *old_adapter_hs = NULL;

    if (rule_cnt > 0) {
        new_adapter_hs = adapter_hs_new(expr_rt->n_worker_thread, rules, rule_cnt, expr_rt->logger);
        if (NULL == new_adapter_hs) {
            log_error(expr_rt->logger, MODULE_EXPR,
                      "[%s:%d] table[%s] rebuild adapter_hs engine failed when update %zu expr rules",
                      __FUNCTION__, __LINE__, table_name, rule_cnt);
            ret = -1;
        }
    }

    old_adapter_hs = expr_rt->hs;
    expr_rt->hs = new_adapter_hs;
    if (old_adapter_hs != NULL) {
        maat_garbage_bagging(expr_rt->ref_garbage_bin, old_adapter_hs, 
                         (void (*)(void*))adapter_hs_free);
    }
    rcu_hash_commit(expr_rt->item_htable);
    expr_rt->rule_num = rule_cnt;

    if (rules != NULL) {
        FREE(rules);
    }
    
    if (ex_data_array != NULL) {
        FREE(ex_data_array);
    }

    return ret;
}

int expr_runtime_scan(struct expr_runtime *expr_rt, int thread_id, const char *data, 
                      size_t data_len, int vtable_id, struct maat_state *state)
{
    if (0 == expr_rt->rule_num) {
        //empty expr table
        return 0;
    }

    size_t n_hit_item = 0;
    struct hs_scan_result hit_results[MAX_SCANNER_HIT_ITEM_NUM] = {0};
    
    int ret = adapter_hs_scan(expr_rt->hs, thread_id, data, data_len, 
                              hit_results, MAX_SCANNER_HIT_ITEM_NUM, 
                              &n_hit_item);
    if (ret < 0) {
        return -1;
    }

    if (0 == n_hit_item) {
        return 0;
    }

    if (n_hit_item > MAX_SCANNER_HIT_ITEM_NUM) {
        log_info(expr_rt->logger, MODULE_EXPR, 
                 "hit expr item count:%d exceed maxium:%d", 
                 n_hit_item, MAX_SCANNER_HIT_ITEM_NUM);
        n_hit_item = MAX_SCANNER_HIT_ITEM_NUM;
    }
    
    long long hit_item_ids[MAX_SCANNER_HIT_ITEM_NUM];
    struct maat_item_inner *item = NULL;
    int real_hit_item_cnt = 0;
    long long district_id = state->district_id;

    memset(hit_item_ids, 0, sizeof(hit_item_ids));
    
    for (size_t i = 0; i < n_hit_item; i++) {
        item = (struct maat_item_inner *)(hit_results[i].user_tag);
        if (item->district_id == district_id || item->district_id == DISTRICT_ANY) {
            hit_item_ids[real_hit_item_cnt++] = hit_results[i].item_id;
        }
    }

    size_t group_hit_cnt = 0;
    ret = maat_compile_state_update(expr_rt->item_htable, vtable_id, hit_item_ids, 
                                    real_hit_item_cnt, &group_hit_cnt, state);
    if (ret < 0) {
        return -1;
    }

    return group_hit_cnt;
}

struct adapter_hs_stream *expr_runtime_stream_open(struct expr_runtime *expr_rt, int thread_id)
{
    if (NULL == expr_rt || thread_id < 0) {
        return NULL;
    }

    return adapter_hs_stream_open(expr_rt->hs, thread_id);
}

int expr_runtime_stream_scan(struct expr_runtime *expr_rt, struct adapter_hs_stream *s_handle, 
                             const char *data, size_t data_len, int vtable_id, struct maat_state *state)
{
    if (0 == expr_rt->rule_num) {
        //empty expr table
        return 0;
    }

    size_t n_hit_item = 0;
    struct hs_scan_result hit_results[MAX_SCANNER_HIT_ITEM_NUM] = {0};
    int ret = adapter_hs_scan_stream(s_handle, data, data_len, hit_results, MAX_SCANNER_HIT_ITEM_NUM, &n_hit_item);
    if (ret < 0) {
        return -1;
    }

    if (0 == n_hit_item) {
        return 0;
    }

    if (n_hit_item > MAX_SCANNER_HIT_ITEM_NUM) {
        log_info(expr_rt->logger, MODULE_EXPR, 
                 "hit expr item count:%d exceed maxium:%d", 
                 n_hit_item, MAX_SCANNER_HIT_ITEM_NUM);
        n_hit_item = MAX_SCANNER_HIT_ITEM_NUM;
    }
    
    long long hit_item_ids[MAX_SCANNER_HIT_ITEM_NUM];
    memset(hit_item_ids, 0, sizeof(hit_item_ids));

    for (size_t i = 0; i < n_hit_item; i++) {
        hit_item_ids[i] = hit_results[i].item_id;
    }

    size_t group_hit_cnt = 0;
    ret = maat_compile_state_update(expr_rt->item_htable, vtable_id, hit_item_ids, 
                                    n_hit_item, &group_hit_cnt, state);
    if (ret < 0) {
        return -1;
    }

    return group_hit_cnt;
}

void expr_runtime_stream_close(struct adapter_hs_stream *s_handle)
{
    adapter_hs_stream_close(s_handle);
}

void expr_runtime_scan_hit_inc(struct expr_runtime *expr_rt, int thread_id)
{
    alignment_int64_array_add(expr_rt->hit_cnt, thread_id, 1);
}

long long expr_runtime_scan_hit_sum(struct expr_runtime *expr_rt, int n_thread)
{
    return alignment_int64_array_sum(expr_rt->hit_cnt, n_thread);
}
