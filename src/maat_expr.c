/*
**********************************************************************************************
*	File: maat_expr.c
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
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
#include "maat.h"
#include "maat_rule.h"
#include "maat_compile.h"
#include "maat_group.h"
#include "alignment.h"
#include "maat_garbage_collection.h"

#define MODULE_EXPR	 module_name_str("maat.expr")

/*
    If expr_engine_type == MAAT_EXPR_ENGINE_AUTO, and the pattern number less than 50K,
    expr_engine_type = MAAT_EXPR_ENGINE_HS; Otherwise expr_engine_type = MAAT_EXPR_ENGINE_RS
*/
#define ENGINE_TYPE_SWITCH_THRESHOLD 50000

struct expr_schema {
	int item_id_column;
    int group_id_column;
	int district_column;
	int keywords_column;
	int expr_type_column;
    int match_method_column;
    int is_hexbin_column;
    int table_id;
    enum maat_expr_engine engine_type;
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
    char keywords[MAX_KEYWORDS_STR_LEN + 1];
    enum expr_type expr_type;
    enum expr_match_mode match_mode;
    int is_hexbin;
    int is_case_sensitive;
    void *user_data;
    int district_id;
};

struct expr_runtime {
    struct expr_matcher *matcher;
    struct rcu_hash_table *item_hash;      // <item_id, struct expr_item>

    long long version;  //expr_rt version
    long long rule_num;
    long long regex_rule_num;
    size_t n_worker_thread;

    struct log_handle *logger;
    struct maat_garbage_bin *ref_garbage_bin;

    enum expr_engine_type engine_type;
    int district_num;
    struct maat_kv_store *district_map;
    struct maat_kv_store *tmp_district_map;

    long long *scan_cnt;
    long long *scan_cpu_time;
    long long *hit_cnt;
    long long update_err_cnt;
    long long *scan_bytes;
};

static enum expr_type int_to_expr_type(int expr_type)
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

static enum expr_match_mode int_to_match_mode(int match_method)
{
    enum expr_match_mode mode = EXPR_MATCH_MODE_INVALID;

    switch (match_method) {
    case 0:
        mode = EXPR_MATCH_MODE_SUB;
        break;
    case 1:
        mode = EXPR_MATCH_MODE_SUFFIX;
        break;
    case 2:
        mode = EXPR_MATCH_MODE_PREFIX;
        break;
    case 3:
        mode = EXPR_MATCH_MODE_EXACTLY;
        break;
    default:
        break;
    }

    return mode;
}

static int expr_runtime_get_district_id(struct expr_runtime *expr_rt,
                                        const char *district)
{
    long long district_id = DISTRICT_ANY;

	int map_ret = maat_kv_read(expr_rt->district_map, district, &district_id, 1);
	if (map_ret < 0) {
        if (NULL == expr_rt->tmp_district_map) {
            expr_rt->tmp_district_map = maat_kv_store_duplicate(expr_rt->district_map);
        }
        
        map_ret = maat_kv_read(expr_rt->tmp_district_map, district, &district_id, 1);
        if (map_ret < 0) {
            district_id = expr_rt->district_num;
		    maat_kv_register(expr_rt->tmp_district_map, district, district_id);
		    expr_rt->district_num++;
        }
	}

	return (int)district_id;
}

int expr_runtime_set_scan_district(struct expr_runtime *expr_rt, const char *district, 
                                    size_t district_len, long long *district_id)
{
    if (NULL == expr_rt || NULL == district || 0 == district_len) {
        return -1;
    }

    return maat_kv_read_unNull(expr_rt->district_map, district, district_len,
                               district_id, 1);
}

static struct expr_item *
expr_item_new(struct expr_schema *expr_schema, const char *table_name,
              const char *line, struct expr_runtime *expr_rt)
{
    size_t column_offset = 0;
    size_t column_len = 0;
    int db_hexbin = -1;
    int expr_type = -1;
    int match_method_type = -1;
    enum table_type table_type = TABLE_TYPE_INVALID;
    struct expr_item *expr_item = ALLOC(struct expr_item, 1);

    int ret = get_column_pos(line, expr_schema->item_id_column, &column_offset,
                             &column_len);
    if (ret < 0) {
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> has no item_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    expr_item->item_id = atoll(line + column_offset);

    ret = get_column_pos(line, expr_schema->group_id_column, &column_offset,
                         &column_len);
    if (ret < 0) {
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> has no group_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    expr_item->group_id = atoll(line + column_offset);

    ret = get_column_pos(line, expr_schema->keywords_column, &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> has no keywords in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }

    if (column_len > MAX_KEYWORDS_STR_LEN) {
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> keywords length too long in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    memcpy(expr_item->keywords, (line + column_offset), column_len);

    ret = get_column_pos(line, expr_schema->expr_type_column, &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> has no expr_type in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    
    expr_type = atoi(line + column_offset);
    expr_item->expr_type = int_to_expr_type(expr_type);
    if (expr_item->expr_type == EXPR_TYPE_INVALID) {
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> has invalid expr_type in line:%s",
                 __FUNCTION__, __LINE__, table_name, line);
        goto error;
    } else if (expr_item->expr_type == EXPR_TYPE_REGEX) {
        ret = expr_matcher_verify_regex_expression(expr_item->keywords, expr_rt->logger);
        if (0 == ret) {
            log_fatal(expr_rt->logger, MODULE_EXPR, 
                      "[%s:%d] expr table:<%s> regex expression(item_id:%lld):%s illegal,"
                      " will be dropped", __FUNCTION__, __LINE__, table_name,
                      expr_item->item_id, expr_item->keywords);
            goto error;
        }
    }
   
    table_type = table_manager_get_table_type(expr_schema->ref_tbl_mgr, expr_schema->table_id);
    if (table_type == TABLE_TYPE_EXPR_PLUS) {
        ret = get_column_pos(line, expr_schema->district_column, &column_offset, &column_len);
        if (ret < 0) {
            goto error;
        }

        if (column_len > MAX_DISTRICT_STR_LEN) {
            log_fatal(expr_rt->logger, MODULE_EXPR, 
                      "[%s:%d] expr table:<%s> district length exceed maximum:%d"
                      " in line:%s", __FUNCTION__, __LINE__, table_name,
                      MAX_DISTRICT_STR_LEN, line);
            goto error;
        }

        char district[MAX_DISTRICT_STR_LEN + 1] = {0};
        memcpy(district, (line + column_offset), column_len);
        assert(strlen(district) > 0);
        str_unescape(district);
        expr_item->district_id = expr_runtime_get_district_id(expr_rt, district);
    } else {
        expr_item->district_id = DISTRICT_ANY;
    }

    ret = get_column_pos(line, expr_schema->match_method_column, &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> has no match_method in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }
    
    match_method_type = atoi(line + column_offset);
    expr_item->match_mode = int_to_match_mode(match_method_type);
    if (expr_item->match_mode == EXPR_MATCH_MODE_INVALID) {
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> has invalid match_method in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        goto error;
    }

    ret = get_column_pos(line, expr_schema->is_hexbin_column, &column_offset, &column_len);
    if (ret < 0) {
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> has no is_hexbin in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
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
            log_fatal(expr_rt->logger, MODULE_EXPR, 
                      "[%s:%d] expr table:<%s> has invalid hexbin value:%d in line:%s",
                      __FUNCTION__, __LINE__, table_name, db_hexbin, line);
            goto error;
    }

    return expr_item;
error:
    FREE(expr_item);
    return NULL;
}

void *expr_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                      const char *table_name, struct log_handle *logger)
{
    char table_type[NAME_MAX] = {0};
	struct expr_schema *expr_schema = ALLOC(struct expr_schema, 1);
    expr_schema->engine_type = MAAT_EXPR_ENGINE_AUTO;

    cJSON *custom_item = NULL;
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (item != NULL && item->type == cJSON_Number) {
        expr_schema->table_id = item->valueint;
    } else {
        log_fatal(logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    /* table_type already validate in maat_table_new() */
    item = cJSON_GetObjectItem(json, "table_type");
    memcpy(table_type, item->valuestring, strlen(item->valuestring));

    item = cJSON_GetObjectItem(json, "expr_engine");
    if (item != NULL && item->type == cJSON_String) {
        if (strcmp(item->valuestring, "hyperscan") == 0) {
            expr_schema->engine_type = MAAT_EXPR_ENGINE_HS;
        } else if (strcmp(item->valuestring, "rulescan") == 0) {
            expr_schema->engine_type = MAAT_EXPR_ENGINE_RS;
        } else {
           log_fatal(logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> schema has invalid expr_engine", 
                  __FUNCTION__, __LINE__, table_name);
            goto error; 
        }
    }

    item = cJSON_GetObjectItem(json, "custom");
    if (item == NULL || item->type != cJSON_Object) {
        log_fatal(logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> schema has no custom column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

	custom_item = cJSON_GetObjectItem(item, "item_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->item_id_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> schema has no item_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

	custom_item = cJSON_GetObjectItem(item, "group_id");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->group_id_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> schema has no group_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "keywords");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->keywords_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> schema has no keywords column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    /* expr_plus has district */
    if (strcmp(table_type, "expr_plus") == 0) {
        custom_item = cJSON_GetObjectItem(item, "district");
        if (custom_item != NULL && custom_item->type == cJSON_Number) {
            expr_schema->district_column = custom_item->valueint;
        } else {
            log_fatal(logger, MODULE_EXPR, 
                  "[%s:%d] expr_plus table:<%s> schema has no district column", 
                  __FUNCTION__, __LINE__, table_name);
            goto error;
        }
    }

    custom_item = cJSON_GetObjectItem(item, "expr_type");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->expr_type_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> schema has no expr_type column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "match_method");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->match_method_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> schema has no match_method column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    custom_item = cJSON_GetObjectItem(item, "is_hexbin");
    if (custom_item != NULL && custom_item->type == cJSON_Number) {
        expr_schema->is_hexbin_column = custom_item->valueint;
    } else {
        log_fatal(logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> schema has no is_hexbin column", 
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

static void expr_rule_reset(struct expr_rule *rule)
{
    if (NULL == rule) {
        return;
    }

    for (size_t i = 0; i < rule->n_patterns; i++) {
        FREE(rule->patterns[i].pat);
    }
}

static void expr_item_free(struct expr_item *item)
{
    if (NULL == item) {
        return;
    }
    
    if (item->user_data != NULL) {
        FREE(item->user_data);
    }

    FREE(item);
}

static void expr_item_free_cb(void *user_ctx, void *data)
{
    struct expr_item *item = (struct expr_item *)data;
    expr_item_free(item);
}

void *expr_runtime_new(void *expr_schema, size_t max_thread_num, 
                       struct maat_garbage_bin *garbage_bin, 
                       struct log_handle *logger)
{
    if (NULL == expr_schema) {
        return NULL;
    }

    struct expr_schema *schema = (struct expr_schema *)expr_schema;
    struct expr_runtime *expr_rt = ALLOC(struct expr_runtime, 1);

    expr_rt->item_hash = rcu_hash_new(expr_item_free_cb, NULL, 0);
    expr_rt->n_worker_thread = max_thread_num;
    expr_rt->ref_garbage_bin = garbage_bin;
    expr_rt->logger = logger;
    expr_rt->district_map = maat_kv_store_new();
    if (schema->engine_type == MAAT_EXPR_ENGINE_AUTO) {
        expr_rt->engine_type = table_manager_get_expr_engine(schema->ref_tbl_mgr);
    } else {
        expr_rt->engine_type = schema->engine_type;
    }
    
    expr_rt->hit_cnt = alignment_int64_array_alloc(max_thread_num);
    expr_rt->scan_cnt = alignment_int64_array_alloc(max_thread_num);
    expr_rt->scan_bytes = alignment_int64_array_alloc(max_thread_num);
    expr_rt->scan_cpu_time = alignment_int64_array_alloc(max_thread_num);

    return expr_rt;
}

void expr_runtime_free(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    if (expr_rt->matcher != NULL) {
        expr_matcher_free(expr_rt->matcher);
        expr_rt->matcher = NULL;
    }

    if (expr_rt->item_hash != NULL) {
        rcu_hash_free(expr_rt->item_hash);
        expr_rt->item_hash = NULL;
    }

    assert(expr_rt->tmp_district_map == NULL);

    if (expr_rt->district_map != NULL) {
        maat_kv_store_free(expr_rt->district_map);
        expr_rt->district_map = NULL;
    }

    if (expr_rt->scan_cnt != NULL) {
        alignment_int64_array_free(expr_rt->scan_cnt);
        expr_rt->scan_cnt = NULL;
    }

    if (expr_rt->scan_cpu_time != NULL) {
        alignment_int64_array_free(expr_rt->scan_cpu_time);
        expr_rt->scan_cpu_time = NULL;
    }

    if (expr_rt->hit_cnt != NULL) {
        alignment_int64_array_free(expr_rt->hit_cnt);
        expr_rt->hit_cnt = NULL;
    }

    if (expr_rt->scan_bytes != NULL) {
        alignment_int64_array_free(expr_rt->scan_bytes);
        expr_rt->scan_bytes = NULL;
    }

    FREE(expr_rt);
}

static int expr_runtime_update_row(struct expr_runtime *expr_rt, char *key,
                                   size_t key_len, struct expr_item *item,
                                   int is_valid)
{
    int ret = -1;

    if (0 == is_valid) {
        //delete
        rcu_hash_del(expr_rt->item_hash, key, key_len);
    } else {
        //add
        ret = rcu_hash_add(expr_rt->item_hash, key, key_len, (void *)item);
        if (ret < 0) {
            log_fatal(expr_rt->logger, MODULE_EXPR,
                      "[%s:%d] expr item(item_id:%lld) add to item_hash failed", 
                      __FUNCTION__, __LINE__, item->item_id);
            return -1;
        }
    }

    return 0;
}

static enum expr_pattern_type expr_type2pattern_type(enum expr_type expr_type)
{
    enum expr_pattern_type pattern_type = EXPR_PATTERN_TYPE_STR;

    switch (expr_type) {
        case EXPR_TYPE_STRING:
        case EXPR_TYPE_AND:
        case EXPR_TYPE_OFFSET:
            pattern_type = EXPR_PATTERN_TYPE_STR;
            break;
        case EXPR_TYPE_REGEX:
            pattern_type = EXPR_PATTERN_TYPE_REG;
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
static int expr_item_to_expr_rule(struct expr_item *expr_item,
                                  struct expr_rule *expr_rule,
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

    switch (expr_item->expr_type) {
        case EXPR_TYPE_AND:
            for (i = 0, pos = expr_item->keywords; ; i++, pos = NULL) {
                tmp = strtok_r_esc(pos, '&', &saveptr);
                if (NULL == tmp) {
                    break;
                }

                if (i >= MAAT_MAX_EXPR_ITEM_NUM) {
                    log_fatal(logger, MODULE_EXPR,
                              "[%s:%d]abandon config expr_item(item_id:%d) "
                              "too many patterns", __FUNCTION__, __LINE__,
                              expr_item->item_id);
                    return -1;
                }

                sub_key_array[i] = tmp;
                sub_key_array[i] = str_unescape(sub_key_array[i]); 
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
                    log_fatal(logger, MODULE_EXPR,
                              "[%s:%d]abandon config expr_item(item_id:%d) "
                              "too many patterns", __FUNCTION__, __LINE__,
                              expr_item->item_id);
                    return -1;
                }

                sub_key_array[i] = tmp;
                sscanf(sub_key_array[i], "%d-%d:", &(key_left_offset[i]),
                       &(key_right_offset[i]));
				if (!(key_left_offset[i] >= 0 && key_right_offset[i] > 0 
                      && key_left_offset[i] <= key_right_offset[i])) {
					log_fatal(logger, MODULE_EXPR,
							 "[%s:%d]abandon config expr_item(item_id:%d) "
                             "has invalid offset.", __FUNCTION__, __LINE__,
                             expr_item->item_id);
                    return -1;
				}

				sub_key_array[i] = (char *)memchr(sub_key_array[i], ':',
                                                  strlen(sub_key_array[i]));
				if (NULL == sub_key_array[i]) {
					log_fatal(logger, MODULE_EXPR,
							"[%s:%d]abandon config expr_item(item_id:%d) "
                            "has invalid offset keyword format.",
                            __FUNCTION__, __LINE__, expr_item->item_id);
                    return -1;
				}

				sub_key_array[i]++;//jump over ':'
				sub_key_array[i] = str_unescape(sub_key_array[i]);
            }
            sub_expr_cnt = i;
            break;
        case EXPR_TYPE_STRING: //AND/OFFSET/STRING type expression use \b to represent blank(' ')
            sub_expr_cnt = 1;
            sub_key_array[0] = expr_item->keywords;
            sub_key_array[0] = str_unescape(sub_key_array[0]);
            break;
        case EXPR_TYPE_REGEX: //only regex type expression use \s to represent blank(' ')
            sub_expr_cnt = 1;
            sub_key_array[0] = expr_item->keywords;
            break;
        default:
            log_fatal(logger, MODULE_EXPR, 
                      "[%s:%d]abandon config expr_item(item_id:%lld) has "
                      "invalid expr type=%d", __FUNCTION__, __LINE__,
                      expr_item->item_id, expr_item->expr_type);
            return -1;
    }

    for (i = 0; i < sub_expr_cnt; i++) {
        size_t region_str_len = 0;
        char *region_string = NULL;
        size_t sub_key_len = 0;

        if (TRUE == expr_item->is_case_sensitive) {
            // insensitive
            expr_rule->patterns[i].case_sensitive = EXPR_CASE_SENSITIVE;
        } else {
            expr_rule->patterns[i].case_sensitive = EXPR_CASE_INSENSITIVE;
        }

        expr_rule->patterns[i].type = expr_type2pattern_type(expr_item->expr_type);

        if (TRUE == expr_item->is_hexbin && 
            expr_rule->patterns[i].type != EXPR_PATTERN_TYPE_REG) {
            region_str_len = strlen(sub_key_array[i]) * 8;
			region_string = ALLOC(char, region_str_len + 1);
			region_str_len = hex2bin(sub_key_array[i], strlen(sub_key_array[i]),
                                     region_string, region_str_len);
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
        if (expr_rule->patterns[i].match_mode == EXPR_MATCH_MODE_SUB) {
            expr_rule->patterns[i].start_offset = key_left_offset[i];
            expr_rule->patterns[i].end_offset = key_right_offset[i];
        }
    }
    expr_rule->expr_id = expr_item->item_id;
    expr_rule->tag = expr_item->user_data;
    expr_rule->n_patterns = sub_expr_cnt;
    
    return 0;
}

int expr_runtime_update(void *expr_runtime, void *expr_schema, 
                        const char *table_name, const char *line, 
                        int valid_column)
{
    if (NULL == expr_runtime || NULL == expr_schema ||
        NULL == line) {
        return -1;
    }

    struct expr_schema *schema = (struct expr_schema *)expr_schema;
    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;

    long long item_id = get_column_value(line, schema->item_id_column);
    if (item_id < 0) {
        log_fatal(expr_rt->logger, MODULE_EXPR,
                  "[%s:%d] expr table:<%s> has no item_id(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  schema->item_id_column, line);
        expr_rt->update_err_cnt++;
        return -1;
    }

    int is_valid = get_column_value(line, valid_column);
    if (is_valid < 0) {
        log_fatal(expr_rt->logger, MODULE_EXPR,
                  "[%s:%d] expr table:<%s> has no is_valid(column seq:%d)"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  valid_column, line);
        expr_rt->update_err_cnt++;
        return -1;
    }
    
    struct expr_item *expr_item = NULL;
    if (1 == is_valid) {
        //add
        expr_item = expr_item_new(schema, table_name, line, expr_rt);
        if (NULL == expr_item) {
            expr_rt->update_err_cnt++;
            return -1;
        }

        int *item_district_id = ALLOC(int, 1);
        *item_district_id = expr_item->district_id;
        
        expr_item->user_data = item_district_id;
    }

    int ret = expr_runtime_update_row(expr_rt, (char *)&item_id, sizeof(long long),
                                      expr_item, is_valid);
    if (ret < 0) {
        if (expr_item != NULL) {
            expr_item_free(expr_item);
        }
        expr_rt->update_err_cnt++;
        return -1;
    }

    return 0;
}

static void garbage_expr_matcher_free(void *expr_matcher, void *arg)
{
    struct expr_matcher *matcher = (struct expr_matcher *)expr_matcher;
    expr_matcher_free(matcher);
}

const char *expr_engine_int2str(enum expr_engine_type type)
{
    switch (type) {
        case EXPR_ENGINE_TYPE_HS:
            return "hyperscan";
        case EXPR_ENGINE_TYPE_RS:
            return "rulescan";
        default:
            return "unknown";
    }
}

int expr_runtime_commit(void *expr_runtime, const char *table_name,
                        long long maat_rt_version)
{
    if (NULL == expr_runtime) {
        return -1;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;

    int updating_flag = rcu_hash_is_updating(expr_rt->item_hash);
    if (0 == updating_flag) {
        return 0;
    }

    if (expr_rt->tmp_district_map != NULL) {
        struct maat_kv_store *tmp_map = expr_rt->district_map;
        expr_rt->district_map = expr_rt->tmp_district_map;
        expr_rt->tmp_district_map = NULL;
        maat_garbage_bagging(expr_rt->ref_garbage_bin, tmp_map, NULL, 
                             garbage_maat_kv_store_free);
    }

    int ret = 0;
    size_t i = 0;
    size_t real_rule_cnt = 0;
    size_t real_lit_rule_cnt = 0;
    size_t real_regex_rule_cnt = 0;
    struct expr_rule *rules = NULL;
    void **ex_data_array = NULL;

    size_t rule_cnt = rcu_updating_hash_list(expr_rt->item_hash, &ex_data_array);
    if (rule_cnt > 0) {
        rules = ALLOC(struct expr_rule, rule_cnt);
        for (i = 0; i < rule_cnt; i++) {
            struct expr_item *expr_item = (struct expr_item *)ex_data_array[i];
            struct expr_rule tmp_rule = {0};
            ret = expr_item_to_expr_rule(expr_item, &tmp_rule, expr_rt->logger);
            if (ret < 0) {
                continue;
            }

            rules[real_rule_cnt++] = tmp_rule;

            if (expr_item->expr_type == EXPR_TYPE_REGEX) {
                real_regex_rule_cnt++;
            } else {
                real_lit_rule_cnt++;
            }
        }
    }

    if (expr_rt->engine_type == EXPR_ENGINE_TYPE_AUTO) {
        if (real_lit_rule_cnt <= ENGINE_TYPE_SWITCH_THRESHOLD) {
            expr_rt->engine_type = EXPR_ENGINE_TYPE_HS;
        } else {
            expr_rt->engine_type = EXPR_ENGINE_TYPE_RS;
        }
    }

    struct expr_matcher *new_matcher = NULL;
    struct expr_matcher *old_matcher = NULL;

    if (rule_cnt > 0) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        new_matcher = expr_matcher_new(rules, real_rule_cnt, expr_rt->engine_type,
                                       expr_rt->n_worker_thread, expr_rt->logger);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 +
                                   (end.tv_nsec - start.tv_nsec) / 1000000;

        if (NULL == new_matcher) {
            log_fatal(expr_rt->logger, MODULE_EXPR,
                      "[%s:%d] table[%s] rebuild expr_matcher failed when update"
                      " %zu expr rules", __FUNCTION__, __LINE__, table_name, real_rule_cnt);
            ret = -1;
        } else {
            log_info(expr_rt->logger, MODULE_EXPR,
                     "table[%s] has %zu rules, commit %zu expr rules(literal_rules:%zu regex_rules:%zu)"
                     " and rebuild expr_matcher(%s) completed, version:%lld, consume:%lldms",
                     table_name, rule_cnt, real_rule_cnt, real_lit_rule_cnt, real_regex_rule_cnt,
                     expr_engine_int2str(expr_rt->engine_type), maat_rt_version, time_elapse_ms);
        }
    }

    old_matcher = expr_rt->matcher;
    expr_rt->matcher = new_matcher;
    rcu_hash_commit(expr_rt->item_hash);

    if (old_matcher != NULL) {
        maat_garbage_bagging(expr_rt->ref_garbage_bin, old_matcher, NULL, garbage_expr_matcher_free);
    }
    
    expr_rt->rule_num = real_rule_cnt;
    expr_rt->regex_rule_num = real_regex_rule_cnt;
    expr_rt->version = maat_rt_version;

    if (rules != NULL) {
        for (i = 0; i < rule_cnt; i++) {
            expr_rule_reset(&rules[i]);
        }
       FREE(rules); 
    }
    
    if (ex_data_array != NULL) {
        FREE(ex_data_array);
    }

    return ret;
}

long long expr_runtime_rule_count(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return 0;
    }
    
    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    return expr_rt->rule_num;
}

long long expr_runtime_regex_rule_count(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return 0;
    }
    
    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    return expr_rt->regex_rule_num;
}

long long expr_runtime_get_version(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return -1;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    return expr_rt->version;
}

int expr_runtime_scan(struct expr_runtime *expr_rt, int thread_id,
                      const char *data, size_t data_len,
                      int vtable_id, struct maat_state *state)
{
    if (0 == expr_rt->rule_num) {
        //empty expr table
        return 0;
    }

    if (NULL == expr_rt->matcher) {
        return 0;
    }

    size_t n_hit_item = 0;
    struct expr_scan_result hit_results[MAX_HIT_ITEM_NUM];
    int ret = expr_matcher_match(expr_rt->matcher, thread_id, data, data_len, 
                                 hit_results, MAX_HIT_ITEM_NUM, &n_hit_item);
    if (ret < 0) {
        return -1;
    }

    struct maat_item hit_maat_items[n_hit_item];
    size_t real_hit_item_cnt = 0;

    if (0 == n_hit_item) {
        goto next;
    }

    for (size_t i = 0; i < n_hit_item; i++) {
        int tag_district_id = *(int *)(hit_results[i].user_tag);
        if (tag_district_id == state->district_id || tag_district_id == DISTRICT_ANY) {
            long long item_id = hit_results[i].rule_id;
            struct expr_item *expr_item = (struct expr_item *)rcu_hash_find(expr_rt->item_hash, 
                                                                            (char *)&item_id,
                                                                            sizeof(long long));
            if (!expr_item) {
                // item config has been deleted
                continue;
            }

            hit_maat_items[real_hit_item_cnt].item_id = item_id;
            hit_maat_items[real_hit_item_cnt].group_id = expr_item->group_id;
            
            real_hit_item_cnt++;
        }
    }

next:
    if (NULL == state->compile_state) {
        state->compile_state = compile_state_new();
        alignment_int64_array_add(state->maat_inst->stat->compile_state_cnt,
                                  state->thread_id, 1);
    }

    return compile_state_update(state->compile_state, state->maat_inst, vtable_id,
                                state->compile_table_id, state->scan_cnt,
                                hit_maat_items, real_hit_item_cnt);
}

struct expr_matcher_stream *
expr_runtime_stream_open(struct expr_runtime *expr_rt, int thread_id)
{
    if (NULL == expr_rt || thread_id < 0) {
        return NULL;
    }

    struct expr_matcher_stream *stream = expr_matcher_stream_open(expr_rt->matcher,
                                                                  thread_id);
    if (NULL == stream) {
        return NULL;
    }

    return stream;
}

int expr_runtime_stream_scan(struct expr_runtime *expr_rt,
                             struct expr_matcher_stream *s_handle,
                             const char *data, size_t data_len,
                             int vtable_id, struct maat_state *state)
{
    if (0 == expr_rt->rule_num) {
        //empty expr table
        return 0;
    }

    size_t n_hit_item = 0;
    struct expr_scan_result hit_results[MAX_HIT_ITEM_NUM];

    int ret = expr_matcher_stream_match(s_handle, data, data_len, hit_results,
                                        MAX_HIT_ITEM_NUM, &n_hit_item);
    if (ret < 0) {
        return -1;
    }

    struct maat_item hit_maat_items[n_hit_item];
    struct expr_item *expr_item = NULL;
    size_t real_hit_item_cnt = 0;

    if (0 == n_hit_item) {
        goto next;
    }

    for (size_t i = 0; i < n_hit_item; i++) {
        long long item_id = hit_results[i].rule_id;
        expr_item = (struct expr_item *)rcu_hash_find(expr_rt->item_hash,
                                                      (char *)&item_id,
                                                      sizeof(long long));
        if (!expr_item) {
            // item config has been deleted
            continue;
        }

        hit_maat_items[real_hit_item_cnt].item_id = item_id;
        hit_maat_items[real_hit_item_cnt].group_id = expr_item->group_id;
        real_hit_item_cnt++;
    }

next:
    if (NULL == state->compile_state) {
        state->compile_state = compile_state_new();
        alignment_int64_array_add(state->maat_inst->stat->compile_state_cnt,
                                  state->thread_id, 1);
    }

    return compile_state_update(state->compile_state, state->maat_inst, vtable_id,
                                state->compile_table_id, state->scan_cnt,
                                hit_maat_items, real_hit_item_cnt);
}

void expr_runtime_stream_close(struct expr_runtime *expr_rt, int thread_id, 
                               struct expr_matcher_stream *stream)
{
    if (NULL == expr_rt || thread_id < 0 || NULL == stream) {
        return;
    }

    expr_matcher_stream_close(stream);
}

void expr_runtime_hit_inc(struct expr_runtime *expr_rt, int thread_id)
{
    if (NULL == expr_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(expr_rt->hit_cnt, thread_id, 1);
}

void expr_runtime_perf_stat(struct expr_runtime *expr_rt, size_t scan_len, 
                            struct timespec *start, struct timespec *end, 
                            int thread_id)
{
    if (NULL == expr_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(expr_rt->scan_cnt, thread_id, 1);
    alignment_int64_array_add(expr_rt->scan_bytes, thread_id, scan_len);

    if (start != NULL && end != NULL) {
        long long consume_time = (end->tv_sec - start->tv_sec) * 1000000000 +
                                 (end->tv_nsec - start->tv_nsec);
        alignment_int64_array_add(expr_rt->scan_cpu_time, thread_id, consume_time);
    }
}

long long expr_runtime_scan_count(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return 0;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    long long sum = alignment_int64_array_sum(expr_rt->scan_cnt, 
                                              expr_rt->n_worker_thread);
    alignment_int64_array_reset(expr_rt->scan_cnt, expr_rt->n_worker_thread);

    return sum;
}

long long expr_runtime_scan_cpu_time(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return 0;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    long long sum = alignment_int64_array_sum(expr_rt->scan_cpu_time, 
                                              expr_rt->n_worker_thread);
    alignment_int64_array_reset(expr_rt->scan_cpu_time, expr_rt->n_worker_thread);

    return sum;
}

long long expr_runtime_hit_count(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return 0;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    long long sum = alignment_int64_array_sum(expr_rt->hit_cnt, 
                                              expr_rt->n_worker_thread);
    alignment_int64_array_reset(expr_rt->hit_cnt, expr_rt->n_worker_thread);

    return sum;
}

long long expr_runtime_update_err_count(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return 0;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    return expr_rt->update_err_cnt;
}

long long expr_runtime_scan_bytes(struct expr_runtime *expr_rt)
{
    if (NULL == expr_rt) {
        return 0;
    }

    long long sum = alignment_int64_array_sum(expr_rt->scan_bytes, 
                                              expr_rt->n_worker_thread);
    alignment_int64_array_reset(expr_rt->scan_bytes, expr_rt->n_worker_thread);

    return sum;
}