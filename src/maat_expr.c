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
#include "maat_core.h"
#include "maat_rule.h"
#include "maat_object.h"
#include "alignment.h"
#include "maat_garbage_collection.h"

#define MODULE_EXPR	 module_name_str("maat.expr")

/*
    If expr_engine_type == MAAT_EXPR_ENGINE_AUTO, and the pattern number less than 50K,
    expr_engine_type = MAAT_EXPR_ENGINE_HS; Otherwise expr_engine_type = MAAT_EXPR_ENGINE_RS
*/
#define ENGINE_TYPE_SWITCH_THRESHOLD 50000

struct expr_schema {
    int table_id;
    enum maat_expr_engine engine_type;
    struct table_manager *ref_tbl_mgr;
};

enum match_method {
    MATCH_METHOD_SUB = 0,
	MATCH_METHOD_RIGHT,
	MATCH_METHOD_LEFT,
	MATCH_METHOD_COMPLETE,
    MATCH_METHOD_MAX
};

struct expr_item {
    uuid_t item_uuid;
    uuid_t object_uuid;
    char keywords[MAX_KEYWORDS_STR_LEN + 1];
    enum expr_type expr_type;
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

    long long *scan_times;
    long long *scan_cpu_time;
    long long *scan_bytes;

    long long *hit_times;
    long long *hit_item_num;
    long long *hit_pattern_num;

    long long update_err_cnt;
};

struct expr_runtime_stream {
    struct expr_runtime *ref_expr_rt;
    struct expr_matcher_stream *handle;
};

static struct expr_item *
expr_item_new(struct expr_schema *expr_schema, const char *table_name,
              const cJSON *json, struct expr_runtime *expr_rt, uuid_t item_uuid)
{
    struct expr_item *expr_item = ALLOC(struct expr_item, 1);
    cJSON *tmp_obj = NULL;
    size_t len = 0;
    int ret;

    uuid_copy(expr_item->item_uuid, item_uuid);

    tmp_obj = cJSON_GetObjectItem(json, "object_uuid");
    if (tmp_obj == NULL && tmp_obj->type != cJSON_String) {
        char *json_str = cJSON_Print(json);
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> has no object_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, json_str);
        FREE(json_str);
        goto error;
    }
    uuid_parse(tmp_obj->valuestring, expr_item->object_uuid);

    tmp_obj = cJSON_GetObjectItem(json, "expression");
    if (tmp_obj == NULL || tmp_obj->type != cJSON_String) {
        char *json_str = cJSON_Print(json);
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> has no expression in line:%s",
                  __FUNCTION__, __LINE__, table_name, json_str);
        FREE(json_str);
        goto error;
    }
    len = strlen(tmp_obj->valuestring);

    if (len > MAX_KEYWORDS_STR_LEN) {
        char *json_str = cJSON_Print(json);
        log_fatal(expr_rt->logger, MODULE_EXPR, 
                  "[%s:%d] expr table:<%s> expression length too long in line:%s",
                  __FUNCTION__, __LINE__, table_name, json_str);
        FREE(json_str);
        goto error;
    }
    memcpy(expr_item->keywords, tmp_obj->valuestring, len);

    tmp_obj = cJSON_GetObjectItem(json, "expr_type");
    if (tmp_obj == NULL || tmp_obj->type != cJSON_String) {
        char *json_str = cJSON_Print(json);
        log_fatal(expr_rt->logger, MODULE_EXPR,
                  "[%s:%d] expr table:<%s> has no expr_type in line:%s",
                  __FUNCTION__, __LINE__, table_name, json_str);
        FREE(json_str);
        goto error;
    }

    if (strncmp(tmp_obj->valuestring, "and", 3) == 0) {
        expr_item->expr_type = EXPR_TYPE_AND;
    } else if (strncmp(tmp_obj->valuestring, "regex", 5) == 0) {
        expr_item->expr_type = EXPR_TYPE_REGEX;
    } else {
        expr_item->expr_type = EXPR_TYPE_INVALID;
    }

    if (expr_item->expr_type == EXPR_TYPE_INVALID) {
        char *json_str = cJSON_Print(json);
        log_fatal(expr_rt->logger, MODULE_EXPR,
                  "[%s:%d] expr table:<%s> has invalid expr_type in line:%s",
                 __FUNCTION__, __LINE__, table_name, json_str);
        FREE(json_str);
        goto error;
    } else if (expr_item->expr_type == EXPR_TYPE_REGEX) {
        ret = expr_matcher_verify_regex_expression(expr_item->keywords, expr_rt->logger);
        if (0 == ret) {
            char uuid_str[UUID_STR_LEN] = {0};
            uuid_unparse(item_uuid, uuid_str);
            log_fatal(expr_rt->logger, MODULE_EXPR,
                      "[%s:%d] expr table:<%s> regex expression(item_id:%s):%s illegal,"
                      " will be dropped", __FUNCTION__, __LINE__, table_name,
                      uuid_str, expr_item->keywords);
            goto error;
        }
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

    if (schema->engine_type == MAAT_EXPR_ENGINE_AUTO) {
        expr_rt->engine_type = table_manager_get_expr_engine(schema->ref_tbl_mgr);
    } else {
        expr_rt->engine_type = schema->engine_type;
    }
    
    expr_rt->scan_times = alignment_int64_array_alloc(max_thread_num);
    expr_rt->scan_bytes = alignment_int64_array_alloc(max_thread_num);
    expr_rt->scan_cpu_time = alignment_int64_array_alloc(max_thread_num);

    expr_rt->hit_times = alignment_int64_array_alloc(max_thread_num);
    expr_rt->hit_item_num = alignment_int64_array_alloc(max_thread_num);
    expr_rt->hit_pattern_num = alignment_int64_array_alloc(max_thread_num);

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

    if (expr_rt->scan_times != NULL) {
        alignment_int64_array_free(expr_rt->scan_times);
        expr_rt->scan_times = NULL;
    }

    if (expr_rt->scan_cpu_time != NULL) {
        alignment_int64_array_free(expr_rt->scan_cpu_time);
        expr_rt->scan_cpu_time = NULL;
    }

    if (expr_rt->scan_bytes != NULL) {
        alignment_int64_array_free(expr_rt->scan_bytes);
        expr_rt->scan_bytes = NULL;
    }

    if (expr_rt->hit_times != NULL) {
        alignment_int64_array_free(expr_rt->hit_times);
        expr_rt->hit_times = NULL;
    }

    if (expr_rt->hit_item_num != NULL) {
        alignment_int64_array_free(expr_rt->hit_item_num);
        expr_rt->hit_item_num = NULL;
    }

    if (expr_rt->hit_pattern_num != NULL) {
        alignment_int64_array_free(expr_rt->hit_pattern_num);
        expr_rt->hit_pattern_num = NULL;
    }

    FREE(expr_rt);
}

static int expr_runtime_update_row(struct expr_runtime *expr_rt, char *key,
                                   size_t key_len, struct expr_item *item,
                                   enum maat_operation op)
{
    int ret = -1;

    if (MAAT_OP_DEL == op) {
        //delete
        rcu_hash_del(expr_rt->item_hash, key, key_len);
    } else {
        //add
        ret = rcu_hash_add(expr_rt->item_hash, key, key_len, (void *)item);
        if (ret < 0) {
            char uuid_str[UUID_STR_LEN] = {0};
            uuid_unparse(item->item_uuid, uuid_str);
            log_debug(expr_rt->logger, MODULE_EXPR,
                      "[%s:%d] expr item(item_id:%s) add to item_hash failed", 
                      __FUNCTION__, __LINE__, uuid_str);
            return -1;
        }
    }

    return 0;
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

static int expr_keywords_to_expr_pattern(char *keywords, struct expr_pattern *pattern, struct log_handle *logger)
{
    char *ctrl_str = NULL;
    char *expr_str = NULL;
    int case_ctrl_flag = 0;

    pattern->match_mode = EXPR_MATCH_MODE_SUB;
    pattern->case_sensitive = EXPR_CASE_INSENSITIVE;
    /* -1 means offset no limit, As long as the pattern appears in the scan data, it will hit */
    pattern->start_offset = -1;
    pattern->end_offset = -1;

    if (keywords[0] == '(') {
        ctrl_str = keywords + 1;
        char *ctrl_str_end = strchr(ctrl_str, ')');
        if (NULL == ctrl_str_end) {
            return -1;
        }
        ctrl_str_end[0] = '\0';
        expr_str = ctrl_str_end + 1;
    } else {
        expr_str = keywords;
    }

    if (ctrl_str != NULL) {
        char case_switch[8] = {0};
        char *nocase_str = strstr(ctrl_str, "nocase");
        if (nocase_str) {
            case_ctrl_flag = 1;
            sscanf(nocase_str, "nocase=%s", case_switch);
            if (strcmp(case_switch, "off") == 0) {
                pattern->case_sensitive = EXPR_CASE_SENSITIVE;
            } else {
                pattern->case_sensitive = EXPR_CASE_INSENSITIVE;
            }
        }

        char *offset_str = strstr(ctrl_str, "offset");
        char *depth_str = strstr(ctrl_str, "depth");
        if (offset_str && depth_str) {
            sscanf(offset_str, "offset=%d", &pattern->start_offset);
            sscanf(depth_str, "depth=%d", &pattern->end_offset);
            pattern->match_mode = EXPR_MATCH_MODE_SUB;

            if (pattern->start_offset < 0 || pattern->end_offset <= 0 || (pattern->start_offset > pattern->end_offset)) {
                return -1;
            }
        }
    }

    if (expr_str[0] == '^') {
        pattern->match_mode = EXPR_MATCH_MODE_PREFIX;
        expr_str++;
    }

    char *expr_suffix = strchr_esc(expr_str, '$');
    if (expr_suffix != NULL) {
        expr_suffix[0] = '\0';
        if (pattern->match_mode == EXPR_MATCH_MODE_PREFIX) {
            pattern->match_mode = EXPR_MATCH_MODE_EXACTLY;
        } else {
            pattern->match_mode = EXPR_MATCH_MODE_SUFFIX;
        }
    }

    char *hex_str_start = strchr_esc(expr_str, '|');
    char *tmp_start_str = expr_str;
    char *tmp_end_str = NULL;
    char tmp_keywords[MAX_KEYWORDS_STR_LEN + 1] = {0};
    size_t pattern_len = 0;

    if (hex_str_start && !case_ctrl_flag) {
        pattern->case_sensitive = EXPR_CASE_SENSITIVE;
    }

    while (hex_str_start != NULL) {
        hex_str_start[0] = '\0';
        hex_str_start++;

        tmp_end_str = strchr_esc(hex_str_start, '|');
        if (tmp_end_str == NULL) {
            return -1;
        }
        tmp_end_str[0] = '\0';
        tmp_end_str++;

        size_t region_str_len = strlen(hex_str_start) * 8;
        char *region_string = ALLOC(char, region_str_len + 1);
        region_str_len = hex2bin(hex_str_start, strlen(hex_str_start), region_string, region_str_len);
        
        tmp_start_str = str_unescape(tmp_start_str);
        //snprintf(tmp_keywords + pattern_len, MAX_KEYWORDS_STR_LEN - pattern_len, "%s%s", tmp_start_str, region_string);
        if (pattern_len + strlen(tmp_start_str) + region_str_len > MAX_KEYWORDS_STR_LEN) {
            return -1;
        }
        memcpy(tmp_keywords + pattern_len, tmp_start_str, strlen(tmp_start_str));
        pattern_len += strlen(tmp_start_str);
        memcpy(tmp_keywords + pattern_len, region_string, region_str_len);//can't use strcpy cause region_string is from hexbin and may contain '\0'
        pattern_len += region_str_len;

        if (region_string != NULL) {
            FREE(region_string);
        }

        tmp_start_str = tmp_end_str;
        hex_str_start = strchr_esc(tmp_start_str, '|');
    }
    if (tmp_end_str != NULL && tmp_end_str[0] != '\0') {
        tmp_end_str = str_unescape(tmp_end_str);
        if (pattern_len + strlen(tmp_start_str) + strlen(tmp_end_str) > MAX_KEYWORDS_STR_LEN) {
            return -1;
        }
        snprintf(tmp_keywords + pattern_len, MAX_KEYWORDS_STR_LEN - pattern_len, "%s%s", tmp_start_str, tmp_end_str);
        pattern_len = strlen(tmp_keywords);
    }

    if (pattern_len == 0) {
        expr_str = str_unescape(expr_str);
        pattern->pat_len = strlen(expr_str);
        pattern->pat = ALLOC(char, pattern->pat_len + 1);
        memcpy(pattern->pat, expr_str, pattern->pat_len);
        
    } else {
        pattern->pat = ALLOC(char, pattern_len + 1);
        memcpy(pattern->pat, tmp_keywords, pattern_len);
        pattern->pat_len = pattern_len;
    }

    if (pattern->pat_len == 0) {
        return -1;
    }

    return 0;
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
    char tmp_keywords[MAX_KEYWORDS_STR_LEN + 1];
    char uuid_str[UUID_STR_LEN] = {0};
    
    uuid_unparse(expr_item->item_uuid, uuid_str);

    memcpy(tmp_keywords, expr_item->keywords, MAX_KEYWORDS_STR_LEN + 1);

    switch (expr_item->expr_type) {
        case EXPR_TYPE_AND:
            for (i = 0, pos = tmp_keywords; ; i++, pos = NULL) {
                tmp = strtok_r_esc(pos, '&', &saveptr);
                if (NULL == tmp) {
                    break;
                }

                if (i >= MAAT_MAX_EXPR_ITEM_NUM) {
                    log_fatal(logger, MODULE_EXPR,
                            "[%s:%d]abandon config expr_item(item_id:%s) "
                            "too many patterns", __FUNCTION__, __LINE__,
                            uuid_str);
                    return -1;
                }

                if (expr_keywords_to_expr_pattern(tmp, &expr_rule->patterns[i], logger) < 0) {
                    log_fatal(logger, MODULE_EXPR,
                            "[%s:%d]abandon config expr_item(item_id:%s) "
                            "has invalid pattern %s", __FUNCTION__, __LINE__,
                            uuid_str, tmp);
                    return -1;
                }
                expr_rule->patterns[i].type = EXPR_PATTERN_TYPE_STR;
            }
            sub_expr_cnt = i;
            break;
        case EXPR_TYPE_REGEX:
            sub_expr_cnt = 1;
            size_t pat_len = strlen(tmp_keywords);
            expr_rule->patterns[0].pat = ALLOC(char, pat_len + 1);
            memcpy(expr_rule->patterns[0].pat, tmp_keywords, pat_len);
            expr_rule->patterns[0].pat_len = pat_len;
            expr_rule->patterns[0].type = EXPR_PATTERN_TYPE_REG;
            expr_rule->patterns[0].match_mode = EXPR_MATCH_MODE_SUB;
            expr_rule->patterns[0].case_sensitive = EXPR_CASE_INSENSITIVE;
            expr_rule->patterns[0].start_offset = -1;
            expr_rule->patterns[0].end_offset = -1;
            break;
        default:
            log_fatal(logger, MODULE_EXPR, 
                    "[%s:%d]abandon config expr_item(item_id:%s) has "
                    "invalid expr type=%d", __FUNCTION__, __LINE__,
                    uuid_str, expr_item->expr_type);
            return -1;
    }

    uuid_copy(expr_rule->expr_uuid, expr_item->item_uuid);
    expr_rule->n_patterns = sub_expr_cnt;
    
    return 0;
}

int expr_runtime_update(void *expr_runtime, void *expr_schema, 
                        const char *table_name, const char *line, 
                        enum maat_operation op)
{
    if (NULL == expr_runtime || NULL == expr_schema ||
        NULL == line) {
        return -1;
    }

    struct expr_schema *schema = (struct expr_schema *)expr_schema;
    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    cJSON *tmp_obj = NULL;
    cJSON *json = cJSON_Parse(line);
    
    if (NULL == json) {
        log_fatal(expr_rt->logger, MODULE_EXPR,
                  "[%s:%d] expr table:<%s> line:%s is not a valid json",
                  __FUNCTION__, __LINE__, table_name, line);
        expr_rt->update_err_cnt++;
        return -1;
    }

    tmp_obj = cJSON_GetObjectItem(json, "uuid");
    if (tmp_obj == NULL || tmp_obj->type != cJSON_String) {
        log_fatal(expr_rt->logger, MODULE_EXPR,
                  "[%s:%d] expr table:<%s> has no item_id in line:%s",
                  __FUNCTION__, __LINE__, table_name, line);
        expr_rt->update_err_cnt++;
        goto ERROR;
    }

    uuid_t item_uuid;
    uuid_parse(tmp_obj->valuestring, item_uuid);
    if (uuid_is_null(item_uuid)) {
        char *json_str = cJSON_Print(json);
        log_fatal(expr_rt->logger, MODULE_EXPR,
                  "[%s:%d] expr table:<%s> item_id wrong"
                  " in table_line:%s", __FUNCTION__, __LINE__, table_name,
                  json_str);
        FREE(json_str);
        expr_rt->update_err_cnt++;
        goto ERROR;
    }
    
    struct expr_item *expr_item = NULL;
    if (MAAT_OP_ADD == op) {
        //add
        expr_item = expr_item_new(schema, table_name, json, expr_rt, item_uuid);
        if (NULL == expr_item) {
            expr_rt->update_err_cnt++;
            goto ERROR;
        }
    }

    int ret = expr_runtime_update_row(expr_rt, (char *)&item_uuid, sizeof(item_uuid),
                                      expr_item, op);
    if (ret < 0) {
        if (expr_item != NULL) {
            expr_item_free(expr_item);
        }
        //don't return failed, ignore the case of adding duplicate keys
    }

    cJSON_Delete(json);
    return 0;
ERROR:
    if (json != NULL) {
        cJSON_Delete(json);
    }
    return -1;
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

    int ret = 0;
    size_t i = 0;
    size_t real_rule_cnt = 0;
    size_t real_lit_rule_cnt = 0;
    size_t real_regex_rule_cnt = 0;
    struct expr_rule *rules = NULL;
    void **ex_data_array = NULL;
    enum expr_engine_type engine_type;

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
            engine_type = EXPR_ENGINE_TYPE_HS;
        } else {
            engine_type = EXPR_ENGINE_TYPE_RS;
        }
    } else {
        engine_type = expr_rt->engine_type;
    }

    struct expr_matcher *new_matcher = NULL;
    struct expr_matcher *old_matcher = NULL;

    if (rule_cnt > 0) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        new_matcher = expr_matcher_new(rules, real_rule_cnt, engine_type,
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
                     expr_engine_int2str(engine_type), maat_rt_version, time_elapse_ms);
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
                      const char *attribute_name, struct maat_state *state)
{
    //clear rule_state->last_hit_object
    if (state != NULL && state->rule_compile_state != NULL) {
        rule_compile_state_clear_last_hit_object(state->rule_compile_state);
    }

    if (0 == expr_rt->rule_num) {
        //empty expr table
        return 0;
    }

    if (NULL == expr_rt->matcher) {
        return 0;
    }

    size_t n_hit_item = 0;
    size_t n_hit_pattern = 0;
    struct expr_scan_result hit_results[MAX_HIT_ITEM_NUM];
    int ret = expr_matcher_match(expr_rt->matcher, thread_id, data, data_len, 
                                 hit_results, MAX_HIT_ITEM_NUM, &n_hit_item,
                                 &n_hit_pattern);
    if (ret < 0) {
        return -1;
    }

    if (n_hit_pattern > 0) {
        alignment_int64_array_add(expr_rt->hit_pattern_num, state->thread_id,
                                  n_hit_pattern);
    }

    struct maat_item hit_maat_items[n_hit_item];
    size_t real_hit_item_num = 0;

    if (0 == n_hit_item) {
        goto next;
    }

    for (size_t i = 0; i < n_hit_item; i++) {
        struct expr_item *expr_item = (struct expr_item *)rcu_hash_find(expr_rt->item_hash, 
                                                                        (char *)&hit_results[i].rule_uuid,
                                                                        sizeof(uuid_t));
        if (!expr_item) {
            // item config has been deleted
            continue;
        }

        uuid_copy(hit_maat_items[real_hit_item_num].item_uuid, expr_item->item_uuid);
        uuid_copy(hit_maat_items[real_hit_item_num].object_uuid, expr_item->object_uuid);
        real_hit_item_num++;
    }

    if (real_hit_item_num > 0) {
        alignment_int64_array_add(expr_rt->hit_item_num, state->thread_id,
                                  real_hit_item_num);
    }

next:
    if (NULL == state->rule_compile_state) {
        state->rule_compile_state = rule_compile_state_new();
        alignment_int64_array_add(state->maat_inst->stat->rule_state_cnt,
                                  state->thread_id, 1);
    }

    return rule_compile_state_update(state->rule_compile_state, state->maat_inst, attribute_name,
                                state->rule_table_id, state->Nth_scan,
                                hit_maat_items, real_hit_item_num);
}

struct expr_runtime_stream *
expr_runtime_stream_open(struct expr_runtime *expr_rt, int thread_id)
{
    if (NULL == expr_rt || thread_id < 0) {
        return NULL;
    }

    struct expr_runtime_stream *expr_rt_stream = ALLOC(struct expr_runtime_stream, 1);

    expr_rt_stream->ref_expr_rt = expr_rt;
    expr_rt_stream->handle = expr_matcher_stream_open(expr_rt->matcher, thread_id);
    if (NULL == expr_rt_stream->handle) {
        log_info(expr_rt->logger, MODULE_EXPR,
                 "[%s:%d] expr_matcher_stream_open failed, expr_rt->matcher is %p", __FUNCTION__, __LINE__, expr_rt->matcher);
    }

    return expr_rt_stream;
}

int expr_runtime_stream_scan(struct expr_runtime_stream *expr_rt_stream,
                             const char *data, size_t data_len,
                             const char *attribute_name, struct maat_state *state)
{
    struct expr_runtime *expr_rt = expr_rt_stream->ref_expr_rt;

    //clear rule_state->last_hit_object
    if (state != NULL && state->rule_compile_state != NULL) {
        rule_compile_state_clear_last_hit_object(state->rule_compile_state);
    }

    if (0 == expr_rt->rule_num) {
        //empty expr table
        return 0;
    }

    if (NULL == expr_rt_stream->handle) {
        return 0;
    }

    size_t n_hit_item = 0;
    size_t n_hit_pattern = 0;
    struct expr_scan_result hit_results[MAX_HIT_ITEM_NUM];

    int ret = expr_matcher_stream_match(expr_rt_stream->handle, data, data_len, hit_results,
                                        MAX_HIT_ITEM_NUM, &n_hit_item, &n_hit_pattern);
    if (ret < 0) {
        return -1;
    }

    if (n_hit_pattern > 0) {
        alignment_int64_array_add(expr_rt->hit_pattern_num, state->thread_id,
                                  n_hit_pattern);
    }

    struct maat_item hit_maat_items[n_hit_item];
    struct expr_item *expr_item = NULL;
    size_t real_hit_item_cnt = 0;

    if (0 == n_hit_item) {
        goto next;
    }

    for (size_t i = 0; i < n_hit_item; i++) {
        expr_item = (struct expr_item *)rcu_hash_find(expr_rt->item_hash,
                                                      (char *)&hit_results[i].rule_uuid,
                                                      sizeof(uuid_t));
        if (!expr_item) {
            // item config has been deleted
            continue;
        }

        uuid_copy(hit_maat_items[real_hit_item_cnt].item_uuid, expr_item->item_uuid);
        uuid_copy(hit_maat_items[real_hit_item_cnt].object_uuid, expr_item->object_uuid);
        real_hit_item_cnt++;
    }

    if (real_hit_item_cnt > 0) {
        alignment_int64_array_add(expr_rt->hit_item_num, state->thread_id,
                                  real_hit_item_cnt);
    }

next:
    if (NULL == state->rule_compile_state) {
        state->rule_compile_state = rule_compile_state_new();
        alignment_int64_array_add(state->maat_inst->stat->rule_state_cnt,
                                  state->thread_id, 1);
    }

    return rule_compile_state_update(state->rule_compile_state, state->maat_inst, attribute_name,
                                state->rule_table_id, state->Nth_scan,
                                hit_maat_items, real_hit_item_cnt);
}

void expr_runtime_stream_close(struct expr_runtime_stream *expr_rt_stream)
{
    if (NULL == expr_rt_stream) {
        return;
    }

    expr_rt_stream->ref_expr_rt = NULL;
    if (expr_rt_stream->handle != NULL) {
        expr_matcher_stream_close(expr_rt_stream->handle);
    }

    FREE(expr_rt_stream);
}

void expr_runtime_perf_stat(struct expr_runtime *expr_rt, size_t scan_len, 
                            struct timespec *start, struct timespec *end, 
                            int thread_id)
{
    if (NULL == expr_rt || thread_id < 0) {
        return;
    }

    if (start != NULL && end != NULL) {
        long long consume_time = (end->tv_sec - start->tv_sec) * 1000000000 +
                                 (end->tv_nsec - start->tv_nsec);
        alignment_int64_array_add(expr_rt->scan_cpu_time, thread_id, consume_time);
    }
}

void expr_runtime_scan_bytes_add(struct expr_runtime *expr_rt, int thread_id,
                                 size_t scan_len)
{
    if (NULL == expr_rt || thread_id < 0 || 0 == scan_len) {
        return;
    }

    alignment_int64_array_add(expr_rt->scan_bytes, thread_id, scan_len);
}

long long expr_runtime_scan_bytes(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return 0;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    long long sum = alignment_int64_array_sum(expr_rt->scan_bytes, 
                                              expr_rt->n_worker_thread);
    alignment_int64_array_reset(expr_rt->scan_bytes, expr_rt->n_worker_thread);

    return sum;
}

void expr_runtime_scan_times_inc(struct expr_runtime *expr_rt, int thread_id)
{
    if (NULL == expr_rt || thread_id < 0) {
        return;
    } 

    alignment_int64_array_add(expr_rt->scan_times, thread_id, 1);
}

long long expr_runtime_scan_times(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return 0;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    long long sum = alignment_int64_array_sum(expr_rt->scan_times, 
                                              expr_rt->n_worker_thread);
    alignment_int64_array_reset(expr_rt->scan_times, expr_rt->n_worker_thread);

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

void expr_runtime_stream_scan_times_inc(struct expr_runtime_stream *expr_rt_stream,
                                        int thread_id)
{
    if (NULL == expr_rt_stream || thread_id < 0) {
        return;
    }

    struct expr_runtime *expr_rt = expr_rt_stream->ref_expr_rt;
    alignment_int64_array_add(expr_rt->scan_times, thread_id, 1);
}

void expr_runtime_stream_scan_bytes_add(struct expr_runtime_stream *expr_rt_stream,
                                        int thread_id, size_t scan_len)
{
     if (NULL == expr_rt_stream || thread_id < 0) {
        return;
    }

     struct expr_runtime *expr_rt = expr_rt_stream->ref_expr_rt;
    alignment_int64_array_add(expr_rt->scan_bytes, thread_id, scan_len);
}

void expr_runtime_hit_times_inc(struct expr_runtime *expr_rt, int thread_id)
{
    if (NULL == expr_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(expr_rt->hit_times, thread_id, 1);
}

void expr_runtime_stream_hit_times_inc(struct expr_runtime_stream *expr_rt_stream,
                                       int thread_id)
{
    if (NULL == expr_rt_stream || thread_id < 0) {
        return;
    }

    struct expr_runtime *expr_rt = expr_rt_stream->ref_expr_rt;
    alignment_int64_array_add(expr_rt->hit_times, thread_id, 1);
}

long long expr_runtime_hit_times(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return 0;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    long long sum = alignment_int64_array_sum(expr_rt->hit_times, 
                                              expr_rt->n_worker_thread);
    alignment_int64_array_reset(expr_rt->hit_times,
                                expr_rt->n_worker_thread);

    return sum;
}

long long expr_runtime_hit_item_num(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return 0;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    long long sum = alignment_int64_array_sum(expr_rt->hit_item_num, 
                                              expr_rt->n_worker_thread);
    alignment_int64_array_reset(expr_rt->hit_item_num, expr_rt->n_worker_thread);

    return sum;
}

long long expr_runtime_hit_pattern_num(void *expr_runtime)
{
    if (NULL == expr_runtime) {
        return 0;
    }

    struct expr_runtime *expr_rt = (struct expr_runtime *)expr_runtime;
    long long sum = alignment_int64_array_sum(expr_rt->hit_pattern_num, 
                                              expr_rt->n_worker_thread);
    alignment_int64_array_reset(expr_rt->hit_pattern_num,
                                expr_rt->n_worker_thread);

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