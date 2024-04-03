#include <gtest/gtest.h>

#include "log/log.h"
#include "adapter_hs.h"
#include "maat_utils.h"
#include "cJSON/cJSON.h"

struct log_handle *g_logger = NULL;

enum expr_match_mode match_method_to_match_mode(const char *method)
{
    enum expr_match_mode mode = EXPR_MATCH_MODE_INVALID;

    if (strcmp(method, "sub") == 0) {
        mode = EXPR_MATCH_MODE_SUB;
    } else if (strcmp(method, "exactly") == 0) {
        mode = EXPR_MATCH_MODE_EXACTLY;
    } else if (strcmp(method, "prefix") == 0) {
        mode = EXPR_MATCH_MODE_PREFIX;
    } else if (strcmp(method, "suffix") == 0) {
        mode = EXPR_MATCH_MODE_SUFFIX;
    } else {
        assert(0);
    }

    return mode;
}

enum expr_case_sensitive case_sensitive_str_to_enum(const char *str)
{
    enum expr_case_sensitive case_sensitive = EXPR_CASE_SENSITIVE;

    if (strcmp(str, "yes") == 0) {
        case_sensitive = EXPR_CASE_SENSITIVE;
    } else if (strcmp(str, "no") == 0) {
        case_sensitive = EXPR_CASE_INSENSITIVE;
    } else {
        assert(0);
    }

    return case_sensitive;
}

static int is_hexbin_str_to_int(const char *str)
{
    int ret = 0;

    if (strcmp(str, "yes") == 0) {
        ret = 1;
    }

    return ret;
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

enum expr_pattern_type pattern_type_str_to_enum(const char *str)
{
    enum expr_pattern_type pattern_type = EXPR_PATTERN_TYPE_STR;

    if (strcmp(str, "regex") == 0) {
        pattern_type = EXPR_PATTERN_TYPE_REG;
    } else if (strcmp(str, "literal") == 0) {
        pattern_type = EXPR_PATTERN_TYPE_STR;
    } else {
        assert(0);
    }

    return pattern_type;
}

static int
parse_config_file(const char *filename, struct expr_rule exprs[], size_t *n_expr)
{
    unsigned char *json_buff = NULL;
    size_t json_buff_size = 0;
    
    int ret = load_file_to_memory(filename, &json_buff, &json_buff_size);
    if (ret < 0) {
        printf("load file:%s to memory failed.\n", filename);
        return -1;
    }

    size_t rule_cnt = 0;
    cJSON *rules_obj = NULL;
    cJSON *root = cJSON_Parse((const char *)json_buff);
    if (NULL == root) {
        printf("Error before: %-200.200s\n", cJSON_GetErrorPtr());
        ret = -1;
        goto next;
    }

    rules_obj = cJSON_GetObjectItem(root, "expr_rules");
    if (NULL == rules_obj) {
        printf("Error before: %-200.200s\n", cJSON_GetErrorPtr());
        ret = -1;
        goto next;
    }

    rule_cnt = cJSON_GetArraySize(rules_obj);
    for (size_t i = 0; i < rule_cnt; i++) {
        cJSON *expr_obj = cJSON_GetArrayItem(rules_obj, i);
        cJSON *tmp_item = cJSON_GetObjectItem(expr_obj, "expr_id");
        if (tmp_item != NULL && tmp_item->type == cJSON_Number) {
            exprs[i].expr_id = tmp_item->valueint;
        }

        tmp_item = cJSON_GetObjectItem(expr_obj, "pattern_num");
        if (tmp_item != NULL && tmp_item->type == cJSON_Number) {
            exprs[i].n_patterns = tmp_item->valueint;
        }

        tmp_item = cJSON_GetObjectItem(expr_obj, "patterns");
        if (NULL == tmp_item || tmp_item->type != cJSON_Array) {
            printf("json has no patterns array.\n");
            ret = -1;
            goto next;
        }

        size_t pattern_cnt = cJSON_GetArraySize(tmp_item);
        for (size_t j = 0; j < pattern_cnt; j++) {
            cJSON *pat_item = cJSON_GetArrayItem(tmp_item, j);

            cJSON *item = cJSON_GetObjectItem(pat_item, "pattern_type");
            if (item != NULL && item->type == cJSON_String) {
                exprs[i].patterns[j].type =
                    pattern_type_str_to_enum(item->valuestring);
            }

            item = cJSON_GetObjectItem(pat_item, "match_method");
            if (item != NULL && item->type == cJSON_String) {
                exprs[i].patterns[j].match_mode =
                    match_method_to_match_mode(item->valuestring);
            }

            item = cJSON_GetObjectItem(pat_item, "case_sensitive");
            if (item != NULL && item->type == cJSON_String) {
                exprs[i].patterns[j].case_sensitive =
                    case_sensitive_str_to_enum(item->valuestring);
            }

            int is_hexbin = 0;
            item = cJSON_GetObjectItem(pat_item, "is_hexbin");
            if (item != NULL && item->type == cJSON_String) {
                is_hexbin = is_hexbin_str_to_int(item->valuestring);
            }

            item = cJSON_GetObjectItem(pat_item, "pattern");
            if (item != NULL && item->type == cJSON_String) {
                exprs[i].patterns[j].pat = ALLOC(char, strlen(item->valuestring) + 1);

                if (is_hexbin == 1) {
                    size_t pat_str_len = strlen(item->valuestring);
                    char *pat_str = ALLOC(char, pat_str_len + 1);
                    pat_str_len = hex2bin(item->valuestring, strlen(item->valuestring), 
                                          pat_str, pat_str_len);
                    
                    memcpy(exprs[i].patterns[j].pat, pat_str, pat_str_len);
                    free(pat_str);
                    exprs[i].patterns[j].pat_len = pat_str_len;
                } else {
                    memcpy(exprs[i].patterns[j].pat, item->valuestring, 
                           strlen(item->valuestring));
                    exprs[i].patterns[j].pat_len = strlen(item->valuestring);
                }
            }

            if (exprs[i].patterns->match_mode == EXPR_MATCH_MODE_SUB) {
                item = cJSON_GetObjectItem(pat_item, "offset");
                if (item != NULL && item->type == cJSON_String) {
                    int key_left_offset = -1;
                    int key_right_offset = -1;
                    sscanf(item->valuestring, "%d~%d", &key_left_offset,
                           &key_right_offset);
                    if (key_left_offset < -1 || key_right_offset < -1) {
                        printf("Error: offset should not less than -1, "
                               "left_offset:%d, right_offset:%d\n",
                                key_left_offset, key_right_offset);
                    }
                    exprs[i].patterns[j].start_offset = key_left_offset;
                    exprs[i].patterns[j].end_offset = key_right_offset;
                } else {
                    exprs[i].patterns[j].start_offset = -1;
                    exprs[i].patterns[j].end_offset = -1;
                }
            }

            if (exprs[i].patterns->match_mode == EXPR_MATCH_MODE_EXACTLY) {
                exprs[i].patterns[j].start_offset = 0;
                exprs[i].patterns[j].end_offset = exprs[i].patterns[j].pat_len - 1;
            }
        }
        exprs[i].n_patterns = pattern_cnt;
    }

    *n_expr = rule_cnt;
next:
    cJSON_Delete(root);
    FREE(json_buff);
    return ret;
}

static void expr_array_free(struct expr_rule rules[], size_t n_rule)
{
    for (size_t i = 0; i < n_rule; i++) {
        for (size_t j = 0; j < rules[i].n_patterns; j++) {
            if (rules[i].patterns[j].pat != NULL) {
                free(rules[i].patterns[j].pat);
                rules[i].patterns[j].pat = NULL;
            }
        }
    }
}

TEST(hs_expr_matcher_init, invalid_input_parameter)
{
    struct expr_rule rules[64];
    size_t n_rule = 0;
    
    struct expr_matcher *matcher =
        expr_matcher_new(NULL, 0, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher == NULL);

    matcher = expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher == NULL);

    n_rule = 1;
    rules[0].expr_id = 101;
    rules[0].n_patterns = 10;
    matcher = expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher == NULL);

    memset(rules, 0, sizeof(rules));
    n_rule = 1;
    rules[0].expr_id = 101;
    rules[0].n_patterns = 1;
    matcher = expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher == NULL);
}

TEST(rs_expr_matcher_init, invalid_input_parameter)
{
    struct expr_rule rules[64];
    size_t n_rule = 0;
    
    struct expr_matcher *matcher =
        expr_matcher_new(NULL, 0, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher == NULL);

    matcher = expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher == NULL);

    n_rule = 1;
    rules[0].expr_id = 101;
    rules[0].n_patterns = 10;
    matcher = expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher == NULL);

    memset(rules, 0, sizeof(rules));
    n_rule = 1;
    rules[0].expr_id = 101;
    rules[0].n_patterns = 1;
    matcher = expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher == NULL);
}

TEST(hs_expr_matcher_match, literal_sub_has_normal_offset)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;

    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello aaa";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data2[64] = "Ahello aaa";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 101);
    
    char scan_data3[64] = "Aahello aaa";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 101);

    char scan_data4[64] = "Aaahello aaa";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(rs_expr_matcher_match, literal_sub_has_normal_offset)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;

    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello aaa";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data2[64] = "Ahello aaa";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 101);
    
    char scan_data3[64] = "Aahello aaa";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                            64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 101);

    char scan_data4[64] = "Aaahello aaa";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(hs_expr_matcher_match, literal_sub_has_left_unlimit_offset)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;

    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello bbb";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 102);

    char scan_data2[64] = "Ahello bbb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 102);

    char scan_data3[64] = "Aahello bbb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 102);

    char scan_data4[64] = "Aaahello bbb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                            64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(rs_expr_matcher_match, literal_sub_has_left_unlimit_offset)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;

    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello bbb";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 102);

    char scan_data2[64] = "Ahello bbb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                            64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 102);

    char scan_data3[64] = "Aahello bbb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 102);

    char scan_data4[64] = "Aaahello bbb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(hs_expr_matcher_match, literal_sub_has_right_unlimit_offset)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;

    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello ccc";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data2[64] = "1234hello ccc";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data3[64] = "12345hello ccc";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 103);

    char scan_data4[64] = "12345hello cccAaBb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 103);

    char scan_data5[64] = "123456hello cccAaBb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data5, strlen(scan_data5), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 103);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(rs_expr_matcher_match, literal_sub_has_right_unlimit_offset)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;

    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello ccc";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data2[64] = "1234hello ccc";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data3[64] = "12345hello ccc";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 103);

    char scan_data4[64] = "12345hello cccAaBb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 103);

    char scan_data5[64] = "123456hello cccAaBb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data5, strlen(scan_data5), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 103);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(hs_expr_matcher_match, literal_sub_with_no_offset)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello ddd";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 104);

    char scan_data2[64] = "123hello ddd";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 104);

    char scan_data3[64] = "123hello ddd456";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 104);

    char scan_data4[64] = "helloddd";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(rs_expr_matcher_match, literal_sub_with_no_offset)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello ddd";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 104);

    char scan_data2[64] = "123hello ddd";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 104);

    char scan_data3[64] = "123hello ddd456";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 104);

    char scan_data4[64] = "helloddd";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(hs_expr_matcher_match, literal_exactly)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello eee";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                            64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 105);

    char scan_data2[64] = "Ahello eee";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    char scan_data3[64] = "hello eeeB";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(rs_expr_matcher_match, literal_exactly)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello eee";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 105);

    char scan_data2[64] = "Ahello eee";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data3[64] = "hello eeeB";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(hs_expr_matcher_match, literal_prefix)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello fff";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 106);

    char scan_data2[64] = "Ahello fff";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data3[64] = "Ahello fffBCD";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data4[64] = "hello fffBCD";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 106);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(rs_expr_matcher_match, literal_prefix)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello fff";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 106);

    char scan_data2[64] = "Ahello fff";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data3[64] = "Ahello fffBCD";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data4[64] = "hello fffBCD";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 106);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(hs_expr_matcher_match, literal_suffix)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello ggg";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 107);

    char scan_data2[64] = "ABChello ggg";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                            64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 107);

    char scan_data3[64] = "ABChello gggDEF";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data4[64] = "hello gggDEF";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                            64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(rs_expr_matcher_match, literal_suffix)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "hello ggg";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                            64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 107);

    char scan_data2[64] = "ABChello ggg";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 107);

    char scan_data3[64] = "ABChello gggDEF";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data3, strlen(scan_data3), result,
                            64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    char scan_data4[64] = "hello gggDEF";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data4, strlen(scan_data4), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(hs_expr_matcher_match, literal_sub_with_hex)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "Content-Type: /html";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1);
    EXPECT_EQ(result[0].rule_id, 108);

    char scan_data2[64] = " html";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0); 

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(rs_expr_matcher_match, literal_sub_with_hex)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char scan_data1[64] = "Content-Type: /html";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1); 
    EXPECT_EQ(result[0].rule_id, 108);

    char scan_data2[64] = " html";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 0); 

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(hs_expr_matcher_match, literal_with_chinese)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char data0[64] = "#中国 你好";
    struct expr_scan_result result0[64] = {0};
    size_t n_result0 = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, data0, strlen(data0), result0, 64,
                             &n_result0, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result0, 1);
    EXPECT_EQ(n_hit_pattern, 1); 
    EXPECT_EQ(result0[0].rule_id, 110);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(rs_expr_matcher_match, literal_with_chinese)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char data0[64] = "#中国 你好";
    struct expr_scan_result result0[64] = {0};
    size_t n_result0 = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, data0, strlen(data0), result0, 64,
                             &n_result0, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result0, 1);
    EXPECT_EQ(n_hit_pattern, 1); 
    EXPECT_EQ(result0[0].rule_id, 110);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(hs_expr_matcher_match, same_pattern_different_offset)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char data[64] = "onetoday,anothertoday";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, data, strlen(data), result, 64,
                             &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 3); 
    EXPECT_EQ(result[0].rule_id, 112);

    expr_matcher_free(matcher);
    matcher = NULL;                                             
}

TEST(rs_expr_matcher_match, same_pattern_different_offset)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    char data[64] = "onetoday,anothertoday";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, data, strlen(data), result, 64,
                             &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 3); 
    EXPECT_EQ(result[0].rule_id, 112);

    expr_matcher_free(matcher);
    matcher = NULL;                                             
}

TEST(hs_expr_matcher_match, long_scan_data)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    const char* scan_data = "A directed path in a directed graph is a finite or infinite\
sequence of edges which joins a sequence of distinct vertices, but with the added restriction\
that the edges be all directed in the same direction.";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data, strlen(scan_data), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 3);
    EXPECT_EQ(result[0].rule_id, 113);

    expr_matcher_free(matcher);
    matcher = NULL;                          
}

TEST(rs_expr_matcher_match, long_scan_data)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    const char* scan_data = "A directed path in a directed graph is a finite or infinite\
sequence of edges which joins a sequence of distinct vertices, but with the added restriction\
that the edges be all directed in the same direction.";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data, strlen(scan_data), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 3); 
    EXPECT_EQ(result[0].rule_id, 113);

    expr_matcher_free(matcher);
    matcher = NULL;                          
}

TEST(expr_matcher_match, regex_expression_check)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./regex_expr.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    for (size_t i = 0; i < n_rule; i++) {
        for (size_t j = 0; j < rules[i].n_patterns; j++) {
            expr_matcher_verify_regex_expression(rules[i].patterns[j].pat, g_logger);
        }
    }

    expr_array_free(rules, n_rule);
}

TEST(hs_expr_matcher_stream, basic)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    const char* scan_data1 = "A directed path in a directed graph is a finite";
    const char *scan_data2 = " or infinite sequence of edges which joins a "
                             "sequence of distinct vertices";

    struct expr_scan_result result[64] = {0};
    size_t n_hit_result = 0;
    size_t n_hit_pattern = 0;
    int thread_id = 0;

    struct expr_matcher_stream *stream =
        expr_matcher_stream_open(matcher, thread_id);
    EXPECT_TRUE(stream != NULL);

    ret = expr_matcher_stream_match(stream, scan_data1, strlen(scan_data1), result,
                                    64, &n_hit_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_hit_result, 0);
    EXPECT_EQ(n_hit_pattern, 2); 

    ret = expr_matcher_stream_match(stream, scan_data2, strlen(scan_data2), result,
                                    64, &n_hit_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(n_hit_pattern, 3); 
    EXPECT_EQ(result[0].rule_id, 113);

    expr_matcher_stream_close(stream);
    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(rs_expr_matcher_stream, basic)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    const char* scan_data1 = "A directed path in a directed graph is a finite";
    const char *scan_data2 = " or infinite sequence of edges which joins a "
                             "sequence of distinct vertices";

    struct expr_scan_result result[64] = {0};
    size_t n_hit_result = 0;
    size_t n_hit_pattern = 0;
    int thread_id = 0;

    struct expr_matcher_stream *stream = expr_matcher_stream_open(matcher, thread_id);
    EXPECT_TRUE(stream != NULL);

    ret = expr_matcher_stream_match(stream, scan_data1, strlen(scan_data1), result,
                                    64, &n_hit_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_hit_result, 0);
    EXPECT_EQ(n_hit_pattern, 2); 

    ret = expr_matcher_stream_match(stream, scan_data2, strlen(scan_data2), result,
                                    64, &n_hit_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(n_hit_pattern, 3); 
    EXPECT_EQ(result[0].rule_id, 113);

    expr_matcher_stream_close(stream);
    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(hs_expr_matcher, regex_basic)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    ret = expr_matcher_verify_regex_expression("[0-9]rain", g_logger);
    EXPECT_EQ(ret, 1);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    const char *scan_data1 = "http://www.cyberessays.com/search_results.php?"
                             "action=search&query=username,abckkk,1234567";
    //const char *scan_data2 = "8rain";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1); 
    EXPECT_EQ(result[0].rule_id, 114);

    expr_matcher_free(matcher);
    matcher = NULL;                  
}

TEST(rs_expr_matcher, regex_basic)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    ret = expr_matcher_verify_regex_expression("[0-9]rain", g_logger);
    EXPECT_EQ(ret, 1);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    const char *scan_data1 = "http://www.cyberessays.com/search_results.php?"
                             "action=search&query=username,abckkk,1234567";
    
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1); 
    EXPECT_EQ(result[0].rule_id, 114);

    expr_matcher_free(matcher);
    matcher = NULL;
}

TEST(hs_expr_matcher, regex_unicode)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    const char *scan_data = "string contains É";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data, strlen(scan_data), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1); 
    EXPECT_EQ(result[0].rule_id, 116);

    expr_matcher_free(matcher);
    matcher = NULL;                  
}

TEST(rs_expr_matcher, regex_unicode)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_RS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    const char *scan_data = "string contains É";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data, strlen(scan_data), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 1); 
    EXPECT_EQ(result[0].rule_id, 116);

    expr_matcher_free(matcher);
    matcher = NULL;                  
}

TEST(hs_expr_matcher, hit_pattern_num)
{
    struct expr_rule rules[64] = {0};
    size_t n_rule = 0;
    
    int ret = parse_config_file("./expr_matcher.conf", rules, &n_rule);
    EXPECT_EQ(ret, 0);

    struct expr_matcher *matcher =
        expr_matcher_new(rules, n_rule, EXPR_ENGINE_TYPE_HS, 1, g_logger);
    EXPECT_TRUE(matcher != NULL);
    expr_array_free(rules, n_rule);

    const char *scan_data1 = "string has one two";
    const char *scan_data2 = "string has one two three";
    struct expr_scan_result result[64] = {0};
    size_t n_result = 0;
    size_t n_hit_pattern = 0;

    ret = expr_matcher_match(matcher, 0, scan_data1, strlen(scan_data1), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
    EXPECT_EQ(n_hit_pattern, 2); 

    ret = expr_matcher_match(matcher, 0, scan_data2, strlen(scan_data2), result,
                             64, &n_result, &n_hit_pattern);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(n_hit_pattern, 3);
    EXPECT_EQ(result[0].rule_id, 115);

    expr_matcher_free(matcher);
    matcher = NULL;
}

int main(int argc, char **argv)
{
    int ret = 0;
    ::testing::InitGoogleTest(&argc, argv);
    g_logger = log_handle_create("./expr_matcher_gtest.log", 0);

    ret = RUN_ALL_TESTS();

    log_handle_destroy(g_logger);

    return ret;
}
