#include <gtest/gtest.h>

#include "log/log.h"
#include "adapter_hs.h"
#include "maat_utils.h"
#include "cJSON/cJSON.h"

struct log_handle *g_logger = NULL;

enum hs_match_mode match_method_to_match_mode(const char *method)
{
    enum hs_match_mode mode = HS_MATCH_MODE_MAX;

    if (strcmp(method, "sub") == 0) {
        mode = HS_MATCH_MODE_SUB;
    } else if (strcmp(method, "exactly") == 0) {
        mode = HS_MATCH_MODE_EXACTLY;
    } else if (strcmp(method, "prefix") == 0) {
        mode = HS_MATCH_MODE_PREFIX;
    } else if (strcmp(method, "suffix") == 0) {
        mode = HS_MATCH_MODE_SUFFIX;
    } else {
        assert(0);
    }

    return mode;
}

enum hs_case_sensitive case_sensitive_str_to_enum(const char *str)
{
    enum hs_case_sensitive case_sensitive = HS_CASE_SENSITIVE;

    if (strcmp(str, "yes") == 0) {
        case_sensitive = HS_CASE_SENSITIVE;
    } else if (strcmp(str, "no") == 0) {
        case_sensitive = HS_CASE_INSESITIVE;
    } else {
        assert(0);
    }

    return case_sensitive;
}

int is_hexbin_str_to_int(const char *str)
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

int parse_config_file(const char *filename, and_expr_t exprs[], size_t *n_expr)
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
            cJSON *item = cJSON_GetObjectItem(pat_item, "match_method");
            if (item != NULL && item->type == cJSON_String) {
                exprs[i].patterns[j].match_mode = match_method_to_match_mode(item->valuestring);
            }

            item = cJSON_GetObjectItem(pat_item, "case_sensitive");
            if (item != NULL && item->type == cJSON_String) {
                exprs[i].patterns[j].case_sensitive = case_sensitive_str_to_enum(item->valuestring);
            }

            item = cJSON_GetObjectItem(pat_item, "is_hexbin");
            if (item != NULL && item->type == cJSON_String) {
                exprs[i].patterns[j].is_hexbin = is_hexbin_str_to_int(item->valuestring);
            }

            item = cJSON_GetObjectItem(pat_item, "pattern");
            if (item != NULL && item->type == cJSON_String) {
                exprs[i].patterns[j].pat = ALLOC(char, strlen(item->valuestring));

                if (exprs[i].patterns[j].is_hexbin == 1) {
                    size_t pat_str_len = strlen(item->valuestring) + 1;
                    char *pat_str = ALLOC(char, pat_str_len);
                    pat_str_len = hex2bin(item->valuestring, strlen(item->valuestring), 
                                          pat_str, pat_str_len);
                    
                    memcpy(exprs[i].patterns[j].pat, pat_str, pat_str_len);
                    exprs[i].patterns[j].pat_len = pat_str_len;
                } else {
                    memcpy(exprs[i].patterns[j].pat, item->valuestring, 
                           strlen(item->valuestring));
                    exprs[i].patterns[j].pat_len = strlen(item->valuestring);
                }
            }

            if (exprs[i].patterns->match_mode == HS_MATCH_MODE_SUB) {
                item = cJSON_GetObjectItem(pat_item, "offset");
                if (item != NULL && item->type == cJSON_String) {
                    int key_left_offset = -1;
                    int key_right_offset = -1;
                    sscanf(item->valuestring, "%d~%d", &key_left_offset, &key_right_offset);
                    if (key_left_offset < -1 || key_right_offset < -1) {
                        printf("Error: offset should not less than -1, left_offset:%d, right_offset:%d\n",
                                key_left_offset, key_right_offset);
                    }
                    exprs[i].patterns[j].l_offset = key_left_offset;
                    exprs[i].patterns[j].r_offset = key_right_offset;
                } else {
                    exprs[i].patterns[j].l_offset = -1;
                    exprs[i].patterns[j].r_offset = -1;
                }
            }
        }
        exprs[i].n_patterns = pattern_cnt;
    }

    *n_expr = rule_cnt;
next:
    cJSON_Delete(root);
    return ret;
}

void expr_array_free(and_expr_t expr_array[], size_t n_expr_array)
{
    for (size_t i = 0; i < n_expr_array; i++) {
        for (size_t j = 0; j < expr_array[i].n_patterns; j++) {
            if (expr_array[i].patterns[j].pat != NULL) {
                free(expr_array[i].patterns[j].pat);
                expr_array[i].patterns[j].pat = NULL;
            }
        }
    }
}

TEST(block_mode_initialize, invalid_input_parameter)
{
    struct adapter_hs *hs_instance = NULL;
    and_expr_t exprs[64];

    /* case1: invalid scan_mode parameter */
    hs_instance = adapter_hs_initialize(HS_SCAN_MODE_MAX, HS_PATTERN_TYPE_REG, 
                                        1, exprs, 1, g_logger);
    EXPECT_EQ(hs_instance, NULL);

    /* case2: invalid expr parameter */
    hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_REG, 
                                        1, NULL, 1, g_logger);
    EXPECT_EQ(hs_instance, NULL);

    /* case3: invalid expr num */
    hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_REG, 
                                        1, exprs, 0, g_logger);
    EXPECT_EQ(hs_instance, NULL);
}

TEST(block_mode_scan, invalid_input_parameter)
{
    and_expr_t expr_array[64];
    size_t n_expr_array = 0;

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_REG, 
                                                           1, NULL, 0, g_logger);
    EXPECT_EQ(hs_instance, NULL);

    hs_instance = adapter_hs_initialize(HS_SCAN_MODE_MAX, HS_PATTERN_TYPE_REG, 1, expr_array, 
                                        n_expr_array, g_logger);
    EXPECT_EQ(hs_instance, NULL);

    n_expr_array = 1;
    expr_array[0].expr_id = 101;
    expr_array[0].n_patterns = 10;
    hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_REG, 1, expr_array, 
                                        n_expr_array, g_logger);
    EXPECT_EQ(hs_instance, NULL);

    memset(expr_array, 0, sizeof(expr_array));
    n_expr_array = 1;
    expr_array[0].expr_id = 101;
    expr_array[0].n_patterns = 1;
    hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_REG, 1, expr_array, 
                                        n_expr_array, g_logger);
    EXPECT_EQ(hs_instance, NULL);
}

TEST(block_mode_scan, literal_sub_has_normal_offset)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;

    int ret = parse_config_file("./literal_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_expr_array, 11);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_STR, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, NULL);
    expr_array_free(expr_array, n_expr_array);

    char scan_data1[64] = "hello aaa";
    struct hs_scan_result result[64] = {0};
    size_t n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data1, strlen(scan_data1), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    char scan_data2[64] = "Ahello aaa";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data2, strlen(scan_data2), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 101);
    
    char scan_data3[64] = "Aahello aaa";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data3, strlen(scan_data3), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    adapter_hs_destroy(hs_instance);
    hs_instance = NULL;
}

TEST(block_mode_scan, literal_sub_has_left_unlimit_offset)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;

    int ret = parse_config_file("./literal_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_STR, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, NULL);
    expr_array_free(expr_array, n_expr_array);

    char scan_data1[64] = "hello bbb";
    struct hs_scan_result result[64] = {0};
    size_t n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data1, strlen(scan_data1), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 102);

    char scan_data2[64] = "Ahello bbb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data2, strlen(scan_data2), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 102);

    char scan_data3[64] = "Aahello bbb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data3, strlen(scan_data3), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    adapter_hs_destroy(hs_instance);
    hs_instance = NULL;
}

TEST(block_mode_scan, literal_sub_has_right_unlimit_offset)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;

    int ret = parse_config_file("./literal_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_STR, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, NULL);
    expr_array_free(expr_array, n_expr_array);

    char scan_data1[64] = "hello ccc";
    struct hs_scan_result result[64] = {0};
    size_t n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data1, strlen(scan_data1), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    char scan_data2[64] = "1234hello ccc";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data2, strlen(scan_data2), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    char scan_data3[64] = "12345hello ccc";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data3, strlen(scan_data3), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 103);

    char scan_data4[64] = "12345hello cccAaBb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data4, strlen(scan_data4), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 103);

    char scan_data5[64] = "123456hello cccAaBb";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data5, strlen(scan_data5), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 103);

    adapter_hs_destroy(hs_instance);
    hs_instance = NULL;
}

TEST(block_mode_scan, literal_sub_with_no_offset)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_config_file("./literal_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_STR, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, NULL);
    expr_array_free(expr_array, n_expr_array);

    char scan_data1[64] = "hello ddd";
    struct hs_scan_result result[64] = {0};
    size_t n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data1, strlen(scan_data1), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 104);

    char scan_data2[64] = "123hello ddd";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data2, strlen(scan_data2), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 104);

    char scan_data3[64] = "123hello ddd456";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data3, strlen(scan_data3), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 104);

    char scan_data4[64] = "helloddd";
    memset(result, 0, sizeof(result));
    n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data4, strlen(scan_data4), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    adapter_hs_destroy(hs_instance);
    hs_instance = NULL;
}

TEST(block_mode_scan, literal_exactly)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_config_file("./literal_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_STR, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, NULL);
    expr_array_free(expr_array, n_expr_array);

    char scan_data1[64] = "hello eee";
    struct hs_scan_result result[64] = {0};
    size_t n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data1, strlen(scan_data1), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 105);

    char scan_data2[64] = "Ahello eee";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data2, strlen(scan_data2), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    char scan_data3[64] = "hello eeeB";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data3, strlen(scan_data3), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    adapter_hs_destroy(hs_instance);
    hs_instance = NULL;
}

TEST(block_mode_scan, literal_prefix)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_config_file("./literal_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_STR, 1, 
                                                            expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, NULL);
    expr_array_free(expr_array, n_expr_array);

    char scan_data1[64] = "hello fff";
    struct hs_scan_result result[64] = {0};
    size_t n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data1, strlen(scan_data1), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 106);

    char scan_data2[64] = "Ahello fff";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data2, strlen(scan_data2), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    char scan_data3[64] = "Ahello fffBCD";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data3, strlen(scan_data3), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    char scan_data4[64] = "hello fffBCD";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data4, strlen(scan_data4), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 106);

    adapter_hs_destroy(hs_instance);
    hs_instance = NULL;
}

TEST(block_mode_scan, literal_suffix)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_config_file("./literal_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_STR, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, NULL);
    expr_array_free(expr_array, n_expr_array);

    char scan_data1[64] = "hello ggg";
    struct hs_scan_result result[64] = {0};
    size_t n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data1, strlen(scan_data1), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 107);

    char scan_data2[64] = "ABChello ggg";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data2, strlen(scan_data2), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 107);

    char scan_data3[64] = "ABChello gggDEF";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data3, strlen(scan_data3), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    char scan_data4[64] = "hello gggDEF";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data4, strlen(scan_data4), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    adapter_hs_destroy(hs_instance);
    hs_instance = NULL;
}

TEST(block_mode_scan, literal_sub_with_hexbin)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_config_file("./literal_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_STR, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, NULL);
    expr_array_free(expr_array, n_expr_array);

    char scan_data1[64] = "Content-Type: /html";
    struct hs_scan_result result[64] = {0};
    size_t n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, scan_data1, strlen(scan_data1), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 108);

    char scan_data2[64] = " html";
    memset(result, 0, sizeof(result));
    n_result = 0;

    ret = adapter_hs_scan(hs_instance, 0, scan_data2, strlen(scan_data2), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    adapter_hs_destroy(hs_instance);
    hs_instance = NULL;
}

TEST(block_mode_scan, literal_with_chinese)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_config_file("./literal_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, HS_PATTERN_TYPE_STR, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, NULL);
    expr_array_free(expr_array, n_expr_array);

    char data0[64] = "#中国 你好";
    struct hs_scan_result result0[64] = {0};
    size_t n_result0 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data0, strlen(data0), result0, 64, &n_result0);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result0, 1);
    EXPECT_EQ(result0[0].item_id, 110);

    adapter_hs_destroy(hs_instance);
    hs_instance = NULL;
}

int main(int argc, char **argv)
{
    int ret = 0;
    ::testing::InitGoogleTest(&argc, argv);
    g_logger = log_handle_create("./tmp.log", 0);

    ret = RUN_ALL_TESTS();

    log_handle_destroy(g_logger);

    return ret;
}
