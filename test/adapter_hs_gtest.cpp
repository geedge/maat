#include <gtest/gtest.h>

#include "log/log.h"
#include "adapter_hs.h"
#include "maat_utils.h"

struct log_handle *g_logger = NULL;

int parse_and_expr_file(const char *filename, and_expr_t expr[], size_t *n_expr)
{
    FILE *fp = fopen(filename, "r");

    char line[4096] = {0};
    size_t i = 0;
    while (NULL != fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == ' ' || line[0] == '\t') {
            memset(line, 0, sizeof(line));
            continue;
        }

        char pattern_buf[1024] = {0};
        int ret = sscanf(line, "%u\t%lu\t%s", &(expr[i].expr_id), &(expr[i].n_patterns), pattern_buf);
        EXPECT_NE(ret, 0);

        str_unescape(pattern_buf);
        char *expr_token = NULL;
        char *sub_expr_token = NULL;
        char *save_expr_ptr = NULL;
        size_t j = 0;
        for (expr_token = pattern_buf; ; expr_token = NULL) {
            sub_expr_token = strtok_r(expr_token, "&", &save_expr_ptr);
            if (sub_expr_token == NULL) {
                break;
            }

            char *pattern_token = sub_expr_token;
            char *save_pattern_ptr = NULL;
            char *sub_pattern_token = strtok_r(pattern_token, ":", &save_pattern_ptr);
            expr[i].patterns[j].type = atoi(sub_pattern_token);
            size_t str_len = strlen(save_pattern_ptr);
            expr[i].patterns[j].pat = (char *)calloc(sizeof(char), str_len);
            memcpy(expr[i].patterns[j].pat, save_pattern_ptr, str_len);
            expr[i].patterns[j].pat_len = str_len;
            j++;
        }
        i++;
        memset(line, 0, sizeof(line));
    }
    *n_expr = i;
    fclose(fp);

    return 0;
}

void expr_array_free(and_expr_t expr_array[], size_t n_expr_array)
{
    for (size_t i = 0; i < n_expr_array; i++) {
        for (size_t j = 0; j < expr_array[i].n_patterns; j++) {
            free(expr_array[i].patterns[j].pat);
            expr_array[i].patterns[j].pat = NULL;
        }
    }
}

TEST(block_mode_initialize, invalid_input_parameter)
{
    struct adapter_hs *hs_instance = NULL;
    and_expr_t exprs[64];

    /* case1: invalid scan_mode parameter */
    hs_instance = adapter_hs_initialize(0, 1, exprs, 1, g_logger);
    EXPECT_EQ(hs_instance, nullptr);

    /* case2: invalid expr parameter */
    hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, nullptr, 1, g_logger);
    EXPECT_EQ(hs_instance, nullptr);

    /* case3: invalid expr num */
    hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, exprs, 0, g_logger);
    EXPECT_EQ(hs_instance, nullptr);
}

TEST(block_mode_scan, invalid_input_parameter)
{
    and_expr_t expr_array[64];
    size_t n_expr_array = 0;

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, nullptr, 0, g_logger);
    EXPECT_EQ(hs_instance, nullptr);

    hs_instance = adapter_hs_initialize(0, 1, expr_array, n_expr_array, g_logger);
    EXPECT_EQ(hs_instance, nullptr);

    n_expr_array = 1;
    expr_array[0].expr_id = 101;
    expr_array[0].n_patterns = 10;
    hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, expr_array, n_expr_array, g_logger);
    EXPECT_EQ(hs_instance, nullptr);

    memset(expr_array, 0, sizeof(expr_array));
    n_expr_array = 1;
    expr_array[0].expr_id = 101;
    expr_array[0].n_patterns = 1;
    expr_array[0].patterns[0].type = 0;
    hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, expr_array, n_expr_array, g_logger);
    EXPECT_EQ(hs_instance, nullptr);
}

TEST(block_mode_scan, literal_hit1)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_and_expr_file("./and_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_expr_array, 10);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, nullptr);
    expr_array_free(expr_array, n_expr_array);

    char data0[64] = "luis";
    struct hs_scan_result result0[64] = {0};
    size_t n_result0 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data0, strlen(data0), result0, 64, &n_result0);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result0, 0);

    char data1[64] = "hello";
    struct hs_scan_result result1[64] = {0};
    size_t n_result1 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data1, strlen(data1), result1, 64, &n_result1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result1, 1);
    EXPECT_EQ(result1[0].item_id, 101);

    char data2[64] = "world";
    struct hs_scan_result result2[64] = {0};
    size_t n_result2 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data2, strlen(data2), result2, 64, &n_result2);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result2, 1);
    EXPECT_EQ(result2[0].item_id, 102);
    
    adapter_hs_destroy(hs_instance);
    hs_instance = nullptr;
}

TEST(block_mode_scan, literal_hit2)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_and_expr_file("./and_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, nullptr);
    expr_array_free(expr_array, n_expr_array);

    char data0[64] = "hello maat";
    struct hs_scan_result result0[64] = {0};
    size_t n_result0 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data0, strlen(data0), result0, 64, &n_result0);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result0, 2);
    EXPECT_EQ(result0[0].item_id, 103);
    EXPECT_EQ(result0[1].item_id, 101);

    char data1[64] = "maat World";
    struct hs_scan_result result1[64] = {0};
    size_t n_result1 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data1, strlen(data1), result1, 64, &n_result1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result1, 2);
    EXPECT_EQ(result1[0].item_id, 103);
    EXPECT_EQ(result1[1].item_id, 102);

    adapter_hs_destroy(hs_instance);
    hs_instance = nullptr;
}

TEST(block_mode_scan, literal_hit3)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_and_expr_file("./and_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, nullptr);
    expr_array_free(expr_array, n_expr_array);

    char data0[64] = "hello world";
    struct hs_scan_result result0[64] = {0};
    size_t n_result0 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data0, strlen(data0), result0, 64, &n_result0);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result0, 3);
    EXPECT_EQ(result0[0].item_id, 104);
    EXPECT_EQ(result0[1].item_id, 102);
    EXPECT_EQ(result0[2].item_id, 101);

    char data1[64] = "hello World";
    struct hs_scan_result result1[64] = {0};
    size_t n_result1 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data1, strlen(data1), result1, 64, &n_result1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result1, 2);
    EXPECT_EQ(result1[0].item_id, 102);
    EXPECT_EQ(result1[1].item_id, 101);

    adapter_hs_destroy(hs_instance);
    hs_instance = nullptr;
}

TEST(block_mode_scan, literal_russian_hit3)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_and_expr_file("./and_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, nullptr);
    expr_array_free(expr_array, n_expr_array);

    char data0[64] = "يىلىدىكى";
    struct hs_scan_result result0[64] = {0};
    size_t n_result0 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data0, strlen(data0), result0, 64, &n_result0);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result0, 1);
    EXPECT_EQ(result0[0].item_id, 109);
   
    adapter_hs_destroy(hs_instance);
    hs_instance = nullptr;
}

TEST(block_mode_scan, literal_case_insensitive_hit4)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_and_expr_file("./and_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, nullptr);
    expr_array_free(expr_array, n_expr_array);

    char data0[64] = "today";
    struct hs_scan_result result[64] = {0};
    size_t n_result = 0;
    ret = adapter_hs_scan(hs_instance, 0, data0, strlen(data0), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    char data1[64] = "Today";
    n_result = 0;
    memset(result, 0, sizeof(result));
    ret = adapter_hs_scan(hs_instance, 0, data1, strlen(data1), result, 64, &n_result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(result[0].item_id, 110);

    adapter_hs_destroy(hs_instance);
    hs_instance = nullptr;
}

TEST(block_mode_scan, literal_and_regex1)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_and_expr_file("./and_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, 
                                                            expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, nullptr);
    expr_array_free(expr_array, n_expr_array);

    char data0[64] = "1hello world";
    struct hs_scan_result result0[64] = {0};
    size_t n_result0 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data0, strlen(data0), result0, 64, &n_result0);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result0, 4);
    EXPECT_EQ(result0[0].item_id, 105);
    EXPECT_EQ(result0[1].item_id, 104);
    EXPECT_EQ(result0[2].item_id, 102);
    EXPECT_EQ(result0[3].item_id, 101);

    char data1[64] = "8hello World";
    struct hs_scan_result result1[64] = {0};
    size_t n_result1 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data1, strlen(data1), result1, 64, &n_result1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result1, 2);
    EXPECT_EQ(result1[0].item_id, 102);
    EXPECT_EQ(result1[1].item_id, 101);

    adapter_hs_destroy(hs_instance);
    hs_instance = nullptr;
}

TEST(block_mode_scan, literal_and_regex2)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_and_expr_file("./and_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, nullptr);
    expr_array_free(expr_array, n_expr_array);

    char data0[64] = "1hello 2world";
    struct hs_scan_result result0[64] = {0};
    size_t n_result0 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data0, strlen(data0), result0, 64, &n_result0);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result0, 5);
    EXPECT_EQ(result0[0].item_id, 106);
    EXPECT_EQ(result0[1].item_id, 105);
    EXPECT_EQ(result0[2].item_id, 104);
    EXPECT_EQ(result0[3].item_id, 102);
    EXPECT_EQ(result0[4].item_id, 101);

    char data1[64] = "8hello 9World";
    struct hs_scan_result result1[64] = {0};
    size_t n_result1 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data1, strlen(data1), result1, 64, &n_result1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result1, 2);
    EXPECT_EQ(result1[0].item_id, 102);
    EXPECT_EQ(result1[1].item_id, 101);

    adapter_hs_destroy(hs_instance);
    hs_instance = nullptr;
}

TEST(block_mode_scan, regex_hit1)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_and_expr_file("./and_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, nullptr);
    expr_array_free(expr_array, n_expr_array);

    char data0[64] = "Cookie: Txa123aheadBCAxd";
    struct hs_scan_result result0[64] = {0};
    size_t n_result0 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data0, strlen(data0), result0, 64, &n_result0);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result0, 1);
    EXPECT_EQ(result0[0].item_id, 107);

    adapter_hs_destroy(hs_instance);
    hs_instance = nullptr;
}

TEST(block_mode_scan, chinese_hit1)
{
    and_expr_t expr_array[64] = {0};
    size_t n_expr_array = 0;
    
    int ret = parse_and_expr_file("./and_expr.conf", expr_array, &n_expr_array);
    EXPECT_EQ(ret, 0);

    struct adapter_hs *hs_instance = adapter_hs_initialize(HS_SCAN_MODE_BLOCK, 1, 
                                                           expr_array, n_expr_array, g_logger);
    EXPECT_NE(hs_instance, nullptr);
    expr_array_free(expr_array, n_expr_array);

    char data0[64] = "中国 你好";
    struct hs_scan_result result0[64] = {0};
    size_t n_result0 = 0;
    ret = adapter_hs_scan(hs_instance, 0, data0, strlen(data0), result0, 64, &n_result0);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result0, 1);
    EXPECT_EQ(result0[0].item_id, 108);

    adapter_hs_destroy(hs_instance);
    hs_instance = nullptr;
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
