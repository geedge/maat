#include <gtest/gtest.h>

#include "maat/maat.h"
#include "maat_rule.h"
#include "maat_utils.h"
#include "maat_table_schema.h"
#include "maat_table_runtime.h"
#include "maat_command.h"

struct maat *g_maat_instance = NULL;
const char *table_info_path = "./table_info.conf";
const char *rule_full_path = "./rule/full/index";
const char *rule_inc_path = "./rule/inc/index";
const char *json_path="./maat_json.json";
const char *iris_file = "./HTTP_URL.000001";

TEST(maat_scan_string, hit_one_expr) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
    char data[64] = "";
    int result_array[5] = {0};
    size_t n_result_array = 0;
	int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, -1);
 
    char data1[64] = "baidu.com";
    ret = maat_scan_string(g_maat_instance, table_id, 0, data1, strlen(data1), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 0);

    char data2[64] = "hello";
    ret = maat_scan_string(g_maat_instance, table_id, 0, data2, strlen(data2), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 1);
    EXPECT_EQ(result_array[0], 101);

/*
    memset(result_array, 0, sizeof(result_array));
    char data3[64] = "maat";
    ret = maat_scan_string(g_maat_instance, table_id, 0, data3, strlen(data3), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 1);
    EXPECT_EQ(result_array[0], 102); */

/*
    memset(result_array, 0, sizeof(result_array));
    char data4[64] = "world";
    ret = maat_scan_string(g_maat_instance, table_id, 0, data4, strlen(data4), result_array, &n_result_array, NULL);
    EXPECT_EQ(n_result_array, 1);
    EXPECT_EQ(result_array[0], 103); */
}
#if 0
TEST(maat_scan_string, hit_two_expr) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
    char data[64] = "hello maat";
    int result_array[5] = {0};
    size_t n_result_array = 0;
	int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 2);
    EXPECT_EQ(result_array[0], 102);
    EXPECT_EQ(result_array[1], 101);

    memset(result_array, 0, sizeof(result_array));
    char data1[64] = "maat world";
    ret = maat_scan_string(g_maat_instance, table_id, 0, data1, strlen(data1), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 2);
    EXPECT_EQ(result_array[0], 103);
    EXPECT_EQ(result_array[1], 102);
}

TEST(maat_scan_string, hit_three_expr) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
    char data[64] = "hello world";
    int result_array[5] = {0};
    size_t n_result_array = 0;
	int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 3);
    EXPECT_EQ(result_array[0], 104);
    EXPECT_EQ(result_array[1], 103);
    EXPECT_EQ(result_array[2], 101);
}

TEST(maat_scan_string, hit_four_expr) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
    char data[64] = "9hello world";
    int result_array[5] = {0};
    size_t n_result_array = 0;
	int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 4);
    EXPECT_EQ(result_array[0], 105);
    EXPECT_EQ(result_array[1], 104);
    EXPECT_EQ(result_array[2], 103);
    EXPECT_EQ(result_array[3], 101);
}

TEST(maat_scan_string, hit_five_expr) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
    char data[64] = "9hello 8world";
    int result_array[5] = {0};
    size_t n_result_array = 0;
	int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 5);
    EXPECT_EQ(result_array[0], 106);
    EXPECT_EQ(result_array[1], 105);
    EXPECT_EQ(result_array[2], 104);
    EXPECT_EQ(result_array[3], 103);
    EXPECT_EQ(result_array[4], 101);
}

TEST(maat_scan_string, config_dynamic_update) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
   
    char data[128] = "www.baidu.com";
    int result_array[5] = {0};
    size_t n_result_array = 0;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 0);

    /* generate inc update config */
    system_cmd_mkdir("./rule/inc/index");
    char new_rule[128] = "207 7   baidu  0  0  0  1";
 
    FILE *fp = fopen("./rule/inc/HTTP_URL.000002", "w+");
    EXPECT_NE(fp, nullptr);
    fprintf(fp, "%s\n", "0000000001");
    fprintf(fp, "%s\n", new_rule);
    fclose(fp);

    char new_rule_idx[128] = "HTTP_URL	1	./rule/inc/HTTP_URL.000002";
    fp = fopen("./rule/inc/index/inc_config_index.000002", "w+");
    EXPECT_NE(fp, nullptr);
    fprintf(fp, "%s\n", new_rule_idx);
    fclose(fp);

    /* if updated rule already valid */
    memset(result_array, 0, sizeof(result_array));
    sleep(2);
    ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 1);
    EXPECT_EQ(result_array[0], 207);

    /* if the old rules are still valid */
    memset(result_array, 0, sizeof(result_array));
    char data1[64] = "9hello 8world";
	ret = maat_scan_string(g_maat_instance, table_id, 0, data1, strlen(data1), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 5);
    EXPECT_EQ(result_array[0], 106);
    EXPECT_EQ(result_array[1], 105);
    EXPECT_EQ(result_array[2], 104);
    EXPECT_EQ(result_array[3], 103);
    EXPECT_EQ(result_array[4], 101);
}


TEST(maat_scan_string, hit_one_expr) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
   
    char data[128] = "i.ytimg.com";
    int result_array[5] = {0};
    size_t n_result_array = 0;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 1);
    EXPECT_EQ(result_array[0], 30);
}

TEST(maat_scan_string, hit_two_expr) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
   
    char data[128] = "should hit aaa bbb";
    int result_array[5] = {0};
    size_t n_result_array = 0;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 2);
    EXPECT_EQ(result_array[0], 28);
    EXPECT_EQ(result_array[1], 27);
}

TEST(maat_scan_string, hit_three_expr) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
   
    char data[128] = "should hit aaa bbb C#中国";
    int result_array[5] = {0};
    size_t n_result_array = 0;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 3);
    EXPECT_EQ(result_array[0], 28);
    EXPECT_EQ(result_array[1], 27);
    EXPECT_EQ(result_array[2], 18);
}
#endif
TEST(maat_redis, write) {
    char line[1024] = {0};
    char table_name[64] = "HTTP_URL";
    struct maat_cmd_line rule_line;
    rule_line.table_name = (char *)malloc(sizeof(char) * 64);

    memcpy((void *)rule_line.table_name, table_name, strlen(table_name));
    FILE *fp = fopen(iris_file, "r");
    EXPECT_NE(fp, nullptr);

    int rule_num = 0;
    fscanf(fp, "%d\n", &rule_num);

    while (NULL != fgets(line, sizeof(line), fp)) {
        rule_line.table_line = (char *)malloc(sizeof(line));
        memcpy((void *)rule_line.table_line, line, strlen(line));
        maat_cmd_set_line(g_maat_instance, &rule_line);
        break;
    }

}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

    struct maat_options *opts = maat_options_new();
    //maat_options_set_iris_full_dir(opts, rule_full_path);
    //maat_options_set_iris_inc_dir(opts, rule_inc_path);
    maat_options_set_redis_ip(opts, "127.0.0.1");
    maat_options_set_redis_port(opts, 6379);
    //maat_options_set_json_file(opts, json_path);

    g_maat_instance = maat_new(opts, table_info_path);
    EXPECT_NE(g_maat_instance, nullptr);

	ret=RUN_ALL_TESTS();

    maat_free(g_maat_instance);
    g_maat_instance = NULL;

	return ret;
}