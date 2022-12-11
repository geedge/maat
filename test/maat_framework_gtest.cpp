#include <gtest/gtest.h>

#include "maat/maat.h"
#include "maat_rule.h"
#include "maat_utils.h"
#include "maat_table_schema.h"
#include "maat_table_runtime.h"
#include "maat_command.h"
#include "IPMatcher.h"

struct maat *g_maat_instance = NULL;
const char *table_info_path = "./table_info.conf";
const char *rule_full_path = "./rule/full/index";
const char *rule_inc_path = "./rule/inc/index";
const char *json_path="./maat_json.json";
const char *iris_file = "./HTTP_URL.000001";
#if 0
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
#endif
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

TEST(maat_scan_ipv4, hit_ip_and_port) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "IP_PLUS_CONFIG");
    char ip_str[32] = "192.168.58.19";
    uint16_t port = 20000;
    struct addr_4tuple addr;
    addr.type = IP_TYPE_V4;
    int ret = inet_pton(AF_INET, ip_str, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    addr.ipv4.sport = htons(port);

    int results[3] = {-1};
    size_t n_result = 0;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 7);

    port = 20001;
    addr.ipv4.sport = htons(port);
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
}

TEST(maat_scan_ipv4, hit_ip_and_port_range) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "IP_PLUS_CONFIG");
    char ip_str[32] = "192.168.50.24";
    uint16_t port = 1;
    struct addr_4tuple addr;
    addr.type = IP_TYPE_V4;
    int ret = inet_pton(AF_INET, ip_str, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    addr.ipv4.sport = htons(port);

    int results[3] = {-1};
    size_t n_result = 0;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 4);

    port = 40000;
    addr.ipv4.sport = htons(port);
    memset(results, 0, sizeof(results));
    n_result = 0;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 4);

    port = 40001;
    addr.ipv4.sport = htons(port);
    memset(results, 0, sizeof(results));
    n_result = 0;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
}

TEST(maat_scan_ipv4, hit_ip_range_and_port_range) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "IP_PLUS_CONFIG");
    char ip_str1[32] = "10.0.1.20";
    char ip_str2[32] = "10.0.1.25";
    char ip_str3[32] = "10.0.1.26";
    uint16_t port1 = 1;
    uint16_t port2 = 443;
    struct addr_4tuple addr;
    addr.type = IP_TYPE_V4;
    int ret = inet_pton(AF_INET, ip_str1, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    addr.ipv4.sport = htons(port1);

    int results[3] = {-1};
    size_t n_result = 0;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 8);

    ret = inet_pton(AF_INET, ip_str2, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    addr.ipv4.sport = htons(port2);
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 8);

    ret = inet_pton(AF_INET, ip_str3, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    addr.ipv4.sport = htons(port2);
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
}

TEST(maat_scan_ipv4, hit_ip_cidr_and_port_range) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "IP_PLUS_CONFIG");
    char ip_str1[32] = "192.168.0.1";
    char ip_str2[32] = "192.168.0.0";
    uint16_t port = 5210;
    struct addr_4tuple addr;
    addr.type = IP_TYPE_V4;
    int ret = inet_pton(AF_INET, ip_str1, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    addr.ipv4.sport = htons(port);

    int results[3] = {-1};
    size_t n_result = 0;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 50);

    ret = inet_pton(AF_INET, ip_str2, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
}

TEST(maat_scan_ipv4, hit_ip_cidr_and_port_mask) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "IP_PLUS_CONFIG");
    char ip_str[32] = "192.168.40.10";
    uint16_t port = 443;
    struct addr_4tuple addr;
    addr.type = IP_TYPE_V4;
    int ret = inet_pton(AF_INET, ip_str, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    addr.ipv4.sport = htons(port);

    int results[3] = {-1};
    size_t n_result = 0;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 2);
    EXPECT_EQ(results[0], 63);
    EXPECT_EQ(results[1], 67);

    port = 442;
    addr.ipv4.sport = htons(port);
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
}

TEST(maat_scan_ipv6, hit_ip_range_and_port_mask) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "IP_PLUS_CONFIG");
    char ip_str[32] = "1001:da8:205:1::101";
    uint16_t port = 5210;
    struct addr_4tuple addr;
    addr.type = IP_TYPE_V6;
    int ret = inet_pton(AF_INET6, ip_str, &addr.ipv6.sip);
    EXPECT_EQ(ret, 1);
    addr.ipv6.sport = htons(port);

    int results[3] = {-1};
    size_t n_result = 0;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 47);

    port = 442;
    addr.ipv6.sport = htons(port);
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

    struct maat_options *opts = maat_options_new();
    maat_options_set_json_file(opts, json_path);

    g_maat_instance = maat_new(opts, table_info_path);
    EXPECT_NE(g_maat_instance, nullptr);

	ret=RUN_ALL_TESTS();

    maat_free(g_maat_instance);

	return ret;
}