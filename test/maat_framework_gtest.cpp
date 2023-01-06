#include <gtest/gtest.h>

#include "utils.h"
#include "maat/maat.h"
#include "maat_rule.h"
#include "maat_utils.h"
#include "maat_table_schema.h"
#include "maat_table_runtime.h"
#include "maat_command.h"
#include "IPMatcher.h"
#include "json2iris.h"
#include "maat_config_monitor.h"

struct maat *g_maat_instance = NULL;
const char *table_info_path = "./table_info.conf";
const char *json_path="./maat_json.json";
const char *json_filename = "maat_json.json";

TEST(maat_scan_string, hit_one_expr) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
   
    char data[128] = "i.ytimg.com";
    int results[5] = {0};
    size_t n_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 30);
}

TEST(maat_scan_string, hit_two_expr) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
   
    char data[128] = "should hit aaa bbb";
    int results[5] = {0};
    size_t n_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 2);
    EXPECT_EQ(results[0], 28);
    EXPECT_EQ(results[1], 27);
}

TEST(maat_scan_string, hit_three_expr) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
   
    char data[128] = "should hit aaa bbb C#中国";
    int results[5] = {0};
    size_t n_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 3);
    EXPECT_EQ(results[0], 28);
    EXPECT_EQ(results[1], 27);
    EXPECT_EQ(results[2], 18);
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
    struct maat_state *state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 7);

    port = 20001;
    addr.ipv4.sport = htons(port);
    state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
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
    struct maat_state *state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 4);

    port = 40000;
    addr.ipv4.sport = htons(port);
    memset(results, 0, sizeof(results));
    n_result = 0;
    state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 4);

    port = 40001;
    addr.ipv4.sport = htons(port);
    memset(results, 0, sizeof(results));
    n_result = 0;
    state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
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
    struct maat_state *state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 8);

    ret = inet_pton(AF_INET, ip_str2, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    addr.ipv4.sport = htons(port2);
    state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 8);

    ret = inet_pton(AF_INET, ip_str3, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    addr.ipv4.sport = htons(port2);
    state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
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
    struct maat_state *state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 50);

    ret = inet_pton(AF_INET, ip_str2, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
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
    struct maat_state *state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 2);
    EXPECT_EQ(results[0], 63);
    EXPECT_EQ(results[1], 67);

    port = 442;
    addr.ipv4.sport = htons(port);
    state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
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
    struct maat_state *state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 47);

    port = 442;
    addr.ipv6.sport = htons(port);
    state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);
}

TEST(maat_scan_string, dynamic_config) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
   
    char data[128] = "hello world";
    int results[5] = {0};
    size_t n_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    const char *table_name = "HTTP_URL";
    const char *table_line = "9999\t8888\thello world\t0\t0\t0\t1\t";
    struct maat_cmd_line line_rule;
    line_rule.rule_id = 101;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    sleep(2);
    state = NULL;
    ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 9999);
}

TEST(maat_scan_ip, dynamic_config) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "IP_PLUS_CONFIG");
   
    char ip_str[32] = "10.0.6.201";
    uint16_t port = 443;
    struct addr_4tuple addr;
    addr.type = IP_TYPE_V4;
    int ret = inet_pton(AF_INET, ip_str, &addr.ipv4.sip);
    EXPECT_EQ(ret, 1);
    addr.ipv4.sport = htons(port);

    int results[3] = {-1};
    size_t n_result = 0;
    struct maat_state *state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 0);

    const char *table_name = "IP_PLUS_CONFIG";
    const char *table_line = "9998\t8887\t4\trange\t10.0.6.201\t255.255.0.0\trange\t0\t65535\t6\t0\t1";
    struct maat_cmd_line line_rule;
    line_rule.rule_id = 101;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 0);

    sleep(2);
    state = NULL;
    ret = maat_scan_ip(g_maat_instance, table_id, 0, &addr, results, &n_result, &state);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result, 1);
    EXPECT_EQ(results[0], 9998);
}

int count_line_num_cb(const char *table_name, const char *line, void *u_para)
{
	(*((unsigned int *)u_para))++;
	return 0;
}

int line_idx = 0;
long long absolute_expire_time=0;
int make_serial_rule(const char *table_name, const char *line, void *u_para)
{
	struct serial_rule *s_rule=(struct serial_rule *)u_para;
	int rule_id = 0;
	char *buff = ALLOC(char, strlen(line) + 1);
    
    memcpy(buff, line, strlen(line) + 1);

	while (buff[strlen(buff) - 1] == '\n' || buff[strlen(buff) - 1] == '\t') {
		buff[strlen(buff) - 1] = '\0';
	}

    int j = 0;
    char *str1 = NULL;
    char *token = NULL;
    char *saveptr1 = NULL;

	for (j = 0,str1 = buff; ; j++, str1 = NULL) {
		 token = strtok_r(str1, "\t ", &saveptr1);
		 if (token == NULL)
			 break;
		 if (j == 0) {
			sscanf(token,"%d", &rule_id);
		 }
 	}
	
    memcpy(buff, line, strlen(line)+1);
	while(buff[strlen(buff)-1]=='\n'||buff[strlen(buff)-1]=='\t') {
		buff[strlen(buff)-1]='\0';
	}

	maat_cmd_set_serial_rule(s_rule + line_idx, MAAT_OP_ADD, rule_id, table_name, buff, absolute_expire_time);
	line_idx++;
	FREE(str1);

	return 0;
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

    char json_iris_path[128] = {0};
    char redis_ip[64] = "127.0.0.1";
    int redis_port = 6379;
    int redis_db = 0;

    struct log_handle *logger = log_handle_create("./tmp.log", 0);

    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp", json_filename);

    redisContext *c = maat_cmd_connect_redis(redis_ip, redis_port, redis_db, logger);
    EXPECT_NE(c, nullptr);

    redisReply *reply = maat_cmd_wrap_redis_command(c, "flushdb");
    EXPECT_NE(reply, nullptr);
    
    if ((access(json_iris_path, F_OK)) < 0) {
        char tmp_iris_path[128] = {0};
        char *json_buff = NULL;
        size_t json_buff_sz = 0;
        
        int ret = load_file_to_memory(json_filename, (unsigned char **)&json_buff, &json_buff_sz);
        EXPECT_NE(ret, -1);

        ret = json2iris(json_buff, json_filename, c, tmp_iris_path, 
                        sizeof(tmp_iris_path), NULL, NULL, logger);
        EXPECT_NE(ret, -1);
    }

    size_t total_line_cnt = 0;
    char tmp_iris_full_idx_path[128] = {0};
    snprintf(tmp_iris_full_idx_path, sizeof(tmp_iris_full_idx_path), "%s/index", json_iris_path);
    config_monitor_traverse(0, tmp_iris_full_idx_path, NULL, count_line_num_cb, NULL, &total_line_cnt, logger);

    struct serial_rule *s_rule = ALLOC(struct serial_rule, total_line_cnt);
    long long server_time = maat_cmd_redis_server_time_s(c);
    EXPECT_NE(server_time, -1);

    absolute_expire_time = server_time + 300;
    config_monitor_traverse(0, tmp_iris_full_idx_path, NULL, make_serial_rule, NULL, s_rule, logger);

    int success_cnt = 0;
    do {
        success_cnt = maat_cmd_write_rule(c, s_rule, total_line_cnt, server_time, logger);
    } while (success_cnt < 0);

    EXPECT_EQ(success_cnt, (int)total_line_cnt);

    for (size_t i = 0; i < total_line_cnt; i++) {
        maat_cmd_clear_rule_cache(s_rule + i);
    }
    FREE(s_rule);
    redisFree(c);

    struct maat_options *opts = maat_options_new();
    maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
    maat_options_set_logger(opts, logger);

    g_maat_instance = maat_new(opts, table_info_path);

	ret=RUN_ALL_TESTS();
    
    log_handle_destroy(g_maat_instance->logger);
    maat_free(g_maat_instance);

	return ret;
}