#include "maat.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "json2iris.h"
#include "maat_table.h"
#include "maat_config_monitor.h"

#include <gtest/gtest.h>

#define MODULE_INPUT_MODE_GTEST	 module_name_str("maat.input_mode_gtest")

const char *table_info_path = "./table_info.conf";
const char *json_filename = "maat_json.json";
struct log_handle *g_logger = NULL;

TEST(json_mode, maat_scan_string) {
    char tmp_iris_path[PATH_MAX] = {0};
    char json_iris_path[PATH_MAX] = {0};
    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp", json_filename);

    if (access(json_iris_path, F_OK) < 0) {
        char *json_buff = NULL;
        size_t json_buff_sz = 0;

		int ret = load_file_to_memory(json_filename, (unsigned char**)&json_buff, &json_buff_sz);
        EXPECT_NE(ret, -1);

		ret = json2iris(json_buff, json_filename, NULL, tmp_iris_path, sizeof(tmp_iris_path),
                        NULL, NULL, g_logger);
        FREE(json_buff);
		EXPECT_NE(ret, -1);
	}

	struct maat_options *opts = maat_options_new();
    char json_path[PATH_MAX] = {0};
    snprintf(json_path, sizeof(json_path), "./%s", json_filename);
    maat_options_set_json_file(opts, json_path);
    maat_options_set_logger_path(opts, "./maat_input_mode_gtest.log");

    struct maat *maat_instance = maat_new(opts, table_info_path);
    EXPECT_TRUE(maat_instance != NULL);

    const char *table_name = "KEYWORDS_TABLE";
    int table_id = maat_get_table_id(maat_instance, table_name);
    char scan_data[128] = "string1, string2, string3, string4, string5, string6, string7, string8";
    long long results[5] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    int ret = maat_scan_string(maat_instance, table_id, thread_id, scan_data, strlen(scan_data), 
                               results, sizeof(results), &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    long long clause_id = maat_runtime_get_sequence(maat_instance->maat_rt, "test_seq");
    EXPECT_EQ(clause_id, 0);
    clause_id = maat_runtime_get_sequence(maat_instance->maat_rt, "test_seq");
    EXPECT_EQ(clause_id, 1);
    clause_id = maat_runtime_get_sequence(maat_instance->maat_rt, "test_seq");
    EXPECT_EQ(clause_id, 2);

    maat_options_free(opts);
    maat_state_free(state);
    state = NULL;
    maat_free(maat_instance);
}

TEST(iris_mode, maat_scan_string) {
    char tmp_iris_path[512] = {0};
    char json_iris_path[512] = {0};
    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp", json_filename);

    if (access(json_iris_path, F_OK) < 0) {
        char *json_buff = NULL;
        size_t json_buff_sz = 0;

		int ret = load_file_to_memory(json_filename, (unsigned char**)&json_buff, &json_buff_sz);
        EXPECT_NE(ret, -1);

		ret = json2iris(json_buff, json_filename, NULL, tmp_iris_path, sizeof(tmp_iris_path), 
                        NULL, NULL, g_logger);
        FREE(json_buff);
		EXPECT_NE(ret, -1);
	}

    char tmp_iris_full_idx_path[PATH_MAX] = {0};
    char tmp_iris_inc_idx_path[PATH_MAX] = {0};
    snprintf(tmp_iris_full_idx_path, sizeof(tmp_iris_full_idx_path), "%s/index", json_iris_path);
    snprintf(tmp_iris_inc_idx_path, sizeof(tmp_iris_inc_idx_path), "%s/index", json_iris_path);

    struct maat_options *opts = maat_options_new();
    maat_options_set_iris(opts, tmp_iris_full_idx_path, tmp_iris_inc_idx_path);
    maat_options_set_logger_path(opts, "./maat_input_mode_gtest.log");

    struct maat *maat_instance = maat_new(opts, table_info_path);
    EXPECT_TRUE(maat_instance != NULL);

    const char *table_name = "KEYWORDS_TABLE";
    int table_id = maat_get_table_id(maat_instance, table_name);
    char scan_data[128] = "string1, string2, string3, string4, string5, string6, string7, string8";
    long long results[5] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    int ret = maat_scan_string(maat_instance, table_id, thread_id, scan_data, strlen(scan_data), 
                               results, sizeof(results), &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    maat_options_free(opts);
    maat_state_free(state);
    state = NULL;
    maat_free(maat_instance);
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
    redisContext *ctx = s_rule->ref_ctx;
	char *buff = ALLOC(char, strlen(line) + 1);

    memcpy(buff, line, strlen(line) + 1);
	while(buff[strlen(line) - 1] == '\n' || buff[strlen(line) - 1] == '\t') {
		buff[strlen(line) - 1] = '\0';
	}

    const char *redis_rule_key = "TEST_RULE_KEY";
    redisReply *reply = maat_cmd_wrap_redis_command(ctx, "INCRBY %s %d", redis_rule_key, 1);
	if (reply->type == REDIS_REPLY_NIL) {
		printf("incrby redis_rule_key:%s failed.", redis_rule_key);
        return -1;
	} else {
		s_rule->rule_id = maat_cmd_read_redis_integer(reply);
		freeReplyObject(reply);
		reply = NULL;
	}

	maat_cmd_set_serial_rule(s_rule + line_idx, MAAT_OP_ADD, s_rule->rule_id, table_name, 
                             buff, absolute_expire_time);
    (s_rule + line_idx)->ref_ctx = ctx;
	line_idx++;

    FREE(buff);

	return 0;
}

TEST(redis_mode, maat_scan_string) {
    char json_iris_path[512] = {0};
    char redis_ip[64] = "127.0.0.1";
    int redis_port = 6379;
    int redis_db = 0;

    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp", json_filename);

    redisContext *c = maat_cmd_connect_redis(redis_ip, redis_port, redis_db, g_logger);
    EXPECT_TRUE(c != NULL);

    redisReply *reply = maat_cmd_wrap_redis_command(c, "flushdb");
    EXPECT_TRUE(reply != NULL);
    
    if (access(json_iris_path, F_OK) < 0) {
        char tmp_iris_path[128] = {0};
        char *json_buff = NULL;
        size_t json_buff_sz = 0;
        
        int ret = load_file_to_memory(json_filename, (unsigned char **)&json_buff, &json_buff_sz);
        EXPECT_NE(ret, -1);

        ret = json2iris(json_buff, json_filename, c, tmp_iris_path, sizeof(tmp_iris_path), 
                        NULL, NULL, g_logger);
        FREE(json_buff);
        EXPECT_NE(ret, -1);
    }

    size_t total_line_cnt = 0;
    char tmp_iris_full_idx_path[PATH_MAX] = {0};
    snprintf(tmp_iris_full_idx_path, sizeof(tmp_iris_full_idx_path), "%s/index", json_iris_path);
    config_monitor_traverse(0, tmp_iris_full_idx_path, NULL, count_line_num_cb, NULL, 
                            &total_line_cnt, g_logger);

    struct serial_rule *s_rule = ALLOC(struct serial_rule, total_line_cnt);
    s_rule->ref_ctx = c;
    long long server_time = maat_cmd_redis_server_time_s(c);
    EXPECT_NE(server_time, -1);

    absolute_expire_time = server_time + 300;
    config_monitor_traverse(0, tmp_iris_full_idx_path, NULL, make_serial_rule, NULL, 
                            s_rule, g_logger);
    s_rule->ref_ctx = NULL;
    int success_cnt = 0;
    do {
        success_cnt = maat_cmd_write_rule(c, s_rule, total_line_cnt, server_time, g_logger);
    } while (success_cnt < 0);

    EXPECT_EQ(success_cnt, (int)total_line_cnt);

    for (size_t i = 0; i < total_line_cnt; i++) {
        maat_cmd_clear_rule_cache(s_rule + i);
    }
    FREE(s_rule);
    redisFree(c);

    struct maat_options *opts = maat_options_new();
    maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
    maat_options_set_logger_path(opts, "./maat_input_mode_gtest.log");

    struct maat *maat_instance = maat_new(opts, table_info_path);
    const char *table_name = "KEYWORDS_TABLE";
    int table_id = maat_get_table_id(maat_instance, table_name);
    char scan_data[128] = "string1, string2, string3, string4, string5, string6, string7, string8";
    long long results[5] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    int ret = maat_scan_string(maat_instance, table_id, thread_id, scan_data, strlen(scan_data), 
                               results, sizeof(results), &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    maat_options_free(opts);
    maat_state_free(state);
    state = NULL;
    maat_free(maat_instance);
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
    g_logger = log_handle_create("./input_mode_gtest.log", 0);

    char json_iris_path[NAME_MAX] = {0};
    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp", json_filename);
    if ((access(json_iris_path, F_OK)) == 0) {
        system_cmd_rmdir(json_iris_path);
    }

	ret=RUN_ALL_TESTS();

    log_handle_destroy(g_logger);
	return ret;
}
