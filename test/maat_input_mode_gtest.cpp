#include "utils.h"
#include "maat/maat.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "json2iris.h"
#include "maat_table.h"
#include "maat_config_monitor.h"

#include <gtest/gtest.h>

const char *table_info_path = "./table_info.conf";
const char *json_filename = "maat_json.json";

TEST(EQ_Test, Always_True) {
  EXPECT_EQ(1, 1);
}

TEST(json_mode, maat_scan_string) {
    char json_iris_path[128] = {0};
    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp", json_filename);

    if ((access(json_iris_path, F_OK)) == 0) {
        system_cmd_rmdir(json_iris_path);
	}

	struct maat_options *opts = maat_options_new();
    char json_path[128] = {0};
    snprintf(json_path, sizeof(json_path), "./%s", json_filename);
    maat_options_set_json_file(opts, json_path);

    struct maat *maat_instance = maat_new(opts, table_info_path);
    EXPECT_NE(maat_instance, nullptr);

    int table_id = table_manager_get_table_id(maat_instance->tbl_mgr, "HTTP_URL");
   
    char scan_data[128] = "hello";
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_string(maat_instance, table_id, 0, scan_data, strlen(scan_data), results, sizeof(results), &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 191);

    maat_options_free(opts);
    maat_state_free(&state);
    maat_free(maat_instance);
}

TEST(iris_mode, maat_scan_string) {
    char tmp_iris_path[128] = {0};
    char json_iris_path[128] = {0};
    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp", json_filename);

    if ((access(json_iris_path, F_OK)) < 0) {
        char *json_buff = NULL;
        size_t json_buff_sz = 0;

		int ret = load_file_to_memory(json_filename, (unsigned char**)&json_buff, &json_buff_sz);
        EXPECT_NE(ret, -1);

		ret = json2iris(json_buff, json_filename, NULL, tmp_iris_path, sizeof(tmp_iris_path), NULL, NULL, NULL);
		EXPECT_NE(ret, -1);
	}

    char tmp_iris_full_idx_path[128] = {0};
    char tmp_iris_inc_idx_path[128] = {0};
    snprintf(tmp_iris_full_idx_path, sizeof(tmp_iris_full_idx_path), "%s/index", json_iris_path);
    snprintf(tmp_iris_inc_idx_path, sizeof(tmp_iris_inc_idx_path), "%s/index", json_iris_path);

    struct maat_options *opts = maat_options_new();
    maat_options_set_iris(opts, tmp_iris_full_idx_path, tmp_iris_inc_idx_path);

    struct maat *maat_instance = maat_new(opts, table_info_path);
    EXPECT_NE(maat_instance, nullptr);

    int table_id = table_manager_get_table_id(maat_instance->tbl_mgr, "HTTP_URL");
   
    char scan_data[128] = "hello";
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_string(maat_instance, table_id, 0, scan_data, strlen(scan_data), results, sizeof(results), &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 191);

    maat_options_free(opts);
    maat_state_free(&state);
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

TEST(redis_mode, maat_scan_string) {
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

        ret = json2iris(json_buff, json_filename, c, tmp_iris_path, sizeof(tmp_iris_path), NULL, NULL, logger);
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

    struct maat *maat_instance = maat_new(opts, table_info_path);
    int table_id = table_manager_get_table_id(maat_instance->tbl_mgr, "HTTP_URL");
   
    char scan_data[128] = "hello";
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_string(maat_instance, table_id, 0, scan_data, strlen(scan_data), results, sizeof(results), &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 191);

    maat_options_free(opts);
    maat_state_free(&state);
    log_handle_destroy(maat_instance->logger);
    maat_free(maat_instance);
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
	ret=RUN_ALL_TESTS();
	return ret;
}