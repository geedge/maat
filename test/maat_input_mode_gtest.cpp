#include "maat.h"
#include "maat_utils.h"
#include "maat_core.h"
#include "json2iris.h"
#include "test_utils.h"
#include "maat_table.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"

#include <gtest/gtest.h>

#define MODULE_INPUT_MODE_GTEST	 module_name_str("maat.input_mode_gtest")

const char *g_table_info_path = "./table_info.conf";
const char *g_json_filename = "maat_json.json";
struct log_handle *g_logger = NULL;

TEST(json_mode, maat_scan_string) {
    char iris_idx_path[PATH_MAX] = {0};
    char json_iris_path[PATH_MAX] = {0};
    char json_path[PATH_MAX] = {0};
    long long results[5] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    char scan_data[128] = "string1, string2, string3, string4, "
                          "string5, string6, string7, string8";
    const char *table_name = "KEYWORDS_TABLE";

    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp",
             g_json_filename);
    snprintf(iris_idx_path, sizeof(iris_idx_path), "%s/index", json_iris_path);
    snprintf(json_path, sizeof(json_path), "./%s", g_json_filename);

    int ret = write_json_to_iris(g_json_filename, iris_idx_path,
                                 sizeof(iris_idx_path), g_logger);    
    assert(ret == 0);

	struct maat_options *opts = maat_options_new();
    maat_options_set_json_file(opts, json_path);
    maat_options_set_stat_on(opts);
    maat_options_set_perf_on(opts);
    maat_options_set_logger(opts, "./maat_input_mode_gtest.log", LOG_LEVEL_INFO);

    struct maat *maat_inst = maat_new(opts, g_table_info_path);
    EXPECT_TRUE(maat_inst != NULL);
   
    int table_id = maat_get_table_id(maat_inst, table_name);
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                           results, sizeof(results), &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    maat_options_free(opts);
    maat_state_free(state);
    maat_free(maat_inst);
}

TEST(iris_mode, maat_scan_string) {
    char json_iris_path[512] = {0};
    char iris_idx_path[PATH_MAX] = {0};
    long long results[5] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    char scan_data[128] = "string1, string2, string3, string4, "
                          "string5, string6, string7, string8";

    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp",
             g_json_filename);
    snprintf(iris_idx_path, sizeof(iris_idx_path), "%s/index", json_iris_path);

    int ret = write_json_to_iris(g_json_filename, iris_idx_path,
                                 sizeof(iris_idx_path), g_logger);    
    assert(ret == 0);

    struct maat_options *opts = maat_options_new();
    maat_options_set_stat_on(opts);
    maat_options_set_perf_on(opts);
    maat_options_set_iris(opts, iris_idx_path, iris_idx_path);
    maat_options_set_logger(opts, "./maat_input_mode_gtest.log", LOG_LEVEL_INFO);
     
    struct maat *maat_inst = maat_new(opts, g_table_info_path);
    EXPECT_TRUE(maat_inst != NULL);

    int table_id = maat_get_table_id(maat_inst, table_name);
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                           results, sizeof(results), &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    maat_options_free(opts);
    maat_state_free(state);
    maat_free(maat_inst);
}

TEST(redis_mode, maat_scan_string) {
    char redis_ip[32] = "127.0.0.1";
    int redis_port = 6379;
    int redis_db = 0;
    const char *table_name = "KEYWORDS_TABLE";
    long long results[5] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    char scan_data[128] = "string1, string2, string3, string4, "
                          "string5, string6, string7, string8";

    int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port,
                                  redis_db, g_logger);
    assert(ret == 0);

    struct maat_options *opts = maat_options_new();
    maat_options_set_stat_on(opts);
    maat_options_set_perf_on(opts);
    maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
    maat_options_set_logger(opts, "./maat_input_mode_gtest.log",
                            LOG_LEVEL_INFO);

    struct maat *maat_inst = maat_new(opts, g_table_info_path);
    assert(maat_inst != NULL);

    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int table_id = maat_get_table_id(maat_inst, table_name);

    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                           results, sizeof(results), &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    maat_options_free(opts);
    maat_state_free(state);
    maat_free(maat_inst);
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
    g_logger = log_handle_create("./maat_input_mode_gtest.log", 0);

    char json_iris_path[NAME_MAX] = {0};
    snprintf(json_iris_path, sizeof(json_iris_path),
             "./%s_iris_tmp", g_json_filename);
    if ((access(json_iris_path, F_OK)) == 0) {
        system_cmd_rmdir(json_iris_path);
    }

	ret=RUN_ALL_TESTS();

    log_handle_destroy(g_logger);
	return ret;
}