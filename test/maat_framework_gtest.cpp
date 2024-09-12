#include <gtest/gtest.h>
#include <dirent.h>
#include <openssl/md5.h>

#include "test_utils.h"
#include "maat.h"
#include "maat_core.h"
#include "maat_utils.h"
#include "maat_command.h"
#include "ip_matcher.h"
#include "log/log.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"

#define MODULE_FRAMEWORK_GTEST	 module_name_str("maat.framework_gtest")

#define ARRAY_SIZE              10
#define HIT_PATH_SIZE           128
#define	WAIT_FOR_EFFECTIVE_S	2

const char *g_table_info_path = "./table_info.json";
const char *g_json_filename = "maat_json.json";

size_t g_thread_num = 4;



int test_add_expr_command(struct maat *maat_inst, const char *expr_table, 
                          long long rule_id, int timeout,
                          const char *keywords)
{
    char huge_serv_def[1024 * 2] = {0};

    memset(huge_serv_def, 's', sizeof(huge_serv_def) - 1);
    huge_serv_def[sizeof(huge_serv_def) - 1] = '\0';

    int ret = rule_table_set_line(maat_inst, "RULE_DEFAULT", MAAT_OP_ADD,
                                     rule_id, huge_serv_def, 1, timeout);
    EXPECT_EQ(ret, 1);

    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, "OBJECT2RULE_DEFAULT", MAAT_OP_ADD,
                                       object_id, rule_id, 0, expr_table, 1, timeout);
    EXPECT_EQ(ret, 1);

    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, expr_table, MAAT_OP_ADD, item_id,
                              object_id, keywords, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    return ret;
}

int del_command(struct maat *maat_inst, int rule_id)
{
    return rule_table_set_line(maat_inst, "RULE_DEFAULT", MAAT_OP_DEL,
                                  rule_id, "null", 1, 0);
}

const char *watched_json = "./json_update/maat.json";
const char *old_json = "./json_update/old.json";
const char *new_json = "./json_update/new.json";
const char *corrupted_json = "./json_update/corrupted.json";
const char *json_decrypt_key = "himaat!";
const char *tmp_gzipped_file_name = "./json_update/tmp_gzipped_json.gz";

class JsonUpdate : public testing::Test
{
protected:
    static void SetUpTestCase() {
        system_cmd_gzip(old_json, tmp_gzipped_file_name);
        system_cmd_encrypt(tmp_gzipped_file_name, watched_json, json_decrypt_key);

        int scan_interval_ms = 500;
        logger = log_handle_create("./maat_framework_gtest.log", 0);
        struct maat_options *opts = maat_options_new();
        maat_options_set_instance_name(opts, "firewall");
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_perf_on(opts);
        maat_options_set_json_file(opts, watched_json);
        maat_options_set_json_file_gzip_flag(opts, 1);
        maat_options_set_json_file_decrypt_key(opts, json_decrypt_key);
        maat_options_set_rule_update_checking_interval_ms(opts, scan_interval_ms);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in JsonUpdate failed.",
                      __FUNCTION__, __LINE__);
            assert(0);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *JsonUpdate::_shared_maat_inst;
struct log_handle *JsonUpdate::logger;

void scan_with_old_or_new_cfg(struct maat *maat_inst, int is_old)
{
    const char *hit_old_data = "Hello world! I'm eve.";
    const char *hit_new_data = "Maat was borned in MESA.";
    const char *table_name = "HTTP_URL";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_inst, table_id, hit_old_data,
                               strlen(hit_old_data), results, ARRAY_SIZE,
                               &n_hit_result, state);
    if (is_old) {
        EXPECT_EQ(ret, MAAT_SCAN_HIT);
        EXPECT_TRUE(results[0] == 1);
    } else {
        EXPECT_EQ(ret, MAAT_SCAN_OK);
    }

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);
    ret = maat_scan_string(maat_inst, table_id, hit_new_data,
                           strlen(hit_new_data), results, ARRAY_SIZE,
                           &n_hit_result, state);
    if (!is_old) {
        EXPECT_EQ(ret, MAAT_SCAN_HIT);
        EXPECT_EQ(results[0], 2);
    } else {
        EXPECT_EQ(ret, MAAT_SCAN_OK);
    }

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

TEST_F(JsonUpdate, OldCfg) {
    scan_with_old_or_new_cfg(JsonUpdate::_shared_maat_inst, 1);
}

TEST_F(JsonUpdate, NewCfg) {
    system_cmd_gzip(corrupted_json, tmp_gzipped_file_name);
    system_cmd_encrypt(tmp_gzipped_file_name, watched_json, json_decrypt_key);

    sleep(2);
    scan_with_old_or_new_cfg(JsonUpdate::_shared_maat_inst, 1);

    system_cmd_gzip(new_json, tmp_gzipped_file_name);
    int ret = system_cmd_encrypt(tmp_gzipped_file_name, watched_json,
                                 json_decrypt_key);
    EXPECT_EQ(ret, 0);

    sleep(5);
    scan_with_old_or_new_cfg(JsonUpdate::_shared_maat_inst, 0);
}

class FlagScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);        
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_hit_path_enabled(opts);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in FlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *FlagScan::_shared_maat_inst;
struct log_handle *FlagScan::logger;

TEST_F(FlagScan, basic) {
    const char *flag_table_name = "FLAG_CONFIG";
    struct maat *maat_inst = FlagScan::_shared_maat_inst;

    int flag_table_id = maat_get_table_id(maat_inst, flag_table_name);
    //rule_id:192 flag: 0000 0001 mask: 0000 0011
    //scan_data: 0000 1001 or 0000 1101 should hit
    long long scan_data = 9;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_flag(maat_inst, flag_table_id, scan_data, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 207);
    EXPECT_EQ(results[1], 192);
    
    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);
    maat_state_reset(state);

    scan_data = 13;
    memset(results, 0, sizeof(results));
    n_hit_result = 0;
    ret = maat_scan_flag(maat_inst, flag_table_id, scan_data, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 207);
    EXPECT_EQ(results[1], 192);

    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_reset(state);

    scan_data = 6;
    memset(results, 0, sizeof(results));
    n_hit_result = 0;
    ret = maat_scan_flag(maat_inst, flag_table_id, scan_data, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}   

TEST_F(FlagScan, withExprRegion) {
    const char *flag_table_name = "FLAG_CONFIG";
    const char *expr_table_name = "HTTP_URL";
    struct maat *maat_inst = FlagScan::_shared_maat_inst;

    int flag_table_id = maat_get_table_id(maat_inst, flag_table_name);
    int expr_table_id = maat_get_table_id(maat_inst, expr_table_name);
    //rule_id:193 flag: 0000 0010 mask: 0000 0011
    //scan_data: 0000 0010 or 0000 0100 should hit
    long long flag_scan_data = 2;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_flag(maat_inst, flag_table_id, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    const char *expr_scan_data = "hello world";
    ret = maat_scan_string(maat_inst, expr_table_id, expr_scan_data, 
                           strlen(expr_scan_data), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 193);

    ret = maat_scan_not_logic(maat_inst, expr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}   

TEST_F(FlagScan, hitMultiRule) {
    const char *flag_table_name = "FLAG_CONFIG";
    struct maat *maat_inst = FlagScan::_shared_maat_inst;

    int flag_table_id = maat_get_table_id(maat_inst, flag_table_name);
    //rule_id:192 flag: 0000 0001 mask: 0000 0011
    //rule_id:194 flag: 0001 0101 mask: 0001 1111
    //scan_data: 0001 0101 should hit rule192 and rule194
    long long flag_scan_data = 21;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_flag(maat_inst, flag_table_id, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 3);
    EXPECT_EQ(results[0], 207);
    EXPECT_EQ(results[1], 194);
    EXPECT_EQ(results[2], 192);

    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(maat_inst, flag_table_id, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    maat_state_free(state);
    state = NULL;
}  

TEST_F(FlagScan, hitRepeatedRule) {
    const char *flag_table_name = "FLAG_CONFIG";
    struct maat *maat_inst = FlagScan::_shared_maat_inst;

    int flag_table_id = maat_get_table_id(maat_inst, flag_table_name);
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //rule_id:192 flag: 0000 0001 mask: 0000 0011
    //scan_data: 0000 1001 or 0000 1101 should hit
    long long flag_scan_data1 = 9; 
    int ret = maat_scan_flag(maat_inst, flag_table_id, flag_scan_data1, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 207);
    EXPECT_EQ(results[1], 192);

    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //rule_id:192 flag: 0000 0001 mask: 0000 0011
    //rule_id:194 flag: 0001 0101 mask: 0001 1111
    //scan_data: 0001 0101 should hit rule192 and rule194
	long long flag_scan_data2 = 21;
    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(maat_inst, flag_table_id, flag_scan_data2, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 194);

    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(maat_inst, flag_table_id, flag_scan_data2, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    maat_state_free(state);
    state = NULL;
}  

TEST_F(FlagScan, FlagPlus) {
    const char *flag_table_name = "FLAG_PLUS_CONFIG";
    const char *district_str = "I love China";
    struct maat *maat_inst = FlagScan::_shared_maat_inst;

    int flag_table_id = maat_get_table_id(maat_inst, flag_table_name);
    //rule_id:196 flag: 0001 1111 mask: 0000 1111
    //scan_data: 0000 1111 or 0001 1111 should hit
    long long scan_data1 = 15;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_flag(maat_inst, flag_table_id, scan_data1, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_ERR);
 
    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_state_set_scan_district(state, flag_table_id, district_str,
                                       strlen(district_str));
    ASSERT_EQ(ret, 0);

    ret = maat_scan_flag(maat_inst, flag_table_id, scan_data1, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 196);

    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_flag(maat_inst, flag_table_id, scan_data1, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, flag_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);
    maat_state_free(state);
    state = NULL;
}

//hyperscan engine
class HsStringScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_hit_path_enabled(opts);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in HsStringScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsStringScan::_shared_maat_inst;
struct log_handle *HsStringScan::logger;

TEST_F(HsStringScan, ScanDataOnlyOneByte) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char scan_data = 0x20;

    int ret = maat_scan_string(maat_inst, table_id, &scan_data, sizeof(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, Full) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "http://www.cyberessays.com/search_results.php"
                            "?action=search&query=username,abckkk,1234567";

    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 125);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, Regex) {
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "Cookie: Txa123aheadBCAxd";
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 148);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, RegexUnicode) {
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "String contains É";
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 229);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, BackslashR_N_Escape) {
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    const char *payload = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ret = maat_scan_string(maat_inst, table_id, payload, strlen(payload),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 225);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, BackslashR_N_Escape_IncUpdate) {
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    const char *payload = "html>\\r\\n";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ret = maat_scan_string(maat_inst, table_id, payload, strlen(payload),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 234);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_reset(state);

    const char *rule_table_name = "RULE_DEFAULT";
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table add line */
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object_id, rule_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    /* expr table add line */
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    const char *keywords = "html>\\\\r\\\\n";

    /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                              object_id, keywords, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 3);

    ret = maat_scan_string(maat_inst, table_id, payload, strlen(payload), 
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 234);
    EXPECT_EQ(results[1], rule_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, BackslashCtrlCharactor)
{
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    const char *payload = "()abc^$def|";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ret = maat_scan_string(maat_inst, table_id, payload, strlen(payload),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 235);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, ExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *district_str1 ="HTTP URL";
	const char *district_str2 ="我的diStricT";
	const char *scan_data1 = "http://www.cyberessays.com/search_results.php"
                             "?action=search&query=abckkk,1234567";
	const char *scan_data2 = "Addis Sapphire Hotel";
    const char *table_name = "HTTP_SIGNATURE";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
	int ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
						        results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_ERR);//Should return error for district not setting.

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_state_set_scan_district(state, table_id, district_str1,
                                       strlen(district_str1));
	ASSERT_EQ(ret, 0);

	ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 128);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_reset(state);
	ret = maat_state_set_scan_district(state, table_id, district_str2,
                                       strlen(district_str2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 190);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, ExprPlusWithOffset)
{
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
	const char *district_str = "Payload";
	unsigned char udp_payload_not_hit[] = { /* Stun packet */
							0x00, 0x03, 0x00, 0x4a, 0x21, 0x12, 0xa4, 0x42, 
							0x4f, 0xc2, 0xc2, 0x70, 0xb3, 0xa8, 0x4e, 0x22, 
							0xf5, 0x22, 0x87, 0x4c, 0x40, 0x00, 0x00, 0x46, 
							0x03, 0x02, 0xab, 0x39, 0xbb, 0x97, 0xe5, 0x01, 
							0x3a, 0x46, 0x1c, 0x28, 0x5b, 0xab, 0xfa, 0x9a, 
							0xab, 0x2e, 0x71, 0x39, 0x66, 0xa0, 0xd7, 0xb9, 
							0xd8, 0x41, 0xa7, 0xa0, 0x84, 0xa9, 0xf3, 0x1b, 
							0x03, 0x7f, 0xa8, 0x28, 0xa2, 0xd3, 0x64, 0xc2, 
							0x3d, 0x20, 0xe0, 0xb1, 0x41, 0x12, 0x6c, 0x2f, 
							0xc5, 0xbb, 0xc3, 0xba, 0x69, 0x73, 0x52, 0x64, 
							0xf6, 0x30, 0x81, 0xf4, 0x3f, 0xc2, 0x19, 0x6a, 
							0x68, 0x61, 0x93, 0x08, 0xc0, 0x0a };
	unsigned char udp_payload_hit[] = { /* Stun packet */					//rule:"1-1:03&9-10:2d&14-16:2d34&19-21:2d&24-25:2d"
							0x00, 0x03, 0x00, 0x4a, 0x21, 0x12, 0xa4, 0x42, //1-1:03
							0x4f, 0xc2, 0x2d, 0x70, 0xb3, 0xa8, 0x4e, 0x2d, //10-10:2d
							0x34, 0x22, 0x87, 0x4c, 0x2d, 0x00, 0x00, 0x46, //15-16:2d34
							0x2d, 0x34, 0xab, 0x39, 0xbb, 0x97, 0xe5, 0x01, //20-20:2d
							0x03, 0x46, 0x1c, 0x28, 0x5b, 0xab, 0xfa, 0x9a, //24-24:2d
							0xab, 0x2e, 0x71, 0x39, 0x66, 0xa0, 0xd7, 0xb9, 
							0xd8, 0x41, 0xa7, 0xa0, 0x84, 0xa9, 0xf3, 0x1b, 
							0x03, 0x7f, 0xa8, 0x28, 0xa2, 0xd3, 0x64, 0xc2, 
							0x3d, 0x20, 0xe0, 0xb1, 0x41, 0x12, 0x6c, 0x2f, 
							0xc5, 0xbb, 0xc3, 0xba, 0x69, 0x73, 0x52, 0x64, 
							0xf6, 0x30, 0x81, 0xf4, 0x3f, 0xc2, 0x19, 0x6a, 
							0x68, 0x61, 0x93, 0x08, 0xc0, 0x0a };

	int table_id = maat_get_table_id(maat_inst, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, district_str,
                                           strlen(district_str));
	EXPECT_EQ(ret, 0);

	ret = maat_scan_string(maat_inst, table_id, (char*)udp_payload_not_hit,
                           sizeof(udp_payload_not_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_scan_string(maat_inst, table_id, (char*)udp_payload_hit,
                           sizeof(udp_payload_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 149);
	
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, ExprPlusWithHex) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
	const char *scan_data1 = "text/html; charset=UTF-8";
	const char *scan_data2 = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *district_str1 = "Content-Type";
	const char *district_str2 = "User-Agent";

	int table_id = maat_get_table_id(maat_inst, "HTTP_SIGNATURE");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, district_str1,
                                           strlen(district_str1));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 156);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_state_set_scan_district(state, table_id, district_str2,
                                       strlen(district_str2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK); //maat-v3 consider as half hit, it's unreasonable
    
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    table_id = maat_get_table_id(maat_inst, "KEYWORDS_TABLE");
    ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 132);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, ExprAndExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *expr_table_name = "HTTP_URL";
    const char *expr_plus_table_name = "HTTP_SIGNATURE";
    const char *district_str = "I love China";
    const char *scan_data = "today is Monday and yesterday is Tuesday";

    int expr_table_id = maat_get_table_id(maat_inst, expr_table_name);
    int expr_plus_table_id = maat_get_table_id(maat_inst, expr_plus_table_name);

    int ret = maat_scan_string(maat_inst, expr_plus_table_id, scan_data,
                               strlen(scan_data), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_ERR);

    ret = maat_scan_not_logic(maat_inst, expr_plus_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_state_set_scan_district(state, expr_plus_table_id, district_str,
                                       strlen(district_str));
    ASSERT_EQ(ret, 0);
    ret = maat_scan_string(maat_inst, expr_plus_table_id, scan_data,
                           strlen(scan_data), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, expr_plus_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, expr_table_id, scan_data,
                           strlen(scan_data), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 195);

    ret = maat_scan_not_logic(maat_inst, expr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, ShouldNotHitExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
	const char *district_str = "tcp.payload";
	unsigned char udp_payload_not_hit[] = { /* Stun packet */
							0x00, 0x03, 0x00, 0x4a, 0x21, 0x12, 0xa4, 0x42, 
							0x4f, 0xc2, 0xc2, 0x70, 0xb3, 0xa8, 0x4e, 0x22, 
							0xf5, 0x22, 0x87, 0x4c, 0x40, 0x00, 0x00, 0x46, 
							0x03, 0x02, 0xab, 0x39, 0xbb, 0x97, 0xe5, 0x01, 
							0x3a, 0x46, 0x1c, 0x28, 0x5b, 0xab, 0xfa, 0x9a, 
							0xab, 0x2e, 0x71, 0x39, 0x66, 0xa0, 0xd7, 0xb9, 
							0xd8, 0x41, 0xa7, 0xa0, 0x84, 0xa9, 0xf3, 0x1b, 
							0x03, 0x7f, 0xa8, 0x28, 0xa2, 0xd3, 0x64, 0xc2, 
							0x3d, 0x20, 0xe0, 0xb1, 0x41, 0x12, 0x6c, 0x2f, 
							0xc5, 0xbb, 0xc3, 0xba, 0x69, 0x73, 0x52, 0x64, 
							0xf6, 0x30, 0x81, 0xf4, 0x3f, 0xc2, 0x19, 0x6a, 
							0x68, 0x61, 0x93, 0x08, 0xc0, 0x0a, 0xab, 0x00 };

	int table_id = maat_get_table_id(maat_inst, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, district_str,
                                           strlen(district_str));
	ASSERT_EQ(ret, 0);
    
	ret = maat_scan_string(maat_inst, table_id, (char *)udp_payload_not_hit,
                           sizeof(udp_payload_not_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK); //maat-v3 consider as half hit, it's unreasonable

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, Expr8) {
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    char scan_data[128] = "string1, string2, string3, string4, string5, "
                          "string6, string7, string8";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, HexBinCaseSensitive) {
    const char *table_name = "KEYWORDS_TABLE";
	const char *scan_data1 = "String TeST should not hit.";
	const char *scan_data2 = "String TEST should hit";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 206);
    EXPECT_EQ(results[1], 191);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

TEST_F(HsStringScan, HexbinCombineString)
{
    const char *table_name = "KEYWORDS_TABLE";
	const char *scan_data1 = "abcd ABCD";
	const char *scan_data2 = "abcd abCD";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 236);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

TEST_F(HsStringScan, BugReport20190325) {
    unsigned char scan_data[] = {/* Packet 1 */
                                 0x01, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00,
                                 0x00, 0xf4, 0x01, 0x00, 0x00, 0x32, 0x00, 0x00,
                                 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x2d, 0x3d, 0x3d, 0x20, 0x48, 0x3d, 0x48, 0x20,
                                 0x3d, 0x3d, 0x2d, 0x3a, 0x00, 0x02, 0x00, 0x00,
                                 0x00, 0x07, 0x0e, 0x00, 0x00, 0xe8, 0x03, 0x00,
                                 0x00, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x33,
                                 0x2e, 0x31, 0x39, 0x2e, 0x30, 0x2d, 0x31, 0x35,
                                 0x2d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63,
                                 0x00, 0x31, 0x3a, 0x47, 0x32, 0x2e, 0x34, 0x30,
                                 0x00};
    const char *table_name = "TROJAN_PAYLOAD";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_string(maat_inst, table_id, (char *)scan_data,
                               sizeof(scan_data), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 150);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, PrefixAndSuffix) {
    const char *hit_twice = "ceshi3@mailhost.cn";
	const char *hit_suffix = "11111111111ceshi3@mailhost.cn";
	const char *hit_prefix = "ceshi3@mailhost.cn11111111111";
    const char *cont_sz_table_name = "CONTENT_SIZE";
    const char *mail_addr_table_name = "MAIL_ADDR";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    int thread_id = 0;

    int cont_sz_table_id = maat_get_table_id(maat_inst, cont_sz_table_name);
    ASSERT_GT(cont_sz_table_id, 0);

    int mail_addr_table_id = maat_get_table_id(maat_inst, mail_addr_table_name);
    ASSERT_GT(mail_addr_table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_integer(maat_inst, cont_sz_table_id, 2015, results,
                                ARRAY_SIZE, &n_hit_result, state);
    
    ret = maat_scan_not_logic(maat_inst, cont_sz_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, mail_addr_table_id, hit_twice,
                           strlen(hit_twice), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 151);
    EXPECT_EQ(results[1], 152);

    ret = maat_scan_not_logic(maat_inst, mail_addr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);
    ret = maat_scan_string(maat_inst, mail_addr_table_id, hit_suffix,
                           strlen(hit_suffix), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 151);

    ret = maat_scan_not_logic(maat_inst, mail_addr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_integer(maat_inst, cont_sz_table_id, 2015, results,
                                ARRAY_SIZE, &n_hit_result, state);

    ret = maat_scan_not_logic(maat_inst, cont_sz_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, mail_addr_table_id, hit_prefix,
                           strlen(hit_prefix), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 152);

    ret = maat_scan_not_logic(maat_inst, mail_addr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, MaatUnescape) {
    const char *scan_data = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 132);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, OffsetChunk64) {
    const char *table_name = "IMAGE_FP";
	const char *file_name = "./testdata/mesa_logo.jpg";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp==NULL);

    char scan_data[64];
    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
	ASSERT_TRUE(sp != NULL);

    int ret = 0;
    int read_size = 0;
    int pass_flag = 0;
    while (0 == feof(fp)) {
        read_size = fread(scan_data, 1, sizeof(scan_data), fp);
        ret = maat_stream_scan(sp, scan_data, read_size, results,
                               ARRAY_SIZE, &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break;
        }

        ret = maat_scan_not_logic(maat_inst, table_id, results,
                                  ARRAY_SIZE, &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break; 
        }
    }
    EXPECT_EQ(pass_flag, 1);
    EXPECT_EQ(results[0], 136);
    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, OffsetChunk1460) {
    const char *table_name = "IMAGE_FP";
	const char *file_name = "./testdata/mesa_logo.jpg";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp==NULL);

    char scan_data[1460];
    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
	ASSERT_TRUE(sp != NULL);

    int ret = 0;
    int read_size = 0;
    int pass_flag = 0;
    while (0 == feof(fp)) {
        read_size = fread(scan_data, 1, sizeof(scan_data), fp);
        ret = maat_stream_scan(sp, scan_data, read_size, results,
                               ARRAY_SIZE, &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break;
        }

        ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break; 
        }
    }
    EXPECT_EQ(pass_flag, 1);
    EXPECT_EQ(results[0], 136);
    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, StreamScanUTF8) {
    const char *table_name = "TROJAN_PAYLOAD";
	const char* file_name = "./testdata/jd.com.html";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    char scan_data[2048];
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp == NULL);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
    ASSERT_FALSE(sp == NULL);

    int pass_flag = 0;
    while (0 == feof(fp)) {
		size_t read_size = fread(scan_data, 1, sizeof(scan_data), fp);
		int ret = maat_stream_scan(sp, scan_data, read_size, results,
                                   ARRAY_SIZE, &n_hit_result, state);
		if (ret == MAAT_SCAN_HIT) {
			pass_flag = 1;
			break;
		}

        ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                                  &n_hit_result, state);
        if (ret == MAAT_SCAN_HIT) {
			pass_flag = 1;
			break;
		}
	}

    EXPECT_EQ(pass_flag, 1);
	EXPECT_EQ(results[0], 157);

    maat_stream_free(sp);
    fclose(fp);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, StreamInput) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *table_name = "HTTP_URL";
    const char *scan_data1 = "www.cyberessays.com";
	const char *scan_data2 = "http://www.cyberessays.com/search_results.php?"
                            "action=search&query=yulingjing,abckkk,1234567";

	int table_id = maat_get_table_id(maat_inst, table_name);
	ASSERT_GT(table_id, 0);

	struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
	ASSERT_TRUE(sp != NULL);

	int ret = maat_stream_scan(sp, scan_data1, strlen(scan_data1), results,
                               ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
	maat_stream_free(sp);

	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 125);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(HsStringScan, dynamic_config) {
    const char *table_name = "HTTP_URL";
    char data[128] = "hello world, welcome to maat version4, it's funny.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = HsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_inst, table_id, data, strlen(data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    const char *rule_table_name = "RULE_DEFAULT";
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table add line */
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object_id, rule_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    /* expr table add line */
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    const char *keywords = "welcome to maat";

    /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                              object_id, keywords, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 3);

    ret = maat_scan_string(maat_inst, table_id, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_DEL, item_id,
                              object_id, keywords, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table del line */
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL,
                                       object_id, rule_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    /* rule table del line */
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_id, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

class RsStringScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);
        maat_options_set_hit_path_enabled(opts);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in RsStringScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsStringScan::_shared_maat_inst;
struct log_handle *RsStringScan::logger;

TEST_F(RsStringScan, ScanDataOnlyOneByte) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;

    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char scan_data = 0x20;

    int ret = maat_scan_string(maat_inst, table_id, &scan_data, sizeof(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, Full) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "http://www.cyberessays.com/search_results.php?"
                            "action=search&query=username,abckkk,1234567";

    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 125);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, Regex) {
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *cookie = "Cookie: Txa123aheadBCAxd";
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ret = maat_scan_string(maat_inst, table_id, cookie, strlen(cookie),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 148);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, RegexUnicode) {
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "String contains É";
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 229);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, BackslashR_N_Escape) {
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    const char *payload = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ret = maat_scan_string(maat_inst, table_id, payload, strlen(payload),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 225);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, BackslashR_N_Escape_IncUpdate) {
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    const char *payload = "html>\\r\\n";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ret = maat_scan_string(maat_inst, table_id, payload, strlen(payload),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 234);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_reset(state);

    const char *rule_table_name = "RULE_DEFAULT";
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table add line */
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object_id, rule_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    /* expr table add line */
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    const char *keywords = "html>\\\\r\\\\n";

    /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                              object_id, keywords, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 3);

    ret = maat_scan_string(maat_inst, table_id, payload, strlen(payload), 
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 234);
    EXPECT_EQ(results[1], rule_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, BackslashCtrlCharactor)
{
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    const char *payload = "()abc^$def|";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ret = maat_scan_string(maat_inst, table_id, payload, strlen(payload),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 235);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, ExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *district_str1 ="HTTP URL";
	const char *district_str2 ="我的diStricT";
	const char *scan_data1 = "http://www.cyberessays.com/search_results.php?"
                             "action=search&query=abckkk,1234567";
	const char *scan_data2 = "Addis Sapphire Hotel";
    const char *table_name = "HTTP_SIGNATURE";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

	int ret = maat_scan_string(maat_inst, table_id, scan_data1,
                               strlen(scan_data1), results, ARRAY_SIZE,
                               &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_ERR);//Should return error for district not setting.

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_state_set_scan_district(state, table_id, district_str1,
                                       strlen(district_str1));
	ASSERT_EQ(ret, 0);

	ret = maat_scan_string(maat_inst, table_id, scan_data1,
                           strlen(scan_data1), results, ARRAY_SIZE,
                           &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
	EXPECT_EQ(results[0], 128);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_reset(state);
	ret = maat_state_set_scan_district(state, table_id, district_str2,
                                       strlen(district_str2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_inst, table_id, scan_data2,
                           strlen(scan_data2), results, ARRAY_SIZE,
                           &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
	EXPECT_EQ(results[0], 190);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, ExprPlusWithOffset)
{
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
	const char *district_str = "Payload";
	unsigned char udp_payload_not_hit[] = { /* Stun packet */
							0x00, 0x03, 0x00, 0x4a, 0x21, 0x12, 0xa4, 0x42, 
							0x4f, 0xc2, 0xc2, 0x70, 0xb3, 0xa8, 0x4e, 0x22, 
							0xf5, 0x22, 0x87, 0x4c, 0x40, 0x00, 0x00, 0x46, 
							0x03, 0x02, 0xab, 0x39, 0xbb, 0x97, 0xe5, 0x01, 
							0x3a, 0x46, 0x1c, 0x28, 0x5b, 0xab, 0xfa, 0x9a, 
							0xab, 0x2e, 0x71, 0x39, 0x66, 0xa0, 0xd7, 0xb9, 
							0xd8, 0x41, 0xa7, 0xa0, 0x84, 0xa9, 0xf3, 0x1b, 
							0x03, 0x7f, 0xa8, 0x28, 0xa2, 0xd3, 0x64, 0xc2, 
							0x3d, 0x20, 0xe0, 0xb1, 0x41, 0x12, 0x6c, 0x2f, 
							0xc5, 0xbb, 0xc3, 0xba, 0x69, 0x73, 0x52, 0x64, 
							0xf6, 0x30, 0x81, 0xf4, 0x3f, 0xc2, 0x19, 0x6a, 
							0x68, 0x61, 0x93, 0x08, 0xc0, 0x0a };
	unsigned char udp_payload_hit[] = { /* Stun packet */					//rule:"1-1:03&9-10:2d&14-16:2d34&19-21:2d&24-25:2d"
							0x00, 0x03, 0x00, 0x4a, 0x21, 0x12, 0xa4, 0x42, //1-1:03
							0x4f, 0xc2, 0x2d, 0x70, 0xb3, 0xa8, 0x4e, 0x2d, //10-10:2d
							0x34, 0x22, 0x87, 0x4c, 0x2d, 0x00, 0x00, 0x46, //15-16:2d34
							0x2d, 0x34, 0xab, 0x39, 0xbb, 0x97, 0xe5, 0x01, //20-20:2d
							0x03, 0x46, 0x1c, 0x28, 0x5b, 0xab, 0xfa, 0x9a, //24-24:2d
							0xab, 0x2e, 0x71, 0x39, 0x66, 0xa0, 0xd7, 0xb9, 
							0xd8, 0x41, 0xa7, 0xa0, 0x84, 0xa9, 0xf3, 0x1b, 
							0x03, 0x7f, 0xa8, 0x28, 0xa2, 0xd3, 0x64, 0xc2, 
							0x3d, 0x20, 0xe0, 0xb1, 0x41, 0x12, 0x6c, 0x2f, 
							0xc5, 0xbb, 0xc3, 0xba, 0x69, 0x73, 0x52, 0x64, 
							0xf6, 0x30, 0x81, 0xf4, 0x3f, 0xc2, 0x19, 0x6a, 
							0x68, 0x61, 0x93, 0x08, 0xc0, 0x0a };

	int table_id = maat_get_table_id(maat_inst, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, district_str,
                                           strlen(district_str));
	EXPECT_EQ(ret, 0);

	ret = maat_scan_string(maat_inst, table_id, (char*)udp_payload_not_hit,
                           sizeof(udp_payload_not_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_scan_string(maat_inst, table_id, (char*)udp_payload_hit,
                           sizeof(udp_payload_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
	EXPECT_EQ(results[0], 149);
	
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, ExprPlusWithHex) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
	const char *scan_data1 = "text/html; charset=UTF-8";
	const char *scan_data2 = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *district_str1 = "Content-Type";
	const char *district_str2 = "User-Agent";

	int table_id = maat_get_table_id(maat_inst, "HTTP_SIGNATURE");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, district_str1,
                                           strlen(district_str1));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 156);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_state_set_scan_district(state, table_id, district_str2,
                                       strlen(district_str2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK); //maat-v3 consider as half hit, it's unreasonable
    
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    table_id = maat_get_table_id(maat_inst, "KEYWORDS_TABLE");
    ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 132);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, ExprAndExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *expr_table_name = "HTTP_URL";
    const char *expr_plus_table_name = "HTTP_SIGNATURE";
    const char *district_str = "I love China";
    const char *scan_data = "today is Monday and yesterday is Tuesday";

    int expr_table_id = maat_get_table_id(maat_inst, expr_table_name);
    int expr_plus_table_id = maat_get_table_id(maat_inst, expr_plus_table_name);

    int ret = maat_scan_string(maat_inst, expr_plus_table_id, scan_data,
                               strlen(scan_data), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_ERR);

    ret = maat_scan_not_logic(maat_inst, expr_plus_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_state_set_scan_district(state, expr_plus_table_id, district_str,
                                       strlen(district_str));
    ASSERT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, expr_plus_table_id, scan_data,
                           strlen(scan_data), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, expr_plus_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, expr_table_id, scan_data,
                           strlen(scan_data), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 195);

    ret = maat_scan_not_logic(maat_inst, expr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, ShouldNotHitExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
	const char *district_str = "tcp.payload";
	unsigned char udp_payload_not_hit[] = { /* Stun packet */
							0x00, 0x03, 0x00, 0x4a, 0x21, 0x12, 0xa4, 0x42, 
							0x4f, 0xc2, 0xc2, 0x70, 0xb3, 0xa8, 0x4e, 0x22, 
							0xf5, 0x22, 0x87, 0x4c, 0x40, 0x00, 0x00, 0x46, 
							0x03, 0x02, 0xab, 0x39, 0xbb, 0x97, 0xe5, 0x01, 
							0x3a, 0x46, 0x1c, 0x28, 0x5b, 0xab, 0xfa, 0x9a, 
							0xab, 0x2e, 0x71, 0x39, 0x66, 0xa0, 0xd7, 0xb9, 
							0xd8, 0x41, 0xa7, 0xa0, 0x84, 0xa9, 0xf3, 0x1b, 
							0x03, 0x7f, 0xa8, 0x28, 0xa2, 0xd3, 0x64, 0xc2, 
							0x3d, 0x20, 0xe0, 0xb1, 0x41, 0x12, 0x6c, 0x2f, 
							0xc5, 0xbb, 0xc3, 0xba, 0x69, 0x73, 0x52, 0x64, 
							0xf6, 0x30, 0x81, 0xf4, 0x3f, 0xc2, 0x19, 0x6a, 
							0x68, 0x61, 0x93, 0x08, 0xc0, 0x0a, 0xab, 0x00 };

	int table_id = maat_get_table_id(maat_inst, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, district_str,
                                           strlen(district_str));
	ASSERT_EQ(ret, 0);
    
	ret = maat_scan_string(maat_inst, table_id, (char *)udp_payload_not_hit,
                           sizeof(udp_payload_not_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK); //maat-v3 consider as half hit, it's unreasonable

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, Expr8) {
    const char *table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int table_id = maat_get_table_id(maat_inst, table_name);
    char scan_data[128] = "string1, string2, string3, string4, string5,"
                          " string6, string7, string8";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, HexBinCaseSensitive) {
    const char *table_name = "KEYWORDS_TABLE";
	const char *scan_data1 = "String TeST should not hit.";
	const char *scan_data2 = "String TEST should hit";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);
    ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 206);
    EXPECT_EQ(results[1], 191);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, HexbinCombineString)
{
    const char *table_name = "KEYWORDS_TABLE";
	const char *scan_data1 = "abcd ABCD";
	const char *scan_data2 = "abcd abCD";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 236);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

TEST_F(RsStringScan, BugReport20190325) {
    unsigned char scan_data[] = {/* Packet 1 */
                                 0x01, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00,
                                 0x00, 0xf4, 0x01, 0x00, 0x00, 0x32, 0x00, 0x00,
                                 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x2d, 0x3d, 0x3d, 0x20, 0x48, 0x3d, 0x48, 0x20,
                                 0x3d, 0x3d, 0x2d, 0x3a, 0x00, 0x02, 0x00, 0x00,
                                 0x00, 0x07, 0x0e, 0x00, 0x00, 0xe8, 0x03, 0x00,
                                 0x00, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x33,
                                 0x2e, 0x31, 0x39, 0x2e, 0x30, 0x2d, 0x31, 0x35,
                                 0x2d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63,
                                 0x00, 0x31, 0x3a, 0x47, 0x32, 0x2e, 0x34, 0x30,
                                 0x00};
    const char *table_name = "TROJAN_PAYLOAD";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_string(maat_inst, table_id, (char *)scan_data,
                               sizeof(scan_data), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 150);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, PrefixAndSuffix) {
    const char *hit_twice = "ceshi3@mailhost.cn";
	const char *hit_suffix = "11111111111ceshi3@mailhost.cn";
	const char *hit_prefix = "ceshi3@mailhost.cn11111111111";
    const char *cont_sz_table_name = "CONTENT_SIZE";
    const char *mail_addr_table_name = "MAIL_ADDR";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    int thread_id = 0;

    int cont_sz_table_id = maat_get_table_id(maat_inst, cont_sz_table_name);
    ASSERT_GT(cont_sz_table_id, 0);

    int mail_addr_table_id = maat_get_table_id(maat_inst, mail_addr_table_name);
    ASSERT_GT(mail_addr_table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_integer(maat_inst, cont_sz_table_id, 2015, results,
                                ARRAY_SIZE, &n_hit_result, state);
    
    ret = maat_scan_not_logic(maat_inst, cont_sz_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, mail_addr_table_id, hit_twice,
                           strlen(hit_twice), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 151);
    EXPECT_EQ(results[1], 152);

    ret = maat_scan_not_logic(maat_inst, mail_addr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);
    ret = maat_scan_string(maat_inst, mail_addr_table_id, hit_suffix,
                           strlen(hit_suffix), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 151);

    ret = maat_scan_not_logic(maat_inst, mail_addr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_integer(maat_inst, cont_sz_table_id, 2015, results,
                                ARRAY_SIZE, &n_hit_result, state);
    
    ret = maat_scan_not_logic(maat_inst, cont_sz_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, mail_addr_table_id, hit_prefix,
                           strlen(hit_prefix), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 152);

    ret = maat_scan_not_logic(maat_inst, mail_addr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, MaatUnescape) {
    const char *scan_data = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 132);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, OffsetChunk64) {
    const char *table_name = "IMAGE_FP";
	const char *file_name = "./testdata/mesa_logo.jpg";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp==NULL);

    char scan_data[64];
    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
	ASSERT_TRUE(sp != NULL);

    int ret = 0;
    int read_size = 0;
    int pass_flag = 0;
    while (0 == feof(fp)) {
        read_size = fread(scan_data, 1, sizeof(scan_data), fp);
        ret = maat_stream_scan(sp, scan_data, read_size,
                                results, ARRAY_SIZE, &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break;
        }

        ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                                  &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break;
        }
    }
    EXPECT_EQ(pass_flag, 1);
    EXPECT_EQ(results[0], 136);

    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, OffsetChunk1460) {
    const char *table_name = "IMAGE_FP";
	const char *file_name = "./testdata/mesa_logo.jpg";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp==NULL);

    char scan_data[1460];
    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
	ASSERT_TRUE(sp != NULL);

    int ret = 0;
    int read_size = 0;
    int pass_flag = 0;
    while (0 == feof(fp)) {
        read_size = fread(scan_data, 1, sizeof(scan_data), fp);
        ret = maat_stream_scan(sp, scan_data, read_size,
                                results, ARRAY_SIZE, &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break;
        }

        ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                                  &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break;
        }
    }

    EXPECT_EQ(pass_flag, 1);
    EXPECT_EQ(results[0], 136);

    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, StreamScanUTF8) {
    const char *table_name = "TROJAN_PAYLOAD";
	const char* file_name = "./testdata/jd.com.html";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    char scan_data[1500];
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp == NULL);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
    ASSERT_FALSE(sp == NULL);

    int pass_flag = 0;
    while (0 == feof(fp)) {
		size_t read_size = fread(scan_data, 1, sizeof(scan_data), fp);
        //read_size can't exceed 1500
		int ret = maat_stream_scan(sp, scan_data, read_size, results,
                                   ARRAY_SIZE, &n_hit_result, state);
		if (ret == MAAT_SCAN_HIT) {
			pass_flag = 1;
			break;
		}

        ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                                  &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break;
        }
	}

    EXPECT_EQ(pass_flag, 1);
	EXPECT_EQ(results[0], 157);

    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, StreamInput) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data1 = "www.cyberessays.com";
	const char *scan_data2 = "http://www.cyberessays.com/search_results.php?"
                             "action=search&query=yulingjing,abckkk,1234567";
	const char *table_name = "HTTP_URL";

	int table_id = maat_get_table_id(maat_inst, table_name);
	ASSERT_GT(table_id, 0);

	struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
	ASSERT_TRUE(sp != NULL);

	int ret = maat_stream_scan(sp, scan_data1, strlen(scan_data1), results,
                               ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
	maat_stream_free(sp);

	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
	EXPECT_EQ(results[0], 125);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(RsStringScan, dynamic_config) {
    const char *table_name = "HTTP_URL";
    char data[128] = "hello world, welcome to maat version4, it's funny.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = RsStringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    int ret = maat_scan_string(maat_inst, table_id, data, strlen(data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_reset(state);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *rule_table_name = "RULE_DEFAULT";
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table add line */
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object_id, rule_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    /* expr table add line */
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    const char *keywords = "welcome to maat";

     /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                              object_id, keywords, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    ret = maat_scan_string(maat_inst, table_id, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /* EXPR_TYPE_AND MATCH_METHOD_SUB*/
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_DEL, item_id,
                              object_id, keywords, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table del line */
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL,
                                       object_id, rule_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    /* rule table del line */
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule_id, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    ret = maat_scan_string(maat_inst, table_id, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

class HsStreamScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        assert(_shared_maat_inst != NULL);
       
        maat_cmd_flushDB(_shared_maat_inst);
        maat_free(_shared_maat_inst);

        maat_options_set_foreign_cont_dir(opts, "./foreign_files/");
        maat_options_set_gc_timeout_ms(opts, 0); // start GC immediately
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
    } 

    static struct maat *_shared_maat_inst;
};

struct maat *HsStreamScan::_shared_maat_inst;

TEST_F(HsStreamScan, dynamic_config) {
    const char *table_name = "HTTP_URL";
    const char *keywords1 = "hello";
    char keyword_buf[128];
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data1 = "www.cyberessays.com";
    const char *scan_data2 = "hello world cyberessays.com/search_results.php?"
                             "action=search&query=yulingjing,abckkk,1234567";
    struct maat *maat_inst = HsStreamScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    // STEP 1: add keywords1 and wait scan stream to hit
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = test_add_expr_command(maat_inst, table_name, rule1_id, 0, keywords1);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    int table_id = maat_get_table_id(maat_inst, table_name);
	ASSERT_GT(table_id, 0);

	struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
	ASSERT_TRUE(sp != NULL);

	ret = maat_stream_scan(sp, scan_data1, strlen(scan_data1), results,
                           ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
	EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    // STEP 2: Inc config update, use same stream to scan and wait old expr_runtime invalid 
    random_keyword_generate(keyword_buf, sizeof(keyword_buf));
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = test_add_expr_command(maat_inst, table_name, rule_id, 0, keyword_buf);
    EXPECT_EQ(ret, 1);

    // Inc config has not yet taken effect, stream scan can hit rule
    ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    maat_state_reset(state);

    sleep(WAIT_FOR_EFFECTIVE_S);

    // Inc config has taken effect, stream reference old expr_runtime, should not hit rule
    ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_stream_free(sp);
    maat_state_free(state);
    sp = NULL;
    state = NULL;
}

class RsStreamScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        assert(_shared_maat_inst != NULL);
       
        maat_cmd_flushDB(_shared_maat_inst);
        maat_free(_shared_maat_inst);

        maat_options_set_foreign_cont_dir(opts, "./foreign_files/");
        maat_options_set_gc_timeout_ms(opts, 0); // start GC immediately
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
    } 

    static struct maat *_shared_maat_inst;
};

struct maat *RsStreamScan::_shared_maat_inst;

TEST_F(RsStreamScan, dynamic_config) {
    const char *scan_data1 = "www.cyberessays.com";
	const char *scan_data2 = "hello world cyberessays.com/search_results.php?"
                             "action=search&query=yulingjing,abckkk,1234567";
    const char *table_name = "HTTP_URL";
    const char *keywords1 = "hello";
    char keyword_buf[128];
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = RsStreamScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    // STEP 1: add keywords1 and wait scan stream to hit
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = test_add_expr_command(maat_inst, table_name, rule1_id, 0, keywords1);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    int table_id = maat_get_table_id(maat_inst, table_name);
	ASSERT_GT(table_id, 0);

	struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
	ASSERT_TRUE(sp != NULL);

	ret = maat_stream_scan(sp, scan_data1, strlen(scan_data1), results,
                           ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
	EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    // STEP 2: Inc config update, use same stream to scan and wait old expr_runtime invalid 
    random_keyword_generate(keyword_buf, sizeof(keyword_buf));
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = test_add_expr_command(maat_inst, table_name, rule_id, 0, keyword_buf);
    EXPECT_EQ(ret, 1);

    // Inc config has not yet taken effect, stream scan can hit rule
    ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    sleep(WAIT_FOR_EFFECTIVE_S);

    // Inc config has taken effect, stream reference old expr_runtime, should not hit rule
    ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_stream_free(sp);
    maat_state_free(state);
    sp = NULL;
    state = NULL;
}

class IPScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in IPScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IPScan::_shared_maat_inst;
struct log_handle *IPScan::logger;

TEST_F(IPScan, IPv4Unspecified) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    char ip_str1[32] = "0.0.0.0";
    uint32_t sip1;
    int ret = inet_pton(AF_INET, ip_str1, &sip1);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv4(maat_inst, table_id, sip1, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, IPv4Broadcast) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    char ip_str1[32] = "255.255.255.255";
    uint32_t sip1;
    int ret = inet_pton(AF_INET, ip_str1, &sip1);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv4(maat_inst, table_id, sip1, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, MatchSingleIPv4) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    char ip_str[32] = "100.64.3.1";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv4(maat_inst, table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 169);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, IPv6Unspecified) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    char ip_str[32] = "::";
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv6(maat_inst, table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 210);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);  
}

TEST_F(IPScan, IPv6Broadcast) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    char ip_str[64] = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF";
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv6(maat_inst, table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);  
}

TEST_F(IPScan, MatchSingleIPv6) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    char ip_str[64] = "1:1:1:1:1:1:1:1";
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    ret = maat_scan_ipv6(maat_inst, table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 210);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, MatchIPv4Range) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    char ip_str[32] = "10.0.7.100";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv4(maat_inst, table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 208);
    EXPECT_EQ(results[1], 154);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}
TEST_F(IPScan, MatchIPv4Port) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    char ip_str[32] = "192.168.30.44";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv4_port(maat_inst, table_id, sip, 443, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_ipv4_port(maat_inst, table_id, sip, 80, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 232);

    maat_state_free(state);
    state = NULL;
}
TEST_F(IPScan, MatchIPv6Range) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    char ip_str[32] = "1001:da8:205:1::101";
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv6(maat_inst, table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 210);
    EXPECT_EQ(results[1], 155);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}
TEST_F(IPScan, MatchIPv6Port) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    char ip_str[32] = "2607:5d00:2:2::32:28";
    int port=443;
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv6_port(maat_inst, table_id, sip, port, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 230);
    EXPECT_EQ(results[1], 210);
    
    maat_state_reset(state);
    //If the port is not present, should not match rules with port range. In this case, only rule 210 "::/0" should match.
    ret = maat_scan_ipv6(maat_inst, table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 210);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, BugReport20210515) {
    const char *table_name = "IP_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    char ip_str[64] = "2409:8915:3430:7e7:8c9b:ff2a:7aa1:e74";
    uint8_t ip_addr[sizeof(struct in6_addr)];
    int ret = inet_pton(AF_INET6, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv6(maat_inst, table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, RuleUpdates) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    char ip_str[32] = "100.100.100.100";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv4(maat_inst, table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    const char *rule_table_name = "RULE_DEFAULT";
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";

     /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                 rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table add line */
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD, 
                                       object_id, rule_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    /* ip table add line */
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                            object_id, "100.100.100.100", 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_ipv4(maat_inst, table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /* ip table del line */
    ret = ip_table_set_line(maat_inst, table_name, MAAT_OP_DEL, item_id,
                            object_id, "100.100.100.100", 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table del line */
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL,
                                       object_id, rule_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    /* rule table del line */
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, 
                                 rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_ipv4(maat_inst, table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, RuleChangeConditionId) {
    //This test is a reproduce of bug OMPUB-1343.
    const char *src_table_name = "ATTRIBUTE_IP_PLUS_SOURCE";
    const char *dst_table_name = "ATTRIBUTE_IP_PLUS_DESTINATION";
    const char *phy_ip_table_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;
    int ret;

    const char *rule_table_name = "RULE_DEFAULT";
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";

     /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                 rule_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table add line */
    long long object_id1 = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD, 
                                       object_id1, rule_id, 0, src_table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    /* ip table add line */
    long long item_id1 = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_inst, phy_ip_table_name, MAAT_OP_ADD, item_id1,
                            object_id1, "1.1.1.1", 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table add line */
    long long object_id2 = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD, 
                                       object_id2, rule_id, 0, dst_table_name, 2, 0);
    EXPECT_EQ(ret, 1);

    /* ip table add line */
    long long item_id2 = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_inst, phy_ip_table_name, MAAT_OP_ADD, item_id2,
                            object_id2, "11.11.11.11", 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    int src_table_id = maat_get_table_id(maat_inst, src_table_name);
    int dst_table_id = maat_get_table_id(maat_inst, dst_table_name);
    char sip1_str[32] = "1.1.1.1";
    char sip2_str[32] = "2.2.2.2";
    char dip_str[32] = "11.11.11.11";
    uint32_t sip1;
    uint32_t sip2;
    uint32_t dip;
    
    ret = inet_pton(AF_INET, sip1_str, &sip1);
    EXPECT_EQ(ret, 1);

    ret = inet_pton(AF_INET, sip2_str, &sip2);
    EXPECT_EQ(ret, 1);

    ret = inet_pton(AF_INET, dip_str, &dip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    ret = maat_scan_ipv4(maat_inst, dst_table_id, dip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, 
                                 rule_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                 rule_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);


    /* object2rule table del line */
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL,
                                       object_id1, rule_id, 0, src_table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL,
                                       object_id2, rule_id, 0, dst_table_name, 2, 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object_id1, rule_id, 0, src_table_name, 2, 0);
    EXPECT_EQ(ret, 1); 

    const char *app_id_table_name = "APP_ID";
    int app_id_table_id = maat_get_table_id(maat_inst, app_id_table_name);
    /* object2rule table add line */
    long long object_id3 = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD, 
                                       object_id3, rule_id, 0, app_id_table_name, 1, 0);
    EXPECT_EQ(ret, 1);
    

    sleep(WAIT_FOR_EFFECTIVE_S);

    //maat_state_reset(state);
    n_hit_result = 0;

    struct maat_hit_object object;
    object.item_id = 0;
    object.attribute_id = 0;
    object.object_id = object_id3;

    ret = maat_scan_object(maat_inst, app_id_table_id, &object, 1, results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_ipv4(maat_inst, src_table_id, sip2, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);

    maat_state_free(state);
    state = NULL;
}

class IntervalScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in IntervalScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_inst);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IntervalScan::_shared_maat_inst;
struct log_handle *IntervalScan::logger;

TEST_F(IntervalScan, IntegerRange) {	
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "CONTENT_SIZE";
    struct maat *maat_inst = IntervalScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    unsigned int scan_data1 = 2015;

	int ret = maat_scan_integer(maat_inst, table_id, scan_data1, results,
                                ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_reset(state);

    unsigned int scan_data2 = 300;
    ret = maat_scan_integer(maat_inst, table_id, scan_data2, results,
                            ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(IntervalScan, SingleInteger) {	
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "CONTENT_SIZE";
    struct maat *maat_inst = IntervalScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    unsigned int scan_data1 = 3000;

	int ret = maat_scan_integer(maat_inst, table_id, scan_data1, results,
                                ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 218);
    
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(IntervalScan, IntervalPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "INTERGER_PLUS";
    struct maat *maat_inst = IntervalScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    const char *district_str = "interval.plus";

    int ret = maat_state_set_scan_district(state, table_id, district_str,
                                           strlen(district_str));
    EXPECT_EQ(ret, 0);

    unsigned int scan_data1 = 2020;
	ret = maat_scan_integer(maat_inst, table_id, scan_data1, results,
                            ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 209);
    EXPECT_EQ(results[1], 179);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

class ObjectScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in ObjectScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_inst);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *ObjectScan::_shared_maat_inst;
struct log_handle *ObjectScan::logger;

TEST_F(ObjectScan, PhysicalTable) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = ObjectScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GE(table_id, 0);

    struct maat_hit_object hit_object;
    hit_object.object_id = 247;
    hit_object.attribute_id = table_id;
    int ret = maat_scan_object(maat_inst, table_id, &hit_object, 1, results,
                              ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 226);

    maat_state_free(state);
    state = NULL;
    sleep(2);
}

TEST_F(ObjectScan, Attribute) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "HTTP_RESPONSE_KEYWORDS";
    struct maat *maat_inst = ObjectScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GE(table_id, 0);

    struct maat_hit_object hit_object;
    hit_object.object_id = 259;
    hit_object.attribute_id = table_id;
    int ret = maat_scan_object(maat_inst, table_id, &hit_object, 1, results,
                              ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 233);

    maat_state_free(state);
    state = NULL;
    sleep(2);
}

TEST_F(ObjectScan, SetScanRuleTable) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = ObjectScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GE(table_id, 0);

    const char *rule_table_name = "RULE_FIREWALL_CONJUNCTION";
    int rule_table_id = maat_get_table_id(maat_inst, rule_table_name);

    int ret = maat_state_set_scan_rule_table(state, rule_table_id);
    EXPECT_EQ(ret, 0);

    struct maat_hit_object hit_object;
    hit_object.object_id = 248;
    hit_object.attribute_id = table_id;
    ret = maat_scan_object(maat_inst, table_id, &hit_object, 1, results,
                          ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 227);

    maat_state_free(state);
    state = NULL;
    sleep(2);
}

class NOTLogic : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in NOTLogic failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_inst);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *NOTLogic::_shared_maat_inst;
struct log_handle *NOTLogic::logger;

TEST_F(NOTLogic, OneRegion) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-143.";
	const char *string_should_not_hit = "This string contains both must-contained-string-of-rule-143 "
                                        "and must-not-contained-string-of-rule-143.";
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "HTTP_URL_FILTER";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

	int ret = maat_scan_string(maat_inst, table_id, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
						
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 143);

    maat_state_reset(state);
	
	ret = maat_scan_string(maat_inst, table_id, string_should_not_hit,
                           strlen(string_should_not_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    
	maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanNotAtLast) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-144.";
	const char *string_should_not_hit = "This string contains both must-contained-string-of-rule-144 "
                                        "and must-not-contained-string-of-rule-144.";
    const char *string_contain_nothing = "This string contains nothing.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *hit_table_name = "HTTP_URL_FILTER";
    const char *not_hit_table_name = "HTTP_RESPONSE_KEYWORDS";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int hit_table_id = maat_get_table_id(maat_inst, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    // scan string_should_hit(HTTP_URL_FILTER) & string_should_not_hit(HTTP_RESPONSE_KEYWORDS) => not hit rule
    int ret = maat_scan_string(maat_inst, hit_table_id, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int not_hit_table_id =  maat_get_table_id(maat_inst, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

    ret = maat_scan_string(maat_inst, not_hit_table_id, string_should_not_hit,
                           strlen(string_should_not_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, not_hit_table_id, string_contain_nothing,
                           strlen(string_contain_nothing), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //scan string_should_hit(HTTP_URL_FILTER) & nothing(HTTP_RESPONSE_KEYWORDS) => hit rule144
    ret = maat_scan_string(maat_inst, hit_table_id, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, not_hit_table_id, string_contain_nothing,
                           strlen(string_contain_nothing), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 144);
 
    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanIrrelavantAtLast) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-144.";
	const char *string_irrelevant = "This string contains nothing to hit.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *hit_table_name = "HTTP_URL_FILTER";
    const char *not_hit_table_name = "HTTP_RESPONSE_KEYWORDS";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int hit_table_id = maat_get_table_id(maat_inst, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    int ret = maat_scan_string(maat_inst, hit_table_id, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int not_hit_table_id = maat_get_table_id(maat_inst, not_hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    ret = maat_scan_string(maat_inst, not_hit_table_id, string_irrelevant,
                           strlen(string_irrelevant), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 144);
    
    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanHitAtLastEmptyExpr) {
    const char *string_should_not_hit = "This string should not hit.";
	const char *string_match_no_region = "This string is matched against a empty table.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *not_hit_table_name = "HTTP_URL_FILTER";
    const char *hit_table_name = "IP_PLUS_CONFIG";
    const char *empty_table_name = "EMPTY_KEYWORD";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int not_hit_table_id = maat_get_table_id(maat_inst, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

    int ret = maat_scan_string(maat_inst, not_hit_table_id, string_should_not_hit,
                               strlen(string_should_not_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.8.186", &sip);

    int hit_table_id = maat_get_table_id(maat_inst, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    ret = maat_scan_ipv4(maat_inst, hit_table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 186);

    ret = maat_scan_not_logic(maat_inst, hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int empty_table_id = maat_get_table_id(maat_inst, empty_table_name);
    ASSERT_GT(empty_table_id, 0);

    ret = maat_scan_string(maat_inst, empty_table_id, string_match_no_region, 
                           strlen(string_match_no_region), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, empty_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanHitAtLastEmptyInteger) {
    const char *string_should_not_hit = "This string should not hit.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *not_hit_table_name = "HTTP_URL_FILTER";
    const char *hit_table_name = "IP_PLUS_CONFIG";
    const char *empty_table_name = "EMPTY_INTERGER";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int not_hit_table_id = maat_get_table_id(maat_inst, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

    int ret = maat_scan_string(maat_inst, not_hit_table_id, string_should_not_hit, 
                               strlen(string_should_not_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.8.187", &sip);

    int hit_table_id = maat_get_table_id(maat_inst, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    ret = maat_scan_ipv4(maat_inst, hit_table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 187);

    ret = maat_scan_not_logic(maat_inst, hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int empty_table_id = maat_get_table_id(maat_inst, empty_table_name);
    ASSERT_GT(empty_table_id, 0);

    ret = maat_scan_integer(maat_inst, empty_table_id, 2015,
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, empty_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanNotIP) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-145.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *hit_table_name = "HTTP_URL";
    const char *not_hit_table_name = "ATTRIBUTE_IP_CONFIG";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int hit_table_id = maat_get_table_id(maat_inst, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    // scan string_should_hit(HTTP_URL) & hit ip(ATTRIBUTE_IP_CONFIG) => not hit rule
    int ret = maat_scan_string(maat_inst, hit_table_id, string_should_hit, 
                               strlen(string_should_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.6.205", &sip);

    int not_hit_table_id = maat_get_table_id(maat_inst, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

    ret = maat_scan_ipv4(maat_inst, not_hit_table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 145);

    maat_state_reset(state);

    // scan string_should_hit(HTTP_URL) & not hit ip(ATTRIBUTE_IP_CONFIG) => hit rule145
    ret = maat_scan_string(maat_inst, hit_table_id, string_should_hit, 
                               strlen(string_should_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    inet_pton(AF_INET, "10.0.6.201", &sip);
    ret = maat_scan_ipv4(maat_inst, not_hit_table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK); 

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanNotWithDistrict) {
    const char *string1 = "This string ONLY contains scan_with_district_221.";
    const char *string2 = "This string contains User-Agent:Mozilla/5.0";
    const char *string3 = "This string contains User-Agent:Chrome";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *url_table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_REQUEST_HEADER";
    const char *district_str1 = "User-Agent";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int url_table_id = maat_get_table_id(maat_inst, url_table_name);
    ASSERT_GT(url_table_id, 0);

    // scan string1(HTTP_URL) & string2(HTTP_REQUEST_HEADER) => not hit rule
    int ret = maat_scan_string(maat_inst, url_table_id, string1, 
                               strlen(string1), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int attribute_id = maat_get_table_id(maat_inst, attribute_name);
    ASSERT_GT(attribute_id, 0);

    ret = maat_state_set_scan_district(state, attribute_id, district_str1,
                                       strlen(district_str1));
    ASSERT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, attribute_id, string2, strlen(string2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, attribute_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    // scan string1(HTTP_URL) & string3(HTTP_REQUEST_HEADER) => hit rule221
    ret = maat_scan_string(maat_inst, url_table_id, string1, 
                           strlen(string1), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_state_set_scan_district(state, attribute_id, district_str1,
                                       strlen(district_str1));
    ASSERT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, attribute_id, string3, strlen(string3),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, attribute_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 221);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, NotUrlAndNotIp) {
    const char *string_should_half_hit = "This string ONLY contains must-contained-string-of-rule-146.";
    const char *string_should_not_hit = "This string contains must-contained-string-of-rule-146 and "
                                         "must-contained-not-string-of-rule-146.";
    const char *string_nothing = "This string contain nothing";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *url_table_name = "HTTP_URL_FILTER";
    const char *ip_table_name = "ATTRIBUTE_IP_CONFIG";
    const char *http_table_name = "HTTP_RESPONSE_KEYWORDS";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int url_table_id = maat_get_table_id(maat_inst, url_table_name);
    ASSERT_GT(url_table_id, 0);

    //scan string_should_half_hit(HTTP_URL_FILTER) & hit ip(ATTRIBUTE_IP_CONFIG) => not hit rule
    int ret = maat_scan_string(maat_inst, url_table_id, string_should_half_hit, 
                               strlen(string_should_half_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.6.201", &sip);

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    // scan string_should_half_hit(HTTP_RESPONSE_KEYWORDS) & not hit ip(ATTRIBUTE_IP_CONFIG) => not hit rule
    int http_table_id = maat_get_table_id(maat_inst, http_table_name);
    ASSERT_GT(http_table_id, 0);

    ret = maat_scan_string(maat_inst, http_table_id, string_should_not_hit, 
                           strlen(string_should_not_hit), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT); 
    
    ret = maat_scan_not_logic(maat_inst, http_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    inet_pton(AF_INET, "10.1.0.0", &sip);
    ret = maat_scan_ipv4(maat_inst, ip_table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    // scan scan string_should_half_hit(HTTP_URL_FILTER) & not hit ip(ATTRIBUTE_IP_CONFIG) => hit rule146
    ret = maat_scan_string(maat_inst, url_table_id, string_should_half_hit, 
                               strlen(string_should_half_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, http_table_id, string_nothing, 
                           strlen(string_nothing), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK); 

    ret = maat_scan_not_logic(maat_inst, http_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    
    inet_pton(AF_INET, "10.1.0.0", &sip);
    ret = maat_scan_ipv4(maat_inst, ip_table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 146);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, NotPhysicalTable) {
    const char *string1 = "This string ONLY contains not_logic_rule_224_1.";
    const char *string2 = "This string ONLY contains not_logic_rule_224_2.";
    const char *string3 = "This string ONLY contains nothing.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *phy_table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "HTTP_RESPONSE_KEYWORDS";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int phy_table_id = maat_get_table_id(maat_inst, phy_table_name);
    ASSERT_GT(phy_table_id, 0);

    int attribute_id = maat_get_table_id(maat_inst, attribute_name);
    ASSERT_GT(attribute_id, 0);

    // scan hit string1(KEYWORDS_TABLE) & hit string2(HTTP_RESPONSE_KEYWORDS) => not hit rule
    int ret = maat_scan_string(maat_inst, phy_table_id, string1, 
                               strlen(string1), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, phy_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, attribute_id, string2, strlen(string2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    //scan not hit string1(KEYWORDS_TABLE) & hit string2(HTTP_RESPONSE_KEYWORDS) => hit rule224
    ret = maat_scan_string(maat_inst, phy_table_id, string3, strlen(string3),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, phy_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, attribute_id, string2, strlen(string2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT); 
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 224);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, EightNotCondition) {
    const char *string_nothing = "This string contain nothing";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name1 = "HTTP_RESPONSE_KEYWORDS_1";
    const char *table_name2 = "HTTP_RESPONSE_KEYWORDS_2";
    const char *table_name3 = "HTTP_RESPONSE_KEYWORDS_3";
    const char *table_name4 = "HTTP_RESPONSE_KEYWORDS_4";
    const char *table_name5 = "HTTP_RESPONSE_KEYWORDS_5";
    const char *table_name6 = "HTTP_RESPONSE_KEYWORDS_6";
    const char *table_name7 = "HTTP_RESPONSE_KEYWORDS_7";
    const char *table_name8 = "HTTP_RESPONSE_KEYWORDS_8";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id1 = maat_get_table_id(maat_inst, table_name1);
    ASSERT_GT(table_id1, 0);

    int ret = maat_scan_string(maat_inst, table_id1, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id1, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int table_id2 = maat_get_table_id(maat_inst, table_name2);
    ASSERT_GT(table_id2, 0);

    ret = maat_scan_string(maat_inst, table_id2, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id2, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int table_id3 = maat_get_table_id(maat_inst, table_name3);
    ASSERT_GT(table_id3, 0);

    ret = maat_scan_string(maat_inst, table_id3, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id3, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    
    int table_id4 = maat_get_table_id(maat_inst, table_name4);
    ASSERT_GT(table_id4, 0);

    ret = maat_scan_string(maat_inst, table_id4, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id4, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int table_id5 = maat_get_table_id(maat_inst, table_name5);
    ASSERT_GT(table_id5, 0);

    ret = maat_scan_string(maat_inst, table_id5, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id5, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int table_id6 = maat_get_table_id(maat_inst, table_name6);
    ASSERT_GT(table_id6, 0);

    ret = maat_scan_string(maat_inst, table_id6, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id6, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int table_id7 = maat_get_table_id(maat_inst, table_name7);
    ASSERT_GT(table_id7, 0);

    ret = maat_scan_string(maat_inst, table_id7, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id7, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int table_id8 = maat_get_table_id(maat_inst, table_name8);
    ASSERT_GT(table_id8, 0);

    ret = maat_scan_string(maat_inst, table_id8, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK); 

    ret = maat_scan_not_logic(maat_inst, table_id8, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 147);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, NotConditionAndExcludeObject1) {
    const char *string_should_not_hit = "This string ONLY contains must-contained-string-of-rule-200 and "
                                         "must-not-contained-string-of-rule-200";
    const char *string_should_half_hit = "This string ONLY contains must-contained-string-of-rule-200";
    const char *string_nothing = "This string contain nothing";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *url_table_name = "HTTP_URL_FILTER";
    const char *http_table_name = "HTTP_RESPONSE_KEYWORDS";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int url_table_id = maat_get_table_id(maat_inst, url_table_name);
    ASSERT_GT(url_table_id, 0);

    int ret = maat_scan_string(maat_inst, url_table_id, string_should_not_hit, 
                               strlen(string_should_not_hit), results,
                               ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, url_table_id, string_should_half_hit, 
                               strlen(string_should_half_hit), results,
                               ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int http_table_id = maat_get_table_id(maat_inst, http_table_name);
    ASSERT_GT(http_table_id, 0);

    ret = maat_scan_string(maat_inst, http_table_id, string_nothing, 
                           strlen(string_nothing), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, http_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 216);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, NotConditionAndExcludeObject2) {
    const char *string1 = "This string ONLY contains mail.string-of-rule-217.com";
    const char *string2= "This string ONLY contains www.string-of-rule-217.com";
    const char *string_keywords = "This string contain keywords-for-rule-217";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *url_table_name = "HTTP_URL_FILTER";
    const char *http_table_name = "HTTP_RESPONSE_KEYWORDS";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int url_table_id = maat_get_table_id(maat_inst, url_table_name);
    ASSERT_GT(url_table_id, 0);

    int http_table_id = maat_get_table_id(maat_inst, http_table_name);
    ASSERT_GT(http_table_id, 0);

    int ret = maat_scan_string(maat_inst, http_table_id, string_keywords,
                               strlen(string_keywords), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, http_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, url_table_id, string1, strlen(string1),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = maat_scan_string(maat_inst, http_table_id, string_keywords,
                               strlen(string_keywords), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, http_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, url_table_id, string2, strlen(string2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 217);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, SingleNotCondition) {
    const char *string_nothing = "nothing string";
    const char *string_should_hit = "string has not_logic_keywords_222";
    const char *table_name = "HTTP_NOT_LOGIC_1";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    //string_should_hit(HTTP_NOT_LOGIC_1) => not hit rule
    int ret = maat_scan_string(maat_inst, table_id, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //string nothing(HTTP_NOT_LOGIC_1) => hit rule222
    ret = maat_scan_string(maat_inst, table_id, string_nothing, strlen(string_nothing),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 222); 

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, MultiNotConditions) {
    const char *string_nothing = "nothing string";
    const char *string1 = "string has not_logic_rule_223_1";
    const char *string2 = "string has not_logic_rule_223_1";
    const char *string3 = "string has not_logic_rule_223_1";
    const char *table_name = "HTTP_NOT_LOGIC";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    // rule223 = !string1 & !string2 & !string3
    //Case1: scan string1 & !string2 & !string3
    int ret = maat_scan_string(maat_inst, table_id, string1, strlen(string1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, table_id, string_nothing, strlen(string_nothing),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //Case2: scan !string1 & string2 & !string3
    ret = maat_scan_string(maat_inst, table_id, string_nothing, strlen(string_nothing),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_id, string2, strlen(string2),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //Case3: scan !string1 & !string2 & string3
    ret = maat_scan_string(maat_inst, table_id, string_nothing, strlen(string_nothing),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_id, string3, strlen(string3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);
    
    //Case4: scan !string1 & !string2 & !string3
    ret = maat_scan_string(maat_inst, table_id, string_nothing, strlen(string_nothing),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 223); 

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, MultiObjectsInOneNotCondition) {
    const char *src_asn1 = "AS1234";
    const char *src_asn2 = "AS6789";
    const char *src_asn3 = "AS9001";
    const char *src_asn_nothing = "nothing string";
    const char *dst_asn = "AS2345";
    const char *src_asn_table_name = "ASN_NOT_LOGIC";
    const char *dst_asn_table_name = "DESTINATION_IP_ASN";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //--------------------------------------
	//			Source ASN1 & Dest ASN => not hit rule
	//--------------------------------------
    int src_table_id = maat_get_table_id(maat_inst, src_asn_table_name);
    ASSERT_GT(src_table_id, 0);

    int ret = maat_scan_string(maat_inst, src_table_id, src_asn1, strlen(src_asn1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);                          

    int dst_table_id = maat_get_table_id(maat_inst, dst_asn_table_name);
    ASSERT_GT(dst_table_id, 0);

    ret = maat_scan_string(maat_inst, dst_table_id, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    //--------------------------------------
	//			Source ASN2 & Dest ASN => not hit rule
	//--------------------------------------
    ret = maat_scan_string(maat_inst, src_table_id, src_asn2, strlen(src_asn2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, dst_table_id, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    //--------------------------------------
	//			Source ASN3 & Dest ASN => not hit rule
	//--------------------------------------
    ret = maat_scan_string(maat_inst, src_table_id, src_asn3, strlen(src_asn3),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, dst_table_id, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    // Source nothing & Dest ASN => hit rule177
    ret = maat_scan_string(maat_inst, src_table_id, src_asn_nothing,
                           strlen(src_asn_nothing),results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, src_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, dst_table_id, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 177);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, MultiLiteralsInOneNotCondition) {
    const char *src_asn1 = "AS1234";
    const char *src_asn2 = "AS6789";
    const char *src_nothing = "nothing";
    const char *my_county = "Greece.Sparta";
    const char *ip_table_name = "IP_PLUS_CONFIG";
    const char *src_asn_table_name = "SOURCE_IP_ASN";
    const char *ip_geo_table_name = "SOURCE_IP_GEO";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int src_table_id = maat_get_table_id(maat_inst, src_asn_table_name);
    ASSERT_GT(src_table_id, 0);

    int ip_geo_table_id = maat_get_table_id(maat_inst, ip_geo_table_name);
    ASSERT_GT(ip_geo_table_id, 0);

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0); 

    //-------------------------------------------
	//			Source ASN1 & IP Geo
	//-------------------------------------------
    int ret = maat_scan_string(maat_inst, src_table_id, src_asn1, strlen(src_asn1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, ip_geo_table_id, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //-------------------------------------------
	//			Source nothing & IP Geo
	//-------------------------------------------
    ret = maat_scan_string(maat_inst, src_table_id, src_nothing, strlen(src_nothing),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, ip_geo_table_id, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 181);

    maat_state_reset(state);

    //-------------------------------------------
	//			Source ASN2 & IP Geo
	//-------------------------------------------
    ret = maat_scan_string(maat_inst, src_table_id, src_asn2, strlen(src_asn2),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, ip_geo_table_id, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //--------------------------------------
	//			hit IP & IP Geo
	//--------------------------------------
    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.40.88", &ip_addr);
    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, ip_geo_table_id, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //--------------------------------------
	//			not hit IP & IP Geo
	//--------------------------------------
    inet_pton(AF_INET, "192.168.40.89", &ip_addr);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, ip_geo_table_id, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 181);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, SameAttributeInMultiCondition) {
    const char *src_asn1 = "AS1234";
    const char *src_asn2 = "AS9002";
    const char *src_asn3 = "AS9003";
    const char *my_county = "Greece.Sparta";
    const char *ip_table_name = "IP_PLUS_CONFIG";
    const char *dst_asn_table_name = "DESTINATION_IP_ASN";
    const char *ip_geo_table_name = "SOURCE_IP_GEO";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int dst_table_id = maat_get_table_id(maat_inst, dst_asn_table_name);
    ASSERT_GT(dst_table_id, 0);

    int ip_geo_table_id = maat_get_table_id(maat_inst, ip_geo_table_name);
    ASSERT_GT(ip_geo_table_id, 0);

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0); 

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.40.88", &ip_addr);
    //-------------------------------------------
	//			Dest ASN1 & Dest ASN3 & IP Config
	//-------------------------------------------
    int ret = maat_scan_string(maat_inst, dst_table_id, src_asn1, strlen(src_asn1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, dst_table_id, src_asn3, strlen(src_asn3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, dst_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //-------------------------------------------
	//			Dest ASN2 & Dest ASN3 & IP Config
	//-------------------------------------------
    ret = maat_scan_string(maat_inst, dst_table_id, src_asn2, strlen(src_asn2),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, dst_table_id, src_asn3, strlen(src_asn3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, dst_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    //-------------------------------------------
	//			Dest IP Geo & Dest ASN3 & IP Config
	//-------------------------------------------
    ret = maat_scan_string(maat_inst, ip_geo_table_id, my_county, strlen(my_county),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_geo_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, dst_table_id, src_asn3, strlen(src_asn3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, dst_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,  
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    //-------------------------------------------
	//			Dest ASN3 & IP Geo
	//-------------------------------------------
    ret = maat_scan_string(maat_inst, dst_table_id, src_asn3, strlen(src_asn3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, dst_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);                          

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 185);

    maat_state_reset(state);

    //--------------------------------------
	//			IP Config & IP Geo
	//--------------------------------------
    ret = maat_scan_string(maat_inst, dst_table_id, src_asn3, strlen(src_asn3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    inet_pton(AF_INET, "192.168.40.89", &ip_addr);
    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, dst_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

class ExcludeLogic : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in ExcludeLogic failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_inst);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *ExcludeLogic::_shared_maat_inst;
struct log_handle *ExcludeLogic::logger;

TEST_F(ExcludeLogic, ScanExcludeAtFirst) {
    const char *string_should_not_hit = "This string ONLY contains must-not-contained-string-of-rule-199.";
	const char *string_should_hit = "This string contains must-contained-string-of-rule-199";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *not_hit_table_name = "KEYWORDS_TABLE";
    const char *hit_table_name = "HTTP_URL";
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int not_hit_table_id = maat_get_table_id(maat_inst, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

    int ret = maat_scan_string(maat_inst, not_hit_table_id, string_should_not_hit,
                               strlen(string_should_not_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int hit_table_id =  maat_get_table_id(maat_inst, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    ret = maat_scan_string(maat_inst, hit_table_id, string_should_hit,
                           strlen(string_should_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 199);

    ret = maat_scan_not_logic(maat_inst, hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(ExcludeLogic, ScanExcludeAtLast) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-200.";
	const char *string_should_not_hit = "This string contains both must-contained-string-of-rule-200"
                                        " and must-not-contained-string-of-rule-200.";
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "HTTP_URL";
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_inst, table_id, string_should_not_hit,
                               strlen(string_should_not_hit), results,
                               ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

	ret = maat_scan_string(maat_inst, table_id, string_should_hit,
                           strlen(string_should_hit), results,
                           ARRAY_SIZE, &n_hit_result, state);
						
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 200);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);                          

	maat_state_free(state);
    state = NULL;
}

TEST_F(ExcludeLogic, ScanIrrelavantAtLast) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-200.";
	const char *string_irrelevant = "This string contains nothing to hit.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *hit_table_name = "HTTP_URL";
    const char *not_hit_table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int hit_table_id = maat_get_table_id(maat_inst, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    int ret = maat_scan_string(maat_inst, hit_table_id, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 200);

    ret = maat_scan_not_logic(maat_inst, hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int not_hit_table_id = maat_get_table_id(maat_inst, not_hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    ret = maat_scan_string(maat_inst, not_hit_table_id, string_irrelevant,
                           strlen(string_irrelevant), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    
    ret = maat_scan_not_logic(maat_inst, not_hit_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(ExcludeLogic, ScanAttribute) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *table_name = "ATTRIBUTE_IP_PLUS_TABLE";

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    uint32_t should_hit_ip;
    uint32_t should_not_hit_ip;
    inet_pton(AF_INET, "100.64.1.1", &should_hit_ip);
    
    int ret = maat_scan_ipv4(maat_inst, table_id, should_hit_ip, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 202);
    maat_state_reset(state);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    inet_pton(AF_INET, "100.64.1.5", &should_hit_ip);
    ret = maat_scan_ipv4(maat_inst, table_id, should_hit_ip, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 202);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    inet_pton(AF_INET, "100.64.1.6", &should_not_hit_ip);
    ret = maat_scan_ipv4(maat_inst, table_id, should_not_hit_ip, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    inet_pton(AF_INET, "100.64.1.11", &should_not_hit_ip);
    ret = maat_scan_ipv4(maat_inst, table_id, should_not_hit_ip, results,
                        ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    
    maat_state_free(state);
}

TEST_F(ExcludeLogic, ScanWithMultiCondition) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *ip_table_name = "ATTRIBUTE_IP_PLUS_TABLE";

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.50.43", &ip_addr);

    int ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    inet_pton(AF_INET, "47.92.108.93", &ip_addr);
    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *expr_table_name = "HTTP_RESPONSE_KEYWORDS";
    int expr_table_id = maat_get_table_id(maat_inst, expr_table_name);
    ASSERT_GT(expr_table_id, 0);

    const char *should_not_hit_expr = "www.jianshu.com";
    ret = maat_scan_string(maat_inst, expr_table_id, should_not_hit_expr,
                           strlen(should_not_hit_expr), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, expr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *should_hit_expr = "mail.jianshu.com";
    ret = maat_scan_string(maat_inst, expr_table_id, should_hit_expr,
                           strlen(should_hit_expr), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 203);

    ret = maat_scan_not_logic(maat_inst, expr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(ExcludeLogic, ExcludeInDifferentLevel) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *ip_table_name = "ATTRIBUTE_IP_PLUS_TABLE";

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0);

    uint32_t ip_addr;
    inet_pton(AF_INET, "100.64.2.1", &ip_addr);

    int ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    inet_pton(AF_INET, "100.64.2.6", &ip_addr);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *expr_table_name = "HTTP_RESPONSE_KEYWORDS";
    int expr_table_id = maat_get_table_id(maat_inst, expr_table_name);
    ASSERT_GT(expr_table_id, 0);

    const char *should_not_hit_expr1 = "www.baidu.com";
    ret = maat_scan_string(maat_inst, expr_table_id, should_not_hit_expr1,
                           strlen(should_not_hit_expr1), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, expr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *should_not_hit_expr2 = "mail.baidu.com";
    ret = maat_scan_string(maat_inst, expr_table_id, should_not_hit_expr2,
                           strlen(should_not_hit_expr2), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, expr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *should_hit_expr = "hit.baidu.com";
    ret = maat_scan_string(maat_inst, expr_table_id, should_hit_expr,
                           strlen(should_hit_expr), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 204);

    ret = maat_scan_not_logic(maat_inst, expr_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

void maat_read_entry_start_cb(int update_type, void *u_para)
{
}

void maat_read_entry_cb(int table_id, const char *table_line, enum maat_operation op, void *u_para)
{
	char ip_str[16] = {0};
	int entry_id = -1, seq = -1;
	unsigned int ip_uint = 0;
	int is_valid = 0;
	unsigned int local_ip_nr = 16820416;//192.168.0.1

	sscanf(table_line, "%d\t%s\t%d\t%d", &seq,ip_str, &entry_id, &is_valid);
	inet_pton(AF_INET, ip_str, &ip_uint);
	if (local_ip_nr == ip_uint) {
        EXPECT_EQ(is_valid, 1);
        EXPECT_EQ(entry_id, 101);
	}
}

void maat_read_entry_finish_cb(void *u_para)
{
}

class PluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_DEBUG);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in PluginTable failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_inst);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *PluginTable::_shared_maat_inst;
struct log_handle *PluginTable::logger;

TEST_F(PluginTable, Callback) {
    const char *table_name = "QD_ENTRY_INFO";
    struct maat *maat_inst = PluginTable::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    int ret = maat_table_callback_register(maat_inst, table_id, 
                                           maat_read_entry_start_cb,
                                           maat_read_entry_cb, 
                                           maat_read_entry_finish_cb,
                                           maat_inst);
    EXPECT_EQ(ret, 0);
}

struct plugin_ud {
	char key[32];
    char value[32];
    int id;
};

void plugin_EX_new_cb(const char *table_name, int table_id, const char *key, 
                      const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
    int valid = 0, tag = 0;
	struct plugin_ud *ud = ALLOC(struct plugin_ud, 1);
    
	int ret = sscanf(table_line, "%d\t%s\t%s\t%d\t%d",
                     &(ud->id), ud->key, ud->value, &valid, &tag);
    EXPECT_EQ(ret, 5);

    *ad = ud;
	(*counter)++;
}

void plugin_EX_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct plugin_ud *ud = (struct plugin_ud *)(*ad);

    memset(ud, 0, sizeof(struct plugin_ud));
	free(ud);
	*ad = NULL;
}

void plugin_EX_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct plugin_ud *ud = (struct plugin_ud *)(*from);

	*to = ud;
}

TEST_F(PluginTable, EX_DATA) {
    const char *table_name = "TEST_PLUGIN_EXDATA_TABLE";
    struct maat *maat_inst = PluginTable::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int plugin_ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                   plugin_EX_new_cb,
                                                   plugin_EX_free_cb,
                                                   plugin_EX_dup_cb,
                                                   0, &plugin_ex_data_counter);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(plugin_ex_data_counter, 4);

    const char *key1 = "HeBei";
    struct plugin_ud *ud = NULL;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           key1, strlen(key1));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Shijiazhuang");
    EXPECT_EQ(ud->id, 1);

    const char *key2 = "ShanDong";
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           key2, strlen(key2));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Jinan");
    EXPECT_EQ(ud->id, 3);
}

TEST_F(PluginTable, LONG_KEY_TYPE) {
    const char *table_name = "TEST_PLUGIN_LONG_KEY_TYPE_TABLE";
    struct maat *maat_inst = PluginTable::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int plugin_ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                   plugin_EX_new_cb,
                                                   plugin_EX_free_cb,
                                                   plugin_EX_dup_cb,
                                                   0, &plugin_ex_data_counter);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(plugin_ex_data_counter, 4);

    long long key1 = 11111111;
    struct plugin_ud *ud = NULL;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           (char *)&key1, sizeof(long long));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Shijiazhuang");
    EXPECT_EQ(ud->id, 1);

    long long key2 = 33333333;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           (char *)&key2, sizeof(long long));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Jinan");
    EXPECT_EQ(ud->id, 3);

    int key3 = 22222222;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           (char *)&key3, sizeof(key3));
    ASSERT_TRUE(ud == NULL);
}

TEST_F(PluginTable, INT_KEY_TYPE) {
    const char *table_name = "TEST_PLUGIN_INT_KEY_TYPE_TABLE";
    struct maat *maat_inst = PluginTable::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int plugin_ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                   plugin_EX_new_cb,
                                                   plugin_EX_free_cb,
                                                   plugin_EX_dup_cb,
                                                   0, &plugin_ex_data_counter);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(plugin_ex_data_counter, 4);

    int key1 = 101;
    struct plugin_ud *ud = NULL;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           (char *)&key1, sizeof(key1));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "China");
    EXPECT_EQ(ud->id, 1);

    int key2 = 102;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           (char *)&key2, sizeof(key2));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "America");
    EXPECT_EQ(ud->id, 2);

    long long key3 = 103;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           (char *)&key3, sizeof(key3));
    ASSERT_TRUE(ud == NULL);
}

TEST_F(PluginTable, IP_KEY_TYPE) {
    const char *table_name = "TEST_PLUGIN_IP_KEY_TYPE_TABLE";
    struct maat *maat_inst = PluginTable::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int plugin_ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                   plugin_EX_new_cb,
                                                   plugin_EX_free_cb,
                                                   plugin_EX_dup_cb,
                                                   0, &plugin_ex_data_counter);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(plugin_ex_data_counter, 4);

    uint32_t ipv4_addr1;
    ret = inet_pton(AF_INET, "100.64.1.1", &ipv4_addr1);
    EXPECT_EQ(ret, 1);

    struct plugin_ud *ud = NULL;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           (char *)&ipv4_addr1,
                                                           sizeof(ipv4_addr1));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "XiZang");
    EXPECT_EQ(ud->id, 4);

    uint32_t ipv4_addr2;
    ret = inet_pton(AF_INET, "100.64.1.2", &ipv4_addr2);
    EXPECT_EQ(ret, 1);

    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           (char *)&ipv4_addr2,
                                                           sizeof(ipv4_addr2));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "XinJiang");
    EXPECT_EQ(ud->id, 4);

    uint8_t ipv6_addr1[16];
    ret = inet_pton(AF_INET6, "2001:da8:205:1::101", ipv6_addr1);
    EXPECT_EQ(ret, 1);

    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           (char *)ipv6_addr1,
                                                           sizeof(ipv6_addr1));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "GuiZhou");
    EXPECT_EQ(ud->id, 6);

    uint8_t ipv6_addr2[16];
    ret = inet_pton(AF_INET6, "1001:da8:205:1::101", ipv6_addr2);
    EXPECT_EQ(ret, 1);

    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                           (char *)ipv6_addr2,
                                                           sizeof(ipv6_addr2));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "SiChuan");
    EXPECT_EQ(ud->id, 6);
}

class IPPluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in IPPluginTable failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_inst);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IPPluginTable::_shared_maat_inst;
struct log_handle *IPPluginTable::logger;

struct ip_plugin_ud {
	long long rule_id;
	char *buffer;
    size_t buf_len;
};
void ip_plugin_ex_new_cb(const char *table_name, int table_id, const char *key, 
                         const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	size_t column_offset=0, column_len=0;
	struct ip_plugin_ud *ud = ALLOC(struct ip_plugin_ud, 1);

	int ret = get_column_pos(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);

	ud->rule_id = atoll(table_line + column_offset);

	ret = get_column_pos(table_line, 4, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	ud->buffer = ALLOC(char, column_len + 1);
	strncpy(ud->buffer, table_line + column_offset, column_len);

    ud->buf_len = column_len + 1;
	*ad = ud;
	(*counter)++;
}

void ip_plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct ip_plugin_ud *ud = (struct ip_plugin_ud *)(*ad);

    ud->rule_id = 0;
    memset(ud->buffer, 0, ud->buf_len);
    ud->buf_len = 0;

	free(ud->buffer);
	free(ud);
	*ad = NULL;
}

void ip_plugin_ex_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct ip_plugin_ud *ud = (struct ip_plugin_ud *)(*from);
	
	*to = ud;
}

TEST_F(IPPluginTable, EX_DATA) {
    int ip_plugin_ex_data_counter = 0;
    const char *table_name = "TEST_IP_PLUGIN_WITH_EXDATA";
    struct maat *maat_inst = IPPluginTable::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                   ip_plugin_ex_new_cb,
                                                   ip_plugin_ex_free_cb,
                                                   ip_plugin_ex_dup_cb,
                                                   0, &ip_plugin_ex_data_counter);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(ip_plugin_ex_data_counter, 5);

    struct ip_addr ipv4;
    ipv4.ip_type = IPv4;
    ret = inet_pton(AF_INET, "192.168.30.100", &ipv4.ipv4);
    EXPECT_EQ(ret, 1);

    struct ip_plugin_ud *results[ARRAY_SIZE];
    ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_id, &ipv4, 
                                           (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(results[0]->rule_id, 101);
    EXPECT_EQ(results[1]->rule_id, 102);

    struct ip_addr ipv6;
    ipv6.ip_type = IPv6;
    inet_pton(AF_INET6, "2001:db8:1234::5210", &(ipv6.ipv6));
    memset(results, 0, sizeof(results));

	ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_id, &ipv6, 
                                           (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 2);
	EXPECT_EQ(results[0]->rule_id, 104);
	EXPECT_EQ(results[1]->rule_id, 103);

	//Reproduce BugReport-Liumengyan-20210515
	inet_pton(AF_INET6, "240e:97c:4010:104::17", &(ipv6.ipv6));
	ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_id, &ipv6, 
                                           (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 0);
}

class IPPortPluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in IPPortPluginTable failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_inst);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IPPortPluginTable::_shared_maat_inst;
struct log_handle *IPPortPluginTable::logger;

struct ipport_plugin_ud {
	long long rule_id;
	char *buffer;
    size_t buf_len;
};

void ipport_plugin_ex_new_cb(const char *table_name, int table_id, const char *key, 
                         const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	size_t column_offset=0, column_len=0;
	struct ipport_plugin_ud *ud = ALLOC(struct ipport_plugin_ud, 1);

	int ret = get_column_pos(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);

	ud->rule_id = atoll(table_line + column_offset);

	ret = get_column_pos(table_line, 5, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	ud->buffer = ALLOC(char, column_len + 1);
	strncpy(ud->buffer, table_line + column_offset, column_len);

    ud->buf_len = column_len + 1;
	*ad = ud;
	(*counter)++;
}

void ipport_plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct ipport_plugin_ud *ud = (struct ipport_plugin_ud *)(*ad);

    ud->rule_id = 0;
    memset(ud->buffer, 0, ud->buf_len);
    ud->buf_len = 0;

	free(ud->buffer);
	free(ud);
	*ad = NULL;
}

void ipport_plugin_ex_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct ipport_plugin_ud *ud = (struct ipport_plugin_ud *)(*from);
	
	*to = ud;
}

TEST_F(IPPortPluginTable, EX_DATA) {
    int ex_data_counter = 0;
    const char *table_name = "TEST_IPPORT_PLUGIN_WITH_EXDATA";
    struct maat *maat_inst = IPPortPluginTable::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                   ipport_plugin_ex_new_cb,
                                                   ipport_plugin_ex_free_cb,
                                                   ipport_plugin_ex_dup_cb,
                                                   0, &ex_data_counter);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(ex_data_counter, 4);

    struct ip_addr ipv4;
    ipv4.ip_type = IPV4;
    ret = inet_pton(AF_INET, "192.168.100.1", &ipv4.ipv4);
    EXPECT_EQ(ret, 1);

    uint16_t port = htons(255);

    struct ipport_plugin_ud *results[ARRAY_SIZE];
    ret = maat_ipport_plugin_table_get_ex_data(maat_inst, table_id, &ipv4, port,
                                               (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0]->rule_id, 103);

    struct ip_addr ipv6;
    ipv6.ip_type = IPv6;
    inet_pton(AF_INET6, "2001:db8:1234::5210", ipv6.ipv6);
    memset(results, 0, sizeof(results));

	ret = maat_ipport_plugin_table_get_ex_data(maat_inst, table_id, &ipv6, port,
                                              (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(results[0]->rule_id, 104);

    inet_pton(AF_INET6, "240e:97c:4010:104::17", ipv6.ipv6);
    ret = maat_ipport_plugin_table_get_ex_data(maat_inst, table_id, &ipv6, port,
                                              (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 0); 
}

class FQDNPluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in FQDNPluginTable failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *FQDNPluginTable::_shared_maat_inst;
struct log_handle *FQDNPluginTable::logger;

#define FQDN_PLUGIN_EX_DATA
struct fqdn_plugin_ud
{
	int rule_id;
	int catid;
};

void fqdn_plugin_ex_new_cb(const char *table_name, int table_id, const char *key, 
                           const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	size_t column_offset = 0, column_len = 0;
	struct fqdn_plugin_ud *ud = ALLOC(struct fqdn_plugin_ud, 1);

	int ret = get_column_pos(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);

	ud->rule_id = atoi(table_line + column_offset);
	ret = get_column_pos(table_line, 3, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	sscanf(table_line + column_offset, "catid=%d", &ud->catid);

	*ad = ud;
	(*counter)++;
}

void fqdn_plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct fqdn_plugin_ud *u = (struct fqdn_plugin_ud *)(*ad);

    u->rule_id = 0;
    u->catid = 0;

	free(u);
	*ad = NULL;
}

void fqdn_plugin_ex_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct fqdn_plugin_ud *u = (struct fqdn_plugin_ud *)(*from);

	*to = u;
}

TEST_F(FQDNPluginTable, EX_DATA) {
    const char *table_name = "TEST_FQDN_PLUGIN_WITH_EXDATA";
    struct maat *maat_inst = FQDNPluginTable::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int fqdn_plugin_ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                    fqdn_plugin_ex_new_cb,
                                                    fqdn_plugin_ex_free_cb,
                                                    fqdn_plugin_ex_dup_cb,
                                                    0, &fqdn_plugin_ex_data_counter);
    ASSERT_TRUE(ret>=0);
	EXPECT_EQ(fqdn_plugin_ex_data_counter, 5);

    struct fqdn_plugin_ud *result[4];

	ret = maat_fqdn_plugin_table_get_ex_data(maat_inst, table_id, "www.example1.com",
                                            (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_EQ(result[0]->rule_id, 201);
	EXPECT_EQ(result[1]->rule_id, 202);

	ret = maat_fqdn_plugin_table_get_ex_data(maat_inst, table_id, "www.example3.com",
                                            (void**)result, 4);
	EXPECT_EQ(ret, 0);

	ret = maat_fqdn_plugin_table_get_ex_data(maat_inst, table_id, "r3---sn-i3belne6.example2.com",
                                            (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_TRUE(result[0]->rule_id == 205 || result[0]->rule_id == 204);
}

struct bool_plugin_ud {
	int id;
	char *name;
    size_t name_len;
};
void bool_plugin_ex_new_cb(const char *table_name, int table_id, const char *key, 
                           const char *table_line, void **ad, long argl, void *argp)
{
	int *counter=(int *)argp;
	size_t column_offset=0, column_len=0;
	struct bool_plugin_ud *ud = ALLOC(struct bool_plugin_ud, 1);
	
    int ret = get_column_pos(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);

	ud->id = atoi(table_line + column_offset);
	ret = get_column_pos(table_line, 3, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	ud->name = ALLOC(char, column_len + 1);
	memcpy(ud->name, table_line+column_offset, column_len);
	ud->name_len = column_len + 1;
    
	*ad = ud;
	(*counter)++;
}
void bool_plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct bool_plugin_ud *u = (struct bool_plugin_ud *)(*ad);
	
    u->id = 0;
	memset(u->name, 0, u->name_len);
    u->name_len = 0;

	free(u->name);
	free(u);
	*ad = NULL;
	
}
void bool_plugin_ex_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct bool_plugin_ud *u = (struct bool_plugin_ud *)(*from);
	
	*to = u;
}

class BoolPluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in BoolPluginTable failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *BoolPluginTable::_shared_maat_inst;
struct log_handle *BoolPluginTable::logger;

TEST_F(BoolPluginTable, EX_DATA) {
    int ex_data_counter = 0;
	const char *table_name = "TEST_BOOL_PLUGIN_WITH_EXDATA";
    struct maat *maat_inst = BoolPluginTable::_shared_maat_inst;

	int table_id = maat_get_table_id(maat_inst, table_name);
	ASSERT_GT(table_id, 0);

	int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
								                   bool_plugin_ex_new_cb,
								                   bool_plugin_ex_free_cb,
								                   bool_plugin_ex_dup_cb,
								                   0, &ex_data_counter);
	ASSERT_TRUE(ret >= 0);
	EXPECT_EQ(ex_data_counter, 6);

	struct bool_plugin_ud *result[6];
	unsigned long long items_1[] = {999};
	ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_id, items_1,
                                             1, (void**)result, 6);
	EXPECT_EQ(ret, 0);

	unsigned long long items_2[] = {1, 2, 1000};
	ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_id, items_2,
                                             3, (void**)result, 6);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0]->id, 301);

	unsigned long long items_3[]={101, 102, 1000};
	ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_id, items_3,
                                             3, (void**)result, 6);
	EXPECT_EQ(ret, 4);

	unsigned long long items_4[]={7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 7};
	ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_id, items_4,
                                             sizeof(items_4)/sizeof(unsigned long long),
                                             (void**)result, 6);
	EXPECT_EQ(ret, 1);	
	EXPECT_EQ(result[0]->id, 305);
}

class Attribute : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in Attribute failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_inst);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Attribute::_shared_maat_inst;
struct log_handle *Attribute::logger;

TEST_F(Attribute, basic) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "HTTP_RESPONSE_KEYWORDS";
    struct maat *maat_inst = Attribute::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    char scan_data[128] = "string1, string2, string3, string4, string5,"
                          " string6, string7, string8";
    
    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(state);
    state = NULL;
}

class TableSchemaTag : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_hit_path_enabled(opts);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in TableSchemaTag failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_inst);
       log_handle_destroy(logger);
    }    

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *TableSchemaTag::_shared_maat_inst;
struct log_handle *TableSchemaTag::logger;

TEST_F(TableSchemaTag, RuleTable) {
    const char *rule1_table_name = "RULE_DEFAULT";
    const char *rule2_table_name = "RULE_ALIAS";
    const char *rule3_table_name = "RULE_CONJUNCTION";
    const char *g2c_table_name = "OBJECT2RULE";
    struct maat *maat_inst = TableSchemaTag::_shared_maat_inst;

    //RULE_DEFAULT
    int rule1_table_id = maat_get_table_id(maat_inst, rule1_table_name);
    EXPECT_EQ(rule1_table_id, 0);

    const char *tag1 = maat_get_table_schema_tag(maat_inst, rule1_table_id);
    EXPECT_TRUE(tag1 == NULL);

    //RULE_ALIAS
    int rule2_table_id = maat_get_table_id(maat_inst, rule2_table_name);
    EXPECT_EQ(rule2_table_id, 1);

    const char *tag2 = maat_get_table_schema_tag(maat_inst, rule2_table_id);
    EXPECT_TRUE(tag2 != NULL);

    int ret = strcmp(tag2, "{\"rule_alias\": \"rule\"}");
    EXPECT_EQ(ret, 0);

    //RULE_CONJUNCTION
    int rule3_table_id = maat_get_table_id(maat_inst, rule3_table_name);
    EXPECT_EQ(rule3_table_id, 2);

    const char *tag3 = maat_get_table_schema_tag(maat_inst, rule3_table_id);
    EXPECT_TRUE(tag3 != NULL);

    ret = strcmp(tag3, "{\"rule_conjunction\": \"rule\"}");
    EXPECT_EQ(ret, 0);

    //OBJECT2RULE
    int g2c_table_id = maat_get_table_id(maat_inst, g2c_table_name);
    EXPECT_EQ(g2c_table_id, 3);

    const char *tag4 = maat_get_table_schema_tag(maat_inst, g2c_table_id);
    EXPECT_TRUE(tag4 != NULL);

    ret = strcmp(tag4, "{\"object2rule\": \"object2rule\"}");
    EXPECT_EQ(ret, 0);

    //RULE_PLUGIN
    const char *plugin_table_name = "RULE_PLUGIN";
    int plugin_table_id = maat_get_table_id(maat_inst, plugin_table_name);
    EXPECT_EQ(plugin_table_id, 8);

    const char *tag5 = maat_get_table_schema_tag(maat_inst, plugin_table_id);
    EXPECT_TRUE(tag5 != NULL);

    ret = strcmp(tag5, "{\"rule_plugin\": \"plugin\"}");
    EXPECT_EQ(ret, 0);

    //HTTP_REGION
    const char *region_table_name = "HTTP_REGION";
    const char *url_table_name = "HTTP_URL";
    const char *host_table_name = "HTTP_HOST";

    int region_table_id = maat_get_table_id(maat_inst, region_table_name);
    EXPECT_EQ(region_table_id, 10);

    int url_table_id = maat_get_table_id(maat_inst, url_table_name);
    EXPECT_EQ(url_table_id, 10);

    int host_table_id = maat_get_table_id(maat_inst, host_table_name);
    EXPECT_EQ(host_table_id, 10);

    const char *tag6 = maat_get_table_schema_tag(maat_inst, region_table_id);
    EXPECT_TRUE(tag6 != NULL);

    ret = strcmp(tag6, "{\"http_region\": \"expr\"}");
    EXPECT_EQ(ret, 0);

    //HTTP_RESPONSE_KEYWORDS
    const char *attribute_name = "HTTP_RESPONSE_KEYWORDS";
    int attribute_id = maat_get_table_id(maat_inst, attribute_name);
    EXPECT_EQ(attribute_id, 25);

    const char *tag7 = maat_get_table_schema_tag(maat_inst, attribute_id);
    EXPECT_TRUE(tag7 != NULL);

    ret = strcmp(tag7, "{\"http_response_keywords\": \"attribute\"}");
    EXPECT_EQ(ret, 0);

    //ATTRIBUTE_IP_PLUS_TABLE
    const char *attribute1_name = "ATTRIBUTE_IP_PLUS_TABLE";
    int attribute1_id = maat_get_table_id(maat_inst, attribute1_name);
    EXPECT_EQ(attribute1_id, 28);

    const char *attribute2_name = "ATTRIBUTE_IP_PLUS_SOURCE";
    int attribute2_id = maat_get_table_id(maat_inst, attribute2_name);
    EXPECT_EQ(attribute2_id, 28);

    const char *attribute3_name = "ATTRIBUTE_IP_PLUS_DESTINATION";
    int attribute3_id = maat_get_table_id(maat_inst, attribute3_name);
    EXPECT_EQ(attribute3_id, 28);

    const char *tag8 = maat_get_table_schema_tag(maat_inst, attribute1_id);
    EXPECT_TRUE(tag8 != NULL);

    ret = strcmp(tag8, "{\"attribute_ip_plus_table\": \"attribute\"}");
    EXPECT_EQ(ret, 0);
}

class RuleTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_hit_path_enabled(opts);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in RuleTable failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_inst);
       log_handle_destroy(logger);
    }    

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RuleTable::_shared_maat_inst;
struct log_handle *RuleTable::logger;

struct rule_ex_param {
	char name[NAME_MAX];
	int id;
};

void rule_ex_param_new(const char *table_name, int table_id, const char *key, 
                          const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	*ad = NULL;

	struct rule_ex_param *param = ALLOC(struct rule_ex_param, 1);
	
    int rule_id = 0;
    int service_id = 0;
    int action = 0;
    int do_blacklist = 0;
    int do_log = 0;
    char tags[1024] = {0};

	sscanf(table_line, "%d\t%d\t%d\t%d\t%d\t%s\t%*[^:]:%[^,],%d", 
           &rule_id, &service_id, &action, &do_blacklist, &do_log, 
           tags, param->name, &(param->id));
    
	(*counter)++;
	*ad = param;
}

void rule_ex_param_free(int table_id, void **ad, long argl, void *argp)
{
	if (*ad == NULL) {
		return;
	}

	struct rule_ex_param *param = (struct rule_ex_param *)*ad;
    memset(param, 0, sizeof(struct rule_ex_param));
	free(param);
}

void rule_ex_param_dup(int table_id, void **to, void **from, long argl, void *argp)
{
	struct rule_ex_param *from_param = *((struct rule_ex_param **)from);

	*((struct rule_ex_param**)to) = from_param;
}

TEST_F(RuleTable, RuleRuleUpdate) {
    struct maat *maat_inst = RuleTable::_shared_maat_inst;

    const char *rule_table_name = "RULE_DEFAULT";
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name,
                                     MAAT_OP_ADD, rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    ret = rule_table_set_line(maat_inst, rule_table_name,
                                 MAAT_OP_DEL, rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);
}

TEST_F(RuleTable, Conjunction1) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "i.ytimg.com/vi/OtCNcustg_I/hqdefault.jpg?sqp=-oaymwEZCNAC"
                            "ELwBSFXyq4qpAwsIARUAAIhCGAFwAQ==&rs=AOn4CLDOp_5fHMaCA9XZuJdCRv4DNDorMg";
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = RuleTable::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 197);
    EXPECT_EQ(results[1], 141);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_EQ(n_read, 2);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RuleTable, Conjunction2) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "i.ytimg.com/vi/OtCNcustg_I/hqdefault.jpg?sqp=-oaymwEZCNACELw"
                            "BSFXyq4qpAwsIARUAAIhCGAFwAQ==&rs=AOn4CLDOp_5fHMaCA9XZuJdCRv4DNDorMg";
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = RuleTable::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 197);
    EXPECT_EQ(results[1], 141);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_EQ(n_read, 2);

    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    memset(hit_path, 0, sizeof(hit_path));
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_EQ(n_read, 4);

    maat_state_free(state);
    state = NULL;
}

class Policy : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_hit_path_enabled(opts);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in Policy failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }    

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Policy::_shared_maat_inst;
struct log_handle *Policy::logger;

void accept_tags_entry_cb(int table_id, const char *table_line, enum maat_operation op, void *u_para)
{
	int* callback_times = (int *)u_para;
	char status[32] = {0};
	int entry_id = -1, seq = -1;
	int is_valid = 0;

	sscanf(table_line, "%d\t%s\t%d\t%d", &seq,status, &entry_id, &is_valid);
	EXPECT_STREQ(status, "SUCCESS");
	(*callback_times)++;
}

TEST_F(Policy, PluginRuleTags1) {
    const char *table_name = "TEST_EFFECTIVE_RANGE_TABLE";
    struct maat *maat_inst = Policy::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int callback_times=0;
	int ret = maat_table_callback_register(maat_inst, table_id,
							               NULL,
							               accept_tags_entry_cb, 
							               NULL,
							               &callback_times);
	ASSERT_GE(ret, 0);
	EXPECT_EQ(callback_times, 5);
}

void accept_tags_entry2_cb(int table_id, const char *table_line, enum maat_operation op, void *u_para)
{
	int *callback_times = (int *)u_para;
	(*callback_times)++;
}

TEST_F(Policy, PluginRuleTags2) {
    const char *table_name = "IR_INTERCEPT_IP";
    struct maat *maat_inst = Policy::_shared_maat_inst;

	int table_id = maat_get_table_id(maat_inst, table_name);
	ASSERT_GT(table_id, 0);

	int callback_times = 0;
	int ret = maat_table_callback_register(maat_inst, table_id,
							               NULL,
							               accept_tags_entry2_cb, 
							               NULL,
							               &callback_times);
	ASSERT_GE(ret, 0);
	EXPECT_EQ(callback_times, 2);
}

TEST_F(Policy, RuleRuleTags) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *should_hit = "string bbb should hit";
	const char *should_not_hit = "string aaa should not hit";
	const char *table_name = "HTTP_URL";
	struct maat *maat_inst = Policy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
	ASSERT_GT(table_id, 0);

	int ret = maat_scan_string(maat_inst, table_id, should_not_hit, 
                               strlen(should_not_hit), results, ARRAY_SIZE,
						        &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_scan_string(maat_inst, table_id, should_hit, 
                           strlen(should_hit), results, ARRAY_SIZE,
						   &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(Policy, RuleEXData) {
    
    const char *url = "firewall should hit";
	const char *table_name = "HTTP_URL";
    const char *plugin_table_name = "RULE_FIREWALL_PLUGIN";
    const char *conj_rule_table_name = "RULE_FIREWALL_CONJUNCTION";
    const char *phy_rule_table_name = "RULE_FIREWALL_DEFAULT";
	const char *expect_name = "I have a name";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = Policy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    int plugin_table_id = maat_get_table_id(maat_inst, plugin_table_name);
    int conj_rule_table_id = maat_get_table_id(maat_inst, conj_rule_table_name);
    int phy_rule_table_id = maat_get_table_id(maat_inst, phy_rule_table_name);

    int ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_inst, plugin_table_name,
                                                    rule_ex_param_new,
                                                    rule_ex_param_free,
                                                    rule_ex_param_dup,
                                                    0, &ex_data_counter);
    ASSERT_TRUE(ret == 0);
    EXPECT_EQ(ex_data_counter, 2);

    ret = maat_state_set_scan_rule_table(state, conj_rule_table_id);
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, table_id, url, strlen(url),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 198);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int rule_table_ids[ARRAY_SIZE];
    ret = maat_state_get_rule_table_ids(state, results, 1, rule_table_ids);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(rule_table_ids[0], phy_rule_table_id);

    void *ex_data = maat_plugin_table_get_ex_data(maat_inst, plugin_table_id, 
                                                 (char *)&results[0], sizeof(long long));
    ASSERT_TRUE(ex_data!=NULL);
    struct rule_ex_param *param = (struct rule_ex_param *)ex_data;
	EXPECT_EQ(param->id, 7799);

	EXPECT_EQ(strcmp(param->name, expect_name), 0);

	maat_state_free(state);
    state = NULL;
}

TEST_F(Policy, SubObject) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = Policy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
	const char *scan_data = "ceshi6@mailhost.cn";
	
	uint32_t ip_addr;
	inet_pton(AF_INET,"10.0.6.201", &ip_addr);

	int table_id = maat_get_table_id(maat_inst, "MAIL_ADDR");
	ASSERT_GT(table_id, 0);
	
	int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
						       results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	table_id = maat_get_table_id(maat_inst, "IP_CONFIG");	
	ASSERT_GT(table_id, 0);
	
	ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);	
	
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 153);
	
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *rule_table_name = "RULE_DEFAULT";
    int phy_rule_table_id = maat_get_table_id(maat_inst, rule_table_name);

    int rule_table_ids[ARRAY_SIZE];
    ret = maat_state_get_rule_table_ids(state, results, 1, rule_table_ids);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(rule_table_ids[0], phy_rule_table_id);

	maat_state_free(state);
}

TEST_F(Policy, EvaluationOrder) {
    const char *url = "cavemancircus.com/2019/12/27/pretty-girls-6/";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = Policy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, "HTTP_URL");
	ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_inst, table_id, url, strlen(url),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 3);
    EXPECT_EQ(results[0], 166);
    EXPECT_EQ(results[1], 168);
    EXPECT_EQ(results[2], 167);

    struct maat_hit_path hit_path[128];
    memset(hit_path, 0, sizeof(hit_path));
    size_t n_hit_path = maat_state_get_hit_paths(state, hit_path, 128);
    EXPECT_EQ(n_hit_path, 6);

    EXPECT_EQ(hit_path[0].attribute_id, table_id);
    EXPECT_EQ(hit_path[0].sub_object_id, 158);
    EXPECT_EQ(hit_path[0].top_object_id, 158);
    EXPECT_EQ(hit_path[0].condition_index, 2);
    EXPECT_EQ(hit_path[0].rule_id, 168);

    EXPECT_EQ(hit_path[1].attribute_id, table_id);
    EXPECT_EQ(hit_path[1].sub_object_id, 157);
    EXPECT_EQ(hit_path[1].top_object_id, 157);
    EXPECT_EQ(hit_path[1].condition_index, 0);
    EXPECT_EQ(hit_path[1].rule_id, 166);

    EXPECT_EQ(hit_path[2].attribute_id, table_id);
    EXPECT_EQ(hit_path[2].sub_object_id, 155);
    EXPECT_EQ(hit_path[2].top_object_id, -1);
    EXPECT_EQ(hit_path[2].condition_index, -1);
    EXPECT_EQ(hit_path[2].rule_id, -1);

    EXPECT_EQ(hit_path[3].attribute_id, table_id);
    EXPECT_EQ(hit_path[3].sub_object_id, 158);
    EXPECT_EQ(hit_path[3].top_object_id, 158);
    EXPECT_EQ(hit_path[3].condition_index, 6);
    EXPECT_EQ(hit_path[3].rule_id, 168);

    EXPECT_EQ(hit_path[4].attribute_id, table_id);
    EXPECT_EQ(hit_path[4].sub_object_id, 158);
    EXPECT_EQ(hit_path[4].top_object_id, 158);
    EXPECT_EQ(hit_path[4].condition_index, 1);
    EXPECT_EQ(hit_path[4].rule_id, 167);

    EXPECT_EQ(hit_path[5].attribute_id, table_id);
    EXPECT_EQ(hit_path[5].sub_object_id, 158);
    EXPECT_EQ(hit_path[5].top_object_id, 158);
    EXPECT_EQ(hit_path[5].condition_index, 3);
    EXPECT_EQ(hit_path[5].rule_id, 167);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.23.23", &ip_addr);

    table_id = maat_get_table_id(maat_inst, "IP_PLUS_CONFIG");
    ASSERT_GT(table_id, 0);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 165);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

TEST_F(Policy, NotConditionHitPath) {
    const char *url_table_name = "HTTP_URL";
    const char *ip_table_name = "ATTRIBUTE_IP_CONFIG";
    const char *url = "www.youtube.com";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = Policy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int url_table_id = maat_get_table_id(maat_inst, url_table_name);
	ASSERT_GT(url_table_id, 0);

    int ret = maat_scan_string(maat_inst, url_table_id, url, strlen(url),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.101.101", &ip_addr);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 228);

    struct maat_hit_path hit_path[128];
    memset(hit_path, 0, sizeof(hit_path));
    size_t n_hit_path = maat_state_get_hit_paths(state, hit_path, 128);
    EXPECT_EQ(n_hit_path, 4);

    EXPECT_EQ(hit_path[0].Nth_scan, 1);
    EXPECT_EQ(hit_path[0].attribute_id, url_table_id);
    EXPECT_EQ(hit_path[0].negate_option, 0);
    EXPECT_EQ(hit_path[0].condition_index, 1);
    EXPECT_EQ(hit_path[0].sub_object_id, 249);
    EXPECT_EQ(hit_path[0].top_object_id, 249);
    EXPECT_EQ(hit_path[0].rule_id, 228);

    EXPECT_EQ(hit_path[1].Nth_scan, 2);
    EXPECT_EQ(hit_path[1].attribute_id, ip_table_id);
    EXPECT_EQ(hit_path[1].negate_option, 1);
    EXPECT_EQ(hit_path[1].condition_index, -1);
    EXPECT_EQ(hit_path[1].sub_object_id, 100);
    EXPECT_EQ(hit_path[1].top_object_id, 144);
    EXPECT_EQ(hit_path[1].rule_id, -1);

    EXPECT_EQ(hit_path[2].Nth_scan, 2);
    EXPECT_EQ(hit_path[2].attribute_id, ip_table_id);
    EXPECT_EQ(hit_path[2].negate_option, 1);
    EXPECT_EQ(hit_path[2].condition_index, -1);
    EXPECT_EQ(hit_path[2].sub_object_id, 100);
    EXPECT_EQ(hit_path[2].top_object_id, -1);
    EXPECT_EQ(hit_path[2].rule_id, -1);

    EXPECT_EQ(hit_path[3].Nth_scan, 2);
    EXPECT_EQ(hit_path[3].attribute_id, ip_table_id);
    EXPECT_EQ(hit_path[3].negate_option, 1);
    EXPECT_EQ(hit_path[3].condition_index, 2);
    EXPECT_EQ(hit_path[3].sub_object_id, 250);
    EXPECT_EQ(hit_path[3].top_object_id, 250);
    EXPECT_EQ(hit_path[3].rule_id, 228);

    maat_state_free(state);
}

TEST_F(Policy, ReadColumn) {
    const char *ip = "192.168.0.1";
	const char *tmp = "something";
	char line[256] = {0};
    size_t offset=0, len=0;

	snprintf(line, sizeof(line), "1\t%s\t%s", ip, tmp);
	int ret = maat_helper_read_column(line, 2, &offset, &len);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(0, strncmp(ip, line+offset, len));
	
	ret = maat_helper_read_column(line, 3, &offset, &len);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(0, strncmp(tmp, line+offset, len));
}

class TableInfo : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in TableInfo failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }   

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst; 
};

struct maat *TableInfo::_shared_maat_inst;
struct log_handle *TableInfo::logger;

TEST_F(TableInfo, Conjunction) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "soq is using table conjunction function."
                            "http://www.3300av.com/novel/27122.txt";
    const char *table_name = "HTTP_URL";
    const char *conj_table_name = "HTTP_HOST";
    struct maat *maat_inst = TableInfo::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int conj_table_id = maat_get_table_id(maat_inst, conj_table_name);
    ASSERT_GT(conj_table_id, 0);

    int ret = maat_scan_string(maat_inst, conj_table_id, scan_data,
                               strlen(scan_data), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 134);
    EXPECT_EQ(results[1], 133);

    ret = maat_scan_not_logic(maat_inst, conj_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

#if 0 //TODO: change iris rule to json rule
class FileTest : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *rule_folder = "./ntcrule/full/index";
        const char *table_info = "./file_test_tableinfo.json";

        struct maat_options *opts = maat_options_new();
        maat_options_set_caller_thread_number(opts, g_thread_num);
        maat_options_set_instance_name(opts, "files");
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_iris(opts, rule_folder, rule_folder);
        maat_options_set_rule_update_checking_interval_ms(opts, 500);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);

        _shared_maat_inst = maat_new(opts, table_info);
        maat_options_free(opts);
        EXPECT_TRUE(_shared_maat_inst != NULL);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
    }

    static struct maat *_shared_maat_inst;
};
struct maat *FileTest::_shared_maat_inst;

TEST_F(FileTest, StreamFiles) {
    const char test_data_dir[64] = "./test_streamfiles";
    const char *table_name = "NTC_HTTP_REQ_BODY";
    int thread_id = 0;
    struct maat *maat_inst = FileTest::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    struct dirent **name_list;
    int n = my_scandir(test_data_dir, &name_list, NULL, 
                       (int (*)(const void*, const void*))alphasort);
    ASSERT_GT(n, 0);
    struct maat_stream *stream = maat_stream_new(maat_inst, table_id, state);
    ASSERT_FALSE(stream == NULL);

    struct stat file_info;
	size_t file_size = 0;
    char file_path[PATH_MAX] = {0};
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int hit_cnt = 0;

    for (int i = 0; i < n; i++) {
        if ((strcmp(name_list[i]->d_name, ".") == 0) || 
            (strcmp(name_list[i]->d_name, "..") == 0)) {
			continue;
		}

        snprintf(file_path, sizeof(file_path), "%s/%s", test_data_dir, 
                 name_list[i]->d_name);
        int ret = stat(file_path, &file_info);
		ASSERT_TRUE(ret == 0);

		file_size = file_info.st_size;
		char *buff = ALLOC(char, file_size + 1);
		FILE *fp = fopen(file_path, "rb");
		if (fp == NULL) {
			printf("fopen %s error.\n", file_path);
			continue;
		}

		int read_len = fread(buff, 1, file_size, fp);
		ret = maat_stream_scan(stream, buff, read_len, results, ARRAY_SIZE, 
                                &n_hit_result, state);
		read_len = fread(buff, 1, sizeof(buff), fp);
		if (ret > 0) {
			hit_cnt++;
		}
		fclose(fp);
		free(buff);
		buff = NULL;
    }
    maat_state_free(state);
    state = NULL;
    maat_stream_free(stream);
    EXPECT_GT(hit_cnt, 0);

    for (int i = 0; i < n; i++) {
        free(name_list[i]);
    }

    free(name_list);
}
#endif

class ObjectHierarchy : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in ObjectHierarchy failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }   

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst; 
};

struct maat *ObjectHierarchy::_shared_maat_inst;
struct log_handle *ObjectHierarchy::logger;

TEST_F(ObjectHierarchy, AttributeOfOnePhysical)
{
    const char *http_content = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *http_url = "https://blog.csdn.net/littlefang/article/details/8213058";
    const char *url_table_name = "HTTP_URL";
    const char *keywords_table_name = "HTTP_RESPONSE_KEYWORDS";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ObjectHierarchy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, url_table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_inst, table_id, http_url, strlen(http_url),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    table_id = maat_get_table_id(maat_inst, keywords_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_inst, table_id, http_content, strlen(http_content),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 160);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    const char *should_not_hit = "2018-10-05 is a keywords of table "
                                 "KEYWORDS_TABLE. Should not hit.";
    ret = maat_scan_string(maat_inst, table_id, should_not_hit,
                           strlen(should_not_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(ObjectHierarchy, AttributeWithAttribute) {
    const char *http_req_hdr_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/78.0.3904.108 Safari/537.36";
	const char *http_resp_hdr_cookie = "uid=12345678;BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; sugstore=1;";
    const char *req_table_name = "HTTP_REQUEST_HEADER";
    const char *res_table_name = "HTTP_RESPONSE_HEADER";
    const char *district_str1 = "User-Agent";
    const char *district_str2 = "Cookie";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ObjectHierarchy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, req_table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_state_set_scan_district(state, table_id, district_str1,
                                           strlen(district_str1));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, table_id, http_req_hdr_ua,
                           strlen(http_req_hdr_ua), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    table_id = maat_get_table_id(maat_inst, res_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, district_str2,
                                       strlen(district_str2));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, table_id, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 162);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(ObjectHierarchy, OneObjectInTwoAttribute) {
    const char *http_resp_hdr_cookie = "sessionid=888888;BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; sugstore=1;";
    const char *req_table_name = "HTTP_REQUEST_HEADER";
    const char *res_table_name = "HTTP_RESPONSE_HEADER";
    const char *district_str1 = "Cookie";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ObjectHierarchy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, req_table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_state_set_scan_district(state, table_id, district_str1,
                                           strlen(district_str1));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, table_id, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    table_id = maat_get_table_id(maat_inst, res_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, district_str1,
                                       strlen(district_str1));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, table_id, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 163);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(ObjectHierarchy, MultiObjectsInOneCondition) {
    const char *src_asn1 = "AS1234";
    const char *src_asn2 = "AS6789";
    const char *src_asn3 = "AS9001";
    const char *dst_asn = "AS2345";
    const char *src_asn_table_name = "SOURCE_IP_ASN";
    const char *dst_asn_table_name = "DESTINATION_IP_ASN";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ObjectHierarchy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //--------------------------------------
	//			Source ASN1 & Dest ASN
	//--------------------------------------
    int src_table_id = maat_get_table_id(maat_inst, src_asn_table_name);
    ASSERT_GT(src_table_id, 0);

    int ret = maat_scan_string(maat_inst, src_table_id, src_asn1, strlen(src_asn1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int dst_table_id = maat_get_table_id(maat_inst, dst_asn_table_name);
    ASSERT_GT(dst_table_id, 0);

    ret = maat_scan_string(maat_inst, dst_table_id, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 178);

    ret = maat_scan_not_logic(maat_inst, dst_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //--------------------------------------
	//			Source ASN2 & Dest ASN
	//--------------------------------------
    ret = maat_scan_string(maat_inst, src_table_id, src_asn2, strlen(src_asn2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, dst_table_id, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 178);

    ret = maat_scan_not_logic(maat_inst, dst_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //--------------------------------------
	//			Source ASN3 & Dest ASN
	//--------------------------------------
    ret = maat_scan_string(maat_inst, src_table_id, src_asn3, strlen(src_asn3),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, dst_table_id, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 178);

    ret = maat_scan_not_logic(maat_inst, dst_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(ObjectHierarchy, MultiLiteralsInOneCondition) {
    const char *src_asn1 = "AS1234";
    const char *src_asn2 = "AS6789";
    const char *my_county = "Greece.Sparta";
    const char *ip_table_name = "IP_CONFIG";
    const char *src_asn_table_name = "SOURCE_IP_ASN";
    const char *ip_geo_table_name = "SOURCE_IP_GEO";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ObjectHierarchy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int src_table_id = maat_get_table_id(maat_inst, src_asn_table_name);
    ASSERT_GT(src_table_id, 0);

    int ip_geo_table_id = maat_get_table_id(maat_inst, ip_geo_table_name);
    ASSERT_GT(ip_geo_table_id, 0);

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0); 

    //--------------------------------------
	//			Source ASN1 & IP
	//--------------------------------------

    int ret = maat_scan_string(maat_inst, src_table_id, src_asn1, strlen(src_asn1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.40.88", &ip_addr);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 180);

    maat_state_reset(state);

    //--------------------------------------
	//			IP Geo & IP
	//--------------------------------------
    ret = maat_scan_string(maat_inst, ip_geo_table_id, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 180);

    maat_state_reset(state);

    //--------------------------------------
	//			(Source ASN2 | IP Geo) & IP
	//--------------------------------------
    ret = maat_scan_string(maat_inst, src_table_id, src_asn2, strlen(src_asn2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, ip_geo_table_id, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 180);

    maat_state_free(state);
    state = NULL;
}

class MaatCmd : public testing::Test
{
protected:
    static void SetUpTestCase() {
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_FATAL);
        maat_options_set_hit_path_enabled(opts);
        maat_options_set_hit_object_enabled(opts);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        assert(_shared_maat_inst != NULL);
       
        maat_cmd_flushDB(_shared_maat_inst);
        maat_free(_shared_maat_inst);

        maat_options_set_foreign_cont_dir(opts, "./foreign_files/");
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);

        _ex_data_counter = ALLOC(int, 1);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        FREE(_ex_data_counter);
    } 

    static struct maat *_shared_maat_inst;
    static int *_ex_data_counter;
};

struct maat *MaatCmd::_shared_maat_inst;
int *MaatCmd::_ex_data_counter;

TEST_F(MaatCmd, SetIP) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *ip_table_name = "IP_CONFIG";
	const char *rule_table_name = "RULE_DEFAULT";
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    maat_reload_log_level(maat_inst, LOG_LEVEL_INFO);

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table add line */
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object_id, rule_id, 0, ip_table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    /* item table add line */
    const char *ip1 = "172.0.0.1";
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item_id,
                            object_id, ip1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);
   
    uint32_t sip;
    ret = inet_pton(AF_INET, ip1, &sip);
    EXPECT_EQ(ret, 1);

    int table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GE(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, table_id, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, SetExpr) {
    const char *scan_data = "Hiredis is a minimalistic C client library"
                            " for the Redis database.\r\n";
	const char *table_name = "HTTP_URL";
	
	const char *keywords1 = "Hiredis";
	const char *keywords2 = "C Client";
    const char *rule_table_name = "RULE_DEFAULT";
	char keywords[512];

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    snprintf(keywords, sizeof(keywords), "%s&%s", keywords1, keywords2);
	long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 2);

    test_add_expr_command(maat_inst, table_name, rule_id - 1, 0, keywords);
    test_add_expr_command(maat_inst, table_name, rule_id, 0, keywords);
    
    sleep(WAIT_FOR_EFFECTIVE_S);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_TRUE(results[0] == rule_id || results[0] == (rule_id - 1));

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, rule_id-1, 
                                 "null", 1, 0);
    EXPECT_EQ(ret, 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, rule_id, 
                                 "null", 1, 0);
    EXPECT_EQ(ret, 1);
    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    int timeout = 1;
    rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    test_add_expr_command(maat_inst, table_name, rule_id, timeout, keywords);
    sleep(timeout + 1);
    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, SetExpr8) {
    const char *scan_data8 = "string1, string2, string3, string4, string5, string6, string7, string8";
	const char *scan_data7 = "string1, string2, string3, string4, string5, string6, string7";
	
	const char *rule_table_name = "RULE_DEFAULT";
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char *table_name = "KEYWORDS_TABLE";
	
	const char *keywords8 = "string1&string2&string3&string4&string5&string6&string7&string8";
	const char *keywords7 = "string1&string2&string3&string4&string5&string6&string7";

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table add line */
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object_id, rule_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                              object_id, keywords8, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_inst, table_id, scan_data8, strlen(scan_data8),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_DEL, item_id,
                              object_id, keywords8, NULL, 1, 0);
    EXPECT_EQ(ret, 1);
    
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                              object_id, keywords7, NULL, 1, 0);
   
    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(&results, 0, sizeof(results));
    ret = maat_scan_string(maat_inst, table_id, scan_data7, strlen(scan_data7),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, ObjectScan) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "HTTP_URL";
	const char *rule_table_name = "RULE_DEFAULT";
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GE(table_id, 0);

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table add line */
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object_id, rule_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    struct maat_hit_object hit_object;
    hit_object.object_id = object_id;
    hit_object.attribute_id = table_id;
    ret = maat_scan_object(maat_inst, table_id, &hit_object, 1, results, ARRAY_SIZE,
                          &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);

    maat_state_free(state);
    state = NULL;
}

/** 
 *  Filter such as URL: http://filtermenot.com  => {attribute_id, object_id}
    One rule reference this filter twice, the rule should be hit. 
 */
TEST_F(MaatCmd, SameFilterRefByOneRule) {
    const char *attribute_name = "HTTP_URL_FILTER";
    const char *scan_data = "http://filtermenot.com";
    const char *keywords = "menot.com";
    const char *rule_table_name = "RULE_DEFAULT";
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, attribute_name);
    ASSERT_GT(table_id, 0);

    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule_id, "null", 2, 0); // rule has two condition
    EXPECT_EQ(ret, 1);

    //condition1 & condition2 has same filter => {attribute_id, object_id}
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD, 
                                       object_id, rule_id, 0, attribute_name, 1, 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object_id, rule_id, 0, attribute_name, 2, 0);
    EXPECT_EQ(ret, 1);

    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, "HTTP_URL", MAAT_OP_ADD, item_id, object_id,
                              keywords, "null", 1, 0);
    EXPECT_EQ(ret, 1); 

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, RuleIDRecycle) {
    const char *table_name = "HTTP_URL";
	const char *scan_data = "Reuse rule ID is allowed.";
	const char *keywords = "Reuse&rule";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    test_add_expr_command(maat_inst, table_name, rule_id, 0, keywords);
    sleep(WAIT_FOR_EFFECTIVE_S);

    int ret = maat_scan_string(maat_inst, table_id, scan_data,
                               strlen(scan_data), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    del_command(maat_inst, rule_id);
    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    test_add_expr_command(maat_inst, table_name, rule_id, 0, keywords);
    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(results, 0, sizeof(results));
    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, ReturnRuleIDWithDescendingOrder) {
    const char *table_name = "HTTP_URL";
	const char *scan_data = "This string will hit mulptiple rules.";
	const char *keywords = "string will hit";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int i = 0;
    int repeat_times = 4;
    long long expect_rule_id[ARRAY_SIZE] = {0};
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", repeat_times);

    for (i = 0; i < repeat_times; i++) {
        //add in ascending order
        expect_rule_id[i] = rule_id + 1 - repeat_times + i;
        test_add_expr_command(maat_inst, table_name, expect_rule_id[i], 0, keywords);
    }

    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, repeat_times);
    for (i = 0; i < repeat_times; i++) {
        EXPECT_EQ(results[i], expect_rule_id[repeat_times -i - 1]);
    }

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

TEST_F(MaatCmd, SubObject) {
    const char *table_name = "HTTP_URL";
    const char *rule_table_name = "RULE_DEFAULT";
	const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char *g2g_table_name = "OBJECT2OBJECT";
	const char *scan_data1 = "www.v2ex.com/t/573028#程序员的核心竞争力是什么";
	const char *keyword1 = "程序员&核心竞争力";
	const char *scan_data2 = "https://ask.leju.com/bj/detail/12189672562229248/?bi=tg&type=sina-pc"
                             "&pos=index-dbtlwzl&wt_campaign=M_5CE750003F393&wt_source=PDPS_514ACACFD9E770";
	const char *keyword2 = "ask.leju.com/b&/detail/12189672562229248/?&?bi=tg\\&type=sina-pc\\&&\\&pos="
                           "index-dbtlwzl\\&&\\&type=sina-pc\\&pos=index-dbtlwzl\\&";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

     /* rule table add line */
     //rule1
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                     rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //rule2
    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                 rule2_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* object2rule table add line */
    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD, 
                                       object1_id, rule1_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule2
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD, 
                                       object1_id, rule2_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    //object2 -> object1 -> rule1
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2object_table_set_line(maat_inst, g2g_table_name, MAAT_OP_ADD,
                                     object1_id, object2_id, 0);
    EXPECT_EQ(ret, 1);

    /* item1 -> object2 -> object1 -> rule1
                             \
                              \ _  rule2
    */
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                              object2_id, keyword1, NULL, 1, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], rule2_id);
    EXPECT_EQ(results[1], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /* item1 -> object2 -> object1 -> rule1
                          \
                           \_ X -> rule2
    */
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL,
                                       object1_id, rule2_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);
    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /* item1 -> object2 -> object1 -> X 
                  \
                   \_ -> rule2
    */
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL,
                                       object1_id, rule1_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object2_id, rule2_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);
    ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule2_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /*  item1 -> object2 -> object1 -> X 
                  \
                   \_ -> rule2
        item2 -> object3
    */
    long long object3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2object_table_set_line(maat_inst, g2g_table_name, MAAT_OP_ADD,
                                     object1_id, object3_id, 0);
    EXPECT_EQ(ret, 1);

    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item2_id,
                              object3_id, keyword2, NULL, 1, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    sleep(2);
    ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /*  item1 -> object2 -> object1 -> X
                  \
                   \_ -> rule2
        item2 -> object3
    */
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL,
                                       object1_id, rule1_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);
    ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule2_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, RefObject) {
    const char *table_name = "HTTP_URL";
    const char* rule_table_name = "RULE_DEFAULT";
	const char* g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char* scan_data1 = "m.facebook.com/help/2297503110373101?helpref=hc_nav&refid=69";
	const char* keyword1 = "something-should-not-hit";
	const char* keyword2 = "facebook.com/help/2297503110373101";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    //TODO: value=0 MAAT_OPT_ENABLE_UPDATE
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                     rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item1_id,
                              object1_id, keyword1, NULL, 1, 0); /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    /* item1 -> object1 -> X -> rule1
                                 /
                                /
                item2 -> object2
    */
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object2_id, rule1_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item2_id,
                              object2_id, keyword2, NULL, 1, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, 
                                 rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                 rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL, 
                                       object1_id, rule1_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD, 
                                       object2_id, rule1_id, 0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, Attribute) {
    const char* rule_table_name = "RULE_DEFAULT";
    const char* g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char* table_name="HTTP_SIGNATURE";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                     rule1_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0,
                                       "HTTP_REQUEST_HEADER", 1, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item1_id,
                              object1_id, "AppleWebKit", "User-Agent", 0, 0);/*EXPR_TYPE_STRING MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                              /
                      object2_/
    */
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object2_id, rule1_id, 0,
                                       "HTTP_RESPONSE_HEADER", 2, 0);
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                              /
              item2 -> object2/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item2_id,
                              object2_id, "uid=12345678;", "Cookie", 0, 0);/*EXPR_TYPE_STRING MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

	const char* http_req_hdr_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                  "(KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36";
	const char* http_resp_hdr_cookie = "uid=12345678;BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; sugstore=1;";
    const char *district_str1 = "User-Agent";
    const char *district_str2 = "Cookie";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_inst, "HTTP_REQUEST_HEADER");
    ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, district_str1,
                                       strlen(district_str1));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, table_id, http_req_hdr_ua,
                           strlen(http_req_hdr_ua), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    table_id = maat_get_table_id(maat_inst, "HTTP_RESPONSE_HEADER");
    ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, district_str2,
                                       strlen(district_str2));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, table_id, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //delete object1
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL,
                                       object1_id, rule1_id, 0,
                                       "HTTP_REQUEST_HEADER", 1, 0);
    EXPECT_EQ(ret, 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule1_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    table_id = maat_get_table_id(maat_inst, "HTTP_RESPONSE_HEADER");
    ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, district_str2,
                                       strlen(district_str2));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, table_id, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, SetLines) {
    int i = 0;
    const int TEST_CMD_LINE_NUM = 4;
    const char *table_name = "QD_ENTRY_INFO";
    struct maat_cmd_line line_rule;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    long long expect_rule_id[TEST_CMD_LINE_NUM] = {0};
    const char *table_line_add[TEST_CMD_LINE_NUM] = {
        "1\t192.168.0.1\t100\t1",
        "1\t192.168.0.1\t101\t1",
        "1\t192.168.0.1\t102\t1",
        "1\t192.168.0.1\t103\t1",
        };
    const char *table_line_del[TEST_CMD_LINE_NUM] = {
        "1\t192.168.0.1\t100\t0",
        "1\t192.168.0.1\t101\t0",
        "1\t192.168.0.1\t102\t0",
        "1\t192.168.0.1\t103\t0",
        };
    int ret = 0;

    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        expect_rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
        line_rule.rule_id = expect_rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_add[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_ADD);
        EXPECT_GT(ret, 0);
    }

    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_id = expect_rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_del[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_DEL);
        EXPECT_GT(ret, 0);
    }
}

int g_test_update_paused = 0;
void pause_update_test_entry_cb(int table_id,const char* table_line, enum maat_operation op, void* u_para)
{
	char status[32] = {0};
	int entry_id = -1, seq = -1;
	int is_valid = 0;

	sscanf(table_line, "%d\t%s\t%d\t%d", &seq, status, &entry_id, &is_valid);
	EXPECT_EQ(g_test_update_paused, 0);
}

TEST_F(MaatCmd, PauseUpdate) {
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    const char *table_name = "QD_ENTRY_INFO";

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_table_callback_register(maat_inst, table_id, NULL,
                                           pause_update_test_entry_cb,
                                           NULL, NULL);
    //TODO: value = 0 MAAT_OPT_ENABLE_UPDATE
    g_test_update_paused = 1;

    char *line = NULL;
    struct maat_cmd_line line_rule;
    line_rule.rule_id = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
    line_rule.table_name = table_name;
    asprintf(&line, "1\t192.168.0.1\t101\t1");
    line_rule.table_line = line;
    line_rule.expire_after = 0;

    ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_ADD);
    EXPECT_EQ(ret, 1);
    free(line);
    
    g_test_update_paused = 0;
    //TODO: value = 1 MAAT_OPT_ENABLE_UPDATE
}

void prepare_file_to_set(const char* filename, char** file_buff,
                         size_t *file_size, char* file_key, size_t key_size)
{
	int i=0;
	struct stat file_info;
	unsigned char md5[MD5_DIGEST_LENGTH];
	char md5string[2*MD5_DIGEST_LENGTH+1];
	memset(md5, 0, sizeof(md5));
	memset(md5string, 0, sizeof(md5string));

	int ret = stat(filename, &file_info);
	ASSERT_TRUE(ret == 0);

	FILE *fp=fopen(filename,"r");
	ASSERT_FALSE(fp == NULL);

	*file_size = file_info.st_size;
    *file_buff = ALLOC(char, *file_size + 1);
	ret = fread(*file_buff, 1, *file_size, fp);
	fclose(fp);
	
	MD5((const unsigned char *)(*file_buff), (unsigned long)(*file_size), md5);
	for (i = 0; i < MD5_DIGEST_LENGTH; ++i) {
		sprintf(&md5string[i*2], "%02x", (unsigned int)md5[i]);
	}
	snprintf(file_key, key_size, "__FILE_%s", md5string);
}

int is_same_file(const char *filename1, const char *filename2)
{
	char md5string[2][MD5_DIGEST_LENGTH*2+1];
	memset(md5string, 0, sizeof(md5string));
	md5_file(filename1, md5string[0]);
	md5_file(filename2, md5string[1]);

	if (0 == strcmp(md5string[0], md5string[1])) {
		return 1;
	} else {
		return 0;
	}
}

int g_test_foregin_read_OK = 0, g_test_foreign_del_OK = 0;
char file1_to_del[256], file2_to_del[256];
const char* empty_file_name = "An_empty_file";
void foreign_key_test_entry_cb(int table_id, const char *table_line, enum maat_operation op, void *u_para)
{
	int rule_id=-1, not_care=0, tag=0;
	int is_valid=0;
	char file1_origin_name[256], file2_origin_name[256];
	char file1_localname[256], file2_localname[256];
	char end[16];

	memset(file1_localname, 0, sizeof(file1_localname));
	memset(file2_localname, 0, sizeof(file2_localname));
	
	sscanf(table_line, "%d\t%d\t%d\t%d\t%s\t%s\t\%s\t%s\t%s",
           &rule_id, &not_care, &tag, &is_valid, file1_origin_name, 
           file1_localname, file2_origin_name, file2_localname, end);
	EXPECT_STREQ(end, "End");

	if (is_valid == 1) {		
		EXPECT_TRUE(is_same_file(file1_origin_name, file1_localname));
		if (0 == strncmp(file2_origin_name, empty_file_name, strlen(empty_file_name))) {
			EXPECT_TRUE(0==strncasecmp(file2_localname, "null", strlen("null")));
		} else {
			EXPECT_TRUE(is_same_file(file2_origin_name, file2_localname));
		}
		g_test_foregin_read_OK = 1;
	} else {
		strcpy(file1_to_del, file1_localname);
		strcpy(file2_to_del, file2_localname);
		g_test_foreign_del_OK = 1;
	}
}

TEST_F(MaatCmd, SetFile) {
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    const char* table_name = "TEST_FOREIGN_KEY";

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_table_callback_register(maat_inst, table_id, NULL,
                                           foreign_key_test_entry_cb,
                                           NULL, NULL);
    EXPECT_EQ(ret, 0);

    const char *file1_name = "./testdata/digest_test.data";
    const char *file2_name = "./testdata/mesa_logo.jpg";	
	char *file_buff = NULL, file1_key[256], file2_key[256];
	size_t file_size = 0;

    prepare_file_to_set(file1_name, &file_buff, &file_size, file1_key,
                        sizeof(file1_key));
    ret = maat_cmd_set_file(maat_inst, file1_key, file_buff, file_size, MAAT_OP_ADD);
	EXPECT_EQ(ret, 1);
	free(file_buff);
	file_buff = NULL;

    prepare_file_to_set(file2_name, &file_buff, &file_size, file2_key,
                        sizeof(file2_key));
	ret = maat_cmd_set_file(maat_inst, file2_key, file_buff, file_size, MAAT_OP_ADD);
	EXPECT_EQ(ret, 1);
	free(file_buff);
	file_buff = NULL;
	g_test_foregin_read_OK = 0;

    char line[1024] = {0};
    int tag = 0;
    struct maat_cmd_line line_rule;
    line_rule.rule_id = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
    line_rule.table_name = table_name;
    snprintf(line, sizeof(line),"%lld\t2\t%d\t1\t%s\tredis://%s\t%s\tredis://%s\tEnd",
             line_rule.rule_id, tag, file1_name, file1_key, file2_name, file2_key);
    line_rule.table_line = line;
    line_rule.expire_after = 0;

    ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_ADD);
    EXPECT_EQ(ret, 1);
	sleep(WAIT_FOR_EFFECTIVE_S);//wait for callback triggered.
	EXPECT_EQ(g_test_foregin_read_OK, 1);

    g_test_foreign_del_OK = 0;
    ret = maat_cmd_set_file(maat_inst, file1_key, NULL, 0, MAAT_OP_DEL);
    EXPECT_EQ(ret, 1);
    ret = maat_cmd_set_file(maat_inst, file2_key, NULL, 0, MAAT_OP_DEL);
    EXPECT_EQ(ret, 1);

    struct maat_cmd_line line_rule_del;
    line_rule_del.rule_id = line_rule.rule_id;
    line_rule_del.table_name = line_rule.table_name;
    memset(line, 0, sizeof(line));
    snprintf(line, sizeof(line), "%lld\t2\t%d\t0\t%s\tredis://%s\t%s\tredis://%s\tEnd",
             line_rule.rule_id, tag, file1_name, file1_key, file2_name, file2_key);
    line_rule_del.table_line = line;
    line_rule_del.expire_after = 0;
    ret = maat_cmd_set_line(maat_inst, &line_rule_del, MAAT_OP_DEL);
    EXPECT_EQ(ret, 1);
    sleep(WAIT_FOR_EFFECTIVE_S);

    struct stat file_info;	
	ret = stat(file1_to_del, &file_info);
	EXPECT_EQ(ret, -1);
	ret = stat(file2_to_del, &file_info);
	EXPECT_EQ(ret, -1);

    // Test empty file, file key is a string "null".
    memset(&line_rule, 0, sizeof(line_rule));
    memset(line, 0, sizeof(line));
    line_rule.rule_id = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
    line_rule.table_name=table_name;
    snprintf(line, sizeof(line),"%lld\t2\t%d\t1\t%s\tredis://%s\t%s\t%s\tEnd",
             line_rule.rule_id, tag, file1_name, file1_key, empty_file_name, "null");
	line_rule.table_line = line;
	line_rule.expire_after = 0;

    g_test_foregin_read_OK = 0;

    ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_ADD);
    EXPECT_EQ(ret, 1);
	sleep(WAIT_FOR_EFFECTIVE_S);//wait for callback triggered.
	EXPECT_EQ(g_test_foregin_read_OK, 1);
}

struct user_info {
	char name[256];
	char ip_addr[32];
	int id;
};
void plugin_ex_new_cb(const char *table_name, int table_id, const char *key, 
                      const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	struct user_info *u = ALLOC(struct user_info, 1);

	int ret = sscanf(table_line, "%d\t%s\t%s", &(u->id), u->ip_addr, u->name);
	EXPECT_EQ(ret, 3);

	*ad = u;
	(*counter)++;
}

void plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct user_info *u = (struct user_info *)(*ad);

    memset(u, 0, sizeof(struct user_info));
	free(u);
	*ad = NULL;
}

void plugin_ex_dup_cb(int table_id,	void **to, void **from, long argl, void *argp)
{
	struct user_info *u = (struct user_info *)(*from);

	*to = u;
}

TEST_F(MaatCmd, RuleEXData) {
    const char *plugin_table_name = "RULE_FIREWALL_PLUGIN";
    const char *rule_table_name = "RULE_FIREWALL_DEFAULT";
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    int *ex_data_counter = MaatCmd::_ex_data_counter;
    int plugin_table_id = maat_get_table_id(maat_inst, plugin_table_name);
    EXPECT_GT(plugin_table_id, 0);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "test:rule1,1111", 1, 0);
    EXPECT_EQ(ret, 1);

    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule2_id, "test:rule2,2222", 1, 0);
    sleep(WAIT_FOR_EFFECTIVE_S);

    *ex_data_counter = 0;
    ret = maat_plugin_table_ex_schema_register(maat_inst, plugin_table_name,
                                               rule_ex_param_new,
                                               rule_ex_param_free,
                                               rule_ex_param_dup,
                                               0, ex_data_counter);
    ASSERT_TRUE(ret == 0);
    EXPECT_EQ(*ex_data_counter, 2);

    void *ex_data = maat_plugin_table_get_ex_data(maat_inst, plugin_table_id,
                                                 (char *)&rule1_id,
                                                 sizeof(long long));
    ASSERT_TRUE(ex_data != NULL);
    struct rule_ex_param *param = (struct rule_ex_param *)ex_data;
	EXPECT_EQ(param->id, 1111);

    ex_data = maat_plugin_table_get_ex_data(maat_inst, plugin_table_id,
                                            (char *)&rule2_id,
                                            sizeof(long long));
    ASSERT_TRUE(ex_data != NULL);
    param = (struct rule_ex_param *)ex_data;
	EXPECT_EQ(param->id, 2222);

    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule2_id, "test:rule2,2222", 1, 0);
    sleep(WAIT_FOR_EFFECTIVE_S);
    EXPECT_EQ(param->id, 2222); 
    sleep(2);
    //excced gc_timeout_s(3s), the data pointed by param has been freed
}

TEST_F(MaatCmd, PluginEXData) {
    const char *table_name = "TEST_PLUGIN_EXDATA_TABLE";
    const int TEST_CMD_LINE_NUM = 4;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    int *ex_data_counter = MaatCmd::_ex_data_counter;
	const char *table_line_add[TEST_CMD_LINE_NUM] = {
        "1\t192.168.0.1\tmahuateng\t1\t0",
		"2\t192.168.0.2\tliuqiangdong\t1\t0",
		"3\t192.168.0.3\tmayun\t1\t0",
		"4\t192.168.0.4\tliyanhong\t1\t0"
    };

    const char *table_line_del[TEST_CMD_LINE_NUM] = {
        "1\t192.168.0.1\tmahuateng\t0\t0",
		"2\t192.168.0.2\tliuqiangdong\t0\t0",
		"3\t192.168.0.3\tmayun\t0\t0",
		"4\t192.168.0.4\tliyanhong\t0\t0"
    };

	int table_id = maat_get_table_id(maat_inst, table_name);
	ASSERT_GT(table_id, 0);
    
    int i = 0, ret = 0;
    struct maat_cmd_line line_rule;
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    /* 1st line */
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_add[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_ADD);
        EXPECT_GT(ret, 0);
    }
	
    sleep(WAIT_FOR_EFFECTIVE_S);

    *ex_data_counter = 0;
	ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
								               plugin_ex_new_cb,
								               plugin_ex_free_cb,
								               plugin_ex_dup_cb,
								               0, ex_data_counter);
	ASSERT_TRUE(ret >= 0);
	EXPECT_EQ(*ex_data_counter, TEST_CMD_LINE_NUM);
	
	struct user_info *uinfo1 = NULL;
    const char *key1 = "192.168.0.2";

	uinfo1 = (struct user_info *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                               key1, strlen(key1));
	ASSERT_TRUE(uinfo1 != NULL);
	EXPECT_EQ(0, strcmp(uinfo1->name, "liuqiangdong"));
	EXPECT_EQ(uinfo1->id, 2);
    
    //DEL
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = rule_id[1];
    line_rule.table_name = table_name;
    line_rule.table_line = table_line_del[1];
    line_rule.expire_after = 0;

	ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_DEL);
	EXPECT_GT(ret, 0);

	sleep(WAIT_FOR_EFFECTIVE_S); //gc_timeout_s == 3 which configured in table_info

    struct user_info *uinfo2 = NULL;
	uinfo2 = (struct user_info *)maat_plugin_table_get_ex_data(maat_inst, table_id,
                                                               key1, strlen(key1));
	ASSERT_TRUE(uinfo2 == NULL);

    //the data pointed by uinfo1 has in garbage queue, but not be freed yet
    EXPECT_EQ(0, strcmp(uinfo1->name, "liuqiangdong"));
	EXPECT_EQ(uinfo1->id, 2);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);
    //exceed gc_timeout_s, the data pointed by uinfo1 has been freed
}

TEST_F(MaatCmd, UpdateIPPlugin) {
    const char *table_name = "TEST_IP_PLUGIN_WITH_ADDR_FORMAT";
	const int TEST_CMD_LINE_NUM = 4;
	struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    int *ex_data_counter = MaatCmd::_ex_data_counter;
	const char *table_line_add[TEST_CMD_LINE_NUM] = {
        "101\t4\t192.168.30.98/31\tSomething-like-json\t1",
		"102\t4\t192.168.30.90-192.168.30.128\tBigger-range-should-in-the-back\t1",
        "103\t6\t2001:db8:1234::-2001:db8:1235::\tBigger-range-should-in-the-back\t1",
		"104\t6\t2001:db8:1234::1-2001:db8:1234::5210\tSomething-like-json\t1"};
    const char *table_line_del[TEST_CMD_LINE_NUM] = {
        "101\t4\t192.168.30.98/31\tSomething-like-json\t0",
		"102\t4\t192.168.30.90-192.168.30.128\tBigger-range-should-in-the-back\t0",
        "103\t6\t2001:db8:1234::-2001:db8:1235::\tBigger-range-should-in-the-back\t0",
		"104\t6\t2001:db8:1234::1-2001:db8:1234::5210\tSomething-like-json\t0"};

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);
    
    int i = 0, ret = 0;
    struct maat_cmd_line line_rule;
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    //add lines
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_add[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_ADD);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S);

    *ex_data_counter = 0;
	ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
								               ip_plugin_ex_new_cb,
								               ip_plugin_ex_free_cb,
								               ip_plugin_ex_dup_cb,
								               0, ex_data_counter);
	ASSERT_TRUE(ret >= 0);
	EXPECT_EQ(*ex_data_counter, TEST_CMD_LINE_NUM);

    struct ip_addr ipv4, ipv6;
    struct ip_plugin_ud *results[ARRAY_SIZE];
    ipv4.ip_type = IPV4;
    inet_pton(AF_INET, "192.168.30.99", &(ipv4.ipv4));

    memset(results, 0, sizeof(results));
    ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_id, &ipv4,
                                           (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(results[0]->rule_id, 101);
    EXPECT_EQ(results[1]->rule_id, 102);

    ipv6.ip_type = 6;
    inet_pton(AF_INET6, "2001:db8:1234::5210", &(ipv6.ipv6));

    memset(results, 0, sizeof(results));
    ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_id, &ipv6,
                                           (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(results[0]->rule_id, 104);
    EXPECT_EQ(results[1]->rule_id, 103);

    //del lines
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_del[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_DEL);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S); //gc_timeout_s == 3 which configured in table_info

    ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_id, &ipv4,
                                          (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 0);

    //the data pointed by results[idx] has in garbage queue, but not be freed yet
    EXPECT_EQ(results[0]->rule_id, 104);
    EXPECT_EQ(results[1]->rule_id, 103);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);
    //exceed gc_timeout_s, the data pointed by results[idx] has been freed
}

TEST_F(MaatCmd, UpdateFQDNPlugin) {
    const char *table_name = "TEST_FQDN_PLUGIN_WITH_EXDATA";
	const int TEST_CMD_LINE_NUM = 5;
	struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    int *ex_data_counter = MaatCmd::_ex_data_counter;
    const char *table_line_add[TEST_CMD_LINE_NUM]={
		"201\twww.example1.com\tcatid=1\t1",
		"202\t*.example1.com\tcatid=1\t1",
		"203\tnews.example1.com\tcatid=2\t1",
		"204\tr3---sn-i3belne6.example2.com\tcatid=3\t1",
		"205\tr3---sn-i3belne6.example2.com\tcatid=3\t1"};
    const char *table_line_del[TEST_CMD_LINE_NUM]={
		"201\twww.example1.com\tcatid=1\t0",
		"202\t*.example1.com\tcatid=1\t0",
		"203\tnews.example1.com\tcatid=2\t0",
		"204\tr3---sn-i3belne6.example2.com\tcatid=3\t0",
		"205\tr3---sn-i3belne6.example2.com\tcatid=3\t0"};
    
    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);
    
    int i = 0, ret = 0;
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    struct maat_cmd_line line_rule;
    //add lines
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_add[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_ADD);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S);

    *ex_data_counter = 0;
    ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                               fqdn_plugin_ex_new_cb,
                                               fqdn_plugin_ex_free_cb,
                                               fqdn_plugin_ex_dup_cb,
                                               0, ex_data_counter);
    ASSERT_TRUE(ret >= 0);
	EXPECT_EQ(*ex_data_counter, 5);

    struct fqdn_plugin_ud *results[ARRAY_SIZE];
    memset(results, 0, sizeof(results));

    ret = maat_fqdn_plugin_table_get_ex_data(maat_inst, table_id,
                                             "r3---sn-i3belne6.example2.com", 
                                             (void**)results, ARRAY_SIZE);
    ASSERT_EQ(ret, 2);
    EXPECT_EQ(results[0]->catid, 3);

    //del lines
    for (i = 3; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_del[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_DEL);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S);
    ret = maat_fqdn_plugin_table_get_ex_data(maat_inst, table_id, 
                                            "r3---sn-i3belne6.example2.com", 
                                            (void**)results, ARRAY_SIZE);
    ASSERT_EQ(ret, 0);                                 
    EXPECT_EQ(results[0]->catid, 3);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);
    //exceed gc_timeout_s, the data pointed by results[idx] has been freed
}

TEST_F(MaatCmd, UpdateBoolPlugin) {
    const char *table_name = "TEST_BOOL_PLUGIN_WITH_EXDATA";
	const int TEST_CMD_LINE_NUM = 6;
	struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    int *ex_data_counter = MaatCmd::_ex_data_counter;
    const char *table_line_add[TEST_CMD_LINE_NUM] = {
		"301\t1&2&1000\ttunnel1\t1",
		"302\t101&102\ttunnel2\t1",
		"303\t102\ttunnel3\t1",
		"304\t101\ttunnel4\t1",
		"305\t0&1&2&3&4&5&6&7\ttunnel5\t1",
		"306\t101&101\tinvalid\t1"};
    const char *table_line_del[TEST_CMD_LINE_NUM] = {
        "301\t1&2&1000\ttunnel1\t0",
		"302\t101&102\ttunnel2\t0",
		"303\t102\ttunnel3\t0",
		"304\t101\ttunnel4\t0",
		"305\t0&1&2&3&4&5&6&7\ttunnel5\t0",
		"306\t101&101\tinvalid\t0"};
    
    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);
    
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    struct maat_cmd_line line_rule;
    int i = 0, ret = 0;

    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_add[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_ADD);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S);

    *ex_data_counter = 0;
    ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
								               bool_plugin_ex_new_cb,
								               bool_plugin_ex_free_cb,
								               bool_plugin_ex_dup_cb,
								               0, ex_data_counter);
	ASSERT_TRUE(ret>=0);
	EXPECT_EQ(*ex_data_counter, 6);

    unsigned long long items[] = {101, 102, 1000};
    struct bool_plugin_ud *results[ARRAY_SIZE];
    memset(results, 0, sizeof(results));
    ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_id, items, 3,
                                             (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 4);
    EXPECT_EQ(results[0]->name_len, 8);

    for (i = 3; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_del[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_DEL);
        EXPECT_GT(ret, 0);
    }
    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_id, items, 3,
                                             (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(results[0]->name_len, 8);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);
    //exceed gc_timeout_s, the data pointed by results[idx] has been freed
}

#define RULE_ID_NUMS 1000
TEST_F(MaatCmd, ObjectInMassRules) {
    const char* g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char* rule_table_name = "RULE_DEFAULT";
	const char* table_url = "HTTP_URL";
	const char* table_appid = "APP_ID";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //item_url1 -> object1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    int ret = expr_table_set_line(maat_inst, table_url, MAAT_OP_ADD, item1_id,
                                  object1_id, "baidu.com&tsg", NULL, 1, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    //item_url2 -> object2
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, table_url, MAAT_OP_ADD, item2_id,
                              object2_id, "baidu.com&zhengzhou", NULL, 1, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    //item_appid -> object3
    long long object3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    long long item3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = interval_table_set_line(maat_inst, table_appid, MAAT_OP_ADD, item3_id,
                                  object3_id, "100", NULL, 0);
    EXPECT_EQ(ret, 1);

    /*  item_url1 -> object1 -> rule[0 ~ RULE_ID_NUMS] 
                                /
          item_appid -> object3_/
    */
    int i = 0;
    long long rule_id[RULE_ID_NUMS] = {0};
    for (i = 0; i < RULE_ID_NUMS; i++) {
        rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
        ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule_id[i], "mass_rule", 2, 0);
        EXPECT_EQ(ret, 1);
    }

    for (i = 0; i < RULE_ID_NUMS; i++) {
        ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                           object1_id, rule_id[i], 0, table_url, 0, 0);
        EXPECT_EQ(ret, 1);

        ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                           object3_id, rule_id[i], 0, table_appid, 2, 0);
        EXPECT_EQ(ret, 1);
    }

    /* item_url2 -> object2 -> target_rule
                                    /
              item_appid -> object3_/
    */
    long long target_rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 target_rule_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object2_id, target_rule_id, 0, table_url, 1, 0);
    EXPECT_EQ(ret, 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object3_id, target_rule_id, 0, table_appid, 2, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url1 = "https://www.baidu.com/s?wd=tsg";
	const char* http_url2 = "https://www.baidu.com/s?wd=zhengzhou&rsv_spt=1"
                             "&rsv_iqid=0x8b4cae8100000560&issp=1&f=8&rsv_bp=1";

    int url_table_id = maat_get_table_id(maat_inst, table_url);
    ASSERT_GT(url_table_id, 0);

    int appid_table_id = maat_get_table_id(maat_inst, table_appid);
    ASSERT_GT(appid_table_id, 0);

    long long results[4] = {0};
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, url_table_id, http_url2, strlen(http_url2),
                           results, 4, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_integer(maat_inst, appid_table_id, 100, results, 4,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], target_rule_id);

    ret = maat_scan_not_logic(maat_inst, appid_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = maat_scan_string(maat_inst, url_table_id, http_url1, strlen(http_url1),
                           results, 4, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_integer(maat_inst, appid_table_id, 100, results, 4,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 4);

    ret = maat_scan_not_logic(maat_inst, appid_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, HitObject) {
   const char *rule_table_name = "RULE_DEFAULT";
	const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
    const char *g2g_table_name = "OBJECT2OBJECT";
	const char *http_sig_table_name = "HTTP_SIGNATURE";
	const char *ip_table_name = "IP_CONFIG";
	const char *keywords_table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    /* rule1 */
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0,
                                       "HTTP_REQUEST_HEADER", 1, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item1_id, object1_id, "hit object item first",
                              "URL", 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                             /
                    object21_/
    */
    long long object21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object21_id, rule1_id, 0,
                                       "HTTP_RESPONSE_HEADER", 2, 0);
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                            /
        object2 -> object21 _/
    */
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2object_table_set_line(maat_inst, g2g_table_name, MAAT_OP_ADD,
                                     object21_id, object2_id, 0);
    EXPECT_EQ(ret, 1);

    /*       item1 -> object1 -> rule1
                                    /
       item2 -> object2 -> object21 _/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item2_id, object2_id, "hit object item second",
                              "Cookie", 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /*
            item1 -> object1 -> object11
                        \
                          \ -> rule1
                                  /
     item2 -> object2 -> object21 _/             
    */
    long long object11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2object_table_set_line(maat_inst, g2g_table_name, MAAT_OP_ADD,
                                     object11_id, object1_id, 0);
    EXPECT_EQ(ret, 1);
    
    //item3 -> object3, object3 is not referenced by any rule.
    long long item3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item3_id,
                            object3_id, "220.181.38.150-220.181.38.151", 0);
    EXPECT_EQ(ret, 1);

    //item4 -> object4, object4 is not referenced by any rule.
    long long item4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item4_id, object4_id, "hit object item forth", NULL, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /*
            item1 -> object1 -> object11
                    /   \
          item5 -> /     \ -> rule1
                                  /
     item2 -> object2 -> object21 _/             
    */
    //item5 -> object1 which means object1 has multi items
    long long item5_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item5_id, object1_id,
                              "hit object item fifth",
                              NULL, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url = "en.wikipedia.org hit object item first";
	const char* http_resp_hdr_cookie = "laptop=thinkpad X1 extrem;hit object item second"
                                       "main[XWJOKE]=hoho; Hm_lvt_bbac0322e6ee13093f98d5c4b5a10912=1578874808;";

    int http_req_table_id = maat_get_table_id(maat_inst, "HTTP_REQUEST_HEADER");
    ASSERT_GT(http_req_table_id, 0);

    ret = maat_state_set_scan_district(state, http_req_table_id, "URL", strlen("URL"));
    EXPECT_EQ(ret, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, http_req_table_id, http_url, strlen(http_url),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    size_t scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 1);

    struct maat_hit_object hit_objects[128];
    memset(hit_objects, 0, sizeof(hit_objects));

    size_t n_hit_object = maat_state_get_direct_hit_object_cnt(state);
    maat_state_get_direct_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 1);
    EXPECT_EQ(hit_objects[0].item_id, item1_id);
    EXPECT_EQ(hit_objects[0].object_id, object1_id);
    EXPECT_EQ(hit_objects[0].attribute_id, http_req_table_id);

    memset(hit_objects, 0, sizeof(hit_objects));
    n_hit_object = maat_state_get_indirect_hit_object_cnt(state);
    maat_state_get_indirect_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 1);
    EXPECT_EQ(hit_objects[0].item_id, 0);
    EXPECT_EQ(hit_objects[0].object_id, object11_id);
    EXPECT_EQ(hit_objects[0].attribute_id, http_req_table_id);

    size_t n_last_hit_object = maat_state_get_last_hit_object_cnt(state);
    struct maat_hit_object last_hit_objects[128] = {0};
    maat_state_get_last_hit_objects(state, last_hit_objects, 128);
    EXPECT_EQ(n_last_hit_object, 2);

    EXPECT_EQ(last_hit_objects[0].item_id, item1_id);
    EXPECT_EQ(last_hit_objects[0].object_id, object1_id);
    EXPECT_EQ(last_hit_objects[0].attribute_id, http_req_table_id);

    EXPECT_EQ(last_hit_objects[1].item_id, 0);
    EXPECT_EQ(last_hit_objects[1].object_id, object11_id);
    EXPECT_EQ(last_hit_objects[1].attribute_id, http_req_table_id);

    int http_res_table_id = maat_get_table_id(maat_inst, "HTTP_RESPONSE_HEADER");
    ASSERT_GT(http_res_table_id, 0);

    const char *district_str1 = "Cookie";
    ret = maat_state_set_scan_district(state, http_res_table_id, district_str1,
                                       strlen(district_str1));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, http_res_table_id, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 2);

    memset(hit_objects, 0, sizeof(hit_objects));
    n_hit_object = maat_state_get_direct_hit_object_cnt(state);
    maat_state_get_direct_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 1);

    EXPECT_EQ(hit_objects[0].item_id, item2_id);
    EXPECT_EQ(hit_objects[0].object_id, object2_id);
    EXPECT_EQ(hit_objects[0].attribute_id, http_res_table_id);

    memset(hit_objects, 0, sizeof(hit_objects));
    n_hit_object = maat_state_get_indirect_hit_object_cnt(state);
    maat_state_get_indirect_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 1);
    EXPECT_EQ(hit_objects[0].item_id, 0);
    EXPECT_EQ(hit_objects[0].object_id, object21_id);
    EXPECT_EQ(hit_objects[0].attribute_id, http_res_table_id);
    
    n_last_hit_object = maat_state_get_last_hit_object_cnt(state);
    maat_state_get_last_hit_objects(state, last_hit_objects, 128);
    EXPECT_EQ(n_last_hit_object, 2);

    EXPECT_EQ(last_hit_objects[0].item_id, item2_id);
    EXPECT_EQ(last_hit_objects[0].object_id, object2_id);
    EXPECT_EQ(last_hit_objects[0].attribute_id, http_res_table_id);

    EXPECT_EQ(last_hit_objects[1].item_id, 0);
    EXPECT_EQ(last_hit_objects[1].object_id, object21_id);
    EXPECT_EQ(last_hit_objects[1].attribute_id, http_res_table_id);

    const char* keywords1="In graph theory, hit object item forth";
    const char *keywords2="To test one object hit object item fifth";
    
    int keywords_table_id = maat_get_table_id(maat_inst, keywords_table_name);
    ASSERT_GT(keywords_table_id, 0);

    struct maat_stream *stream = maat_stream_new(maat_inst, keywords_table_id, state);
    ret = maat_stream_scan(stream, keywords1, strlen(keywords1), results, ARRAY_SIZE,
                          &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 3);

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0);

    uint32_t ip_addr;
    inet_pton(AF_INET, "220.181.38.150", &ip_addr);
    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 4);

    memset(hit_objects, 0, sizeof(hit_objects));
    n_hit_object = maat_state_get_direct_hit_object_cnt(state);
    maat_state_get_direct_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 2);

    EXPECT_EQ(hit_objects[0].item_id, item4_id);
    EXPECT_EQ(hit_objects[0].object_id, object4_id);
    EXPECT_EQ(hit_objects[0].attribute_id, keywords_table_id); //physical table(keywords_table) attribute_id is 0
 
    EXPECT_EQ(hit_objects[1].item_id, item3_id);
    EXPECT_EQ(hit_objects[1].object_id, object3_id);
    EXPECT_EQ(hit_objects[1].attribute_id, ip_table_id);

    ret = maat_stream_scan(stream, keywords2, strlen(keywords2), results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 5);

    memset(hit_objects, 0, sizeof(hit_objects));
    n_hit_object = maat_state_get_direct_hit_object_cnt(state);
    maat_state_get_direct_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 2);

    EXPECT_EQ(hit_objects[0].item_id, item5_id);
    EXPECT_EQ(hit_objects[0].object_id, object1_id);
    EXPECT_EQ(hit_objects[0].attribute_id, keywords_table_id); //physical table(keywords_table) attribute_id is 0

    EXPECT_EQ(hit_objects[1].item_id, item4_id);
    EXPECT_EQ(hit_objects[1].object_id, object4_id);
    EXPECT_EQ(hit_objects[1].attribute_id, keywords_table_id); //physical table(keywords_table) attribute_id is 0

    n_last_hit_object = maat_state_get_last_hit_object_cnt(state);
    maat_state_get_last_hit_objects(state, last_hit_objects, 128);
    EXPECT_EQ(n_last_hit_object, 3);

    EXPECT_EQ(last_hit_objects[0].item_id, item5_id);
    EXPECT_EQ(last_hit_objects[0].object_id, object1_id);
    EXPECT_EQ(last_hit_objects[0].attribute_id, keywords_table_id);

    EXPECT_EQ(last_hit_objects[1].item_id, item4_id);
    EXPECT_EQ(last_hit_objects[1].object_id, object4_id);
    EXPECT_EQ(last_hit_objects[1].attribute_id, keywords_table_id);

    EXPECT_EQ(last_hit_objects[2].item_id, 0);
    EXPECT_EQ(last_hit_objects[2].object_id, object11_id);
    EXPECT_EQ(last_hit_objects[2].attribute_id, keywords_table_id);

    maat_stream_free(stream);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, HitPathBasic) {
    const char *g2g_table_name = "OBJECT2OBJECT";
	const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *http_sig_table_name = "HTTP_SIGNATURE";
	const char *ip_table_name = "IP_CONFIG";
	const char *keywords_table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    /* rule1 */
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0,
                                       "HTTP_REQUEST_HEADER", 1, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item1_id, object1_id, "graph_theory", "URL",
                              0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                             /
                    object21_/
    */
    long long object21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object21_id, rule1_id, 0,
                                       "HTTP_RESPONSE_HEADER", 2, 0);
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                            /
        object2 -> object21 _/
    */
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2object_table_set_line(maat_inst, g2g_table_name, MAAT_OP_ADD,
                                     object21_id, object2_id, 0);
    EXPECT_EQ(ret, 1);

    /*       item1 -> object1 -> rule1
                                    /
       item2 -> object2 -> object21 _/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item2_id, object2_id, "time=2020-02-11", "Cookie",
                              0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /*
            item1 -> object1 -> object11
                        \
                          \ -> rule1
                                  /
     item2 -> object2 -> object21 _/             
    */
    long long object11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2object_table_set_line(maat_inst, g2g_table_name, MAAT_OP_ADD,
                                     object11_id, object1_id, 0);
    EXPECT_EQ(ret, 1);
    
    //item3 -> object3, object3 is not referenced by any rule.
    long long item3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item3_id,
                            object3_id, "220.181.38.148-220.181.38.149", 0);
    EXPECT_EQ(ret, 1);

    //item4 -> object4, object4 is not referenced by any rule.
    long long item4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item4_id, object4_id,
                              "a finite or infinite",
                              NULL, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url = "en.wikipedia.org/wiki/Path_(graph_theory)";
	const char* http_resp_hdr_cookie = "laptop=thinkpad X1 extrem;time=2020-02-11T15:34:00;"
                                       "main[XWJOKE]=hoho; Hm_lvt_bbac0322e6ee13093f98d5c4b5a10912=1578874808;";

    int http_req_table_id = maat_get_table_id(maat_inst, "HTTP_REQUEST_HEADER");
    ASSERT_GT(http_req_table_id, 0);

    ret = maat_state_set_scan_district(state, http_req_table_id, "URL", strlen("URL"));
    EXPECT_EQ(ret, 0);

    int Nth_scan = 0;

    Nth_scan++;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, http_req_table_id, http_url, strlen(http_url),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, http_req_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    size_t scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 1);

    struct maat_hit_path hit_path[128];
    memset(hit_path, 0, sizeof(hit_path));
    int n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 2);

    int path_idx = 0;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item1_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object11_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, http_req_table_id);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    path_idx++;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item1_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, http_req_table_id);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    int http_res_table_id = maat_get_table_id(maat_inst, "HTTP_RESPONSE_HEADER");
	ASSERT_GT(http_res_table_id, 0);

    ret = maat_state_set_scan_district(state, http_res_table_id, "Cookie",
                                       strlen("Cookie"));
    EXPECT_EQ(ret, 0);

    Nth_scan++;
    ret = maat_scan_string(maat_inst, http_res_table_id, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, http_res_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 2);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 4);
    
    path_idx = 0;
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan-1);
	EXPECT_EQ(hit_path[path_idx].item_id, item1_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object11_id);
    EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    path_idx++;
    ASSERT_EQ(path_idx, 1);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan-1);
	EXPECT_EQ(hit_path[path_idx].item_id, item1_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object1_id);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule1_id);

    path_idx++;
    ASSERT_EQ(path_idx, 2);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object21_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, http_res_table_id);
	EXPECT_EQ(hit_path[path_idx].rule_id, rule1_id);

    path_idx++;
    ASSERT_EQ(path_idx, 3);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, http_res_table_id);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);
    const char* keywords1="In graph theory, a path in a graph is a finite or infinite \
sequence of edges which joins a sequence of vertices which, by most definitions,\
are all distinct (and since the vertices are distinct, so are the edges). ";
	const char* keywords2="A directed path in a directed graph is a finite or infinite\
sequence of edges which joins a sequence of distinct vertices, but with the added restriction\
that the edges be all directed in the same direction.";

    int keywords_table_id = maat_get_table_id(maat_inst, keywords_table_name);
    ASSERT_GT(keywords_table_id, 0);

    struct maat_stream *stream = maat_stream_new(maat_inst, keywords_table_id, state);
    Nth_scan++;
    ret = maat_stream_scan(stream, keywords1, strlen(keywords1), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, keywords_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 3);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 5);

    path_idx++;
	ASSERT_EQ(path_idx, 4);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item4_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object4_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0);

    Nth_scan++;
    uint32_t ip_addr;
    inet_pton(AF_INET, "220.181.38.148", &ip_addr);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 4);
 
    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 6);

    path_idx++;
	ASSERT_EQ(path_idx, 5);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item3_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object3_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, ip_table_id);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    Nth_scan++;   
    ret = maat_stream_scan(stream, keywords2, strlen(keywords2), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, keywords_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 5);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 7);

    path_idx++;
	ASSERT_EQ(path_idx, 6);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item4_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object4_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);
    maat_stream_free(stream);
    maat_state_free(state);
    state = NULL; 
}

/* same object in multi rule */
/*
        item1 -> object1 -> rule1
                             /
                            /
    item2 -> object2 -> object21
                          \
                           \
    item3 -> object3 -> rule2
                \
                 \--> rule3
                      / 
    item4 -> object4 -/   
*/
TEST_F(MaatCmd, HitPathAdvanced) {
    const char *g2g_table_name = "OBJECT2OBJECT";
	const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *ip_table_name = "IP_CONFIG";
	const char *keywords_table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    /* rule1 */
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0,
                                       "KEYWORDS_TABLE", 1, 0); //condition_index:1
    EXPECT_EQ(ret, 1);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item1_id, object1_id, "computer_theory", NULL,
                              0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                             /
                    object21_/
    */
    long long object21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object21_id, rule1_id, 0,
                                       "KEYWORDS_TABLE", 2, 0); //condition_index:2
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                            /
        object2 -> object21 _/
    */
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2object_table_set_line(maat_inst, g2g_table_name, MAAT_OP_ADD,
                                     object21_id, object2_id, 0);
    EXPECT_EQ(ret, 1);

    /*       item1 -> object1 -> rule1
                                    /
       item2 -> object2 -> object21 _/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item2_id, object2_id, "social_theory", NULL,
                              0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);
   
    //rule2
    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule2_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    /*        item1 -> object1 -> rule1
                                    /
       item2 -> object2 -> object21 _/
                             \
                              \
                            rule2    
    */
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object21_id, rule2_id, 0,
                                       "KEYWORDS_TABLE", 3, 0); //condition_index:3
    EXPECT_EQ(ret, 1); 

    /*         item1 -> object1 -> rule1
                                    /
       item2 -> object2 -> object21 _/
                             \
                              \
        item3 -> object3 -> rule2 
    */
    long long item3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item3_id,
                            object3_id, "220.181.38.168-220.181.38.169", 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object3_id, rule2_id, 0,
                                       "IP_CONFIG", 4, 0); //condition_index:4
    EXPECT_EQ(ret, 1); 

    /*         item1 -> object1 -> rule1
                                    /
       item2 -> object2 -> object21 _/
                             \
                              \
        item3 -> object3 -> rule2 
                    \
                     \ --> rule3
    */
    long long rule3_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule3_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object3_id, rule3_id, 0,
                                       "IP_CONFIG", 5, 0); //condition_index:5
    EXPECT_EQ(ret, 1); 

    /*         item1 -> object1 -> rule1
                                    /
                                   /
            item2 -> object2 -> object21
                                  \
                                   \
             item3 -> object3 -> rule2 
                        \
                         \
                      rule3
                         /
                        /
           item4 -> object4
    */
    long long item4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item4_id, object4_id,
                              "basic and advanced",
                              NULL, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object4_id, rule3_id, 0,
                                       "KEYWORDS_TABLE", 6, 0); //condition_index:6
    EXPECT_EQ(ret, 1); 

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url_computer = "en.wikipedia.org/wiki/Path_(computer_theory)";
    const char* http_url_social = "en.wikipedia.org/wiki/Path_(social_theory)";

    int keywords_table_id = maat_get_table_id(maat_inst, "KEYWORDS_TABLE");
    ASSERT_GT(keywords_table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, keywords_table_id, http_url_computer,
                           strlen(http_url_computer), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    struct maat_hit_path hit_path[128];
    memset(hit_path, 0, sizeof(hit_path));
    int n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 1);

    int path_idx = 0;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
	EXPECT_EQ(hit_path[path_idx].item_id, item1_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, -1);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    ret = maat_scan_string(maat_inst, keywords_table_id, http_url_social,
                           strlen(http_url_social), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 3);
    
    path_idx = 0;
	EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
	EXPECT_EQ(hit_path[path_idx].item_id, item1_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 1);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule1_id);

    path_idx++;
    ASSERT_EQ(path_idx, 1);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object21_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 2);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule1_id);

    path_idx++;
    ASSERT_EQ(path_idx, 2);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, -1);
    EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    uint32_t ip_addr;
    inet_pton(AF_INET, "220.181.38.168", &ip_addr);

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0);

    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule2_id);

    memset(hit_path, 0, sizeof(hit_path));
    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 5);

    path_idx = 0;
	EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
	EXPECT_EQ(hit_path[path_idx].item_id, item1_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 1);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule1_id);

    path_idx++;
    ASSERT_EQ(path_idx, 1);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object21_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 3);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule2_id);

    path_idx++;
    ASSERT_EQ(path_idx, 2);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, -1);
    EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    path_idx++;
    ASSERT_EQ(path_idx, 3);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 3);
	EXPECT_EQ(hit_path[path_idx].item_id, item3_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object3_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object3_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, ip_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 4);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule2_id);

    path_idx++;
    ASSERT_EQ(path_idx, 4);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object21_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 2);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule1_id);

    const char *keywords1 = "In theory, basic and advanced is common";
    ret = maat_scan_string(maat_inst, keywords_table_id, keywords1,
                           strlen(keywords1), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule3_id);

    memset(hit_path, 0, sizeof(hit_path));
    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 7);

    path_idx = 0;
	EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
	EXPECT_EQ(hit_path[path_idx].item_id, item1_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 1);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule1_id);

    path_idx++;
    ASSERT_EQ(path_idx, 1);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object21_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 3);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule2_id);

    path_idx++;
    ASSERT_EQ(path_idx, 2);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, -1);
    EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    path_idx++;
    ASSERT_EQ(path_idx, 3);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 3);
	EXPECT_EQ(hit_path[path_idx].item_id, item3_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object3_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object3_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, ip_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 5);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule3_id);

    path_idx++;
    ASSERT_EQ(path_idx, 4);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 4);
	EXPECT_EQ(hit_path[path_idx].item_id, item4_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object4_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object4_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 6);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule3_id);

    path_idx++;
    ASSERT_EQ(path_idx, 5);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 3);
	EXPECT_EQ(hit_path[path_idx].item_id, item3_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object3_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object3_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, ip_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 4);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule2_id);

    path_idx++;
    ASSERT_EQ(path_idx, 6);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object21_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
	EXPECT_EQ(hit_path[path_idx].condition_index, 2);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule1_id);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, HitPathHasNotObject) {
    const char *g2g_table_name = "OBJECT2OBJECT";
	const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *http_sig_table_name = "HTTP_SIGNATURE";
	const char *ip_table_name = "IP_CONFIG";
	const char *keywords_table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    /* rule1 */
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    // !object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 1,
                                       "HTTP_REQUEST_HEADER", 1, 0);
    EXPECT_EQ(ret, 1);

    // !(item1 -> object1) -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item1_id, object1_id, "math_theory", "URL", 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* !(item1 -> object1) -> rule1
                             /
                    object21_/
    */
    long long object21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object21_id, rule1_id, 0,
                                       "HTTP_RESPONSE_HEADER", 2, 0);
    EXPECT_EQ(ret, 1);

    /* !(item1 -> object1) -> rule1
                            /
        object2 -> object21 _/
    */
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2object_table_set_line(maat_inst, g2g_table_name, MAAT_OP_ADD,
                                     object21_id, object2_id, 0);
    EXPECT_EQ(ret, 1);

    /*       !(item1 -> object1) -> rule1
                                    /
       item2 -> object2 -> object21 _/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item2_id, object2_id, "time=2020-02-12", "Cookie",
                              0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /*
          item1 -> object1 -> object11

            !(item1 -> object1) -> rule1
                                  /
     item2 -> object2 -> object21 _/
    */
    long long object11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2object_table_set_line(maat_inst, g2g_table_name, MAAT_OP_ADD,
                                     object11_id, object1_id, 0);
    EXPECT_EQ(ret, 1);
    
    //item3 -> object3, object3 is not referenced by any rule.
    long long item3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item3_id,
                            object3_id, "220.181.38.158-220.181.38.159", 0);
    EXPECT_EQ(ret, 1);

    //item4 -> object4, object4 is not referenced by any rule.
    long long item4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item4_id, object4_id,
                              "a finite and infinite",
                              NULL, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url = "en.wikipedia.org/wiki/Path_(chemistry_theory)";
	const char* http_resp_hdr_cookie = "laptop=thinkpad X1 extrem;time=2020-02-12T15:34:00;"
                                       "main[XWJOKE]=hoho; Hm_lvt_bbac0322e6ee13093f98d5c4b5a10912=1578874808;";

    int http_req_table_id = maat_get_table_id(maat_inst, "HTTP_REQUEST_HEADER");
    ASSERT_GT(http_req_table_id, 0);

    ret = maat_state_set_scan_district(state, http_req_table_id, "URL", strlen("URL"));
    EXPECT_EQ(ret, 0);

    int Nth_scan = 0;

    Nth_scan++;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, http_req_table_id, http_url, strlen(http_url),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, http_req_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    size_t scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 1);

    struct maat_hit_path hit_path[128];
    memset(hit_path, 0, sizeof(hit_path));
    int n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 2);

    int path_idx = 0;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, -1);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object11_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, http_req_table_id);
    EXPECT_EQ(hit_path[path_idx].negate_option, 1);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    path_idx++;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, -1);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, http_req_table_id);
    EXPECT_EQ(hit_path[path_idx].negate_option, 1);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    int http_res_table_id = maat_get_table_id(maat_inst, "HTTP_RESPONSE_HEADER");
	ASSERT_GT(http_res_table_id, 0);

    ret = maat_state_set_scan_district(state, http_res_table_id, "Cookie",
                                       strlen("Cookie"));
    EXPECT_EQ(ret, 0);

    Nth_scan++;
    ret = maat_scan_string(maat_inst, http_res_table_id, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, http_res_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 2);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 4);
    
    path_idx = 0;
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan-1);
	EXPECT_EQ(hit_path[path_idx].item_id, -1);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object11_id);
    EXPECT_EQ(hit_path[path_idx].negate_option, 1);
    EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    path_idx++;
    ASSERT_EQ(path_idx, 1);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan-1);
	EXPECT_EQ(hit_path[path_idx].item_id, -1);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object1_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object1_id);
    EXPECT_EQ(hit_path[path_idx].negate_option, 1);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule1_id);

    path_idx++;
    ASSERT_EQ(path_idx, 2);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, object21_id);
	EXPECT_EQ(hit_path[path_idx].attribute_id, http_res_table_id);
    EXPECT_EQ(hit_path[path_idx].negate_option, 0);
	EXPECT_EQ(hit_path[path_idx].rule_id, rule1_id);

    path_idx++;
    ASSERT_EQ(path_idx, 3);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object2_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, http_res_table_id);
    EXPECT_EQ(hit_path[path_idx].negate_option, 0);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);
   
    const char *keywords1 = "In math theory, a finite and infinite come up all the time.";
    const char *keywords2= "a finite and infinite come up again.";

    int keywords_table_id = maat_get_table_id(maat_inst, keywords_table_name);
    ASSERT_GT(keywords_table_id, 0);

    struct maat_stream *stream = maat_stream_new(maat_inst, keywords_table_id, state);
    Nth_scan++;
    ret = maat_stream_scan(stream, keywords1, strlen(keywords1), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, keywords_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 3);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 5);

    path_idx++;
	ASSERT_EQ(path_idx, 4);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item4_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object4_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
    EXPECT_EQ(hit_path[path_idx].negate_option, 0);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0);

    Nth_scan++;
    uint32_t ip_addr;
    inet_pton(AF_INET, "220.181.38.158", &ip_addr);
    ret = maat_scan_ipv4(maat_inst, ip_table_id, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 4);
 
    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 6);

    path_idx++;
	ASSERT_EQ(path_idx, 5);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item3_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object3_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, ip_table_id);
    EXPECT_EQ(hit_path[path_idx].negate_option, 0);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    Nth_scan++;   
    ret = maat_stream_scan(stream, keywords2, strlen(keywords2), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, keywords_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 5);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 7);

    path_idx++;
	ASSERT_EQ(path_idx, 6);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item4_id);
	EXPECT_EQ(hit_path[path_idx].sub_object_id, object4_id);
	EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
	EXPECT_EQ(hit_path[path_idx].attribute_id, keywords_table_id);
    EXPECT_EQ(hit_path[path_idx].negate_option, 0);
	EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    maat_stream_free(stream);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, SameSuperObjectRefByMultiRule) {
    int thread_id = 0;
    const char *g2g_table_name = "OBJECT2OBJECT";
	const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *http_sig_table_name = "HTTP_SIGNATURE";
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;

    /* item5 -> object5 -> object52 -> rule2
                              \
                               \ -> rule3
    */
    long long item5_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object5_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    int ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                                  item5_id, object5_id,
                                  "same superobject referenced by multi rule",
                                  "KEY", 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    long long object52_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2object_table_set_line(maat_inst, g2g_table_name, MAAT_OP_ADD,
                                     object52_id, object5_id, 0);
    EXPECT_EQ(ret, 1);

    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule2_id, "HTTP_RESPONSE_HEADER", 1, 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object52_id, rule2_id, 0,
                                       "HTTP_RESPONSE_HEADER", 0, 0);
    EXPECT_EQ(ret, 1);

    long long rule3_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule3_id, "HTTP_RESPONSE_HEADER", 1, 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object52_id, rule3_id, 0,
                                       "HTTP_RESPONSE_HEADER", 0, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    int http_res_table_id = maat_get_table_id(maat_inst, "HTTP_RESPONSE_HEADER");
	ASSERT_GT(http_res_table_id, 0);

    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_state_set_scan_district(state, http_res_table_id, "KEY", strlen("KEY"));
    EXPECT_EQ(ret, 0);
    
    const char *http_res_key_str = "same superobject referenced by multi rule";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_hit_path hit_path[128];

    ret = maat_scan_string(maat_inst, http_res_table_id, http_res_key_str,
                           strlen(http_res_key_str), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], rule3_id);
    EXPECT_EQ(results[1], rule2_id);
    
    ret = maat_scan_not_logic(maat_inst, http_res_table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    memset(hit_path, 0, sizeof(hit_path));
    int n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 3);

    int path_idx = 0;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
    EXPECT_EQ(hit_path[path_idx].item_id, item5_id);
    EXPECT_EQ(hit_path[path_idx].sub_object_id, object5_id);
    EXPECT_EQ(hit_path[path_idx].top_object_id, object52_id);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule3_id);

    path_idx++;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
    EXPECT_EQ(hit_path[path_idx].item_id, item5_id);
    EXPECT_EQ(hit_path[path_idx].sub_object_id, object5_id);
    EXPECT_EQ(hit_path[path_idx].top_object_id, -1);
    EXPECT_EQ(hit_path[path_idx].rule_id, -1);

    path_idx++;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
    EXPECT_EQ(hit_path[path_idx].item_id, item5_id);
    EXPECT_EQ(hit_path[path_idx].sub_object_id, object5_id);
    EXPECT_EQ(hit_path[path_idx].top_object_id, object52_id);
    EXPECT_EQ(hit_path[path_idx].rule_id, rule2_id);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, SameScanStatusWhenConditionUpdate_TSG6419) {
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char* rule_table_name = "RULE_DEFAULT";
	const char* ip_table_name = "IP_PLUS_CONFIG";
    const char *app_id_table_name = "APP_ID";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    /* item11 -> object11 -> condition1 -> rule1
                                          /
           item21 -> object21 -> condition2 _/
    */
    long long object11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object11_id, rule1_id, 0, ip_table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    long long item11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item11_id,
                            object11_id, "192.168.2.1-192.168.2.4", 0);
    EXPECT_EQ(ret, 1);

    long long object21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object21_id, rule1_id, 0, app_id_table_name, 2, 0);
    EXPECT_EQ(ret, 1);

    long long item21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = interval_table_set_line(maat_inst, app_id_table_name, MAAT_OP_ADD,
                                  item21_id, object21_id, "31", NULL, 0);
    EXPECT_EQ(ret, 1);
    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.2.2", &ip_addr);

    int table_id = maat_get_table_id(maat_inst, ip_table_name);
    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int scan_app_id = 32;
    table_id = maat_get_table_id(maat_inst, app_id_table_name);
    ret = maat_scan_integer(maat_inst, table_id, scan_app_id, results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    /* item11 -> object11 -> condition1 -> rule1
                                          /
           item21 -> object21 -> condition2 _/
          item22 -> object22 -> condition3 _/
    */
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule1_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule1_id, "null", 3, 0);
    EXPECT_EQ(ret, 1);

    long long object22_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object22_id, rule1_id, 0, app_id_table_name, 3, 0);
    EXPECT_EQ(ret, 1);

    long long item22_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = interval_table_set_line(maat_inst, app_id_table_name, MAAT_OP_ADD,
                                  item22_id, object22_id, "32", NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    table_id = maat_get_table_id(maat_inst, app_id_table_name);
    ret = maat_scan_integer(maat_inst, table_id, 31, results, ARRAY_SIZE,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_integer(maat_inst, table_id, scan_app_id, results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, ObjectEdit) {
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *ip_table_name = "IP_PLUS_CONFIG"; 
    const char *app_id_table_name = "APP_ID";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    /* item11 -> object11 -> condition1 -> rule1
           item21 -> object21 -> condition2 _/
    */
    long long object11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object11_id, rule1_id, 0, ip_table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    long long item11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item11_id,
                            object11_id, "192.168.3.1-192.168.3.4", 0);
    EXPECT_EQ(ret, 1);

    long long object21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object21_id, rule1_id, 0, app_id_table_name, 2, 0);
    EXPECT_EQ(ret, 1);

    long long item21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = interval_table_set_line(maat_inst, app_id_table_name, MAAT_OP_ADD,
                                  item21_id, object21_id, "41", NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.3.2", &ip_addr);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    table_id = maat_get_table_id(maat_inst, app_id_table_name);
    ASSERT_GT(table_id, 0);

    int scan_app_id = 42;
    ret = maat_scan_integer(maat_inst, table_id, scan_app_id, results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /* item11 -> object11 -> condition1 -> rule1
            item21 -> object21 -> condition2 _/
              item22 -> /
    */
    char scan_app_id_str[8] = {0};
    snprintf(scan_app_id_str, sizeof(scan_app_id_str), "%d", scan_app_id);
    long long item22_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = interval_table_set_line(maat_inst, app_id_table_name, MAAT_OP_ADD,
                                  item22_id, object21_id, scan_app_id_str, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    //TODO: EXPECT_EQ(ret,?)

    table_id = maat_get_table_id(maat_inst, app_id_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_integer(maat_inst, table_id, scan_app_id, results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[128];
    memset(hit_path, 0, sizeof(hit_path));

    int n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 2);
    maat_state_reset(state);

    /* item11 -> object11 -> condition1 -> rule1
           item21 -> object21 -> condition2 _/
    */
    ret = interval_table_set_line(maat_inst, app_id_table_name, MAAT_OP_DEL,
                                item22_id, object21_id, scan_app_id_str, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(results, 0, sizeof(results));
    table_id = maat_get_table_id(maat_inst, ip_table_name);
    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    table_id = maat_get_table_id(maat_inst, app_id_table_name);
    ret = maat_scan_integer(maat_inst, table_id, scan_app_id, results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, RuleDelete_TSG6548) {
    const char* g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char* rule_table_name = "RULE_DEFAULT";
	const char* ip_table_name = "IP_PLUS_CONFIG";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //item11 -> object11 -> condition1 -> rule1
    long long object11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object11_id, rule1_id, 0, ip_table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    long long item11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item11_id,
                            object11_id, "192.168.73.163-192.168.73.180", 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.73.169", &ip_addr);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL,
                                       object11_id, rule1_id, 0, ip_table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    int hit_cnt = 0;
    int miss_cnt = 0;
    time_t update_time = time(NULL);
	time_t now = update_time;
	while (now - update_time < 3) {
		ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results,
                             ARRAY_SIZE, &n_hit_result, state);
		if (ret == MAAT_SCAN_HIT) {
			hit_cnt++;
			EXPECT_EQ(results[0], rule1_id);
		} 
        if (ret == MAAT_SCAN_HALF_HIT) {
			miss_cnt++;
		}
		now = time(NULL);
	}

	//scan hit for at most 1 second (rule updating latency), miss for at least 2 seconds.
	EXPECT_LE(hit_cnt, miss_cnt);
	maat_state_free(state);                                    
}

TEST_F(MaatCmd, UpdateDeadLockDetection) {
    const char* g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char* rule_table_name = "RULE_DEFAULT";
	const char* table_http_url = "HTTP_URL";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0, table_http_url, 0, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, table_http_url, MAAT_OP_ADD, item1_id,
                              object1_id, "part-1", NULL, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* scan_data1 = "scan string part-1.";
	const char* scan_data2 = "scan string part-2.";

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_inst, table_http_url);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1),
                          results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule2_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //object2 -> rule2
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object2_id, rule2_id, 0, table_http_url, 0, 0);
    EXPECT_EQ(ret, 1);

    //item2 -> object2 -> rule2
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, table_http_url, MAAT_OP_ADD, item2_id,
                              object2_id, "part-2", NULL, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    //DON'T DO THIS!!!
	//Roll back version, trigger full udpate.
	//This operation generates some FATAL logs in test_maat_redis.log.yyyy-mm-dd.
	maat_cmd_incrby(maat_inst, "MAAT_VERSION", -100);

    //Wating for scanner garbage collect expiration.
	sleep(10);

    memset(results, 0, sizeof(results));
    ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    //After full update, condition ids are re-orgnized, therefore mid are not compatible to the new scanner (hierarchy).
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT); 

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, StreamScanWhenExprTableIncUpdate) {
    const char* g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char* rule_table_name = "RULE_DEFAULT";
	const char* scan_table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0, scan_table_name, 0, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    const char *scan_data = "Here is a stream-keywords-001-inc-update, this should hit.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_inst, scan_table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *stream = maat_stream_new(maat_inst, table_id, state);
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, scan_table_name, MAAT_OP_ADD,
                              item1_id, object1_id, "stream-keywords-001-inc-update",
                              NULL, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    /* maat_stream store expr_runtime version when maat_stream_new().
       Add new expr_item has changed expr_runtime version which has been sensed by maat_stream_scan.
    */
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    
    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_stream_free(stream);

    stream = maat_stream_new(maat_inst, table_id, state);
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_stream_free(stream);
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, StreamScanSegfaultWhenVersionRollBack_TSG6324) {
    const char* g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char* rule_table_name = "RULE_DEFAULT";
	const char* scan_table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0, scan_table_name, 0, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, scan_table_name, MAAT_OP_ADD, item1_id,
                              object1_id, "stream-keywords-002", NULL, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char *scan_data = "Here is a stream-keywords-002, this should hit.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_inst, scan_table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *stream = maat_stream_new(maat_inst, table_id, state);
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //DON'T DO THIS!!!
	//Roll back version, trigger full update.	
	//This operation generates FATAL logs in test_maat_redis.log.yyyy-mm-dd.
	//For example: Add object 22 vt_id 0 to condition 2 of rule 979 failed, object is already existed
	maat_cmd_incrby(maat_inst, "MAAT_VERSION", -100);

	//Wating for scanner garbage collect expiration.
	sleep(10);

	ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK); //Scan was interupted after full update.

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_stream_free(stream);
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, IPAndStreamScanWhenIncUpdate) {
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *expr_table_name = "KEYWORDS_TABLE";
    const char *ip_table_name = "IP_PLUS_CONFIG";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0, expr_table_name, 0, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, expr_table_name, MAAT_OP_ADD, item1_id,
                              object1_id, "stream-keywords-003", NULL, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1 
                            /
         item2 -> object2 --/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item2_id,
                            object2_id, "100.100.100.1", 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object2_id, rule1_id, 0, ip_table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    char ip_str[32] = "100.100.100.1";
    uint32_t ip_addr;
    ret = inet_pton(AF_INET, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);

    int table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //add rule2 for rule runtime inc update
    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule2_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char *scan_data = "Here is a stream-keywords-003, this should hit.";
    table_id = maat_get_table_id(maat_inst, expr_table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *stream = maat_stream_new(maat_inst, table_id, state);
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    /* 
        becase rule1_id has been returned, maat_scan_xx will not return duplicate rule_id again
    */
    table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);
    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_stream_free(stream);
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, IPAndStreamScanWhenFullUpdate) {
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *ip_table_name = "IP_PLUS_CONFIG";
    const char *expr_table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0, expr_table_name, 0, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, expr_table_name, MAAT_OP_ADD,
                              item1_id, object1_id, "stream-keywords-004",
                              NULL, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1 
                            /
         item2 -> object2 --/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD,
                            item2_id, object2_id, "100.100.100.2", 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object2_id, rule1_id, 0, ip_table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    char ip_str[32] = "100.100.100.2";
    uint32_t ip_addr;
    ret = inet_pton(AF_INET, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);

    int table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //DON'T DO THIS!!!
	//Roll back version, trigger full update.	
	maat_cmd_incrby(maat_inst, "MAAT_VERSION", -100);

	//Wating for scanner garbage collect expiration.
	sleep(10);

    const char *scan_data = "Here is a stream-keywords-004, this should hit.";
    table_id = maat_get_table_id(maat_inst, expr_table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *stream = maat_stream_new(maat_inst, table_id, state);
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    /* maat_state keep the rule_rt version when maat_state_new().
       After full updating, new rule_rt version is different from that of maat_state,
       so MAAT_SCAN_HIT will never happen.
    */
    table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);
    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_stream_free(stream);
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, IPAndStringScanWhenIncUpdate) {
     const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *expr_table_name = "HTTP_URL";
    const char *ip_table_name = "IP_PLUS_CONFIG";
    const char *keywords = "IP&stringinc";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0, expr_table_name, 0, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, expr_table_name, MAAT_OP_ADD, item1_id,
                              object1_id, keywords, NULL, 1, 0); /*EXPR_TYPE_AND MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1 
                            /
         item2 -> object2 --/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item2_id,
                            object2_id, "100.100.100.1", 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object2_id, rule1_id, 0, ip_table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    char ip_str[32] = "100.100.100.1";
    uint32_t ip_addr;
    ret = inet_pton(AF_INET, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);

    int table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //add rule2 for rule runtime inc update
    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule2_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char *scan_data = "Here is a IP and stringinc, this should hit.";
    table_id = maat_get_table_id(maat_inst, expr_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule1_id);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    /* 
        becase rule1_id has been returned, maat_scan_xx will not return duplicate rule_id again
    */
    table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);
    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, IPAndStringScanWhenFullupdate) {
    const char *g2c_table_name = "OBJECT2RULE_DEFAULT";
    const char *rule_table_name = "RULE_DEFAULT";
    const char *ip_table_name = "IP_PLUS_CONFIG";
    const char *expr_table_name = "HTTP_URL";
    const char *keywords = "IP&string";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object1_id, rule1_id, 0, expr_table_name, 0, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, expr_table_name, MAAT_OP_ADD, item1_id,
                              object1_id, keywords, "null", 1, 0); /*EXPR_TYPE_AND MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1 
                            /
         item2 -> object2 --/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item2_id,
                            object2_id, "100.100.100.3", 0);
    EXPECT_EQ(ret, 1);

    ret = object2rule_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD,
                                       object2_id, rule1_id, 0, ip_table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    char ip_str[32] = "100.100.100.3";
    uint32_t ip_addr;
    ret = inet_pton(AF_INET, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);

    int table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //DON'T DO THIS!!!
	//Roll back version, trigger full update.	
	maat_cmd_incrby(maat_inst, "MAAT_VERSION", -100);

	//Wating for scanner garbage collect expiration.
	sleep(10);

    const char *scan_data = "scan IP and string, this should hit.";
    table_id = maat_get_table_id(maat_inst, expr_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    /* maat_state keep the rule_rt version when maat_state_new().
       After full updating, new rule_rt version is different from that of maat_state,
       so MAAT_SCAN_HIT will never happen.
    */
    table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

class MaatRollback : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
                                  "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);        
        int ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatRollback failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};
struct maat *MaatRollback::_shared_maat_inst;
struct log_handle *MaatRollback::logger;

static int clear_config_in_redis(redisContext *c, struct log_handle *logger)
{
    long long redis_version = 0;
    redisReply *reply = maat_wrap_redis_command(c, logger, "GET MAAT_VERSION");
    if (reply != NULL) {
		if (reply->type == REDIS_REPLY_NIL ||
            reply->type == REDIS_REPLY_ERROR) {
			log_fatal(logger, MODULE_FRAMEWORK_GTEST, 
                      "[%s:%d] GET MAAT_VERSION failed, maybe Redis is busy",
                      __FUNCTION__, __LINE__);
			freeReplyObject(reply);
			reply = NULL;
			return -1;
		}
	} else {
		log_fatal(logger, MODULE_FRAMEWORK_GTEST, 
                  "[%s:%d] GET MAAT_VERSION failed with NULL reply, error: %s",
                  __FUNCTION__, __LINE__, c->errstr);
		return -1;
	}

    redis_version = maat_read_redis_integer(reply);
	if (redis_version < 0) {
		if (reply->type == REDIS_REPLY_ERROR) {
			log_fatal(logger, MODULE_FRAMEWORK_GTEST, 
                      "[%s:%d] Redis Communication error: %s", 
                      __FUNCTION__, __LINE__, reply->str);
		}
        freeReplyObject(reply);
	    reply = NULL;
		return -1;
	}

	freeReplyObject(reply);
	reply = NULL;

    reply = maat_wrap_redis_command(c, logger, "MULTI");
	freeReplyObject(reply);
	reply = NULL;
	
    int append_cmd_cnt = 0;
	redisAppendCommand(c, "FLUSHDB");
	append_cmd_cnt++;
	redisAppendCommand(c, "SET MAAT_VERSION %lld", redis_version);
	append_cmd_cnt++;
	redisAppendCommand(c, "SET MAAT_PRE_VER %lld", redis_version);
	append_cmd_cnt++;
	redisAppendCommand(c, "SET %s 1", mr_region_id_var);
	append_cmd_cnt++;
	redisAppendCommand(c, "SET %s 1", mr_object_id_var);
	append_cmd_cnt++;
	redisAppendCommand(c, "EXEC");
	append_cmd_cnt++;

    int redis_transaction_success = 1;
    for (int i = 0; i < append_cmd_cnt; i++) {
		int ret = maat_wrap_redis_get_reply(c, &reply);
		if (ret == REDIS_OK) {
			if (reply->type == REDIS_REPLY_NIL) {
				redis_transaction_success = 0;
			}
			freeReplyObject(reply);
			reply = NULL;
		}
	}

    if (0 == redis_transaction_success) {
		return -1;
	}

    return 0;
}

static int
rollback_redis_version(redisContext *c, struct log_handle *logger)
{
    redisReply *reply =
        maat_wrap_redis_command(c, logger, "SET MAAT_VERSION 0");
    if (NULL == reply) {
        log_fatal(logger, MODULE_FRAMEWORK_GTEST, 
                  "[%s:%d] set MAAT_VERSION failed, "
                  "Redis Communication error: %s", 
                  __FUNCTION__, __LINE__, c->errstr);
        return -1;
    }
    freeReplyObject(reply);
    reply = NULL;

    return 0;
}

TEST_F(MaatRollback, FullConfigRollback) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = MaatRollback::_shared_maat_inst;
    struct log_handle *logger = MaatRollback::logger;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "http://www.cyberessays.com/search_results.php?"
                            "action=search&query=username,abckkk,1234567";

    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 125);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    sleep(5);
    char redis_ip[64] = "127.0.0.1";
    int redis_port = 6379;
    int redis_db = 0;
    redisContext *c = maat_connect_redis(redis_ip, redis_port, redis_db, logger);
    EXPECT_TRUE(c != NULL);

    ret = clear_config_in_redis(c, logger);
    EXPECT_EQ(ret, 0);

    ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
    EXPECT_EQ(ret, 0);

    ret = rollback_redis_version(c, logger);
    EXPECT_EQ(ret, 0);
    redisFree(c);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 125);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatRollback, FullConfigRollbackWhenScanUnfinished) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = MaatRollback::_shared_maat_inst;
    struct log_handle *logger = MaatRollback::logger;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "http://www.cyberessays.com/search_results.php?"
                            "action=search&query=username,abckkk,1234567";

    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 125);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    sleep(5);
    char redis_ip[64] = "127.0.0.1";
    int redis_port = 6379;
    int redis_db = 0;
    redisContext *c = maat_connect_redis(redis_ip, redis_port, redis_db, logger);
    EXPECT_TRUE(c != NULL);

    ret = clear_config_in_redis(c, logger);
    EXPECT_EQ(ret, 0);

    ret = write_json_to_redis(g_json_filename, redis_ip, redis_port, redis_db, logger);
    EXPECT_EQ(ret, 0);

    ret = rollback_redis_version(c, logger);
    EXPECT_EQ(ret, 0);
    redisFree(c);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 125);

    ret = maat_scan_not_logic(maat_inst, table_id, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

    ret=RUN_ALL_TESTS();

	return ret;
}
