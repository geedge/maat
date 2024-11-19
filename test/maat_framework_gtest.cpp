#include <gtest/gtest.h>
#include <dirent.h>
#include <openssl/md5.h>
#include <uuid/uuid.h>

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


static int test_add_expr_command(struct maat *maat_inst, const char *expr_table, 
                          const char *attr_name, const char *rule_uuid_str, int timeout,
                          const char *keywords, struct maat_cmd_and_condition *and_condition)
{
    char huge_serv_def[1024 * 2] = {0};

    memset(huge_serv_def, 's', sizeof(huge_serv_def) - 1);
    huge_serv_def[sizeof(huge_serv_def) - 1] = '\0';

    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char object_uuid_str[UUID_STR_LEN] = {0};
    char item_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object_id);
    snprintf(item_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item_id);
    
    int ret = expr_table_set_line(maat_inst, expr_table, MAAT_OP_ADD, item_uuid_str,
                              object_uuid_str, keywords, EXPR_TYPE_AND, 0);
    EXPECT_EQ(ret, 1);

    and_condition->or_condition_num = 1;
    and_condition->negate_option = 0;
    and_condition->or_conditions[0].attribute_name = attr_name;
    and_condition->or_conditions[0].object_uuids_str[0] = object_uuid_str;
    and_condition->or_conditions[0].object_num = 1;
    ret = rule_table_set_line(maat_inst, "RULE_DEFAULT", MAAT_OP_ADD,
                                 rule_uuid_str, and_condition, 1, NULL, timeout);
    EXPECT_EQ(ret, 1);

    return ret;
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
    const char *attribute_name = "HTTP_URL";
    const char *table_name = "HTTP_URL";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, hit_old_data,
                               strlen(hit_old_data), results, ARRAY_SIZE,
                               &n_hit_result, state);
    if (is_old) {
        EXPECT_EQ(ret, MAAT_SCAN_HIT);
        char uuid_str[UUID_STR_LEN] = {0};
        uuid_unparse(results[0], uuid_str);
        EXPECT_TRUE(strcmp(uuid_str, "9c5ee166-3af6-fb23-f8f8-8c7062ed3717") == 0);
    } else {
        EXPECT_EQ(ret, MAAT_SCAN_OK);
    }

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);
    ret = maat_scan_string(maat_inst, table_name, attribute_name, hit_new_data,
                           strlen(hit_new_data), results, ARRAY_SIZE,
                           &n_hit_result, state);
    if (!is_old) {
        EXPECT_EQ(ret, MAAT_SCAN_HIT);
        char uuid_str[UUID_STR_LEN] = {0};
        uuid_unparse(results[0], uuid_str);
        EXPECT_EQ(strcmp(uuid_str, "9b0d44a1-1e9e-7988-6ab2-c619d5906818"), 0);
    } else {
        EXPECT_EQ(ret, MAAT_SCAN_OK);
    }

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
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
    const char *attribute_name = "FLAG_CONFIG";
    struct maat *maat_inst = FlagScan::_shared_maat_inst;

    //rule_id:192 flag: 0000 0001 mask: 0000 0011
    //scan_data: 0000 1001 or 0000 1101 should hit
    long long scan_data = 9;
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));

    int ret = maat_scan_flag(maat_inst, flag_table_name, attribute_name, scan_data, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000207");

    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000192");
    
    ret = maat_scan_not_logic(maat_inst, flag_table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE];
    int n_read = 0;
    memset(hit_path, 0, sizeof(hit_path));
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);
    maat_state_reset(state);

    scan_data = 13;
    memset(results, 0, sizeof(results));
    n_hit_result = 0;
    ret = maat_scan_flag(maat_inst, flag_table_name, attribute_name, scan_data, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000207");

    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000192");

    ret = maat_scan_not_logic(maat_inst, flag_table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_reset(state);

    scan_data = 6;
    memset(results, 0, sizeof(results));
    n_hit_result = 0;
    ret = maat_scan_flag(maat_inst, flag_table_name, attribute_name, scan_data, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, flag_table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}   

TEST_F(FlagScan, withExprRegion) {
    const char *flag_table_name = "FLAG_CONFIG";
    const char *flag_attribute_name = "FLAG_CONFIG";
    const char *expr_table_name = "HTTP_URL";
    const char *expr_attribute_name = "HTTP_URL";
    struct maat *maat_inst = FlagScan::_shared_maat_inst;

    //rule_id:193 flag: 0000 0010 mask: 0000 0011
    //scan_data: 0000 0010 or 0000 0100 should hit
    long long flag_scan_data = 2;
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));

    int ret = maat_scan_flag(maat_inst, flag_table_name, flag_attribute_name, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, flag_table_name, flag_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE];
    int n_read = 0;

    memset(hit_path, 0, sizeof(hit_path));
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    const char *expr_scan_data = "hello world";
    ret = maat_scan_string(maat_inst, expr_table_name, expr_attribute_name, expr_scan_data, 
                           strlen(expr_scan_data), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000193");

    ret = maat_scan_not_logic(maat_inst, expr_table_name, expr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}   

TEST_F(FlagScan, hitMultiRule) {
    const char *flag_table_name = "FLAG_CONFIG";
    const char *flag_attribute_name = "FLAG_CONFIG";
    struct maat *maat_inst = FlagScan::_shared_maat_inst;

    //rule_id:192 flag: 0000 0001 mask: 0000 0011
    //rule_id:194 flag: 0001 0101 mask: 0001 1111
    //scan_data: 0001 0101 should hit rule192 and rule194
    long long flag_scan_data = 21;
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));

    int ret = maat_scan_flag(maat_inst, flag_table_name, flag_attribute_name, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 3);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000207");

    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000194");
    
    uuid_unparse(results[2], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000192");

    ret = maat_scan_not_logic(maat_inst, flag_table_name, flag_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(maat_inst, flag_table_name, flag_attribute_name, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, flag_table_name, flag_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE];
    int n_read = 0;

    memset(hit_path, 0, sizeof(hit_path));
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    maat_state_free(state);
    state = NULL;
}  

TEST_F(FlagScan, hitRepeatedRule) {
    const char *flag_table_name = "FLAG_CONFIG";
    const char *flag_attribute_name = "FLAG_CONFIG";
    struct maat *maat_inst = FlagScan::_shared_maat_inst;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));

    //rule_id:192 flag: 0000 0001 mask: 0000 0011
    //scan_data: 0000 1001 or 0000 1101 should hit
    long long flag_scan_data1 = 9; 
    int ret = maat_scan_flag(maat_inst, flag_table_name, flag_attribute_name, flag_scan_data1, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_TRUE(strcmp(uuid_str, "00000000-0000-0000-0000-000000000207") == 0);
    uuid_unparse(results[1], uuid_str);
    EXPECT_EQ(strcmp(uuid_str, "00000000-0000-0000-0000-000000000192"), 0);

    ret = maat_scan_not_logic(maat_inst, flag_table_name, flag_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //rule_id:192 flag: 0000 0001 mask: 0000 0011
    //rule_id:194 flag: 0001 0101 mask: 0001 1111
    //scan_data: 0001 0101 should hit rule192 and rule194
	long long flag_scan_data2 = 21;
    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(maat_inst, flag_table_name, flag_attribute_name, flag_scan_data2, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000194");

    ret = maat_scan_not_logic(maat_inst, flag_table_name, flag_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(maat_inst, flag_table_name, flag_attribute_name, flag_scan_data2, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, flag_table_name, flag_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE];
    int n_read = 0;

    memset(hit_path, 0, sizeof(hit_path));
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    maat_state_free(state);
    state = NULL;
} 

class StringScan : public testing::TestWithParam<const char*> {
protected:
    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
    static const char *current_expr_engine;

    static void SetUpTestSuite(const char* expr_engine) {
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
        maat_options_set_hit_object_enabled(opts);

        if (strcmp(expr_engine, "HS") == 0) {
            maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);
        } else if (strcmp(expr_engine, "RS") == 0) {
            maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);
        }

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in StringScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestSuite() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    void SetUp() override 
    {
        const char *expr_engine = GetParam();
        if (current_expr_engine == nullptr || strcmp(expr_engine, current_expr_engine) != 0)
        {
            if (_shared_maat_inst != nullptr)
            {
                TearDownTestSuite();
            }
            SetUpTestSuite(expr_engine);
            current_expr_engine = expr_engine;
        }
    }
    void TearDown() override 
    {
        // no-op
    }
};

struct maat *StringScan::_shared_maat_inst;
struct log_handle *StringScan::logger;
const char *StringScan::current_expr_engine = nullptr;

TEST_P(StringScan, ScanDataOnlyOneByte) {
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    struct maat *maat_inst = StringScan::_shared_maat_inst;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char scan_data = 0x20;

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, &scan_data, sizeof(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, Full) {
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    struct maat *maat_inst = StringScan::_shared_maat_inst;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "http://www.cyberessays.com/search_results.php"
                            "?action=search&query=username,abckkk,1234567";

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000125");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, Regex) {
    int ret = 0;
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "Cookie: Txa123aheadBCAxd";
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000148");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, RegexUnicode) {
    int ret = 0;
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "String contains É";
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000229");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, BackslashR_N_Escape) {
    int ret = 0;
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
    const char *payload = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_string(maat_inst, table_name, attribute_name, payload, strlen(payload),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000225");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}


TEST_P(StringScan, BackslashR_N_Escape_IncUpdate) {
    int ret = 0;
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
    const char *payload = "html>\\r\\n";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_string(maat_inst, table_name, attribute_name, payload, strlen(payload),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000234");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_reset(state);

    const char *rule_table_name = "RULE_DEFAULT";

    /* expr table add line */
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char object_uuid_str[UUID_STR_LEN] = {0};
    char item_uuid_str[UUID_STR_LEN] = {0};
    const char *keywords = "html>\\\\r\\\\n";

    snprintf(object_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object_id);
    snprintf(item_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item_id);
    /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_uuid_str,
                              object_uuid_str, keywords, EXPR_TYPE_AND, 0);
    EXPECT_EQ(ret, 1);

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);

    struct maat_cmd_and_condition and_condition;
    and_condition.or_condition_num = 1;
    and_condition.negate_option = 0;
    and_condition.or_conditions[0].attribute_name = attribute_name;
    and_condition.or_conditions[0].object_uuids_str[0] = object_uuid_str;
    and_condition.or_conditions[0].object_num = 1;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 3);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, payload, strlen(payload), 
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000234");
    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, BackslashCtrlCharactor)
{
    int ret = 0;
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
    const char *payload = "()abc^$def|";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_string(maat_inst, table_name, attribute_name, payload, strlen(payload),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000235");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, Expr8) {
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    char scan_data[128] = "string1, string2, string3, string4, string5, "
                          "string6, string7, string8";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;

    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000182");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE];
    int n_read = 0;

    memset(hit_path, 0, sizeof(hit_path));
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, HexBinCaseSensitive) {
    const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
	const char *scan_data1 = "String TeST should not hit.";
	const char *scan_data2 = "String TEST should hit";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    int thread_id = 0;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data1, strlen(scan_data1), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data2, strlen(scan_data2), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000206");
    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000191");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

TEST_P(StringScan, HexbinCombineString)
{
    const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
	const char *scan_data1 = "abcd ABCD";
	const char *scan_data2 = "abcd abCD";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    int thread_id = 0;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data1, strlen(scan_data1), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data2, strlen(scan_data2), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000236");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

TEST_P(StringScan, BugReport20190325) {
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
    const char *attribute_name = "TROJAN_PAYLOAD";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    int thread_id = 0;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, (char *)scan_data,
                               sizeof(scan_data), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000150");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, PrefixAndSuffix) {
    const char *hit_twice = "ceshi3@mailhost.cn";
	const char *hit_suffix = "11111111111ceshi3@mailhost.cn";
	const char *hit_prefix = "ceshi3@mailhost.cn11111111111";
    const char *cont_sz_table_name = "CONTENT_SIZE";
    const char *cont_sz_attribute_name = "CONTENT_SIZE";
    const char *mail_addr_table_name = "MAIL_ADDR";
    const char *mail_addr_attribute_name = "MAIL_ADDR";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    int thread_id = 0;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_integer(maat_inst, cont_sz_table_name, cont_sz_attribute_name, 2015, results,
                                ARRAY_SIZE, &n_hit_result, state);
    
    ret = maat_scan_not_logic(maat_inst, cont_sz_table_name, cont_sz_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, mail_addr_table_name, mail_addr_attribute_name, hit_twice,
                           strlen(hit_twice), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000151");
    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000152");

    ret = maat_scan_not_logic(maat_inst, mail_addr_table_name, mail_addr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);
    ret = maat_scan_string(maat_inst, mail_addr_table_name, mail_addr_attribute_name, hit_suffix,
                           strlen(hit_suffix), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000151");

    ret = maat_scan_not_logic(maat_inst, mail_addr_table_name, mail_addr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_integer(maat_inst, cont_sz_table_name, cont_sz_attribute_name, 2015, results,
                                ARRAY_SIZE, &n_hit_result, state);

    ret = maat_scan_not_logic(maat_inst, cont_sz_table_name, cont_sz_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, mail_addr_table_name, mail_addr_attribute_name, hit_prefix,
                           strlen(hit_prefix), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000152");

    ret = maat_scan_not_logic(maat_inst, mail_addr_table_name, mail_addr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, MaatUnescape) {
    const char *scan_data = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    int thread_id = 0;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000132");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, OffsetChunk64) {
    const char *table_name = "IMAGE_FP";
    const char *attribute_name = "IMAGE_FP";
	const char *file_name = "./testdata/mesa_logo.jpg";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp==NULL);

    char scan_data[64];

    memset(results, 0, sizeof(results));

    struct maat_stream *sp = maat_stream_new(maat_inst, table_name, attribute_name, state);
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

        ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results,
                                  ARRAY_SIZE, &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break; 
        }
    }
    EXPECT_EQ(pass_flag, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000136");
    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, OffsetChunk1460) {
    const char *table_name = "IMAGE_FP";
    const char *attribute_name = "IMAGE_FP";
	const char *file_name = "./testdata/mesa_logo.jpg";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp==NULL);

    char scan_data[1460];

    memset(results, 0, sizeof(results));

    struct maat_stream *sp = maat_stream_new(maat_inst, table_name, attribute_name, state);
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

        ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break; 
        }
    }
    EXPECT_EQ(pass_flag, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000136");
    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, StreamScanUTF8) {
    const char *table_name = "TROJAN_PAYLOAD";
    const char *attribute_name = "TROJAN_PAYLOAD";
	const char* file_name = "./testdata/jd.com.html";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    char scan_data[2048];
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp == NULL);

    memset(results, 0, sizeof(results));
    struct maat_stream *sp = maat_stream_new(maat_inst, table_name, attribute_name, state);
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

        ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                                  &n_hit_result, state);
        if (ret == MAAT_SCAN_HIT) {
			pass_flag = 1;
			break;
		}
	}

    EXPECT_EQ(pass_flag, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000157");

    maat_stream_free(sp);
    fclose(fp);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, InvisibleCharactor) {
    const char *hex_data = "00A12B3CEEFF";
	const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    int thread_id = 0;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    size_t binary_data_length = strlen(hex_data) / 2;
    unsigned char binary_data[binary_data_length];

    // 将十六进制字符串转换为二进制数据
    for (size_t i = 0; i < binary_data_length; i++) {
        sscanf(&hex_data[2 * i], "%2hhx", &binary_data[i]);
    }

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, (char*)binary_data, binary_data_length, 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000238");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, StreamInput) {
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    const char *scan_data1 = "www.cyberessays.com";
	const char *scan_data2 = "http://www.cyberessays.com/search_results.php?"
                            "action=search&query=yulingjing,abckkk,1234567";

    memset(results, 0, sizeof(results));

	struct maat_stream *sp = maat_stream_new(maat_inst, table_name, attribute_name, state);
	ASSERT_TRUE(sp != NULL);

	int ret = maat_stream_scan(sp, scan_data1, strlen(scan_data1), results,
                               ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
	maat_stream_free(sp);

	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000125");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

//TODO: HS has different behavior with RS
TEST_P(StringScan, StreamHitDirectObject) {
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    int ret;
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *table_name_url = "HTTP_URL";
    const char *attribute_name_url = "HTTP_URL";
    const char *scan_data1 = "www.3300av.com";
	const char *scan_data2 = "sdadhuadhasdgufgh;sdfhjaufhiwebfiusdafhaos;dhfaluhjweh";

    memset(results, 0, sizeof(results));

	struct maat_stream *sp = maat_stream_new(maat_inst, table_name_url, attribute_name_url, state);
	ASSERT_TRUE(sp != NULL);

	ret = maat_stream_scan(sp, scan_data1, strlen(scan_data1), results,
                           ARRAY_SIZE, &n_hit_result, state);

	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000133");

    struct maat_hit_object object_array[ARRAY_SIZE];
    ret = maat_state_get_direct_hit_objects(state, object_array, ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    uuid_unparse(object_array[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000112");

    ret = maat_scan_not_logic(maat_inst, table_name_url, attribute_name_url, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    ret = maat_state_get_direct_hit_objects(state, object_array, ARRAY_SIZE);
    EXPECT_EQ(ret, 0);
    maat_stream_free(sp);


    maat_state_reset(state);
    const char *attribute_name_sig = "HTTP_SIGNATURE";
    const char *table_name_sig = "HTTP_SIGNATURE";
    const char *scan_data3 = "abckkk";
    const char *scan_data4 = "123";
    sp = maat_stream_new(maat_inst, table_name_sig, attribute_name_sig, state);
    ASSERT_TRUE(sp != NULL);

    ret = maat_stream_scan(sp, scan_data3, strlen(scan_data3), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_stream_scan(sp, scan_data4, strlen(scan_data4), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000128");

    ret = maat_state_get_direct_hit_objects(state, object_array, ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    uuid_unparse(object_array[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000107");

    ret = maat_scan_not_logic(maat_inst, table_name_sig, attribute_name_sig, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_stream_scan(sp, scan_data4, strlen(scan_data4), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);//rule has been hit before

    ret = maat_state_get_direct_hit_objects(state, object_array, ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    uuid_unparse(object_array[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000107");

    maat_stream_free(sp);
	maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, StreamLiteralPrefix)
{
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    int ret;
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *table_name_url = "KEYWORDS_TABLE";
    const char *attribute_name_url = "KEYWORDS_TABLE";
    const char *scan_data = "test-literal-prefix abcd";

    memset(results, 0, sizeof(results));

	struct maat_stream *sp = maat_stream_new(maat_inst, table_name_url, attribute_name_url, state);
	ASSERT_TRUE(sp != NULL);

	ret = maat_stream_scan(sp, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);

	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000239");

    ret = maat_scan_not_logic(maat_inst, table_name_url, attribute_name_url, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);


    maat_stream_free(sp);
	maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, StreamLiteralSuffix)
{
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    int ret;
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *table_name_url = "KEYWORDS_TABLE";
    const char *attribute_name_url = "KEYWORDS_TABLE";
    const char *scan_data = "abcd test-literal-suffix";

    memset(results, 0, sizeof(results));

	struct maat_stream *sp = maat_stream_new(maat_inst, table_name_url, attribute_name_url, state);
	ASSERT_TRUE(sp != NULL);

	ret = maat_stream_scan(sp, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);

	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000241");

    ret = maat_scan_not_logic(maat_inst, table_name_url, attribute_name_url, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);


    maat_stream_free(sp);
	maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, StreamRegexPrefix)
{
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    int ret;
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *table_name_url = "KEYWORDS_TABLE";
    const char *attribute_name_url = "KEYWORDS_TABLE";
    const char *scan_data = "test-regex-prefix abcd";

    memset(results, 0, sizeof(results));

	struct maat_stream *sp = maat_stream_new(maat_inst, table_name_url, attribute_name_url, state);
	ASSERT_TRUE(sp != NULL);

	ret = maat_stream_scan(sp, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);

	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000240");

    ret = maat_scan_not_logic(maat_inst, table_name_url, attribute_name_url, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);


    maat_stream_free(sp);
	maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, StreamRegexSuffix)
{
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    int ret;
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *table_name_url = "KEYWORDS_TABLE";
    const char *attribute_name_url = "KEYWORDS_TABLE";
    const char *scan_data = "abcd test-regex-suffix";

    memset(results, 0, sizeof(results));

	struct maat_stream *sp = maat_stream_new(maat_inst, table_name_url, attribute_name_url, state);
	ASSERT_TRUE(sp != NULL);

	ret = maat_stream_scan(sp, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);

	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000242");

    ret = maat_scan_not_logic(maat_inst, table_name_url, attribute_name_url, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);


    maat_stream_free(sp);
	maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, LiteralPrefix)
{
    const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = StringScan::_shared_maat_inst;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "test-literal-prefix abcde";

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000239");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, LiteralSuffix)
{
    const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = StringScan::_shared_maat_inst;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "abcd test-literal-suffix";

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000241");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, RegexPrefix)
{
    const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = StringScan::_shared_maat_inst;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "test-regex-prefix abcde";

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000240");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, RegexSuffix)
{
    const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = StringScan::_shared_maat_inst;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "abcd test-regex-suffix";

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000242");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_P(StringScan, dynamic_config) {
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    char data[128] = "hello world, welcome to maat version4, it's funny.";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = StringScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));

    int ret = maat_scan_string(maat_inst, table_name, attribute_name, data, strlen(data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    const char *rule_table_name = "RULE_DEFAULT";

    /* expr table add line */
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char item_uuid_str[UUID_STR_LEN] = {0};
    char object_uuid_str[UUID_STR_LEN] = {0};
    const char *keywords = "welcome to maat";
    snprintf(item_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item_id);
    snprintf(object_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object_id);

    /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_uuid_str,
                              object_uuid_str, keywords, EXPR_TYPE_AND, 0);
    EXPECT_EQ(ret, 1);

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);
    struct maat_cmd_and_condition and_condition;
    and_condition.negate_option = 0;
    and_condition.or_condition_num = 1;
    and_condition.or_conditions[0].attribute_name = attribute_name;
    and_condition.or_conditions[0].object_num = 1;
    and_condition.or_conditions[0].object_uuids_str[0] = object_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 3);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_DEL, item_uuid_str,
                              object_uuid_str, keywords, EXPR_TYPE_AND, 0);
    EXPECT_EQ(ret, 1);

    /* rule table del line */
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

//hyperscan engine
INSTANTIATE_TEST_CASE_P(HS, StringScan, testing::Values("HS"));
//rulescan engine
INSTANTIATE_TEST_CASE_P(RS, StringScan, testing::Values("RS"));

class StreamScan : public testing::TestWithParam<const char*> {
protected:
    static struct maat *_shared_maat_inst;

    static void SetUpTestCaseWrapper(const char* expr_engine) {
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

        if (strcmp(expr_engine, "HS") == 0) {
            maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);
        } else if (strcmp(expr_engine, "RS") == 0) {
            maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);
        }

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCaseWrapper() {
        maat_free(_shared_maat_inst);
    }

    void SetUp() override {
        SetUpTestCaseWrapper(GetParam());
    }

    void TearDown() override {
        TearDownTestCaseWrapper();
    }
};

struct maat *StreamScan::_shared_maat_inst;

TEST_P(StreamScan, dynamic_config) {
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    const char *keywords1 = "hello";
    char keyword_buf[128];
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data1 = "www.cyberessays.com";
    const char *scan_data2 = "hello world cyberessays.com/search_results.php?"
                             "action=search&query=yulingjing,abckkk,1234567";
    struct maat *maat_inst = StreamScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    // STEP 1: add keywords1 and wait scan stream to hit
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_condition;
    int ret = test_add_expr_command(maat_inst, table_name, attribute_name, rule1_uuid_str, 0, keywords1, &and_condition);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(results, 0, sizeof(results));

	struct maat_stream *sp = maat_stream_new(maat_inst, table_name, attribute_name, state);
	ASSERT_TRUE(sp != NULL);

	ret = maat_stream_scan(sp, scan_data1, strlen(scan_data1), results,
                           ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    // STEP 2: Inc config update, use same stream to scan and wait old expr_runtime invalid 
    random_keyword_generate(keyword_buf, sizeof(keyword_buf));
    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule2_id);
    ret = test_add_expr_command(maat_inst, table_name, attribute_name, rule2_uuid_str, 0, keyword_buf, &and_condition);
    EXPECT_EQ(ret, 1);

    // Inc config has not yet taken effect, stream scan can hit rule
    ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    maat_state_reset(state);

    sleep(WAIT_FOR_EFFECTIVE_S);

    // Inc config has taken effect, stream reference old expr_runtime, should not hit rule
    ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_stream_free(sp);
    maat_state_free(state);
    sp = NULL;
    state = NULL;
}

//hyperscan engine
INSTANTIATE_TEST_CASE_P(HS, StreamScan, testing::Values("HS"));
//rulescan engine
INSTANTIATE_TEST_CASE_P(RS, StreamScan, testing::Values("RS"));

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
    const char *attribute_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str1[32] = "0.0.0.0";
    uint32_t sip1;
    int ret = inet_pton(AF_INET, ip_str1, &sip1);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv4(maat_inst, table_name, attribute_name, sip1, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    
    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, IPv4Broadcast) {
    const char *table_name = "IP_PLUS_CONFIG";
    const char *attribute_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str1[32] = "255.255.255.255";
    uint32_t sip1;
    int ret = inet_pton(AF_INET, ip_str1, &sip1);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv4(maat_inst, table_name, attribute_name, sip1, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    
    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, MatchSingleIPv4) {
    const char *table_name = "IP_PLUS_CONFIG";
    const char *attribute_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str[32] = "100.64.3.1";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv4(maat_inst, table_name, attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000169");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, IPv6Unspecified) {
    const char *table_name = "IP_PLUS_CONFIG";
    const char *attribute_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str[32] = "::";
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, sip);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv6(maat_inst, table_name, attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000210");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);  
}

TEST_F(IPScan, IPv6Broadcast) {
    const char *table_name = "IP_PLUS_CONFIG";
    const char *attribute_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str[64] = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF";
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, sip);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv6(maat_inst, table_name, attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    
    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);  
}

TEST_F(IPScan, MatchSingleIPv6) {
    const char *table_name = "IP_PLUS_CONFIG";
    const char *attribute_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str[64] = "1:1:1:1:1:1:1:1";
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, sip);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv6(maat_inst, table_name, attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000210");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, MatchIPv4Range) {
    const char *table_name = "IP_PLUS_CONFIG";
    const char *attribute_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str[32] = "10.0.7.100";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv4(maat_inst, table_name, attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000208");

    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000154");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}
TEST_F(IPScan, MatchIPv4Port) {
    const char *table_name = "IP_PLUS_CONFIG";
    const char *attribute_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str[32] = "192.168.30.44";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    
    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv4_port(maat_inst, table_name, attribute_name, sip, 443, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_ipv4_port(maat_inst, table_name, attribute_name, sip, 80, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000232");

    maat_state_free(state);
    state = NULL;
}
TEST_F(IPScan, MatchIPv6Range) {
    const char *table_name = "IP_PLUS_CONFIG";
    const char *attribute_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str[32] = "1001:da8:205:1::101";
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv6(maat_inst, table_name, attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000210");

    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000155");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}
TEST_F(IPScan, MatchIPv6Port) {
    const char *table_name = "IP_PLUS_CONFIG";
    const char *attribute_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str[32] = "2607:5d00:2:2::32:28";
    int port=443;
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv6_port(maat_inst, table_name, attribute_name, sip, port, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000230");

    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000210");
    
    maat_state_reset(state);
    //If the port is not present, should not match rules with port range. In this case, only rule 210 "::/0" should match.
    ret = maat_scan_ipv6(maat_inst, table_name, attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000210");

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, BugReport20210515) {
    const char *table_name = "IP_CONFIG";
    const char *attribute_name = "IP_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str[64] = "2409:8915:3430:7e7:8c9b:ff2a:7aa1:e74";
    uint8_t ip_addr[sizeof(struct in6_addr)];
    int ret = inet_pton(AF_INET6, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv6(maat_inst, table_name, attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(IPScan, RuleUpdates) {
    const char *table_name = "IP_PLUS_CONFIG";
    const char *attribute_name = "IP_PLUS_CONFIG";
    struct maat *maat_inst = IPScan::_shared_maat_inst;
    int thread_id = 0;

    char ip_str[32] = "100.100.100.100";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    ret = maat_scan_ipv4(maat_inst, table_name, attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /* ip table add line */
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char object_uuid_str[UUID_STR_LEN] = {0};
    char item_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object_id);
    snprintf(item_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item_id);
    ret = ip_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_uuid_str,
                            object_uuid_str, "100.100.100.100", NULL, 0);
    EXPECT_EQ(ret, 1);

    const char *rule_table_name = "RULE_DEFAULT";

     /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);
    struct maat_cmd_and_condition and_condition;
    and_condition.negate_option = 0;
    and_condition.or_condition_num = 1;
    and_condition.or_conditions[0].object_num = 1;
    and_condition.or_conditions[0].object_uuids_str[0] = object_uuid_str;
    and_condition.or_conditions[0].attribute_name = attribute_name;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                 rule_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_ipv4(maat_inst, table_name, attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /* ip table del line */
    ret = ip_table_set_line(maat_inst, table_name, MAAT_OP_DEL, item_uuid_str,
                            object_uuid_str, "100.100.100.100", NULL, 0);
    EXPECT_EQ(ret, 1);

    /* rule table del line */
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, 
                                 rule_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_ipv4(maat_inst, table_name, attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

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
	uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "CONTENT_SIZE";
    const char *attribute_name = "CONTENT_SIZE";
    struct maat *maat_inst = IntervalScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    unsigned int scan_data1 = 2015;

	int ret = maat_scan_integer(maat_inst, table_name, attribute_name, scan_data1, results,
                                ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_reset(state);

    unsigned int scan_data2 = 300;
    ret = maat_scan_integer(maat_inst, table_name, attribute_name, scan_data2, results,
                            ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(IntervalScan, SingleInteger) {	
	uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "CONTENT_SIZE";
    const char *attribute_name = "CONTENT_SIZE";
    struct maat *maat_inst = IntervalScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    unsigned int scan_data1 = 3000;

	int ret = maat_scan_integer(maat_inst, table_name, attribute_name, scan_data1, results,
                                ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000218");
    
    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
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
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = ObjectScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    struct maat_hit_object hit_object;
    uuid_parse("00000000-0000-0000-0000-000000000247", hit_object.object_uuid);

    int ret = maat_scan_object(maat_inst, table_name, attribute_name, &hit_object, 1, results,
                              ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000226");

    maat_state_free(state);
    state = NULL;
    sleep(2);
}

TEST_F(ObjectScan, Attribute) {
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *attribute_name = "HTTP_RESPONSE_KEYWORDS";
    const char *table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = ObjectScan::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    struct maat_hit_object hit_object;
    uuid_parse("00000000-0000-0000-0000-000000000259", hit_object.object_uuid);

    int ret = maat_scan_object(maat_inst, table_name, attribute_name, &hit_object, 1, results,
                              ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000233");

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
	uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *attribute_name = "HTTP_URL_FILTER";
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	int ret = maat_scan_string(maat_inst, table_name, attribute_name, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
						
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	
    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000143");

    maat_state_reset(state);
	
	ret = maat_scan_string(maat_inst, table_name, attribute_name, string_should_not_hit,
                           strlen(string_should_not_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
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
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *hit_attribute_name = "HTTP_URL_FILTER";
    const char *hit_table_name = "HTTP_URL";
    const char *not_hit_attribute_name = "HTTP_RESPONSE_KEYWORDS";
    const char *not_hit_table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    // scan string_should_hit(HTTP_URL_FILTER) & string_should_not_hit(HTTP_RESPONSE_KEYWORDS) => not hit rule
    int ret = maat_scan_string(maat_inst, hit_table_name, hit_attribute_name, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, not_hit_table_name, not_hit_attribute_name, string_should_not_hit,
                           strlen(string_should_not_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, not_hit_table_name, not_hit_attribute_name, string_contain_nothing,
                           strlen(string_contain_nothing), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_name, not_hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //scan string_should_hit(HTTP_URL_FILTER) & nothing(HTTP_RESPONSE_KEYWORDS) => hit rule144
    ret = maat_scan_string(maat_inst, hit_table_name, hit_attribute_name, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, not_hit_table_name, not_hit_attribute_name, string_contain_nothing,
                           strlen(string_contain_nothing), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_name, not_hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000144");
 
    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanIrrelavantAtLast) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-144.";
	const char *string_irrelevant = "This string contains nothing to hit.";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *hit_attribute_name = "HTTP_URL_FILTER";
    const char *hit_table_name = "HTTP_URL";
    const char *not_hit_attribute_name = "HTTP_RESPONSE_KEYWORDS";
    const char *not_hit_table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, hit_table_name, hit_attribute_name, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, hit_table_name, hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, not_hit_table_name, not_hit_attribute_name, string_irrelevant,
                           strlen(string_irrelevant), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_name, not_hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000144");
    
    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanHitAtLastEmptyExpr) {
    const char *string_should_not_hit = "This string should not hit.";
	const char *string_match_no_region = "This string is matched against a empty table.";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *not_hit_attribute_name = "HTTP_URL_FILTER";
    const char *not_hit_table_name = "HTTP_URL";
    const char *hit_attribute_name = "IP_PLUS_CONFIG";
    const char *hit_table_name = "IP_PLUS_CONFIG";
    const char *empty_attribute_name = "EMPTY_KEYWORD";
    const char *empty_table_name = "EMPTY_KEYWORD";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, not_hit_table_name, not_hit_attribute_name, string_should_not_hit,
                               strlen(string_should_not_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_name, not_hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.8.186", &sip);

    ret = maat_scan_ipv4(maat_inst, hit_table_name, hit_attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000186");

    ret = maat_scan_not_logic(maat_inst, hit_table_name, hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, empty_table_name, empty_attribute_name, string_match_no_region, 
                           strlen(string_match_no_region), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, empty_table_name, empty_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanHitAtLastEmptyInteger) {
    const char *string_should_not_hit = "This string should not hit.";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *not_hit_attribute_name = "HTTP_URL_FILTER";
    const char *not_hit_table_name = "HTTP_URL";
    const char *hit_attribute_name = "IP_PLUS_CONFIG";
    const char *hit_table_name = "IP_PLUS_CONFIG";
    const char *empty_attribute_name = "EMPTY_INTERGER";
    const char *empty_table_name = "EMPTY_INTERGER";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, not_hit_table_name, not_hit_attribute_name, string_should_not_hit, 
                               strlen(string_should_not_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_name, not_hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.8.187", &sip);

    ret = maat_scan_ipv4(maat_inst, hit_table_name, hit_attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000187");

    ret = maat_scan_not_logic(maat_inst, hit_table_name, hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int empty_table_id = maat_get_table_id(maat_inst, empty_table_name);
    ASSERT_GT(empty_table_id, 0);

    ret = maat_scan_integer(maat_inst, empty_table_name, empty_attribute_name, 2015,
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, empty_table_name, empty_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanNotIP) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-145.";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *hit_table_name = "HTTP_URL";
    const char *hit_attribute_name = "HTTP_URL";
    const char *not_hit_attribute_name = "ATTRIBUTE_IP_CONFIG";
    const char *not_hit_table_name = "IP_CONFIG";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    // scan string_should_hit(HTTP_URL) & hit ip(ATTRIBUTE_IP_CONFIG) => not hit rule
    int ret = maat_scan_string(maat_inst, hit_table_name, hit_attribute_name, string_should_hit, 
                               strlen(string_should_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, hit_table_name, hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.6.205", &sip);

    ret = maat_scan_ipv4(maat_inst, not_hit_table_name, not_hit_attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_name, not_hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000145");

    maat_state_reset(state);

    // scan string_should_hit(HTTP_URL) & not hit ip(ATTRIBUTE_IP_CONFIG) => hit rule145
    ret = maat_scan_string(maat_inst, hit_table_name, hit_attribute_name, string_should_hit, 
                               strlen(string_should_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    inet_pton(AF_INET, "10.0.6.201", &sip);
    ret = maat_scan_ipv4(maat_inst, not_hit_table_name, not_hit_attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_name, not_hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK); 

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, NotUrlAndNotIp) {
    const char *string_should_half_hit = "This string ONLY contains must-contained-string-of-rule-146.";
    const char *string_should_not_hit = "This string contains must-contained-string-of-rule-146 and "
                                         "must-contained-not-string-of-rule-146.";
    const char *string_nothing = "This string contain nothing";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *url_attribute_name = "HTTP_URL_FILTER";
    const char *url_table_name = "HTTP_URL";
    const char *ip_attribute_name = "ATTRIBUTE_IP_CONFIG";
    const char *ip_table_name = "IP_CONFIG";
    const char *http_attribute_name = "HTTP_RESPONSE_KEYWORDS";
    const char *http_table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //scan string_should_half_hit(HTTP_URL_FILTER) & hit ip(ATTRIBUTE_IP_CONFIG) => not hit rule
    int ret = maat_scan_string(maat_inst, url_table_name, url_attribute_name, string_should_half_hit, 
                               strlen(string_should_half_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_name, url_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.6.201", &sip);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    // scan string_should_half_hit(HTTP_RESPONSE_KEYWORDS) & not hit ip(ATTRIBUTE_IP_CONFIG) => not hit rule

    ret = maat_scan_string(maat_inst, http_table_name, http_attribute_name, string_should_not_hit, 
                           strlen(string_should_not_hit), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT); 
    
    ret = maat_scan_not_logic(maat_inst, http_table_name, http_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    inet_pton(AF_INET, "10.1.0.0", &sip);
    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    // scan scan string_should_half_hit(HTTP_URL_FILTER) & not hit ip(ATTRIBUTE_IP_CONFIG) => hit rule146
    ret = maat_scan_string(maat_inst, url_table_name, url_attribute_name, string_should_half_hit, 
                               strlen(string_should_half_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, http_table_name, http_attribute_name, string_nothing, 
                           strlen(string_nothing), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK); 

    ret = maat_scan_not_logic(maat_inst, http_table_name, http_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    
    inet_pton(AF_INET, "10.1.0.0", &sip);
    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000146");

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, NotPhysicalTable) {
    const char *string1 = "This string ONLY contains not_logic_rule_224_1.";
    const char *string2 = "This string ONLY contains not_logic_rule_224_2.";
    const char *string3 = "This string ONLY contains nothing.";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "HTTP_RESPONSE_KEYWORDS";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    // scan hit string1(KEYWORDS_TABLE) & hit string2(HTTP_RESPONSE_KEYWORDS) => not hit rule
    int ret = maat_scan_string(maat_inst, table_name, table_name, string1, 
                               strlen(string1), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, table_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, string2, strlen(string2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    //scan not hit string1(KEYWORDS_TABLE) & hit string2(HTTP_RESPONSE_KEYWORDS) => hit rule224
    ret = maat_scan_string(maat_inst, table_name, table_name, string3, strlen(string3),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, table_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, string2, strlen(string2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT); 
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000224");

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, EightNotCondition) {
    const char *string_nothing = "This string contain nothing";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *attribute_name1 = "HTTP_RESPONSE_KEYWORDS_1";
    const char *attribute_name2 = "HTTP_RESPONSE_KEYWORDS_2";
    const char *attribute_name3 = "HTTP_RESPONSE_KEYWORDS_3";
    const char *attribute_name4 = "HTTP_RESPONSE_KEYWORDS_4";
    const char *attribute_name5 = "HTTP_RESPONSE_KEYWORDS_5";
    const char *attribute_name6 = "HTTP_RESPONSE_KEYWORDS_6";
    const char *attribute_name7 = "HTTP_RESPONSE_KEYWORDS_7";
    const char *attribute_name8 = "HTTP_RESPONSE_KEYWORDS_8";
    const char *table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, table_name, attribute_name1, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name1, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_name2, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name2, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_name3, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name3, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_name4, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name4, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_name5, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name5, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_name6, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name6, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_name7, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name7, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_name8, string_nothing, 
                               strlen(string_nothing), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK); 

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name8, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000147");

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, NotConditionAndExcludeObject1) {
    const char *string_should_not_hit = "This string ONLY contains must-contained-string-of-rule-200 and "
                                         "must-not-contained-string-of-rule-200";
    const char *string_should_half_hit = "This string ONLY contains must-contained-string-of-rule-200";
    const char *string_nothing = "This string contain nothing";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *url_attribute_name = "HTTP_URL_FILTER";
    const char *url_table_name = "HTTP_URL";
    const char *http_attribute_name = "HTTP_RESPONSE_KEYWORDS";
    const char *http_table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, url_table_name, url_attribute_name, string_should_not_hit, 
                               strlen(string_should_not_hit), results,
                               ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_name, url_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, url_table_name, url_attribute_name, string_should_half_hit, 
                               strlen(string_should_half_hit), results,
                               ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_name, url_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, http_table_name, http_attribute_name, string_nothing, 
                           strlen(string_nothing), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, http_table_name, http_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000216");

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, NotConditionAndExcludeObject2) {
    const char *string1 = "This string ONLY contains mail.string-of-rule-217.com";
    const char *string2= "This string ONLY contains www.string-of-rule-217.com";
    const char *string_keywords = "This string contain keywords-for-rule-217";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *url_attribute_name = "HTTP_URL_FILTER";
    const char *url_table_name = "HTTP_URL";
    const char *http_attribute_name = "HTTP_RESPONSE_KEYWORDS";
    const char *http_table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, http_table_name, http_attribute_name, string_keywords,
                               strlen(string_keywords), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, http_table_name, http_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, url_table_name, url_attribute_name, string1, strlen(string1),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_name, url_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = maat_scan_string(maat_inst, http_table_name, http_attribute_name, string_keywords,
                               strlen(string_keywords), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, http_table_name, http_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, url_table_name, url_attribute_name, string2, strlen(string2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_name, url_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000217");

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, SingleNotCondition) {
    const char *string_nothing = "nothing string";
    const char *string_should_hit = "string has not_logic_keywords_222";
    const char *attribute_name = "HTTP_NOT_LOGIC_1";
    const char *table_name = "KEYWORDS_TABLE";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //string_should_hit(HTTP_NOT_LOGIC_1) => not hit rule
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //string nothing(HTTP_NOT_LOGIC_1) => hit rule222
    ret = maat_scan_string(maat_inst, table_name, attribute_name, string_nothing, strlen(string_nothing),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000222");

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, MultiNotConditions) {
    const char *string_nothing = "nothing string";
    const char *string1 = "string has not_logic_rule_223_1";
    const char *string2 = "string has not_logic_rule_223_1";
    const char *string3 = "string has not_logic_rule_223_1";
    const char *attribute_name = "HTTP_NOT_LOGIC";
    const char *table_name = "KEYWORDS_TABLE";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    // rule223 = !string1 & !string2 & !string3
    //Case1: scan string1 & !string2 & !string3
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, string1, strlen(string1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, string_nothing, strlen(string_nothing),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //Case2: scan !string1 & string2 & !string3
    ret = maat_scan_string(maat_inst, table_name, attribute_name, string_nothing, strlen(string_nothing),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, string2, strlen(string2),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //Case3: scan !string1 & !string2 & string3
    ret = maat_scan_string(maat_inst, table_name, attribute_name, string_nothing, strlen(string_nothing),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, string3, strlen(string3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);
    
    //Case4: scan !string1 & !string2 & !string3
    ret = maat_scan_string(maat_inst, table_name, attribute_name, string_nothing, strlen(string_nothing),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000223"); 

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, MultiObjectsInOneNotCondition) {
    const char *src_asn1 = "AS1234";
    const char *src_asn2 = "AS6789";
    const char *src_asn3 = "AS9001";
    const char *src_asn_nothing = "nothing string";
    const char *dst_asn = "AS2345";
    const char *src_asn_attribute_name = "ASN_NOT_LOGIC";
    const char *dst_asn_attribute_name = "DESTINATION_IP_ASN";
    const char *table_name = "AS_NUMBER";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //--------------------------------------
	//			Source ASN1 & Dest ASN => not hit rule
	//--------------------------------------
    int ret = maat_scan_string(maat_inst, table_name, src_asn_attribute_name, src_asn1, strlen(src_asn1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, src_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);                          

    ret = maat_scan_string(maat_inst, table_name, dst_asn_attribute_name, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    //--------------------------------------
	//			Source ASN2 & Dest ASN => not hit rule
	//--------------------------------------
    ret = maat_scan_string(maat_inst, table_name, src_asn_attribute_name, src_asn2, strlen(src_asn2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, src_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, dst_asn_attribute_name, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    //--------------------------------------
	//			Source ASN3 & Dest ASN => not hit rule
	//--------------------------------------
    ret = maat_scan_string(maat_inst, table_name, src_asn_attribute_name, src_asn3, strlen(src_asn3),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, src_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, dst_asn_attribute_name, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    // Source nothing & Dest ASN => hit rule177
    ret = maat_scan_string(maat_inst, table_name, src_asn_attribute_name, src_asn_nothing,
                           strlen(src_asn_nothing),results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, table_name, src_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, dst_asn_attribute_name, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000177");

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, MultiLiteralsInOneNotCondition) {
    const char *src_asn1 = "AS1234";
    const char *src_asn2 = "AS6789";
    const char *src_nothing = "nothing";
    const char *my_county = "Greece.Sparta";
    const char *ip_attribute_name = "IP_PLUS_CONFIG";
    const char *ip_table_name = "IP_PLUS_CONFIG";
    const char *src_asn_attribute_name = "SOURCE_IP_ASN";
    const char *src_asn_table_name = "AS_NUMBER";
    const char *ip_geo_attribute_name = "SOURCE_IP_GEO";
    const char *ip_geo_table_name = "GeoLocation";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //-------------------------------------------
	//			Source ASN1 & IP Geo
	//-------------------------------------------
    int ret = maat_scan_string(maat_inst, src_asn_table_name, src_asn_attribute_name, src_asn1, strlen(src_asn1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, ip_geo_table_name, ip_geo_attribute_name, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_asn_table_name, src_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //-------------------------------------------
	//			Source nothing & IP Geo
	//-------------------------------------------
    ret = maat_scan_string(maat_inst, src_asn_table_name, src_asn_attribute_name, src_nothing, strlen(src_nothing),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, ip_geo_table_name, ip_geo_attribute_name, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_asn_table_name, src_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000181");

    maat_state_reset(state);

    //-------------------------------------------
	//			Source ASN2 & IP Geo
	//-------------------------------------------
    ret = maat_scan_string(maat_inst, src_asn_table_name, src_asn_attribute_name, src_asn2, strlen(src_asn2),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, ip_geo_table_name, ip_geo_attribute_name, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, src_asn_table_name, src_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //--------------------------------------
	//			hit IP & IP Geo
	//--------------------------------------
    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.40.88", &ip_addr);
    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, ip_geo_table_name, ip_geo_attribute_name, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //--------------------------------------
	//			not hit IP & IP Geo
	//--------------------------------------
    inet_pton(AF_INET, "192.168.40.89", &ip_addr);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, ip_geo_table_name, ip_geo_attribute_name, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000181");

    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, SameAttributeInMultiCondition) {
    const char *src_asn1 = "AS1234";
    const char *src_asn2 = "AS9002";
    const char *src_asn3 = "AS9003";
    const char *my_county = "Greece.Sparta";
    const char *ip_table_name = "IP_PLUS_CONFIG";
    const char *ip_attribute_name = "IP_PLUS_CONFIG";
    const char *dst_asn_attribute_name = "DESTINATION_IP_ASN";
    const char *dst_asn_table_name = "AS_NUMBER";
    const char *ip_geo_attribute_name = "SOURCE_IP_GEO";
    const char *ip_geo_table_name = "GeoLocation";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = NOTLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.40.88", &ip_addr);
    //-------------------------------------------
	//			Dest ASN1 & Dest ASN3 & IP Config
	//-------------------------------------------
    int ret = maat_scan_string(maat_inst, dst_asn_table_name, dst_asn_attribute_name, src_asn1, strlen(src_asn1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, dst_asn_table_name, dst_asn_attribute_name, src_asn3, strlen(src_asn3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, dst_asn_table_name, dst_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //-------------------------------------------
	//			Dest ASN2 & Dest ASN3 & IP Config
	//-------------------------------------------
    ret = maat_scan_string(maat_inst, dst_asn_table_name, dst_asn_attribute_name, src_asn2, strlen(src_asn2),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, dst_asn_table_name, dst_asn_attribute_name, src_asn3, strlen(src_asn3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, dst_asn_table_name, dst_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    //-------------------------------------------
	//			Dest IP Geo & Dest ASN3 & IP Config
	//-------------------------------------------
    ret = maat_scan_string(maat_inst, ip_geo_table_name, ip_geo_attribute_name, my_county, strlen(my_county),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_geo_table_name, ip_geo_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, dst_asn_table_name, dst_asn_attribute_name, src_asn3, strlen(src_asn3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, dst_asn_table_name, dst_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,  
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    maat_state_reset(state);

    //-------------------------------------------
	//			Dest ASN3 & IP Geo
	//-------------------------------------------
    ret = maat_scan_string(maat_inst, dst_asn_table_name, dst_asn_attribute_name, src_asn3, strlen(src_asn3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, dst_asn_table_name, dst_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);                          

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000185");

    maat_state_reset(state);

    //--------------------------------------
	//			IP Config & IP Geo
	//--------------------------------------
    ret = maat_scan_string(maat_inst, dst_asn_table_name, dst_asn_attribute_name, src_asn3, strlen(src_asn3),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    inet_pton(AF_INET, "192.168.40.89", &ip_addr);
    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, dst_asn_table_name, dst_asn_attribute_name, results, ARRAY_SIZE,
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
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *not_hit_table_name = "KEYWORDS_TABLE";
    const char *not_hit_attribute_name = "KEYWORDS_TABLE";
    const char *hit_table_name = "HTTP_URL";
    const char *hit_attribute_name = "HTTP_URL";
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, not_hit_table_name, not_hit_attribute_name, string_should_not_hit,
                               strlen(string_should_not_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, not_hit_table_name, not_hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, hit_table_name, hit_attribute_name, string_should_hit,
                           strlen(string_should_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000199");

    ret = maat_scan_not_logic(maat_inst, hit_table_name, hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(ExcludeLogic, ScanExcludeAtLast) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-200.";
	const char *string_should_not_hit = "This string contains both must-contained-string-of-rule-200"
                                        " and must-not-contained-string-of-rule-200.";
	uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, table_name, attribute_name, string_should_not_hit,
                               strlen(string_should_not_hit), results,
                               ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

	ret = maat_scan_string(maat_inst, table_name, attribute_name, string_should_hit,
                           strlen(string_should_hit), results,
                           ARRAY_SIZE, &n_hit_result, state);
						
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000200");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);                          

	maat_state_free(state);
    state = NULL;
}

TEST_F(ExcludeLogic, ScanIrrelavantAtLast) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-200.";
	const char *string_irrelevant = "This string contains nothing to hit.";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *hit_table_name = "HTTP_URL";
    const char *hit_attribute_name = "HTTP_URL";
    const char *not_hit_table_name = "KEYWORDS_TABLE";
    const char *not_hit_attribute_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, hit_table_name, hit_attribute_name, string_should_hit,
                               strlen(string_should_hit), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000200");

    ret = maat_scan_not_logic(maat_inst, hit_table_name, hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, not_hit_table_name, not_hit_attribute_name, string_irrelevant,
                           strlen(string_irrelevant), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    
    ret = maat_scan_not_logic(maat_inst, not_hit_table_name, not_hit_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(ExcludeLogic, ScanAttribute) {
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *attribute_name = "ATTRIBUTE_IP_PLUS_TABLE";
    const char *table_name = "IP_PLUS_CONFIG";

    uint32_t should_hit_ip;
    uint32_t should_not_hit_ip;
    inet_pton(AF_INET, "100.64.1.1", &should_hit_ip);
    
    int ret = maat_scan_ipv4(maat_inst, table_name, attribute_name, should_hit_ip, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000202");

    maat_state_reset(state);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    inet_pton(AF_INET, "100.64.1.5", &should_hit_ip);
    ret = maat_scan_ipv4(maat_inst, table_name, attribute_name, should_hit_ip, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000202");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    inet_pton(AF_INET, "100.64.1.6", &should_not_hit_ip);
    ret = maat_scan_ipv4(maat_inst, table_name, attribute_name, should_not_hit_ip, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    inet_pton(AF_INET, "100.64.1.11", &should_not_hit_ip);
    ret = maat_scan_ipv4(maat_inst, table_name, attribute_name, should_not_hit_ip, results,
                        ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    
    maat_state_free(state);
}

TEST_F(ExcludeLogic, ScanWithMultiCondition) {
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *src_ip_attribute_name = "ATTRIBUTE_IP_PLUS_SOURCE";
    const char *dst_ip_attribute_name = "ATTRIBUTE_IP_PLUS_DESTINATION";
    const char *ip_table_name = "IP_PLUS_CONFIG";

    int ip_table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(ip_table_id, 0);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.50.43", &ip_addr);

    int ret = maat_scan_ipv4(maat_inst, ip_table_name, src_ip_attribute_name, ip_addr, results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, src_ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    inet_pton(AF_INET, "47.92.108.93", &ip_addr);
    ret = maat_scan_ipv4(maat_inst, ip_table_name, dst_ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, dst_ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *expr_attribute_name = "HTTP_RESPONSE_KEYWORDS";
    const char *expr_table_name = "KEYWORDS_TABLE";

    const char *should_not_hit_expr = "www.jianshu.com";
    ret = maat_scan_string(maat_inst, expr_table_name, expr_attribute_name, should_not_hit_expr,
                           strlen(should_not_hit_expr), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, expr_table_name, expr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *should_hit_expr = "mail.jianshu.com";
    ret = maat_scan_string(maat_inst, expr_table_name, expr_attribute_name, should_hit_expr,
                           strlen(should_hit_expr), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000203");

    ret = maat_scan_not_logic(maat_inst, expr_table_name, expr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(ExcludeLogic, ExcludeInDifferentLevel) {
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ExcludeLogic::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *src_ip_attribute_name = "ATTRIBUTE_IP_PLUS_SOURCE";
    const char *dst_ip_attribute_name = "ATTRIBUTE_IP_PLUS_DESTINATION";
    const char *ip_table_name = "IP_PLUS_CONFIG";

    uint32_t ip_addr;
    inet_pton(AF_INET, "100.64.2.1", &ip_addr);

    int ret = maat_scan_ipv4(maat_inst, ip_table_name, src_ip_attribute_name, ip_addr, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, src_ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    inet_pton(AF_INET, "100.64.2.6", &ip_addr);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, dst_ip_attribute_name, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, dst_ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *expr_attribute_name = "HTTP_RESPONSE_KEYWORDS";
    const char *expr_table_name = "KEYWORDS_TABLE";

    const char *should_not_hit_expr1 = "www.baidu.com";
    ret = maat_scan_string(maat_inst, expr_table_name, expr_attribute_name, should_not_hit_expr1,
                           strlen(should_not_hit_expr1), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, expr_table_name, expr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *should_not_hit_expr2 = "mail.baidu.com";
    ret = maat_scan_string(maat_inst, expr_table_name, expr_attribute_name, should_not_hit_expr2,
                           strlen(should_not_hit_expr2), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, expr_table_name, expr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *should_hit_expr = "hit.baidu.com";
    ret = maat_scan_string(maat_inst, expr_table_name, expr_attribute_name, should_hit_expr,
                           strlen(should_hit_expr), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000204");

    ret = maat_scan_not_logic(maat_inst, expr_table_name, expr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

void maat_read_entry_start_cb(int update_type, void *u_para)
{
}

void maat_read_entry_cb(const char *table_name, const char *table_line, enum maat_operation op, void *u_para)
{
	char ip_str[16] = {0};
	int entry_id = -1;
	unsigned int ip_uint = 0;
	int is_valid = 0;
	unsigned int local_ip_nr = 16820416;//192.168.0.1
    cJSON *json = cJSON_Parse(table_line);

    EXPECT_TRUE(json != NULL);

    cJSON *tmp_obj = cJSON_GetObjectItem(json, "ip");
    EXPECT_TRUE(tmp_obj != NULL);
    strcpy(ip_str, tmp_obj->valuestring);
    inet_pton(AF_INET, ip_str, &ip_uint);
    if (local_ip_nr == ip_uint) {
        tmp_obj = cJSON_GetObjectItem(json, "is_valid");
        EXPECT_TRUE(tmp_obj != NULL);
        is_valid = tmp_obj->valueint;
        tmp_obj = cJSON_GetObjectItem(json, "entry_id");
        EXPECT_TRUE(tmp_obj != NULL);
        entry_id = tmp_obj->valueint;
        EXPECT_EQ(is_valid, 1);
        EXPECT_EQ(entry_id, 101);
    }

    cJSON_Delete(json);
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

    
    int ret = maat_table_callback_register(maat_inst, table_name, 
                                           maat_read_entry_start_cb,
                                           maat_read_entry_cb, 
                                           maat_read_entry_finish_cb,
                                           maat_inst);
    EXPECT_EQ(ret, 0);
}

struct plugin_ud {
	char key[32];
    char value[32];
    uuid_t uuid;
};

void plugin_EX_new_cb(const char *table_name, const char *key, 
                      const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	struct plugin_ud *ud = ALLOC(struct plugin_ud, 1);

    cJSON *json = cJSON_Parse(table_line);
    EXPECT_TRUE(json != NULL);

    cJSON *tmp_obj = cJSON_GetObjectItem(json, "uuid");
    EXPECT_TRUE(tmp_obj != NULL);
    uuid_parse(tmp_obj->valuestring, ud->uuid);

    tmp_obj = cJSON_GetObjectItem(json, "key");
    EXPECT_TRUE(tmp_obj != NULL);
    if (tmp_obj->type == cJSON_Number) {
        snprintf(ud->key, sizeof(ud->key), "%d", tmp_obj->valueint);
    } else {
        strncpy(ud->key, tmp_obj->valuestring, sizeof(ud->key));
    }

    tmp_obj = cJSON_GetObjectItem(json, "city");
    EXPECT_TRUE(tmp_obj != NULL);
    strncpy(ud->value, tmp_obj->valuestring, sizeof(ud->value));

    cJSON_Delete(json);

    *ad = ud;
	(*counter)++;
}

void plugin_EX_free_cb(const char *table_name, void **ad, long argl, void *argp)
{
	struct plugin_ud *ud = (struct plugin_ud *)(*ad);

    memset(ud, 0, sizeof(struct plugin_ud));
	free(ud);
	*ad = NULL;
}

void plugin_EX_dup_cb(const char *table_name, void **to, void **from, long argl, void *argp)
{
	struct plugin_ud *ud = (struct plugin_ud *)(*from);

	*to = ud;
}

TEST_F(PluginTable, EX_DATA) {
    const char *table_name = "TEST_PLUGIN_EXDATA_TABLE";
    struct maat *maat_inst = PluginTable::_shared_maat_inst;

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
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           key1, strlen(key1));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Shijiazhuang");
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(ud->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000001");

    const char *key2 = "ShanDong";
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           key2, strlen(key2));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Jinan");
    uuid_unparse(ud->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000003");
}

TEST_F(PluginTable, LONG_KEY_TYPE) {
    const char *table_name = "TEST_PLUGIN_LONG_KEY_TYPE_TABLE";
    struct maat *maat_inst = PluginTable::_shared_maat_inst;

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
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           (char *)&key1, sizeof(long long));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Shijiazhuang");
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(ud->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000001");

    long long key2 = 33333333;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           (char *)&key2, sizeof(long long));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Jinan");
    uuid_unparse(ud->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000003");

    int key3 = 22222222;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           (char *)&key3, sizeof(key3));
    ASSERT_TRUE(ud == NULL);
}

TEST_F(PluginTable, INT_KEY_TYPE) {
    const char *table_name = "TEST_PLUGIN_INT_KEY_TYPE_TABLE";
    struct maat *maat_inst = PluginTable::_shared_maat_inst;

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
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           (char *)&key1, sizeof(key1));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "China");
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(ud->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000001");

    int key2 = 102;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           (char *)&key2, sizeof(key2));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "America");
    uuid_unparse(ud->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000002");

    long long key3 = 103;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           (char *)&key3, sizeof(key3));
    ASSERT_TRUE(ud == NULL);
}

TEST_F(PluginTable, IP_KEY_TYPE) {
    const char *table_name = "TEST_PLUGIN_IP_KEY_TYPE_TABLE";
    struct maat *maat_inst = PluginTable::_shared_maat_inst;

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
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           (char *)&ipv4_addr1,
                                                           sizeof(ipv4_addr1));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "XiZang");
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(ud->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000001");

    uint32_t ipv4_addr2;
    ret = inet_pton(AF_INET, "100.64.1.2", &ipv4_addr2);
    EXPECT_EQ(ret, 1);

    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           (char *)&ipv4_addr2,
                                                           sizeof(ipv4_addr2));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "XinJiang");
    uuid_unparse(ud->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000002");

    uint8_t ipv6_addr1[16];
    ret = inet_pton(AF_INET6, "2001:da8:205:1::101", ipv6_addr1);
    EXPECT_EQ(ret, 1);

    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           (char *)ipv6_addr1,
                                                           sizeof(ipv6_addr1));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "GuiZhou");
    uuid_unparse(ud->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000003");

    uint8_t ipv6_addr2[16];
    ret = inet_pton(AF_INET6, "1001:da8:205:1::101", ipv6_addr2);
    EXPECT_EQ(ret, 1);

    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                           (char *)ipv6_addr2,
                                                           sizeof(ipv6_addr2));
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "SiChuan");
    uuid_unparse(ud->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000004");
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
	uuid_t rule_uuid;
	char *buffer;
    size_t buf_len;
};
void ip_plugin_ex_new_cb(const char *table_name, const char *key, 
                         const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	struct ip_plugin_ud *ud = ALLOC(struct ip_plugin_ud, 1);

    cJSON *json = cJSON_Parse(table_line);
    EXPECT_TRUE(json != NULL);

    cJSON *tmp_obj = cJSON_GetObjectItem(json, "uuid");
    EXPECT_TRUE(tmp_obj != NULL);
    uuid_parse(tmp_obj->valuestring, ud->rule_uuid);

    tmp_obj = cJSON_GetObjectItem(json, "buffer");
    EXPECT_TRUE(tmp_obj != NULL);
    ud->buf_len = strlen(tmp_obj->valuestring);
    ud->buffer = ALLOC(char, ud->buf_len + 1);
    strncpy(ud->buffer, tmp_obj->valuestring, ud->buf_len);

    cJSON_Delete(json);

	*ad = ud;
	(*counter)++;
}

void ip_plugin_ex_free_cb(const char *table_name, void **ad, long argl, void *argp)
{
	struct ip_plugin_ud *ud = (struct ip_plugin_ud *)(*ad);

    uuid_clear(ud->rule_uuid);
    memset(ud->buffer, 0, ud->buf_len);
    ud->buf_len = 0;

	free(ud->buffer);
	free(ud);
	*ad = NULL;
}

void ip_plugin_ex_dup_cb(const char *table_name, void **to, void **from, long argl, void *argp)
{
	struct ip_plugin_ud *ud = (struct ip_plugin_ud *)(*from);
	
	*to = ud;
}

TEST_F(IPPluginTable, EX_DATA) {
    int ip_plugin_ex_data_counter = 0;
    const char *table_name = "TEST_IP_PLUGIN_WITH_EXDATA";
    struct maat *maat_inst = IPPluginTable::_shared_maat_inst;

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
    ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_name, &ipv4, 
                                           (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000101");

    uuid_unparse(results[1]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000102");

    struct ip_addr ipv6;
    ipv6.ip_type = IPv6;
    inet_pton(AF_INET6, "2001:db8:1234::5210", &(ipv6.ipv6));
    memset(results, 0, sizeof(results));

	ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_name, &ipv6, 
                                           (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 2);
    uuid_unparse(results[0]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000104");

    uuid_unparse(results[1]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000103");

	//Reproduce BugReport-Liumengyan-20210515
	inet_pton(AF_INET6, "240e:97c:4010:104::17", &(ipv6.ipv6));
	ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_name, &ipv6, 
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
	uuid_t rule_uuid;
	char *buffer;
    size_t buf_len;
};

void ipport_plugin_ex_new_cb(const char *table_name, const char *key, 
                         const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	struct ipport_plugin_ud *ud = ALLOC(struct ipport_plugin_ud, 1);

    cJSON *json = cJSON_Parse(table_line);
    EXPECT_TRUE(json != NULL);

    cJSON *tmp_obj = cJSON_GetObjectItem(json, "uuid");
    EXPECT_TRUE(tmp_obj != NULL);
    uuid_parse(tmp_obj->valuestring, ud->rule_uuid);

    cJSON_Delete(json);

	*ad = ud;
	(*counter)++;
}

void ipport_plugin_ex_free_cb(const char *table_name, void **ad, long argl, void *argp)
{
	struct ipport_plugin_ud *ud = (struct ipport_plugin_ud *)(*ad);

    uuid_clear(ud->rule_uuid);
    if (ud->buffer) {
        memset(ud->buffer, 0, ud->buf_len);
        ud->buf_len = 0;
        FREE(ud->buffer);
    }
	
	FREE(ud);
	*ad = NULL;
}

void ipport_plugin_ex_dup_cb(const char *table_name, void **to, void **from, long argl, void *argp)
{
	struct ipport_plugin_ud *ud = (struct ipport_plugin_ud *)(*from);
	
	*to = ud;
}

TEST_F(IPPortPluginTable, EX_DATA) {
    int ex_data_counter = 0;
    const char *table_name = "TEST_IPPORT_PLUGIN_WITH_EXDATA";
    struct maat *maat_inst = IPPortPluginTable::_shared_maat_inst;

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
    ret = maat_ipport_plugin_table_get_ex_data(maat_inst, table_name, &ipv4, port,
                                               (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000103");

    ret = inet_pton(AF_INET, "192.168.100.4", &ipv4.ipv4);
    EXPECT_EQ(ret, 1);
    port = htons(150);
    memset(results, 0, sizeof(results));
    ret = maat_ipport_plugin_table_get_ex_data(maat_inst, table_name, &ipv4, port,
                                               (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    uuid_unparse(results[0]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000102");

    struct ip_addr ipv6;
    ipv6.ip_type = IPv6;
    inet_pton(AF_INET6, "2001:db8:1234::5210", ipv6.ipv6);
    port = htons(255);
    memset(results, 0, sizeof(results));

	ret = maat_ipport_plugin_table_get_ex_data(maat_inst, table_name, &ipv6, port,
                                              (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 1);
    uuid_unparse(results[0]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000104");

    ipv6.ip_type = IPv6;
    inet_pton(AF_INET6, "2001:db8:1234::5213", ipv6.ipv6);
    port = htons(255);
    memset(results, 0, sizeof(results));

	ret = maat_ipport_plugin_table_get_ex_data(maat_inst, table_name, &ipv6, port,
                                              (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 1);
    uuid_unparse(results[0]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000104");

    inet_pton(AF_INET6, "240e:97c:4010:104::17", ipv6.ipv6);
    ret = maat_ipport_plugin_table_get_ex_data(maat_inst, table_name, &ipv6, port,
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
	uuid_t rule_uuid;
	int catid;
};

void fqdn_plugin_ex_new_cb(const char *table_name, const char *key, 
                           const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	struct fqdn_plugin_ud *ud = ALLOC(struct fqdn_plugin_ud, 1);

    cJSON *json = cJSON_Parse(table_line);
    EXPECT_TRUE(json != NULL);

    cJSON *tmp_obj = cJSON_GetObjectItem(json, "uuid");
    EXPECT_TRUE(tmp_obj != NULL);
    uuid_parse(tmp_obj->valuestring, ud->rule_uuid);

    tmp_obj = cJSON_GetObjectItem(json, "buffer");
    EXPECT_TRUE(tmp_obj != NULL);
    sscanf(tmp_obj->valuestring, "catid=%d", &ud->catid);

    cJSON_Delete(json);

	*ad = ud;
	(*counter)++;
}

void fqdn_plugin_ex_free_cb(const char *table_name, void **ad, long argl, void *argp)
{
	struct fqdn_plugin_ud *u = (struct fqdn_plugin_ud *)(*ad);

    uuid_clear(u->rule_uuid);
    u->catid = 0;

	free(u);
	*ad = NULL;
}

void fqdn_plugin_ex_dup_cb(const char *table_name, void **to, void **from, long argl, void *argp)
{
	struct fqdn_plugin_ud *u = (struct fqdn_plugin_ud *)(*from);

	*to = u;
}

TEST_F(FQDNPluginTable, EX_DATA) {
    const char *table_name = "TEST_FQDN_PLUGIN_WITH_EXDATA";
    struct maat *maat_inst = FQDNPluginTable::_shared_maat_inst;

    int fqdn_plugin_ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                    fqdn_plugin_ex_new_cb,
                                                    fqdn_plugin_ex_free_cb,
                                                    fqdn_plugin_ex_dup_cb,
                                                    0, &fqdn_plugin_ex_data_counter);
    ASSERT_TRUE(ret>=0);
	EXPECT_EQ(fqdn_plugin_ex_data_counter, 5);

    struct fqdn_plugin_ud *result[4];

	ret = maat_fqdn_plugin_table_get_ex_data(maat_inst, table_name, "www.example1.com",
                                            (void**)result, 4);
	ASSERT_EQ(ret, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(result[0]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000201");

    uuid_unparse(result[1]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000202");

	ret = maat_fqdn_plugin_table_get_ex_data(maat_inst, table_name, "www.example3.com",
                                            (void**)result, 4);
	EXPECT_EQ(ret, 0);

	ret = maat_fqdn_plugin_table_get_ex_data(maat_inst, table_name, "r3---sn-i3belne6.example2.com",
                                            (void**)result, 4);
	ASSERT_EQ(ret, 2);
    uuid_unparse(result[0]->rule_uuid, uuid_str);
    EXPECT_TRUE(strcmp(uuid_str, "00000000-0000-0000-0000-000000000204") == 0 || 
                strcmp(uuid_str, "00000000-0000-0000-0000-000000000205") == 0);
}

struct bool_plugin_ud {
	uuid_t uuid;
	char *name;
    size_t name_len;
};
void bool_plugin_ex_new_cb(const char *table_name, const char *key, 
                           const char *table_line, void **ad, long argl, void *argp)
{
	int *counter=(int *)argp;
	struct bool_plugin_ud *ud = ALLOC(struct bool_plugin_ud, 1);

    cJSON *json = cJSON_Parse(table_line);
    EXPECT_TRUE(json != NULL);

    cJSON *tmp_obj = cJSON_GetObjectItem(json, "uuid");
    EXPECT_TRUE(tmp_obj != NULL);
    uuid_parse(tmp_obj->valuestring, ud->uuid);

    tmp_obj = cJSON_GetObjectItem(json, "buffer");
    EXPECT_TRUE(tmp_obj != NULL);
    ud->name_len = strlen(tmp_obj->valuestring);
    ud->name = ALLOC(char, ud->name_len + 1);
    strncpy(ud->name, tmp_obj->valuestring, ud->name_len);

    cJSON_Delete(json);
    
	*ad = ud;
	(*counter)++;
}
void bool_plugin_ex_free_cb(const char *table_name, void **ad, long argl, void *argp)
{
	struct bool_plugin_ud *u = (struct bool_plugin_ud *)(*ad);
	
    uuid_clear(u->uuid);
	memset(u->name, 0, u->name_len);
    u->name_len = 0;

	free(u->name);
	free(u);
	*ad = NULL;
	
}
void bool_plugin_ex_dup_cb(const char *table_name, void **to, void **from, long argl, void *argp)
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

	int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
								                   bool_plugin_ex_new_cb,
								                   bool_plugin_ex_free_cb,
								                   bool_plugin_ex_dup_cb,
								                   0, &ex_data_counter);
	ASSERT_TRUE(ret >= 0);
	EXPECT_EQ(ex_data_counter, 6);

	struct bool_plugin_ud *result[6];
	unsigned long long items_1[] = {999};
	ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_name, items_1,
                                             1, (void**)result, 6);
	EXPECT_EQ(ret, 0);

	unsigned long long items_2[] = {1, 2, 1000};
	ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_name, items_2,
                                             3, (void**)result, 6);
	EXPECT_EQ(ret, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(result[0]->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000301");

	unsigned long long items_3[]={101, 102, 1000};
	ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_name, items_3,
                                             3, (void**)result, 6);
	EXPECT_EQ(ret, 4);

	unsigned long long items_4[]={7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 7};
	ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_name, items_4,
                                             sizeof(items_4)/sizeof(unsigned long long),
                                             (void**)result, 6);
	EXPECT_EQ(ret, 1);
    uuid_unparse(result[0]->uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000305");
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
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *attribute_name = "HTTP_RESPONSE_KEYWORDS";
    const char *table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = Attribute::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    
    char scan_data[128] = "string1, string2, string3, string4, string5,"
                          " string6, string7, string8";
    
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
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
    struct maat *maat_inst = TableSchemaTag::_shared_maat_inst;

    //RULE_DEFAULT
    const char *tag1 = maat_get_table_schema_tag(maat_inst, rule1_table_name);
    EXPECT_TRUE(tag1 == NULL);

    //RULE_ALIAS
    const char *tag2 = maat_get_table_schema_tag(maat_inst, rule2_table_name);
    EXPECT_TRUE(tag2 != NULL);

    int ret = strcmp(tag2, "{\"rule_alias\": \"rule\"}");
    EXPECT_EQ(ret, 0);

    //RULE_CONJUNCTION
    const char *tag3 = maat_get_table_schema_tag(maat_inst, rule3_table_name);
    EXPECT_TRUE(tag3 != NULL);

    ret = strcmp(tag3, "{\"rule_conjunction\": \"rule\"}");
    EXPECT_EQ(ret, 0);

    //RULE_PLUGIN
    const char *plugin_table_name = "RULE_PLUGIN";
    const char *tag5 = maat_get_table_schema_tag(maat_inst, plugin_table_name);
    EXPECT_TRUE(tag5 != NULL);

    ret = strcmp(tag5, "{\"rule_plugin\": \"plugin\"}");
    EXPECT_EQ(ret, 0);

    //HTTP_REGION
    const char *region_table_name = "HTTP_REGION";

    const char *tag6 = maat_get_table_schema_tag(maat_inst, region_table_name);
    EXPECT_TRUE(tag6 != NULL);

    ret = strcmp(tag6, "{\"http_region\": \"expr\"}");
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

void rule_ex_param_new(const char *table_name, const char *key, 
                          const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	*ad = NULL;

    cJSON *json = cJSON_Parse(table_line);
    EXPECT_TRUE(json != NULL);

    cJSON *tmp_obj = cJSON_GetObjectItem(json, "action_parameter");
    EXPECT_TRUE(tmp_obj != NULL);

	struct rule_ex_param *param = ALLOC(struct rule_ex_param, 1);

	sscanf(tmp_obj->valuestring, "%*[^:]:%[^,],%d", param->name, &(param->id));
    
	(*counter)++;
	*ad = param;

    cJSON_Delete(json);
}

void rule_ex_param_free(const char *table_name, void **ad, long argl, void *argp)
{
	if (*ad == NULL) {
		return;
	}

	struct rule_ex_param *param = (struct rule_ex_param *)*ad;
    memset(param, 0, sizeof(struct rule_ex_param));
	free(param);
}

void rule_ex_param_dup(const char *table_name, void **to, void **from, long argl, void *argp)
{
	struct rule_ex_param *from_param = *((struct rule_ex_param **)from);

	*((struct rule_ex_param**)to) = from_param;
}

TEST_F(RuleTable, Conjunction1) {
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "i.ytimg.com/vi/OtCNcustg_I/hqdefault.jpg?sqp=-oaymwEZCNAC"
                            "ELwBSFXyq4qpAwsIARUAAIhCGAFwAQ==&rs=AOn4CLDOp_5fHMaCA9XZuJdCRv4DNDorMg";
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    struct maat *maat_inst = RuleTable::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000197");

    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000141");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE];
    int n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_EQ(n_read, 2);

    maat_state_free(state);
    state = NULL;
}

TEST_F(RuleTable, Conjunction2) {
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "i.ytimg.com/vi/OtCNcustg_I/hqdefault.jpg?sqp=-oaymwEZCNACELw"
                            "BSFXyq4qpAwsIARUAAIhCGAFwAQ==&rs=AOn4CLDOp_5fHMaCA9XZuJdCRv4DNDorMg";
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    struct maat *maat_inst = RuleTable::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000197");

    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000141");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    struct maat_hit_path hit_path[HIT_PATH_SIZE];
    int n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_EQ(n_read, 2);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
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

void accept_tags_entry_cb(const char *table_name, const char *table_line, enum maat_operation op, void *u_para)
{
	int* callback_times = (int *)u_para;

    cJSON *json = cJSON_Parse(table_line);
    EXPECT_TRUE(json != NULL);

    cJSON *tmp_obj = cJSON_GetObjectItem(json, "status");
    EXPECT_TRUE(tmp_obj != NULL);
	EXPECT_STREQ(tmp_obj->valuestring, "SUCCESS");

	(*callback_times)++;

    cJSON_Delete(json);
}

TEST_F(Policy, PluginRuleTags1) {
    const char *table_name = "TEST_EFFECTIVE_RANGE_TABLE";
    struct maat *maat_inst = Policy::_shared_maat_inst;

    int callback_times=0;
	int ret = maat_table_callback_register(maat_inst, table_name,
							               NULL,
							               accept_tags_entry_cb, 
							               NULL,
							               &callback_times);
	ASSERT_GE(ret, 0);
	EXPECT_EQ(callback_times, 5);
}

void accept_tags_entry2_cb(const char *table_name, const char *table_line, enum maat_operation op, void *u_para)
{
	int *callback_times = (int *)u_para;
	(*callback_times)++;
}

TEST_F(Policy, PluginRuleTags2) {
    const char *table_name = "IR_INTERCEPT_IP";
    struct maat *maat_inst = Policy::_shared_maat_inst;

	int callback_times = 0;
	int ret = maat_table_callback_register(maat_inst, table_name,
							               NULL,
							               accept_tags_entry2_cb, 
							               NULL,
							               &callback_times);
	ASSERT_GE(ret, 0);
	EXPECT_EQ(callback_times, 2);
}

TEST_F(Policy, RuleRuleTags) {
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *should_hit = "string bbb should hit";
	const char *should_not_hit = "string aaa should not hit";
	const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
	struct maat *maat_inst = Policy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);


	int ret = maat_scan_string(maat_inst, table_name, attribute_name, should_not_hit, 
                               strlen(should_not_hit), results, ARRAY_SIZE,
						        &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	
    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_scan_string(maat_inst, table_name, attribute_name, should_hit, 
                           strlen(should_hit), results, ARRAY_SIZE,
						   &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(Policy, RuleEXData) {
    
    const char *url = "firewall should hit";
	const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    const char *plugin_table_name = "RULE_FIREWALL_PLUGIN";
    const char *conj_rule_table_name = "RULE_FIREWALL_CONJUNCTION";
	const char *expect_name = "I have a name";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = Policy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_inst, plugin_table_name,
                                                    rule_ex_param_new,
                                                    rule_ex_param_free,
                                                    rule_ex_param_dup,
                                                    0, &ex_data_counter);
    ASSERT_TRUE(ret == 0);
    EXPECT_EQ(ex_data_counter, 2);

    ret = maat_state_set_scan_rule_table(state, conj_rule_table_name);
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, url, strlen(url),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000198");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    void *ex_data = maat_plugin_table_get_ex_data(maat_inst, plugin_table_name, 
                                                 uuid_str, strlen(uuid_str));
    ASSERT_TRUE(ex_data!=NULL);
    struct rule_ex_param *param = (struct rule_ex_param *)ex_data;
	EXPECT_EQ(param->id, 7799);

	EXPECT_EQ(strcmp(param->name, expect_name), 0);

	maat_state_free(state);
    state = NULL;
}

TEST_F(Policy, SubObject) {
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = Policy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
	const char *scan_data = "ceshi6@mailhost.cn";
	
	uint32_t ip_addr;
	inet_pton(AF_INET,"10.0.6.201", &ip_addr);

    const char *attribute_name = "MAIL_ADDR";
    const char *table_name = "MAIL_ADDR";
	
	int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
						       results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	
    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    const char *ip_table_name = "IP_CONFIG";
    const char *ip_attribute_name = "IP_CONFIG";
	
	ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);	
	
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000153");
	
    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
}

TEST_F(Policy, EvaluationOrder) {
    const char *url = "cavemancircus.com/2019/12/27/pretty-girls-6/";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = Policy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";

    int ret = maat_scan_string(maat_inst, table_name, attribute_name, url, strlen(url),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 3);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000166");

    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000168");

    uuid_unparse(results[2], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000167");

    struct maat_hit_path hit_path[128];
    memset(hit_path, 0, sizeof(hit_path));
    size_t n_hit_path = maat_state_get_hit_paths(state, hit_path, 128);
    EXPECT_EQ(n_hit_path, 6);

    EXPECT_STREQ(hit_path[0].attribute_name, attribute_name);
    uuid_unparse(hit_path[0].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000157");
    uuid_unparse(hit_path[0].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000157");
    EXPECT_EQ(hit_path[0].condition_index, 0);
    uuid_unparse(hit_path[0].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000166");

    EXPECT_STREQ(hit_path[1].attribute_name, attribute_name);
    uuid_unparse(hit_path[1].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000155");
    EXPECT_EQ(uuid_is_null(hit_path[1].top_object_uuid), 1);
    EXPECT_EQ(hit_path[1].condition_index, -1);
    EXPECT_EQ(uuid_is_null(hit_path[1].rule_uuid), 1);


    EXPECT_STREQ(hit_path[2].attribute_name, attribute_name);
    uuid_unparse(hit_path[2].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000158");
    uuid_unparse(hit_path[2].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000158");
    EXPECT_EQ(hit_path[2].condition_index, 0);
    uuid_unparse(hit_path[2].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000168");
    

    EXPECT_STREQ(hit_path[3].attribute_name, attribute_name);
    uuid_unparse(hit_path[3].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000158");
    uuid_unparse(hit_path[3].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000158");
    EXPECT_EQ(hit_path[3].condition_index, 1);
    uuid_unparse(hit_path[3].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000168");


    EXPECT_STREQ(hit_path[4].attribute_name, attribute_name);
    uuid_unparse(hit_path[4].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000158");
    uuid_unparse(hit_path[4].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000158");
    EXPECT_EQ(hit_path[4].condition_index, 0);
    uuid_unparse(hit_path[4].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000167");


    EXPECT_STREQ(hit_path[5].attribute_name, attribute_name);
    uuid_unparse(hit_path[5].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000158");
    uuid_unparse(hit_path[5].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000158");
    EXPECT_EQ(hit_path[5].condition_index, 1);
    uuid_unparse(hit_path[5].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000167");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.23.23", &ip_addr);

    const char *ip_plus_table_name = "IP_PLUS_CONFIG";
    const char *ip_plus_attribute_name = "IP_PLUS_CONFIG";

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv4(maat_inst, ip_plus_table_name, ip_plus_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000165");

    ret = maat_scan_not_logic(maat_inst, ip_plus_table_name, ip_plus_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

TEST_F(Policy, NotConditionHitPath) {
    const char *url_table_name = "HTTP_URL";
    const char *url_attribute_name = "HTTP_URL";
    const char *ip_table_name = "IP_CONFIG";
    const char *ip_attribute_name = "ATTRIBUTE_IP_CONFIG";
    const char *url = "www.youtube.com";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = Policy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, url_table_name, url_attribute_name, url, strlen(url),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.101.101", &ip_addr);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000228");

    struct maat_hit_path hit_path[128];
    memset(hit_path, 0, sizeof(hit_path));
    size_t n_hit_path = maat_state_get_hit_paths(state, hit_path, 128);
    EXPECT_EQ(n_hit_path, 4);

    EXPECT_EQ(hit_path[0].Nth_scan, 1);
    EXPECT_STREQ(hit_path[0].attribute_name, url_attribute_name);
    EXPECT_EQ(hit_path[0].negate_option, 0);
    EXPECT_EQ(hit_path[0].condition_index, 0);
    uuid_unparse(hit_path[0].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000249");
    uuid_unparse(hit_path[0].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000249");
    uuid_unparse(hit_path[0].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000228");


    EXPECT_EQ(hit_path[1].Nth_scan, 2);
    EXPECT_STREQ(hit_path[1].attribute_name, ip_attribute_name);
    EXPECT_EQ(hit_path[1].negate_option, 1);
    EXPECT_EQ(hit_path[1].condition_index, -1);
    uuid_unparse(hit_path[1].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000100");
    uuid_unparse(hit_path[1].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000502");
    EXPECT_EQ(uuid_is_null(hit_path[1].rule_uuid), 1);

    EXPECT_EQ(hit_path[2].Nth_scan, 2);
    EXPECT_STREQ(hit_path[2].attribute_name, ip_attribute_name);
    EXPECT_EQ(hit_path[2].negate_option, 1);
    EXPECT_EQ(hit_path[2].condition_index, -1);
    uuid_unparse(hit_path[2].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000100");
    EXPECT_EQ(uuid_is_null(hit_path[2].top_object_uuid), 1);
    EXPECT_EQ(uuid_is_null(hit_path[2].rule_uuid), 1);


    EXPECT_EQ(hit_path[3].Nth_scan, 2);
    EXPECT_STREQ(hit_path[3].attribute_name, ip_attribute_name);
    EXPECT_EQ(hit_path[3].negate_option, 1);
    EXPECT_EQ(hit_path[3].condition_index, 1);
    uuid_unparse(hit_path[3].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000250");
    uuid_unparse(hit_path[3].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000250");
    uuid_unparse(hit_path[3].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000228");

    maat_state_free(state);
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
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "soq is using table conjunction function."
                            "http://www.3300av.com/novel/27122.txt";
    const char *conj_table_name = "HTTP_HOST";
    const char *attribute_name = "HTTP_URL";
    struct maat *maat_inst = TableInfo::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, conj_table_name, attribute_name, scan_data,
                               strlen(scan_data), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000134");

    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000133");

    ret = maat_scan_not_logic(maat_inst, conj_table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

class FileTest : public testing::Test
{
protected:
    static void SetUpTestCase() {
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
        maat_options_set_caller_thread_number(opts, g_thread_num);
        maat_options_set_instance_name(opts, "files");
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_rule_update_checking_interval_ms(opts, 500);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);

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
    }

    static struct maat *_shared_maat_inst;
    static struct log_handle *logger;
};
struct maat *FileTest::_shared_maat_inst;
struct log_handle *FileTest::logger;

TEST_F(FileTest, StreamFiles) {
    const char test_data_dir[64] = "./test_streamfiles";
    const char *keywords_table_name = "KEYWORDS_TABLE";
    const char *keywords_attribute_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_inst = FileTest::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    struct dirent **name_list;
    int n = my_scandir(test_data_dir, &name_list, NULL, 
                       (int (*)(const void*, const void*))alphasort);
    ASSERT_GT(n, 0);
    struct maat_stream *stream = maat_stream_new(maat_inst, keywords_table_name, keywords_attribute_name, state);
    ASSERT_FALSE(stream == NULL);

    struct stat file_info;
	size_t file_size = 0;
    char file_path[PATH_MAX] = {0};
    uuid_t results[ARRAY_SIZE];
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
    const char *url_attribute_name = "HTTP_URL";
    const char *url_table_name = "HTTP_URL";
    const char *keywords_attribute_name = "HTTP_RESPONSE_KEYWORDS";
    const char *keywords_table_name = "KEYWORDS_TABLE";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ObjectHierarchy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int ret = maat_scan_string(maat_inst, url_table_name, url_attribute_name, http_url, strlen(http_url),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_name, url_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, keywords_table_name, keywords_attribute_name, http_content, strlen(http_content),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000160");

    ret = maat_scan_not_logic(maat_inst, keywords_table_name, keywords_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    const char *should_not_hit = "2018-10-05 is a keywords of table "
                                 "KEYWORDS_TABLE. Should not hit.";
    ret = maat_scan_string(maat_inst, keywords_table_name, keywords_attribute_name, should_not_hit,
                           strlen(should_not_hit), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, keywords_table_name, keywords_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(ObjectHierarchy, OneObjectInTwoAttribute) {
    const char *http_resp_hdr_cookie = "sessionid=888888;BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; sugstore=1;";
    const char *req_attribute_name = "HTTP_REQUEST_HEADER";
    const char *res_attribute_name = "HTTP_RESPONSE_HEADER";
    const char *table_name = "HTTP_SIGNATURE";

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    int ret = 0;
    struct maat *maat_inst = ObjectHierarchy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    ret = maat_scan_string(maat_inst, table_name, req_attribute_name, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, req_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, res_attribute_name, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000163");

    ret = maat_scan_not_logic(maat_inst, table_name, res_attribute_name, results, ARRAY_SIZE,
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
    const char *src_asn_attribute_name = "SOURCE_IP_ASN";
    const char *dst_asn_sttribute_name = "DESTINATION_IP_ASN";
    const char *table_name = "AS_NUMBER";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ObjectHierarchy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //--------------------------------------
	//			Source ASN1 & Dest ASN
	//--------------------------------------
    int ret = maat_scan_string(maat_inst, table_name, src_asn_attribute_name, src_asn1, strlen(src_asn1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, src_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, dst_asn_sttribute_name, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000178");

    ret = maat_scan_not_logic(maat_inst, table_name, dst_asn_sttribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //--------------------------------------
	//			Source ASN2 & Dest ASN
	//--------------------------------------
    ret = maat_scan_string(maat_inst, table_name, src_asn_attribute_name, src_asn2, strlen(src_asn2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, src_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, dst_asn_sttribute_name, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000178");

    ret = maat_scan_not_logic(maat_inst, table_name, dst_asn_sttribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //--------------------------------------
	//			Source ASN3 & Dest ASN
	//--------------------------------------
    ret = maat_scan_string(maat_inst, table_name, src_asn_attribute_name, src_asn3, strlen(src_asn3),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, src_asn_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, dst_asn_sttribute_name, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000178");

    ret = maat_scan_not_logic(maat_inst, table_name, dst_asn_sttribute_name, results, ARRAY_SIZE,
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
    const char *ip_attribute_name = "IP_CONFIG";
    const char *src_asn_attribute_name = "SOURCE_IP_ASN";
    const char *src_asn_table_name = "AS_NUMBER";
    const char *ip_geo_attribute_name = "SOURCE_IP_GEO";
    const char *ip_geo_table_name = "GeoLocation";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = ObjectHierarchy::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //--------------------------------------
	//			Source ASN1 & IP
	//--------------------------------------

    int ret = maat_scan_string(maat_inst, src_asn_table_name, src_asn_attribute_name, src_asn1, strlen(src_asn1),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.40.88", &ip_addr);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000180");

    maat_state_reset(state);

    //--------------------------------------
	//			IP Geo & IP
	//--------------------------------------
    ret = maat_scan_string(maat_inst, ip_geo_table_name, ip_geo_attribute_name, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000180");

    maat_state_reset(state);

    //--------------------------------------
	//			(Source ASN2 | IP Geo) & IP
	//--------------------------------------
    ret = maat_scan_string(maat_inst, src_asn_table_name, src_asn_attribute_name, src_asn2, strlen(src_asn2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, ip_geo_table_name, ip_geo_attribute_name, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000180");

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
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *ip_table_name = "IP_CONFIG";
    const char *ip_attribute_name = "IP_CONFIG";
	const char *rule_table_name = "RULE_DEFAULT";
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    maat_reload_log_level(maat_inst, LOG_LEVEL_INFO);

    /* item table add line */
    const char *ip1 = "172.0.0.1";
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char object_uuid_str[UUID_STR_LEN] = {0};
    char item_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object_id);
    snprintf(item_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item_id);
    int ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item_uuid_str,
                            object_uuid_str, ip1, NULL, 0);
    EXPECT_EQ(ret, 1);

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);
    struct maat_cmd_and_condition and_condition;
    and_condition.negate_option = 0;
    and_condition.or_condition_num = 1;
    and_condition.or_conditions[0].attribute_name = ip_attribute_name;
    and_condition.or_conditions[0].object_num = 1;
    and_condition.or_conditions[0].object_uuids_str[0] = object_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);
   
    uint32_t sip;
    ret = inet_pton(AF_INET, ip1, &sip);
    EXPECT_EQ(ret, 1);

    int table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GE(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, sip, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, SetExpr) {
    const char *scan_data = "Hiredis is a minimalistic C client library"
                            " for the Redis database.\r\n";
	const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
	
	const char *keywords1 = "Hiredis";
	const char *keywords2 = "C Client";
    const char *rule_table_name = "RULE_DEFAULT";
	char keywords[512];

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    snprintf(keywords, sizeof(keywords), "%s&%s", keywords1, keywords2);
	long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 2);
    char rule_uuid_str1[UUID_STR_LEN] = {0};
    char rule_uuid_str2[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str1, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", (rule_id - 1));
    snprintf(rule_uuid_str2, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);

    struct maat_cmd_and_condition and_condition1, and_condition2;
    test_add_expr_command(maat_inst, table_name, attribute_name, rule_uuid_str1, 0, keywords, &and_condition1);
    test_add_expr_command(maat_inst, table_name, attribute_name, rule_uuid_str2, 0, keywords, &and_condition2);
    
    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str2);
    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str1);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, rule_uuid_str1, 
                                 &and_condition1, 1, NULL, 0);
    EXPECT_EQ(ret, 1);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, rule_uuid_str2, 
                                 &and_condition2, 1, NULL, 0);
    EXPECT_EQ(ret, 1);
    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    int timeout = 1;
    rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);
    struct maat_cmd_and_condition and_condition;
    test_add_expr_command(maat_inst, table_name, attribute_name, rule_uuid_str, timeout, keywords, &and_condition);
    sleep(timeout + 1);
    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, SetExpr8) {
    const char *scan_data8 = "string1, string2, string3, string4, string5, string6, string7, string8";
	const char *scan_data7 = "string1, string2, string3, string4, string5, string6, string7";
	
	const char *rule_table_name = "RULE_DEFAULT";
	const char *table_name = "KEYWORDS_TABLE";
    const char *attribute_name = "KEYWORDS_TABLE";
	
	const char *keywords8 = "string1&string2&string3&string4&string5&string6&string7&string8";
	const char *keywords7 = "string1&string2&string3&string4&string5&string6&string7";

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char item_uuid_str[UUID_STR_LEN] = {0};
    char object_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item_id);
    snprintf(object_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object_id);
    int ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_uuid_str,
                              object_uuid_str, keywords8, EXPR_TYPE_AND, 0);
    EXPECT_EQ(ret, 1);

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);
    struct maat_cmd_and_condition and_condition;
    and_condition.negate_option = 0;
    and_condition.or_condition_num = 1;
    and_condition.or_conditions[0].attribute_name = attribute_name;
    and_condition.or_conditions[0].object_num = 1;
    and_condition.or_conditions[0].object_uuids_str[0] = object_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data8, strlen(scan_data8),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_DEL, item_uuid_str,
                              object_uuid_str, keywords8, EXPR_TYPE_AND, 0);
    EXPECT_EQ(ret, 1);
    
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_uuid_str,
                              object_uuid_str, keywords7, EXPR_TYPE_AND, 0);
   
    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(&results, 0, sizeof(results));
    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data7, strlen(scan_data7),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, ObjectScan) {
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
	const char *rule_table_name = "RULE_DEFAULT";
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    /* rule table add line */
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char rule_uuid_str[UUID_STR_LEN] = {0};
    char object_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);
    snprintf(object_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object_id);
    struct maat_cmd_and_condition and_condition;
    and_condition.negate_option = 0;
    and_condition.or_condition_num = 1;
    and_condition.or_conditions[0].attribute_name = attribute_name;
    and_condition.or_conditions[0].object_num = 1;
    and_condition.or_conditions[0].object_uuids_str[0] = object_uuid_str;
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    struct maat_hit_object hit_object;
    uuid_parse(object_uuid_str, hit_object.object_uuid);
    strncpy(hit_object.attribute_name, attribute_name, sizeof(hit_object.attribute_name));
    ret = maat_scan_object(maat_inst, table_name, attribute_name, &hit_object, 1, results, ARRAY_SIZE,
                          &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str);

    maat_state_free(state);
    state = NULL;
}

/** 
 *  Filter such as URL: http://filtermenot.com  => {attribute_id, object_id}
    One rule reference this filter twice, the rule should be hit. 
 */
TEST_F(MaatCmd, SameFilterRefByOneRule) {
    const char *attribute_name = "HTTP_URL_FILTER";
    const char *table_name = "HTTP_URL";
    const char *scan_data = "http://filtermenot.com";
    const char *keywords = "menot.com";
    const char *rule_table_name = "RULE_DEFAULT";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);


    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char object_uuid_str[UUID_STR_LEN] = {0};
    char item_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object_id);
    snprintf(item_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item_id);
    int ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_uuid_str, object_uuid_str,
                              keywords, EXPR_TYPE_AND, 0);
    EXPECT_EQ(ret, 1);

    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);
    struct maat_cmd_and_condition and_condition[2];
    and_condition[0].negate_option = 0;
    and_condition[0].or_condition_num = 1;
    and_condition[0].or_conditions[0].attribute_name = attribute_name;
    and_condition[0].or_conditions[0].object_num = 1;
    and_condition[0].or_conditions[0].object_uuids_str[0] = object_uuid_str;
    //condition1 & condition2 has same filter => {attribute_name, object_uuid}
    and_condition[1].negate_option = 0;
    and_condition[1].or_condition_num = 1;
    and_condition[1].or_conditions[0].attribute_name = attribute_name;
    and_condition[1].or_conditions[0].object_num = 1;
    and_condition[1].or_conditions[0].object_uuids_str[0] = object_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule_uuid_str, and_condition, 2, NULL, 0); // rule has two condition
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, RuleIDRecycle) {
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
	const char *scan_data = "Reuse rule ID is allowed.";
	const char *keywords = "Reuse&rule";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);
    struct maat_cmd_and_condition and_condition;
    test_add_expr_command(maat_inst, table_name, attribute_name, rule_uuid_str, 0, keywords, &and_condition);
    sleep(WAIT_FOR_EFFECTIVE_S);

    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data,
                               strlen(scan_data), results, ARRAY_SIZE,
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    rule_table_set_line(maat_inst, "RULE_DEFAULT", MAAT_OP_DEL, rule_uuid_str, &and_condition, 1, NULL, 0);
    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    test_add_expr_command(maat_inst, table_name, attribute_name, rule_uuid_str, 0, keywords, &and_condition);
    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(results, 0, sizeof(results));
    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, ReturnRuleIDWithDescendingOrder) {
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
	const char *scan_data = "This string will hit mulptiple rules.";
	const char *keywords = "string will hit";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int i = 0;
    int repeat_times = 4;
    long long expect_rule_id[ARRAY_SIZE] = {0};
    char rule_uuid_str_array[ARRAY_SIZE][UUID_STR_LEN];
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", repeat_times);

    for (i = 0; i < repeat_times; i++) {
        //add in ascending order
        struct maat_cmd_and_condition and_condition;
        expect_rule_id[i] = rule_id + 1 - repeat_times + i;
        snprintf(rule_uuid_str_array[i], UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", expect_rule_id[i]);
        test_add_expr_command(maat_inst, table_name, attribute_name, rule_uuid_str_array[i], 0, keywords, &and_condition);
    }

    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, repeat_times);
    for (i = 0; i < repeat_times; i++) {
        char uuid_str[UUID_STR_LEN] = {0};
        uuid_unparse(results[i], uuid_str);
        EXPECT_STREQ(uuid_str, rule_uuid_str_array[repeat_times - i - 1]);
    }

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
}

TEST_F(MaatCmd, SubObject) {
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    const char *rule_table_name = "RULE_DEFAULT";
	const char *object_group_table_name = "OBJECT_GROUP";
	const char *scan_data1 = "www.v2ex.com/t/573028#程序员的核心竞争力是什么";
	const char *keyword1 = "程序员&核心竞争力";
	const char *scan_data2 = "https://ask.leju.com/bj/detail/12189672562229248/?bi=tg&type=sina-pc"
                             "&pos=index-dbtlwzl&wt_campaign=M_5CE750003F393&wt_source=PDPS_514ACACFD9E770";
	const char *keyword2 = "ask.leju.com/b&/detail/12189672562229248/?&?bi=tg\\&type=sina-pc\\&&\\&pos="
                           "index-dbtlwzl\\&&\\&type=sina-pc\\&pos=index-dbtlwzl\\&";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //object2 -> object1 -> rule1
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN];
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);
    ret = object_group_table_set_line(maat_inst, object_group_table_name, MAAT_OP_ADD,
                                     object1_uuid_str, &object2_uuid_str, 1, NULL, 0, 0);
    EXPECT_EQ(ret, 1);

    /* item1 -> object2 -> object1 -> rule1
                             \
                              \ _  rule2
    */
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item_id);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_uuid_str,
                              object2_uuid_str, keyword1, EXPR_TYPE_AND, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    
    /* rule table add line */
    //rule1
    //object1 -> rule1
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_condition;
    and_condition.negate_option = 0;
    and_condition.or_condition_num = 1;
    and_condition.or_conditions[0].attribute_name = attribute_name;
    and_condition.or_conditions[0].object_num = 1;
    and_condition.or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                     rule1_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    //rule2
    //object1 -> rule2
    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule2_id);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                 rule2_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data1, strlen(scan_data1),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);
    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /* item1 -> object2 -> object1 -> rule1
                          \
                           \_ X -> rule2
    */
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, 
                                 rule2_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);
    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data1, strlen(scan_data1),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /* item1 -> object2 -> object1 -> X 
                  \
                   \_ -> rule2
    */
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, 
                                 rule1_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    and_condition.or_conditions[0].object_uuids_str[0] = object2_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                 rule2_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);
    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data1, strlen(scan_data1),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /*  item1 -> object2 -> object1 -> X 
                  \
                   \_ -> rule2
        item2 -> object3 -> object1
    */
    long long object3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object3_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object3_id);
    ret = object_group_table_set_line(maat_inst, object_group_table_name, MAAT_OP_ADD,
                                     object1_uuid_str, &object3_uuid_str, 1, NULL, 0, 0);
    EXPECT_EQ(ret, 1);

    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item2_uuid_str,
                              object3_uuid_str, keyword2, EXPR_TYPE_AND, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    sleep(2);
    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data2, strlen(scan_data2),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    /*  item1 -> object2 -> object1 -> X
                  \
                   \_ -> rule2
        item2 -> object3 -> object1
    */
    and_condition.or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule1_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule1_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);
    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data1, strlen(scan_data1),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, RefObject) {
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    const char* rule_table_name = "RULE_DEFAULT";
	const char* scan_data1 = "m.facebook.com/help/2297503110373101?helpref=hc_nav&refid=69";
	const char* keyword1 = "something-should-not-hit";
	const char* keyword2 = "facebook.com/help/2297503110373101";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //object1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    int ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item1_uuid_str,
                              object1_uuid_str, keyword1, EXPR_TYPE_AND, 0); /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_condition;
    and_condition.negate_option = 0;
    and_condition.or_condition_num = 1;
    and_condition.or_conditions[0].attribute_name = attribute_name;
    and_condition.or_conditions[0].object_num = 1;
    and_condition.or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                     rule1_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    /* item1 -> object1 -> X                   
        item2 -> object2 -> rule1
    */
    rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, rule1_uuid_str, &and_condition, 1, NULL, 0);

    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);
    and_condition.or_conditions[0].object_uuids_str[0] = object2_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                     rule1_uuid_str, &and_condition, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item2_uuid_str,
                              object2_uuid_str, keyword2, EXPR_TYPE_AND, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data1, strlen(scan_data1),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, Attribute) {
    const char* rule_table_name = "RULE_DEFAULT";
	const char* table_name="HTTP_SIGNATURE";
    const char *attribute_req_name = "HTTP_REQUEST_HEADER";
    const char *attribute_resp_name = "HTTP_RESPONSE_HEADER";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //item1 -> object1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item1_uuid_str,
                              object1_uuid_str, "AppleWebKit", EXPR_TYPE_AND, 0);/*EXPR_TYPE_STRING MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);

    /* item1 -> object1 -> rule1
                              /
              item2 -> object2/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item2_uuid_str,
                              object2_uuid_str, "uid=12345678;", EXPR_TYPE_AND, 0);/*EXPR_TYPE_STRING MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[2];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = attribute_req_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = attribute_resp_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object2_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                     rule1_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

	const char* http_req_hdr_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                  "(KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36";
	const char* http_resp_hdr_cookie = "uid=12345678;BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; sugstore=1;";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;

    ret = maat_scan_string(maat_inst, table_name, attribute_req_name, http_req_hdr_ua,
                           strlen(http_req_hdr_ua), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_req_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_string(maat_inst, table_name, attribute_resp_name, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_resp_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    //delete object1
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL, 
                                     rule1_uuid_str, and_conditions, 2, NULL, 0);
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = attribute_resp_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object2_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD, 
                                     rule1_uuid_str, and_conditions, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_name, attribute_resp_name, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_resp_name, results, ARRAY_SIZE,
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
        "{\"uuid\":\"00000000-0000-0000-0000-000000000001\", \"ip\":\"192.168.0.1\", \"entry_id\":100, \"is_valid\":1}",
        "{\"uuid\":\"00000000-0000-0000-0000-000000000002\", \"ip\":\"192.168.0.1\", \"entry_id\":101, \"is_valid\":1}",
        "{\"uuid\":\"00000000-0000-0000-0000-000000000003\", \"ip\":\"192.168.0.1\", \"entry_id\":102, \"is_valid\":1}",
        "{\"uuid\":\"00000000-0000-0000-0000-000000000004\", \"ip\":\"192.168.0.1\", \"entry_id\":103, \"is_valid\":1}",
        };
    const char *table_line_del[TEST_CMD_LINE_NUM] = {
        "{\"uuid\":\"00000000-0000-0000-0000-000000000001\", \"ip\":\"192.168.0.1\", \"entry_id\":100, \"is_valid\":1}",
        "{\"uuid\":\"00000000-0000-0000-0000-000000000002\", \"ip\":\"192.168.0.1\", \"entry_id\":101, \"is_valid\":1}",
        "{\"uuid\":\"00000000-0000-0000-0000-000000000003\", \"ip\":\"192.168.0.1\", \"entry_id\":102, \"is_valid\":1}",
        "{\"uuid\":\"00000000-0000-0000-0000-000000000004\", \"ip\":\"192.168.0.1\", \"entry_id\":103, \"is_valid\":1}",
        };
    int ret = 0;

    char rule_uuid_strs[TEST_CMD_LINE_NUM][UUID_STR_LEN];
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        expect_rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
        snprintf(rule_uuid_strs[i], UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", expect_rule_id[i]);
        line_rule.rule_uuid_str = rule_uuid_strs[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_add[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_ADD);
        EXPECT_GT(ret, 0);
    }

    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_uuid_str = rule_uuid_strs[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_del[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_DEL);
        EXPECT_GT(ret, 0);
    }
}

int g_test_update_paused = 0;
void pause_update_test_entry_cb(const char *table_name, const char* table_line, enum maat_operation op, void* u_para)
{
	EXPECT_EQ(g_test_update_paused, 0);
}

TEST_F(MaatCmd, PauseUpdate) {
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    const char *table_name = "QD_ENTRY_INFO";

    int ret = maat_table_callback_register(maat_inst, table_name, NULL,
                                           pause_update_test_entry_cb,
                                           NULL, NULL);
    g_test_update_paused = 1;

    char *line = NULL;
    struct maat_cmd_line line_rule;
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
    char rule_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);
    line_rule.rule_uuid_str = rule_uuid_str;
    line_rule.table_name = table_name;
    asprintf(&line, "{\"uuid\":\"00000000-0000-0000-0000-000000000001\", \"ip\":\"192.168.0.1\", \"entry_id\":101, \"is_valid\":1}");
    line_rule.table_line = line;
    line_rule.expire_after = 0;

    ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_ADD);
    EXPECT_EQ(ret, 1);
    free(line);
    
    g_test_update_paused = 0;
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
void foreign_key_test_entry_cb(const char *table_name, const char *table_line, enum maat_operation op, void *u_para)
{
	char file1_origin_name[256], file2_origin_name[256];
	char file1_localname[256], file2_localname[256];

	memset(file1_localname, 0, sizeof(file1_localname));
	memset(file2_localname, 0, sizeof(file2_localname));
	
	cJSON *json = cJSON_Parse(table_line);
    EXPECT_TRUE(json != NULL);

    cJSON *tmp_obj = cJSON_GetObjectItem(json, "file1_name");
    EXPECT_TRUE(tmp_obj != NULL);
    snprintf(file1_origin_name, sizeof(file1_origin_name), "%s", tmp_obj->valuestring);

    tmp_obj = cJSON_GetObjectItem(json, "file1_key");
    EXPECT_TRUE(tmp_obj != NULL);
    snprintf(file1_localname, sizeof(file1_localname), "%s", tmp_obj->valuestring);

    tmp_obj = cJSON_GetObjectItem(json, "file2_name");
    EXPECT_TRUE(tmp_obj != NULL);
    snprintf(file2_origin_name, sizeof(file2_origin_name), "%s", tmp_obj->valuestring);

    tmp_obj = cJSON_GetObjectItem(json, "file2_key");
    EXPECT_TRUE(tmp_obj != NULL);
    snprintf(file2_localname, sizeof(file2_localname), "%s", tmp_obj->valuestring);

	if (op == MAAT_OP_ADD) {		
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

    cJSON_Delete(json);
}

TEST_F(MaatCmd, SetFile) {
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    const char* table_name = "TEST_FOREIGN_KEY";

    int ret = maat_table_callback_register(maat_inst, table_name, NULL,
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
    long long rule_id = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
    char rule_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);
    line_rule.rule_uuid_str = rule_uuid_str;
    line_rule.table_name = table_name;
    snprintf(line, sizeof(line),"{\"uuid\":\"%s\",\
                                \"tag\":%d,\
                                \"file1_name\":\"%s\",\
                                \"file1_key\":\"redis://%s\",\
                                \"file2_name\":\"%s\",\
                                \"file2_key\":\"redis://%s\"}",
             line_rule.rule_uuid_str, tag, file1_name, file1_key, file2_name, file2_key);
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

    ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_DEL);
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
    rule_id = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
    snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id);
    line_rule.rule_uuid_str = rule_uuid_str;
    line_rule.table_name=table_name;
    snprintf(line, sizeof(line),"{\"uuid\":\"%s\",\
                                \"tag\":%d,\
                                \"file1_name\":\"%s\",\
                                \"file1_key\":\"redis://%s\",\
                                \"file2_name\":\"%s\",\
                                \"file2_key\":\"%s\"}",
             line_rule.rule_uuid_str, tag, file1_name, file1_key, empty_file_name, "null");
	line_rule.table_line = line;
	line_rule.expire_after = 0;

    g_test_foregin_read_OK = 0;

    ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_ADD);
    EXPECT_EQ(ret, 1);
	sleep(WAIT_FOR_EFFECTIVE_S);//wait for callback triggered.
	EXPECT_EQ(g_test_foregin_read_OK, 1);
}

TEST_F(MaatCmd, RuleEXData) {
    const char *plugin_table_name = "RULE_FIREWALL_PLUGIN";
    const char *rule_table_name = "RULE_FIREWALL_DEFAULT";
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    int *ex_data_counter = MaatCmd::_ex_data_counter;

    long long object_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_condition;
    and_condition.negate_option = 0;
    and_condition.or_condition_num = 1;
    and_condition.or_conditions[0].attribute_name = "HTTP_URL";
    and_condition.or_conditions[0].object_num = 1;
    and_condition.or_conditions[0].object_uuids_str[0] = object_uuid_str;
    int ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, &and_condition, 1, "test:rule1,1111", 0);
    EXPECT_EQ(ret, 1);

    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule2_id);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule2_uuid_str, &and_condition, 1, "test:rule2,2222", 0);
    sleep(WAIT_FOR_EFFECTIVE_S);

    *ex_data_counter = 0;
    ret = maat_plugin_table_ex_schema_register(maat_inst, plugin_table_name,
                                               rule_ex_param_new,
                                               rule_ex_param_free,
                                               rule_ex_param_dup,
                                               0, ex_data_counter);
    ASSERT_TRUE(ret == 0);
    EXPECT_EQ(*ex_data_counter, 2);

    void *ex_data = maat_plugin_table_get_ex_data(maat_inst, plugin_table_name,
                                                 (char *)rule1_uuid_str,
                                                 strlen(rule1_uuid_str));
    ASSERT_TRUE(ex_data != NULL);
    struct rule_ex_param *param = (struct rule_ex_param *)ex_data;
	EXPECT_EQ(param->id, 1111);

    ex_data = maat_plugin_table_get_ex_data(maat_inst, plugin_table_name,
                                            (char *)rule2_uuid_str,
                                            strlen(rule2_uuid_str));
    ASSERT_TRUE(ex_data != NULL);
    param = (struct rule_ex_param *)ex_data;
	EXPECT_EQ(param->id, 2222);

    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule2_uuid_str, &and_condition, 1, "test:rule2,2222", 0);
    sleep(WAIT_FOR_EFFECTIVE_S);
    EXPECT_EQ(param->id, 2222); 
    sleep(2);
    //excced gc_timeout_s(3s), the data pointed by param has been freed
}

struct user_info {
	char name[256];
	char ip_addr[32];
	int id;
};
void plugin_ex_new_cb(const char *table_name, const char *key, 
                      const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	struct user_info *u = ALLOC(struct user_info, 1);

    cJSON *json = cJSON_Parse(table_line);
    EXPECT_TRUE(json != NULL);

    cJSON *tmp_obj = cJSON_GetObjectItem(json, "id");
    EXPECT_TRUE(tmp_obj != NULL);
    u->id = tmp_obj->valueint;

    tmp_obj = cJSON_GetObjectItem(json, "key");
    EXPECT_TRUE(tmp_obj != NULL);
    snprintf(u->ip_addr, sizeof(u->ip_addr), "%s", tmp_obj->valuestring);

    tmp_obj = cJSON_GetObjectItem(json, "name");
    EXPECT_TRUE(tmp_obj != NULL);
    snprintf(u->name, sizeof(u->name), "%s", tmp_obj->valuestring);

    cJSON_Delete(json);

	*ad = u;
	(*counter)++;
}

void plugin_ex_free_cb(const char *table_name, void **ad, long argl, void *argp)
{
	struct user_info *u = (struct user_info *)(*ad);

    memset(u, 0, sizeof(struct user_info));
	free(u);
	*ad = NULL;
}

void plugin_ex_dup_cb(const char *table_name,	void **to, void **from, long argl, void *argp)
{
	struct user_info *u = (struct user_info *)(*from);

	*to = u;
}

TEST_F(MaatCmd, PluginEXData) {
    const char *table_name = "TEST_PLUGIN_EXDATA_TABLE";
    const int TEST_CMD_LINE_NUM = 4;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    int *ex_data_counter = MaatCmd::_ex_data_counter;
	const char *table_line[TEST_CMD_LINE_NUM] = {
        "{\"id\":1, \"key\":\"192.168.0.1\", \"name\":\"mahuateng\"}",
		"{\"id\":2, \"key\":\"192.168.0.2\", \"name\":\"liuqiangdong\"}",
		"{\"id\":3, \"key\":\"192.168.0.3\", \"name\":\"mayun\"}",
		"{\"id\":4, \"key\":\"192.168.0.4\", \"name\":\"liyanhong\"}",
    };
    
    int i = 0, ret = 0;
    struct maat_cmd_line line_rule;
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    char rule_uuid_strs[TEST_CMD_LINE_NUM][UUID_STR_LEN];
    /* 1st line */
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
        snprintf(rule_uuid_strs[i], UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id[i]);
        line_rule.rule_uuid_str = rule_uuid_strs[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line[i];
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

	uinfo1 = (struct user_info *)maat_plugin_table_get_ex_data(maat_inst, table_name,
                                                               key1, strlen(key1));
	ASSERT_TRUE(uinfo1 != NULL);
	EXPECT_EQ(0, strcmp(uinfo1->name, "liuqiangdong"));
	EXPECT_EQ(uinfo1->id, 2);
    
    //DEL
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_uuid_str = rule_uuid_strs[1];
    line_rule.table_name = table_name;
    line_rule.table_line = table_line[1];
    line_rule.expire_after = 0;

	ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_DEL);
	EXPECT_GT(ret, 0);

	sleep(WAIT_FOR_EFFECTIVE_S); //gc_timeout_s == 3 which configured in table_info

    struct user_info *uinfo2 = NULL;
	uinfo2 = (struct user_info *)maat_plugin_table_get_ex_data(maat_inst, table_name,
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
	const char *table_line[TEST_CMD_LINE_NUM] = {
        "{\"uuid\":\"00000000-0000-0000-0000-000000000101\", \"ip\":\"192.168.30.98/31\", \"buffer\":\"Something-like-json\", \"is_valid\":1}",
		"{\"uuid\":\"00000000-0000-0000-0000-000000000102\", \"ip\":\"192.168.30.90-192.168.30.128\", \"buffer\":\"Bigger-range-should-in-the-back\", \"is_valid\":1}",
        "{\"uuid\":\"00000000-0000-0000-0000-000000000103\", \"ip\":\"2001:db8:1234::-2001:db8:1235::\", \"buffer\":\"Bigger-range-should-in-the-back\", \"is_valid\":1}",
		"{\"uuid\":\"00000000-0000-0000-0000-000000000104\", \"ip\":\"2001:db8:1234::1-2001:db8:1234::5210\", \"buffer\":\"Something-like-json\", \"is_valid\":1}"
        };
    
    int i = 0, ret = 0;
    struct maat_cmd_line line_rule;
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    char rule_uuid_strs[TEST_CMD_LINE_NUM][UUID_STR_LEN];
    //add lines
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
        snprintf(rule_uuid_strs[i], UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id[i]);
        line_rule.rule_uuid_str = rule_uuid_strs[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line[i];
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
    ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_name, &ipv4,
                                           (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000101");
    uuid_unparse(results[1]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000102");

    ipv6.ip_type = 6;
    inet_pton(AF_INET6, "2001:db8:1234::5210", &(ipv6.ipv6));

    memset(results, 0, sizeof(results));
    ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_name, &ipv6,
                                           (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    uuid_unparse(results[0]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000104");
    uuid_unparse(results[1]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000103");

    //del lines
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_uuid_str = rule_uuid_strs[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_DEL);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S); //gc_timeout_s == 3 which configured in table_info

    ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_name, &ipv4,
                                          (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 0);

    //the data pointed by results[idx] has in garbage queue, but not be freed yet
    uuid_unparse(results[0]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000104");
    uuid_unparse(results[1]->rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000103");

    sleep(WAIT_FOR_EFFECTIVE_S * 2);
    //exceed gc_timeout_s, the data pointed by results[idx] has been freed
}

TEST_F(MaatCmd, UpdateFQDNPlugin) {
    const char *table_name = "TEST_FQDN_PLUGIN_WITH_EXDATA";
	const int TEST_CMD_LINE_NUM = 5;
	struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    int *ex_data_counter = MaatCmd::_ex_data_counter;
    const char *table_line[TEST_CMD_LINE_NUM]={
		"{\"uuid\":\"00000000-0000-0000-0000-000000000201\", \"fqdn\":\"www.example1.com\", \"buffer\":\"catid=1\", \"is_valid\":1}",
		"{\"uuid\":\"00000000-0000-0000-0000-000000000202\", \"fqdn\":\"*.example1.com\", \"buffer\":\"catid=1\", \"is_valid\":1}",
		"{\"uuid\":\"00000000-0000-0000-0000-000000000203\", \"fqdn\":\"news.example1.com\", \"buffer\":\"catid=2\", \"is_valid\":1}",
		"{\"uuid\":\"00000000-0000-0000-0000-000000000204\", \"fqdn\":\"r3---sn-i3belne6.example2.com\", \"buffer\":\"catid=3\", \"is_valid\":1}",
		"{\"uuid\":\"00000000-0000-0000-0000-000000000205\", \"fqdn\":\"r3---sn-i3belne6.example2.com\", \"buffer\":\"catid=3\", \"is_valid\":1}"
        };
    
    int i = 0, ret = 0;
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    char rule_uuid_strs[TEST_CMD_LINE_NUM][UUID_STR_LEN];
    struct maat_cmd_line line_rule;
    //add lines
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
        snprintf(rule_uuid_strs[i], UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id[i]);
        line_rule.rule_uuid_str = rule_uuid_strs[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line[i];
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

    ret = maat_fqdn_plugin_table_get_ex_data(maat_inst, table_name,
                                             "r3---sn-i3belne6.example2.com", 
                                             (void**)results, ARRAY_SIZE);
    ASSERT_EQ(ret, 2);
    EXPECT_EQ(results[0]->catid, 3);

    //del lines
    for (i = 3; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_uuid_str = rule_uuid_strs[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_DEL);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S);
    ret = maat_fqdn_plugin_table_get_ex_data(maat_inst, table_name, 
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
    const char *table_line[TEST_CMD_LINE_NUM] = {
		"{\"uuid\":\"00000000-0000-0000-0000-000000000301\", \"bool_expr\":\"1&2&1000\", \"buffer\":\"tunnel1\", \"is_valid\":1}",
		"{\"uuid\":\"00000000-0000-0000-0000-000000000302\", \"bool_expr\":\"101&102\", \"buffer\":\"tunnel2\", \"is_valid\":1}",
		"{\"uuid\":\"00000000-0000-0000-0000-000000000303\", \"bool_expr\":\"102\", \"buffer\":\"tunnel3\", \"is_valid\":1}",
		"{\"uuid\":\"00000000-0000-0000-0000-000000000304\", \"bool_expr\":\"101\", \"buffer\":\"tunnel4\", \"is_valid\":1}",
		"{\"uuid\":\"00000000-0000-0000-0000-000000000305\", \"bool_expr\":\"0&1&2&3&4&5&6&7\", \"buffer\":\"tunnel5\", \"is_valid\":1}",
		"{\"uuid\":\"00000000-0000-0000-0000-000000000306\", \"bool_expr\":\"101&101\", \"buffer\":\"invalid\", \"is_valid\":1}"
        };
    
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    char rule_uuid_strs[TEST_CMD_LINE_NUM][UUID_STR_LEN];
    struct maat_cmd_line line_rule;
    int i = 0, ret = 0;

    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
        snprintf(rule_uuid_strs[i], UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id[i]);
        line_rule.rule_uuid_str = rule_uuid_strs[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line[i];
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
    ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_name, items, 3,
                                             (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 4);
    EXPECT_EQ(results[0]->name_len, 7);

    for (i = 3; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_uuid_str = rule_uuid_strs[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_inst, &line_rule, MAAT_OP_DEL);
        EXPECT_GT(ret, 0);
    }
    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_name, items, 3,
                                             (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(results[0]->name_len, 7);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);
    //exceed gc_timeout_s, the data pointed by results[idx] has been freed
}

#define RULE_ID_NUMS 1000
TEST_F(MaatCmd, ObjectInMassRules) {
	const char* rule_table_name = "RULE_DEFAULT";
	const char* url_table_name = "HTTP_URL";
    const char* url_attribute_anme = "HTTP_URL";
	const char* appid_table_name = "APP_ID";
    const char* appid_attribute_name = "APP_ID";
    int thread_id = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //item_url1 -> object1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    int ret = expr_table_set_line(maat_inst, url_table_name, MAAT_OP_ADD, item1_uuid_str,
                                  object1_uuid_str, "baidu.com&tsg", EXPR_TYPE_AND, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    //item_url2 -> object2
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = expr_table_set_line(maat_inst, url_table_name, MAAT_OP_ADD, item2_uuid_str,
                              object2_uuid_str, "baidu.com&zhengzhou", EXPR_TYPE_AND, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    //item_appid -> object3
    long long object3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    long long item3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char object3_uuid_str[UUID_STR_LEN] = {0};
    char item3_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object3_id);
    snprintf(item3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item3_id);
    ret = interval_table_set_line(maat_inst, appid_table_name, MAAT_OP_ADD, item3_uuid_str,
                                  object3_uuid_str, "100", 0);
    EXPECT_EQ(ret, 1);

    /*  item_url1 -> object1 -> rule[0 ~ RULE_ID_NUMS] 
                                /
          item_appid -> object3_/
    */
    int i = 0;
    long long rule_id[RULE_ID_NUMS] = {0};
    struct maat_cmd_and_condition and_conditions[2];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = url_attribute_anme;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = appid_attribute_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object3_uuid_str;
    for (i = 0; i < RULE_ID_NUMS; i++) {
        char rule_uuid_str[UUID_STR_LEN] = {0};
        rule_id[i] = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
        snprintf(rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule_id[i]);
        ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule_uuid_str, and_conditions, 2, "mass_rule", 0);
        EXPECT_EQ(ret, 1);
    }

    /* item_url2 -> object2 -> target_rule
                                    /
              item_appid -> object3_/
    */
    long long target_rule_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char target_rule_uuid_str[UUID_STR_LEN] = {0};
    snprintf(target_rule_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", target_rule_id);
    struct maat_cmd_and_condition target_and_conditions[2];
    target_and_conditions[0].negate_option = 0;
    target_and_conditions[0].or_condition_num = 1;
    target_and_conditions[0].or_conditions[0].attribute_name = url_attribute_anme;
    target_and_conditions[0].or_conditions[0].object_num = 1;
    target_and_conditions[0].or_conditions[0].object_uuids_str[0] = object2_uuid_str;
    target_and_conditions[1].negate_option = 0;
    target_and_conditions[1].or_condition_num = 1;
    target_and_conditions[1].or_conditions[0].attribute_name = appid_attribute_name;
    target_and_conditions[1].or_conditions[0].object_num = 1;
    target_and_conditions[1].or_conditions[0].object_uuids_str[0] = object3_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 target_rule_uuid_str, target_and_conditions, 2, "null", 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url1 = "https://www.baidu.com/s?wd=tsg";
	const char* http_url2 = "https://www.baidu.com/s?wd=zhengzhou&rsv_spt=1"
                             "&rsv_iqid=0x8b4cae8100000560&issp=1&f=8&rsv_bp=1";

    uuid_t results[4];
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, url_table_name, url_attribute_anme, http_url2, strlen(http_url2),
                           results, 4, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_name, url_attribute_anme, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_integer(maat_inst, appid_table_name, appid_attribute_name, 100, results, 4,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, target_rule_uuid_str);

    ret = maat_scan_not_logic(maat_inst, appid_table_name, appid_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_reset(state);

    ret = maat_scan_string(maat_inst, url_table_name, url_attribute_anme, http_url1, strlen(http_url1),
                           results, 4, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, url_table_name, url_attribute_anme, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_integer(maat_inst, appid_table_name, appid_attribute_name, 100, results, 4,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 4);

    ret = maat_scan_not_logic(maat_inst, appid_table_name, appid_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, HitObject) {
   const char *rule_table_name = "RULE_DEFAULT";
    const char *object_group_table_name = "OBJECT_GROUP";
	const char *http_sig_table_name = "HTTP_SIGNATURE";
    const char *http_req_attr_name = "HTTP_REQUEST_HEADER";
    const char *http_resp_attr_name = "HTTP_RESPONSE_HEADER";
	const char *ip_table_name = "IP_CONFIG";
    const char *ip_attribute_name = "IP_CONFIG";
	const char *keywords_table_name = "KEYWORDS_TABLE";
    const char *keywords_attr_name = "KEYWORDS";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //object1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //item1 -> object1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item1_uuid_str, object1_uuid_str, "hit object item first",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    //object21
    long long object21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object21_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object21_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object21_id);

    /* item1 -> object1 -> rule1
                             /
                    object21_/
    */

    /* rule1 */
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[2];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = http_req_attr_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = http_resp_attr_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object21_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                            /
        object2 -> object21 _/
    */
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);
    ret = object_group_table_set_line(maat_inst, object_group_table_name, MAAT_OP_ADD,
                                     object21_uuid_str, &object2_uuid_str, 1, NULL, 0, 0);
    EXPECT_EQ(ret, 1);

    /*       item1 -> object1 -> rule1
                                    /
       item2 -> object2 -> object21 _/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item2_uuid_str, object2_uuid_str, "hit object item second",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /*
            item1 -> object1 -> object11
                        \
                          \ -> rule1
                                  /
     item2 -> object2 -> object21 _/             
    */
    long long object11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object11_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object11_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object11_id);
    ret = object_group_table_set_line(maat_inst, object_group_table_name, MAAT_OP_ADD,
                                     object11_uuid_str, &object1_uuid_str, 1, NULL, 0, 0);
    EXPECT_EQ(ret, 1);
    
    //item3 -> object3, object3 is not referenced by any rule.
    long long item3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object3_uuid_str[UUID_STR_LEN] = {0};
    char item3_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object3_id);
    snprintf(item3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item3_id);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item3_uuid_str,
                            object3_uuid_str, "220.181.38.150-220.181.38.151", NULL, 0);
    EXPECT_EQ(ret, 1);

    //item4 -> object4, object4 is not referenced by any rule.
    long long item4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object4_uuid_str[UUID_STR_LEN] = {0};
    char item4_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object4_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object4_id);
    snprintf(item4_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item4_id);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item4_uuid_str, object4_uuid_str, "hit object item forth", EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
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
    char item5_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item5_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item5_id);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item5_uuid_str, object1_uuid_str,
                              "hit object item fifth",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url = "en.wikipedia.org hit object item first";
	const char* http_resp_hdr_cookie = "laptop=thinkpad X1 extrem;hit object item second"
                                       "main[XWJOKE]=hoho; Hm_lvt_bbac0322e6ee13093f98d5c4b5a10912=1578874808;";

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, http_sig_table_name, http_req_attr_name, http_url, strlen(http_url),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    size_t scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 1);

    struct maat_hit_object hit_objects[128];
    memset(hit_objects, 0, sizeof(hit_objects));

    size_t n_hit_object = maat_state_get_direct_hit_object_cnt(state);
    maat_state_get_direct_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(hit_objects[0].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item1_uuid_str);
    uuid_unparse(hit_objects[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
    EXPECT_STREQ(hit_objects[0].attribute_name, http_req_attr_name);

    memset(hit_objects, 0, sizeof(hit_objects));
    n_hit_object = maat_state_get_indirect_hit_object_cnt(state);
    maat_state_get_indirect_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 1);
    EXPECT_TRUE(uuid_is_null(hit_objects[0].item_uuid));
    uuid_unparse(hit_objects[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object11_uuid_str);
    EXPECT_STREQ(hit_objects[0].attribute_name, http_req_attr_name);

    size_t n_last_hit_object = maat_state_get_last_hit_object_cnt(state);
    struct maat_hit_object last_hit_objects[128];
    maat_state_get_last_hit_objects(state, last_hit_objects, 128);
    EXPECT_EQ(n_last_hit_object, 2);

    uuid_unparse(last_hit_objects[0].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item1_uuid_str);
    uuid_unparse(last_hit_objects[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
    EXPECT_STREQ(last_hit_objects[0].attribute_name, http_req_attr_name);

    EXPECT_TRUE(uuid_is_null(last_hit_objects[1].item_uuid));
    uuid_unparse(last_hit_objects[1].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object11_uuid_str);
    EXPECT_STREQ(last_hit_objects[1].attribute_name, http_req_attr_name);


    ret = maat_scan_string(maat_inst, http_sig_table_name, http_resp_attr_name, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 2);

    memset(hit_objects, 0, sizeof(hit_objects));
    n_hit_object = maat_state_get_direct_hit_object_cnt(state);
    maat_state_get_direct_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 1);

    uuid_unparse(hit_objects[0].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
    uuid_unparse(hit_objects[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
    EXPECT_STREQ(hit_objects[0].attribute_name, http_resp_attr_name);

    memset(hit_objects, 0, sizeof(hit_objects));
    n_hit_object = maat_state_get_indirect_hit_object_cnt(state);
    maat_state_get_indirect_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 1);
    EXPECT_TRUE(uuid_is_null(hit_objects[0].item_uuid));
    uuid_unparse(hit_objects[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object21_uuid_str);
    EXPECT_STREQ(hit_objects[0].attribute_name, http_resp_attr_name);
    
    n_last_hit_object = maat_state_get_last_hit_object_cnt(state);
    maat_state_get_last_hit_objects(state, last_hit_objects, 128);
    EXPECT_EQ(n_last_hit_object, 2);

    uuid_unparse(last_hit_objects[0].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
    uuid_unparse(last_hit_objects[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
    EXPECT_STREQ(last_hit_objects[0].attribute_name, http_resp_attr_name);

    EXPECT_TRUE(uuid_is_null(last_hit_objects[1].item_uuid));
    uuid_unparse(last_hit_objects[1].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object21_uuid_str);
    EXPECT_STREQ(last_hit_objects[1].attribute_name, http_resp_attr_name);

    const char* keywords1="In graph theory, hit object item forth";
    const char *keywords2="To test one object hit object item fifth";

    struct maat_stream *stream = maat_stream_new(maat_inst, keywords_table_name, keywords_attr_name, state);
    ret = maat_stream_scan(stream, keywords1, strlen(keywords1), results, ARRAY_SIZE,
                          &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 3);

    uint32_t ip_addr;
    inet_pton(AF_INET, "220.181.38.150", &ip_addr);
    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 4);

    memset(hit_objects, 0, sizeof(hit_objects));
    n_hit_object = maat_state_get_direct_hit_object_cnt(state);
    maat_state_get_direct_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 2);

    uuid_unparse(hit_objects[0].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item4_uuid_str);
    uuid_unparse(hit_objects[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object4_uuid_str);
    EXPECT_STREQ(hit_objects[0].attribute_name, keywords_attr_name);
 
    uuid_unparse(hit_objects[1].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item3_uuid_str);
    uuid_unparse(hit_objects[1].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object3_uuid_str);
    EXPECT_STREQ(hit_objects[1].attribute_name, ip_attribute_name);

    ret = maat_stream_scan(stream, keywords2, strlen(keywords2), results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 5);

    memset(hit_objects, 0, sizeof(hit_objects));
    n_hit_object = maat_state_get_direct_hit_object_cnt(state);
    maat_state_get_direct_hit_objects(state, hit_objects, n_hit_object);
    EXPECT_EQ(n_hit_object, 1);

    uuid_unparse(hit_objects[0].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item5_uuid_str);
    uuid_unparse(hit_objects[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
    EXPECT_STREQ(hit_objects[0].attribute_name, keywords_attr_name);

    n_last_hit_object = maat_state_get_last_hit_object_cnt(state);
    maat_state_get_last_hit_objects(state, last_hit_objects, 128);
    EXPECT_EQ(n_last_hit_object, 2);

    uuid_unparse(last_hit_objects[0].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item5_uuid_str);
    uuid_unparse(last_hit_objects[0].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
    EXPECT_STREQ(last_hit_objects[0].attribute_name, keywords_attr_name);

    EXPECT_TRUE(uuid_is_null(last_hit_objects[1].item_uuid));
    uuid_unparse(last_hit_objects[1].object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object11_uuid_str);
    EXPECT_STREQ(last_hit_objects[1].attribute_name, keywords_attr_name);

    maat_stream_free(stream);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, HitPathBasic) {
    const char *object_group_table_name = "OBJECT_GROUP";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *http_sig_table_name = "HTTP_SIGNATURE";
    const char *http_req_attr_name = "HTTP_REQUEST_HEADER";
    const char *http_resp_attr_name = "HTTP_RESPONSE_HEADER";
	const char *ip_table_name = "IP_CONFIG";
    const char *ip_attribute_name = "IP_CONFIG";
	const char *keywords_table_name = "KEYWORDS_TABLE";
    const char *keywords_attr_name = "KEYWORDS";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item1_uuid_str, object1_uuid_str, "graph_theory",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                             /
                    object21_/
    */
    long long object21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object21_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object21_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object21_id);

    /* rule1 */
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    struct maat_cmd_and_condition and_conditions[2];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = http_req_attr_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = http_resp_attr_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object21_uuid_str;
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                rule1_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                            /
        object2 -> object21 _/
    */
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);
    ret = object_group_table_set_line(maat_inst, object_group_table_name, MAAT_OP_ADD,
                                     object21_uuid_str, &object2_uuid_str, 1, NULL, 0, 0);
    EXPECT_EQ(ret, 1);

    /*       item1 -> object1 -> rule1
                                    /
       item2 -> object2 -> object21 _/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item2_uuid_str, object2_uuid_str, "time=2020-02-11",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /*
            item1 -> object1 -> object11
                        \
                          \ -> rule1
                                  /
     item2 -> object2 -> object21 _/             
    */
    long long object11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object11_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object11_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object11_id);
    ret = object_group_table_set_line(maat_inst, object_group_table_name, MAAT_OP_ADD,
                                     object11_uuid_str, &object1_uuid_str, 1, NULL, 0, 0);
    EXPECT_EQ(ret, 1);
    
    //item3 -> object3, object3 is not referenced by any rule.
    long long item3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object3_uuid_str[UUID_STR_LEN] = {0};
    char item3_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object3_id);
    snprintf(item3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item3_id);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item3_uuid_str,
                            object3_uuid_str, "220.181.38.148-220.181.38.149", NULL, 0);
    EXPECT_EQ(ret, 1);

    //item4 -> object4, object4 is not referenced by any rule.
    long long item4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object4_uuid_str[UUID_STR_LEN] = {0};
    char item4_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object4_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object4_id);
    snprintf(item4_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item4_id);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item4_uuid_str, object4_uuid_str,
                              "a finite or infinite",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url = "en.wikipedia.org/wiki/Path_(graph_theory)";
	const char* http_resp_hdr_cookie = "laptop=thinkpad X1 extrem;time=2020-02-11T15:34:00;"
                                       "main[XWJOKE]=hoho; Hm_lvt_bbac0322e6ee13093f98d5c4b5a10912=1578874808;";

    int Nth_scan = 0;

    Nth_scan++;
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, http_sig_table_name, http_req_attr_name, http_url, strlen(http_url),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, http_sig_table_name, http_req_attr_name, results, ARRAY_SIZE,
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
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item1_uuid_str);
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
    uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object11_uuid_str);
    EXPECT_STREQ(hit_path[path_idx].attribute_name, http_req_attr_name);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    path_idx++;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item1_uuid_str);
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
    EXPECT_STREQ(hit_path[path_idx].attribute_name, http_req_attr_name);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    Nth_scan++;
    ret = maat_scan_string(maat_inst, http_sig_table_name, http_resp_attr_name, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, http_sig_table_name, http_resp_attr_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 2);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 4);
    
    path_idx = 0;
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan-1);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item1_uuid_str);
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object11_uuid_str);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    path_idx++;
    ASSERT_EQ(path_idx, 1);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan-1);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item1_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str); 
	uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 2);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object21_uuid_str);
    EXPECT_STREQ(hit_path[path_idx].attribute_name, http_resp_attr_name);
	uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 3);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
    EXPECT_STREQ(hit_path[path_idx].attribute_name, http_resp_attr_name);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1); 
	
    const char* keywords1="In graph theory, a path in a graph is a finite or infinite \
sequence of edges which joins a sequence of vertices which, by most definitions,\
are all distinct (and since the vertices are distinct, so are the edges). ";
	const char* keywords2="A directed path in a directed graph is a finite or infinite\
sequence of edges which joins a sequence of distinct vertices, but with the added restriction\
that the edges be all directed in the same direction.";

    struct maat_stream *stream = maat_stream_new(maat_inst, keywords_table_name, keywords_attr_name, state);
    Nth_scan++;
    ret = maat_stream_scan(stream, keywords1, strlen(keywords1), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, keywords_table_name, keywords_attr_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 3);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 5);

    path_idx++;
	ASSERT_EQ(path_idx, 4);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item4_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object4_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    Nth_scan++;
    uint32_t ip_addr;
    inet_pton(AF_INET, "220.181.38.148", &ip_addr);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 4);
 
    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 6);

    path_idx++;
	ASSERT_EQ(path_idx, 5);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item3_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object3_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, ip_attribute_name);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    Nth_scan++;   
    ret = maat_stream_scan(stream, keywords2, strlen(keywords2), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, keywords_table_name, keywords_attr_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 5);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 7);

    path_idx++;
	ASSERT_EQ(path_idx, 6);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item4_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object4_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

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
    const char *object_group_table_name = "OBJECT_GROUP";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *ip_table_name = "IP_CONFIG";
    const char *ip_attribute_name = "IP_CONFIG";
	const char *keywords_table_name = "KEYWORDS_TABLE";
    const char *keywords_attr_name = "KEYWORDS";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item1_uuid_str, object1_uuid_str, "computer_theory",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                             /
                    object21_/
    */
    long long object21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object21_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object21_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object21_id);

    /* rule1 */
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[2];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = keywords_attr_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = keywords_attr_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object21_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1
                            /
        object2 -> object21 _/
    */
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);
    ret = object_group_table_set_line(maat_inst, object_group_table_name, MAAT_OP_ADD,
                                     object21_uuid_str, &object2_uuid_str, 1, NULL, 0, 0);
    EXPECT_EQ(ret, 1);

    /*       item1 -> object1 -> rule1
                                    /
       item2 -> object2 -> object21 _/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item2_uuid_str, object2_uuid_str, "social_theory",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
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
    char object3_uuid_str[UUID_STR_LEN] = {0};
    char item3_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object3_id);
    snprintf(item3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item3_id);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item3_uuid_str,
                            object3_uuid_str, "220.181.38.168-220.181.38.169", NULL, 0);
    EXPECT_EQ(ret, 1);

    //rule2
    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule2_id);
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = keywords_attr_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object21_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = ip_attribute_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object3_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule2_uuid_str, and_conditions, 2, NULL, 0);
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
    char object4_uuid_str[UUID_STR_LEN] = {0};
    char item4_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object4_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object4_id);
    snprintf(item4_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item4_id);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item4_uuid_str, object4_uuid_str,
                              "basic and advanced",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    //rule3
    long long rule3_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule3_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule3_id);
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = ip_attribute_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object3_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = keywords_attr_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object4_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule3_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url_computer = "en.wikipedia.org/wiki/Path_(computer_theory)";
    const char* http_url_social = "en.wikipedia.org/wiki/Path_(social_theory)";

    int keywords_table_id = maat_get_table_id(maat_inst, "KEYWORDS_TABLE");
    ASSERT_GT(keywords_table_id, 0);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, keywords_table_name, keywords_attr_name, http_url_computer,
                           strlen(http_url_computer), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    struct maat_hit_path hit_path[128];
    memset(hit_path, 0, sizeof(hit_path));
    int n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 1);

    int path_idx = 0;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item1_uuid_str);
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, -1);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    ret = maat_scan_string(maat_inst, keywords_table_name, keywords_attr_name, http_url_social,
                           strlen(http_url_social), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 3);
    
    path_idx = 0;
	EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item1_uuid_str);
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 0);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 1);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object21_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 1);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 2);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
    EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, -1);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    uint32_t ip_addr;
    inet_pton(AF_INET, "220.181.38.168", &ip_addr);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);

    memset(hit_path, 0, sizeof(hit_path));
    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 5);

    path_idx = 0;
	EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item1_uuid_str);
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
    uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 0);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 1);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object21_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 0);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 2);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, -1);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    path_idx++;
    ASSERT_EQ(path_idx, 3);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 3);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item3_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object3_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object3_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, ip_attribute_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 1);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 4);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object21_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 1);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    const char *keywords1 = "In theory, basic and advanced is common";
    ret = maat_scan_string(maat_inst, keywords_table_name, keywords_attr_name, keywords1,
                           strlen(keywords1), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule3_uuid_str);

    memset(hit_path, 0, sizeof(hit_path));
    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 7);

    path_idx = 0;
	EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item1_uuid_str);
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
    uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 0);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 1);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object21_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 0);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 2);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, -1);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    path_idx++;
    ASSERT_EQ(path_idx, 3);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 3);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item3_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object3_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object3_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, ip_attribute_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 0);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule3_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 4);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 4);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item4_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object4_uuid_str);
    uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object4_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 1);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule3_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 5);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 3);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item3_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object3_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object3_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, ip_attribute_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 1);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 6);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 2);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object21_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
	EXPECT_EQ(hit_path[path_idx].condition_index, 1);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, HitPathHasNotObject) {
    const char *object_group_table_name = "OBJECT_GROUP";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *http_sig_table_name = "HTTP_SIGNATURE";
    const char *http_req_attr_name = "HTTP_REQUEST_HEADER";
    const char *http_resp_attr_name = "HTTP_RESPONSE_HEADER";
	const char *ip_table_name = "IP_CONFIG";
    const char *ip_attribute_name = "IP_CONFIG";
	const char *keywords_table_name = "KEYWORDS_TABLE";
    const char *keywords_attr_name = "KEYWORDS";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    // !object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    // !(item1 -> object1) -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item1_uuid_str, object1_uuid_str, "math_theory", EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* !(item1 -> object1) -> rule1
                             /
                    object21_/
    */
    long long object21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object21_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object21_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object21_id);

    /* rule1 */
    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[2];
    and_conditions[0].negate_option = 1;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = http_req_attr_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = http_resp_attr_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object21_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    /* !(item1 -> object1) -> rule1
                            /
        object2 -> object21 _/
    */
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);
    ret = object_group_table_set_line(maat_inst, object_group_table_name, MAAT_OP_ADD,
                                     object21_uuid_str, &object2_uuid_str, 1, NULL, 0, 0);
    EXPECT_EQ(ret, 1);

    /*       !(item1 -> object1) -> rule1
                                    /
       item2 -> object2 -> object21 _/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                              item2_uuid_str, object2_uuid_str, "time=2020-02-12",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /*
          item1 -> object1 -> object11

            !(item1 -> object1) -> rule1
                                  /
     item2 -> object2 -> object21 _/
    */
    long long object11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object11_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object11_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object11_id);
    ret = object_group_table_set_line(maat_inst, object_group_table_name, MAAT_OP_ADD,
                                     object11_uuid_str, &object1_uuid_str, 1, NULL, 0, 0);
    EXPECT_EQ(ret, 1);
    
    //item3 -> object3, object3 is not referenced by any rule.
    long long item3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object3_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object3_uuid_str[UUID_STR_LEN] = {0};
    char item3_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object3_id);
    snprintf(item3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item3_id);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item3_uuid_str,
                            object3_uuid_str, "220.181.38.158-220.181.38.159", NULL, 0);
    EXPECT_EQ(ret, 1);

    //item4 -> object4, object4 is not referenced by any rule.
    long long item4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object4_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object4_uuid_str[UUID_STR_LEN] = {0};
    char item4_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object4_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object4_id);
    snprintf(item4_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item4_id);
    ret = expr_table_set_line(maat_inst, keywords_table_name, MAAT_OP_ADD,
                              item4_uuid_str, object4_uuid_str,
                              "a finite and infinite",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url = "en.wikipedia.org/wiki/Path_(chemistry_theory)";
	const char* http_resp_hdr_cookie = "laptop=thinkpad X1 extrem;time=2020-02-12T15:34:00;"
                                       "main[XWJOKE]=hoho; Hm_lvt_bbac0322e6ee13093f98d5c4b5a10912=1578874808;";

    int Nth_scan = 0;

    Nth_scan++;
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_inst, http_sig_table_name, http_req_attr_name, http_url, strlen(http_url),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, http_sig_table_name, http_req_attr_name, results, ARRAY_SIZE,
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
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].item_uuid) == 1);
	char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object11_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, http_req_attr_name);
    EXPECT_EQ(hit_path[path_idx].negate_option, 1);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    path_idx++;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].item_uuid) == 1);
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, http_req_attr_name);    
    EXPECT_EQ(hit_path[path_idx].negate_option, 1);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);


    Nth_scan++;
    ret = maat_scan_string(maat_inst, http_sig_table_name, http_resp_attr_name, http_resp_hdr_cookie,
                           strlen(http_resp_hdr_cookie), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, http_sig_table_name, http_resp_attr_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 2);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 4);
    
    path_idx = 0;
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan-1);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].item_uuid) == 1);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object11_uuid_str);
    EXPECT_EQ(hit_path[path_idx].negate_option, 1);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    path_idx++;
    ASSERT_EQ(path_idx, 1);
    EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan-1);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].item_uuid) == 1);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object1_uuid_str);
    EXPECT_EQ(hit_path[path_idx].negate_option, 1);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 2);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object21_uuid_str);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, http_resp_attr_name);
    EXPECT_EQ(hit_path[path_idx].negate_option, 0);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    path_idx++;
    ASSERT_EQ(path_idx, 3);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item2_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object2_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
	EXPECT_STREQ(hit_path[path_idx].attribute_name, http_resp_attr_name);
    EXPECT_EQ(hit_path[path_idx].negate_option, 0);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);
   
    const char *keywords1 = "In math theory, a finite and infinite come up all the time.";
    const char *keywords2= "a finite and infinite come up again.";

    int keywords_table_id = maat_get_table_id(maat_inst, keywords_table_name);
    ASSERT_GT(keywords_table_id, 0);

    struct maat_stream *stream = maat_stream_new(maat_inst, keywords_table_name, keywords_attr_name, state);
    Nth_scan++;
    ret = maat_stream_scan(stream, keywords1, strlen(keywords1), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, keywords_table_name, keywords_attr_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 3);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 5);

    path_idx++;
	ASSERT_EQ(path_idx, 4);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item4_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object4_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
    EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
    EXPECT_EQ(hit_path[path_idx].negate_option, 0);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    Nth_scan++;
    uint32_t ip_addr;
    inet_pton(AF_INET, "220.181.38.158", &ip_addr);
    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 4);
 
    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 6);

    path_idx++;
	ASSERT_EQ(path_idx, 5);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item3_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object3_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
    EXPECT_STREQ(hit_path[path_idx].attribute_name, ip_attribute_name);
    EXPECT_EQ(hit_path[path_idx].negate_option, 0);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    Nth_scan++;   
    ret = maat_stream_scan(stream, keywords2, strlen(keywords2), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, keywords_table_name, keywords_attr_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    scan_times = maat_state_get_scan_count(state);
    EXPECT_EQ(scan_times, 5);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 7);

    path_idx++;
	ASSERT_EQ(path_idx, 6);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item4_uuid_str);
	uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object4_uuid_str);
	EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
    EXPECT_STREQ(hit_path[path_idx].attribute_name, keywords_attr_name);
    EXPECT_EQ(hit_path[path_idx].negate_option, 0);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    maat_stream_free(stream);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, SameSuperObjectRefByMultiRule) {
    int thread_id = 0;
    const char *object_group_table_name = "OBJECT_GROUP";
	const char *rule_table_name = "RULE_DEFAULT";
	const char *http_sig_table_name = "HTTP_SIGNATURE";
    const char *http_resp_attr_name = "HTTP_RESPONSE_HEADER";
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;

    /* item5 -> object5 -> object52 -> rule2
                              \
                               \ -> rule3
    */
    long long item5_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object5_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object5_uuid_str[UUID_STR_LEN] = {0};
    char item5_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object5_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object5_id);
    snprintf(item5_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item5_id);
    int ret = expr_table_set_line(maat_inst, http_sig_table_name, MAAT_OP_ADD,
                                  item5_uuid_str, object5_uuid_str,
                                  "same superobject referenced by multi rule",
                                  EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    long long object52_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object52_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object52_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object52_id);
    ret = object_group_table_set_line(maat_inst, object_group_table_name, MAAT_OP_ADD,
                                     object52_uuid_str, &object5_uuid_str, 1, NULL, 0, 0);
    EXPECT_EQ(ret, 1);

    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule2_id);
    struct maat_cmd_and_condition and_condition;
    and_condition.negate_option = 0;
    and_condition.or_condition_num = 1;
    and_condition.or_conditions[0].attribute_name = http_resp_attr_name;
    and_condition.or_conditions[0].object_num = 1;
    and_condition.or_conditions[0].object_uuids_str[0] = object52_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule2_uuid_str, &and_condition, 1, "HTTP_RESPONSE_HEADER", 0);
    EXPECT_EQ(ret, 1);

    long long rule3_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule3_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule3_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule3_id);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule3_uuid_str, &and_condition, 1, "HTTP_RESPONSE_HEADER", 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);


    struct maat_state *state = maat_state_new(maat_inst, thread_id);    
    const char *http_res_key_str = "same superobject referenced by multi rule";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    struct maat_hit_path hit_path[128];

    ret = maat_scan_string(maat_inst, http_sig_table_name, http_resp_attr_name, http_res_key_str,
                           strlen(http_res_key_str), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule3_uuid_str);
    uuid_unparse(results[1], uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);
    
    ret = maat_scan_not_logic(maat_inst, http_sig_table_name, http_resp_attr_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    memset(hit_path, 0, sizeof(hit_path));
    int n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 3);

    int path_idx = 0;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item5_uuid_str);
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object5_uuid_str);
    uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object52_uuid_str);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule3_uuid_str);

    path_idx++;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item5_uuid_str);
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object5_uuid_str);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].top_object_uuid) == 1);
    EXPECT_TRUE(uuid_is_null(hit_path[path_idx].rule_uuid) == 1);

    path_idx++;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, 1);
    uuid_unparse(hit_path[path_idx].item_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, item5_uuid_str);
    uuid_unparse(hit_path[path_idx].sub_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object5_uuid_str);
    uuid_unparse(hit_path[path_idx].top_object_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, object52_uuid_str);
    uuid_unparse(hit_path[path_idx].rule_uuid, uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, ObjectEdit) {
	const char *rule_table_name = "RULE_DEFAULT";
	const char *ip_table_name = "IP_PLUS_CONFIG"; 
    const char *ip_attribute_name = "IP_PLUS_CONFIG";
    const char *app_id_table_name = "APP_ID";
    const char *app_id_attribute_name = "APP_ID";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    /* item11 -> object11 -> condition1 -> rule1
           item21 -> object21 -> condition2 _/
    */
    long long object11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object11_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object11_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object11_id);

    long long item11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item11_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item11_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item11_id);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item11_uuid_str,
                            object11_uuid_str, "192.168.3.1-192.168.3.4", NULL, 0);
    EXPECT_EQ(ret, 1);

    long long object21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object21_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object21_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object21_id);

    long long item21_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item21_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item21_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item21_id);
    ret = interval_table_set_line(maat_inst, app_id_table_name, MAAT_OP_ADD,
                                  item21_uuid_str, object21_uuid_str, "41", 0);
    EXPECT_EQ(ret, 1);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[2];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = ip_attribute_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object11_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = app_id_attribute_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object21_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.3.2", &ip_addr);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    int scan_app_id = 42;
    ret = maat_scan_integer(maat_inst, app_id_table_name, app_id_attribute_name, scan_app_id, results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, app_id_table_name, app_id_attribute_name, results, ARRAY_SIZE,
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
    char item22_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item22_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item22_id);
    ret = interval_table_set_line(maat_inst, app_id_table_name, MAAT_OP_ADD,
                                  item22_uuid_str, object21_uuid_str, scan_app_id_str, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);


    ret = maat_scan_integer(maat_inst, app_id_table_name, app_id_attribute_name, scan_app_id, results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, app_id_table_name, app_id_attribute_name, results, ARRAY_SIZE,
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
                                item22_uuid_str, object21_uuid_str, scan_app_id_str, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_integer(maat_inst, app_id_table_name, app_id_attribute_name, scan_app_id, results,
                            ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, app_id_table_name, app_id_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, RuleDelete_TSG6548) {
	const char* rule_table_name = "RULE_DEFAULT";
	const char* ip_table_name = "IP_PLUS_CONFIG";
    const char *ip_attribute_name = "IP_PLUS_CONFIG";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //item11 -> object11 -> condition1 -> rule1
    long long object11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object11_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object11_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object11_id);

    long long item11_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item11_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item11_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item11_id);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item11_uuid_str,
                            object11_uuid_str, "192.168.73.163-192.168.73.180", NULL, 0);
    EXPECT_EQ(ret, 1);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[1];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = ip_attribute_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object11_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.73.169", &ip_addr);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results,
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_DEL,
                                 rule1_uuid_str, and_conditions, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    int hit_cnt = 0;
    int miss_cnt = 0;
    time_t update_time = time(NULL);
	time_t now = update_time;
	while (now - update_time < 3) {
		ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results,
                             ARRAY_SIZE, &n_hit_result, state);
		if (ret == MAAT_SCAN_HIT) {
			hit_cnt++;
            uuid_unparse(results[0], uuid_str);
            EXPECT_STREQ(uuid_str, rule1_uuid_str);
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
	const char* rule_table_name = "RULE_DEFAULT";
	const char* table_http_url = "HTTP_URL";
    const char *attribute_http_url = "HTTP_URL";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, table_http_url, MAAT_OP_ADD, item1_uuid_str,
                              object1_uuid_str, "part-1", EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[1];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = attribute_http_url;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* scan_data1 = "scan string part-1.";
	const char* scan_data2 = "scan string part-2.";

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;

    ret = maat_scan_string(maat_inst, table_http_url, attribute_http_url, scan_data1, strlen(scan_data1),
                          results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, table_http_url, attribute_http_url, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);


    //object2 -> rule2
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);

    //item2 -> object2 -> rule2
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = expr_table_set_line(maat_inst, table_http_url, MAAT_OP_ADD, item2_uuid_str,
                              object2_uuid_str, "part-2", EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule2_id);
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object2_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule2_uuid_str, and_conditions, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    //DON'T DO THIS!!!
	//Roll back version, trigger full udpate.
	//This operation generates some FATAL logs in test_maat_redis.log.yyyy-mm-dd.
	maat_cmd_incrby(maat_inst, "MAAT_VERSION", -100);

    //Wating for scanner garbage collect expiration.
	sleep(10);

    memset(results, 0, sizeof(results));
    ret = maat_scan_string(maat_inst, table_http_url, attribute_http_url, scan_data2, strlen(scan_data2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    //After full update, condition ids are re-orgnized, therefore mid are not compatible to the new scanner (hierarchy).
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT); 

    ret = maat_scan_not_logic(maat_inst, table_http_url, attribute_http_url, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, StreamScanWhenExprTableIncUpdate) {
	const char* rule_table_name = "RULE_DEFAULT";
	const char* scan_table_name = "KEYWORDS_TABLE";
    const char *scan_attribute_name = "KEYWORDS_TABLE";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[1];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = scan_attribute_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    const char *scan_data = "Here is a stream-keywords-001-inc-update, this should hit.";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;

    struct maat_stream *stream = maat_stream_new(maat_inst, scan_table_name, scan_attribute_name, state);
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    ret = maat_scan_not_logic(maat_inst, scan_table_name, scan_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, scan_table_name, MAAT_OP_ADD,
                              item1_uuid_str, object1_uuid_str, "stream-keywords-001-inc-update",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    /* maat_stream store expr_runtime version when maat_stream_new().
       Add new expr_item has changed expr_runtime version which has been sensed by maat_stream_scan.
    */
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    
    ret = maat_scan_not_logic(maat_inst, scan_table_name, scan_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_stream_free(stream);

    stream = maat_stream_new(maat_inst, scan_table_name, scan_attribute_name, state);
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, scan_table_name, scan_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_stream_free(stream);
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, StreamScanSegfaultWhenVersionRollBack_TSG6324) {
	const char* rule_table_name = "RULE_DEFAULT";
	const char* scan_table_name = "KEYWORDS_TABLE";
    const char *scan_attribute_name = "KEYWORDS_TABLE";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, scan_table_name, MAAT_OP_ADD, item1_uuid_str,
                              object1_uuid_str, "stream-keywords-002", EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[1];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = scan_attribute_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 1, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char *scan_data = "Here is a stream-keywords-002, this should hit.";
    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;

    struct maat_stream *stream = maat_stream_new(maat_inst, scan_table_name, scan_attribute_name, state);
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, scan_table_name, scan_attribute_name, results, ARRAY_SIZE,
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

    ret = maat_scan_not_logic(maat_inst, scan_table_name, scan_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_stream_free(stream);
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, IPAndStreamScanWhenIncUpdate) {
	const char *rule_table_name = "RULE_DEFAULT";
	const char *expr_table_name = "KEYWORDS_TABLE";
    const char *expr_attribute_name = "KEYWORDS_TABLE";
    const char *ip_table_name = "IP_PLUS_CONFIG";
    const char *ip_attribute_name = "IP_PLUS_CONFIG";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, expr_table_name, MAAT_OP_ADD, item1_uuid_str,
                              object1_uuid_str, "stream-keywords-003", EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1 
                            /
         item2 -> object2 --/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item2_uuid_str,
                            object2_uuid_str, "100.100.100.1", NULL, 0);
    EXPECT_EQ(ret, 1);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[2];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = expr_attribute_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = ip_attribute_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object2_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    char ip_str[32] = "100.100.100.1";
    uint32_t ip_addr;
    ret = inet_pton(AF_INET, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);

    int table_id = maat_get_table_id(maat_inst, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //add rule2 for rule runtime inc update
    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule2_id);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule2_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char *scan_data = "Here is a stream-keywords-003, this should hit.";

    struct maat_stream *stream = maat_stream_new(maat_inst, expr_table_name, expr_attribute_name, state);
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, expr_table_name, expr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    /* 
        becase rule1_id has been returned, maat_scan_xx will not return duplicate rule_id again
    */
    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_stream_free(stream);
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, IPAndStreamScanWhenFullUpdate) {
	const char *rule_table_name = "RULE_DEFAULT";
	const char *ip_table_name = "IP_PLUS_CONFIG";
    const char *ip_attribute_name = "IP_PLUS_CONFIG";
    const char *expr_table_name = "KEYWORDS_TABLE";
    const char *expr_attribute_name = "KEYWORDS_TABLE";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, expr_table_name, MAAT_OP_ADD,
                              item1_uuid_str, object1_uuid_str, "stream-keywords-004",
                              EXPR_TYPE_AND, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1 
                            /
         item2 -> object2 --/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD,
                            item2_uuid_str, object2_uuid_str, "100.100.100.2", NULL, 0);
    EXPECT_EQ(ret, 1);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[2];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = expr_attribute_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = ip_attribute_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object2_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    char ip_str[32] = "100.100.100.2";
    uint32_t ip_addr;
    ret = inet_pton(AF_INET, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //DON'T DO THIS!!!
	//Roll back version, trigger full update.	
	maat_cmd_incrby(maat_inst, "MAAT_VERSION", -100);

	//Wating for scanner garbage collect expiration.
	sleep(10);

    const char *scan_data = "Here is a stream-keywords-004, this should hit.";

    struct maat_stream *stream = maat_stream_new(maat_inst, expr_table_name, expr_attribute_name, state);
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results,
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, expr_table_name, expr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    /* maat_state keep the rule_rt version when maat_state_new().
       After full updating, new rule_rt version is different from that of maat_state,
       so MAAT_SCAN_HIT will never happen.
    */
    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_stream_free(stream);
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, IPAndStringScanWhenIncUpdate) {
	const char *rule_table_name = "RULE_DEFAULT";
	const char *expr_table_name = "HTTP_URL";
    const char *expr_attribute_name = "HTTP_URL";
    const char *ip_table_name = "IP_PLUS_CONFIG";
    const char *ip_attribute_name = "IP_PLUS_CONFIG";
    const char *keywords = "IP&stringinc";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, expr_table_name, MAAT_OP_ADD, item1_uuid_str,
                              object1_uuid_str, keywords, EXPR_TYPE_AND, 0); /*EXPR_TYPE_AND MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1 
                            /
         item2 -> object2 --/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item2_uuid_str,
                            object2_uuid_str, "100.100.100.1", NULL, 0);
    EXPECT_EQ(ret, 1);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[2];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = expr_attribute_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = ip_attribute_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object2_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    char ip_str[32] = "100.100.100.1";
    uint32_t ip_addr;
    ret = inet_pton(AF_INET, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //add rule2 for rule runtime inc update
    long long rule2_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule2_id);
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                 rule2_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char *scan_data = "Here is a IP and stringinc, this should hit.";

    ret = maat_scan_string(maat_inst, expr_table_name, expr_attribute_name, scan_data, strlen(scan_data),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule1_uuid_str);

    ret = maat_scan_not_logic(maat_inst, expr_table_name, expr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    /* 
        becase rule1_id has been returned, maat_scan_xx will not return duplicate rule_id again
    */
    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, rule2_uuid_str);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmd, IPAndStringScanWhenFullupdate) {
    const char *rule_table_name = "RULE_DEFAULT";
    const char *ip_table_name = "IP_PLUS_CONFIG";
    const char *ip_attribute_name = "IP_PLUS_CONFIG";
    const char *expr_table_name = "HTTP_URL";
    const char *expr_attribute_name = "HTTP_URL";
    const char *keywords = "IP&string";
    int thread_id = 0, ret = 0;
    struct maat *maat_inst = MaatCmd::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    //object1 -> rule1
    long long object1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object1_id);

    //item1 -> object1 -> rule1
    long long item1_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    char item1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(item1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item1_id);
    ret = expr_table_set_line(maat_inst, expr_table_name, MAAT_OP_ADD, item1_uuid_str,
                              object1_uuid_str, keywords, EXPR_TYPE_AND, 0); /*EXPR_TYPE_AND MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> object1 -> rule1 
                            /
         item2 -> object2 --/
    */
    long long item2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    long long object2_id = maat_cmd_incrby(maat_inst, "SEQUENCE_OBJECT", 1);
    char object2_uuid_str[UUID_STR_LEN] = {0};
    char item2_uuid_str[UUID_STR_LEN] = {0};
    snprintf(object2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", object2_id);
    snprintf(item2_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", item2_id);
    ret = ip_table_set_line(maat_inst, ip_table_name, MAAT_OP_ADD, item2_uuid_str,
                            object2_uuid_str, "100.100.100.3", NULL, 0);
    EXPECT_EQ(ret, 1);

    long long rule1_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    char rule1_uuid_str[UUID_STR_LEN] = {0};
    snprintf(rule1_uuid_str, UUID_STR_LEN, "00000000-0000-0000-0000-%012lld", rule1_id);
    struct maat_cmd_and_condition and_conditions[2];
    and_conditions[0].negate_option = 0;
    and_conditions[0].or_condition_num = 1;
    and_conditions[0].or_conditions[0].attribute_name = expr_attribute_name;
    and_conditions[0].or_conditions[0].object_num = 1;
    and_conditions[0].or_conditions[0].object_uuids_str[0] = object1_uuid_str;
    and_conditions[1].negate_option = 0;
    and_conditions[1].or_condition_num = 1;
    and_conditions[1].or_conditions[0].attribute_name = ip_attribute_name;
    and_conditions[1].or_conditions[0].object_num = 1;
    and_conditions[1].or_conditions[0].object_uuids_str[0] = object2_uuid_str;
    ret = rule_table_set_line(maat_inst, rule_table_name, MAAT_OP_ADD,
                                     rule1_uuid_str, and_conditions, 2, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    char ip_str[32] = "100.100.100.3";
    uint32_t ip_addr;
    ret = inet_pton(AF_INET, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);

    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    //DON'T DO THIS!!!
	//Roll back version, trigger full update.	
	maat_cmd_incrby(maat_inst, "MAAT_VERSION", -100);

	//Wating for scanner garbage collect expiration.
	sleep(10);

    const char *scan_data = "scan IP and string, this should hit.";

    ret = maat_scan_string(maat_inst, expr_table_name, expr_attribute_name, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, expr_table_name, expr_attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    /* maat_state keep the rule_rt version when maat_state_new().
       After full updating, new rule_rt version is different from that of maat_state,
       so MAAT_SCAN_HIT will never happen.
    */
    ret = maat_scan_ipv4(maat_inst, ip_table_name, ip_attribute_name, ip_addr, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_not_logic(maat_inst, ip_table_name, ip_attribute_name, results, ARRAY_SIZE,
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
    const char *attribute_name = "HTTP_URL";
    struct maat *maat_inst = MaatRollback::_shared_maat_inst;
    struct log_handle *logger = MaatRollback::logger;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "http://www.cyberessays.com/search_results.php?"
                            "action=search&query=username,abckkk,1234567";

    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000125");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
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

    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000125");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
                              &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatRollback, FullConfigRollbackWhenScanUnfinished) {
    const char *table_name = "HTTP_URL";
    const char *attribute_name = "HTTP_URL";
    struct maat *maat_inst = MaatRollback::_shared_maat_inst;
    struct log_handle *logger = MaatRollback::logger;

    uuid_t results[ARRAY_SIZE];
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "http://www.cyberessays.com/search_results.php?"
                            "action=search&query=username,abckkk,1234567";

    int ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    char uuid_str[UUID_STR_LEN] = {0};
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000125");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
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

    ret = maat_scan_string(maat_inst, table_name, attribute_name, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    uuid_unparse(results[0], uuid_str);
    EXPECT_STREQ(uuid_str, "00000000-0000-0000-0000-000000000125");

    ret = maat_scan_not_logic(maat_inst, table_name, attribute_name, results, ARRAY_SIZE,
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
