#include <gtest/gtest.h>
#include <dirent.h>
#include <openssl/md5.h>

#include "maat.h"
#include "maat_rule.h"
#include "maat_utils.h"
#include "maat_command.h"
#include "ip_matcher.h"
#include "json2iris.h"
#include "log/log.h"
#include "maat_config_monitor.h"

#define MODULE_FRAMEWORK_GTEST	 module_name_str("maat.framework_gtest")

#define ARRAY_SIZE              10
#define HIT_PATH_SIZE           128
#define	WAIT_FOR_EFFECTIVE_S	1

const char *table_info_path = "./table_info.conf";
const char *json_path="./maat_json.json";
const char *json_filename = "maat_json.json";

size_t g_thread_num = 4;

extern int system_cmd_rmdir(const char *dir);

void wait_for_cmd_effective(struct maat *maat_instance, long long version_before)
{
	long long version_after = version_before;
	int is_updating = 1;
	long long wating_us = 0, sleep_us = 1000 * 100;

	while (is_updating || version_before == version_after) {
		is_updating = maat_cmd_config_is_updating(maat_instance);
        version_after = maat_cmd_get_config_version(maat_instance);
		
		usleep(sleep_us);//waiting for commands go into effect
		wating_us += sleep_us;
	}
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

int write_config_to_redis(char *redis_ip, int redis_port, int redis_db,
                          struct log_handle *logger)
{
    char json_iris_path[512] = {0};

    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp", json_filename);

    redisContext *c = maat_cmd_connect_redis(redis_ip, redis_port, redis_db, logger);
    if (NULL == c) {
        return -1;
    }

    redisReply *reply = maat_cmd_wrap_redis_command(c, "flushdb");
    if (NULL == reply) {
        return -1;
    } else {
        freeReplyObject(reply);
	    reply = NULL;
    }
    
    if (0 == access(json_iris_path, F_OK)) {
        system_cmd_rmdir(json_iris_path);
    }

    if (access(json_iris_path, F_OK) < 0) {
        char tmp_iris_path[128] = {0};
        char *json_buff = NULL;
        size_t json_buff_sz = 0;
        
        int ret = load_file_to_memory(json_filename, (unsigned char **)&json_buff, &json_buff_sz);
        if (ret < 0) {
            return -1;
        }

        ret = json2iris(json_buff, json_filename, c, tmp_iris_path, 
                        sizeof(tmp_iris_path), NULL, NULL, logger);
        FREE(json_buff);
        if (ret < 0) {
            return -1;
        }
    }

    size_t total_line_cnt = 0;
    char tmp_iris_full_idx_path[PATH_MAX] = {0};
    snprintf(tmp_iris_full_idx_path, sizeof(tmp_iris_full_idx_path), "%s/index", json_iris_path);
    config_monitor_traverse(0, tmp_iris_full_idx_path, NULL, count_line_num_cb, NULL, &total_line_cnt, logger);

    struct serial_rule *s_rule = ALLOC(struct serial_rule, total_line_cnt);
    s_rule->ref_ctx = c;
    long long server_time = maat_cmd_redis_server_time_s(c);
    if (server_time < 0) {
        return -1;
    }

    absolute_expire_time = server_time + 300;
    config_monitor_traverse(0, tmp_iris_full_idx_path, NULL, make_serial_rule, NULL, s_rule, logger);
    s_rule->ref_ctx = NULL;
    line_idx = 0;
    absolute_expire_time = 0;

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

    return 0;
}

int compile_table_set_line(struct maat *maat_instance, const char *table_name,
                           enum maat_operation op, long long compile_id,
                           const char *user_region, int clause_num, int expire_after)
{
    char table_line[1024 * 16] = {0};
    sprintf(table_line, "%lld\t0\t0\t0\t0\t0\t%s\t%d\t%d\t0.0", 
            compile_id, user_region, op, clause_num);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = compile_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_instance, &line_rule);
}
#define TO_GROUP2X_KEY(group_id, parent_id)	((unsigned long)group_id<<32|parent_id)
int group2compile_table_set_line(struct maat *maat_instance, const char *table_name,
                                 enum maat_operation op, long long group_id, long long compile_id,
                                 int not_flag, const char *vtable_name, int clause_index,
                                 int expire_after)
{
    char table_line[128] = {0};
    sprintf(table_line, "%lld\t%lld\t%d\t%d\t%s\t%d", 
            group_id, compile_id, op, not_flag, vtable_name, clause_index);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = TO_GROUP2X_KEY(group_id, compile_id);
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_instance, &line_rule);
}

int group2group_table_set_line(struct maat *maat_instance, const char *table_name, enum maat_operation op,
                               long long group_id, long long superior_group_id, int expire_after)
{
    char table_line[128] = {0};
    sprintf(table_line, "%lld\t%lld\t%d", group_id, superior_group_id, op);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = TO_GROUP2X_KEY(group_id, superior_group_id);
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_instance, &line_rule);
}

int expr_table_set_line(struct maat *maat_instance, const char *table_name, enum maat_operation op,
                        long long item_id, long long group_id, const char *keywords, const char *district,
                        int expr_type, int match_method, int is_hexbin, int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_instance, table_name);
    if (table_id < 0) {
        return 0;
    }
    
    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    assert(table_type == TABLE_TYPE_EXPR || table_type == TABLE_TYPE_EXPR_PLUS);

    if (table_type == TABLE_TYPE_EXPR_PLUS) {
        sprintf(table_line, "%lld\t%lld\t%s\t%s\t%d\t%d\t%d\t%d", item_id, group_id, district,
                keywords, expr_type, match_method, is_hexbin, op);
    } else {
        sprintf(table_line, "%lld\t%lld\t%s\t%d\t%d\t%d\t%d", item_id, group_id, keywords, expr_type,
            match_method, is_hexbin, op);
    }

    struct maat_cmd_line line_rule;
    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_instance, &line_rule);
}

int intval_table_set_line(struct maat *maat_instance, const char *table_name, enum maat_operation op,
                          long long item_id, long long group_id, unsigned int low_boundary,
                          unsigned int up_boundary, const char *district, int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_instance, table_name);
    if (table_id < 0) {
        return 0;
    }

    enum table_type table_type = table_manager_get_table_type(maat_instance->tbl_mgr, table_id);
    assert(table_type == TABLE_TYPE_INTERVAL || table_type == TABLE_TYPE_INTERVAL_PLUS);

    if (table_type == TABLE_TYPE_INTERVAL_PLUS) {
        sprintf(table_line, "%lld\t%lld\t%s\t%u\t%u\t%d", item_id, group_id, district,
                low_boundary, up_boundary, op);
    } else {
        sprintf(table_line, "%lld\t%lld\t%u\t%u\t%d", item_id, group_id,
                low_boundary, up_boundary, op);
    }

    struct maat_cmd_line line_rule;
    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_instance, &line_rule);
}

int ip_table_set_line(struct maat *maat_instance, const char *table_name, enum maat_operation op,
                      long long item_id, long long group_id, enum IP_TYPE type, const char *ip1, 
                      const char *ip2, uint16_t port_min, uint16_t port_max, int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_instance, table_name);
    if (table_id < 0) {
        return 0;
    }

    int ip_type = 4;
    if (type == IPv6) {
        ip_type = 6;
    }

    sprintf(table_line, "%lld\t%lld\t%d\t%s\t%s\t%s\t%s\t%u\t%u\t6\t%d", item_id, group_id, ip_type, 
            "range", ip1, ip2, "range", port_min, port_max, op);
    struct maat_cmd_line line_rule;
    
    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_instance, &line_rule);
}

int test_add_expr_command(struct maat *maat_instance, const char *expr_table, 
                          long long compile_id, int timeout, const char *keywords)
{
    char huge_serv_def[1024 * 2] = {0};

    memset(huge_serv_def, 's', sizeof(huge_serv_def) - 1);
    huge_serv_def[sizeof(huge_serv_def) - 1] = '\0';

    int ret = compile_table_set_line(maat_instance, "COMPILE", MAAT_OP_ADD, compile_id, 
                                     huge_serv_def, 1, timeout);
    EXPECT_EQ(ret, 1);

    long long group_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, "GROUP2COMPILE", MAAT_OP_ADD, group_id, 
                                       compile_id, 0, "null", 1, timeout);
    EXPECT_EQ(ret, 1);

    long long item_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, expr_table, MAAT_OP_ADD, item_id, group_id, keywords, 
                              "null", 1, 0, 0, 0);
    EXPECT_EQ(ret, 1);

    return ret;
}

int del_command(struct maat *maat_instance, int compile_id)
{
    return compile_table_set_line(maat_instance, "COMPILE", MAAT_OP_DEL, compile_id, NULL, 1, 0);
}
#if 0
class MaatStreamScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);

        _shared_maat_instance = maat_new(opts, table_info_path);
        assert(_shared_maat_instance != NULL);
       
        maat_cmd_flushDB(_shared_maat_instance);
        maat_free(_shared_maat_instance);

        maat_options_set_foreign_cont_dir(opts, "./foreign_files/");
        maat_options_set_rule_effect_interval_ms(opts, 20 * 1000); //20s for garbage collection
        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
    } 

    static struct maat *_shared_maat_instance;
};

struct maat *MaatStreamScan::_shared_maat_instance;

TEST_F(MaatStreamScan, dynamic_config) {
    const char *scan_data1 = "http://www.cyberessays.com/search_results.php?action=search&query=yulingjing,abckkk,1234567";
	const char *scan_data2 = "hello world";
    const char *table_name = "HTTP_URL";
    const char *keywords1 = "action=search\\&query=(.*)";
    const char *keywords2 = "hello";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatStreamScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    long long compile1_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = test_add_expr_command(maat_instance, table_name, compile1_id, 0, keywords1);
    EXPECT_EQ(ret, 1);
    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    int table_id = maat_get_table_id(maat_instance, table_name);
	ASSERT_GT(table_id, 0);

	struct maat_stream *sp = maat_stream_new(maat_instance, table_id, state);
	ASSERT_TRUE(sp != NULL);

	ret = maat_stream_scan(sp, "www.cyberessays.com", strlen("www.cyberessays.com"),
                                results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_stream_scan(sp, scan_data1, strlen(scan_data1), results, ARRAY_SIZE,
                            &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], compile1_id);
	maat_state_reset(state);

    long long compile2_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    ret = test_add_expr_command(maat_instance, table_name, compile2_id, 0, keywords2);
    EXPECT_EQ(ret, 1);

    for (int i = 0; i < 100; i++) {
        ret = maat_stream_scan(sp, "www.cyberessays.com", strlen("www.cyberessays.com"),
                               results, ARRAY_SIZE, &n_hit_result, state);
        EXPECT_EQ(ret, MAAT_SCAN_OK);

        ret = maat_stream_scan(sp, scan_data2, strlen(scan_data2), results, ARRAY_SIZE,
                               &n_hit_result, state);
        EXPECT_EQ(ret, MAAT_SCAN_HIT);
        EXPECT_EQ(results[0], compile2_id);
        maat_state_reset(state);
        usleep(500 * 1000);

        compile2_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
        ret = test_add_expr_command(maat_instance, table_name, compile2_id, 0, keywords2);
        EXPECT_EQ(ret, 1);
        
    }
    maat_stream_free(sp);
    maat_state_free(state);
    sp = NULL;
    state = NULL;
}
#endif
#if 1
class MaatFlagScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);        
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *MaatFlagScan::_shared_maat_instance;
struct log_handle *MaatFlagScan::logger;

TEST_F(MaatFlagScan, basic) {
    const char *flag_table_name = "FLAG_CONFIG";
    struct maat *maat_instance = MaatFlagScan::_shared_maat_instance;

    int flag_table_id = maat_get_table_id(maat_instance, flag_table_name);
    //compile_id:192 flag: 0000 0001 mask: 0000 0011
    //scan_data: 0000 1001 or 0000 1101 should hit
    long long scan_data = 9;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int ret = maat_scan_flag(maat_instance, flag_table_id, scan_data, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 192);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);
    maat_state_reset(state);

    scan_data = 13;
    memset(results, 0, sizeof(results));
    n_hit_result = 0;
    ret = maat_scan_flag(maat_instance, flag_table_id, scan_data, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 192);
    maat_state_reset(state);

    scan_data = 6;
    memset(results, 0, sizeof(results));
    n_hit_result = 0;
    ret = maat_scan_flag(maat_instance, flag_table_id, scan_data, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(state);
    state = NULL;
}   

TEST_F(MaatFlagScan, withExprRegion) {
    const char *flag_table_name = "FLAG_CONFIG";
    const char *expr_table_name = "HTTP_URL";
    struct maat *maat_instance = MaatFlagScan::_shared_maat_instance;

    int flag_table_id = maat_get_table_id(maat_instance, flag_table_name);
    int expr_table_id = maat_get_table_id(maat_instance, expr_table_name);
    //compile_id:193 flag: 0000 0010 mask: 0000 0011
    //scan_data: 0000 0010 or 0000 0100 should hit
    long long flag_scan_data = 2;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int ret = maat_scan_flag(maat_instance, flag_table_id, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    const char *expr_scan_data = "hello world";
    ret = maat_scan_string(maat_instance, expr_table_id, expr_scan_data, 
                           strlen(expr_scan_data), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 193);
    maat_state_free(state);
    state = NULL;
}   

TEST_F(MaatFlagScan, hitMultiCompile) {
    const char *flag_table_name = "FLAG_CONFIG";
    struct maat *maat_instance = MaatFlagScan::_shared_maat_instance;

    int flag_table_id = maat_get_table_id(maat_instance, flag_table_name);
    //compile_id:192 flag: 0000 0001 mask: 0000 0011
    //compile_id:194 flag: 0001 0101 mask: 0001 1111
    //scan_data: 0001 0101 should hit compile192 and compile194
    long long flag_scan_data = 21;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int ret = maat_scan_flag(maat_instance, flag_table_id, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 194);
    EXPECT_EQ(results[1], 192);

    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(maat_instance, flag_table_id, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    maat_state_free(state);
    state = NULL;
}  

TEST_F(MaatFlagScan, hitRepeatedCompile) {
    const char *flag_table_name = "FLAG_CONFIG";
    struct maat *maat_instance = MaatFlagScan::_shared_maat_instance;

    int flag_table_id = maat_get_table_id(maat_instance, flag_table_name);
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    //compile_id:192 flag: 0000 0001 mask: 0000 0011
    //scan_data: 0000 1001 or 0000 1101 should hit
    long long flag_scan_data1 = 9; 
    int ret = maat_scan_flag(maat_instance, flag_table_id, flag_scan_data1, results, 
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 192);

    //compile_id:192 flag: 0000 0001 mask: 0000 0011
    //compile_id:194 flag: 0001 0101 mask: 0001 1111
    //scan_data: 0001 0101 should hit compile192 and compile194
	long long flag_scan_data2 = 21;
    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(maat_instance, flag_table_id, flag_scan_data2, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 194);

    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(maat_instance, flag_table_id, flag_scan_data2, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    maat_state_free(state);
    state = NULL;
}  

TEST_F(MaatFlagScan, FlagPlus) {
    const char *flag_table_name = "FLAG_PLUS_CONFIG";
    const char *region_name = "I love China";
    struct maat *maat_instance = MaatFlagScan::_shared_maat_instance;

    int flag_table_id = maat_get_table_id(maat_instance, flag_table_name);
    //compile_id:196 flag: 0001 1111 mask: 0000 1111
    //scan_data: 0000 1111 or 0001 1111 should hit
    long long scan_data1 = 15;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int ret = maat_scan_flag(maat_instance, flag_table_id, scan_data1, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_ERR);
 
    ret = maat_state_set_scan_district(state, flag_table_id, region_name, strlen(region_name));
    ASSERT_EQ(ret, 0);

    ret = maat_scan_flag(maat_instance, flag_table_id, scan_data1, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 196);

    ret = maat_scan_flag(maat_instance, flag_table_id, scan_data1, results,
                             ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);
    maat_state_free(state);
    state = NULL;
}

class MaatStringScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *MaatStringScan::_shared_maat_instance;
struct log_handle *MaatStringScan::logger;

TEST_F(MaatStringScan, ScanDataOnlyOneByte) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    const char scan_data = 0x20;

    int ret = maat_scan_string(maat_instance, table_id, &scan_data, sizeof(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, Full) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    const char *scan_data = "http://www.cyberessays.com/search_results.php?action=search&query=username,abckkk,1234567";

    int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 125);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, Regex) {
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *cookie = "Cookie: Txa123aheadBCAxd";
    const char *table_name = "HTTP_URL";
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    ret = maat_scan_string(maat_instance, table_id, cookie, strlen(cookie),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 146);
    maat_state_free(state);
    state = NULL;
    //TODO:
#if 0
    size_t i = 0;
    n_hit_result = 0;
    memset(results, 0, sizeof(results));
    const char *sni_should_not_hit[] = {"instagram.fbcdn.net", "a.instagram.fbcdn.net"};
	const char *sni_should_hit[] = {"xx.fbcdn.net", "ainstagram.fbcdn.net"};
	for (i = 0; i < sizeof(sni_should_not_hit)/sizeof(const char *); i++) {
		ret = maat_scan_string(g_maat_instance, table_id, 0, sni_should_not_hit[i], strlen(sni_should_not_hit[i]), 
							   results, 5, &n_hit_result, &state);
		EXPECT_EQ(ret, 0);		
		maat_state_free(&state);
	}

	for (i = 0; i < sizeof(sni_should_hit)/sizeof(const char *); i++) {
		ret = maat_scan_string(g_maat_instance, table_id, 0, sni_should_hit[i], strlen(sni_should_hit[i]), 
							   results, 5, &n_hit_result, &state);
		EXPECT_GE(ret, 1);	
		EXPECT_EQ(results[0], 149);
		maat_state_free(&state);
	}
#endif	
}

TEST_F(MaatStringScan, ExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *region_name1 ="HTTP URL";
	const char *region_name2 ="我的diStricT";
	const char *scan_data1 = "http://www.cyberessays.com/search_results.php?action=search&query=abckkk,1234567";
	const char *scan_data2 = "Addis Sapphire Hotel";
    const char *table_name = "HTTP_SIGNATURE";
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
	int ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1), 
						        results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_ERR);//Should return error for district not setting.

	ret = maat_state_set_scan_district(state, table_id, region_name1, strlen(region_name1));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 128);
	maat_state_reset(state);

	ret = maat_state_set_scan_district(state, table_id, region_name2, strlen(region_name2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_instance, table_id, scan_data2, strlen(scan_data2), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 190);
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, ExprPlusWithOffset)
{
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
	const char *region_name = "Payload";
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

	int table_id = maat_get_table_id(maat_instance, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, region_name, strlen(region_name));
	EXPECT_EQ(ret, 0);

	ret = maat_scan_string(maat_instance, table_id, (char*)udp_payload_not_hit, sizeof(udp_payload_not_hit), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_scan_string(maat_instance, table_id, (char*)udp_payload_hit, sizeof(udp_payload_hit), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 148);
	
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, ExprPlusWithHex) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
	const char *scan_data1 = "text/html; charset=UTF-8";
	const char *scan_data2 = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *region_name1 = "Content-Type";
	const char *region_name2 = "User-Agent";

	int table_id = maat_get_table_id(maat_instance, "HTTP_SIGNATURE");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, region_name1, strlen(region_name1));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 156);

    ret = maat_state_set_scan_district(state, table_id, region_name2, strlen(region_name2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK); //maat-v3 consider as half hit, it's unreasonable
    
    table_id = maat_get_table_id(maat_instance, "KEYWORDS_TABLE");
    ret = maat_scan_string(maat_instance, table_id, scan_data2, strlen(scan_data2),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 132);                    
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, ExprAndExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    const char *expr_table_name = "HTTP_URL";
    const char *expr_plus_table_name = "HTTP_SIGNATURE";
    const char *region_name = "I love China";
    const char *scan_data = "today is Monday and yesterday is Tuesday";

    int expr_table_id = maat_get_table_id(maat_instance, expr_table_name);
    int expr_plus_table_id = maat_get_table_id(maat_instance, expr_plus_table_name);

    int ret = maat_scan_string(maat_instance, expr_plus_table_id, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_ERR);

    ret = maat_state_set_scan_district(state, expr_plus_table_id, region_name, strlen(region_name));
    ASSERT_EQ(ret, 0);
    ret = maat_scan_string(maat_instance, expr_plus_table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_instance, expr_table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 195);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, ShouldNotHitExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
	const char *region_name = "tcp.payload";
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

	int table_id = maat_get_table_id(maat_instance, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, region_name, strlen(region_name));
	ASSERT_EQ(ret, 0);
    
	ret = maat_scan_string(maat_instance, table_id, (char *)udp_payload_not_hit, sizeof(udp_payload_not_hit), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK); //maat-v3 consider as half hit, it's unreasonable
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, Expr8) {
    const char *table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    int table_id = maat_get_table_id(maat_instance, table_name);
    char scan_data[128] = "string1, string2, string3, string4, string5, string6, string7, string8";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, HexBinCaseSensitive) {
    const char *table_name = "KEYWORDS_TABLE";
	const char *scan_data1 = "String TeST should not hit.";
	const char *scan_data2 = "String TEST should hit";
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    int ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_reset(state);

    ret = maat_scan_string(maat_instance, table_id, scan_data2, strlen(scan_data2), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 191);
    maat_state_free(state);
}

TEST_F(MaatStringScan, BugReport20190325) {
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
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    int ret = maat_scan_string(maat_instance, table_id, (char *)scan_data, sizeof(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 150);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, PrefixAndSuffix) {
    const char *hit_twice = "ceshi3@mailhost.cn";
	const char *hit_suffix = "11111111111ceshi3@mailhost.cn";
	const char *hit_prefix = "ceshi3@mailhost.cn11111111111";
    const char *cont_sz_table_name = "CONTENT_SIZE";
    const char *mail_addr_table_name = "MAIL_ADDR";
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    int thread_id = 0;

    int cont_sz_table_id = maat_get_table_id(maat_instance, cont_sz_table_name);
    ASSERT_GT(cont_sz_table_id, 0);

    int mail_addr_table_id = maat_get_table_id(maat_instance, mail_addr_table_name);
    ASSERT_GT(mail_addr_table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    int ret = maat_scan_integer(maat_instance, cont_sz_table_id, 2015, results,
                                ARRAY_SIZE, &n_hit_result, state);
    
    ret = maat_scan_string(maat_instance, mail_addr_table_id, hit_twice, strlen(hit_twice), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 151);
    EXPECT_EQ(results[1], 152);
    maat_state_reset(state);

    ret = maat_scan_string(maat_instance, mail_addr_table_id, hit_suffix, strlen(hit_suffix), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 151);

    ret = maat_scan_integer(maat_instance, cont_sz_table_id, 2015, results,
                                ARRAY_SIZE, &n_hit_result, state);
    ret = maat_scan_string(maat_instance, mail_addr_table_id, hit_prefix, strlen(hit_prefix), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 152);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, MaatUnescape) {
    const char *scan_data = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *table_name = "KEYWORDS_TABLE";
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 132);
    maat_state_free(state);
    state = NULL;
}

#if 0
TEST_F(MaatStringScan, RegexWithNotContains) {
    const char *should_NOT_hit_scan_data = "new.qq.com/rain/a/TWF2021042600418000";
	const char *should_hit_scan_data = "fakesina.com/rain/a/TWF2021042600418000";
	const char *table_name = "HTTP_URL";
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int ret = maat_scan_string(maat_instance, table_id, should_NOT_hit_scan_data, 
                               strlen(should_NOT_hit_scan_data), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_reset(state);

    ret = maat_scan_string(maat_instance, table_id, should_hit_scan_data, 
                           strlen(should_hit_scan_data), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 183);
    maat_state_free(state);
}
#endif
TEST_F(MaatStringScan, OffsetChunk64) {
    const char *table_name = "IMAGE_FP";
	const char *file_name = "./testdata/mesa_logo.jpg";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp==NULL);

    char scan_data[64];
    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *sp = maat_stream_new(maat_instance, table_id, state);
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
    }
    EXPECT_EQ(pass_flag, 1);
    EXPECT_EQ(results[0], 136);
    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, OffsetChunk1460) {
    const char *table_name = "IMAGE_FP";
	const char *file_name = "./testdata/mesa_logo.jpg";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp==NULL);

    char scan_data[1460];
    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *sp = maat_stream_new(maat_instance, table_id, state);
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
    }
    EXPECT_EQ(pass_flag, 1);
    EXPECT_EQ(results[0], 136);
    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}
#if 0
TEST_F(MaatStringScan, GBKEncodedURL) {
    const char *table_name = "HTTP_URL";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    const char *url_gb2312 = "www.baidu.com/?wd=C%23%D6%D0%B9%FA";

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_instance, table_id, thread_id, url_gb2312,
                               strlen(url_gb2312), results, ARRAY_SIZE, &n_hit_result, 
                               state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 129);
    maat_state_free(state);
    state = NULL;
}
#endif
TEST_F(MaatStringScan, StreamInput) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
	const char *scan_data = "http://www.cyberessays.com/search_results.php?action=search&query=yulingjing,abckkk,1234567";
	const char *table_name = "HTTP_URL";

	int table_id = maat_get_table_id(maat_instance, table_name);
	ASSERT_GT(table_id, 0);

	struct maat_stream *sp = maat_stream_new(maat_instance, table_id, state);
	ASSERT_TRUE(sp != NULL);

	int ret = maat_stream_scan(sp, "www.cyberessays.com", strlen("www.cyberessays.com"),
                                results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_stream_scan(sp, scan_data, strlen(scan_data), results, ARRAY_SIZE,
                            &n_hit_result, state);
	maat_stream_free(sp);

	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 125);
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatStringScan, dynamic_config) {
    const char *table_name = "HTTP_URL";
    char data[128] = "hello world, welcome to maat version4, it's funny.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatStringScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    int ret = maat_scan_string(maat_instance, table_id, data, strlen(data), results, 
                               ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_reset(state);

    const char *compile_table_name = "COMPILE";
    const char *g2c_table_name = "GROUP2COMPILE";

    /* compile table add line */
    long long compile_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    /* group2compile table add line */
    long long group_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group_id,
                                       compile_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* expr table add line */
    long long item_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    const char *keywords = "welcome to maat";
    ret = expr_table_set_line(maat_instance, table_name, MAAT_OP_ADD, item_id, group_id,
                              keywords, NULL, 1, 0, 0, 0); /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    ret = maat_scan_string(maat_instance, table_id, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile_id);
    maat_state_reset(state);

    /* expr table del line */
    ret = expr_table_set_line(maat_instance, table_name, MAAT_OP_DEL, item_id, group_id,
                              keywords, NULL, 1, 0, 0, 0); /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    /* group2compile table del line */
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_DEL, group_id,
                                       compile_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* compile table del line */
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_DEL, compile_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    ret = maat_scan_string(maat_instance, table_id, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(state);
    state = NULL;
}

class MaatIPScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *MaatIPScan::_shared_maat_instance;
struct log_handle *MaatIPScan::logger;

TEST_F(MaatIPScan, IPv4_IPPort) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_instance = MaatIPScan::_shared_maat_instance;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    char ip_str[32] = "10.0.7.100";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);
    uint16_t port = htons(65530);
    int proto = 6;

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    ret = maat_scan_ipv4(maat_instance, table_id, sip, port, proto, 
                         results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 154);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatIPScan, IPv4_Port) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_instance = MaatIPScan::_shared_maat_instance;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    char ip_str[32] = "0.0.0.0";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);
    uint16_t port = htons(20303);
    int proto = 6;

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    ret = maat_scan_ipv4(maat_instance, table_id, sip, port, proto, 
                         results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_reset(state);

    port = htons(64999);
    ret = maat_scan_ipv4(maat_instance, table_id, sip, port, proto, 
                         results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 169);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatIPScan, IPv6_IPPort) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_instance = MaatIPScan::_shared_maat_instance;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_instance, table_name);
    char ip_str[32] = "1001:da8:205:1::101";
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, &sip);
    EXPECT_EQ(ret, 1);
    uint16_t port = htons(65510);
    int proto = 6;

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    ret = maat_scan_ipv6(maat_instance, table_id, sip, port, proto, 
                         results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 155);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatIPScan, BugReport20210515) {
    const char *table_name = "IP_CONFIG";
    struct maat *maat_instance = MaatIPScan::_shared_maat_instance;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_instance, table_name);
    char ip_str[64] = "2409:8915:3430:7e7:8c9b:ff2a:7aa1:e74";
    uint8_t ip_addr[sizeof(struct in6_addr)];
    int ret = inet_pton(AF_INET6, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);
    uint16_t port = htons(41159);
    int proto = 6;

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    ret = maat_scan_ipv6(maat_instance, table_id, ip_addr, port, proto, 
                         results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatIPScan, dynamic_config) {
    const char *table_name = "IP_PLUS_CONFIG";
    struct maat *maat_instance = MaatIPScan::_shared_maat_instance;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_instance, table_name);
    char ip_str[32] = "100.100.100.100";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);
    uint16_t port = htons(100);
    int proto = 6;

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    ret = maat_scan_ipv4(maat_instance, table_id, sip, port, proto, 
                         results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_reset(state);

    const char *compile_table_name = "COMPILE";
    const char *g2c_table_name = "GROUP2COMPILE";

     /* compile table add line */
    long long compile_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, 
                                 compile_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    /* group2compile table add line */
    long long group_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, 
                                       group_id, compile_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* ip table add line */
    long long item_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_instance, table_name, MAAT_OP_ADD, item_id, group_id,
                            IPv4, "100.100.100.100", "100.100.100.100", 100, 100, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    ret = maat_scan_ipv4(maat_instance, table_id, sip, port, proto, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile_id);
    maat_state_reset(state);

    /* ip table del line */
    ret = ip_table_set_line(maat_instance, table_name, MAAT_OP_DEL, item_id, group_id,
                            IPv4, "100.100.100.100", "100.100.100.100", 100, 100, 0);
    EXPECT_EQ(ret, 1);

    /* group2compile table del line */
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_DEL, group_id,
                                       compile_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* compile table del line */
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_DEL, 
                                 compile_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    ret = maat_scan_ipv4(maat_instance, table_id, sip, port, proto, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    maat_state_free(state);
    state = NULL;
}

class MaatIntervalScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_instance);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *MaatIntervalScan::_shared_maat_instance;
struct log_handle *MaatIntervalScan::logger;

TEST_F(MaatIntervalScan, Pure) {	
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "CONTENT_SIZE";
    struct maat *maat_instance = MaatIntervalScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    unsigned int scan_data1 = 2015;

	int ret = maat_scan_integer(maat_instance, table_id, scan_data1, results, ARRAY_SIZE, 
                                &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	maat_state_reset(state);

    unsigned int scan_data2 = 300;
    ret = maat_scan_integer(maat_instance, table_id, scan_data2, results, ARRAY_SIZE, 
                            &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
	maat_state_free(state);
    state = NULL;
}

TEST_F(MaatIntervalScan, IntervalPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "INTERGER_PLUS";
    struct maat *maat_instance = MaatIntervalScan::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    const char *district_str = "interval.plus";

    int ret = maat_state_set_scan_district(state, table_id, district_str, strlen(district_str));
    EXPECT_EQ(ret, 0);

    unsigned int scan_data1 = 2020;
	ret = maat_scan_integer(maat_instance, table_id, scan_data1, results, ARRAY_SIZE, 
                                &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 179);
	maat_state_free(state);
    state = NULL;
}

class NOTLogic : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_instance);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *NOTLogic::_shared_maat_instance;
struct log_handle *NOTLogic::logger;

TEST_F(NOTLogic, OneRegion) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-143.";
	const char *string_should_not_hit = "This string contains both must-contained-string-of-rule-143 and must-not-contained-string-of-rule-143.";
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *table_name = "HTTP_URL";
    struct maat *maat_instance = NOTLogic::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

	int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    maat_state_set_last_scan(state);
	int ret = maat_scan_string(maat_instance, table_id, string_should_hit, strlen(string_should_hit), 
						       results, ARRAY_SIZE, &n_hit_result, state);
						
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 143);
    maat_state_reset(state);
	
    maat_state_set_last_scan(state);
	ret = maat_scan_string(maat_instance, table_id, string_should_not_hit, strlen(string_should_not_hit), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanNotAtLast) {
    const char *string_should_hit="This string ONLY contains must-contained-string-of-rule-144.";
	const char *string_should_not_hit="This string contains both must-contained-string-of-rule-144 and must-not-contained-string-of-rule-144.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *hit_table_name = "HTTP_URL";
    const char *not_hit_table_name = "KEYWORDS_TABLE";
    struct maat *maat_instance = NOTLogic::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int hit_table_id = maat_get_table_id(maat_instance, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    int ret = maat_scan_string(maat_instance, hit_table_id, string_should_hit, strlen(string_should_hit), 
						       results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int not_hit_table_id =  maat_get_table_id(maat_instance, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

	maat_state_set_last_scan(state);
    ret = maat_scan_string(maat_instance, not_hit_table_id, string_should_not_hit, strlen(string_should_not_hit), 
						       results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanIrrelavantAtLast) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-144.";
	const char *string_irrelevant = "This string contiains nothing to hit.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *hit_table_name = "HTTP_URL";
    const char *not_hit_table_name = "KEYWORDS_TABLE";
    struct maat *maat_instance = NOTLogic::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int hit_table_id = maat_get_table_id(maat_instance, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    int ret = maat_scan_string(maat_instance, hit_table_id, string_should_hit, strlen(string_should_hit), 
						       results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int not_hit_table_id = maat_get_table_id(maat_instance, not_hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    maat_state_set_last_scan(state);
    ret = maat_scan_string(maat_instance, not_hit_table_id, string_irrelevant, strlen(string_irrelevant), 
						       results, ARRAY_SIZE, &n_hit_result, state);
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
    const char *not_hit_table_name = "HTTP_URL";
    const char *hit_table_name = "IP_PLUS_CONFIG";
    const char *empty_table_name = "EMPTY_KEYWORD";
    struct maat *maat_instance = NOTLogic::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int not_hit_table_id = maat_get_table_id(maat_instance, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

    int ret = maat_scan_string(maat_instance, not_hit_table_id,
                               string_should_not_hit, strlen(string_should_not_hit), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.8.186", &sip);
    uint16_t port = htons(18611);
    int proto = 6;

    int hit_table_id = maat_get_table_id(maat_instance, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    ret = maat_scan_ipv4(maat_instance, hit_table_id, sip, port, proto, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int empty_table_id = maat_get_table_id(maat_instance, empty_table_name);
    ASSERT_GT(empty_table_id, 0);

    maat_state_set_last_scan(state);
    ret = maat_scan_string(maat_instance, empty_table_id, string_match_no_region, 
                           strlen(string_match_no_region), results, ARRAY_SIZE, 
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 186);
    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanHitAtLastEmptyInteger) {
    const char *string_should_not_hit = "This string should not hit.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *not_hit_table_name = "HTTP_URL";
    const char *hit_table_name = "IP_PLUS_CONFIG";
    const char *empty_table_name = "EMPTY_INTERGER";
    struct maat *maat_instance = NOTLogic::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int not_hit_table_id = maat_get_table_id(maat_instance, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

    int ret = maat_scan_string(maat_instance, not_hit_table_id, string_should_not_hit, 
                               strlen(string_should_not_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.8.187", &sip);
    uint16_t port = htons(18611);
    int proto = 6;

    int hit_table_id = maat_get_table_id(maat_instance, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    ret = maat_scan_ipv4(maat_instance, hit_table_id, sip, port, proto,
                         results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int empty_table_id = maat_get_table_id(maat_instance, empty_table_name);
    ASSERT_GT(empty_table_id, 0);

    maat_state_set_last_scan(state);
    ret = maat_scan_integer(maat_instance, empty_table_id, 2015,
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 187);
    maat_state_free(state);
    state = NULL;
}

TEST_F(NOTLogic, ScanNotIP) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-145.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *hit_table_name = "HTTP_URL";
    const char *not_hit_table_name = "IP_CONFIG";
    struct maat *maat_instance = NOTLogic::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int hit_table_id = maat_get_table_id(maat_instance, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    int ret = maat_scan_string(maat_instance, hit_table_id, string_should_hit, 
                               strlen(string_should_hit), results, ARRAY_SIZE, 
                               &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.6.205", &sip);
    uint16_t port = htons(50001);
    int proto = 6;

    int not_hit_table_id = maat_get_table_id(maat_instance, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

    maat_state_set_last_scan(state);
    ret = maat_scan_ipv4(maat_instance, not_hit_table_id, sip, port, proto, 
                         results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    maat_state_free(state);
    state = NULL;
}

void maat_read_entry_start_cb(int update_type, void *u_para)
{

}

void maat_read_entry_cb(int table_id, const char *table_line, void *u_para)
{
	char ip_str[16] = {0};
	int entry_id = -1, seq = -1;
	unsigned int ip_uint = 0;
	int is_valid = 0;
	unsigned int local_ip_nr = 16820416;//192.168.0.1

	sscanf(table_line, "%d\t%s\t%d\t%d", &seq,ip_str, &entry_id, &is_valid);
	inet_pton(AF_INET, ip_str, &ip_uint);
	if (local_ip_nr == ip_uint) {
		if (is_valid == 1) {
			//printf("Load entry id %d success.\n",entry_id);
			EXPECT_EQ(entry_id, 101);
		} else {
			//printf("Offload entry id %d success.\n",entry_id);
		}
	}
}

void maat_read_entry_finish_cb(void *u_para)
{
	//Maat_feather_t feather=u_para;
	// long long version=0;
	// int ret=0,is_last_updating_table=0;
	// ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version, sizeof(version));
	// EXPECT_EQ(ret, 0);
	// ret=Maat_read_state(feather,MAAT_STATE_LAST_UPDATING_TABLE, &is_last_updating_table, sizeof(is_last_updating_table));
	// EXPECT_EQ(ret, 0);
	//printf("Maat Version %lld at plugin finish callback, is_last_update=%d.\n",version,is_last_updating_table);
}

class PluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_instance);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *PluginTable::_shared_maat_instance;
struct log_handle *PluginTable::logger;

TEST_F(PluginTable, Callback) {
    const char *table_name = "QD_ENTRY_INFO";
    struct maat *maat_instance = PluginTable::_shared_maat_instance;

    int table_id = maat_get_table_id(maat_instance, table_name);
    int ret = maat_table_callback_register(maat_instance, table_id, 
                                           maat_read_entry_start_cb,
                                           maat_read_entry_cb, 
                                           maat_read_entry_finish_cb,
                                           maat_instance);
    EXPECT_EQ(ret, 0);
}

struct plugin_ud {
	char key[256];
    char value[256];
    int id;
	int ref_cnt;
};

void plugin_EX_new_cb(const char *table_name, int table_id, const char *key, 
                      const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
    int valid = 0, tag = 0;
	struct plugin_ud *ud = ALLOC(struct plugin_ud, 1);
    
	int ret = sscanf(table_line, "%d\t%s\t%s\t%d\t%d", &(ud->id), ud->key, ud->value, &valid, &tag);
    EXPECT_EQ(ret, 5);
    ud->ref_cnt = 1;
    *ad = ud;
	(*counter)++;
}

void plugin_EX_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct plugin_ud *ud = (struct plugin_ud *)(*ad);
	if ((__sync_sub_and_fetch(&ud->ref_cnt, 1) == 0)) {
		free(ud);
		*ad = NULL;
	}
}

void plugin_EX_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct plugin_ud *ud = (struct plugin_ud *)(*from);
	__sync_add_and_fetch(&(ud->ref_cnt), 1);
	*to = ud;
}

TEST_F(PluginTable, EX_DATA) {
    const char *table_name = "TEST_PLUGIN_EXDATA_TABLE";
    struct maat *maat_instance = PluginTable::_shared_maat_instance;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int plugin_ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_instance, table_name,
                                                   plugin_EX_new_cb,
                                                   plugin_EX_free_cb,
                                                   plugin_EX_dup_cb,
                                                   0, &plugin_ex_data_counter);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(plugin_ex_data_counter, 4);

    const char *key1 = "HeBei";
    struct plugin_ud *ud = NULL;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_instance, table_id, key1);
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Shijiazhuang");
    EXPECT_EQ(ud->id, 1);
    plugin_EX_free_cb(table_id, (void **)&ud, 0, NULL);

    const char *key2 = "ShanDong";
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_instance, table_id, key2);
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Jinan");
    EXPECT_EQ(ud->id, 3);
    plugin_EX_free_cb(table_id, (void **)&ud, 0, NULL);
}

TEST_F(PluginTable, KEY_TYPE) {
    const char *table_name = "TEST_PLUGIN_KEY_TYPE_TABLE";
    struct maat *maat_instance = PluginTable::_shared_maat_instance;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int plugin_ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_instance, table_name,
                                                   plugin_EX_new_cb,
                                                   plugin_EX_free_cb,
                                                   plugin_EX_dup_cb,
                                                   0, &plugin_ex_data_counter);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(plugin_ex_data_counter, 4);

    long long key1 = 11111111;
    struct plugin_ud *ud = NULL;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_instance, table_id, (char *)&key1);
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Shijiazhuang");
    EXPECT_EQ(ud->id, 1);
    plugin_EX_free_cb(table_id, (void **)&ud, 0, NULL);

    long long key2 = 33333333;
    ud = (struct plugin_ud *)maat_plugin_table_get_ex_data(maat_instance, table_id, (char *)&key2);
    ASSERT_TRUE(ud != NULL);
    EXPECT_STREQ(ud->value, "Jinan");
    EXPECT_EQ(ud->id, 3);
    plugin_EX_free_cb(table_id, (void **)&ud, 0, NULL);
}

class IPPluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_instance);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *IPPluginTable::_shared_maat_instance;
struct log_handle *IPPluginTable::logger;

struct ip_plugin_ud {
	long long rule_id;
	char *buffer;
	int ref_cnt;
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

	ret = get_column_pos(table_line, 5, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	ud->buffer = (char *)calloc(sizeof(char), column_len + 1);
	strncpy(ud->buffer, table_line + column_offset, column_len);
	ud->ref_cnt = 1;
	*ad = ud;
	(*counter)++;
}

void ip_plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct ip_plugin_ud *ud = (struct ip_plugin_ud *)(*ad);
	if ((__sync_sub_and_fetch(&ud->ref_cnt, 1) == 0)) {
		free(ud->buffer);
		free(ud);
		*ad = NULL;
	}
}

void ip_plugin_ex_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct ip_plugin_ud *ud = (struct ip_plugin_ud *)(*from);
	__sync_add_and_fetch(&(ud->ref_cnt), 1);
	*to = ud;
}

TEST_F(IPPluginTable, EX_DATA) {
    int ip_plugin_ex_data_counter = 0;
    const char *table_name = "TEST_IP_PLUGIN_WITH_EXDATA";
    struct maat *maat_instance = IPPluginTable::_shared_maat_instance;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_plugin_table_ex_schema_register(maat_instance, table_name,
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
    ret = maat_ip_plugin_table_get_ex_data(maat_instance, table_id, &ipv4, 
                                           (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(results[0]->rule_id, 101);
    EXPECT_EQ(results[1]->rule_id, 102);

    int i = 0;
    for (i = 0; i < ret; i++) {
		ip_plugin_ex_free_cb(0, (void**)&(results[i]), 0, NULL);
	}

    struct ip_addr ipv6;
    ipv6.ip_type = IPv6;
    inet_pton(AF_INET6, "2001:db8:1234::5210", &(ipv6.ipv6));
    memset(results, 0, sizeof(results));

	ret = maat_ip_plugin_table_get_ex_data(maat_instance, table_id, &ipv6, 
                                           (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 2);
	EXPECT_EQ(results[0]->rule_id, 104);
	EXPECT_EQ(results[1]->rule_id, 103);

	for (i = 0; i < ret; i++) {
		ip_plugin_ex_free_cb(0, (void**)&(results[i]), 0, NULL);
	}

	//Reproduce BugReport-Liumengyan-20210515
	inet_pton(AF_INET6, "240e:97c:4010:104::17", &(ipv6.ipv6));
	ret = maat_ip_plugin_table_get_ex_data(maat_instance, table_id, &ipv6, 
                                           (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 0);
}

class FQDNPluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);  
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *FQDNPluginTable::_shared_maat_instance;
struct log_handle *FQDNPluginTable::logger;

#define FQDN_PLUGIN_EX_DATA
struct fqdn_plugin_ud
{
	int rule_id;
	int catid;
	int ref_cnt;
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
	ret = get_column_pos(table_line, 4, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	sscanf(table_line + column_offset, "catid=%d", &ud->catid);
	ud->ref_cnt = 1;
	*ad = ud;
	(*counter)++;
}

void fqdn_plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct fqdn_plugin_ud *u = (struct fqdn_plugin_ud *)(*ad);
	if ((__sync_sub_and_fetch(&u->ref_cnt, 1) == 0)) {
		free(u);
		*ad = NULL;
	}
}

void fqdn_plugin_ex_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct fqdn_plugin_ud *u = (struct fqdn_plugin_ud *)(*from);
	__sync_add_and_fetch(&(u->ref_cnt), 1);
	*to = u;
}

TEST_F(FQDNPluginTable, EX_DATA) {
    const char *table_name = "TEST_FQDN_PLUGIN_WITH_EXDATA";
    struct maat *maat_instance = FQDNPluginTable::_shared_maat_instance;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int fqdn_plugin_ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_instance, table_name,
                                                    fqdn_plugin_ex_new_cb,
                                                    fqdn_plugin_ex_free_cb,
                                                    fqdn_plugin_ex_dup_cb,
                                                    0, &fqdn_plugin_ex_data_counter);
    ASSERT_TRUE(ret>=0);
	EXPECT_EQ(fqdn_plugin_ex_data_counter, 5);

    int i = 0;
    struct fqdn_plugin_ud *result[4];

	ret = maat_fqdn_plugin_table_get_ex_data(maat_instance, table_id, "www.example1.com", (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_EQ(result[0]->rule_id, 201);
	EXPECT_EQ(result[1]->rule_id, 202);

	for (i = 0; i < ret; i++) {
		fqdn_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}

	ret = maat_fqdn_plugin_table_get_ex_data(maat_instance, table_id, "www.example3.com", (void**)result, 4);
	EXPECT_EQ(ret, 0);

	ret = maat_fqdn_plugin_table_get_ex_data(maat_instance, table_id, "r3---sn-i3belne6.example2.com", (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_TRUE(result[0]->rule_id == 205 || result[0]->rule_id == 204);
	
	for (i = 0; i < ret; i++) {
		fqdn_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}
}

struct bool_plugin_ud {
	int id;
	char *name;
	int ref_cnt;
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

	ud->name = (char *)malloc(column_len+1);
	memcpy(ud->name, table_line+column_offset, column_len);
	ud->ref_cnt = 1;
	*ad = ud;
	(*counter)++;
}
void bool_plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct bool_plugin_ud *u = (struct bool_plugin_ud *)(*ad);
	if ((__sync_sub_and_fetch(&u->ref_cnt, 1) == 0))
	{
		free(u->name);
		free(u);
		*ad = NULL;
	}
}
void bool_plugin_ex_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct bool_plugin_ud *u = (struct bool_plugin_ud *)(*from);
	__sync_add_and_fetch(&(u->ref_cnt), 1);
	*to = u;
}

class BoolPluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *BoolPluginTable::_shared_maat_instance;
struct log_handle *BoolPluginTable::logger;

TEST_F(BoolPluginTable, EX_DATA) {
    int ex_data_counter = 0, i = 0;
	const char *table_name = "TEST_BOOL_PLUGIN_WITH_EXDATA";
    struct maat *maat_instance = BoolPluginTable::_shared_maat_instance;

	int table_id = maat_get_table_id(maat_instance, table_name);
	ASSERT_GT(table_id, 0);

	int ret = maat_plugin_table_ex_schema_register(maat_instance, table_name,
								                   bool_plugin_ex_new_cb,
								                   bool_plugin_ex_free_cb,
								                   bool_plugin_ex_dup_cb,
								                   0, &ex_data_counter);
	ASSERT_TRUE(ret >= 0);
	EXPECT_EQ(ex_data_counter, 6);

	struct bool_plugin_ud *result[6];
	unsigned long long items_1[] = {999};
	ret = maat_bool_plugin_table_get_ex_data(maat_instance, table_id, items_1, 1, (void**)result, 6);
	EXPECT_EQ(ret, 0);
	for (i = 0; i < ret; i++) {
        bool_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}

	unsigned long long items_2[] = {1, 2, 1000};
	ret = maat_bool_plugin_table_get_ex_data(maat_instance, table_id, items_2, 3, (void**)result, 6);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0]->id, 301);
	for (i = 0; i < ret; i++) {
        bool_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}

	unsigned long long items_3[]={101, 102, 1000};
	ret = maat_bool_plugin_table_get_ex_data(maat_instance, table_id, items_3, 3, (void**)result, 6);
	EXPECT_EQ(ret, 4);
	for (i = 0; i < ret; i++) {
        bool_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}

	unsigned long long items_4[]={7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 7};
	ret = maat_bool_plugin_table_get_ex_data(maat_instance, table_id, items_4, sizeof(items_4)/sizeof(unsigned long long), (void**)result, 6);
	EXPECT_EQ(ret, 1);	
	EXPECT_EQ(result[0]->id, 305);
	for (i = 0; i < ret; i++) {
        bool_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}
}

class VirtualTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_instance);
       log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *VirtualTable::_shared_maat_instance;
struct log_handle *VirtualTable::logger;

TEST_F(VirtualTable, basic) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *table_name = "HTTP_RESPONSE_KEYWORDS";
    struct maat *maat_instance = VirtualTable::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    char scan_data[128] = "string1, string2, string3, string4, string5, string6, string7, string8";
    
    int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(state);
    state = NULL;
}

class CompileTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
       maat_free(_shared_maat_instance);
       log_handle_destroy(logger);
    }    

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *CompileTable::_shared_maat_instance;
struct log_handle *CompileTable::logger;

struct rule_ex_param {
	int ref_cnt;
	char name[NAME_MAX];
	int id;
	pthread_mutex_t lock;
};

void compile_ex_param_new(const char *table_name, int table_id, const char *key, 
                          const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	*ad = NULL;

	struct rule_ex_param *param = (struct rule_ex_param *)calloc(sizeof(struct rule_ex_param), 1);
	param->ref_cnt = 1;
	pthread_mutex_init(&(param->lock), NULL);
	
    int compile_id = 0;
    int service_id = 0;
    int action = 0;
    int do_blacklist = 0;
    int do_log = 0;
    char tags[1024] = {0};

	sscanf(table_line, "%d\t%d\t%d\t%d\t%d\t%s\t%*[^:]:%[^,],%d", 
           &compile_id, &service_id, &action, &do_blacklist, &do_log, 
           tags, param->name, &(param->id));
    
	(*counter)++;
	*ad = param;
}

void compile_ex_param_free(int table_id, void **ad, long argl, void *argp)
{
	if (*ad == NULL) {
		return;
	}

	struct rule_ex_param *param = (struct rule_ex_param *)*ad;
	pthread_mutex_lock(&(param->lock));
	param->ref_cnt--;
	if (param->ref_cnt > 0) {	
		pthread_mutex_unlock(&(param->lock));
		return;
	}
	free(param);
}

void compile_ex_param_dup(int table_id, void **to, void **from, long argl, void *argp)
{
	struct rule_ex_param *from_param = *((struct rule_ex_param **)from);
	pthread_mutex_lock(&(from_param->lock));
	from_param->ref_cnt++;
	pthread_mutex_unlock(&(from_param->lock));
	*((struct rule_ex_param**)to) = from_param;
}

TEST_F(CompileTable, CompileRuleUpdate) {
    struct maat *maat_instance = CompileTable::_shared_maat_instance;

    const char *compile_table_name = "COMPILE";
    long long compile_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_DEL, compile_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);
    sleep(WAIT_FOR_EFFECTIVE_S);
}

TEST_F(CompileTable, Conjunction1) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "i.ytimg.com/vi/OtCNcustg_I/hqdefault.jpg?sqp=-oaymwEZCNACELwBSFXyq4qpAwsIARUAAIhCGAFwAQ==&rs=AOn4CLDOp_5fHMaCA9XZuJdCRv4DNDorMg";
    const char *table_name = "HTTP_URL";
    struct maat *maat_instance = CompileTable::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 197);
    EXPECT_EQ(results[1], 141);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_EQ(n_read, 2);

    maat_state_free(state);
    state = NULL;
}

TEST_F(CompileTable, Conjunction2) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "i.ytimg.com/vi/OtCNcustg_I/hqdefault.jpg?sqp=-oaymwEZCNACELwBSFXyq4qpAwsIARUAAIhCGAFwAQ==&rs=AOn4CLDOp_5fHMaCA9XZuJdCRv4DNDorMg";
    const char *table_name = "HTTP_URL";
    struct maat *maat_instance = CompileTable::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 197);
    EXPECT_EQ(results[1], 141);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_EQ(n_read, 2);

    ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

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
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
        log_handle_destroy(logger);
    }    

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};

struct maat *Policy::_shared_maat_instance;
struct log_handle *Policy::logger;

void accept_tags_entry_cb(int table_id, const char *table_line, void *u_para)
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
    struct maat *maat_instance = Policy::_shared_maat_instance;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int callback_times=0;
	int ret = maat_table_callback_register(maat_instance, table_id,
							               NULL,
							               accept_tags_entry_cb, 
							               NULL,
							               &callback_times);
	ASSERT_GE(ret, 0);
	EXPECT_EQ(callback_times, 5);
}

void accept_tags_entry2_cb(int table_id, const char *table_line, void *u_para)
{
	int *callback_times = (int *)u_para;
	(*callback_times)++;
}

TEST_F(Policy, PluginRuleTags2) {
    const char *table_name = "IR_INTERCEPT_IP";
    struct maat *maat_instance = Policy::_shared_maat_instance;

	int table_id = maat_get_table_id(maat_instance, table_name);
	ASSERT_GT(table_id, 0);

	int callback_times = 0;
	int ret = maat_table_callback_register(maat_instance, table_id,
							               NULL,
							               accept_tags_entry2_cb, 
							               NULL,
							               &callback_times);
	ASSERT_GE(ret, 0);
	EXPECT_EQ(callback_times, 2);
}

TEST_F(Policy, CompileRuleTags) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *should_hit = "string bbb should hit";
	const char *should_not_hit = "string aaa should not hit";
	const char *table_name = "HTTP_URL";
	struct maat *maat_instance = Policy::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
	ASSERT_GT(table_id, 0);

	int ret = maat_scan_string(maat_instance, table_id, should_not_hit, 
                               strlen(should_not_hit), results, ARRAY_SIZE,
						        &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	
	ret = maat_scan_string(maat_instance, table_id, should_hit, 
                           strlen(should_hit), results, ARRAY_SIZE,
						   &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);

	maat_state_free(state);
    state = NULL;
}

TEST_F(Policy, CompileEXData) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *url = "firewall should hit";
	const char *table_name = "HTTP_URL";
    const char *compile_table_name = "COMPILE_FIREWALL";
	const char *expect_name = "I have a name";
    struct maat *maat_instance = Policy::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    int compile_table_id = maat_get_table_id(maat_instance, compile_table_name);

    int ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(maat_instance, compile_table_name,
                                                    compile_ex_param_new,
                                                    compile_ex_param_free,
                                                    compile_ex_param_dup,
                                                    0, &ex_data_counter);
    ASSERT_TRUE(ret == 0);
    EXPECT_EQ(ex_data_counter, 1);

    ret = maat_state_set_scan_compile_table(state, compile_table_id);
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_instance, table_id, url, strlen(url),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 198);

    void *ex_data = maat_plugin_table_get_ex_data(maat_instance, compile_table_id, 
                                                 (char *)&results[0]);
    ASSERT_TRUE(ex_data!=NULL);
    struct rule_ex_param *param = (struct rule_ex_param *)ex_data;
	EXPECT_EQ(param->id, 7799);

    str_unescape(param->name);
	EXPECT_EQ(strcmp(param->name, expect_name), 0);
	compile_ex_param_free(compile_table_id, &ex_data, 0, NULL);

	maat_state_free(state);
    state = NULL;
}

TEST_F(Policy, SubGroup) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = Policy::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
	const char *scan_data = "ceshi6@mailhost.cn";
	
	uint32_t ip_addr;
	inet_pton(AF_INET,"10.0.6.205", &ip_addr);
    uint16_t port = htons(50001);

	int table_id = maat_get_table_id(maat_instance, "MAIL_ADDR");
	ASSERT_GT(table_id, 0);
	
	int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data), 
						       results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	
	table_id = maat_get_table_id(maat_instance, "IP_CONFIG");	
	ASSERT_GT(table_id, 0);
	
	ret = maat_scan_ipv4(maat_instance, table_id, ip_addr, port, 6,
                         results, ARRAY_SIZE, &n_hit_result, state);	
	
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 153);
	
	maat_state_free(state);
}

TEST_F(Policy, EvaluationOrder) {
    const char *url = "cavemancircus.com/2019/12/27/pretty-girls-6/";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = Policy::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, "HTTP_URL");
	ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_instance, table_id, url, strlen(url),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 3);
    EXPECT_EQ(results[0], 168);
    EXPECT_EQ(results[1], 167);
    EXPECT_EQ(results[2], 166);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.23.23", &ip_addr);
    uint16_t port = htons(65530);

    table_id = maat_get_table_id(maat_instance, "IP_PLUS_CONFIG");
    ASSERT_GT(table_id, 0);

    memset(results, 0, sizeof(results));
    ret = maat_scan_ipv4(maat_instance, table_id, ip_addr, port, 6,
                         results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 165);
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
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
        log_handle_destroy(logger);
    }   

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance; 
};

struct maat *TableInfo::_shared_maat_instance;
struct log_handle *TableInfo::logger;

TEST_F(TableInfo, Conjunction) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *scan_data = "soq is using table conjunction function.http://www.3300av.com/novel/27122.txt";
    const char *table_name = "HTTP_URL";
    const char *conj_table_name = "HTTP_HOST";
    struct maat *maat_instance = TableInfo::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int conj_table_id = maat_get_table_id(maat_instance, conj_table_name);
    ASSERT_GT(conj_table_id, 0);

    int ret = maat_scan_string(maat_instance, conj_table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 134);
    EXPECT_EQ(results[1], 133);
    maat_state_free(state);
    state = NULL;
}

class MaatFileTest : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *rule_folder = "./ntcrule/full/index";
        const char *table_info = "./file_test_tableinfo.conf";
        int scan_interval_ms = 500;
        int effective_interval_ms = 0;

        struct maat_options *opts = maat_options_new();
        maat_options_set_caller_thread_number(opts, g_thread_num);
        maat_options_set_instance_name(opts, "files");
        maat_options_set_iris(opts, rule_folder, rule_folder);
        maat_options_set_rule_update_checking_interval_ms(opts, scan_interval_ms);
        maat_options_set_rule_effect_interval_ms(opts, effective_interval_ms);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);

        _shared_maat_instance = maat_new(opts, table_info);
        maat_options_free(opts);
        EXPECT_TRUE(_shared_maat_instance != NULL);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
    }

    static struct maat *_shared_maat_instance;
};
struct maat *MaatFileTest::_shared_maat_instance;

TEST_F(MaatFileTest, StreamFiles) {
    const char test_data_dir[64] = "./test_streamfiles";
    const char *table_name = "NTC_HTTP_REQ_BODY";
    int thread_id = 0;
    struct maat *maat_instance = MaatFileTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    struct dirent **name_list;
    int n = my_scandir(test_data_dir, &name_list, NULL, 
                       (int (*)(const void*, const void*))alphasort);
    ASSERT_GT(n, 0);
    struct maat_stream *stream = maat_stream_new(maat_instance, table_id, state);
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
		char *buff = ALLOC(char, file_size);
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

class HierarchyTest : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
        log_handle_destroy(logger);
    }   

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance; 
};

struct maat *HierarchyTest::_shared_maat_instance;
struct log_handle *HierarchyTest::logger;

TEST_F(HierarchyTest, VirtualOfOnePhysical)
{
    const char *http_content = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *http_url = "https://blog.csdn.net/littlefang/article/details/8213058";
    const char *url_table_name = "HTTP_URL";
    const char *keywords_table_name = "HTTP_RESPONSE_KEYWORDS";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = HierarchyTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, url_table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_instance, table_id, http_url, strlen(http_url),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    table_id = maat_get_table_id(maat_instance, keywords_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_instance, table_id, http_content, strlen(http_content),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 160);
    maat_state_reset(state);

    const char *should_not_hit = "2018-10-05 is a keywords of table KEYWORDS_TABLE. Should not hit.";
    ret = maat_scan_string(maat_instance, table_id, should_not_hit, strlen(should_not_hit),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    maat_state_free(state);
    state = NULL;
}

TEST_F(HierarchyTest, VirtualWithVirtual) {
    const char *http_req_hdr_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36";
	const char *http_resp_hdr_cookie = "uid=12345678;BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; sugstore=1;";
    const char *req_table_name = "HTTP_REQUEST_HEADER";
    const char *res_table_name = "HTTP_RESPONSE_HEADER";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = HierarchyTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, req_table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_state_set_scan_district(state, table_id, "User-Agent", strlen("User-Agent"));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_instance, table_id, http_req_hdr_ua, strlen(http_req_hdr_ua),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    table_id = maat_get_table_id(maat_instance, res_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, "Cookie", strlen("Cookie"));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_instance, table_id, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 162);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HierarchyTest, OneGroupInTwoVirtual) {
    const char *http_resp_hdr_cookie = "sessionid=888888;BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; sugstore=1;";
    const char *req_table_name = "HTTP_REQUEST_HEADER";
    const char *res_table_name = "HTTP_RESPONSE_HEADER";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = HierarchyTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, req_table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_state_set_scan_district(state, table_id, "Cookie", strlen("Cookie"));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_instance, table_id, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    table_id = maat_get_table_id(maat_instance, res_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, "Cookie", strlen("Cookie"));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_instance, table_id, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 163);

    maat_state_free(state);
    state = NULL;
}

TEST_F(HierarchyTest, TwoVirtualInOneClause) {
    const char *src_asn = "AS1234", *dst_asn = "AS2345";
	const char *my_county = "Greece.Sparta";
    const char *src_asn_table_name = "SOURCE_IP_ASN";
    const char *dst_asn_table_name = "DESTINATION_IP_ASN";
    const char *ip_table_name = "IP_CONFIG";
    const char *src_ip_geo_table_name = "SOURCE_IP_GEO";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = HierarchyTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    //--------------------------------------
	//			Source ASN & Dest ASN
	//--------------------------------------
    int table_id = maat_get_table_id(maat_instance, src_asn_table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(maat_instance, table_id, src_asn, strlen(src_asn),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    table_id = maat_get_table_id(maat_instance, dst_asn_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_instance, table_id, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 178);

    maat_state_reset(state);

    //--------------------------------------
	//			Source IP & Dest ASN
	//--------------------------------------
    table_id = maat_get_table_id(maat_instance, ip_table_name);
    ASSERT_GT(table_id, 0);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.40.88", &ip_addr);
    uint16_t port = htons(8888);

    ret = maat_scan_ipv4(maat_instance, table_id, ip_addr, port, 6,
                         results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    table_id = maat_get_table_id(maat_instance, dst_asn_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_instance, table_id, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 178);

    maat_state_reset(state);

    //--------------------------------------
	//			Source Geo & Dest ASN
	//--------------------------------------
    table_id = maat_get_table_id(maat_instance, src_ip_geo_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_instance, table_id, my_county, strlen(my_county),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    table_id = maat_get_table_id(maat_instance, dst_asn_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_instance, table_id, dst_asn, strlen(dst_asn),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 178);

    maat_state_free(state);
    state = NULL;
}

class MaatCmdTest : public testing::Test
{
protected:
    static void SetUpTestCase() {
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);

        _shared_maat_instance = maat_new(opts, table_info_path);
        assert(_shared_maat_instance != NULL);
       
        maat_cmd_flushDB(_shared_maat_instance);
        maat_free(_shared_maat_instance);

        maat_options_set_foreign_cont_dir(opts, "./foreign_files/");
        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
    } 

    static struct maat *_shared_maat_instance;
};

struct maat *MaatCmdTest::_shared_maat_instance;

TEST_F(MaatCmdTest, SetIP) {
    long long version_before = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *ip_table_name = "IP_CONFIG";
	const char *compile_table_name = "COMPILE";
    const char *g2c_table_name = "GROUP2COMPILE";
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    /* compile table add line */
    long long compile_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile_id, 
                                     "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* group2compile table add line */
    long long group_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group_id,
                                       compile_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* item table add line */
    const char *ip1 = "172.0.0.1";
    const char *ip2 = "172.0.0.1";
    uint16_t port_min = 53331;
    uint16_t port_max = 53331;
    long long item_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_instance, ip_table_name, MAAT_OP_ADD, item_id, group_id,
                            IPv4, ip1, ip2, port_min, port_max, 0);
    EXPECT_EQ(ret, 1);

    version_before = maat_cmd_get_config_version(maat_instance);
    wait_for_cmd_effective(maat_instance, version_before);
   
    uint32_t sip;
    ret = inet_pton(AF_INET, ip1, &sip);
    EXPECT_EQ(ret, 1);
    uint16_t port = htons(53331);
    int proto = 6;

    int table_id = maat_get_table_id(maat_instance, ip_table_name);
    ASSERT_GE(table_id, 0);

    ret = maat_scan_ipv4(maat_instance, table_id, sip, port, proto, results, 
                         ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile_id);

    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmdTest, SetExpr) {
    const char *scan_data = "Hiredis is a minimalistic C client library for the Redis database.\r\n";
	const char *table_name = "HTTP_URL";
	
	const char *keywords1 = "Hiredis";
	const char *keywords2 = "C Client";
	char escape_buff1[256], escape_buff2[256];
	char keywords[512];

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    maat_cmd_str_escape(escape_buff1, sizeof(escape_buff1), keywords1);
    maat_cmd_str_escape(escape_buff2, sizeof(escape_buff2), keywords2);
    snprintf(keywords, sizeof(keywords), "%s&%s", escape_buff1, escape_buff2);
	long long compile_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 2);

    test_add_expr_command(maat_instance, table_name, compile_id - 1, 0, keywords);
    test_add_expr_command(maat_instance, table_name, compile_id, 0, keywords);
    long long version_before = maat_cmd_get_config_version(maat_instance);

    wait_for_cmd_effective(maat_instance, version_before);

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_TRUE(results[0] == compile_id || results[0] == (compile_id - 1));
    maat_state_reset(state);


    ret = compile_table_set_line(maat_instance, "COMPILE", MAAT_OP_DEL, compile_id-1, 
                                 "null", 1, 0);
    EXPECT_EQ(ret, 1);
    ret = compile_table_set_line(maat_instance, "COMPILE", MAAT_OP_DEL, compile_id, 
                                 "null", 1, 0);
    EXPECT_EQ(ret, 1);
    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    maat_state_reset(state);

    int timeout = 1;
    compile_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    test_add_expr_command(maat_instance, table_name, compile_id, timeout, keywords);
    sleep(timeout + 1);
    ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmdTest, SetExpr8) {
    const char *scan_data8 = "string1, string2, string3, string4, string5, string6, string7, string8";
	const char *scan_data7 = "string1, string2, string3, string4, string5, string6, string7";
	
	const char *compile_table_name = "COMPILE";
	const char *table_name = "KEYWORDS_TABLE";
	const char *g2c_table_name = "GROUP2COMPILE";
	
	const char *keywords8 = "string1&string2&string3&string4&string5&string6&string7&string8";
	const char *keywords7 = "string1&string2&string3&string4&string5&string6&string7";

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    /* compile table add line */
    long long compile_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    /* group2compile table add line */
    long long group_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group_id,
                                        compile_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* expr table add line */
    long long item_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, table_name, MAAT_OP_ADD, item_id, group_id,
                              keywords8, NULL, 1, 0, 0, 0); /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_instance, table_id, scan_data8, strlen(scan_data8),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile_id);
    maat_state_reset(state);

    ret = expr_table_set_line(maat_instance, table_name, MAAT_OP_DEL, item_id, group_id,
                              keywords8, NULL, 1, 0, 0, 0);
    EXPECT_EQ(ret, 1);
    
    ret = expr_table_set_line(maat_instance, table_name, MAAT_OP_ADD, item_id, group_id,
                              keywords7, NULL, 1, 0, 0, 0);
   
    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(&results, 0, sizeof(results));
    ret = maat_scan_string(maat_instance, table_id, scan_data7, strlen(scan_data7),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile_id);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmdTest, RuleIDRecycle) {
    const char *table_name = "HTTP_URL";
	const char *scan_data = "Reuse rule ID is allowed.";
	const char *keywords = "Reuse&rule";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    long long rule_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    test_add_expr_command(maat_instance, table_name, rule_id, 0, keywords);
    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    maat_state_reset(state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);

    del_command(maat_instance, rule_id);
    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    maat_state_reset(state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    test_add_expr_command(maat_instance, table_name, rule_id, 0, keywords);
    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    memset(results, 0, sizeof(results));
    ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    maat_state_free(state);
    state = NULL;

    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], rule_id);
}

TEST_F(MaatCmdTest, ReturnRuleIDWithDescendingOrder) {
    const char *table_name = "HTTP_URL";
	const char *scan_data = "This string will hit mulptiple rules.";
	const char *keywords = "string\\bwill\\bhit";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int i = 0;
    int repeat_times = 4;
    long long expect_rule_id[ARRAY_SIZE] = {0};
    long long rule_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", repeat_times);

    for (i = 0; i < repeat_times; i++) {
        //add in ascending order
        expect_rule_id[i] = rule_id + 1 - repeat_times + i;
        test_add_expr_command(maat_instance, table_name, expect_rule_id[i], 0, keywords);
    }

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    memset(results, 0, sizeof(results));
    int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, state);
    maat_state_free(state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, repeat_times);
    for (i = 0; i < repeat_times; i++) {
        EXPECT_EQ(results[i], expect_rule_id[repeat_times -i - 1]);
    }
}

TEST_F(MaatCmdTest, SubGroup) {
    const char *table_name = "HTTP_URL";
	const char *g2c_table_name = "GROUP2COMPILE";
	const char *g2g_table_name = "GROUP2GROUP";
	const char *compile_table_name = "COMPILE";
	const char *scan_data1 = "www.v2ex.com/t/573028#程序员的核心竞争力是什么";
	const char *keyword1 = "程序员&核心竞争力";
	const char *scan_data2 = "https://ask.leju.com/bj/detail/12189672562229248/?bi=tg&type=sina-pc&pos=index-dbtlwzl&wt_campaign=M_5CE750003F393&wt_source=PDPS_514ACACFD9E770";
	const char *keyword2 = "ask.leju.com/b&/detail/12189672562229248/?&?bi=tg\\&type=sina-pc\\&&\\&pos=index-dbtlwzl\\&&\\&type=sina-pc\\&pos=index-dbtlwzl\\&";
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

     /* compile table add line */
     //compile1
    long long compile1_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, 
                                 compile1_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    //compile2
    long long compile2_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, 
                                 compile2_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    /* group2compile table add line */
    //group1 -> compile1
    long long group1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, 
                                       group1_id, compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //group1 -> compile2
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, 
                                       group1_id, compile2_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //group2 -> group1 -> compile1
    long long group2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2group_table_set_line(maat_instance, g2g_table_name, MAAT_OP_ADD,
                                     group2_id, group1_id, 0);
    EXPECT_EQ(ret, 1);

    /* item1 -> group2 -> group1 -> compile1
                             \
                              \ _  compile2
    */
    long long item_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, table_name, MAAT_OP_ADD, item_id, group2_id,
                              keyword1, NULL, 1, 0, 0, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */

    sleep(4);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], compile2_id);
    EXPECT_EQ(results[1], compile1_id);
    maat_state_reset(state);

    /* item1 -> group2 -> group1 -> compile1
                          \
                           \_ X -> compile2
    */
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_DEL, group1_id,
                                      compile2_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);
    sleep(2);

    ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1), results,
                          ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile1_id);
    maat_state_reset(state);

    /* item1 -> group2 -> group1 -> X 
                  \
                   \_ -> compile2
    */
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_DEL, group1_id,
                                      compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_DEL, compile1_id,
                                 NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group2_id,
                                        compile2_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(2);
    ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile2_id);
    maat_state_reset(state);

    /*  item1 -> group2 -> group1 -> X 
                  \
                   \_ -> compile2
        item2 -> group3
    */
    long long group3_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2group_table_set_line(maat_instance, g2g_table_name, MAAT_OP_ADD, group3_id,
                                     group1_id, 0);
    EXPECT_EQ(ret, 1);

    long long item2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, table_name, MAAT_OP_ADD, item2_id, group3_id,
                              keyword2, NULL, 1, 0, 0, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    sleep(2);
    ret = maat_scan_string(maat_instance, table_id, scan_data2, strlen(scan_data2),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    maat_state_reset(state);

    /*  item1 -> group2 -> group1 -> X
                  \
                   \_ -> compile2
        item2 -> group3
    */
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile1_id,
                                 NULL, 1, 0);
    EXPECT_EQ(ret, 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group1_id,
                                       compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_DEL, compile1_id,
                                 NULL, 1, 0);
    EXPECT_EQ(ret, 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_DEL, group1_id,
                                       compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(2);
    ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile2_id);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmdTest, RefGroup) {
    const char *table_name = "HTTP_URL";
	const char* g2c_table_name = "GROUP2COMPILE";
	const char* compile_table_name = "COMPILE";
	const char* scan_data1 = "m.facebook.com/help/2297503110373101?helpref=hc_nav&refid=69";
	const char* keyword1 = "something-should-not-hit";
	const char* keyword2 = "facebook.com/help/2297503110373101";
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    //TODO: value=0 MAAT_OPT_ENABLE_UPDATE
    long long compile1_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, 
                                     compile1_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    //group1 -> compile1
    long long group1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group1_id,
                                       compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> group1 -> compile1
    long long item1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, table_name, MAAT_OP_ADD, item1_id, group1_id,
                              keyword1, NULL, 1, 0, 0, 0); /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    //TODO: value=1 MAAT_OPT_ENABLE_UPDATE
    sleep(2);
    //TODO: value=0 MAAT_OPT_ENABLE_UPDATE

    /* item1 -> group1 -> X -> compile1
                                 /
                                /
                item2 -> group2
    */
    long long group2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group2_id,
                                       compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    long long item2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, table_name, MAAT_OP_ADD, item2_id, group2_id,
                              keyword2, NULL, 1, 0, 0, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_DEL, 
                                 compile1_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, 
                                 compile1_id, NULL, 1, 0);
    EXPECT_EQ(ret, 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_DEL, 
                                       group1_id, compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, 
                                       group2_id, compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    //TODO value=1 MAAT_OPT_ENABLE_UPDATE

    sleep(2);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile1_id);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmdTest, VirtualTable) {
    const char* g2c_table_name = "GROUP2COMPILE";
	const char* compile_table_name = "COMPILE";
	const char* table_name="HTTP_SIGNATURE";
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    long long compile1_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, 
                                     compile1_id, NULL, 2, 0);
    EXPECT_EQ(ret, 1);

    //group1 -> compile1
    long long group1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group1_id,
                                       compile1_id, 0, "HTTP_REQUEST_HEADER", 1, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> group1 -> compile1
    long long item1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, table_name, MAAT_OP_ADD, item1_id, group1_id,
                              "AppleWebKit", "User-Agent", 0, 0, 0, 0);/*EXPR_TYPE_STRING MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    /* item1 -> group1 -> compile1
                              /
                      group2_/
    */
    long long group2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group2_id,
                                       compile1_id, 0, "HTTP_RESPONSE_HEADER", 2, 0);
    EXPECT_EQ(ret, 1);

    /* item1 -> group1 -> compile1
                              /
              item2 -> group2/
    */
    long long item2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, table_name, MAAT_OP_ADD, item2_id, group2_id,
                              "uid=12345678;", "Cookie", 0, 0, 0, 0);/*EXPR_TYPE_STRING MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    sleep(2);

	const char* http_req_hdr_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36";
	const char* http_resp_hdr_cookie = "uid=12345678;BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; sugstore=1;";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_instance, "HTTP_REQUEST_HEADER");
    ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, "User-Agent", strlen("User-Agent"));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_instance, table_id, http_req_hdr_ua, strlen(http_req_hdr_ua),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    table_id = maat_get_table_id(maat_instance, "HTTP_RESPONSE_HEADER");
    ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, "Cookie", strlen("Cookie"));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_instance, table_id, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile1_id);
    maat_state_reset(state);

    //delete group1
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_DEL, group1_id,
                                       compile1_id, 0, "HTTP_REQUEST_HEADER", 1, 0);
    EXPECT_EQ(ret, 1);
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_DEL, compile1_id,
                                 NULL, 2, 0);
    EXPECT_EQ(ret, 1);
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile1_id,
                                 NULL, 1, 0);
    EXPECT_EQ(ret, 1);
    sleep(2);

    table_id = maat_get_table_id(maat_instance, "HTTP_RESPONSE_HEADER");
    ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, "Cookie", strlen("Cookie"));
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(maat_instance, table_id, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile1_id);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmdTest, SetLines) {
    int i = 0;
    const int TEST_CMD_LINE_NUM = 4;
    const char *table_name = "QD_ENTRY_INFO";
    struct maat_cmd_line line_rule;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
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
        expect_rule_id[i] = maat_cmd_incrby(maat_instance, "TEST_PLUG_SEQ", 1);
        line_rule.rule_id = expect_rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_add[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_instance, &line_rule);
        EXPECT_GT(ret, 0);
    }

    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_id = expect_rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_del[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_instance, &line_rule);
        EXPECT_GT(ret, 0);
    }
}

int g_test_update_paused = 0;
void pause_update_test_entry_cb(int table_id,const char* table_line,void* u_para)
{
	char status[32] = {0};
	int entry_id = -1, seq = -1;
	int is_valid = 0;

	sscanf(table_line, "%d\t%s\t%d\t%d", &seq, status, &entry_id, &is_valid);
	EXPECT_EQ(g_test_update_paused, 0);
}

TEST_F(MaatCmdTest, PauseUpdate) {
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    const char *table_name = "QD_ENTRY_INFO";

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_table_callback_register(maat_instance, table_id, NULL,
                                           pause_update_test_entry_cb,
                                           NULL, NULL);
    //TODO: value = 0 MAAT_OPT_ENABLE_UPDATE
    g_test_update_paused = 1;

    char *line = NULL;
    struct maat_cmd_line line_rule;
    line_rule.rule_id = maat_cmd_incrby(maat_instance, "TEST_PLUG_SEQ", 1);
    line_rule.table_name = table_name;
    asprintf(&line, "1\t192.168.0.1\t101\t1");
    line_rule.table_line = line;
    line_rule.expire_after = 0;

    ret = maat_cmd_set_line(maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);
    free(line);
    
    g_test_update_paused = 0;
    //TODO: value = 1 MAAT_OPT_ENABLE_UPDATE
}

void prepare_file_to_set(const char* filename, char** file_buff, size_t *file_size, 
                         char* file_key, size_t key_size)
{
	int i=0;
	struct stat file_info;
	unsigned char md5[MD5_DIGEST_LENGTH];
	char md5string[MD5_DIGEST_LENGTH+1];
	memset(md5, 0, sizeof(md5));
	memset(md5string, 0, sizeof(md5string));

	int ret = stat(filename, &file_info);
	ASSERT_TRUE(ret == 0);

	FILE *fp=fopen(filename,"r");
	ASSERT_FALSE(fp == NULL);

	*file_size = file_info.st_size;
    *file_buff = ALLOC(char, *file_size);
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
void foreign_key_test_entry_cb(int table_id, const char *table_line, void *u_para)
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

TEST_F(MaatCmdTest, SetFile) {
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    const char* table_name = "TEST_FOREIGN_KEY";

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_table_callback_register(maat_instance, table_id, NULL,
                                           foreign_key_test_entry_cb,
                                           NULL, NULL);
    EXPECT_EQ(ret, 0);

    const char *file1_name = "./testdata/digest_test.data";
    const char *file2_name = "./testdata/mesa_logo.jpg";	
	char *file_buff = NULL, file1_key[256], file2_key[256];
	size_t file_size = 0;

    prepare_file_to_set(file1_name, &file_buff, &file_size, file1_key, sizeof(file1_key));
    ret = maat_cmd_set_file(maat_instance, file1_key, file_buff, file_size, MAAT_OP_ADD);
	EXPECT_EQ(ret, 1);
	free(file_buff);
	file_buff = NULL;

    prepare_file_to_set(file2_name, &file_buff, &file_size, file2_key, sizeof(file2_key));
	ret = maat_cmd_set_file(maat_instance, file2_key, file_buff, file_size, MAAT_OP_ADD);
	EXPECT_EQ(ret, 1);
	free(file_buff);
	file_buff = NULL;
	g_test_foregin_read_OK = 0;

    char line[1024] = {0};
    int tag = 0;
    struct maat_cmd_line line_rule;
    line_rule.rule_id = maat_cmd_incrby(maat_instance, "TEST_PLUG_SEQ", 1);
    line_rule.table_name = table_name;
    snprintf(line, sizeof(line),"%lld\t2\t%d\t1\t%s\tredis://%s\t%s\tredis://%s\tEnd",
             line_rule.rule_id, tag, file1_name, file1_key, file2_name, file2_key);
    line_rule.table_line = line;
    line_rule.expire_after = 0;

    ret = maat_cmd_set_line(maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);
	sleep(WAIT_FOR_EFFECTIVE_S * 2);//wait for callback triggered.
	EXPECT_EQ(g_test_foregin_read_OK, 1);

    g_test_foreign_del_OK = 0;
    ret = maat_cmd_set_file(maat_instance, file1_key, NULL, 0, MAAT_OP_DEL);
    EXPECT_EQ(ret, 1);
    ret = maat_cmd_set_file(maat_instance, file2_key, NULL, 0, MAAT_OP_DEL);
    EXPECT_EQ(ret, 1);

    struct maat_cmd_line line_rule_del;
    line_rule_del.rule_id = line_rule.rule_id;
    line_rule_del.table_name = line_rule.table_name;
    memset(line, 0, sizeof(line));
    snprintf(line, sizeof(line), "%lld\t2\t%d\t0\t%s\tredis://%s\t%s\tredis://%s\tEnd",
             line_rule.rule_id, tag, file1_name, file1_key, file2_name, file2_key);
    line_rule_del.table_line = line;
    line_rule_del.expire_after = 0;
    ret = maat_cmd_set_line(maat_instance, &line_rule_del);
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
    line_rule.rule_id = maat_cmd_incrby(maat_instance, "TEST_PLUG_SEQ", 1);
    line_rule.table_name=table_name;
    snprintf(line, sizeof(line),"%lld\t2\t%d\t1\t%s\tredis://%s\t%s\t%s\tEnd",
             line_rule.rule_id, tag, file1_name, file1_key, empty_file_name, "null");
	line_rule.table_line = line;
	line_rule.expire_after = 0;

    g_test_foregin_read_OK = 0;

    ret = maat_cmd_set_line(maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);
	sleep(WAIT_FOR_EFFECTIVE_S * 2);//wait for callback triggered.
	EXPECT_EQ(g_test_foregin_read_OK, 1);
}

struct user_info {
	char name[256];
	char ip_addr[32];
	int id;
	int ref_cnt;
};
void plugin_ex_new_cb(const char *table_name, int table_id, const char *key, 
                      const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	struct user_info *u = ALLOC(struct user_info, 1);
	int valid = 0, tag = 0;
	int ret = sscanf(table_line, "%d\t%s\t%s%d\t%d", &(u->id), u->ip_addr, u->name, &valid, &tag);
	EXPECT_EQ(ret, 5);
	u->ref_cnt = 1;
	*ad = u;
	(*counter)++;
}

void plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct user_info *u = (struct user_info *)(*ad);
	if ((__sync_sub_and_fetch(&u->ref_cnt, 1) == 0)) {
		free(u);
		*ad = NULL;
	}
}

void plugin_ex_dup_cb(int table_id,	void **to, void **from, long argl, void *argp)
{
	struct user_info *u = (struct user_info *)(*from);
	__sync_add_and_fetch(&(u->ref_cnt), 1);
	*to = u;
}

TEST_F(MaatCmdTest, PluginEXData) {
    const char *table_name = "TEST_PLUGIN_EXDATA_TABLE";
    const int TEST_CMD_LINE_NUM = 4;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
	const char *table_line_add[TEST_CMD_LINE_NUM] = {"1\t192.168.0.1\tmahuateng\t1\t0",
							                     "2\t192.168.0.2\tliuqiangdong\t1\t0",
							                     "3\t192.168.0.3\tmayun\t1\t0",
							                     "4\t192.168.0.4\tliyanhong\t1\t0"};

    const char *table_line_del[TEST_CMD_LINE_NUM] = {"1\t192.168.0.1\tmahuateng\t0\t0",
							                     "2\t192.168.0.2\tliuqiangdong\t0\t0",
							                     "3\t192.168.0.3\tmayun\t0\t0",
							                     "4\t192.168.0.4\tliyanhong\t0\t0"};

	int table_id = maat_get_table_id(maat_instance, table_name);
	ASSERT_GT(table_id, 0);
    
    int i = 0, ret = 0;
    struct maat_cmd_line line_rule;
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    /* 1st line */
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_instance, "TEST_PLUG_SEQ", 1);
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_add[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_instance, &line_rule);
        EXPECT_GT(ret, 0);
    }
	
    sleep(WAIT_FOR_EFFECTIVE_S * 2);
    int ex_data_counter = 0;
	ret = maat_plugin_table_ex_schema_register(maat_instance, table_name,
								               plugin_ex_new_cb,
								               plugin_ex_free_cb,
								               plugin_ex_dup_cb,
								               0, &ex_data_counter);
	ASSERT_TRUE(ret >= 0);
	EXPECT_EQ(ex_data_counter, TEST_CMD_LINE_NUM);
	
	struct user_info *uinfo = NULL;
    const char *key1 = "192.168.0.2";
	uinfo = (struct user_info *)maat_plugin_table_get_ex_data(maat_instance, 
                                                              table_id, key1);
	ASSERT_TRUE(uinfo != NULL);
	EXPECT_EQ(0, strcmp(uinfo->name, "liuqiangdong"));
	EXPECT_EQ(uinfo->id, 2);
	plugin_ex_free_cb(table_id, (void**)&uinfo, 0, NULL);
    
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = rule_id[1];
    line_rule.table_name = table_name;
    line_rule.table_line = table_line_del[1];
    line_rule.expire_after = 0;

	ret = maat_cmd_set_line(maat_instance, &line_rule);
	EXPECT_GT(ret, 0);
	
	sleep(WAIT_FOR_EFFECTIVE_S);
    const char *key2 = "192.168.0.2";
	uinfo = (struct user_info *)maat_plugin_table_get_ex_data(maat_instance, 
                                                              table_id, key2);
	ASSERT_TRUE(uinfo == NULL);
}

TEST_F(MaatCmdTest, UpdateIPPlugin) {
    const char *table_name = "TEST_IP_PLUGIN_WITH_EXDATA";
	const int TEST_CMD_LINE_NUM = 4;
	struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
	const char *table_line_add[TEST_CMD_LINE_NUM] = {
        "101\t4\t192.168.30.99\t192.168.30.101\tSomething-like-json\t1\trange",
		"102\t4\t192.168.30.90\t192.168.30.128\tBigger-range-should-in-the-back\t1\trange",
        "103\t6\t2001:db8:1234::\t2001:db8:1235::\tBigger-range-should-in-the-back\t1\trange",
		"104\t6\t2001:db8:1234::1\t2001:db8:1234::5210\tSomething-like-json\t1\trange"};
    const char *table_line_del[TEST_CMD_LINE_NUM] = {
        "101\t4\t192.168.30.99\t192.168.30.101\tSomething-like-json\t0\trange",
		"102\t4\t192.168.30.90\t192.168.30.128\tBigger-range-should-in-the-back\t0\trange",
        "103\t6\t2001:db8:1234::\t2001:db8:1235::\tBigger-range-should-in-the-back\t0\trange",
		"104\t6\t2001:db8:1234::1\t2001:db8:1234::5210\tSomething-like-json\t0\trange"};

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);
    
    int i = 0, ret = 0;
    struct maat_cmd_line line_rule;
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    //add lines
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_instance, "TEST_PLUG_SEQ", 1);
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_add[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_instance, &line_rule);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S);

    int ex_data_counter = 0;
	ret = maat_plugin_table_ex_schema_register(maat_instance, table_name,
								               ip_plugin_ex_new_cb,
								               ip_plugin_ex_free_cb,
								               ip_plugin_ex_dup_cb,
								               0, &ex_data_counter);
	ASSERT_TRUE(ret >= 0);
	EXPECT_EQ(ex_data_counter, TEST_CMD_LINE_NUM);

    struct ip_addr ipv4, ipv6;
    struct ip_plugin_ud *results[ARRAY_SIZE];
    ipv4.ip_type = 4;
    inet_pton(AF_INET, "192.168.30.100", &(ipv4.ipv4));

    memset(results, 0, sizeof(results));
    ret = maat_ip_plugin_table_get_ex_data(maat_instance, table_id, &ipv4, (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(results[0]->rule_id, 101);
    EXPECT_EQ(results[1]->rule_id, 102);
    for (i = 0; i < ret; i++) {
        ip_plugin_ex_free_cb(table_id, (void **)&(results[i]), 0, NULL);
    }

    ipv6.ip_type = 6;
    inet_pton(AF_INET6, "2001:db8:1234::5210", &(ipv6.ipv6));

    memset(results, 0, sizeof(results));
    ret = maat_ip_plugin_table_get_ex_data(maat_instance, table_id, &ipv6, (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(results[0]->rule_id, 104);
    EXPECT_EQ(results[1]->rule_id, 103);
    for (i = 0; i < ret; i++) {
        ip_plugin_ex_free_cb(table_id, (void **)&(results[i]), 0, NULL);
    }

    //del lines
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_del[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_instance, &line_rule);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    memset(results, 0, sizeof(results));
    ret = maat_ip_plugin_table_get_ex_data(maat_instance, table_id, &ipv4, (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 0);
}

TEST_F(MaatCmdTest, UpdateFQDNPlugin) {
    const char *table_name = "TEST_FQDN_PLUGIN_WITH_EXDATA";
	const int TEST_CMD_LINE_NUM = 5;
	struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    const char *table_line_add[TEST_CMD_LINE_NUM]={
		"201\t0\twww.example1.com\tcatid=1\t1",
		"202\t1\t.example1.com\tcatid=1\t1",
		"203\t0\tnews.example1.com\tcatid=2\t1",
		"204\t0\tr3---sn-i3belne6.example2.com\tcatid=3\t1",
		"205\t0\tr3---sn-i3belne6.example2.com\tcatid=3\t1"};
    const char *table_line_del[TEST_CMD_LINE_NUM]={
		"201\t0\twww.example1.com\tcatid=1\t0",
		"202\t1\t.example1.com\tcatid=1\t0",
		"203\t0\tnews.example1.com\tcatid=2\t0",
		"204\t0\tr3---sn-i3belne6.example2.com\tcatid=3\t0",
		"205\t0\tr3---sn-i3belne6.example2.com\tcatid=3\t0"};
    
    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);
    
    int i = 0, ret = 0;
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    struct maat_cmd_line line_rule;
    //add lines
    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_instance, "TEST_PLUG_SEQ", 1);
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_add[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_instance, &line_rule);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    int ex_data_counter = 0;
    ret = maat_plugin_table_ex_schema_register(maat_instance, table_name,
                                               fqdn_plugin_ex_new_cb,
                                               fqdn_plugin_ex_free_cb,
                                               fqdn_plugin_ex_dup_cb,
                                               0, &ex_data_counter);
    ASSERT_TRUE(ret >= 0);
	EXPECT_EQ(ex_data_counter, 5);

    struct fqdn_plugin_ud *results[ARRAY_SIZE];
    memset(results, 0, sizeof(results));

    ret = maat_fqdn_plugin_table_get_ex_data(maat_instance, table_id,
                                             "r3---sn-i3belne6.example2.com", 
                                             (void**)results, ARRAY_SIZE);
    ASSERT_EQ(ret, 2);
    for (i = 0; i < ret; i++) {
		fqdn_plugin_ex_free_cb(0, (void**)&(results[i]), 0, NULL);
	}

    //del lines
    for (i = 3; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_del[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_instance, &line_rule);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S);
    ret = maat_fqdn_plugin_table_get_ex_data(maat_instance, table_id, 
                                            "r3---sn-i3belne6.example2.com", 
                                            (void**)results, ARRAY_SIZE);
    ASSERT_EQ(ret, 0);                                 
}

TEST_F(MaatCmdTest, UpdateBoolPlugin) {
    const char *table_name = "TEST_BOOL_PLUGIN_WITH_EXDATA";
	const int TEST_CMD_LINE_NUM = 6;
	struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
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
    
    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);
    
    long long rule_id[TEST_CMD_LINE_NUM] = {0};
    struct maat_cmd_line line_rule;
    int i = 0, ret = 0;

    for (i = 0; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        rule_id[i] = maat_cmd_incrby(maat_instance, "TEST_PLUG_SEQ", 1);
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_add[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_instance, &line_rule);
        EXPECT_GT(ret, 0);
    }

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    int ex_data_counter = 0;
    ret = maat_plugin_table_ex_schema_register(maat_instance, table_name,
								               bool_plugin_ex_new_cb,
								               bool_plugin_ex_free_cb,
								               bool_plugin_ex_dup_cb,
								               0, &ex_data_counter);
	ASSERT_TRUE(ret>=0);
	EXPECT_EQ(ex_data_counter, 6);

    unsigned long long items[] = {101, 102, 1000};
    struct bool_plugin_ud *results[ARRAY_SIZE];
    memset(results, 0, sizeof(results));
    ret = maat_bool_plugin_table_get_ex_data(maat_instance, table_id, items, 3,
                                             (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 4);
	for (i = 0; i < ret; i++) {
		bool_plugin_ex_free_cb(0, (void**)&(results[i]), 0, NULL);
	}

    for (i = 3; i < TEST_CMD_LINE_NUM; i++) {
        memset(&line_rule, 0, sizeof(line_rule));
        line_rule.rule_id = rule_id[i];
        line_rule.table_name = table_name;
        line_rule.table_line = table_line_del[i];
        line_rule.expire_after = 0;

        ret = maat_cmd_set_line(maat_instance, &line_rule);
        EXPECT_GT(ret, 0);
    }
    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    memset(results, 0, sizeof(results));
    ret = maat_bool_plugin_table_get_ex_data(maat_instance, table_id, items, 3,
                                             (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    for (i = 0; i < ret; i++) {
		bool_plugin_ex_free_cb(0, (void**)&(results[i]), 0, NULL);
	}
}
#define COMPILE_ID_NUMS 1000
TEST_F(MaatCmdTest, GroupInMassCompiles) {
    const char* g2c_table_name = "GROUP2COMPILE";
	const char* compile_table_name = "COMPILE";
	const char* table_url = "HTTP_URL";
	const char* table_appid = "APP_ID";
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    //item_url1 -> group1
    long long group1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    long long item1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    int ret = expr_table_set_line(maat_instance, table_url, MAAT_OP_ADD, item1_id, group1_id,
                              "baidu.com&tsg", NULL, 1, 0, 0, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    //item_url2 -> group2
    long long group2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    long long item2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, table_url, MAAT_OP_ADD, item2_id, group2_id,
                              "baidu.com&zhengzhou", NULL, 1, 0, 0, 0);/* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    //item_appid -> group3
    long long group3_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    long long item3_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = intval_table_set_line(maat_instance, table_appid, MAAT_OP_ADD, item3_id, group3_id,
                                100, 100, NULL, 0);
    EXPECT_EQ(ret, 1);

    /*  item_url1 -> group1 -> compile[0 ~ COMPILE_ID_NUMS] 
                                /
          item_appid -> group3_/
    */
    int i = 0;
    long long compile_id[COMPILE_ID_NUMS] = {0};
    for (i = 0; i < COMPILE_ID_NUMS; i++) {
        compile_id[i] = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
        ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile_id[i],
                                     "mass_compile", 2, 0);
        EXPECT_EQ(ret, 1);
    }

    for (i = 0; i < COMPILE_ID_NUMS; i++) {
        ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group1_id,
                                           compile_id[i], 0, "null", 0, 0);
        EXPECT_EQ(ret, 1);

        ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group3_id,
                                           compile_id[i], 0, "null", 2, 0);
        EXPECT_EQ(ret, 1);
    }

    /* item_url2 -> group2 -> target_compile
                                    /
              item_appid -> group3_/
    */
    long long target_compile_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, target_compile_id,
                                 NULL, 2, 0);
    EXPECT_EQ(ret, 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group2_id,
                                       target_compile_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group3_id,
                                       target_compile_id, 0, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url1 = "https://www.baidu.com/s?wd=tsg";
	const char* http_url2 = "https://www.baidu.com/s?wd=zhengzhou&rsv_spt=1&rsv_iqid=0x8b4cae8100000560&issp=1&f=8&rsv_bp=1";

    int url_table_id = maat_get_table_id(maat_instance, table_url);
    ASSERT_GT(url_table_id, 0);

    int appid_table_id = maat_get_table_id(maat_instance, table_appid);
    ASSERT_GT(appid_table_id, 0);

    long long results[4] = {0};
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_instance, url_table_id, http_url2, strlen(http_url2),
                           results, 4, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_integer(maat_instance, appid_table_id, 100, results, 4,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], target_compile_id);
    maat_state_reset(state);

    ret = maat_scan_string(maat_instance, url_table_id, http_url1, strlen(http_url1),
                           results, 4, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_integer(maat_instance, appid_table_id, 100, results, 4,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 4);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmdTest, HitPath) {
    const char *g2g_table_name = "GROUP2GROUP";
	const char *g2c_table_name = "GROUP2COMPILE";
	const char *compile_table_name = "COMPILE";
	const char *http_sig_table_name = "HTTP_SIGNATURE";
	const char *ip_table_name = "IP_CONFIG";
	const char *keywords_table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    /* compile1 */
    long long compile1_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile1_id,
                                     NULL, 2, 0);
    EXPECT_EQ(ret, 1);

    //group1 -> compile1
    long long group1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group1_id,
                                       compile1_id, 0, "HTTP_REQUEST_HEADER", 1, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> group1 -> compile1
    long long item1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, http_sig_table_name, MAAT_OP_ADD, item1_id, group1_id,
                              "graph_theory", "URL", 0, 0, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    /* item1 -> group1 -> compile1
                             /
                    group21_/
    */
    long long group21_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group21_id,
                                       compile1_id, 0, "HTTP_RESPONSE_HEADER", 2, 0);
    EXPECT_EQ(ret, 1);

    /* item1 -> group1 -> compile1
                            /
        group2 -> group21 _/
    */
    long long group2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2group_table_set_line(maat_instance, g2g_table_name, MAAT_OP_ADD, group2_id,
                                     group21_id, 0);
    EXPECT_EQ(ret, 1);

    /*       item1 -> group1 -> compile1
                                    /
       item2 -> group2 -> group21 _/
    */
    long long item2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, http_sig_table_name, MAAT_OP_ADD, item2_id, group2_id,
                              "time=2020-02-11", "Cookie", 0, 0, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    //item3 -> group3, group3 is not referenced by any compile.
    long long item3_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    long long group3_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = ip_table_set_line(maat_instance, ip_table_name, MAAT_OP_ADD, item3_id, group3_id,
                            IPv4, "220.181.38.148", "220.181.38.149", 0, 65535, 0);
    EXPECT_EQ(ret, 1);

    char temp[1024]={0};
    //item4 -> group4, group4 is not referenced by any compile.
    long long item4_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    long long group4_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = expr_table_set_line(maat_instance, keywords_table_name, MAAT_OP_ADD, item4_id, group4_id,
                              maat_cmd_str_escape(temp, sizeof(temp), "a finite or infinite"),
                              NULL, 0, 0, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* http_url = "en.wikipedia.org/wiki/Path_(graph_theory)";
	const char* http_resp_hdr_cookie = "laptop=thinkpad X1 extrem;time=2020-02-11T15:34:00;main[XWJOKE]=hoho; Hm_lvt_bbac0322e6ee13093f98d5c4b5a10912=1578874808;";

    int table_id = maat_get_table_id(maat_instance, "HTTP_REQUEST_HEADER");
    ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, "URL", strlen("URL"));
    EXPECT_EQ(ret, 0);

    int Nth_scan = 0;

    Nth_scan++;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    ret = maat_scan_string(maat_instance, table_id, http_url, strlen(http_url),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    struct maat_hit_path hit_path[128];
    memset(hit_path, 0, sizeof(hit_path));
    int n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 1);

    int path_idx = 0;
    EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item1_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group1_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, group1_id);
	EXPECT_EQ(hit_path[path_idx].vtable_id, table_id);
	EXPECT_EQ(hit_path[path_idx].compile_id, -1);

    table_id = maat_get_table_id(maat_instance, "HTTP_RESPONSE_HEADER");
	ASSERT_GT(table_id, 0);

    ret = maat_state_set_scan_district(state, table_id, "Cookie", strlen("Cookie"));
    EXPECT_EQ(ret, 0);

    Nth_scan++;
    ret = maat_scan_string(maat_instance, table_id, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie),
                          results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile1_id);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 2);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan-1);
	EXPECT_EQ(hit_path[path_idx].item_id, item1_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group1_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, group1_id);
    EXPECT_EQ(hit_path[path_idx].compile_id, compile1_id);

    path_idx++;
    ASSERT_EQ(path_idx, 1);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item2_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group2_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, group21_id);
	EXPECT_EQ(hit_path[path_idx].vtable_id, table_id);
	EXPECT_EQ(hit_path[path_idx].compile_id, compile1_id);

    const char* keywords1="In graph theory, a path in a graph is a finite or infinite \
sequence of edges which joins a sequence of vertices which, by most definitions,\
are all distinct (and since the vertices are distinct, so are the edges). ";
	const char* keywords2="A directed path in a directed graph is a finite or infinite\
sequence of edges which joins a sequence of distinct vertices, but with the added restriction\
that the edges be all directed in the same direction.";

    table_id = maat_get_table_id(maat_instance, keywords_table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *stream = maat_stream_new(maat_instance, table_id, state);
    Nth_scan++;
    ret = maat_stream_scan(stream, keywords1, strlen(keywords1), results, ARRAY_SIZE,
                          &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 3);

    path_idx++;
	ASSERT_EQ(path_idx, 2);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item4_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group4_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, -1);
	EXPECT_EQ(hit_path[path_idx].vtable_id, 0);
	EXPECT_EQ(hit_path[path_idx].compile_id, -1);

    table_id = maat_get_table_id(maat_instance, ip_table_name);
    ASSERT_GT(table_id, 0);

    Nth_scan++;
    uint32_t ip_addr;
    inet_pton(AF_INET, "220.181.38.148", &ip_addr);
    uint16_t port = htons(17272);
    ret = maat_scan_ipv4(maat_instance, table_id, ip_addr, port, 6, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 4);

    path_idx++;
	ASSERT_EQ(path_idx, 3);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item3_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group3_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, -1);
	EXPECT_EQ(hit_path[path_idx].vtable_id, 0);
	EXPECT_EQ(hit_path[path_idx].compile_id, -1);

    Nth_scan++;   
    ret = maat_stream_scan(stream, keywords2, strlen(keywords2), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 5);

    path_idx++;
	ASSERT_EQ(path_idx, 4);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].item_id, item4_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group4_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, -1);
	EXPECT_EQ(hit_path[path_idx].vtable_id, 0);
	EXPECT_EQ(hit_path[path_idx].compile_id, -1);
    maat_stream_free(stream);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmdTest, SameScanStatusWhenClauseUpdate_TSG6419) {
    const char *g2c_table_name = "GROUP2COMPILE";
	const char* compile_table_name = "COMPILE";
	const char* ip_table_name = "IP_PLUS_CONFIG";
    const char *app_id_table_name = "APP_ID";
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    long long compile1_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile1_id,
                                     NULL, 2, 0);
    EXPECT_EQ(ret, 1);

    /* item11 -> group11 -> clause1 -> compile1
                                          /
           item21 -> group21 -> clause2 _/
    */
    long long group11_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group11_id,
                                       compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    long long item11_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_instance, ip_table_name, MAAT_OP_ADD, item11_id, group11_id,
                            IPv4, "192.168.2.1", "192.168.2.4", 0, 65535, 0);
    EXPECT_EQ(ret, 1);

    long long group21_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group21_id,
                                       compile1_id, 0, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    long long item21_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = intval_table_set_line(maat_instance, app_id_table_name, MAAT_OP_ADD, item21_id,
                                group21_id, 31, 31, NULL, 0);
    EXPECT_EQ(ret, 1);
    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.2.2", &ip_addr);
    uint16_t port = htons(50001);

    int table_id = maat_get_table_id(maat_instance, ip_table_name);
    ret = maat_scan_ipv4(maat_instance, table_id, ip_addr, port, 6, results, ARRAY_SIZE, 
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int scan_app_id = 32;
    table_id = maat_get_table_id(maat_instance, app_id_table_name);
    ret = maat_scan_integer(maat_instance, table_id, scan_app_id, results, ARRAY_SIZE,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    /* item11 -> group11 -> clause1 -> compile1
                                          /
           item21 -> group21 -> clause2 _/
          item22 -> group22 -> clause3 _/
    */
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_DEL, compile1_id,
                                 NULL, 2, 0);
    EXPECT_EQ(ret, 1);
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile1_id,
                                 NULL, 3, 0);
    EXPECT_EQ(ret, 1);

    long long group22_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group22_id,
                                       compile1_id, 0, "null", 3, 0);
    EXPECT_EQ(ret, 1);

    long long item22_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = intval_table_set_line(maat_instance, app_id_table_name, MAAT_OP_ADD, item22_id,
                                group22_id, 32, 32, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    table_id = maat_get_table_id(maat_instance, app_id_table_name);
    ret = maat_scan_integer(maat_instance, table_id, 31, results, ARRAY_SIZE,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_integer(maat_instance, table_id, scan_app_id, results, ARRAY_SIZE,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile1_id);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmdTest, GroupEdit) {
    const char *g2c_table_name = "GROUP2COMPILE";
	const char *compile_table_name = "COMPILE";
	const char *ip_table_name = "IP_PLUS_CONFIG"; 
    const char *app_id_table_name = "APP_ID";
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    long long compile1_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile1_id,
                                     NULL, 2, 0);
    EXPECT_EQ(ret, 1);

    /* item11 -> group11 -> clause1 -> compile1
           item21 -> group21 -> clause2 _/
    */
    long long group11_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group11_id,
                                       compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    long long item11_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_instance, ip_table_name, MAAT_OP_ADD, item11_id, group11_id, 
                            IPv4, "192.168.3.1", "192.168.3.4", 0, 65535, 0);
    EXPECT_EQ(ret, 1);

    long long group21_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group21_id,
                                       compile1_id, 0, "null", 2, 0);
    EXPECT_EQ(ret, 1);

    long long item21_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = intval_table_set_line(maat_instance, app_id_table_name, MAAT_OP_ADD, item21_id,
                                group21_id, 41, 41, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.3.2", &ip_addr);
    uint16_t port = htons(50001);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_instance, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_instance, table_id, ip_addr, port, 6, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    table_id = maat_get_table_id(maat_instance, app_id_table_name);
    ASSERT_GT(table_id, 0);

    int scan_app_id = 42;
    ret = maat_scan_integer(maat_instance, table_id, scan_app_id, results, ARRAY_SIZE,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_reset(state);

    /* item11 -> group11 -> clause1 -> compile1
            item21 -> group21 -> clause2 _/
              item22 -> /
    */
    long long item22_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = intval_table_set_line(maat_instance, app_id_table_name, MAAT_OP_ADD, item22_id, group21_id,
                                scan_app_id, scan_app_id, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    table_id = maat_get_table_id(maat_instance, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_instance, table_id, ip_addr, port, 6, results, ARRAY_SIZE,
                         &n_hit_result, state);
    //TODO: EXPECT_EQ(ret,?)

    table_id = maat_get_table_id(maat_instance, app_id_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_integer(maat_instance, table_id, scan_app_id, results, ARRAY_SIZE,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile1_id);

    struct maat_hit_path hit_path[128];
    memset(hit_path, 0, sizeof(hit_path));

    int n_read = maat_state_get_hit_paths(state, hit_path, sizeof(hit_path));
    EXPECT_EQ(n_read, 2);
    maat_state_reset(state);

    /* item11 -> group11 -> clause1 -> compile1
           item21 -> group21 -> clause2 _/
    */
    ret = intval_table_set_line(maat_instance, app_id_table_name, MAAT_OP_DEL, item22_id, group21_id,
                                scan_app_id, scan_app_id, NULL, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    memset(results, 0, sizeof(results));
    table_id = maat_get_table_id(maat_instance, ip_table_name);
    ret = maat_scan_ipv4(maat_instance, table_id, ip_addr, port, 6, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    table_id = maat_get_table_id(maat_instance, app_id_table_name);
    ret = maat_scan_integer(maat_instance, table_id, scan_app_id, results, ARRAY_SIZE,
                            &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmdTest, CompileDelete_TSG6548) {
    const char* g2c_table_name = "GROUP2COMPILE";
	const char* compile_table_name = "COMPILE";
	const char* ip_table_name = "IP_PLUS_CONFIG";
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    long long compile1_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile1_id,
                                     NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    //item11 -> group11 -> clause1 -> compile1
    long long group11_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group11_id,
                                       compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    long long item11_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_instance, ip_table_name, MAAT_OP_ADD, item11_id, group11_id, 
                            IPv4, "192.168.73.163", "192.168.73.180", 0, 65535, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    uint32_t ip_addr;
    inet_pton(AF_INET, "192.168.73.169", &ip_addr);
    uint16_t port = htons(50001);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_instance, ip_table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_ipv4(maat_instance, table_id, ip_addr, port, 6, results, ARRAY_SIZE,
                         &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile1_id);

    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_DEL, compile1_id,
                                 NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_DEL, group11_id,
                                        compile1_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    int hit_cnt = 0;
    int miss_cnt = 0;
    time_t update_time = time(NULL);
	time_t now = update_time;
	while (now - update_time < 3) {
		ret = maat_scan_ipv4(maat_instance, table_id, ip_addr, port, 6, results, ARRAY_SIZE,
                             &n_hit_result, state);
		if (ret == MAAT_SCAN_HIT) {
			hit_cnt++;
			EXPECT_EQ(results[0], compile1_id);
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

TEST_F(MaatCmdTest, UpdateDeadLockDetection) {
    const char* g2c_table_name = "GROUP2COMPILE";
	const char* compile_table_name = "COMPILE";
	const char* table_http_url = "HTTP_URL";
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    long long compile1_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile1_id,
                                     NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    //group1 -> compile1
    long long group1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group1_id,
                                       compile1_id, 0, "null", 0, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> group1 -> compile1
    long long item1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, table_http_url, MAAT_OP_ADD, item1_id, group1_id,
                              "part-1", NULL, 0, 0, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    const char* scan_data1 = "scan string part-1.";
	const char* scan_data2 = "scan string part-2.";

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_instance, table_http_url);
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(maat_instance, table_id, scan_data1, strlen(scan_data1),
                          results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile1_id);

    long long compile2_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile2_id,
                                     NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    //group2 -> compile2
    long long group2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group2_id,
                                       compile2_id, 0, "null", 0, 0);
    EXPECT_EQ(ret, 1);

    //item2 -> group2 -> compile2
    long long item2_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, table_http_url, MAAT_OP_ADD, item2_id, group2_id,
                              "part-2", NULL, 0, 0, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    //DON'T DO THIS!!!
	//Roll back version, trigger full udpate.
	//This operation generates some FATAL logs in test_maat_redis.log.yyyy-mm-dd.
	maat_cmd_incrby(maat_instance, "MAAT_VERSION", -100);

    //Wating for scanner garbage collect expiration.
	sleep(10);

    memset(results, 0, sizeof(results));
    ret = maat_scan_string(maat_instance, table_id, scan_data2, strlen(scan_data2),
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT); //After full update, clause ids are re-orgnized, therefore mid are not compatible to the new scanner (hierarchy).
    maat_state_free(state);
    state = NULL;
}

TEST_F(MaatCmdTest, StreamScanSegfaultWhenVersionRollBack_TSG6324) {
    const char* g2c_table_name = "GROUP2COMPILE";
	const char* compile_table_name = "COMPILE";
	const char* scan_table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_instance = MaatCmdTest::_shared_maat_instance;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);

    long long compile1_id = maat_cmd_incrby(maat_instance, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_instance, compile_table_name, MAAT_OP_ADD, compile1_id,
                                     NULL, 1, 0);
    EXPECT_EQ(ret, 1);

    //group1 -> compile1
    long long group1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_instance, g2c_table_name, MAAT_OP_ADD, group1_id,
                                       compile1_id, 0, "null", 0, 0);
    EXPECT_EQ(ret, 1);

    //item1 -> group1 -> compile1
    long long item1_id = maat_cmd_incrby(maat_instance, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_instance, scan_table_name, MAAT_OP_ADD, item1_id, group1_id,
                              "stream-keywords-001", NULL, 0, 0, 0, 0); /*EXPR_TYPE_STRING MATCH_METHOD_SUB*/
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    const char *scan_data = "Here is a stream-keywords-001, this should hit.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_instance, scan_table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *stream = maat_stream_new(maat_instance, table_id, state);
    ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results, ARRAY_SIZE,
                           &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile1_id);

    //DON'T DO THIS!!!
	//Roll back version, trigger full update.	
	//This operation generates FATAL logs in test_maat_redis.log.yyyy-mm-dd.
	//For example: Add group 22 vt_id 0 to clause 2 of compile 979 failed, group is already exisited
	maat_cmd_incrby(maat_instance, "MAAT_VERSION", -100);

	//Wating for scanner garbage collect expiration.
	sleep(10);

	ret = maat_stream_scan(stream, scan_data, strlen(scan_data), results, ARRAY_SIZE, 
                           &n_hit_result, state);
	EXPECT_EQ(ret, 0); //Scan was interupted after full update.

	maat_stream_free(stream);
	maat_state_free(state);
    state = NULL;
}

class MaatRollbackTest : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags = "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;

        logger = log_handle_create("./maat_framework_gtest.log", 0);        
        int ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
        if (ret < 0) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);

        _shared_maat_instance = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_instance) {
            log_error(logger, MODULE_FRAMEWORK_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
                      __FUNCTION__, __LINE__);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_instance);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_instance;
};
struct maat *MaatRollbackTest::_shared_maat_instance;
struct log_handle *MaatRollbackTest::logger;

static int clear_config_in_redis(redisContext *c, struct log_handle *logger)
{
    long long redis_version = 0;
    redisReply *reply = maat_cmd_wrap_redis_command(c, "GET MAAT_VERSION");
    if (reply != NULL) {
		if (reply->type == REDIS_REPLY_NIL || reply->type == REDIS_REPLY_ERROR) {
			log_error(logger, MODULE_FRAMEWORK_GTEST, 
                      "[%s:%d] GET MAAT_VERSION failed, maybe Redis is busy",
                      __FUNCTION__, __LINE__);
			freeReplyObject(reply);
			reply = NULL;
			return -1;
		}
	} else {
		log_error(logger, MODULE_FRAMEWORK_GTEST, 
                  "[%s:%d] GET MAAT_VERSION failed with NULL reply, error: %s",
                  __FUNCTION__, __LINE__, c->errstr);
		return -1;
	}

    redis_version = maat_cmd_read_redis_integer(reply);
	if (redis_version < 0) {
		if (reply->type == REDIS_REPLY_ERROR) {
			log_error(logger, MODULE_FRAMEWORK_GTEST, 
                      "[%s:%d] Redis Communication error: %s", 
                      __FUNCTION__, __LINE__, reply->str);
		}
        freeReplyObject(reply);
	    reply = NULL;
		return -1;
	}

	freeReplyObject(reply);
	reply = NULL;

    reply = maat_cmd_wrap_redis_command(c, "MULTI");
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
	redisAppendCommand(c, "SET %s 1", mr_group_id_var);
	append_cmd_cnt++;
	redisAppendCommand(c, "EXEC");
	append_cmd_cnt++;

    int redis_transaction_success = 1;
    for (int i = 0; i < append_cmd_cnt; i++) {
		int ret = maat_cmd_wrap_redis_get_reply(c, &reply);
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

static int rollback_redis_version(redisContext *c, struct log_handle *logger)
{
    redisReply *reply = maat_cmd_wrap_redis_command(c, "SET MAAT_VERSION 0");
    if (NULL == reply) {
        log_error(logger, MODULE_FRAMEWORK_GTEST, 
                  "[%s:%d] set MAAT_VERSION failed, Redis Communication error: %s", 
                  __FUNCTION__, __LINE__, c->errstr);
        return -1;
    }
    freeReplyObject(reply);
    reply = NULL;

    return 0;
}

TEST_F(MaatRollbackTest, FullConfigRollback) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_instance = MaatRollbackTest::_shared_maat_instance;
    struct log_handle *logger = MaatRollbackTest::logger;

    int table_id = maat_get_table_id(maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_instance, thread_id);
    const char *scan_data = "http://www.cyberessays.com/search_results.php?action=search&query=username,abckkk,1234567";

    int ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 125);
    maat_state_reset(state);

    sleep(5);
    char redis_ip[64] = "127.0.0.1";
    int redis_port = 6379;
    int redis_db = 0;
    redisContext *c = maat_cmd_connect_redis(redis_ip, redis_port, redis_db, logger);
    EXPECT_TRUE(c != NULL);

    ret = clear_config_in_redis(c, logger);
    EXPECT_EQ(ret, 0);

    ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
    EXPECT_EQ(ret, 0);

    ret = rollback_redis_version(c, logger);
    EXPECT_EQ(ret, 0);
    redisFree(c);

    sleep(WAIT_FOR_EFFECTIVE_S * 2);

    ret = maat_scan_string(maat_instance, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 125);
    maat_state_free(state);
    state = NULL;
}
#endif
int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

    ret=RUN_ALL_TESTS();

	return ret;
}
