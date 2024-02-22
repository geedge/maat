#include <gtest/gtest.h>

#include "log/log.h"
#include "maat.h"
#include "maat_rule.h"
#include "maat_utils.h"
#include "ip_matcher.h"
#include "maat_command.h"
#include "json2iris.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"

#define MODULE_FRAMEWORK_PERF_GTEST	 module_name_str("maat.framework_perf_gtest")

#define ARRAY_SIZE              10
#define	WAIT_FOR_EFFECTIVE_S	2
#define PERF_THREAD_NUM         5
#define PERF_SCAN_TIMES        1000 * 1000

const char *table_info_path = "./table_info.conf";
const char *json_filename = "maat_json.json";

struct thread_param {
	int thread_id;
	int test_times;
	struct maat *maat_inst;
	const char *table_name;
	long long time_elapse_ms;
    struct log_handle *logger;
};

void random_keyword_generate(char *keyword_buf, size_t sz)
{
#define MIN_KEYWORD_LEN	4
    size_t i = 0;
	size_t len = random() % (sz - 1 - MIN_KEYWORD_LEN) + MIN_KEYWORD_LEN;
	for (i = 0; i < len; i++) {
		keyword_buf[i] = 'a' + random() % ('z' - 'a');
	}
	keyword_buf[i] = '\0';
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
	long long rule_id = 0;
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
			sscanf(token,"%lld", &rule_id);
		 }
 	}
	
    memcpy(buff, line, strlen(line)+1);
	while(buff[strlen(buff)-1]=='\n'||buff[strlen(buff)-1]=='\t') {
		buff[strlen(buff)-1]='\0';
	}

	maat_set_serial_rule(s_rule + line_idx, MAAT_OP_ADD, rule_id, table_name,
                         buff, absolute_expire_time);
	line_idx++;

    FREE(buff);

	return 0;
}

static int
write_config_to_redis(const char *json_iris_path,
                      char *redis_ip, int redis_port,
                      int redis_db, struct log_handle *logger)
{
    redisContext *c =
        maat_connect_redis(redis_ip, redis_port, redis_db, logger);
    if (NULL == c) {
        return -1;
    }

    redisReply *reply = maat_wrap_redis_command(c, logger, "flushdb");
    if (NULL == reply) {
        return -1;
    } else {
        freeReplyObject(reply);
	    reply = NULL;
    }
    
    if (access(json_iris_path, F_OK) < 0) {
        char tmp_iris_path[128] = {0};
        char *json_buff = NULL;
        size_t json_buff_sz = 0;
        
        int ret = load_file_to_memory(json_filename,
                                      (unsigned char **)&json_buff,
                                      &json_buff_sz);
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
    snprintf(tmp_iris_full_idx_path, sizeof(tmp_iris_full_idx_path),
             "%s/index", json_iris_path);

    config_monitor_traverse(0, tmp_iris_full_idx_path, NULL,
                            count_line_num_cb, NULL, &total_line_cnt,
                            NULL, logger);

    struct serial_rule *s_rule = ALLOC(struct serial_rule, total_line_cnt);
    long long server_time = maat_redis_server_time_s(c);
    if (server_time < 0) {
        return -1;
    }

    //absolute_expire_time = server_time + 300;
    config_monitor_traverse(0, tmp_iris_full_idx_path, NULL,
                            make_serial_rule, NULL, s_rule,
                            NULL, logger);
    line_idx = 0;
    absolute_expire_time = 0;

    int success_cnt = 0;
    do {
        success_cnt = maat_cmd_write_rule(c, s_rule, total_line_cnt,
                                          server_time, logger);
    } while (success_cnt < 0);

    EXPECT_EQ(success_cnt, (int)total_line_cnt);

    for (size_t i = 0; i < total_line_cnt; i++) {
        maat_clear_rule_cache(s_rule + i);
    }
    FREE(s_rule);
    redisFree(c);

    return 0;
}

static int
compile_table_set_line(struct maat *maat_inst, const char *table_name,
                       enum maat_operation op, long long compile_id,
                       const char *user_region, int clause_num,
                       int expire_after)
{
    char table_line[1024 * 16] = {0};
    sprintf(table_line, "%lld\t0\t0\t0\t0\t0\t%s\t%d\t%d\t0.0", 
            compile_id, user_region, clause_num, op);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = compile_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule);
}

static int
group2compile_table_set_line(struct maat *maat_inst, const char *table_name,
                             enum maat_operation op, long long group_id,
                             long long compile_id, int not_flag,
                             const char *vtable_name, int clause_index,
                             int expire_after)
{
    char table_line[128] = {0};
    sprintf(table_line, "%lld\t%lld\t%d\t%s\t%d\t%d", 
            group_id, compile_id, not_flag, vtable_name, clause_index, op);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = group_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule);
}

static int
expr_table_set_line(struct maat *maat_inst, const char *table_name,
                    enum maat_operation op, long long item_id,
                    long long group_id, const char *keywords,
                    const char *district, int expr_type,
                    int match_method, int is_hexbin, int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }
    
    enum table_type table_type =
        table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    assert(table_type == TABLE_TYPE_EXPR || table_type == TABLE_TYPE_EXPR_PLUS);

    if (table_type == TABLE_TYPE_EXPR_PLUS) {
        sprintf(table_line, "%lld\t%lld\t%s\t%s\t%d\t%d\t%d\t%d",
                item_id, group_id, district, keywords, expr_type,
                match_method, is_hexbin, op);
    } else {
        sprintf(table_line, "%lld\t%lld\t%s\t%d\t%d\t%d\t%d",
                item_id, group_id, keywords, expr_type,
                match_method, is_hexbin, op);
    }

    struct maat_cmd_line line_rule;
    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule);
}

static int
ip_table_set_line(struct maat *maat_inst, const char *table_name,
                  enum maat_operation op, long long item_id,
                  long long group_id, enum IP_TYPE type,
                  const char *ip1, const char *ip2, int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }

    int ip_type = IPV4;
    if (type == IPv6) {
        ip_type = IPV6;
    }

    sprintf(table_line, "%lld\t%lld\t%d\t%s\t%s\t%s\t%d", 
            item_id, group_id, ip_type, "range", ip1, ip2, op);
    struct maat_cmd_line line_rule;
    
    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule);
}

static int
integer_table_set_line(struct maat *maat_inst, const char *table_name,
                       enum maat_operation op, long long item_id,
                       long long group_id, int low_boundary,
                       int up_boundary, int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }

    sprintf(table_line, "%lld\t%lld\t%d\t%d\t%d",
            item_id, group_id, low_boundary, up_boundary, op);
    struct maat_cmd_line line_rule;

    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule);
}

static int
flag_table_set_line(struct maat *maat_inst, const char *table_name,
                    enum maat_operation op, long long item_id,
                    long long group_id, long long flag,
                    long long flag_mask, int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }

    sprintf(table_line, "%lld\t%lld\t%lld\t%lld\t%d",
            item_id, group_id, flag, flag_mask, op);
    struct maat_cmd_line line_rule;

    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule);
}

static void
test_add_expr_command(struct maat *maat_inst, const char *table_name, 
                      const char *keywords)
{
    long long compile_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_inst, "COMPILE_DEFAULT",
                                     MAAT_OP_ADD, compile_id, "null",
                                     1, 0);
    EXPECT_EQ(ret, 1);

    long long group_id = maat_cmd_incrby(maat_inst, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_inst, "GROUP2COMPILE_DEFAULT",
                                       MAAT_OP_ADD, group_id, compile_id,
                                       0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                              group_id, keywords, "null", 1, 0, 0, 0);
    EXPECT_EQ(ret, 1);
}

static void
test_add_ip_command(struct maat *maat_inst, const char *table_name, 
                    const char *ip)
{
    long long compile_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_inst, "COMPILE_DEFAULT",
                                     MAAT_OP_ADD, compile_id, "null",
                                     1, 0);
    EXPECT_EQ(ret, 1);

    long long group_id = maat_cmd_incrby(maat_inst, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_inst, "GROUP2COMPILE_DEFAULT",
                                       MAAT_OP_ADD, group_id, compile_id,
                                       0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = ip_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                            group_id, IPv4, ip, ip, 0);
    EXPECT_EQ(ret, 1);
}

static void
test_add_integer_command(struct maat *maat_inst, const char *table_name, 
                         int low_boundary, int up_boundary)
{
    long long compile_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_inst, "COMPILE_DEFAULT",
                                     MAAT_OP_ADD, compile_id, "null",
                                     1, 0);
    EXPECT_EQ(ret, 1);

    long long group_id = maat_cmd_incrby(maat_inst, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_inst, "GROUP2COMPILE_DEFAULT",
                                       MAAT_OP_ADD, group_id, compile_id,
                                       0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = integer_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                                 group_id, low_boundary, up_boundary, 0);
    EXPECT_EQ(ret, 1);
}

static void
test_add_flag_command(struct maat *maat_inst, const char *table_name, 
                      long long flag, long long flag_mask)
{
    long long compile_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    int ret = compile_table_set_line(maat_inst, "COMPILE_DEFAULT",
                                     MAAT_OP_ADD, compile_id, "null",
                                     1, 0);
    EXPECT_EQ(ret, 1);

    long long group_id = maat_cmd_incrby(maat_inst, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_inst, "GROUP2COMPILE_DEFAULT",
                                       MAAT_OP_ADD, group_id, compile_id,
                                       0, table_name, 1, 0);
    EXPECT_EQ(ret, 1);

    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    ret = flag_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id,
                              group_id, flag, flag_mask, 0);
    EXPECT_EQ(ret, 1);
}

class MaatPerfStringScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags =
            "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
            "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;
        char json_iris_path[512] = {0};

        snprintf(json_iris_path, sizeof(json_iris_path),
                 "./%s_iris_tmp", json_filename);
        logger = log_handle_create("./maat_framework_perf_gtest.log", 0);        
        int ret = write_config_to_redis(json_iris_path, redis_ip, redis_port,
                                        redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_perf_gtest.log",
                                LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_caller_thread_number(opts, 5);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] create maat instance in MaatStringScan failed.",
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

struct maat *MaatPerfStringScan::_shared_maat_inst;
struct log_handle *MaatPerfStringScan::logger;

void *perf_string_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    const char *scan_data = "today and yesterday should hit";
    long long results[ARRAY_SIZE] = {0};
    int hit_times = 0;
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    maat_register_thread(maat_inst);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_times; i++) {
        int ret = maat_scan_string(maat_inst, table_id, scan_data,
                                   strlen(scan_data), results, ARRAY_SIZE,
                                   &n_hit_result, state);
        if (ret == MAAT_SCAN_HIT) {
            hit_times++;
        }
        maat_state_reset(state);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    param->time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 +
                            (end.tv_nsec - start.tv_nsec) / 1000000;
    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = (hit_times == param->test_times ? 1 : 0);
    log_info(param->logger, MODULE_FRAMEWORK_PERF_GTEST, 
             "thread_id:%d string_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->time_elapse_ms, hit_times);
    return is_all_hit;
}

void *perf_string_update_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    const int CMD_EXPR_NUM = 10;
    char keyword_buf[128];

    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        random_keyword_generate(keyword_buf, sizeof(keyword_buf));
        test_add_expr_command(maat_inst, table_name, keyword_buf);
        sleep(1);
    }

    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = 1;
    
    return is_all_hit;
}

TEST_F(MaatPerfStringScan, LiteralMultiThread) {
    const char *table_name = "EXPR_LITERAL_PERF_CONFIG";
    struct maat *maat_inst = MaatPerfStringScan::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    pthread_t threads[PERF_THREAD_NUM + 1];
    struct thread_param thread_params[PERF_THREAD_NUM + 1];
    int i = 0;
    int *is_all_hit = NULL;

    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        thread_params[i].maat_inst = maat_inst;
        thread_params[i].thread_id = i;
        thread_params[i].table_name = table_name;
        thread_params[i].test_times = PERF_SCAN_TIMES;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_string_scan_thread,
                           thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_string_update_thread,
                           thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
    log_info(maat_inst->logger, MODULE_FRAMEWORK_PERF_GTEST,
             "StringScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class MaatPerfRegexScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags =
            "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
            "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;
        char json_iris_path[512] = {0};

        snprintf(json_iris_path, sizeof(json_iris_path),
                 "./%s_iris_tmp", json_filename);
        logger = log_handle_create("./maat_framework_perf_gtest.log", 0);        
        int ret = write_config_to_redis(json_iris_path, redis_ip, redis_port,
                                        redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_perf_gtest.log",
                                LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_caller_thread_number(opts, 5);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] create maat instance in MaatRegexScan failed.",
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

struct maat *MaatPerfRegexScan::_shared_maat_inst;
struct log_handle *MaatPerfRegexScan::logger;

void *perf_regex_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    const char *scan_data =
        "http://www.cyberessays.com/search_results.php?action=search&query=username,abckkk,1234567";
    long long results[ARRAY_SIZE] = {0};
    int hit_times = 0;
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    maat_register_thread(maat_inst);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_times; i++) {
        int ret = maat_scan_string(maat_inst, table_id, scan_data,
                                   strlen(scan_data), results, ARRAY_SIZE,
                                   &n_hit_result, state);
        if (ret == MAAT_SCAN_HIT) {
            hit_times++;
        }
        maat_state_reset(state);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    param->time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 +
                            (end.tv_nsec - start.tv_nsec) / 1000000;
    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = (hit_times == param->test_times ? 1 : 0);
    log_info(param->logger, MODULE_FRAMEWORK_PERF_GTEST, 
             "thread_id:%d regex_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->time_elapse_ms, hit_times);
    return is_all_hit;
}

void *perf_regex_update_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    const int CMD_EXPR_NUM = 10;
    char keyword_buf[128];

    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        random_keyword_generate(keyword_buf, sizeof(keyword_buf));
        test_add_expr_command(maat_inst, table_name, keyword_buf);
        sleep(1);
    }

    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = 1;
    
    return is_all_hit;
}

TEST_F(MaatPerfRegexScan, RegexMultiThread) {
    const char *table_name = "EXPR_REGEX_PERF_CONFIG";
    struct maat *maat_inst = MaatPerfRegexScan::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    pthread_t threads[PERF_THREAD_NUM + 1];
    struct thread_param thread_params[PERF_THREAD_NUM + 1];
    int i = 0;
    int *is_all_hit = NULL;

    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        thread_params[i].maat_inst = maat_inst;
        thread_params[i].thread_id = i;
        thread_params[i].table_name = table_name;
        thread_params[i].test_times = PERF_SCAN_TIMES;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread,
                           thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread,
                           thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
    
    log_info(maat_inst->logger, MODULE_FRAMEWORK_PERF_GTEST,
             "RegexScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

void *perf_integer_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    int hit_times = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);
    int table_id = maat_get_table_id(maat_inst, table_name);
    maat_register_thread(maat_inst);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_times; i++) {
        int ret = maat_scan_integer(maat_inst, table_id, 3000, results,
                                    ARRAY_SIZE, &n_hit_result, state);
        if (ret == MAAT_SCAN_HIT) {
            hit_times++;
        }
        maat_state_reset(state);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    param->time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                            (end.tv_nsec - start.tv_nsec) / 1000000;
    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = (hit_times == param->test_times ? 1 : 0);
    log_info(param->logger, MODULE_FRAMEWORK_PERF_GTEST, 
             "thread_id:%d integer_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->time_elapse_ms, hit_times);
    return is_all_hit;
}

void *perf_integer_update_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    const int CMD_EXPR_NUM = 10;

    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        test_add_integer_command(maat_inst, table_name, 3001+i, 3001+i);
        sleep(1);
    }

    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = 1;
    
    return is_all_hit;
}

class MaatPerfStreamScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags =
            "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
            "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;
        char json_iris_path[512] = {0};

        snprintf(json_iris_path, sizeof(json_iris_path),
                  "./%s_iris_tmp", json_filename);
        logger = log_handle_create("./maat_framework_perf_gtest.log", 0);        
        int ret = write_config_to_redis(json_iris_path, redis_ip, redis_port,
                                        redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_perf_gtest.log",
                                LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_caller_thread_number(opts, 5);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] create maat instance in MaatStreamScan failed.",
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

struct maat *MaatPerfStreamScan::_shared_maat_inst;
struct log_handle *MaatPerfStreamScan::logger;

void *perf_stream_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    const char *scan_data =
        "http://www.cyberessays.com/search_results.php?action=search&query=username,abckkk,1234567";
    long long results[ARRAY_SIZE] = {0};
    int ret = 0, hit_times = 0;
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);
    struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
    maat_register_thread(maat_inst);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_times; i++) {
        ret = maat_stream_scan(sp, scan_data, strlen(scan_data), results,
                               ARRAY_SIZE, &n_hit_result, state);
        if (ret == MAAT_SCAN_HIT) {
            hit_times++;
        }
        maat_state_reset(state);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    maat_stream_free(sp);
    maat_state_free(state);

    param->time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 +
                            (end.tv_nsec - start.tv_nsec) / 1000000;
    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = ((hit_times == param->test_times) ? 1 : 0);

    log_info(param->logger, MODULE_FRAMEWORK_PERF_GTEST, 
             "thread_id:%d stream_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->time_elapse_ms, hit_times);
    return is_all_hit;
}

TEST_F(MaatPerfStreamScan, MultiThread) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = MaatPerfStreamScan::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    pthread_t threads[PERF_THREAD_NUM];
    struct thread_param thread_params[PERF_THREAD_NUM];
    int i = 0;
    int *is_all_hit = NULL;

    for (i = 0; i < PERF_THREAD_NUM; i++) {
        thread_params[i].maat_inst = maat_inst;
        thread_params[i].thread_id = i;
        thread_params[i].table_name = table_name;
        thread_params[i].test_times = PERF_SCAN_TIMES;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread,
                           thread_params+i);
        } 
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;
        //maybe expr_runtime rebuild in stream_scan, so should not expect is_all_hit always 1
		EXPECT_EQ(*is_all_hit, 1);
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_FRAMEWORK_PERF_GTEST,
             "StreamScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class MaatPerfIPScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags =
            "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
            "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;
        char json_iris_path[512] = {0};

        snprintf(json_iris_path, sizeof(json_iris_path),
                 "./%s_iris_tmp", json_filename);
        logger = log_handle_create("./maat_framework_perf_gtest.log", 0);        
        int ret = write_config_to_redis(json_iris_path, redis_ip, redis_port,
                                        redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_perf_gtest.log",
                                LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_caller_thread_number(opts, 5);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] create maat instance in MaatIPScan failed.",
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

struct maat *MaatPerfIPScan::_shared_maat_inst;
struct log_handle *MaatPerfIPScan::logger;

void *perf_ip_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    char ip_str[32] = "10.0.0.1";
    uint32_t ip_addr;

    int ret = inet_pton(AF_INET, ip_str, &ip_addr);
    EXPECT_EQ(ret, 1);
    
    int hit_times = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);
    int table_id = maat_get_table_id(maat_inst, table_name);
    maat_register_thread(maat_inst);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_times; i++) {
        int ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, results,
                                 ARRAY_SIZE, &n_hit_result, state);
        if (ret == MAAT_SCAN_HIT) {
            hit_times++;
        }
        maat_state_reset(state);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    param->time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 +
                            (end.tv_nsec - start.tv_nsec) / 1000000;
    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = (hit_times == param->test_times ? 1 : 0);
    log_info(param->logger, MODULE_FRAMEWORK_PERF_GTEST, 
             "thread_id:%d ip_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->time_elapse_ms, hit_times);
    return is_all_hit;
}

void *perf_ip_update_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    const int CMD_EXPR_NUM = 10;
    char ip_str[10][32] = {
                            "10.0.7.101",
                            "10.0.7.102",
                            "10.0.7.103",
                            "10.0.7.104",
                            "10.0.7.105",
                            "10.0.7.106",
                            "10.0.7.107",
                            "10.0.7.108",
                            "10.0.7.109",
                            "10.0.7.110"};

    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        test_add_ip_command(maat_inst, table_name, ip_str[i]);
        sleep(1);
    }

    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = 1;
    
    return is_all_hit;
}

TEST_F(MaatPerfIPScan, MultiThread)
{
    const char *table_name = "IP_PERF_CONFIG";
    struct maat *maat_inst = MaatPerfIPScan::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    pthread_t threads[PERF_THREAD_NUM + 1];
    struct thread_param thread_params[PERF_THREAD_NUM + 1];
    int i = 0;
    int *is_all_hit = NULL;

    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        thread_params[i].maat_inst = maat_inst;
        thread_params[i].thread_id = i;
        thread_params[i].table_name = table_name;
        thread_params[i].test_times = PERF_SCAN_TIMES;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread,
                           thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread,
                           thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_FRAMEWORK_PERF_GTEST,
             "IPScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class MaatPerfIntegerScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags =
            "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
            "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;
        char json_iris_path[512] = {0};

        snprintf(json_iris_path, sizeof(json_iris_path),
                 "./%s_iris_tmp", json_filename);
        logger = log_handle_create("./maat_framework_perf_gtest.log", 0);        
        int ret = write_config_to_redis(json_iris_path, redis_ip, redis_port,
                                        redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_perf_gtest.log",
                                LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_caller_thread_number(opts, 5);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] create maat instance in MaatIntegerScan failed.",
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

struct maat *MaatPerfIntegerScan::_shared_maat_inst;
struct log_handle *MaatPerfIntegerScan::logger;

TEST_F(MaatPerfIntegerScan, MultiThread) {
    const char *table_name = "CONTENT_SIZE";
    struct maat *maat_inst = MaatPerfIntegerScan::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    pthread_t threads[PERF_THREAD_NUM + 1];
    struct thread_param thread_params[PERF_THREAD_NUM + 1];
    int i = 0;
    int *is_all_hit = NULL;

    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        thread_params[i].maat_inst = maat_inst;
        thread_params[i].thread_id = i;
        thread_params[i].table_name = table_name;
        thread_params[i].test_times = PERF_SCAN_TIMES;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_integer_scan_thread,
                            thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_integer_update_thread,
                            thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_FRAMEWORK_PERF_GTEST,
             "IntegerScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class MaatPerfFlagScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags =
            "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
            "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;
        char json_iris_path[512] = {0};

        snprintf(json_iris_path, sizeof(json_iris_path),
                 "./%s_iris_tmp", json_filename);
        logger = log_handle_create("./maat_framework_perf_gtest.log", 0);        
        int ret = write_config_to_redis(json_iris_path, redis_ip, redis_port,
                                        redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_perf_gtest.log",
                                LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_caller_thread_number(opts, 5);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
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

struct maat *MaatPerfFlagScan::_shared_maat_inst;
struct log_handle *MaatPerfFlagScan::logger;

void *perf_flag_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    int hit_times = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    long long scan_data = 15;

    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);
    int table_id = maat_get_table_id(maat_inst, table_name);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_times; i++) {
        int ret = maat_scan_flag(maat_inst, table_id, scan_data, results,
                                 ARRAY_SIZE, &n_hit_result, state);
        if (ret == MAAT_SCAN_HIT) {
            hit_times++;
        }
        maat_state_reset(state);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    param->time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 +
                            (end.tv_nsec - start.tv_nsec) / 1000000;
    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = (hit_times == param->test_times ? 1 : 0);
    log_info(param->logger, MODULE_FRAMEWORK_PERF_GTEST, 
             "thread_id:%d flag_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->time_elapse_ms, hit_times);
    return is_all_hit;
}

void *perf_flag_update_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    const int CMD_EXPR_NUM = 10;

    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        test_add_flag_command(maat_inst, table_name, i, 15);
        sleep(1);
    }

    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = 1;
    
    return is_all_hit;
}

TEST_F(MaatPerfFlagScan, MultiThread) {
    const char *table_name = "FLAG_PERF_CONFIG";
    struct maat *maat_inst = MaatPerfFlagScan::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    pthread_t threads[PERF_THREAD_NUM + 1];
    struct thread_param thread_params[PERF_THREAD_NUM + 1];
    int i = 0;
    int *is_all_hit = NULL;

    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        thread_params[i].maat_inst = maat_inst;
        thread_params[i].thread_id = i;
        thread_params[i].table_name = table_name;
        thread_params[i].test_times = PERF_SCAN_TIMES;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_flag_scan_thread,
                            thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_flag_update_thread,
                            thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_FRAMEWORK_PERF_GTEST,
             "FlagScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class MaatPerfFQDNPluginScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags =
            "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
            "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;
        char json_iris_path[512] = {0};

        snprintf(json_iris_path, sizeof(json_iris_path),
                 "./%s_iris_tmp", json_filename);
        logger = log_handle_create("./maat_framework_perf_gtest.log", 0);        
        int ret = write_config_to_redis(json_iris_path, redis_ip, redis_port,
                                        redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_perf_gtest.log",
                                LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_caller_thread_number(opts, 5);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] create maat instance in MaatFQDNPluginScan failed.",
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

struct maat *MaatPerfFQDNPluginScan::_shared_maat_inst;
struct log_handle *MaatPerfFQDNPluginScan::logger;

struct perf_fqdn_plugin_ud {
	long long rule_id;
	int catid;
};

void perf_fqdn_plugin_EX_new_cb(const char *table_name, int table_id,
                                const char *key, const char *table_line,
                                void **ad, long argl, void *argp)
{
	int *counter=(int *)argp;
	size_t column_offset=0, column_len=0;

	struct perf_fqdn_plugin_ud *ud = ALLOC(struct perf_fqdn_plugin_ud, 1);
	int ret = maat_helper_read_column(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);

	ud->rule_id = atoll(table_line+column_offset);
	ret = maat_helper_read_column(table_line, 4, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	sscanf(table_line+column_offset, "catid=%d",&ud->catid);

	*ad = ud;
	(*counter)++;
}

void perf_fqdn_plugin_EX_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct perf_fqdn_plugin_ud *u = (struct perf_fqdn_plugin_ud *)(*ad);

	free(u);
	*ad = NULL;
}

void perf_fqdn_plugin_EX_dup_cb(int table_id, void **to, void **from,
                                long argl, void *argp)
{
	struct perf_fqdn_plugin_ud *u = (struct perf_fqdn_plugin_ud *)(*from);

	*to = u;
}

void* perf_fqdn_plugin_scan_thread(void *arg)
{
	struct thread_param *param = (struct thread_param *)arg;
	struct maat *maat_inst = param->maat_inst;
	struct perf_fqdn_plugin_ud *result[ARRAY_SIZE];

	int i=0, ret=0, hit_times=0;
	int table_id = maat_get_table_id(maat_inst, param->table_name);
    maat_register_thread(maat_inst);

	memset(&result, 0, sizeof(result));
	struct timespec start, end;
	
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < param->test_times; i++) {
	
		ret = maat_fqdn_plugin_table_get_ex_data(maat_inst, table_id, 
                                                 "r3---sn-i3belne6.example2.com",
                                                 (void**)result, ARRAY_SIZE);
		if (ret == 2) {
			hit_times++;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &end);

	param->time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                            (end.tv_nsec - start.tv_nsec) / 1000000;
	int* is_all_hit = (int*)malloc(sizeof(int));
	*is_all_hit = (hit_times == param->test_times) ? 1 : 0;
    log_info(param->logger, MODULE_FRAMEWORK_PERF_GTEST, 
             "thread_id:%d fqdn_plugin_get_ex_data time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->time_elapse_ms, hit_times);

	return is_all_hit;
}

void random_fqdn_generate(char *fqdn_buff, int sz)
{
	int min_fqdn_len = 6, max_fqdn_len = 32;
	int i=0, j=0;

	int len = random() % (max_fqdn_len - min_fqdn_len) + min_fqdn_len;
	if (len >= sz) {
		len = sz - 1;
	}

	for (i = 0; i < len-4; i++) {
		fqdn_buff[i] = 'a' + random() % ('z' - 'a');
		if (j > 5) {
			if (random() % 3 == 0) {
				fqdn_buff[i] = '.';
				j = 0;
			}
		}
		j++;
	}
	fqdn_buff[i] = '\0';
}

void *perf_fqdn_plugin_update_thread(void *arg)
{
	struct thread_param *param = (struct thread_param *)arg;
	struct maat *maat_inst = param->maat_inst;
	const int CMD_EXPR_NUM = 20;
	int i = 0;
	struct maat_cmd_line line_rule;
	char line_buff[1024], fqdn_buff[256];

	for (i = 0; i < CMD_EXPR_NUM; i++) {
		line_rule.rule_id = (int)maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
		line_rule.table_name = param->table_name;
		random_fqdn_generate(fqdn_buff, sizeof(fqdn_buff));
		snprintf(line_buff, 1024, "%lld\t1\t%s\tcatid=4\t1",
                 line_rule.rule_id, fqdn_buff);
		line_rule.table_line = line_buff;
		line_rule.expire_after = 0;
		maat_cmd_set_line(maat_inst, &line_rule);
		sleep(WAIT_FOR_EFFECTIVE_S);
	}

	int *is_all_hit = (int *)malloc(sizeof(int));
	*is_all_hit = 1;

	return is_all_hit;
}

TEST_F(MaatPerfFQDNPluginScan, MultiThread) {
    struct maat *maat_inst = MaatPerfFQDNPluginScan::_shared_maat_inst;
    const char *table_name = "TEST_FQDN_PLUGIN_WITH_EXDATA";
    int fqdn_plugin_ex_data_counter = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    pthread_t threads[PERF_THREAD_NUM + 1];
    struct thread_param thread_params[PERF_THREAD_NUM + 1];
    int i = 0;
    int *is_all_hit = NULL;

    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                 perf_fqdn_plugin_EX_new_cb,
                                                 perf_fqdn_plugin_EX_free_cb,
                                                 perf_fqdn_plugin_EX_dup_cb,
                                                 0, &fqdn_plugin_ex_data_counter);
    ASSERT_TRUE(ret>=0);

    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        thread_params[i].maat_inst = maat_inst;
        thread_params[i].thread_id = i;
        thread_params[i].table_name = table_name;
        thread_params[i].test_times = PERF_SCAN_TIMES;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_fqdn_plugin_scan_thread,
                            thread_params + i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_fqdn_plugin_update_thread,
                            thread_params + i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_FRAMEWORK_PERF_GTEST,
             "FQDNPluginScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class MaatPerfBoolPluginScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *accept_tags =
            "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
            "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;
        char json_iris_path[512] = {0};

        snprintf(json_iris_path, sizeof(json_iris_path),
                 "./%s_iris_tmp", json_filename);
        logger = log_handle_create("./maat_framework_perf_gtest.log", 0);        
        int ret = write_config_to_redis(json_iris_path, redis_ip, redis_port,
                                        redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_perf_gtest.log",
                                LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_caller_thread_number(opts, 5);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] create maat instance in BoolPluginScan failed.",
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

struct maat *MaatPerfBoolPluginScan::_shared_maat_inst;
struct log_handle *MaatPerfBoolPluginScan::logger;

struct bool_plugin_ud {
	int id;
	char *name;
};

void perf_bool_plugin_ex_new_cb(const char *table_name, int table_id,
                                const char *key, const char *table_line,
                                void **ad, long argl, void *argp)
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

	*ad = ud;
	(*counter)++;
}

void perf_bool_plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct bool_plugin_ud *u = (struct bool_plugin_ud *)(*ad);

	free(u->name);
	free(u);
	*ad = NULL;
}

void perf_bool_plugin_ex_dup_cb(int table_id, void **to, void **from,
                                long argl, void *argp)
{
	struct bool_plugin_ud *u = (struct bool_plugin_ud *)(*from);

	*to = u;
}

void* perf_bool_plugin_scan_thread(void *arg)
{
	struct thread_param *param = (struct thread_param *)arg;
	struct maat *maat_inst = param->maat_inst;
	struct perf_fqdn_plugin_ud *result[ARRAY_SIZE];

	int i=0, ret=0, hit_times=0;
	int table_id = maat_get_table_id(maat_inst, param->table_name);
    maat_register_thread(maat_inst);

	memset(&result, 0, sizeof(result));
	struct timespec start, end;
	unsigned long long items_4[]={7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 7};

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < param->test_times; i++) {
	
		ret = maat_bool_plugin_table_get_ex_data(maat_inst, table_id, items_4,
                                                 sizeof(items_4)/sizeof(unsigned long long),
                                                 (void**)result, 6);
		if (ret == 1) {
			hit_times++;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &end);

	param->time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 +
                            (end.tv_nsec - start.tv_nsec) / 1000000;
	int* is_all_hit = (int*)malloc(sizeof(int));
	*is_all_hit = (hit_times == param->test_times) ? 1 : 0;

    log_info(param->logger, MODULE_FRAMEWORK_PERF_GTEST, 
             "thread_id:%d bool_plugin_get_ex_data time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->time_elapse_ms, hit_times);

	return is_all_hit;
}

void *perf_bool_plugin_update_thread(void *arg)
{
	struct thread_param *param = (struct thread_param *)arg;
	struct maat *maat_inst = param->maat_inst;
	const int CMD_EXPR_NUM = 20;
	int i = 0;
	struct maat_cmd_line line_rule;
	char line_buff[1024];

	for (i = 0; i < CMD_EXPR_NUM; i++) {
		line_rule.rule_id = (int)maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
		line_rule.table_name = param->table_name;
		snprintf(line_buff, 1024, "%lld\t1&%d\ttunnel2\t1", line_rule.rule_id, i);
		line_rule.table_line = line_buff;
		line_rule.expire_after = 0;
		maat_cmd_set_line(maat_inst, &line_rule);
		sleep(WAIT_FOR_EFFECTIVE_S);
	}

	int *is_all_hit = (int *)malloc(sizeof(int));
	*is_all_hit = 1;

	return is_all_hit;
}

TEST_F(MaatPerfBoolPluginScan, MultiThread) {
    int ex_data_counter = 0;
    const char *table_name = "TEST_BOOL_PLUGIN_WITH_EXDATA";
    struct maat *maat_inst = MaatPerfBoolPluginScan::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
	ASSERT_GT(table_id, 0);

    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
								                   perf_bool_plugin_ex_new_cb,
								                   perf_bool_plugin_ex_free_cb,
								                   perf_bool_plugin_ex_dup_cb,
								                   0, &ex_data_counter);
	ASSERT_TRUE(ret >= 0);

    pthread_t threads[PERF_THREAD_NUM + 1];
    struct thread_param thread_params[PERF_THREAD_NUM + 1];
    int i = 0;
    int *is_all_hit = NULL;

    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        thread_params[i].maat_inst = maat_inst;
        thread_params[i].thread_id = i;
        thread_params[i].table_name = table_name;
        thread_params[i].test_times = PERF_SCAN_TIMES;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_bool_plugin_scan_thread,
                            thread_params + i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_bool_plugin_update_thread,
                            thread_params + i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_FRAMEWORK_PERF_GTEST,
             "BoolPluginScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class MaatPerfFileScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./maat_framework_perf_gtest.log", 0);        
        const char *rule_folder = "./tsgrule/index";
        const char *table_info = "./tsg_table_info.conf";

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_iris(opts, rule_folder, rule_folder);
        maat_options_set_logger(opts, "./maat_framework_perf_gtest.log",
                                LOG_LEVEL_INFO);
        maat_options_set_caller_thread_number(opts, 5);

        _shared_maat_inst = maat_new(opts, table_info);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] create maat instance in MaatPerfFileScan failed.",
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

struct maat *MaatPerfFileScan::_shared_maat_inst;
struct log_handle *MaatPerfFileScan::logger;

struct perf_ip_plugin_ud {
	long long rule_id;
};

void perf_ip_plugin_EX_new_cb(const char *table_name, int table_id,
                              const char *key, const char *table_line,
                              void **ad, long argl, void *argp)
{
	int *counter=(int *)argp, ret=0;
	size_t column_offset=0, column_len=0;

	struct perf_ip_plugin_ud *ud = ALLOC(struct perf_ip_plugin_ud, 1);
	ret = maat_helper_read_column(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);

	ud->rule_id = atoll(table_line+column_offset);
	ret = maat_helper_read_column(table_line, 5, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	*ad = ud;
	(*counter)++;
}

void perf_ip_plugin_EX_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct perf_ip_plugin_ud *u = (struct perf_ip_plugin_ud*)(*ad);

	free(u);
	*ad = NULL;
}

void perf_ip_plugin_EX_dup_cb(int table_id, void **to, void **from,
                              long argl, void *argp)
{
	struct perf_ip_plugin_ud *u = (struct perf_ip_plugin_ud*)(*from);

	*to = u;
}

static void *ip_plugin_get_thread(void *arg)
{
	const char *table_name = "TSG_IP_LOCATION_BUILT_IN";
	int test_times = 1000*1000, hit_times = 0;
	int ret = 0, i = 0;
	struct maat *maat_inst = (struct maat *)arg;

	int table_id = maat_get_table_id(maat_inst, table_name);
    maat_register_thread(maat_inst);

    struct timespec start, end;
	struct ip_addr ipv4;
    ipv4.ip_type = IPv4;
	inet_pton(AF_INET, "191.70.72.1", &ipv4.ipv4);	
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    struct perf_ip_plugin_ud *results[ARRAY_SIZE];
	for (i = 0; i < test_times; i++) {
		ret = maat_ip_plugin_table_get_ex_data(maat_inst, table_id, &ipv4,
                                               (void**)results, 4);
		if (ret > 0) {
			hit_times++;
		}
	}
    clock_gettime(CLOCK_MONOTONIC, &end);

    long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 +
                                (end.tv_nsec - start.tv_nsec) / 1000000;
    log_info(maat_inst->logger, MODULE_FRAMEWORK_PERF_GTEST, 
             "ip_plugin_get_ex_data time_elapse:%lldms hit_times:%d", 
              time_elapse_ms, hit_times);

	int *is_all_hit = (int *)malloc(sizeof(int));
	*is_all_hit = (hit_times == test_times) ? 1 : 0;
	return is_all_hit;
}

TEST_F(MaatPerfFileScan, IPPlugin) {
    struct maat *maat_inst = MaatPerfFileScan::_shared_maat_inst;
    const char* table_name = "TSG_IP_LOCATION_BUILT_IN";
    int ip_plugin_ex_data_counter = 0;
    int* is_all_hit = NULL;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                   perf_ip_plugin_EX_new_cb,
                                                   perf_ip_plugin_EX_free_cb,
                                                   perf_ip_plugin_EX_dup_cb,
                                                   0, &ip_plugin_ex_data_counter);
    ASSERT_TRUE(ret>=0);

    int i = 0;
    pthread_t threads[PERF_THREAD_NUM];

	for (i = 0; i < PERF_THREAD_NUM; i++) {
		pthread_create(&(threads[i]), NULL, ip_plugin_get_thread, maat_inst);
	}

	for (i = 0; i < PERF_THREAD_NUM; i++) {
		pthread_join(threads[i], (void**)&is_all_hit);
		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit=0;
		free(is_all_hit);
	}
}

class MaatTSGFqdnScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;
        char json_iris_path[512] = {0};
        const char *tsg_table_info = "./tsg_table_info.conf";

        snprintf(json_iris_path, sizeof(json_iris_path), "./tsgrule");
        logger = log_handle_create("./maat_framework_perf_gtest.log", 0);        
        int ret = write_config_to_redis(json_iris_path, redis_ip, redis_port,
                                        redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_perf_gtest.log",
                                LOG_LEVEL_INFO);

        _shared_maat_inst = maat_new(opts, tsg_table_info);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                       "[%s:%d] create maat instance in MaatTSGFqdnScan failed.",
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

struct maat *MaatTSGFqdnScan::_shared_maat_inst;
struct log_handle *MaatTSGFqdnScan::logger;

#if 0
TEST_F(MaatTSGFqdnScan, mem_used) {
    char keyword_buf[128];
    const char *table_name1 = "TSG_OBJ_FQDN";
    const char *table_name2= "TSG_IP_ADDR";
    struct maat *maat_inst = MaatTSGFqdnScan::_shared_maat_inst;
    struct log_handle *logger = MaatTSGFqdnScan::logger;

    for (size_t i = 0; i < 100; i++) {
        random_keyword_generate(keyword_buf, sizeof(keyword_buf));
        int ret = expr_table_set_line(maat_inst, table_name1, MAAT_OP_ADD,
                                      600000000+i, 600000000+i, keyword_buf,
                                      "null", 1, 0, 0, 0);
        EXPECT_EQ(ret, 1);

        ret = ip_table_set_line(maat_inst, table_name2, MAAT_OP_ADD,
                                600000000+i, 600000000+i, IPv4, "100.64.1.1",
                                "100.64.1.2", 0);
        EXPECT_EQ(ret, 1);

        log_info(logger, MODULE_FRAMEWORK_PERF_GTEST, "MaatTSGFqdnScan update one line");
        sleep(150);
    }
}
#endif

class MaatPerfIPPortPluginScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
         const char *accept_tags =
            "{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},"
            "{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
        char redis_ip[64] = "127.0.0.1";
        int redis_port = 6379;
        int redis_db = 0;
        char json_iris_path[512] = {0};

        snprintf(json_iris_path, sizeof(json_iris_path),
                 "./%s_iris_tmp", json_filename);
        logger = log_handle_create("./maat_framework_perf_gtest.log", 0);        
        int ret = write_config_to_redis(json_iris_path, redis_ip, redis_port,
                                        redis_db, logger);
        if (ret < 0) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] write config to redis failed.",
                      __FUNCTION__, __LINE__);
        }

        struct maat_options *opts = maat_options_new();
        maat_options_set_stat_file(opts, "./stat.log");
        maat_options_set_perf_on(opts);
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_framework_perf_gtest.log",
                                LOG_LEVEL_INFO);
        maat_options_set_accept_tags(opts, accept_tags);
        maat_options_set_caller_thread_number(opts, 5);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            log_fatal(logger, MODULE_FRAMEWORK_PERF_GTEST,
                      "[%s:%d] create maat instance in MaatFlagScan failed.",
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

struct maat *MaatPerfIPPortPluginScan::_shared_maat_inst;
struct log_handle *MaatPerfIPPortPluginScan::logger;

static void *perf_ipport_plugin_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
	struct maat *maat_inst = param->maat_inst;
    struct perf_ip_plugin_ud *results[ARRAY_SIZE];
	int i = 0, ret = 0, hit_times = 0;

	int table_id = maat_get_table_id(maat_inst, param->table_name);
    maat_register_thread(maat_inst);

	struct ip_addr ipv4;
    ipv4.ip_type = IPv4;
	inet_pton(AF_INET, "192.168.100.1", &ipv4.ipv4);	
    uint16_t port = htons(215);

	for (i = 0; i < param->test_times; i++) {
		ret = maat_ipport_plugin_table_get_ex_data(maat_inst, table_id, &ipv4,
                                                   port, (void**)results, 4);
		if (ret > 0) {
			hit_times++;
		}
	}

	int *is_all_hit = (int *)malloc(sizeof(int));
	*is_all_hit = (hit_times == param->test_times) ? 1 : 0;
    log_info(maat_inst->logger, MODULE_FRAMEWORK_PERF_GTEST, 
             "ipport_plugin_get_ex_data hit_times:%d", hit_times);

	return is_all_hit;
}

void *perf_ipport_plugin_update_thread(void *arg)
{
	struct thread_param *param = (struct thread_param *)arg;
	struct maat *maat_inst = param->maat_inst;
	const int CMD_EXPR_NUM = 20;
	int i = 0;
	struct maat_cmd_line line_rule;
    char line_buff[1024];

	for (i = 0; i < CMD_EXPR_NUM; i++) {
		line_rule.rule_id = (int)maat_cmd_incrby(maat_inst, "TEST_PLUG_SEQ", 1);
		line_rule.table_name = param->table_name;
		snprintf(line_buff, 1024, "%lld\t4\t192.168.100.1\t%d\t%d\t1",
                 line_rule.rule_id, 200+i, 300+i);
		line_rule.table_line = line_buff;
		line_rule.expire_after = 0;
		maat_cmd_set_line(maat_inst, &line_rule);
		sleep(WAIT_FOR_EFFECTIVE_S);
	}

	int *is_all_hit = (int *)malloc(sizeof(int));
	*is_all_hit = 1;

	return is_all_hit;
}

TEST_F(MaatPerfIPPortPluginScan, MultiThread) {
    struct maat *maat_inst = MaatPerfIPPortPluginScan::_shared_maat_inst;
    const char* table_name = "TEST_IPPORT_PLUGIN_WITH_EXDATA";
    int ip_plugin_ex_data_counter = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                   perf_ip_plugin_EX_new_cb,
                                                   perf_ip_plugin_EX_free_cb,
                                                   perf_ip_plugin_EX_dup_cb,
                                                   0, &ip_plugin_ex_data_counter);
    ASSERT_TRUE(ret>=0);

    pthread_t threads[PERF_THREAD_NUM + 1];
    struct thread_param thread_params[PERF_THREAD_NUM + 1];
    int i = 0;
    int *is_all_hit = NULL;

	for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        thread_params[i].maat_inst = maat_inst;
        thread_params[i].thread_id = i;
        thread_params[i].table_name = table_name;
        thread_params[i].test_times = PERF_SCAN_TIMES;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ipport_plugin_scan_thread,
                            thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_ipport_plugin_update_thread,
                            thread_params+i);
        }
	}

    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

    ret=RUN_ALL_TESTS();

	return ret;
}
