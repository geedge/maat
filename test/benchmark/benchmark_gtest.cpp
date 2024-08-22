#include "maat.h"
#include "log/log.h"
#include "maat_utils.h"
#include "maat_core.h"
#include "json2iris.h"
#include "ip_matcher.h"
#include "maat_table.h"
#include "../test_utils.h"
#include "maat_config_monitor.h"

#include <gtest/gtest.h>

#define MODULE_BENCHMARK_GTEST	 module_name_str("maat.benchmark_gtest")

#define MAX_EXPR_RULE_NUM 2000000
#define MID_EXPR_RULE_NUM 1000000

#define MAX_IP_RULE_NUM 8000000
#define MID_IP_RULE_NUM 4000000

#define MAX_INTEGER_RULE_NUM 10000
#define MID_INTEGER_RULE_NUM 5000

#define MAX_FLAG_RULE_NUM 10000
#define MID_FLAG_RULE_NUM 5000

#define ARRAY_SIZE 10
#define PERF_THREAD_NUM 5
#define MAX_SCAN_TIMES 1000000

const char *g_table_info_path = "./benchmark_table_info.conf";
struct log_handle *g_logger = NULL;

struct thread_param {
	int thread_id;
	int test_times;
    int rule_count;
	struct maat *maat_inst;
	const char *table_name;
	long long time_elapse_ms;
    struct log_handle *logger;
};

static void generate_expr_sample(const char *table_name, int sample_count)
{
    FILE *fp = fopen(table_name, "w+");
    if (NULL == fp) {
        log_fatal(g_logger, "open file %s failed", table_name);
        return;
    }

    fprintf(fp, "%d\n", sample_count);
    fprintf(fp, "1\t1\t%s\t1\t0\t0\t1\n", "the souls of the departed");

    for (int i = 2; i <= sample_count; i++) {
        char keyword_buf[64] = {0};
        random_keyword_generate(keyword_buf, sizeof(keyword_buf));
        fprintf(fp, "%d\t%d\t%s\t1\t0\t0\t1\n", i, i, keyword_buf);
    }
    
    fclose(fp);
}

static void generate_ip_sample(const char *table_name, int sample_count)
{
    FILE *fp = fopen(table_name, "w+");
    if (NULL == fp) {
        log_fatal(g_logger, "open file %s failed", table_name);
        return;
    }

    fprintf(fp, "%d\n", sample_count);
    fprintf(fp, "1\t1\t4\t%s\t%s\t%s\t%s\t%d\t%d\t-1\t1\n", "range",
            "100.64.1.1", "100.64.1.1", "range", 20000, 20000);

    for (int i = 2; i <= sample_count-1; i++) {
        char ip_buf[64] = {0};
        sprintf(ip_buf, "%d.%d.%d.%d", (int)(random() % 256), (int)(random() % 256),
                (int)(random() % 256), (int)(random() % 256));
        fprintf(fp, "%d\t%d\t4\t%s\t%s\t%s\t%s\t%d\t%d\t-1\t1\n",
                i+1, i+1, "range", ip_buf, ip_buf, "range", 20000, 20000);
    }
    
    fclose(fp);
}

static void generate_integer_sample(const char *table_name, int sample_count)
{
    FILE *fp = fopen(table_name, "w+");
    if (NULL == fp) {
        log_fatal(g_logger, "open file %s failed", table_name);
        return;
    }

    fprintf(fp, "%d\n", sample_count);
    fprintf(fp, "1\t1\t%d\t%d\t1\n", 1000000, 1000000);

    for (int i = 2; i <= sample_count-1; i++) {
        fprintf(fp, "%d\t%d\t%d\t%d\t1\n", i+1, i+1, i+1, i+1);
    }
    
    fclose(fp);
}

void generate_flag_sample(const char *table_name, int sample_count)
{
    FILE *fp = fopen(table_name, "w+");
    if (NULL == fp) {
        log_fatal(g_logger, "open file %s failed", table_name);
        return;
    }

    fprintf(fp, "%d\n", sample_count);
    fprintf(fp, "1\t1\t%d\t%d\t1\n", 1000000, 1111111);

    for (int i = 2; i <= sample_count-1; i++) {
        fprintf(fp, "%d\t%d\t%d\t%d\t1\n", i+1, i+1, i+1, i+1);
    }

    fclose(fp);
}

void generate_rule_sample(const char *table_name, int sample_count)
{
    FILE *fp = fopen(table_name, "w+");
    if (NULL == fp) {
        log_fatal(g_logger, "open file %s failed", table_name);
        return;
    }

    fprintf(fp, "%d\n", sample_count);

    for (int i = 0; i < sample_count; i++) {
        fprintf(fp, "%d\t1\t1\t1\t1\t0\t%s\t1\t1\n", 100+i, "null");
    }

    fclose(fp);
}

void generate_group2rule_sample(const char *table_name, const char *vtable_name,
                                   int sample_count)
{
    FILE *fp = fopen(table_name, "w+");
    if (NULL == fp) {
        log_fatal(g_logger, "open file %s failed", table_name);
        return;
    }

    fprintf(fp, "%d\n", sample_count);

    for (int i = 0; i < sample_count; i++) {
        fprintf(fp, "%d\t%d\t0\t%s\t1\t1\n", i+1, 100+i, vtable_name);
    }

    fclose(fp);
}

void *perf_regex_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    const char *scan_data = "Maat was the goddness of harmony, justice, and truth in ancient Egyptian."
                            "Request from User-Agent: Chrome, will go to yyy.abc.net";
    long long results[ARRAY_SIZE] = {0};
    int hit_times = 0;
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_times; i++) {
        int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                                   results, ARRAY_SIZE, &n_hit_result, state);
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
    log_info(param->logger, MODULE_BENCHMARK_GTEST, 
             "thread_id:%d rule_count:%d regex_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->rule_count, param->time_elapse_ms, hit_times);

    return is_all_hit;
}

void *perf_regex_update_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    const char *table_name = param->table_name;
    const int CMD_EXPR_NUM = 10;
    char keyword_buf[128];

    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        random_keyword_generate(keyword_buf, sizeof(keyword_buf));
        FILE *fp = fopen(table_name, "a+");
        if (NULL == fp) {
            continue;
        }

        fprintf(fp, "%d\t%d\t%s\t1\t0\t0\t1\n", 2000001+i, 2000001+i, keyword_buf);
        fclose(fp);

        sleep(1);
    }

    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = 1;
    
    return is_all_hit;
}

void *perf_literal_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    const char *scan_data = "Maat was the goddness of harmony, justice, and truth in ancient Egyptian."
                            " Her feather was the measure that determined whether the souls of the departed "
                            "would reach the paradise of the afterlife successfully";
    long long results[ARRAY_SIZE] = {0};
    int hit_times = 0;
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_times; i++) {
        int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data),
                                   results, ARRAY_SIZE, &n_hit_result, state);
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
    log_info(param->logger, MODULE_BENCHMARK_GTEST, 
             "thread_id:%d rule_count:%d literal_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->rule_count, param->time_elapse_ms, hit_times);

    return is_all_hit;
}

void *perf_literal_update_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    const char *table_name = param->table_name;
    const int CMD_EXPR_NUM = 10;
    char keyword_buf[128];

    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        random_keyword_generate(keyword_buf, sizeof(keyword_buf));
        FILE *fp = fopen(table_name, "a+");
        if (NULL == fp) {
            continue;
        }

        fprintf(fp, "%d\t%d\t%s\t1\t0\t0\t1\n", 2000001+i, 2000001+i, keyword_buf);
        fclose(fp);

        sleep(1);
    }

    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = 1;
    
    return is_all_hit;
}

void *perf_stream_scan_thread(void *arg)
{
     struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    const char *scan_data = "Maat was the goddness of harmony, justice, and truth in ancient Egyptian."
                            " Her feather was the measure that determined whether the souls of the departed "
                            "would reach the paradise of the afterlife successfully";
    long long results[ARRAY_SIZE] = {0};
    int ret = 0, hit_times = 0;
    size_t n_hit_result = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);
    struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_times; i++) {
        ret = maat_stream_scan(sp, scan_data, strlen(scan_data), results, ARRAY_SIZE,
                                &n_hit_result, state);
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

    log_info(param->logger, MODULE_BENCHMARK_GTEST, 
             "thread_id:%d rule_count:%d stream_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->rule_count, param->time_elapse_ms, hit_times);
    return is_all_hit;
}

void *perf_ip_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    long long results[ARRAY_SIZE] = {0};
    int hit_times = 0;
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    EXPECT_GT(table_id, 0);

    uint32_t ip_addr;
    inet_pton(AF_INET, "100.64.1.1", &ip_addr);

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
    log_info(param->logger, MODULE_BENCHMARK_GTEST, 
             "thread_id:%d rule_count:%d ip_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->rule_count, param->time_elapse_ms, hit_times);

    return is_all_hit;
}

void *perf_ip_update_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    const char *table_name = param->table_name;
    const int CMD_EXPR_NUM = 10;

    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        FILE *fp = fopen(table_name, "a+");
        if (NULL == fp) {
            continue;
        }

        char ip_buf[64] = {0};
        sprintf(ip_buf, "%d.%d.%d.%d", (int)(random() % 256), (int)(random() % 256),
                (int)(random() % 256), (int)(random() % 256));
        fprintf(fp, "%d\t%d\t4\t%s\t%s\t%s\t%s\t%d\t%d\t-1\t1\n",
                8000001+i, 8000001+i, "range", ip_buf, ip_buf, "range", 20000, 20000);
        fclose(fp);

        sleep(1);
    }

    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = 1;
    
    return is_all_hit;
}

void *perf_integer_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    long long results[ARRAY_SIZE] = {0};
    int hit_times = 0;
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    EXPECT_GT(table_id, 0);

    long long scan_data = 1000000;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_times; i++) {
        int ret = maat_scan_integer(maat_inst, table_id, scan_data, results,
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
    log_info(param->logger, MODULE_BENCHMARK_GTEST, 
             "thread_id:%d rule_count:%d integer_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->rule_count, param->time_elapse_ms, hit_times);

    return is_all_hit;
}

void *perf_integer_update_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    const char *table_name = param->table_name;
    const int CMD_EXPR_NUM = 10;

    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        FILE *fp = fopen(table_name, "a+");
        if (NULL == fp) {
            continue;
        }

        fprintf(fp, "%d\t%d\t%d\t%d\t1\n", 10001+i, 10001+i, 10001+i, 10001+i);
        fclose(fp);

        sleep(1);
    }

    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = 1;
    
    return is_all_hit;
}

void *perf_flag_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    long long results[ARRAY_SIZE] = {0};
    int hit_times = 0;
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, param->thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    EXPECT_GT(table_id, 0);

    long long scan_data = 1000000;

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
    log_info(param->logger, MODULE_BENCHMARK_GTEST, 
             "thread_id:%d rule_count:%d flag_scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->rule_count, param->time_elapse_ms, hit_times);

    return is_all_hit;
}

void *perf_flag_update_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    const char *table_name = param->table_name;
    const int CMD_EXPR_NUM = 10;

    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        FILE *fp = fopen(table_name, "a+");
        if (NULL == fp) {
            continue;
        }

        fprintf(fp, "%d\t%d\t%d\t%d\t1\n", 10001+i, 10001+i, 10001+i, 10001+i);
        fclose(fp);

        sleep(1);
    }

    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = 1;
    
    return is_all_hit;
}

class HsRegex100BenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_100\t100\t./regex_rules/REGEX_100\n");
        fprintf(fp, "RULE_PERF\t10\t./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF\t10\t./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "REGEX_100", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsRegex100BenchmarkGTest::_shared_maat_inst;
struct log_handle *HsRegex100BenchmarkGTest::logger;

TEST_F(HsRegex100BenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_100";
    struct maat *maat_inst = HsRegex100BenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 100;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsRegex100Scan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsRegex100BenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("./RULE_PERF");
        system_cmd_rmdir("./GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsRegex100BenchmarkGTest::_shared_maat_inst;
struct log_handle *RsRegex100BenchmarkGTest::logger;

TEST_F(RsRegex100BenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_100";
    struct maat *maat_inst = RsRegex100BenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 100;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsRegex100Scan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsRegex200BenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_200\t200\t./regex_rules/REGEX_200\n");
        fprintf(fp, "RULE_PERF\t10\t./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF\t10\t./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "REGEX_200", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsRegex200BenchmarkGTest::_shared_maat_inst;
struct log_handle *HsRegex200BenchmarkGTest::logger;

TEST_F(HsRegex200BenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_200";
    struct maat *maat_inst = HsRegex200BenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 200;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsRegex200Scan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsRegex200BenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("./RULE_PERF");
        system_cmd_rmdir("./GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsRegex200BenchmarkGTest::_shared_maat_inst;
struct log_handle *RsRegex200BenchmarkGTest::logger;

TEST_F(RsRegex200BenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_200";
    struct maat *maat_inst = RsRegex200BenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 200;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsRegex200Scan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsRegex300BenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_300\t300\t./regex_rules/REGEX_300\n");
        fprintf(fp, "RULE_PERF\t10\t./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF\t10\t./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "REGEX_300", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsRegex300BenchmarkGTest::_shared_maat_inst;
struct log_handle *HsRegex300BenchmarkGTest::logger;

TEST_F(HsRegex300BenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_300";
    struct maat *maat_inst = HsRegex300BenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 300;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsRegex300Scan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsRegex300BenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("./RULE_PERF");
        system_cmd_rmdir("./GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsRegex300BenchmarkGTest::_shared_maat_inst;
struct log_handle *RsRegex300BenchmarkGTest::logger;

TEST_F(RsRegex300BenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_300";
    struct maat *maat_inst = RsRegex300BenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 300;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsRegex300Scan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsRegex500BenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_500\t500\t./regex_rules/REGEX_500\n");
        fprintf(fp, "RULE_PERF\t10\t./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF\t10\t./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "REGEX_500", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsRegex500BenchmarkGTest::_shared_maat_inst;
struct log_handle *HsRegex500BenchmarkGTest::logger;

TEST_F(HsRegex500BenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_500";
    struct maat *maat_inst = HsRegex500BenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 500;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsRegex500Scan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsRegex500BenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("./RULE_PERF");
        system_cmd_rmdir("./GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsRegex500BenchmarkGTest::_shared_maat_inst;
struct log_handle *RsRegex500BenchmarkGTest::logger;

TEST_F(RsRegex500BenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_500";
    struct maat *maat_inst = RsRegex500BenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 500;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsRegex500Scan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsRegex1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_1K\t1000\t./regex_rules/REGEX_1K\n");
        fprintf(fp, "RULE_PERF\t10\t./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF\t10\t./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "REGEX_1K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsRegex1KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsRegex1KBenchmarkGTest::logger;

TEST_F(HsRegex1KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_1K";
    struct maat *maat_inst = HsRegex1KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsRegex1KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsRegex1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("./RULE_PERF");
        system_cmd_rmdir("./GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsRegex1KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsRegex1KBenchmarkGTest::logger;

TEST_F(RsRegex1KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_1K";
    struct maat *maat_inst = RsRegex1KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsRegex1KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsRegex2KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_2K\t2000\t./regex_rules/REGEX_2K\n");
        fprintf(fp, "RULE_PERF\t10\t./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF\t10\t./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "REGEX_2K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsRegex2KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsRegex2KBenchmarkGTest::logger;

TEST_F(HsRegex2KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_2K";
    struct maat *maat_inst = HsRegex2KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 2000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsRegex2KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsRegex2KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("./RULE_PERF");
        system_cmd_rmdir("./GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsRegex2KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsRegex2KBenchmarkGTest::logger;

TEST_F(RsRegex2KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_2K";
    struct maat *maat_inst = RsRegex2KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 2000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsRegex2KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsRegex3KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_3K\t3000\t./regex_rules/REGEX_3K\n");
        fprintf(fp, "RULE_PERF\t10\t./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF\t10\t./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "REGEX_3K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsRegex3KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsRegex3KBenchmarkGTest::logger;

TEST_F(HsRegex3KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_3K";
    struct maat *maat_inst = HsRegex3KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 3000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsRegex3KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsRegex3KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsRegex3KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsRegex3KBenchmarkGTest::logger;

TEST_F(RsRegex3KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_3K";
    struct maat *maat_inst = RsRegex3KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 3000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsRegex3KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsRegex5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_5K\t5000\t./regex_rules/REGEX_5K\n");
        fprintf(fp, "RULE_PERF\t10\t./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF\t10\t./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "REGEX_5K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsRegex5KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsRegex5KBenchmarkGTest::logger;

TEST_F(HsRegex5KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_5K";
    struct maat *maat_inst = HsRegex5KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsRegex5KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsRegex5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsRegex5KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsRegex5KBenchmarkGTest::logger;

TEST_F(RsRegex5KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_5K";
    struct maat *maat_inst = RsRegex5KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsRegex5KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsRegex10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_10K\t10000\t./regex_rules/REGEX_10K\n");
        fprintf(fp, "RULE_PERF\t10\t./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF\t10\t./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "REGEX_10K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsRegex10KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsRegex10KBenchmarkGTest::logger;

TEST_F(HsRegex10KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_10K";
    struct maat *maat_inst = HsRegex10KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsRegex10KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsRegex10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsRegex10KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsRegex10KBenchmarkGTest::logger;

TEST_F(RsRegex10KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_10K";
    struct maat *maat_inst = RsRegex10KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsRegex10KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsRegex15KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_15K\t15000\t./regex_rules/REGEX_15K\n");
        fprintf(fp, "RULE_PERF\t10\t./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF\t10\t./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "REGEX_15K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsRegex15KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsRegex15KBenchmarkGTest::logger;

TEST_F(HsRegex15KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_15K";
    struct maat *maat_inst = HsRegex15KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 15000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsRegex15KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsRegex15KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsRegex15KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsRegex15KBenchmarkGTest::logger;

TEST_F(RsRegex15KBenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_15K";
    struct maat *maat_inst = RsRegex15KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 15000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsRegex15KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsExpr1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_1K", 1000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_1K 1000 ./EXPR_LITERAL_1K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "EXPR_LITERAL_1K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsExpr1KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsExpr1KBenchmarkGTest::logger;

TEST_F(HsExpr1KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_1K";
    struct maat *maat_inst = HsExpr1KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsExpr1KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsExpr1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsExpr1KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsExpr1KBenchmarkGTest::logger;

TEST_F(RsExpr1KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_1K";
    struct maat *maat_inst = RsExpr1KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsExpr1KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsExpr5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_5K", 5000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_5K 5000 ./EXPR_LITERAL_5K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "EXPR_LITERAL_5K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsExpr5KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsExpr5KBenchmarkGTest::logger;

TEST_F(HsExpr5KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_5K";
    struct maat *maat_inst = HsExpr5KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsExpr5KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsExpr5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsExpr5KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsExpr5KBenchmarkGTest::logger;

TEST_F(RsExpr5KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_5K";
    struct maat *maat_inst = RsExpr5KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsExpr5KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsExpr10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_10K", 10000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_10K 10000 ./EXPR_LITERAL_10K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "EXPR_LITERAL_10K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsExpr10KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsExpr10KBenchmarkGTest::logger;

TEST_F(HsExpr10KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_10K";
    struct maat *maat_inst = HsExpr10KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsExpr10KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsExpr10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsExpr10KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsExpr10KBenchmarkGTest::logger;

TEST_F(RsExpr10KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_10K";
    struct maat *maat_inst = RsExpr10KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsExpr10KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsExpr50KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_50K", 50000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_50K 50000 ./EXPR_LITERAL_50K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "EXPR_LITERAL_50K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsExpr50KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsExpr50KBenchmarkGTest::logger;

TEST_F(HsExpr50KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_50K";
    struct maat *maat_inst = HsExpr50KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 50000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsExpr50KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsExpr50KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsExpr50KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsExpr50KBenchmarkGTest::logger;

TEST_F(RsExpr50KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_50K";
    struct maat *maat_inst = RsExpr50KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 50000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsExpr50KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsExpr100KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_100K", 100000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_100K 100000 ./EXPR_LITERAL_100K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "EXPR_LITERAL_100K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsExpr100KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsExpr100KBenchmarkGTest::logger;

TEST_F(HsExpr100KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_100K";
    struct maat *maat_inst = HsExpr100KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 100000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsExpr100KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsExpr100KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsExpr100KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsExpr100KBenchmarkGTest::logger;

TEST_F(RsExpr100KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_100K";
    struct maat *maat_inst = RsExpr100KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 100000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsExpr100KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsExpr500KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_500K", 500000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_500K 500000 ./EXPR_LITERAL_500K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "EXPR_LITERAL_500K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsExpr500KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsExpr500KBenchmarkGTest::logger;

TEST_F(HsExpr500KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_500K";
    struct maat *maat_inst = HsExpr500KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 500000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsExpr500KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsExpr500KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsExpr500KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsExpr500KBenchmarkGTest::logger;

TEST_F(RsExpr500KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_500K";
    struct maat *maat_inst = RsExpr500KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 500000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsExpr500KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsExpr1MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_1M", 1000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_1M 1000000 ./EXPR_LITERAL_1M\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "EXPR_LITERAL_1M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsExpr1MBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsExpr1MBenchmarkGTest::logger;

TEST_F(HsExpr1MBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_1M";
    struct maat *maat_inst = HsExpr1MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsExpr1MLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsExpr1MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsExpr1MBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsExpr1MBenchmarkGTest::logger;

TEST_F(RsExpr1MBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_1M";
    struct maat *maat_inst = RsExpr1MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsExpr1MLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsExpr2MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_2M", 2000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_2M 2000000 ./EXPR_LITERAL_2M\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "EXPR_LITERAL_2M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsExpr2MBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsExpr2MBenchmarkGTest::logger;

TEST_F(HsExpr2MBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_2M";
    struct maat *maat_inst = HsExpr2MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 2000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsExpr2MLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsExpr2MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsExpr2MBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsExpr2MBenchmarkGTest::logger;

TEST_F(RsExpr2MBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_2M";
    struct maat *maat_inst = RsExpr2MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 2000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
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
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsExpr2MLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsStream1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("STREAM_1K", 1000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_1K 1000 ./STREAM_1K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "STREAM_1K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsStream1KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsStream1KBenchmarkGTest::logger;

TEST_F(HsStream1KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_1K";
    struct maat *maat_inst = HsStream1KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsStream1KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsStream1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsStream1KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsStream1KBenchmarkGTest::logger;

TEST_F(RsStream1KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_1K";
    struct maat *maat_inst = RsStream1KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsStream1KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsStream5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("STREAM_5K", 5000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_5K 5000 ./STREAM_5K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "STREAM_5K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsStream5KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsStream5KBenchmarkGTest::logger;

TEST_F(HsStream5KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_5K";
    struct maat *maat_inst = HsStream5KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsStream5KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsStream5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsStream5KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsStream5KBenchmarkGTest::logger;

TEST_F(RsStream5KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_5K";
    struct maat *maat_inst = RsStream5KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsStream5KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsStream10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("STREAM_10K", 10000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_10K 10000 ./STREAM_10K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "STREAM_10K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsStream10KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsStream10KBenchmarkGTest::logger;

TEST_F(HsStream10KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_10K";
    struct maat *maat_inst = HsStream10KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsStream10KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsStream10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsStream10KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsStream10KBenchmarkGTest::logger;

TEST_F(RsStream10KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_10K";
    struct maat *maat_inst = RsStream10KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsStream10KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsStream50KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("STREAM_50K", 50000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_50K 50000 ./STREAM_50K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "STREAM_50K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsStream50KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsStream50KBenchmarkGTest::logger;

TEST_F(HsStream50KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_50K";
    struct maat *maat_inst = HsStream50KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 50000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsStream50KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsStream50KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        
        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsStream50KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsStream50KBenchmarkGTest::logger;

TEST_F(RsStream50KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_50K";
    struct maat *maat_inst = RsStream50KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 50000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsStream50KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsStream100KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("STREAM_100K", 100000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_100K 100000 ./STREAM_100K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "STREAM_100K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsStream100KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsStream100KBenchmarkGTest::logger;

TEST_F(HsStream100KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_100K";
    struct maat *maat_inst = HsStream100KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 100000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsStream100KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsStream100KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsStream100KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsStream100KBenchmarkGTest::logger;

TEST_F(RsStream100KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_100K";
    struct maat *maat_inst = RsStream100KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 100000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsStream100KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsStream500KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("STREAM_500K", 500000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_500K 500000 ./STREAM_500K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "STREAM_500K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsStream500KBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsStream500KBenchmarkGTest::logger;

TEST_F(HsStream500KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_500K";
    struct maat *maat_inst = HsStream500KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 500000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsStream500KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsStream500KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsStream500KBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsStream500KBenchmarkGTest::logger;

TEST_F(RsStream500KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_500K";
    struct maat *maat_inst = RsStream500KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 500000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsStream500KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsStream1MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("STREAM_1M", 1000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_1M 1000000 ./STREAM_1M\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "STREAM_1M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsStream1MBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsStream1MBenchmarkGTest::logger;

TEST_F(HsStream1MBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_1M";
    struct maat *maat_inst = HsStream1MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsStream1MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsStream1MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsStream1MBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsStream1MBenchmarkGTest::logger;

TEST_F(RsStream1MBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_1M";
    struct maat *maat_inst = RsStream1MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsStream1MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class HsStream2MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_expr_sample("STREAM_2M", 2000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_2M 2000000 ./STREAM_2M\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "STREAM_2M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_HS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *HsStream2MBenchmarkGTest::_shared_maat_inst;
struct log_handle *HsStream2MBenchmarkGTest::logger;

TEST_F(HsStream2MBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_2M";
    struct maat *maat_inst = HsStream2MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 2000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "HsStream2MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class RsStream2MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *RsStream2MBenchmarkGTest::_shared_maat_inst;
struct log_handle *RsStream2MBenchmarkGTest::logger;

TEST_F(RsStream2MBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_2M";
    struct maat *maat_inst = RsStream2MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 2000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_times = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_times += thread_params[i].test_times;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_times * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "RsStream2MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class IP1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_ip_sample("IP_1K", 1000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_1K 1000 ./IP_1K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "IP_1K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IP1KBenchmarkGTest::_shared_maat_inst;
struct log_handle *IP1KBenchmarkGTest::logger;

TEST_F(IP1KBenchmarkGTest, IPScan) {
    const char *table_name = "IP_1K";
    struct maat *maat_inst = IP1KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP1KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_ip_sample("IP_5K", 5000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_5K 5000 ./IP_5K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "IP_5K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IP5KBenchmarkGTest::_shared_maat_inst;
struct log_handle *IP5KBenchmarkGTest::logger;

TEST_F(IP5KBenchmarkGTest, IPScan) {
    const char *table_name = "IP_5K";
    struct maat *maat_inst = IP5KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP5KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_ip_sample("IP_10K", 10000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_10K 10000 ./IP_10K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "IP_10K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IP10KBenchmarkGTest::_shared_maat_inst;
struct log_handle *IP10KBenchmarkGTest::logger;

TEST_F(IP10KBenchmarkGTest, IPScan) {
    const char *table_name = "IP_10K";
    struct maat *maat_inst = IP10KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP10KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP50KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_ip_sample("IP_50K", 50000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_50K 50000 ./IP_50K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "IP_50K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IP50KBenchmarkGTest::_shared_maat_inst;
struct log_handle *IP50KBenchmarkGTest::logger;

TEST_F(IP50KBenchmarkGTest, IPScan) {
    const char *table_name = "IP_50K";
    struct maat *maat_inst = IP50KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 50000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP50KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP100KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_ip_sample("IP_100K", 100000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_100K 100000 ./IP_100K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "IP_100K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IP100KBenchmarkGTest::_shared_maat_inst;
struct log_handle *IP100KBenchmarkGTest::logger;

TEST_F(IP100KBenchmarkGTest, IPScan) {
    const char *table_name = "IP_100K";
    struct maat *maat_inst = IP100KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 100000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP100KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP500KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_ip_sample("IP_500K", 500000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_500K 500000 ./IP_500K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "IP_500K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IP500KBenchmarkGTest::_shared_maat_inst;
struct log_handle *IP500KBenchmarkGTest::logger;

TEST_F(IP500KBenchmarkGTest, IPScan) {
    const char *table_name = "IP_500K";
    struct maat *maat_inst = IP500KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 500000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP500KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP1MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_ip_sample("IP_1M", 1000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_1M 1000000 ./IP_1M\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "IP_1M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IP1MBenchmarkGTest::_shared_maat_inst;
struct log_handle *IP1MBenchmarkGTest::logger;

TEST_F(IP1MBenchmarkGTest, IPScan) {
    const char *table_name = "IP_1M";
    struct maat *maat_inst = IP1MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP1MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP5MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_ip_sample("IP_5M", 5000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_5M 5000000 ./IP_5M\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "IP_5M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IP5MBenchmarkGTest::_shared_maat_inst;
struct log_handle *IP5MBenchmarkGTest::logger;

TEST_F(IP5MBenchmarkGTest, IPScan) {
    const char *table_name = "IP_5M";
    struct maat *maat_inst = IP5MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 5000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP5MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP10MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_ip_sample("IP_10M", 10000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_10M 10000000 ./IP_10M\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "IP_10M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *IP10MBenchmarkGTest::_shared_maat_inst;
struct log_handle *IP10MBenchmarkGTest::logger;

TEST_F(IP10MBenchmarkGTest, IPScan) {
    const char *table_name = "IP_10M";
    struct maat *maat_inst = IP10MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 10000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP10MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Integer1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_integer_sample("INTEGER_1K", 1000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "INTEGER_1K 1000 ./INTEGER_1K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "INTEGER_1K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Integer1KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Integer1KBenchmarkGTest::logger;

TEST_F(Integer1KBenchmarkGTest, IntegerScan) {
    const char *table_name = "INTEGER_1K";
    struct maat *maat_inst = Integer1KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_integer_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_integer_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Integer1KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Integer5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_integer_sample("INTEGER_5K", 5000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "INTEGER_5K 5000 ./INTEGER_5K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "INTEGER_5K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Integer5KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Integer5KBenchmarkGTest::logger;

TEST_F(Integer5KBenchmarkGTest, IntegerScan) {
    const char *table_name = "INTEGER_5K";
    struct maat *maat_inst = Integer5KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_integer_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_integer_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Integer5KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Integer10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_integer_sample("INTEGER_10K", 10000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "INTEGER_10K 10000 ./INTEGER_10K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "INTEGER_10K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Integer10KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Integer10KBenchmarkGTest::logger;

TEST_F(Integer10KBenchmarkGTest, IntegerScan) {
    const char *table_name = "INTEGER_10K";
    struct maat *maat_inst = Integer10KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_integer_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_integer_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Integer10KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Flag1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_flag_sample("FLAG_1K", 1000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "FLAG_1K 1000 ./FLAG_1K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "FLAG_1K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Flag1KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Flag1KBenchmarkGTest::logger;

TEST_F(Flag1KBenchmarkGTest, FlagScan) {
    const char *table_name = "FLAG_1K";
    struct maat *maat_inst = Flag1KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_flag_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_flag_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Flag1KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Flag5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_flag_sample("FLAG_5K", 5000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "FLAG_5K 5000 ./FLAG_5K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "FLAG_5K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Flag5KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Flag5KBenchmarkGTest::logger;

TEST_F(Flag5KBenchmarkGTest, FlagScan) {
    const char *table_name = "FLAG_5K";
    struct maat *maat_inst = Flag5KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_flag_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_flag_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Flag5KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Flag10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_gtest.log", 0);
        generate_flag_sample("FLAG_10K", 10000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "FLAG_10K 10000 ./FLAG_10K\n");
        fprintf(fp, "RULE_PERF 10 ./RULE_PERF\n");
        fprintf(fp, "GROUP2RULE_PERF 10 ./GROUP2RULE_PERF\n");
        fclose(fp);

        generate_rule_sample("RULE_PERF", 10);
        generate_group2rule_sample("GROUP2RULE_PERF", "FLAG_10K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        _shared_maat_inst = maat_new(opts, g_table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("RULE_PERF");
        system_cmd_rmdir("GROUP2RULE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Flag10KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Flag10KBenchmarkGTest::logger;

TEST_F(Flag10KBenchmarkGTest, FlagScan) {
    const char *table_name = "FLAG_10K";
    struct maat *maat_inst = Flag10KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_times = MAX_SCAN_TIMES;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_flag_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_times = 0;
            pthread_create(&threads[i], NULL, perf_flag_update_thread, thread_params+i);
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

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Flag10KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
    g_logger = log_handle_create("./benchmark_gtest.log", 0);

	ret=RUN_ALL_TESTS();

    log_handle_destroy(g_logger);
	return ret;
}
