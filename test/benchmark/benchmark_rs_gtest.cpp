#include "maat.h"
#include "log/log.h"
#include "maat_utils.h"
#include "maat_rule.h"
#include "json2iris.h"
#include "ip_matcher.h"
#include "maat_table.h"
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
#define MAX_SCAN_COUNT 1000000

const char *table_info_path = "./benchmark_table_info.conf";
struct log_handle *g_logger = NULL;

struct thread_param {
	int thread_id;
	int test_count;
    int rule_count;
	struct maat *maat_inst;
	const char *table_name;
	long long time_elapse_ms;
    struct log_handle *logger;
};

static void random_keyword_generate(char *keyword_buf, size_t sz)
{
#define MIN_KEYWORD_LEN	4
	size_t i = 0, len = 0;
	len = random() % (sz - 1 - MIN_KEYWORD_LEN) + MIN_KEYWORD_LEN;

	for (i = 0; i < len; i++) {
		keyword_buf[i] = 'a' + random() % ('z' - 'a');
	}
	keyword_buf[i] = '\0';
}

void generate_expr_sample(const char *table_name, int sample_count)
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

void generate_ip_sample(const char *table_name, int sample_count)
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

void generate_integer_sample(const char *table_name, int sample_count)
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

void generate_compile_sample(const char *table_name, int sample_count)
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

void generate_group2compile_sample(const char *table_name, const char *vtable_name,
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
    for (int i = 0; i < param->test_count; i++) {
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
    *is_all_hit = (hit_times == param->test_count ? 1 : 0);
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
    for (int i = 0; i < param->test_count; i++) {
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
    *is_all_hit = ((hit_times == param->test_count) ? 1 : 0);

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
    uint16_t port = htons(20000);
    int proto = 6;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_count; i++) {
        int ret = maat_scan_ipv4(maat_inst, table_id, ip_addr, port, proto,
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
    *is_all_hit = (hit_times == param->test_count ? 1 : 0);
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
    for (int i = 0; i < param->test_count; i++) {
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
    *is_all_hit = (hit_times == param->test_count ? 1 : 0);
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
    for (int i = 0; i < param->test_count; i++) {
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
    *is_all_hit = (hit_times == param->test_count ? 1 : 0);
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
    for (int i = 0; i < param->test_count; i++) {
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
    *is_all_hit = (hit_times == param->test_count ? 1 : 0);
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

class Regex100BenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_100\t100\t./regex_rules/REGEX_100\n");
        fprintf(fp, "COMPILE_PERF\t10\t./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF\t10\t./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "REGEX_100", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Regex100BenchmarkGTest::_shared_maat_inst;
struct log_handle *Regex100BenchmarkGTest::logger;

TEST_F(Regex100BenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_100";
    struct maat *maat_inst = Regex100BenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 100;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Regex100Scan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Regex200BenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_200\t200\t./regex_rules/REGEX_200\n");
        fprintf(fp, "COMPILE_PERF\t10\t./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF\t10\t./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "REGEX_200", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Regex200BenchmarkGTest::_shared_maat_inst;
struct log_handle *Regex200BenchmarkGTest::logger;

TEST_F(Regex200BenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_200";
    struct maat *maat_inst = Regex200BenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 200;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Regex200Scan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Regex300BenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "REGEX_300\t300\t./regex_rules/REGEX_300\n");
        fprintf(fp, "COMPILE_PERF\t10\t./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF\t10\t./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "REGEX_300", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Regex300BenchmarkGTest::_shared_maat_inst;
struct log_handle *Regex300BenchmarkGTest::logger;

TEST_F(Regex300BenchmarkGTest, LiteralScan) {
    const char *table_name = "REGEX_300";
    struct maat *maat_inst = Regex300BenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 300;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_regex_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_regex_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Regex300Scan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Expr1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_1K", 1000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_1K 1000 ./EXPR_LITERAL_1K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "EXPR_LITERAL_1K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Expr1KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Expr1KBenchmarkGTest::logger;

TEST_F(Expr1KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_1K";
    struct maat *maat_inst = Expr1KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Expr1KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Expr5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_5K", 5000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_5K 5000 ./EXPR_LITERAL_5K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "EXPR_LITERAL_5K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Expr5KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Expr5KBenchmarkGTest::logger;

TEST_F(Expr5KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_5K";
    struct maat *maat_inst = Expr5KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Expr5KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Expr10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_10K", 10000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_10K 10000 ./EXPR_LITERAL_10K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "EXPR_LITERAL_10K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Expr10KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Expr10KBenchmarkGTest::logger;

TEST_F(Expr10KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_10K";
    struct maat *maat_inst = Expr10KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Expr10KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Expr50KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_50K", 50000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_50K 50000 ./EXPR_LITERAL_50K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "EXPR_LITERAL_50K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Expr50KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Expr50KBenchmarkGTest::logger;

TEST_F(Expr50KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_50K";
    struct maat *maat_inst = Expr50KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 50000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Expr50KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Expr100KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_100K", 100000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_100K 100000 ./EXPR_LITERAL_100K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "EXPR_LITERAL_100K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Expr100KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Expr100KBenchmarkGTest::logger;

TEST_F(Expr100KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_100K";
    struct maat *maat_inst = Expr100KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 100000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Expr100KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Expr500KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_500K", 500000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_500K 500000 ./EXPR_LITERAL_500K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "EXPR_LITERAL_500K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Expr500KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Expr500KBenchmarkGTest::logger;

TEST_F(Expr500KBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_500K";
    struct maat *maat_inst = Expr500KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 500000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Expr500KLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Expr1MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_1M", 1000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_1M 1000000 ./EXPR_LITERAL_1M\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "EXPR_LITERAL_1M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Expr1MBenchmarkGTest::_shared_maat_inst;
struct log_handle *Expr1MBenchmarkGTest::logger;

TEST_F(Expr1MBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_1M";
    struct maat *maat_inst = Expr1MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 1000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Expr1MLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Expr2MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("EXPR_LITERAL_2M", 2000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "EXPR_LITERAL_2M 2000000 ./EXPR_LITERAL_2M\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "EXPR_LITERAL_2M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Expr2MBenchmarkGTest::_shared_maat_inst;
struct log_handle *Expr2MBenchmarkGTest::logger;

TEST_F(Expr2MBenchmarkGTest, LiteralScan) {
    const char *table_name = "EXPR_LITERAL_2M";
    struct maat *maat_inst = Expr2MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 2000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_literal_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_literal_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Expr2MLiteralScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Stream1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("STREAM_1K", 1000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_1K 1000 ./STREAM_1K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "STREAM_1K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Stream1KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Stream1KBenchmarkGTest::logger;

TEST_F(Stream1KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_1K";
    struct maat *maat_inst = Stream1KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Stream1KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Stream5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("STREAM_5K", 5000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_5K 5000 ./STREAM_5K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "STREAM_5K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Stream5KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Stream5KBenchmarkGTest::logger;

TEST_F(Stream5KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_5K";
    struct maat *maat_inst = Stream5KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Stream5KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Stream10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("STREAM_10K", 10000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_10K 10000 ./STREAM_10K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "STREAM_10K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Stream10KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Stream10KBenchmarkGTest::logger;

TEST_F(Stream10KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_10K";
    struct maat *maat_inst = Stream10KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Stream10KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Stream50KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("STREAM_50K", 50000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_50K 50000 ./STREAM_50K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "STREAM_50K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Stream50KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Stream50KBenchmarkGTest::logger;

TEST_F(Stream50KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_50K";
    struct maat *maat_inst = Stream50KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 50000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Stream50KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Stream100KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("STREAM_100K", 100000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_100K 100000 ./STREAM_100K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "STREAM_100K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Stream100KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Stream100KBenchmarkGTest::logger;

TEST_F(Stream100KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_100K";
    struct maat *maat_inst = Stream100KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 100000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Stream100KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Stream500KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("STREAM_500K", 500000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_500K 500000 ./STREAM_500K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "STREAM_500K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Stream500KBenchmarkGTest::_shared_maat_inst;
struct log_handle *Stream500KBenchmarkGTest::logger;

TEST_F(Stream500KBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_500K";
    struct maat *maat_inst = Stream500KBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 500000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Stream500KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Stream1MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("STREAM_1M", 1000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_1M 1000000 ./STREAM_1M\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "STREAM_1M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Stream1MBenchmarkGTest::_shared_maat_inst;
struct log_handle *Stream1MBenchmarkGTest::logger;

TEST_F(Stream1MBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_1M";
    struct maat *maat_inst = Stream1MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 1000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Stream1MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class Stream2MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_expr_sample("STREAM_2M", 2000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "STREAM_2M 2000000 ./STREAM_2M\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "STREAM_2M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
    }

    static struct log_handle *logger;
    static struct maat *_shared_maat_inst;
};

struct maat *Stream2MBenchmarkGTest::_shared_maat_inst;
struct log_handle *Stream2MBenchmarkGTest::logger;

TEST_F(Stream2MBenchmarkGTest, LiteralScan) {
    const char *table_name = "STREAM_2M";
    struct maat *maat_inst = Stream2MBenchmarkGTest::_shared_maat_inst;

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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 2000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_stream_scan_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;
   
    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Stream2MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second);
}

class IP1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_ip_sample("IP_1K", 1000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_1K 1000 ./IP_1K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "IP_1K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP1KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_ip_sample("IP_5K", 5000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_5K 5000 ./IP_5K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "IP_5K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP5KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_ip_sample("IP_10K", 10000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_10K 10000 ./IP_10K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "IP_10K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP10KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP50KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_ip_sample("IP_50K", 50000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_50K 50000 ./IP_50K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "IP_50K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 50000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP50KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP100KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_ip_sample("IP_100K", 100000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_100K 100000 ./IP_100K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "IP_100K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 100000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP100KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP500KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_ip_sample("IP_500K", 500000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_500K 500000 ./IP_500K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "IP_500K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 500000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP500KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP1MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_ip_sample("IP_1M", 1000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_1M 1000000 ./IP_1M\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "IP_1M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 1000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP1MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP5MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_ip_sample("IP_5M", 5000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_5M 5000000 ./IP_5M\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "IP_5M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 5000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP5MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class IP10MBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_ip_sample("IP_10M", 10000000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "IP_10M 10000000 ./IP_10M\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "IP_10M", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);
        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 10000000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_ip_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_ip_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "IP10MScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Integer1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_integer_sample("INTEGER_1K", 1000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "INTEGER_1K 1000 ./INTEGER_1K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "INTEGER_1K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_integer_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_integer_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Integer1KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Integer5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_integer_sample("INTEGER_5K", 5000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "INTEGER_5K 5000 ./INTEGER_5K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "INTEGER_5K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_integer_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_integer_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Integer5KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Integer10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_integer_sample("INTEGER_10K", 10000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "INTEGER_10K 10000 ./INTEGER_10K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "INTEGER_10K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_integer_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_integer_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Integer10KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Flag1KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_flag_sample("FLAG_1K", 1000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "FLAG_1K 1000 ./FLAG_1K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "FLAG_1K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 1000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_flag_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_flag_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Flag1KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Flag5KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_flag_sample("FLAG_5K", 5000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "FLAG_5K 5000 ./FLAG_5K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "FLAG_5K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 5000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_flag_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_flag_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Flag5KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

class Flag10KBenchmarkGTest : public ::testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create("./benchmark_rs_gtest.log", 0);
        generate_flag_sample("FLAG_10K", 10000);

        FILE *fp = fopen("full_config_index.0000001", "w+");
        if (NULL == fp) {
            log_fatal(g_logger, "open file %s failed", "full_config_index.0000001");
            return;
        }
        fprintf(fp, "FLAG_10K 10000 ./FLAG_10K\n");
        fprintf(fp, "COMPILE_PERF 10 ./COMPILE_PERF\n");
        fprintf(fp, "GROUP2COMPILE_PERF 10 ./GROUP2COMPILE_PERF\n");
        fclose(fp);

        generate_compile_sample("COMPILE_PERF", 10);
        generate_group2compile_sample("GROUP2COMPILE_PERF", "FLAG_10K", 10);

        struct maat_options *opts = maat_options_new();
        maat_options_set_logger(opts, "./benchmark_rs_gtest.log", LOG_LEVEL_INFO);
        maat_options_set_iris(opts, "./", "./");
        maat_options_set_rule_effect_interval_ms(opts, 1000);
        maat_options_set_caller_thread_number(opts, PERF_THREAD_NUM);
        maat_options_set_expr_engine(opts, MAAT_EXPR_ENGINE_RS);

        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
        log_handle_destroy(logger);
        system_cmd_rmdir("COMPILE_PERF");
        system_cmd_rmdir("GROUP2COMPILE_PERF");
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
        thread_params[i].test_count = MAX_SCAN_COUNT;
        thread_params[i].rule_count = 10000;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;

        if (i < PERF_THREAD_NUM) {
            pthread_create(&threads[i], NULL, perf_flag_scan_thread, thread_params+i);
        } else {
            thread_params[i].test_count = 0;
            pthread_create(&threads[i], NULL, perf_flag_update_thread, thread_params+i);
        }
    }

    long long time_elapse_ms = 0;
    long long scan_count = 0;
    long long scan_per_second = 0;
    for (i = 0; i < PERF_THREAD_NUM + 1; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;
		scan_count += thread_params[i].test_count;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    scan_per_second = scan_count * 1000 / time_elapse_ms;

    log_info(maat_inst->logger, MODULE_BENCHMARK_GTEST,
             "Flag10KScan match rate on %d-threads speed %lld lookups/s/thread",
             PERF_THREAD_NUM, scan_per_second); 
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
    g_logger = log_handle_create("./benchmark_rs_gtest.log", 0);

	ret=RUN_ALL_TESTS();

    log_handle_destroy(g_logger);
	return ret;
}