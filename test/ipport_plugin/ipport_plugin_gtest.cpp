#include "maat.h"
#include "log/log.h"
#include "cJSON/cJSON.h"
#include "maat_core.h"
#include "maat_utils.h"
#include "log/log.h"
#include "../test_utils.h"
#include "maat_config_monitor.h"
#include "maat_redis_monitor.h"

#include <gtest/gtest.h>

#define MODULE_IPPORT_PLUGIN_GTEST module_name_str("maat.ipport_plugin_gtest")
#define ARRAY_SIZE 10
#define PERF_scan_times 1000 * 1000

const char *g_table_info_path = "./ipport_plugin_table_info.conf";
const char *log_file = "./ipport_plugin_gtest.log";
const char *g_ip_str = "116.71.169.140";

class IPPortPluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        logger = log_handle_create(log_file, 0);
    }

    static void TearDownTestCase() {
        log_handle_destroy(logger);
    }

    static struct log_handle *logger;
};

struct log_handle *IPPortPluginTable::logger;

struct ipport_plugin_ud {
	long long rule_id;
	char *buffer;
    size_t buf_len;
};
void ipport_plugin_ex_new_cb(const char *table_name, int table_id,
                             const char *key, const char *table_line,
                             void **ad, long argl, void *argp)
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

void ipport_plugin_ex_dup_cb(int table_id, void **to, void **from,
                             long argl, void *argp)
{
	struct ipport_plugin_ud *ud = (struct ipport_plugin_ud *)(*from);
	
	*to = ud;
}

struct thread_param {
	int thread_id;
	int test_count;
    uint16_t port;
	struct maat *maat_inst;
	const char *table_name;
	long long time_elapse_ms;
    struct log_handle *logger;
};

void *ipport_plugin_scan_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    struct timespec start, end;
    int table_id = maat_get_table_id(maat_inst, table_name);

    struct ip_addr ipv4;
    ipv4.ip_type = IPV4;
    int ret = inet_pton(AF_INET, g_ip_str, &ipv4.ipv4);
    EXPECT_EQ(ret, 1);

    uint16_t port = htons(param->port);
    int hit_times = 0;
    struct ipport_plugin_ud *results[ARRAY_SIZE];

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < param->test_count; i++) {
        ret = maat_ipport_plugin_table_get_ex_data(maat_inst, table_id, &ipv4,
                                                   port, (void **)results,
                                                   ARRAY_SIZE);
        EXPECT_EQ(ret, 1);
        if (ret == 1) {
            hit_times++;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    param->time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 +
                            (end.tv_nsec - start.tv_nsec) / 1000000;
    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = (hit_times == param->test_count ? 1 : 0);
    log_info(param->logger, MODULE_IPPORT_PLUGIN_GTEST, 
             "thread_id:%d ipport_plugin scan time_elapse:%lldms hit_times:%d", 
             param->thread_id, param->time_elapse_ms, hit_times);
    return is_all_hit;
}

static int
test_add_ipport_plugin_command(struct maat *maat_inst, const char *table_name,
                               long long item_id, const char *ip_str, int port1,
                               int port2)
{
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return -1;
    }

    enum table_type table_type =
        table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_IPPORT_PLUGIN) {
        return -1;
    }

    char table_line[1024] = {0};
    sprintf(table_line, "%lld\t4\t%s\t%d\t%d\t1", item_id, ip_str, port1, port2);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = 0;

    maat_cmd_set_line(maat_inst, &line_rule);

    return 0;
}

static int
test_del_ipport_plugin_command(struct maat *maat_inst, const char *table_name,
                               long long item_id, const char *ip_str, int port1,
                               int port2)
{
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return -1;
    }

    enum table_type table_type =
        table_manager_get_table_type(maat_inst->tbl_mgr, table_id);
    if (table_type != TABLE_TYPE_IPPORT_PLUGIN) {
        return -1;
    }

    char table_line[1024] = {0};
    sprintf(table_line, "%lld\t4\t%s\t%d\t%d\t0", item_id, ip_str, port1, port2);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = 0;

    maat_cmd_set_line(maat_inst, &line_rule);

    return 0;
}

void *ipport_plugin_update_thread(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    struct maat *maat_inst = param->maat_inst;
    const char *table_name = param->table_name;
    const int CMD_EXPR_NUM = 256;
    long long item_id = 9000000;
    int ret = 0;

    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        ret = test_add_ipport_plugin_command(maat_inst, table_name, item_id,
                                             g_ip_str, i+201, i+201);
        if (ret < 0) {
            log_fatal(param->logger, MODULE_IPPORT_PLUGIN_GTEST,
                     "[%s:%d]add ipport rule(item_id:%lld) for table:%s failed.",
                     __FUNCTION__, __LINE__, item_id, table_name);
            continue;
        }
        item_id++;
        usleep(100 * 1000);
    }

    item_id = 9000000; 
    for (int i = 0; i < CMD_EXPR_NUM; i++) {
        ret = test_del_ipport_plugin_command(maat_inst, table_name, item_id,
                                             g_ip_str, i+201, i+201);
        if (ret < 0) {
            log_fatal(param->logger, MODULE_IPPORT_PLUGIN_GTEST,
                     "[%s:%d]del ipport rule(item_id:%lld) for table:%s failed.",
                     __FUNCTION__, __LINE__, item_id, table_name);
            continue;
        }
        usleep(100 * 1000);
        item_id++;
    }

    int *is_all_hit = ALLOC(int, 1);
    *is_all_hit = 1;
    
    return is_all_hit;
}

TEST_F(IPPortPluginTable, WITHOUT_SAME_IP) {
    char redis_ip[32] = "127.0.0.1";
    int redis_port = 6379;
    int redis_db = 0;
    char iris_idx_path[PATH_MAX] = {0};
    struct log_handle *logger = IPPortPluginTable::logger;

    snprintf(iris_idx_path, sizeof(iris_idx_path), "test_data/index");

    int ret = write_iris_to_redis(iris_idx_path, redis_ip, redis_port,
                                  redis_db, logger);
    assert(ret == 0);

    struct maat_options *opts = maat_options_new();
    maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
    maat_options_set_logger(opts, log_file, LOG_LEVEL_INFO);
    maat_options_set_stat_file(opts, "./stat.log");
    maat_options_set_rule_update_checking_interval_ms(opts, 100);

    struct maat *maat_inst = maat_new(opts, g_table_info_path);
    assert(maat_inst);
    maat_options_free(opts);

    int ex_data_counter = 0;
    const char *table_name = "IPPORT_PLUGIN_WITHOUT_SAME_IP";

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                ipport_plugin_ex_new_cb,
                                                ipport_plugin_ex_free_cb,
                                                ipport_plugin_ex_dup_cb,
                                                0, &ex_data_counter);
    EXPECT_EQ(ret, 0);

    int i = 0;
    pthread_t threads[2];
    struct thread_param thread_params[2];

    for (i = 0; i < 2; i++) {
        thread_params[i].maat_inst = maat_inst;
        thread_params[i].thread_id = i;
        thread_params[i].table_name = table_name;
        thread_params[i].port = 10;
        thread_params[i].test_count = PERF_scan_times;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;
    }

    pthread_create(&threads[0], NULL, ipport_plugin_scan_thread, thread_params);
    pthread_create(&threads[1], NULL, ipport_plugin_update_thread,
                    thread_params + 1);

    int *is_all_hit = NULL;
    long long time_elapse_ms = 0;
    long long scan_per_second = 0;
    for (i = 0; i < 2; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }

    maat_free(maat_inst);
    scan_per_second = PERF_scan_times * 1000 / time_elapse_ms;
    log_info(maat_inst->logger, MODULE_IPPORT_PLUGIN_GTEST,
             "IpportPluginScan without same ip match rate speed"
             " %lld lookups/s/thread", scan_per_second);
}

TEST_F(IPPortPluginTable, WITH_256SAME_IP) {
    char redis_ip[32] = "127.0.0.1";
    int redis_port = 6379;
    int redis_db = 0;
    char iris_idx_path[PATH_MAX] = {0};
    struct log_handle *logger = IPPortPluginTable::logger;

    snprintf(iris_idx_path, sizeof(iris_idx_path), "test_data/index");

    int ret = write_iris_to_redis(iris_idx_path, redis_ip, redis_port,
                                  redis_db, logger);
    assert(ret == 0);

    struct maat_options *opts = maat_options_new();
    maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
    maat_options_set_logger(opts, log_file, LOG_LEVEL_INFO);
    maat_options_set_stat_file(opts, "./stat.log");
    maat_options_set_rule_update_checking_interval_ms(opts, 100);

    struct maat *maat_inst = maat_new(opts, g_table_info_path);
    assert(maat_inst);
    maat_options_free(opts);

    int ex_data_counter = 0;
    const char *table_name = "IPPORT_PLUGIN_WITH_256SAME_IP";

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    ret = maat_plugin_table_ex_schema_register(maat_inst, table_name,
                                                ipport_plugin_ex_new_cb,
                                                ipport_plugin_ex_free_cb,
                                                ipport_plugin_ex_dup_cb,
                                                0, &ex_data_counter);
    EXPECT_EQ(ret, 0);

    int i = 0;
    pthread_t threads[2];
    struct thread_param thread_params[2];

    for (i = 0; i < 2; i++) {
        thread_params[i].maat_inst = maat_inst;
        thread_params[i].thread_id = i;
        thread_params[i].table_name = table_name;
        thread_params[i].port = 10;
        thread_params[i].test_count = PERF_scan_times;
        thread_params[i].time_elapse_ms = 0;
        thread_params[i].logger = logger;
    }

    pthread_create(&threads[0], NULL, ipport_plugin_scan_thread, thread_params);
    pthread_create(&threads[1], NULL, ipport_plugin_update_thread,
                    thread_params + 1);

    int *is_all_hit = NULL;
    long long time_elapse_ms = 0;
    long long scan_per_second = 0;
    for (i = 0; i < 2; i++) {
        pthread_join(threads[i], (void **)&is_all_hit);
        time_elapse_ms += thread_params[i].time_elapse_ms;

		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit = 0;
		free(is_all_hit);
    }
    maat_free(maat_inst);

    scan_per_second = PERF_scan_times * 1000 / time_elapse_ms;
    log_info(maat_inst->logger, MODULE_IPPORT_PLUGIN_GTEST,
             "IpportPluginScan with 256 same ip match rate speed"
             " %lld lookups/s/thread", scan_per_second);
}

int main(int argc, char ** argv)
{
	int ret = 0;
	::testing::InitGoogleTest(&argc, argv);
	ret = RUN_ALL_TESTS();

	return ret;
}
