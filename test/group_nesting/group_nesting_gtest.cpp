#include "maat.h"
#include "log/log.h"
#include "cJSON/cJSON.h"
#include "maat_rule.h"
#include "uthash/utarray.h"
#include "maat_utils.h"
#include "maat_command.h"
#include "maat_group.h"
#include <gtest/gtest.h>

#define MODULE_GROUP_NESTING_GTEST	 module_name_str("maat.group_nesting_gtest")

#define MAX_IDS_STR_LEN 64
#define MAX_ITEM_NUM 64
#define WAIT_FOR_EFFECTIVE_S 2
#define MAX_G2G_SCAN_TIMES (1000 * 1000)

const char *g_table_info_path = "./group_exclude_table_info.conf";
const char *log_file = "./group_exclude_gtest.log";

struct group_item {
    long long group_id;
    char incl_sub_ids_str[MAX_IDS_STR_LEN];
    char excl_sub_ids_str[MAX_IDS_STR_LEN];
};

struct group2group_rule {
    size_t n_add_item;
    size_t n_del_item;
    struct group_item add_items[MAX_ITEM_NUM];
    struct group_item del_items[MAX_ITEM_NUM];
};

UT_icd ut_ex_group_id_icd = {sizeof(long long), NULL, NULL, NULL};

static int parse_config_file(const char *filename, struct group2group_rule *rules)
{
    unsigned char *json_buff = NULL;
    size_t json_buff_size = 0;
    
    int ret = load_file_to_memory(filename, &json_buff, &json_buff_size);
    if (ret < 0) {
        printf("load file:%s to memory failed.\n", filename);
        return -1;
    }

    size_t rule_cnt = 0;
    cJSON *items_array = NULL;
    cJSON *root = cJSON_Parse((const char *)json_buff);
    if (NULL == root) {
        printf("Error before: %-200.200s\n", cJSON_GetErrorPtr());
        ret = -1;
        goto next;
    }

    items_array = cJSON_GetObjectItem(root, "add_items");
    if (NULL == items_array) {
        printf("Error before: %-200.200s\n", cJSON_GetErrorPtr());
        ret = -1;
        goto next;
    }

    rule_cnt = cJSON_GetArraySize(items_array);
    for (size_t i = 0; i < rule_cnt; i++) {
        cJSON *item_obj = cJSON_GetArrayItem(items_array, i);
        cJSON *tmp_item = cJSON_GetObjectItem(item_obj, "group_id");
        if (tmp_item != NULL && tmp_item->type == cJSON_Number) {
            rules->add_items[i].group_id = tmp_item->valueint;
        }

        tmp_item = cJSON_GetObjectItem(item_obj, "included_sub_group_ids");
        if (tmp_item != NULL && tmp_item->type == cJSON_String) {
            memcpy(rules->add_items[i].incl_sub_ids_str, tmp_item->valuestring,
                   strlen(tmp_item->valuestring));
        }

        tmp_item = cJSON_GetObjectItem(item_obj, "excluded_sub_group_ids");
        if (tmp_item != NULL && tmp_item->type == cJSON_String) {
            memcpy(rules->add_items[i].excl_sub_ids_str, tmp_item->valuestring,
                   strlen(tmp_item->valuestring));
        }
    }
    rules->n_add_item = rule_cnt;

    items_array = cJSON_GetObjectItem(root, "del_items");
    if (NULL == items_array) {
        printf("Error before: %-200.200s\n", cJSON_GetErrorPtr());
        ret = -1;
        goto next;
    }

    rule_cnt = cJSON_GetArraySize(items_array);
    for (size_t i = 0; i < rule_cnt; i++) {
        cJSON *item_obj = cJSON_GetArrayItem(items_array, i);
        cJSON *tmp_item = cJSON_GetObjectItem(item_obj, "group_id");
        if (tmp_item != NULL && tmp_item->type == cJSON_Number) {
            rules->del_items[i].group_id = tmp_item->valueint;
        }

        tmp_item = cJSON_GetObjectItem(item_obj, "included_sub_group_ids");
        if (tmp_item != NULL && tmp_item->type == cJSON_String) {
            memcpy(rules->del_items[i].incl_sub_ids_str, tmp_item->valuestring,
                   strlen(tmp_item->valuestring));
        }

        tmp_item = cJSON_GetObjectItem(item_obj, "excluded_sub_group_ids");
        if (tmp_item != NULL && tmp_item->type == cJSON_String) {
            memcpy(rules->del_items[i].excl_sub_ids_str, tmp_item->valuestring,
                   strlen(tmp_item->valuestring));
        }
    }
    rules->n_del_item = rule_cnt;

next:
    cJSON_Delete(root);
    FREE(json_buff);
    return ret;
}

class MaatGroupExclude : public testing::Test
{
protected:
    static void SetUpTestCase() {
        unsigned char *json_buff = NULL;
        size_t json_buff_size = 0;

        logger = log_handle_create(log_file, 0);
        garbage_bin = maat_garbage_bin_new(60);
        
        int ret = load_file_to_memory(g_table_info_path, &json_buff, &json_buff_size);
        if (ret < 0) {
            log_fatal(logger, MODULE_GROUP_NESTING_GTEST, "load_file_to_memory failed.");
            assert(0);
        }

        cJSON *root = cJSON_Parse((const char *)json_buff);
	    if (!root) {
            log_fatal(logger, MODULE_GROUP_NESTING_GTEST, "cJSON_Parse failed.");
            assert(0);
	    }

	    g2g_schema = group2group_schema_new(root, NULL, "EXCLUDE_GROUP2GROUP", logger);
        FREE(json_buff);
        cJSON_Delete(root);

        if (NULL == g2g_schema) {
            log_fatal(logger, MODULE_GROUP_NESTING_GTEST, "group2group_schema_new failed.");
            assert(0);
        }
    }

    static void TearDownTestCase() {
        log_handle_destroy(logger);
        maat_garbage_bin_free(garbage_bin);
        group2group_schema_free(g2g_schema);
    }

    static void *g2g_schema;
    static struct log_handle *logger;
    static struct maat_garbage_bin *garbage_bin;
};

void *MaatGroupExclude::g2g_schema;
struct log_handle *MaatGroupExclude::logger;
struct maat_garbage_bin *MaatGroupExclude::garbage_bin;

TEST_F(MaatGroupExclude, level_3_function) {
    char table_line[1024];
    struct group2group_rule rules;
    const char *table_name = "EXCLUDE_GROUP2GROUP";

    void *g2g_runtime = group2group_runtime_new(g2g_schema, 1, garbage_bin, logger);
    if (NULL == g2g_runtime) {
        log_fatal(logger, MODULE_GROUP_NESTING_GTEST, "group2group_runtime_new failed.");
        assert(0);
    }

    memset(&rules, 0, sizeof(rules));
    int ret = parse_config_file("group_nesting_L3.conf", &rules);
    EXPECT_EQ(ret, 0);

    for (size_t i = 0; i < rules.n_add_item; i++) {
        memset(table_line, 0, sizeof(table_line));

        sprintf(table_line, "%lld\t%s\t%s\t%d", rules.add_items[i].group_id,
                rules.add_items[i].incl_sub_ids_str, rules.add_items[i].excl_sub_ids_str, 1);
        group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    }

    group2group_runtime_commit(g2g_runtime, table_name, 1);

    long long hit_group_ids[2] = {11, 13};
    long long super_group_ids[MAX_ITEM_NUM];
    size_t super_group_cnt = group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                                                  super_group_ids, MAX_ITEM_NUM);
    EXPECT_EQ(super_group_cnt, 2);
    EXPECT_EQ(super_group_ids[0], 2);
    EXPECT_EQ(super_group_ids[1], 7);
    
    //delete group_id = 7, super_group_id = 6, is_exclude = 1
    memset(table_line, 0, sizeof(table_line));
    sprintf(table_line, "%lld\t%s\t%s\t%d", rules.del_items[0].group_id,
            rules.del_items[0].incl_sub_ids_str, rules.del_items[0].excl_sub_ids_str, 0);
    group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    group2group_runtime_commit(g2g_runtime, table_name, 2);

    super_group_cnt = group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                                            super_group_ids, MAX_ITEM_NUM);
    EXPECT_EQ(super_group_cnt, 3);
    EXPECT_EQ(super_group_ids[0], 1);
    EXPECT_EQ(super_group_ids[1], 6);
    EXPECT_EQ(super_group_ids[2], 7);

    //delete group_id = 13, super_group_id = 4, is_exclude = 1
    memset(table_line, 0, sizeof(table_line));
    sprintf(table_line, "%lld\t%s\t%s\t%d", rules.del_items[1].group_id,
            rules.del_items[1].incl_sub_ids_str, rules.del_items[1].excl_sub_ids_str, 0);
    group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    group2group_runtime_commit(g2g_runtime, table_name, 3);

    super_group_cnt = group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                                            super_group_ids, MAX_ITEM_NUM);
    EXPECT_EQ(super_group_cnt, 4);
    EXPECT_EQ(super_group_ids[0], 1);
    EXPECT_EQ(super_group_ids[1], 4);
    EXPECT_EQ(super_group_ids[2], 6);
    EXPECT_EQ(super_group_ids[3], 7);

    group2group_runtime_free(g2g_runtime);
}

TEST_F(MaatGroupExclude, level_3_perf) {
    char table_line[1024];
    struct group2group_rule rules;
    const char *table_name = "EXCLUDE_GROUP2GROUP";

    void *g2g_runtime = group2group_runtime_new(g2g_schema, 1, garbage_bin, logger);
    if (NULL == g2g_runtime) {
        log_fatal(logger, MODULE_GROUP_NESTING_GTEST, "group2group_runtime_new failed.");
        assert(0);
    }

    memset(&rules, 0, sizeof(rules));
    int ret = parse_config_file("group_nesting_L3.conf", &rules);
    EXPECT_EQ(ret, 0);

    for (size_t i = 0; i < rules.n_add_item; i++) {
        memset(table_line, 0, sizeof(table_line));

        sprintf(table_line, "%lld\t%s\t%s\t%d", rules.add_items[i].group_id,
                rules.add_items[i].incl_sub_ids_str, rules.add_items[i].excl_sub_ids_str, 1);
        group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    }

    group2group_runtime_commit(g2g_runtime, table_name, 4);

    long long hit_group_ids[2] = {11, 13};
    long long super_group_ids[MAX_ITEM_NUM];
    struct timespec start, end;
    struct log_handle *logger = MaatGroupExclude::logger;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < MAX_G2G_SCAN_TIMES; i++) {
        group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                             super_group_ids, MAX_ITEM_NUM);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
    log_info(logger, MODULE_GROUP_NESTING_GTEST, "level_3_basic hit 2 super_groups scan consume time %lldms",
             time_elapse_ms);

    //delete group_id = 7, super_group_id = 6, is_exclude = 1
    memset(table_line, 0, sizeof(table_line));
    sprintf(table_line, "%lld\t%s\t%s\t%d", rules.del_items[0].group_id,
            rules.del_items[0].incl_sub_ids_str, rules.del_items[0].excl_sub_ids_str, 0);
    group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    group2group_runtime_commit(g2g_runtime, table_name, 5);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < MAX_G2G_SCAN_TIMES; i++) {
        group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                             super_group_ids, MAX_ITEM_NUM);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
    log_info(logger, MODULE_GROUP_NESTING_GTEST, "level_3_basic hit 3 super_groups scan consume time %lldms",
             time_elapse_ms);

    //delete group_id = 13, super_group_id = 4, is_exclude = 1
    memset(table_line, 0, sizeof(table_line));
    sprintf(table_line, "%lld\t%s\t%s\t%d", rules.del_items[1].group_id,
            rules.del_items[1].incl_sub_ids_str, rules.del_items[1].excl_sub_ids_str, 0);
    group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    group2group_runtime_commit(g2g_runtime, table_name, 6);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < MAX_G2G_SCAN_TIMES; i++) {
        group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                             super_group_ids, MAX_ITEM_NUM);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
    log_info(logger, MODULE_GROUP_NESTING_GTEST, "level_3_basic hit 4 super_groups scan consume time %lldms",
             time_elapse_ms);

    group2group_runtime_free(g2g_runtime);
}

TEST_F(MaatGroupExclude, level_4_function) {
    char table_line[1024];
    struct group2group_rule rules;
    const char *table_name = "EXCLUDE_GROUP2GROUP";

    void *g2g_runtime = group2group_runtime_new(g2g_schema, 1, garbage_bin, logger);
    if (NULL == g2g_runtime) {
        log_fatal(logger, MODULE_GROUP_NESTING_GTEST, "group2group_runtime_new failed.");
        assert(0);
    }

    memset(&rules, 0, sizeof(rules));
    int ret = parse_config_file("group_nesting_L4.conf", &rules);
    EXPECT_EQ(ret, 0);

    for (size_t i = 0; i < rules.n_add_item; i++) {
        memset(table_line, 0, sizeof(table_line));

        sprintf(table_line, "%lld\t%s\t%s\t%d", rules.add_items[i].group_id,
                rules.add_items[i].incl_sub_ids_str, rules.add_items[i].excl_sub_ids_str, 1);
        group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    }

    group2group_runtime_commit(g2g_runtime, table_name, 7);

    long long hit_group_ids[2] = {14, 16};
    long long super_group_ids[MAX_ITEM_NUM];
    size_t super_group_cnt = group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                                                  super_group_ids, MAX_ITEM_NUM);
    EXPECT_EQ(super_group_cnt, 5);
    EXPECT_EQ(super_group_ids[0], 4);
    EXPECT_EQ(super_group_ids[1], 7);
    EXPECT_EQ(super_group_ids[2], 8);
    EXPECT_EQ(super_group_ids[3], 9);
    EXPECT_EQ(super_group_ids[4], 10);
    
    //delete group_id = 10, super_group_id = 6, is_exclude = 1
    memset(table_line, 0, sizeof(table_line));
    sprintf(table_line, "%lld\t%s\t%s\t%d", rules.del_items[0].group_id,
            rules.del_items[0].incl_sub_ids_str, rules.del_items[0].excl_sub_ids_str, 0);
    group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    group2group_runtime_commit(g2g_runtime, table_name, 8);

    super_group_cnt = group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                                            super_group_ids, MAX_ITEM_NUM);
    EXPECT_EQ(super_group_cnt, 7);
    EXPECT_EQ(super_group_ids[0], 1);
    EXPECT_EQ(super_group_ids[1], 4);
    EXPECT_EQ(super_group_ids[2], 6);
    EXPECT_EQ(super_group_ids[3], 7);
    EXPECT_EQ(super_group_ids[4], 8);
    EXPECT_EQ(super_group_ids[5], 9);
    EXPECT_EQ(super_group_ids[6], 10);

    group2group_runtime_free(g2g_runtime);
}

TEST_F(MaatGroupExclude, level_4_perf) {
    char table_line[1024];
    struct group2group_rule rules;
    const char *table_name = "EXCLUDE_GROUP2GROUP";

    void *g2g_runtime = group2group_runtime_new(g2g_schema, 1, garbage_bin, logger);
    if (NULL == g2g_runtime) {
        log_fatal(logger, MODULE_GROUP_NESTING_GTEST, "group2group_runtime_new failed.");
        assert(0);
    }

    memset(&rules, 0, sizeof(rules));
    int ret = parse_config_file("group_nesting_L4.conf", &rules);
    EXPECT_EQ(ret, 0);

    for (size_t i = 0; i < rules.n_add_item; i++) {
        memset(table_line, 0, sizeof(table_line));

        sprintf(table_line, "%lld\t%s\t%s\t%d", rules.add_items[i].group_id,
                rules.add_items[i].incl_sub_ids_str, rules.add_items[i].excl_sub_ids_str, 1);
        group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    }

    group2group_runtime_commit(g2g_runtime, table_name, 7);

    long long hit_group_ids[2] = {14, 16};
    long long super_group_ids[MAX_ITEM_NUM];
    struct timespec start, end;
    struct log_handle *logger = MaatGroupExclude::logger;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < MAX_G2G_SCAN_TIMES; i++) {
        group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                             super_group_ids, MAX_ITEM_NUM);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
    log_info(logger, MODULE_GROUP_NESTING_GTEST, "level_4_basic hit 5 super_groups scan consume time %lldms",
             time_elapse_ms);
    
    //delete group_id = 10, super_group_id = 6, is_exclude = 1
    memset(table_line, 0, sizeof(table_line));
    sprintf(table_line, "%lld\t%s\t%s\t%d", rules.del_items[0].group_id,
            rules.del_items[0].incl_sub_ids_str, rules.del_items[0].excl_sub_ids_str, 0);
    group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    group2group_runtime_commit(g2g_runtime, table_name, 8);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < MAX_G2G_SCAN_TIMES; i++) {
        group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                             super_group_ids, MAX_ITEM_NUM);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    time_elapse_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
    log_info(logger, MODULE_GROUP_NESTING_GTEST, "level_4_basic hit 7 super_groups scan consume time %lldms",
             time_elapse_ms);

    group2group_runtime_free(g2g_runtime);
}

TEST_F(MaatGroupExclude, level_exceed_function) {
    char table_line[1024];
    struct group2group_rule rules;
    const char *table_name = "EXCLUDE_GROUP2GROUP";

    void *g2g_runtime = group2group_runtime_new(g2g_schema, 1, garbage_bin, logger);
    if (NULL == g2g_runtime) {
        log_fatal(logger, MODULE_GROUP_NESTING_GTEST, "group2group_runtime_new failed.");
        assert(0);
    }

    memset(&rules, 0, sizeof(rules));
    int ret = parse_config_file("group_nesting_exceed.conf", &rules);
    EXPECT_EQ(ret, 0);

    for (size_t i = 0; i < rules.n_add_item; i++) {
        memset(table_line, 0, sizeof(table_line));

        sprintf(table_line, "%lld\t%s\t%s\t%d", rules.add_items[i].group_id,
                rules.add_items[i].incl_sub_ids_str, rules.add_items[i].excl_sub_ids_str, 1);
        group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    }

    group2group_runtime_commit(g2g_runtime, table_name, 8);

    long long hit_group_ids[2] = {7, 13};
    long long super_group_ids[MAX_ITEM_NUM];
    size_t super_group_cnt = group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                                                  super_group_ids, MAX_ITEM_NUM);
    EXPECT_EQ(super_group_cnt, 6);
    EXPECT_EQ(super_group_ids[0], 4);
    EXPECT_EQ(super_group_ids[1], 5);
    EXPECT_EQ(super_group_ids[2], 8);
    EXPECT_EQ(super_group_ids[3], 10);
    EXPECT_EQ(super_group_ids[4], 11);
    EXPECT_EQ(super_group_ids[5], 12);

    //delete group_id = 13, super_group_id = 10, is_exclude = 0
    memset(table_line, 0, sizeof(table_line));
    sprintf(table_line, "%lld\t%s\t%s\t%d", rules.del_items[0].group_id,
            rules.del_items[0].incl_sub_ids_str, rules.del_items[0].excl_sub_ids_str, 0);
    group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    group2group_runtime_commit(g2g_runtime, table_name, 9);

    hit_group_ids[0] = 7;
    hit_group_ids[1] = 10;
    super_group_cnt = group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                                            super_group_ids, MAX_ITEM_NUM);
    EXPECT_EQ(super_group_cnt, 5);
    EXPECT_EQ(super_group_ids[0], 2);
    EXPECT_EQ(super_group_ids[1], 4);
    EXPECT_EQ(super_group_ids[2], 5);
    EXPECT_EQ(super_group_ids[3], 8);
    EXPECT_EQ(super_group_ids[4], 11);

    group2group_runtime_free(g2g_runtime);
}

int main(int argc, char ** argv)
{
	int ret = 0;
	::testing::InitGoogleTest(&argc, argv);
	ret = RUN_ALL_TESTS();

	return ret;
}