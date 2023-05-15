#include "maat.h"
#include "log/log.h"
#include "cJSON/cJSON.h"
#include "maat_rule.h"
#include "maat_utils.h"
#include "maat_command.h"
#include "maat_group.h"
#include <gtest/gtest.h>

#define MODULE_GROUP_EXCLUDE_GTEST	 module_name_str("maat.group_exclude_gtest")

#define MAX_ITEM_NUM 64
#define WAIT_FOR_EFFECTIVE_S 2

const char *table_info_path = "./table_info.conf";

struct group_item {
    long long group_id;
    long long super_group_id;
    int is_exclude;
};

struct group2group_rule {
    size_t n_add_item;
    size_t n_del_item;
    struct group_item add_items[MAX_ITEM_NUM];
    struct group_item del_items[MAX_ITEM_NUM];
};

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

        tmp_item = cJSON_GetObjectItem(item_obj, "super_group_id");
        if (tmp_item != NULL && tmp_item->type == cJSON_Number) {
            rules->add_items[i].super_group_id = tmp_item->valueint;
        }

        tmp_item = cJSON_GetObjectItem(item_obj, "is_exclude");
        if (tmp_item != NULL && tmp_item->type == cJSON_Number) {
            rules->add_items[i].is_exclude = tmp_item->valueint;
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

        tmp_item = cJSON_GetObjectItem(item_obj, "super_group_id");
        if (tmp_item != NULL && tmp_item->type == cJSON_Number) {
            rules->del_items[i].super_group_id = tmp_item->valueint;
        }

        tmp_item = cJSON_GetObjectItem(item_obj, "is_exclude");
        if (tmp_item != NULL && tmp_item->type == cJSON_Number) {
            rules->del_items[i].is_exclude = tmp_item->valueint;
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

        logger = log_handle_create("./group_exclude_gtest.log", 0);
        garbage_bin = maat_garbage_bin_new(60);
        
        int ret = load_file_to_memory("./group_exclude_table_info.conf",
                                      &json_buff, &json_buff_size);
        if (ret < 0) {
            log_error(logger, MODULE_GROUP_EXCLUDE_GTEST, "load_file_to_memory failed.");
            assert(0);
        }

        cJSON *root = cJSON_Parse((const char *)json_buff);
	    if (!root) {
            log_error(logger, MODULE_GROUP_EXCLUDE_GTEST, "cJSON_Parse failed.");
            assert(0);
	    }

	    g2g_schema = group2group_schema_new(root, NULL, "EXCLUDE_GROUP2GROUP", logger);
        FREE(json_buff);
        cJSON_Delete(root);

        if (NULL == g2g_schema) {
            log_error(logger, MODULE_GROUP_EXCLUDE_GTEST, "group2group_schema_new failed.");
            assert(0);
        }

        g2g_runtime = group2group_runtime_new(g2g_schema, 1, garbage_bin, logger);
        if (NULL == g2g_runtime) {
            log_error(logger, MODULE_GROUP_EXCLUDE_GTEST, "group2group_runtime_new failed.");
            assert(0);
        }
        
    }

    static void TearDownTestCase() {
        log_handle_destroy(logger);
        maat_garbage_bin_free(garbage_bin);
        group2group_runtime_free(g2g_runtime);
        group2group_schema_free(g2g_schema);
    }

    static void *g2g_schema;
    static void *g2g_runtime;
    static struct log_handle *logger;
    static struct maat_garbage_bin *garbage_bin;
};

void *MaatGroupExclude::g2g_schema;
void *MaatGroupExclude::g2g_runtime;
struct log_handle *MaatGroupExclude::logger;
struct maat_garbage_bin *MaatGroupExclude::garbage_bin;

TEST_F(MaatGroupExclude, level_3_basic) {
    char table_line[1024];
    struct group2group_rule rules;
    const char *table_name = "EXCLUDE_GROUP2GROUP";
    //struct log_handle *logger = MaatGroupExclude::logger;

    int ret = parse_config_file("group_exclude_L3.conf", &rules);
    EXPECT_EQ(ret, 0);

    for (size_t i = 0; i < rules.n_add_item; i++) {
        memset(table_line, 0, sizeof(table_line));

        sprintf(table_line, "%lld\t%lld\t%d\t%d", rules.add_items[i].group_id,
                rules.add_items[i].super_group_id, rules.add_items[i].is_exclude, 1);
        group2group_runtime_update(g2g_runtime, g2g_schema, table_name, table_line, 4);
    }

    group2group_runtime_commit(g2g_runtime, table_name, 1);

    long long hit_group_ids[2] = {11, 4};
    long long super_group_ids[MAX_ITEM_NUM];
    size_t super_group_cnt = group2group_runtime_get_super_groups(g2g_runtime, hit_group_ids, 2,
                                                                  super_group_ids, MAX_ITEM_NUM);
    for (size_t i = 0; i < super_group_cnt; i++) {
        printf("super_group_ids[%zu]:%lld\n", i, super_group_ids[i]);
    }
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
	ret=RUN_ALL_TESTS();
	return ret;
}
