#include <gtest/gtest.h>

#include "maat/maat.h"
#include "maat_rule.h"
#include "maat_table_schema.h"
#include "maat_table_runtime.h"

struct maat *g_maat_instance = NULL;
const char *table_info_path = "/home/liuwentan/project/maat-v4/test/table_info.conf";
const char *rule_path = "/home/liuwentan/project/maat-v4/test/rule/full/index";

TEST(maat_scan_string, literal) {
    struct table_schema_manager *table_schema_mgr = g_maat_instance->table_schema_mgr;
    int table_id = table_schema_manager_get_table_id(table_schema_mgr, "HTTP_URL");
    char data[64] = "www.baidu.com";
    int result_array[5] = {0};
    size_t n_result_array = 0;
	int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), result_array, &n_result_array, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(n_result_array, 1);
    EXPECT_EQ(result_array[0], 101);
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

    struct maat_options *opts = maat_options_new();
    maat_options_set_iris_full_dir(opts, rule_path);

    g_maat_instance = maat_new(opts, table_info_path);
    EXPECT_NE(g_maat_instance, nullptr);

	ret=RUN_ALL_TESTS();

    maat_free(g_maat_instance);
    g_maat_instance = NULL;

	return ret;
}