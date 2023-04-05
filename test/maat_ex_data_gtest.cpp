#include "maat.h"
#include "log/log.h"
#include "maat_utils.h"
#include "json2iris.h"
#include "maat_command.h"
#include "maat_ex_data.h"
#include "maat_garbage_collection.h"

#include <gtest/gtest.h>
#include <limits.h>

const char *table_info_path = "./table_info.conf";
const char *json_filename = "maat_json.json";
struct log_handle *g_logger = NULL;
struct maat *g_maat_instance = NULL;

struct user_info {
	char name[256];
	char ip_addr[32];
	int id;
	int ref_cnt;
};

void ex_data_new_cb(const char *table_name, int table_id, const char *key, const char *table_line, 
                    void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	struct user_info *u = ALLOC(struct user_info, 1);
	int valid = 0, tag = 0;
	int ret = sscanf(table_line, "%d\t%s\t%s%d\t%d", &(u->id), u->ip_addr, u->name, &valid, &tag);
	EXPECT_EQ(ret, 5);
	u->ref_cnt = 0;
	*ad = u;
	(*counter)++;
}

void ex_data_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct user_info *u = (struct user_info *)(*ad);
	if ((__sync_sub_and_fetch(&u->ref_cnt, 1) == 0)) {
        printf("yes, free(u)\n");
		free(u);
		*ad = NULL;
	} else {
        printf("u->ref_cnt:%d\n", u->ref_cnt);
    }
}

void ex_data_dup_cb(int table_id,	void **to, void **from, long argl, void *argp)
{
	struct user_info *u = (struct user_info *)(*from);
	__sync_add_and_fetch(&(u->ref_cnt), 1);
	*to = u;
}

TEST(EXDataRuntime, Update) {
    const char *table_name = "TEST_PLUGIN_EXDATA_TABLE";
	int table_id = maat_get_table_id(g_maat_instance, table_name);
	ASSERT_GT(table_id, 0);

    int ex_data_counter = 0;
    struct ex_data_runtime *ex_data_rt = ex_data_runtime_new(table_id, g_logger);
    struct ex_container_schema *container_schema = ALLOC(struct ex_container_schema, 1);
    container_schema->custom_data_free = NULL;
    container_schema->table_id = table_id;
    container_schema->ex_schema.new_func = ex_data_new_cb;
    container_schema->ex_schema.free_func = ex_data_free_cb;
    container_schema->ex_schema.dup_func = ex_data_dup_cb;
    container_schema->ex_schema.argl = 0;
    container_schema->ex_schema.argp = &ex_data_counter;
    container_schema->set_flag = 1;

    ex_data_runtime_set_ex_container_schema(ex_data_rt, container_schema);

    const char *row1 = "1\t192.168.0.1\tmahuateng\t1\t0";
    const char *key1 = "192.168.0.1";
    size_t key1_len = strlen(key1);
    void *ex_data = ex_data_runtime_row2ex_data(ex_data_rt, table_name, row1, key1, key1_len);
    EXPECT_EQ(ex_data_counter, 1);

    struct ex_container *ex_container = ex_container_new(ex_data, NULL);
    int ret = ex_data_runtime_add_ex_container(ex_data_rt, key1, key1_len, ex_container);
    EXPECT_EQ(ret, 0);

    const char *row2 = "2\t192.168.0.2\tliyanhong\t1\t0";
    const char *key2 = "192.168.0.2";
    size_t key2_len = strlen(key2);
    ex_data = ex_data_runtime_row2ex_data(ex_data_rt, table_name, row2, key2, key2_len);
    ex_container = ex_container_new(ex_data, NULL);
    ret = ex_data_runtime_add_ex_container(ex_data_rt, key2, key2_len, ex_container);
    EXPECT_EQ(ret, 0);

    ex_data_runtime_commit(ex_data_rt);

    void *res_data1 = ex_data_runtime_get_ex_data_by_key(ex_data_rt, "192.168.0.1", 11);
    EXPECT_TRUE(res_data1 != NULL);

    struct user_info *info = (struct user_info *)res_data1;
    EXPECT_EQ(0, strcmp(info->name, "mahuateng"));
    EXPECT_EQ(info->id, 1);
    ex_data_free_cb(table_id, (void **)&res_data1, 0, NULL);

    ex_container = NULL;
    void *res_data2 = ex_data_runtime_get_ex_data_by_key(ex_data_rt, "192.168.0.2", 11);
    EXPECT_TRUE(res_data2 != NULL);

    info = (struct user_info *)res_data2;
    EXPECT_EQ(0, strcmp(info->name, "liyanhong"));
    EXPECT_EQ(info->id, 2);
    ex_data_free_cb(table_id, (void **)&res_data2, 0, NULL);

    ex_data_runtime_free(ex_data_rt);
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

    g_logger = log_handle_create("./maat_ex_data_gtest.log", 0);

    char json_iris_path[NAME_MAX] = {0};
    char tmp_iris_path[PATH_MAX] = {0};
    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp", json_filename);
    if ((access(json_iris_path, F_OK)) == 0) {
        system_cmd_rmdir(json_iris_path);
    }

    if (access(json_iris_path, F_OK) < 0) {
        char *json_buff = NULL;
        size_t json_buff_sz = 0;

		int ret = load_file_to_memory(json_filename, (unsigned char**)&json_buff, &json_buff_sz);
        EXPECT_NE(ret, -1);

		ret = json2iris(json_buff, json_filename, NULL, tmp_iris_path, sizeof(tmp_iris_path),
                        NULL, NULL, g_logger);
        FREE(json_buff);
		EXPECT_NE(ret, -1);
	}

	struct maat_options *opts = maat_options_new();
    char json_path[PATH_MAX] = {0};
    snprintf(json_path, sizeof(json_path), "./%s", json_filename);
    maat_options_set_json_file(opts, json_path);

    g_maat_instance = maat_new(opts, table_info_path);
    maat_options_free(opts);
    EXPECT_TRUE(g_maat_instance != NULL);

	ret=RUN_ALL_TESTS();

    log_handle_destroy(g_logger);
    maat_free(g_maat_instance);
    g_maat_instance = NULL;
	return ret;
}
