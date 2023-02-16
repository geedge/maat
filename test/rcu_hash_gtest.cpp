#include "rcu_hash.h"
#include "maat_utils.h"

#include <gtest/gtest.h>

struct user_data {
    int id;
    char name[32];
};

void data_free(void *user_ctx, void *data)
{
    FREE(data);
}

TEST(rcu_hash_new, invalid_input_parameter) {
    struct rcu_hash_table *htable = rcu_hash_new(NULL);
    EXPECT_EQ(htable, NULL);
}

TEST(rcu_hash_add_one_node, single_thread) {
    /* add one node to hash */
    struct rcu_hash_table *htable = rcu_hash_new(data_free);
    EXPECT_NE(htable, NULL);

    struct user_data *data = ALLOC(struct user_data, 1);
    data->id = 101;
    char name[64] = "www.baidu.com";
    memcpy(data->name, name, strlen(name)); 
    char key[64] = "http_url";
    size_t key_len = strlen(key);

    /* add to hash */
    rcu_hash_add(htable, key, key_len, (void *)data);

    /* find in hash before commit */
    void *res = rcu_hash_find(htable, key, key_len);
    EXPECT_EQ(res, NULL);

    int ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 0);

    ret = rcu_hash_garbage_queue_len(htable);
    EXPECT_EQ(ret, 0);

    void **data_array = NULL;
    ret = rcu_hash_list_updating_data(htable, &data_array);
    EXPECT_EQ(ret, 1);

    rcu_hash_commit(htable);

    /* find in hash after commit */
    res = rcu_hash_find(htable, key, key_len);
    EXPECT_NE(res, NULL);

    struct user_data *res_data = (struct user_data *)res;
    EXPECT_EQ(res_data->id, 101);
    EXPECT_STREQ(res_data->name, "www.baidu.com");

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 1);

    ret = rcu_hash_garbage_queue_len(htable);
    EXPECT_EQ(ret, 0);

    ret = rcu_hash_list_updating_data(htable, &data_array);
    EXPECT_EQ(ret, 0);

    rcu_hash_free(htable);
}

TEST(rcu_hash_add_multi_node, single_thread) {
    /* add multi node to hash */
    struct rcu_hash_table *htable = rcu_hash_new(data_free);
    EXPECT_NE(htable, NULL);

    struct user_data *data0 = ALLOC(struct user_data, 1);
    data0->id = 101;
    char name0[64] = "www.baidu.com";
    memcpy(data0->name, name0, strlen(name0)); 
    char key0[64] = "http_url";
    size_t key0_len = strlen(key0);
    rcu_hash_add(htable, key0, key0_len, (void *)data0);

    struct user_data *data1 = ALLOC(struct user_data, 1);
    data1->id = 102;
    char name1[64] = "127.0.0.1";
    memcpy(data1->name, name1, strlen(name1)); 
    char key1[64] = "http_host";
    size_t key1_len = strlen(key1);
    rcu_hash_add(htable, key1, key1_len, (void *)data1);

    /* find in hash before commit */
    void *res = rcu_hash_find(htable, key0, key0_len);
    EXPECT_EQ(res, NULL);
    res = rcu_hash_find(htable, key1, key1_len);
    EXPECT_EQ(res, NULL);

    int ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 0);

    ret = rcu_hash_garbage_queue_len(htable);
    EXPECT_EQ(ret, 0);

    void **data_array = NULL;
    ret = rcu_hash_list_updating_data(htable, &data_array);
    EXPECT_EQ(ret, 2);

    rcu_hash_commit(htable);

    /* find in hash after commit */
    res = rcu_hash_find(htable, key0, key0_len);
    EXPECT_NE(res, NULL);

    struct user_data *res_data0 = (struct user_data *)res;
    EXPECT_EQ(res_data0->id, 101);
    EXPECT_STREQ(res_data0->name, "www.baidu.com");

    res = rcu_hash_find(htable, key1, key1_len);
    EXPECT_NE(res, NULL);

    struct user_data *res_data1 = (struct user_data *)res;
    EXPECT_EQ(res_data1->id, 102);
    EXPECT_STREQ(res_data1->name, "127.0.0.1");

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 2);

    ret = rcu_hash_garbage_queue_len(htable);
    EXPECT_EQ(ret, 0);

    ret = rcu_hash_list_updating_data(htable, &data_array);
    EXPECT_EQ(ret, 0);

    rcu_hash_free(htable);
}

TEST(rcu_hash_del_one_node, single_thread) {
    /* case1: add and del before commit */
    struct rcu_hash_table *htable = rcu_hash_new(data_free);
    EXPECT_NE(htable, NULL);

    struct user_data *data = ALLOC(struct user_data, 1);
    data->id = 101;
    char name[64] = "www.baidu.com";
    memcpy(data->name, name, strlen(name)); 
    char key[64] = "http_url";
    size_t key_len = strlen(key);

    /* add to hash */
    rcu_hash_add(htable, key, key_len, (void *)data);

    void **data_array = NULL;
    int ret = rcu_hash_list_updating_data(htable, &data_array);
    EXPECT_EQ(ret, 1);

    /* find in hash before commit */
    void *res = rcu_hash_find(htable, key, key_len);
    EXPECT_EQ(res, NULL);

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 0);

    ret = rcu_hash_garbage_queue_len(htable);
    EXPECT_EQ(ret, 0);

    rcu_hash_del(htable, key, key_len);

    ret = rcu_hash_list_updating_data(htable, &data_array);
    EXPECT_EQ(ret, 0);

    rcu_hash_commit(htable);

    /* find in hash after commit */
    res = rcu_hash_find(htable, key, key_len);
    EXPECT_EQ(res, NULL);

    /* case2: add && commit, and del */
    struct user_data *data1 = ALLOC(struct user_data, 1);
    data1->id = 102;
    char name1[64] = "127.0.0.1";
    memcpy(data1->name, name1, strlen(name1)); 
    char key1[64] = "http_host";
    size_t key1_len = strlen(key1);
    rcu_hash_add(htable, key1, key1_len, (void *)data1);

    /* add commit */
    rcu_hash_commit(htable);

    rcu_hash_del(htable, key1, key1_len);

    res = rcu_hash_find(htable, key1, key1_len);
    EXPECT_NE(res, NULL);

    struct user_data *res_data = (struct user_data *)res;
    EXPECT_EQ(res_data->id, 102);
    EXPECT_STREQ(res_data->name, "127.0.0.1");

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 1);

    ret = rcu_hash_garbage_queue_len(htable);
    EXPECT_EQ(ret, 1);
    
    /* delete commit */
    rcu_hash_commit(htable);
    res = rcu_hash_find(htable, key1, key1_len);
    EXPECT_EQ(res, NULL);

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 0);

    ret = rcu_hash_garbage_queue_len(htable);
    EXPECT_EQ(ret, 0);

    rcu_hash_free(htable);
}

TEST(rcu_hash_del_multi_node, single_thread) {
    /* case1: add and del before commit */
    struct rcu_hash_table *htable = rcu_hash_new(data_free);
    EXPECT_NE(htable, NULL);

    struct user_data *data1 = ALLOC(struct user_data, 1);
    data1->id = 101;
    char name1[64] = "www.baidu.com";
    memcpy(data1->name, name1, strlen(name1)); 
    char key1[64] = "http_url";
    size_t key1_len = strlen(key1);
    rcu_hash_add(htable, key1, key1_len, (void *)data1);

    struct user_data *data2 = ALLOC(struct user_data, 1);
    data2->id = 102;
    char name2[64] = "127.0.0.1";
    memcpy(data2->name, name2, strlen(name2)); 
    char key2[64] = "http_host";
    size_t key2_len = strlen(key2);
    rcu_hash_add(htable, key2, key2_len, (void *)data2);

    /* find in hash before commit */
    void *res = rcu_hash_find(htable, key1, key1_len);
    EXPECT_EQ(res, NULL);

    int ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 0);

    ret = rcu_hash_garbage_queue_len(htable);
    EXPECT_EQ(ret, 0);

    /* add del, then commit */
    rcu_hash_del(htable, key1, key1_len);

    ret = rcu_hash_garbage_queue_len(htable);
    EXPECT_EQ(ret, 1);

    rcu_hash_commit(htable);

    /* find in hash after commit */
    res = rcu_hash_find(htable, key1, key1_len);
    EXPECT_EQ(res, NULL);

    res = rcu_hash_find(htable, key2, key2_len);
    EXPECT_NE(res, NULL);

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 1);

    ret = rcu_hash_garbage_queue_len(htable);
    EXPECT_EQ(ret, 0);

    rcu_hash_free(htable);
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
	ret=RUN_ALL_TESTS();
	return ret;
}
