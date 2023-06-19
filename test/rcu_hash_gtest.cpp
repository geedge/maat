#include "rcu_hash.h"
#include "maat_utils.h"

#include <gtest/gtest.h>

struct rcu_hash_table *g_htable = NULL;

struct user_data {
    int id;
    char name[32];
};

void data_free(void *user_ctx, void *data)
{
    FREE(data);
}

TEST(rcu_hash_new, invalid_input_parameter) {
    struct rcu_hash_table *htable = rcu_hash_new(NULL, NULL, 0);
    EXPECT_TRUE(htable == NULL);
}

TEST(rcu_hash_add_one_node, single_thread) {
    /* add one node to hash */
    struct rcu_hash_table *htable = rcu_hash_new(data_free, NULL, 0);
    EXPECT_TRUE(htable != NULL);

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
    EXPECT_TRUE(res == NULL);

    int ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 0);

    void **data_array = NULL;
    rcu_hash_commit(htable);

    ret = rcu_hash_list(htable, &data_array);
    EXPECT_EQ(ret, 1);

    if (data_array != NULL) {
        free(data_array);
        data_array = NULL;
    }

    /* find in hash after commit */
    res = rcu_hash_find(htable, key, key_len);
    EXPECT_TRUE(res != NULL);

    struct user_data *res_data = (struct user_data *)res;
    EXPECT_EQ(res_data->id, 101);
    EXPECT_STREQ(res_data->name, "www.baidu.com");

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 1);

    rcu_hash_free(htable);
}

TEST(rcu_hash_add_multi_node, single_thread) {
    /* add multi node to hash */
    struct rcu_hash_table *htable = rcu_hash_new(data_free, NULL, 0);
    EXPECT_TRUE(htable != NULL);

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

    struct user_data *data2 = ALLOC(struct user_data, 1);
    data2->id = 103;
    char name2[64] = "mahuateng";
    memcpy(data2->name, name2, strlen(name2)); 
    char key2[64] = "192.168.0.1";
    size_t key2_len = strlen(key2);
    rcu_hash_add(htable, key2, key2_len, (void *)data2);

    struct user_data *data3 = ALLOC(struct user_data, 1);
    data3->id = 104;
    char name3[64] = "liyanhong";
    memcpy(data3->name, name3, strlen(name3)); 
    char key3[64] = "192.168.0.2";
    size_t key3_len = strlen(key3);
    rcu_hash_add(htable, key3, key3_len, (void *)data3);

    /* find in hash before commit */
    void *res = rcu_hash_find(htable, key0, key0_len);
    EXPECT_TRUE(res == NULL);
    res = rcu_hash_find(htable, key1, key1_len);
    EXPECT_TRUE(res == NULL);

    int ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 0);

    void **data_array = NULL;
    ret = rcu_hash_list(htable, &data_array);
    EXPECT_EQ(ret, 0);
    if (data_array != NULL) {
        free(data_array);
        data_array = NULL;
    }

    rcu_hash_commit(htable);

    ret = rcu_hash_list(htable, &data_array);
    EXPECT_EQ(ret, 4);
    if (data_array != NULL) {
        free(data_array);
        data_array = NULL;
    }

    /* find in hash after commit */
    res = rcu_hash_find(htable, key0, key0_len);
    EXPECT_TRUE(res != NULL);
    struct user_data *res_data0 = (struct user_data *)res;
    EXPECT_EQ(res_data0->id, 101);
    EXPECT_STREQ(res_data0->name, "www.baidu.com");

    res = rcu_hash_find(htable, key1, key1_len);
    EXPECT_TRUE(res != NULL);
    struct user_data *res_data1 = (struct user_data *)res;
    EXPECT_EQ(res_data1->id, 102);
    EXPECT_STREQ(res_data1->name, "127.0.0.1");

    res = rcu_hash_find(htable, key2, key2_len);
    EXPECT_TRUE(res != NULL);
    struct user_data *res_data2 = (struct user_data *)res;
    EXPECT_EQ(res_data2->id, 103);
    EXPECT_STREQ(res_data2->name, "mahuateng");

    res = rcu_hash_find(htable, key3, key3_len);
    EXPECT_TRUE(res != NULL);
    struct user_data *res_data3 = (struct user_data *)res;
    EXPECT_EQ(res_data3->id, 104);
    EXPECT_STREQ(res_data3->name, "liyanhong");

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 4);

    rcu_hash_free(htable);
}

TEST(rcu_hash_del_one_node, single_thread) {
    /* case1: add and del before commit */
    struct rcu_hash_table *htable = rcu_hash_new(data_free, NULL, 0);
    EXPECT_TRUE(htable != NULL);

    struct user_data *data = ALLOC(struct user_data, 1);
    data->id = 101;
    char name[64] = "www.baidu.com";
    memcpy(data->name, name, strlen(name)); 
    char key[64] = "http_url";
    size_t key_len = strlen(key);

    /* add to hash */
    rcu_hash_add(htable, key, key_len, (void *)data);

    void **data_array = NULL;
    int ret = rcu_hash_list(htable, &data_array);
    EXPECT_EQ(ret, 0);
    if (data_array != NULL) {
        free(data_array);
        data_array = NULL;
    }

    /* find in hash before commit */
    void *res = rcu_hash_find(htable, key, key_len);
    EXPECT_TRUE(res == NULL);

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 0);

    rcu_hash_del(htable, key, key_len);

    ret = rcu_hash_list(htable, &data_array);
    EXPECT_EQ(ret, 0);
    if (data_array != NULL) {
        free(data_array);
        data_array = NULL;
    }
    
    rcu_hash_commit(htable);

    /* find in hash after commit */
    res = rcu_hash_find(htable, key, key_len);
    EXPECT_TRUE(res == NULL);

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
    EXPECT_TRUE(res != NULL);

    struct user_data *res_data = (struct user_data *)res;
    EXPECT_EQ(res_data->id, 102);
    EXPECT_STREQ(res_data->name, "127.0.0.1");

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 1);
    
    /* delete commit */
    rcu_hash_commit(htable);
    res = rcu_hash_find(htable, key1, key1_len);
    EXPECT_TRUE(res == NULL);

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 0);

    rcu_hash_free(htable);
}

TEST(rcu_hash_del_multi_node, single_thread) {
    /* case1: add and del before commit */
    struct rcu_hash_table *htable = rcu_hash_new(data_free, NULL, 0);
    EXPECT_TRUE(htable != NULL);

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
    EXPECT_TRUE(res == NULL);

    int ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 0);

    /* add del, then commit */
    rcu_hash_del(htable, key1, key1_len);

    rcu_hash_commit(htable);

    /* find in hash after commit */
    res = rcu_hash_find(htable, key1, key1_len);
    EXPECT_TRUE(res == NULL);

    res = rcu_hash_find(htable, key2, key2_len);
    EXPECT_TRUE(res != NULL);

    ret = rcu_hash_count(htable);
    EXPECT_EQ(ret, 1);

    rcu_hash_free(htable);
}

TEST(rcu_hash_add_with_same_key, single_thread) {
    struct rcu_hash_table *htable = rcu_hash_new(data_free, NULL, 0);
    EXPECT_TRUE(htable != NULL);

    char key[64] = "http_url";
    size_t key_len = strlen(key);

    //add data1
    struct user_data *data1 = ALLOC(struct user_data, 1);
    data1->id = 101;
    char name1[64] = "www.baidu.com";
    memcpy(data1->name, name1, strlen(name1)); 
    int ret = rcu_hash_add(htable, key, key_len, (void *)data1);
    EXPECT_EQ(ret, 0);

    void *res = rcu_hash_find(htable, key, key_len);
    EXPECT_TRUE(res == NULL);

    //add data2
    struct user_data *data2 = ALLOC(struct user_data, 1);
    data2->id = 102;
    char name2[64] = "www.google.com";
    memcpy(data2->name, name2, strlen(name2)); 
    ret = rcu_hash_add(htable, key, key_len, (void *)data2);
    EXPECT_EQ(ret, -1);
    FREE(data2);

    rcu_hash_commit(htable);

    res = rcu_hash_find(htable, key, key_len);
    EXPECT_TRUE(res != NULL);

    struct user_data *tmp_data = (struct user_data *)res;
    EXPECT_EQ(tmp_data->id, 101);
    EXPECT_STREQ(tmp_data->name, "www.baidu.com");

    rcu_hash_free(htable);
}

TEST(rcu_hash_del_with_same_key, single_thread) {
    struct rcu_hash_table *htable = rcu_hash_new(data_free, NULL, 0);
    EXPECT_TRUE(htable != NULL);

    char key[64] = "http_url";
    size_t key_len = strlen(key);

    int ret = rcu_hash_del(htable, key, key_len);
    EXPECT_EQ(ret, 0);

    //add data1
    struct user_data *data1 = ALLOC(struct user_data, 1);
    data1->id = 101;
    char name1[64] = "www.baidu.com";
    memcpy(data1->name, name1, strlen(name1)); 
   
    ret = rcu_hash_add(htable, key, key_len, (void *)data1);
    EXPECT_EQ(ret, 0);

    void *res = rcu_hash_find(htable, key, key_len);
    EXPECT_TRUE(res == NULL);

    ret = rcu_hash_del(htable, key, key_len);
    EXPECT_EQ(ret, 0);

    //add data2
    struct user_data *data2 = ALLOC(struct user_data, 1);
    data2->id = 102;
    char name2[64] = "www.google.com";
    memcpy(data2->name, name2, strlen(name2)); 
    ret = rcu_hash_add(htable, key, key_len, (void *)data2);
    EXPECT_EQ(ret, 0);

    rcu_hash_commit(htable);

    res = rcu_hash_find(htable, key, key_len);
    EXPECT_TRUE(res != NULL);

    struct user_data *tmp_data = (struct user_data *)res;
    EXPECT_EQ(tmp_data->id, 102);
    EXPECT_STREQ(tmp_data->name, "www.google.com");

    rcu_hash_free(htable);
}

TEST(rcu_hash_modify_with_same_key, single_thread) {
    struct rcu_hash_table *htable = rcu_hash_new(data_free, NULL, 0);
    EXPECT_TRUE(htable != NULL);

    char key[64] = "http_url";
    size_t key_len = strlen(key);

    //add data1
    struct user_data *data1 = ALLOC(struct user_data, 1);
    data1->id = 101;
    char name1[64] = "www.baidu.com";
    memcpy(data1->name, name1, strlen(name1)); 
    rcu_hash_add(htable, key, key_len, (void *)data1);

    void *res = rcu_hash_find(htable, key, key_len);
    EXPECT_TRUE(res == NULL);

    //del data1
    rcu_hash_del(htable, key, key_len);

    //add data2
    struct user_data *data2 = ALLOC(struct user_data, 1);
    data2->id = 102;
    char name2[64] = "www.google.com";
    memcpy(data2->name, name2, strlen(name2)); 
    
    rcu_hash_add(htable, key, key_len, (void *)data2);
    rcu_hash_commit(htable);

    res = rcu_hash_find(htable, key, key_len);
    struct user_data *tmp_data = (struct user_data *)res;
    EXPECT_EQ(tmp_data->id, 102);
    EXPECT_STREQ(tmp_data->name, "www.google.com");

    rcu_hash_free(htable);
}

TEST(global_rcu_hash_add, single_thread) {
    EXPECT_TRUE(g_htable != NULL);

    char key1[64] = "http_url";
    size_t key1_len = strlen(key1);

    struct user_data *data1 = ALLOC(struct user_data, 1);
    data1->id = 101;
    char name1[64] = "www.baidu.com";
    memcpy(data1->name, name1, strlen(name1)); 
    rcu_hash_add(g_htable, key1, key1_len, (void *)data1);

    int ret = rcu_hash_count(g_htable);
    EXPECT_EQ(ret, 0);

    rcu_hash_commit(g_htable);

    ret = rcu_hash_count(g_htable);
    EXPECT_EQ(ret, 1);

    void *res = rcu_hash_find(g_htable, key1, key1_len);
    EXPECT_TRUE(res != NULL);
}

TEST(global_rcu_hash_find, single_thread) {
    EXPECT_TRUE(g_htable != NULL);

    const char *key = "http_url";
    size_t key_len = strlen(key);

    void *res = rcu_hash_find(g_htable, key, key_len);
    EXPECT_TRUE(res != NULL);
}

TEST(global_rcu_hash_del, single_thread) {
    EXPECT_TRUE(g_htable != NULL);

    const char *key = "http_url";
    size_t key_len = strlen(key);

    void *res = rcu_hash_find(g_htable, key, key_len);
    EXPECT_TRUE(res != NULL);

    rcu_hash_del(g_htable, key, key_len);
    rcu_hash_commit(g_htable);

    res = rcu_hash_find(g_htable, key, key_len);
    EXPECT_TRUE(res == NULL);
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

    g_htable = rcu_hash_new(data_free, NULL, 0);

	ret=RUN_ALL_TESTS();

    rcu_hash_free(g_htable);

	return ret;
}
