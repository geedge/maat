#include <gtest/gtest.h>

#include "rcu_hash.h"
#include "maat_utils.h"

struct user_data {
    int id;
    char name[32];
};

void data_free(void *data)
{

}

TEST(rcu_hash_new, invalid_input_parameter) {
    struct rcu_hash_table *htable = rcu_hash_new(nullptr);
    EXPECT_EQ(htable, nullptr);
}

TEST(rcu_hash_add, one) {
    struct rcu_hash_table *htable = rcu_hash_new(data_free);
    EXPECT_NE(htable, nullptr);

    struct user_data *data = ALLOC(struct user_data, 1);
    data->id = 101;
    char *name = "www.baidu.com";
    memcpy(data->name, name, strlen(name)); 
    char *key = "http_url";
    size_t key_len = strlen(key);

    rcu_hash_add(htable, key, key_len, (void *)data);

    void *res = rcu_hash_find(htable, key, key_len);
    EXPECT_EQ(res, nullptr);

    rcu_hash_commit(htable);

    res = rcu_hash_find(htable, key, key_len);
    EXPECT_NE(res, nullptr);
    
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
	ret=RUN_ALL_TESTS();
	return ret;
}