#include <limits.h>

#include "maat_utils.h"
#include "maat_garbage_collection.h"
#include <gtest/gtest.h>

struct user_info {
    char user_name[NAME_MAX];
    int user_id;
};

struct user_info *user_info_new(const char *user_name, int user_id)
{
    struct user_info *info = ALLOC(struct user_info, 1);

    memcpy(info->user_name, user_name, sizeof(info->user_name));
    info->user_id = user_id;

    return info;
}

void user_info_free(struct user_info *user_info)
{
    free(user_info);
}

void garbage_user_info_free(void *user_info, void *arg)
{
    struct user_info *info = (struct user_info *)user_info;
    user_info_free(info);
}

TEST(garbage_collection, basic)
{
    struct maat_garbage_bin *garbage_bin = maat_garbage_bin_new(2);
    struct user_info *info = user_info_new("zhangsan", 101);
    maat_garbage_bagging(garbage_bin, info, NULL, garbage_user_info_free);
    maat_garbage_collect_routine(garbage_bin);
    maat_garbage_bin_free(garbage_bin);
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
	ret=RUN_ALL_TESTS();
	return ret;
}
