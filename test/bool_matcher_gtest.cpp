#include <gtest/gtest.h>

#include "log/log.h"
#include "bool_matcher.h"
#include "maat_utils.h"
#include "cJSON/cJSON.h"

#define MAX_ARRAY_SIZE 6

struct log_handle *g_logger = NULL;

TEST(bool_matcher_match, MultiExprWithSameID) {
    struct bool_expr *bool_expr_array = ALLOC(struct bool_expr, 1);

    bool_expr_array->expr_id = 100;
    bool_expr_array->item_num = 2;
    bool_expr_array->items[0].item_id = 1;
    bool_expr_array->items[0].negate_option = 0;
    bool_expr_array->items[1].item_id = 1;
    bool_expr_array->items[1].negate_option = 0;

    size_t mem_size = 0;
    struct bool_matcher *bm = bool_matcher_new(bool_expr_array, 1, &mem_size);
    if (bm == NULL) {
        assert(0);
    }

    unsigned long long item_ids[2] = {1, 1};
    struct bool_expr_match expr_match;
    int bool_match_ret = bool_matcher_match(bm, item_ids, 2, &expr_match, 1);
    EXPECT_EQ(bool_match_ret, 1);
    EXPECT_EQ(expr_match.expr_id, 100);

    bool_matcher_free(bm);
    FREE(bool_expr_array);
}

int main(int argc, char **argv)
{
    int ret = 0;
    ::testing::InitGoogleTest(&argc, argv);
    g_logger = log_handle_create("./bool_matcher_gtest.log", 0);

    ret = RUN_ALL_TESTS();

    log_handle_destroy(g_logger);

    return ret;
}