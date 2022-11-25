/*
 *
 * Copyright (c) 2018
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2021-06-12
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef INCLUDE_BOOL_MATCHER_H
#define INCLUDE_BOOL_MATCHER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

#define MAX_ITEMS_PER_BOOL_EXPR 8

    /* not_flag=0表示布尔项item_id必须出现；not_flag=1表示布尔项item_id不能出现 */
    struct bool_item
    {
        unsigned long long item_id;
        unsigned char not_flag;
    };

    /* At least one item's not_flag should be 0. */
    struct bool_expr
    {
        unsigned long long expr_id;
        void *user_tag;
        size_t item_num;
        struct bool_item items[MAX_ITEMS_PER_BOOL_EXPR];
    };

    struct bool_expr_match
    {
        unsigned long long expr_id;
        void *user_tag;
    };

    struct bool_matcher;

    struct bool_matcher *bool_matcher_new(struct bool_expr *exprs, size_t expr_num, size_t *mem_size);

    /* Returned results are sorted by expr_id in descending order. */
    // Input item_ids MUST be ASCENDING order and NO duplication.
    int bool_matcher_match(struct bool_matcher *matcher, unsigned long long *item_ids, size_t item_num, struct bool_expr_match *results, size_t n_result);

    void bool_matcher_free(struct bool_matcher *matcher);

#ifdef __cplusplus
}
#endif

#endif
