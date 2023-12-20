/*
**********************************************************************************************
*	File: expr_matcher_inc.h
*   Description: for expr matcher internal use only
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2023-06-30
*   Copyright: (c) Since 2023 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _EXPR_MATCHER_INC_H_
#define _EXPR_MATCHER_INC_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include "uthash/utarray.h"
#include "bloom/bloom.h"
#include "expr_matcher.h"

#define MAX_HIT_PATTERN_NUM  1024

struct pattern_offset {
    long long start;
    long long end;
};

struct pattern_attribute {
    long long pattern_id;
    enum expr_match_mode match_mode;
    struct pattern_offset offset;
    size_t pattern_len;
};

struct matched_pattern {
    UT_array *pattern_ids;
    struct bloom *ref_bloom;
    struct pattern_attribute *ref_pat_attr;
    size_t scan_data_len;
};

#ifdef __cplusplus
}
#endif

#endif
