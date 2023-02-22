/*
**********************************************************************************************
*	File: adapter_hs.h
*   Description: wrapper for raw hyperscan
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _ADAPTER_HS_H_
#define _ADAPTER_HS_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

#include "log/log.h"

#define MAX_EXPR_PATTERN_NUM 8

struct adapter_hs;

/* scan mode */
enum hs_scan_mode {
    HS_SCAN_MODE_BLOCK = 1,
    HS_SCAN_MODE_STREAM,
    HS_SCAN_MODE_MAX
};

/* match method */
enum hs_match_mode {
    HS_MATCH_MODE_INVALID = -1,
    HS_MATCH_MODE_EXACTLY = 1,  /* scan data must match pattern exactly */
    HS_MATCH_MODE_PREFIX,       /* pattern must in the head of scan_data */
    HS_MATCH_MODE_SUFFIX,       /* pattern must in the end of scan_data */
    HS_MATCH_MODE_SUB,           /* pattern must in the range[l_offset, r_offset] of scan_data */
    HS_MATCH_MODE_MAX
};

enum hs_pattern_type {
    HS_PATTERN_TYPE_STR = 0,  /* pure literal string */
    HS_PATTERN_TYPE_REG,      /* regex expression */
    HS_PATTERN_TYPE_MAX
};

enum hs_case_sensitive {
    HS_CASE_SENSITIVE = 0,
    HS_CASE_INSESITIVE
};

struct hs_scan_result {
    uint64_t item_id;
    void *user_tag;
};

typedef struct {
    enum hs_case_sensitive case_sensitive;
    enum hs_match_mode match_mode;
    int is_hexbin; /* 1(yes) 0(no) */

    /* 
     * just match in scan_data's range of [l_offset, r_offset], -1 means no limits
     * for example:
     *  [-1, r_offset] means the pattern must in scan_data's [0 ~ r_offset]
     *  [l_offset, -1] means the pattern must in scan_data's [l_offset ~ end]
     */
    int l_offset;
    int r_offset;

    /* start pointer of pattern */
    char *pat;
    /* pattern length */
    size_t pat_len;
} scan_pattern_t;

/* logic AND expression, such as (pattern1 & pattern2) */
typedef struct {
    uint32_t expr_id;
    size_t n_patterns;
    scan_pattern_t patterns[MAX_EXPR_PATTERN_NUM];
    void *user_tag;
} and_expr_t;

/**
 * @brief initialize adapter_hs instance
 * 
 * @param scan_mode:         the following scan as block or stream mode
 * @param nr_worker_threads: the number of scan threads which will call adapter_hs_scan()
 * @param expr_array:        logic AND expression's array
 * @param n_expr_arrays:     the number of logic AND expression's array
 * 
 * @retval the pointer to adapter_hs instance
*/
struct adapter_hs *adapter_hs_initialize(enum hs_scan_mode scan_mode, 
                                         enum hs_pattern_type pattern_type,
                                         size_t n_worker_thread,
                                         and_expr_t *exprs, size_t n_expr,
                                         struct log_handle *logger);

/**
 * @brief scan input data to match logic AND expression, return all matched expr_id
 * 
 * @param instance:  adapter_hs instance obtained by adapter_hs_initialize()
 * @param thread_id: the thread_id of caller
 * @param data:      data to be scanned
 * @param data_len:  the length of data to be scanned
 * @param results:   the array of expr_id
 * @param n_results: number of elements in array of expr_id
*/
int adapter_hs_scan(struct adapter_hs *hs_instance, int thread_id,
                    const char *data, size_t data_len, 
                    struct hs_scan_result *results,
                    size_t n_result, size_t *n_hit_result);

/**
 * @brief destroy adapter_hs instance
 * 
 * @param instance: adapter_hs instance obtained by adapter_hs_initialize()
*/
void adapter_hs_destroy(struct adapter_hs *instance);

struct adapter_hs_stream;
/**
 * @brief open adapter_hs stream after adapter_hs instance initialized for stream scan
 * 
*/
struct adapter_hs_stream *adapter_hs_stream_open(struct adapter_hs *hs_instance, int thread_id);

int adapter_hs_scan_stream(struct adapter_hs_stream *stream, const char *data, size_t data_len,
                           struct hs_scan_result *results, size_t n_result, size_t *n_hit_result);

void adapter_hs_stream_close(struct adapter_hs_stream *stream);

#ifdef __cplusplus
}
#endif

#endif