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

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

#define MAX_EXPR_PATTERN_NUM 8

struct adapter_hs;

/* scan mode */
enum {
    SCAN_MODE_BLOCK = 1,
    SCAN_MODE_STREAM,
};

/* pattern type: PATTERN_TYPE_STR(pure literal string) or PATTERN_TYPE_REG(regex expression) */
enum {
    PATTERN_TYPE_STR = 1,
    PATTERN_TYPE_REG,
};

typedef struct {
    /* pattern type */
    int type;

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
struct adapter_hs *adapter_hs_initialize(int scan_mode, size_t nr_worker_threads, and_expr_t *expr_array, size_t n_expr_array);

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
int adapter_hs_scan(struct adapter_hs *instance, int thread_id, const char *data, size_t data_len, 
                    int results[], size_t *n_results);

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
                           int results[], size_t *n_results);

void adapter_hs_stream_close(struct adapter_hs_stream *stream);

#ifdef __cpluscplus
}
#endif

#endif