/*
**********************************************************************************************
*	File: adapter_rs.h
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2023-06-30
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _ADAPTER_RS_H_
#define _ADAPTER_RS_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

#include "log/log.h"

#include "../expr_matcher.h"
#include "../expr_matcher_inc.h"

int rs_verify_regex_expression(const char *regex_expr, struct log_handle *logger);

/**
 * @brief new adapter_rs literal instance
 * 
 * @param rules:      logic AND expression's array
 * @param n_rule:     the number of logic AND expression's array
 * @param n_thread:  the number of scan threads which will call adapter_rs_lit_scan()
 * 
 * @retval the pointer to adapter_rs literal instance
*/
void *rs_lit_engine_new(struct expr_rule *rules, size_t n_rule,
                         struct pattern_attribute *pat_attr,
                         void *rs_lit_db, size_t n_thread,
                         struct log_handle *logger);

void *rs_regex_engine_new(struct expr_rule *rules, size_t n_rule,
                           struct pattern_attribute *pat_attr,
                           void *rs_regex_db, size_t n_thread,
                           struct log_handle *logger);

void rs_lit_engine_free(void *rs_lit_engine);

void rs_regex_engine_free(void *rs_regex_engine);

/**
 * @brief scan input data to match logic AND expression, return all matched expr_id
 * 
 * @param adapter_rs_lit:  adapter_rs literal instance obtained by adapter_rs_lit_new()
 * @param thread_id:       the thread_id of caller
 * @param scan_data:       data to be scanned
 * @param data_len:        the length of data to be scanned
 * @param result_array:    the array to store hit expr_id which allocated by caller
 * @param n_result_array:  number of elements in array of expr_id
*/
int rs_lit_engine_scan(void *rs_lit_engine, int thread_id,
                        const char *scan_data, size_t data_len,
                        unsigned long long *pattern_id_array,
                        size_t array_size, size_t *n_pattern_id);

int rs_regex_engine_scan(void *rs_lit_engine, int thread_id,
                          const char *scan_data, size_t data_len,
                          unsigned long long *pattern_id_array,
                          size_t array_size, size_t *n_pattern_id);

/**
 * @brief open stream for adapter_rs literal instance
 */
void *rs_lit_stream_open(void *rs_lit_engine, int thread_id);

void *rs_regex_stream_open(void *rs_regex_engine, int thread_id);

void rs_lit_stream_close(void *rs_lit_stream);

void rs_regex_stream_close(void *rs_regex_stream);

/**
 * @brief scan stream by adapter_rs literal stream
 */
int rs_lit_stream_scan(void *rs_lit_stream, const char *scan_data, size_t data_len,
                       unsigned long long *pattern_id_array, size_t array_size,
                       size_t *n_pattern_id);

int rs_regex_stream_scan(void *rs_regex_stream, const char *scan_data, size_t data_len,
                         unsigned long long *pattern_id_array, size_t array_size,
                         size_t *n_pattern_id);

/**
 * @brief build database
*/
void *rs_compile_data_new(enum expr_pattern_type pat_type, size_t n_patterns);

void rs_compile_data_free(void *compile_data);

void rs_populate_compile_data(void *compile_data, size_t index, int pattern_id,
                              char *pat, size_t pat_len, int case_sensitive);

int rs_build_lit_db(void **rs_lit_db, void *compile_data, struct log_handle *logger);

int rs_build_regex_db(void **rs_regex_db, size_t n_thread, void *compile_data,
                      struct log_handle *logger);

#ifdef __cplusplus
}
#endif

#endif