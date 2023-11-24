/*
**********************************************************************************************
*	File: adapter_hs.h
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
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
#include "../expr_matcher.h"
#include "../expr_matcher_inc.h"

int hs_verify_regex_expression(const char *regex_expr, struct log_handle *logger);

/**
 * @brief new adapter_hs literal instance
 * 
 * @param rules:             logic AND expression's array
 * @param n_rule:            the number of logic AND expression's array
 * @param nr_worker_threads: the number of scan threads which will call adapter_hs_scan()
 * 
 * @retval the pointer to adapter_hs literal instance
*/
void *hs_lit_engine_new(struct expr_rule *rules, size_t n_rule,
                         struct pattern_attribute *pat_attr,
                         void *hs_lit_db, size_t n_thread,
                         struct log_handle *logger);

void *hs_regex_engine_new(struct expr_rule *rules, size_t n_rule,
                           struct pattern_attribute *pat_attr,
                           void *hs_regex_db, size_t n_thread,
                           struct log_handle *logger);

void hs_lit_engine_free(void *hs_lit_engine);

void hs_regex_engine_free(void *hs_regex_engine);

/**
 * @brief scan input data to match logic AND expression, return all matched expr_id
 * 
 * @param hs_lit:    adapter_hs literal instance obtained by adapter_hs_lit_new()
 * @param thread_id: the thread_id of caller
 * @param data:      data to be scanned
 * @param data_len:  the length of data to be scanned
 * @param results:   the array of expr_id
 * @param n_results: number of elements in array of expr_id
*/
int hs_lit_engine_scan(void *hs_lit_engine, int thread_id,
                        const char *data, size_t data_len,
                        unsigned long long *pattern_id_array,
                        size_t array_size, size_t *n_pattern_id);

int hs_regex_engine_scan(void *hs_regex_engine, int thread_id,
                          const char *data, size_t data_len,
                          unsigned long long *pattern_id_array,
                          size_t array_size, size_t *n_pattern_id);

void *hs_lit_stream_open(void *hs_lit_engine, int thread_id);

void *hs_regex_stream_open(void *hs_regex_engine, int thread_id);

void hs_lit_stream_close(void *hs_lit_stream);

void hs_regex_stream_close(void *hs_regex_stream);

int hs_lit_stream_scan(void *hs_lit_stream, const char *data, size_t data_len,
                       unsigned long long *pattern_id_array, size_t array_size,
                       size_t *n_pattern_id);

int hs_regex_stream_scan(void *hs_regex_stream, const char *data, size_t data_len,
                         unsigned long long *pattern_id_array, size_t array_size,
                         size_t *n_pattern_id);

/**
 * @brief build database
*/
void *hs_compile_data_new(enum expr_pattern_type pat_type, size_t n_patterns);

void hs_compile_data_free(void *compile_data);

void hs_populate_compile_data(void *compile_data, size_t index, int pattern_id,
                              char *pat, size_t pat_len, int case_sensitive);

int hs_build_lit_db(void **hs_lit_db, void *compile_data, struct log_handle *logger);

int hs_build_regex_db(void **hs_regex_db, void *compile_data, struct log_handle *logger);

#ifdef __cplusplus
}
#endif

#endif