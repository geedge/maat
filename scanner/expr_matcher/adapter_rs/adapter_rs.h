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

int adapter_rs_verify_regex_expression(const char *regex_expr,
                                       struct log_handle *logger);

/**
 * @brief new adapter_rs instance
 * 
 * @param rules:      logic AND expression's array
 * @param n_rule:     the number of logic AND expression's array
 * @param n_worker_threads: the number of scan threads which will call adapter_rs_scan()
 * 
 * @retval the pointer to adapter_rs instance
*/
void *adapter_rs_new(struct expr_rule *rules, size_t n_rule,
                     size_t n_literal_pattern, size_t n_regex_pattern,
                     size_t n_worker_thread, struct log_handle *logger);

void adapter_rs_free(void *rs_instance);

/**
 * @brief scan input data to match logic AND expression, return all matched expr_id
 * 
 * @param rs_instance:  adapter_rs instance obtained by adapter_rs_new()
 * @param thread_id:    the thread_id of caller
 * @param scan_data:    data to be scanned
 * @param data_len:     the length of data to be scanned
 * @param result_array: the array to store hit expr_id which allocated by caller
 * @param n_result_array: number of elements in array of expr_id
*/
int adapter_rs_scan(void *rs_instance, int thread_id,
                    const char *scan_data, size_t data_len,
                    struct expr_scan_result *result_array,
                    size_t n_result_array, size_t *n_hit_results);

/**
 * @brief
 */
void *adapter_rs_stream_open(void *rs_instance, int thread_id);

/**
 * @brief
 */
int adapter_rs_scan_stream(void *rs_stream, const char *scan_data,
						   size_t data_len, struct expr_scan_result *result_array, 
						   size_t n_result_array, size_t *n_hit_results);
/**
 * @brief
 */
void adapter_rs_stream_close(void *rs_stream);

#ifdef __cplusplus
}
#endif

#endif