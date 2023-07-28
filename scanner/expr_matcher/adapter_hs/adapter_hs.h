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

int adapter_hs_verify_regex_expression(const char *regex_expr, struct log_handle *logger);
/**
 * @brief new adapter_hs instance
 * 
 * @param rules:             logic AND expression's array
 * @param n_rule:            the number of logic AND expression's array
 * @param nr_worker_threads: the number of scan threads which will call adapter_hs_scan()
 * 
 * @retval the pointer to adapter_hs instance
*/
void *adapter_hs_new(struct expr_rule *rules, size_t n_rule,
                     size_t n_literal_pattern, size_t n_regex_pattern,
                     size_t n_worker_thread, struct log_handle *logger);

/**
 * @brief scan input data to match logic AND expression, return all matched expr_id
 * 
 * @param instance:  adapter_hs instance obtained by adapter_hs_new()
 * @param thread_id: the thread_id of caller
 * @param data:      data to be scanned
 * @param data_len:  the length of data to be scanned
 * @param results:   the array of expr_id
 * @param n_results: number of elements in array of expr_id
*/
int adapter_hs_scan(void *hs_instance, int thread_id, const char *data, size_t data_len, 
                    struct expr_scan_result *results, size_t n_result, size_t *n_hit_result);

/**
 * @brief destroy adapter_hs instance
 * 
 * @param instance: adapter_hs instance obtained by adapter_hs_new()
*/
void adapter_hs_free(void *instance);

/**
 * @brief open adapter_hs stream after adapter_hs instance initialized for stream scan
 * 
*/
void *adapter_hs_stream_open(void *hs_instance, int thread_id);

int adapter_hs_scan_stream(void *stream, const char *data, size_t data_len,
                           struct expr_scan_result *results, size_t n_result,
                           size_t *n_hit_result);

void adapter_hs_stream_close(void *stream);

#ifdef __cplusplus
}
#endif

#endif