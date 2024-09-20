/*
**********************************************************************************************
*	File: expr_matcher.h
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2023-06-30
*   Copyright: (c) Since 2023 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _EXPR_MATCHER_H_
#define _EXPR_MATCHER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <uuid/uuid.h>

#include "log/log.h"

#define MAX_EXPR_PATTERN_NUM  8

enum expr_engine_type {
    EXPR_ENGINE_TYPE_HS = 0,
    EXPR_ENGINE_TYPE_RS,
	EXPR_ENGINE_TYPE_AUTO
};

enum expr_pattern_type {
	EXPR_PATTERN_TYPE_STR = 0, /* pure literal string */
	EXPR_PATTERN_TYPE_REG = 1, /* regex expression */
};

enum expr_case_sensitive {
	EXPR_CASE_INSENSITIVE = 0,
	EXPR_CASE_SENSITIVE
};

enum expr_match_mode {
	EXPR_MATCH_MODE_INVALID = -1,
	EXPR_MATCH_MODE_EXACTLY = 1, /* scan data must match pattern exactly */
	EXPR_MATCH_MODE_PREFIX,      /* pattern must in the head of scan_data */
	EXPR_MATCH_MODE_SUFFIX,	     /* pattern must in the tail of scan_data */
	EXPR_MATCH_MODE_SUB          /* pattern must in the range[l_offset, r_offset] of scan_data */
};

struct expr_pattern {
	enum expr_pattern_type type;
	enum expr_match_mode match_mode;
	enum expr_case_sensitive case_sensitive;

	/* 
     * just match in scan_data's range of [start_offset, end_offset], -1 means no limits
     * for example:
     *  [-1, end_offset] means the pattern must in scan_data's [0 ~ start_offset]
     *  [start_offset, -1] means the pattern must in scan_data's [start_offset ~ data_end]
    */
	int start_offset;
	int end_offset;

	char *pat;
	size_t pat_len;
};

struct expr_scan_result {
	uuid_t rule_uuid;
	void *user_tag;
};

/* logic AND expression, such as (rule1 & rule2) */
struct expr_rule {
	uuid_t expr_uuid;   /* AND expression ID */
	size_t n_patterns;
	struct expr_pattern patterns[MAX_EXPR_PATTERN_NUM];
	void *tag;           /* user defined data, return with hit result */
};

int expr_matcher_verify_regex_expression(const char *regex_expr,
										 struct log_handle *logger);

/**
 * @brief new expr matcher instance
 * 
 * @param expr_array:       logic AND expression's array
 * @param n_expr_array:     the number of logic AND expression's array
 * @param n_worker_threads: the number of scan threads which will call adapter_rs_scan()
 * 
*/
struct expr_matcher *
expr_matcher_new(struct expr_rule *rules, size_t n_rule,
				 enum expr_engine_type type, size_t n_thread,
				 struct log_handle *logger);

void expr_matcher_free(struct expr_matcher *matcher);

/**
 * @brief scan input data to match logic AND expression, return all matched expr_id
 * 
 * @param matcher:        expr_matcher instance obtained by expr_matcher_new()
 * @param thread_id:      the thread_id of caller
 * @param scan_data:      data to be scanned
 * @param data_len:       the length of data to be scanned
 * @param result_array:   the array to store hit expr_id which allocated by caller
 * @param n_result_array: number of elements in array of expr_id
*/
int expr_matcher_match(struct expr_matcher *matcher, int thread_id,
					   const char *data, size_t data_len,
					   struct expr_scan_result *result_array,
                       size_t array_size, size_t *n_hit_result,
					   size_t *n_hit_pattern);

/**
 * @brief
 */
struct expr_matcher_stream *
expr_matcher_stream_open(struct expr_matcher *matcher, int thread_id);

/**
 * @brief
 */
int expr_matcher_stream_match(struct expr_matcher_stream *stream,
							  const char *data, size_t data_len,
							  struct expr_scan_result *result_array, 
						      size_t array_size, size_t *n_hit_result,
							  size_t *n_hit_pattern);

/**
 * @brief
 */
void expr_matcher_stream_close(struct expr_matcher_stream *stream);

#ifdef __cplusplus
}
#endif

#endif