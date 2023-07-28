/*
**********************************************************************************************
*	File: expr_matcher.cpp
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2023-06-30
*   Copyright: (c) Since 2023 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <unistd.h>
#include <assert.h>
#include <sys/syscall.h>

#include "log/log.h"
#include "expr_matcher.h"
#include "maat_utils.h"
#include "adapter_hs/adapter_hs.h"
#include "adapter_rs/adapter_rs.h"

pid_t expr_matcher_gettid() 
{
	return syscall(SYS_gettid);
}

static const char *expr_matcher_module_name_str(const char *name)
{
	static __thread char module[64];
	snprintf(module, sizeof(module), "%s(%d)", name, expr_matcher_gettid());
    
	return module;
}

#define MODULE_EXPR_MATCHER	 expr_matcher_module_name_str("maat.expr_matcher")

struct expr_matcher {
    enum expr_engine_type engine_type;
    void *engine;
    struct log_handle *logger;
};

struct expr_matcher_stream {
    enum expr_engine_type engine_type;
    void *handle;
};

struct expr_engine_operations {
    enum expr_engine_type type;
    void *(*engine_new)(struct expr_rule *rules, size_t n_rule,
                        size_t n_literal_pattern, size_t n_regex_pattern,
                        size_t n_worker_thread, struct log_handle *logger);
    void (*engine_free)(void *engine);
    int (*engine_scan)(void *engine, int thread_id, const char *scan_data,
                       size_t data_len, struct expr_scan_result *result_array,
                       size_t n_result_array, size_t *n_hit_result);
    void *(*engine_stream_open)(void *engine, int thread_id);
    void (*engine_stream_close)(void *stream);
    int (*engine_scan_stream)(void *stream, const char *scan_data, size_t data_len,
                              struct expr_scan_result *result_array, size_t n_result_array,
                              size_t *n_hit_result);
};

struct expr_engine_operations expr_engine_ops[EXPR_ENGINE_TYPE_MAX] = {
    {
        .type = EXPR_ENGINE_TYPE_HS,
        .engine_new = adapter_hs_new,
        .engine_free = adapter_hs_free,
        .engine_scan = adapter_hs_scan,
        .engine_stream_open = adapter_hs_stream_open,
        .engine_stream_close = adapter_hs_stream_close,
        .engine_scan_stream = adapter_hs_scan_stream
    },
    {
        .type = EXPR_ENGINE_TYPE_RS,
        .engine_new = adapter_rs_new,
        .engine_free = adapter_rs_free,
        .engine_scan = adapter_rs_scan,
        .engine_stream_open = adapter_rs_stream_open,
        .engine_stream_close = adapter_rs_stream_close,
        .engine_scan_stream = adapter_rs_scan_stream
    }
};

int expr_matcher_verify_regex_expression(const char *regex_expr,
                                         struct log_handle *logger)
{
    int ret = adapter_hs_verify_regex_expression(regex_expr, logger);
    if (ret == 0) {
        return 0;
    }

    return adapter_rs_verify_regex_expression(regex_expr, logger);
}

struct expr_matcher *
expr_matcher_new(struct expr_rule *rules, size_t n_rule, enum expr_engine_type engine_type,
                 size_t n_worker_thread, struct log_handle *logger)
{
    if (NULL == rules || 0 == n_rule || 0 == n_worker_thread ||
        (engine_type != EXPR_ENGINE_TYPE_HS && engine_type != EXPR_ENGINE_TYPE_RS)) {
        log_error(logger, MODULE_EXPR_MATCHER, "[%s:%d]engine type:%d is illegal", 
                  __FUNCTION__, __LINE__, engine_type);
        return NULL;
    }

    size_t i = 0, j = 0;
    size_t literal_pat_num = 0;
    size_t regex_pat_num = 0;

    for (i = 0; i < n_rule; i++) {
        if (rules[i].n_patterns > MAX_EXPR_PATTERN_NUM) {
            log_error(logger, MODULE_EXPR_MATCHER, 
                      "[%s:%d] the number of patterns in one expression should less than"
                      " %d", __FUNCTION__, __LINE__, MAX_EXPR_PATTERN_NUM);
            return NULL;
        }

        for (j = 0; j < rules[i].n_patterns; j++) {
            /* pat_len should not 0 */
            if (0 == rules[i].patterns[j].pat_len) {
                log_error(logger, MODULE_EXPR_MATCHER,
                          "[%s:%d] expr pattern length should not 0",
                          __FUNCTION__, __LINE__);
                return NULL;
            }

            if (rules[i].patterns[j].type == EXPR_PATTERN_TYPE_STR) {
                literal_pat_num++;
            } else {
                regex_pat_num++;
            }
        }
    }

    if (0 == literal_pat_num && 0 == regex_pat_num) {
        log_error(logger, MODULE_EXPR_MATCHER,
                  "[%s:%d] exprs has no valid pattern", __FUNCTION__, __LINE__);
        return NULL;
    }

    void *engine = expr_engine_ops[engine_type].engine_new(rules, n_rule, literal_pat_num,
                                                           regex_pat_num, n_worker_thread,
                                                           logger);
    if (NULL == engine) {
        log_error(logger, MODULE_EXPR_MATCHER,
                  "[%s:%d]expr_matcher engine_new failed.", __FUNCTION__, __LINE__);
        return NULL;
    }

    struct expr_matcher *matcher = ALLOC(struct expr_matcher, 1);
    matcher->engine_type = engine_type;
    matcher->engine = engine;
    matcher->logger = logger;
    
    return matcher;
}

void expr_matcher_free(struct expr_matcher *matcher)
{
    if (NULL == matcher) {
       return;
    }

    if (matcher->engine != NULL) {
        expr_engine_ops[matcher->engine_type].engine_free(matcher->engine);
        matcher->engine = NULL;
    }
    
    FREE(matcher);
}

int expr_matcher_match(struct expr_matcher *matcher, int thread_id, const char *scan_data,
                       size_t data_len, struct expr_scan_result *result_array,
                       size_t n_result_array, size_t *n_hit_results)
{
    if (NULL == matcher || thread_id < 0 || NULL == scan_data || 0 == data_len
        || NULL == result_array || 0 == n_result_array || NULL == n_hit_results) {
        return -1;
    }

    return expr_engine_ops[matcher->engine_type].engine_scan(matcher->engine, thread_id,
                                                            scan_data, data_len, result_array,
                                                            n_result_array, n_hit_results);
}

struct expr_matcher_stream *
expr_matcher_stream_open(struct expr_matcher *matcher, int thread_id)
{
    if (NULL == matcher || thread_id < 0) {
        return NULL;
    }

    void *s_handle = expr_engine_ops[matcher->engine_type].engine_stream_open(matcher->engine,
                                                                              thread_id);
    if (NULL == s_handle) {
        log_error(matcher->logger, MODULE_EXPR_MATCHER,
                  "[%s:%d] expr_matcher engine_stream_open failed.",
                  __FUNCTION__, __LINE__);
        return NULL;
    }

    struct expr_matcher_stream *stream = ALLOC(struct expr_matcher_stream, 1);
    stream->engine_type = matcher->engine_type;
    stream->handle = s_handle;
    
    return stream;
}

int expr_matcher_stream_match(struct expr_matcher_stream *stream, const char *scan_data,
						      size_t data_len, struct expr_scan_result *result_array, 
						      size_t n_result_array, size_t *n_hit_results)
{
    if (NULL == stream || NULL == scan_data || 0 == data_len || NULL == result_array
        || 0 == n_result_array || NULL == n_hit_results) {
        return -1;
    }

    return expr_engine_ops[stream->engine_type].engine_scan_stream(stream->handle, scan_data,
                                                                         data_len, result_array,
                                                                         n_result_array, n_hit_results);
}

void expr_matcher_stream_close(struct expr_matcher_stream *stream)
{
    if (NULL == stream) {
        return;
    }

    if (stream->handle != NULL) {
        expr_engine_ops[stream->engine_type].engine_stream_close(stream->handle);
        stream->handle = NULL;
    }
    
    FREE(stream);
}