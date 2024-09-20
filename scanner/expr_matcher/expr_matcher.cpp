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
#include "bloom/bloom.h"
#include "maat_utils.h"
#include "../bool_matcher/bool_matcher.h"
#include "expr_matcher_inc.h"
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
    size_t n_thread;
    enum expr_engine_type engine_type;
    void *lit_runtime;
    void *regex_runtime;
    struct pattern_attribute *pat_attr;
    struct bool_matcher *bm;
    struct bool_expr_match **bool_match_buffs;
    struct log_handle *logger;
};

struct expr_matcher_stream {
    int thread_id;
    enum expr_engine_type engine_type;
    void *lit_stream;
    void *regex_stream;
    struct expr_matcher *ref_matcher;
};

struct db_operations {
    enum expr_engine_type type;
    void *(*compile_data_new)(enum expr_pattern_type pat_type, size_t n_pattern);
    void (*compile_data_free)(void *compile_data);
    void (*populate_compile_data)(void *compile_data, size_t index, int pattern_id,
                                  char *pat, size_t pat_len, int case_sensitive);
    int (*build_db)(void **lit_db, void *compile_data, struct log_handle *logger);
};

struct db_operations db_ops[EXPR_ENGINE_TYPE_AUTO] = {
    {
        .type = EXPR_ENGINE_TYPE_HS,
        .compile_data_new = hs_compile_data_new,
        .compile_data_free = hs_compile_data_free,
        .populate_compile_data = hs_populate_compile_data,
        .build_db = hs_build_lit_db
    },
    {
        .type = EXPR_ENGINE_TYPE_RS,
        .compile_data_new = rs_compile_data_new,
        .compile_data_free = rs_compile_data_free,
        .populate_compile_data = rs_populate_compile_data,
        .build_db = rs_build_lit_db
    }
};

struct engine_operations {
    enum expr_engine_type type;
    void *(*engine_new)(struct expr_rule *rules, size_t n_rule,
                        struct pattern_attribute *pat_attr,
                        void *hs_lit_db, size_t n_thread,
                        struct log_handle *logger);

    void (*engine_free)(void *engine);

    int (*engine_scan)(void *engine, int thread_id,
                       const char *data, size_t data_len,
                       unsigned long long *pattern_id_array,
                       size_t array_size, size_t *n_pattern_id);

    void *(*stream_open)(void *engine, int thread_id);

    void (*stream_close)(void *stream);

    int (*scan_stream)(void *stream, const char *data, size_t data_len,
                       unsigned long long *pattern_id_array, size_t array_size,
                       size_t *n_pattern_id);
};

struct engine_operations engine_ops[EXPR_ENGINE_TYPE_AUTO] = {
    {
        .type = EXPR_ENGINE_TYPE_HS,
        .engine_new = hs_lit_engine_new,
        .engine_free = hs_lit_engine_free,
        .engine_scan = hs_lit_engine_scan,
        .stream_open = hs_lit_stream_open,
        .stream_close = hs_lit_stream_close,
        .scan_stream = hs_lit_stream_scan
    },
    {
        .type = EXPR_ENGINE_TYPE_RS,
        .engine_new = rs_lit_engine_new,
        .engine_free = rs_lit_engine_free,
        .engine_scan = rs_lit_engine_scan,
        .stream_open = rs_lit_stream_open,
        .stream_close = rs_lit_stream_close,
        .scan_stream = rs_lit_stream_scan
    }
};

int expr_matcher_verify_regex_expression(const char *regex_expr,
                                         struct log_handle *logger)
{
    int ret = hs_verify_regex_expression(regex_expr, logger);
    if (ret == 0) {
        return 0;
    }

    return rs_verify_regex_expression(regex_expr, logger);
}

static int expr_rule_pattern_count(struct expr_rule *rules, size_t n_rule,
                                   size_t *n_lit_pat, size_t *n_regex_pat,
                                   struct log_handle *logger)
{
    size_t lit_pat_num = 0;
    size_t regex_pat_num = 0;

    for (size_t i = 0; i < n_rule; i++) {
        if (rules[i].n_patterns > MAX_EXPR_PATTERN_NUM) {
            char uuid_str[37];
            uuid_unparse(rules[i].expr_uuid, uuid_str);
            log_fatal(logger, MODULE_EXPR_MATCHER,
                      "[%s:%d] the number of patterns in expr_rule(rule_id:%s)"
                      " should less than %d", __FUNCTION__, __LINE__,
                      uuid_str, MAX_EXPR_PATTERN_NUM);
            return -1;
        }

        for (size_t j = 0; j < rules[i].n_patterns; j++) {
            /* pat_len should not 0 */
            if (0 == rules[i].patterns[j].pat_len) {
                log_fatal(logger, MODULE_EXPR_MATCHER,
                          "[%s:%d] expr pattern length should not 0",
                          __FUNCTION__, __LINE__);
                return -1;
            }

            if (rules[i].patterns[j].type == EXPR_PATTERN_TYPE_STR) {
                lit_pat_num++;
            } else {
                regex_pat_num++;
            }
        }
    }

    if (0 == lit_pat_num && 0 == regex_pat_num) {
        log_fatal(logger, MODULE_EXPR_MATCHER,
                  "[%s:%d] exprs has no valid pattern",
                  __FUNCTION__, __LINE__);
        return -1;
    }

    *n_lit_pat = lit_pat_num;
    *n_regex_pat = regex_pat_num;

    return 0;
}

static struct bool_expr *bool_exprs_new(struct expr_rule *rules, size_t n_rule,
                                        enum expr_engine_type engine_type,
                                        struct pattern_attribute *pat_attr,
                                        void *lit_compile_data, void *regex_compile_data)
{
    uint32_t pattern_index = 0;
    uint32_t literal_index = 0;
    uint32_t regex_index = 0;

    struct bool_expr *bool_exprs = ALLOC(struct bool_expr, n_rule);

    /* populate adpt_hs_compile_data and bool_expr */
    for (size_t i = 0; i < n_rule; i++) {

        for (size_t j = 0; j < rules[i].n_patterns; j++) {
            pat_attr[pattern_index].pattern_id = pattern_index;
            pat_attr[pattern_index].match_mode = rules[i].patterns[j].match_mode;
            
            if (pat_attr[pattern_index].match_mode == EXPR_MATCH_MODE_SUB || 
                pat_attr[pattern_index].match_mode == EXPR_MATCH_MODE_EXACTLY) {
                pat_attr[pattern_index].offset.start = rules[i].patterns[j].start_offset;
                pat_attr[pattern_index].offset.end = rules[i].patterns[j].end_offset;
            }

            /* literal pattern */
            if (rules[i].patterns[j].type == EXPR_PATTERN_TYPE_STR) {
                db_ops[engine_type].populate_compile_data(lit_compile_data, literal_index,
                                                          pattern_index, rules[i].patterns[j].pat,
                                                          rules[i].patterns[j].pat_len,
                                                          rules[i].patterns[j].case_sensitive);
                literal_index++;
            } else {
                /* regex pattern */
                hs_populate_compile_data(regex_compile_data, regex_index, pattern_index, 
                                         rules[i].patterns[j].pat, rules[i].patterns[j].pat_len,
                                         rules[i].patterns[j].case_sensitive);
                regex_index++;
            }

            bool_exprs[i].items[j].item_id = pattern_index++;
            bool_exprs[i].items[j].negate_option = 0;
        }
        
        uuid_copy(bool_exprs[i].expr_uuid, rules[i].expr_uuid);
        bool_exprs[i].item_num = rules[i].n_patterns;
        bool_exprs[i].user_tag = rules[i].tag;
    }

    return bool_exprs;
}

void expr_matcher_free(struct expr_matcher *matcher)
{
    if (NULL == matcher) {
       return;
    }

    if (matcher->lit_runtime != NULL) {
        engine_ops[matcher->engine_type].engine_free(matcher->lit_runtime);
        matcher->lit_runtime = NULL;
    }
    
    if (matcher->regex_runtime != NULL) {
        hs_regex_engine_free(matcher->regex_runtime);
        matcher->regex_runtime = NULL;
    }

    if (matcher->bm != NULL) {
        bool_matcher_free(matcher->bm);
        matcher->bm = NULL;
    }

    if (matcher->bool_match_buffs != NULL) {
        for (size_t i = 0; i < matcher->n_thread; i++) {
            if (matcher->bool_match_buffs[i] != NULL) {
                FREE(matcher->bool_match_buffs[i]);
            }
        }

        FREE(matcher->bool_match_buffs);
    }

    if (matcher->pat_attr != NULL) {
        FREE(matcher->pat_attr);
    }

    FREE(matcher);
}

struct expr_matcher *
expr_matcher_new(struct expr_rule *rules, size_t n_rule,
                 enum expr_engine_type engine_type,
                 size_t n_thread, struct log_handle *logger)
{
    if (NULL == rules || 0 == n_rule || 0 == n_thread ||
        (engine_type != EXPR_ENGINE_TYPE_HS &&
         engine_type != EXPR_ENGINE_TYPE_RS)) {
        log_fatal(logger, MODULE_EXPR_MATCHER,
                  "[%s:%d]engine type:%d is illegal", 
                  __FUNCTION__, __LINE__, engine_type);
        return NULL;
    }

    size_t lit_pat_cnt = 0;
    size_t regex_pat_cnt = 0;
    size_t pat_cnt = 0;

    int ret = expr_rule_pattern_count(rules, n_rule, &lit_pat_cnt,
                                      &regex_pat_cnt, logger);
    if (ret < 0) {
        return NULL;
    }

    pat_cnt = lit_pat_cnt + regex_pat_cnt;
    void *lit_compile_data = NULL;
    void *regex_compile_data = NULL;

    if (lit_pat_cnt > 0) {
        lit_compile_data = db_ops[engine_type].compile_data_new(EXPR_PATTERN_TYPE_STR,
                                                                lit_pat_cnt);
    }

    if (regex_pat_cnt > 0) {
        regex_compile_data = hs_compile_data_new(EXPR_PATTERN_TYPE_REG, regex_pat_cnt);
    }

    struct pattern_attribute *pat_attr = ALLOC(struct pattern_attribute, pat_cnt);
    struct bool_expr *bool_exprs = bool_exprs_new(rules, n_rule, engine_type,
                                                  pat_attr, lit_compile_data,
                                                  regex_compile_data);
    size_t mem_size = 0;
    int bm_ret = 0;
    struct expr_matcher *matcher = ALLOC(struct expr_matcher, 1);

    matcher->n_thread = n_thread;
    matcher->pat_attr = pat_attr;
    matcher->engine_type = engine_type;
    matcher->logger = logger;
    matcher->bm = bool_matcher_new(bool_exprs, n_rule, &mem_size);
    if (matcher->bm != NULL) {
        log_info(logger, MODULE_EXPR_MATCHER, 
                 "expr_matcher module: build bool matcher of %zu expressions"
                 " with %zu bytes memory", n_rule, mem_size);
    } else {
        log_fatal(logger, MODULE_EXPR_MATCHER,
                  "[%s:%d] expr_matcher module: build bool matcher failed",
                  __FUNCTION__, __LINE__);
        bm_ret = -1;
    }
    FREE(bool_exprs);

    matcher->bool_match_buffs = ALLOC(struct bool_expr_match *, n_thread);
    for (size_t i = 0; i < n_thread; i++) {
        matcher->bool_match_buffs[i] = ALLOC(struct bool_expr_match, MAX_HIT_PATTERN_NUM);
    }

    void *lit_db = NULL;
    if (lit_compile_data != NULL) {
        ret = db_ops[engine_type].build_db(&lit_db, lit_compile_data, logger);
        if (ret < 0) {
            bm_ret = -1;
        }
        db_ops[engine_type].compile_data_free(lit_compile_data);
    }

    if (lit_db != NULL) {
        matcher->lit_runtime = engine_ops[engine_type].engine_new(rules, n_rule, pat_attr,
                                                                  lit_db, n_thread, logger);
        if (NULL == matcher->lit_runtime) {
            log_fatal(logger, MODULE_EXPR_MATCHER,
                     "[%s:%d]expr_matcher new lit runtime failed.",
                     __FUNCTION__, __LINE__);
            bm_ret = -1;
        }
    }
    

    void *regex_db = NULL;
    if (regex_compile_data != NULL) {
        ret = hs_build_regex_db(&regex_db, regex_compile_data, logger);
        if (ret < 0) {
            bm_ret = -1;
        }
        hs_compile_data_free(regex_compile_data);
    }

    if (regex_db != NULL) {
        matcher->regex_runtime = hs_regex_engine_new(rules, n_rule, pat_attr,
                                                      regex_db, n_thread, logger);
        if (NULL == matcher->regex_runtime) {
            log_fatal(logger, MODULE_EXPR_MATCHER,
                      "[%s:%d]expr_matcher new regex runtime failed.",
                      __FUNCTION__, __LINE__);
            bm_ret = -1;
        }
    }

    if (bm_ret < 0) {
        goto error;
    }

    return matcher;
error:
    expr_matcher_free(matcher);
    return NULL;
}

static inline int compare_pattern_id(const void *a, const void *b)
{
	long long ret = *(const unsigned long long *)a - *(const unsigned long long *)b;
	if (ret == 0) {
		return 0;
	} else if (ret < 0) {
		return -1;
	} else {
		return 1;
	}
}

static int expr_matcher_bool_matcher_match(struct bool_matcher *bm, struct bool_expr_match *match_buff,
                                           size_t buff_size, unsigned long long *hit_pattern_ids,
                                           size_t n_hit_pattern, struct expr_scan_result *result_array,
                                           size_t array_size, size_t *n_hit_result)
{
    
    unsigned long long prev_pat_id = 0xFFFFFFFFFFFFFFFF;
    unsigned long long tmp_pat_id = 0;
    unsigned long long unique_pat_ids[n_hit_pattern];
    size_t n_unique_pat_id = 0;

    qsort(hit_pattern_ids, n_hit_pattern, sizeof(unsigned long long), compare_pattern_id);

    for (size_t i = 0; i < n_hit_pattern; i++) {
        tmp_pat_id = hit_pattern_ids[i];
        if (tmp_pat_id != prev_pat_id) {
            unique_pat_ids[n_unique_pat_id++] = tmp_pat_id;
            prev_pat_id = tmp_pat_id;
        }
    }

    int bool_matcher_ret = bool_matcher_match(bm, unique_pat_ids, n_unique_pat_id,
                                              match_buff, MAX_HIT_PATTERN_NUM);
    if (bool_matcher_ret < 0) {
        goto next;
    }

    if (bool_matcher_ret > (int)array_size) {
        bool_matcher_ret = array_size;
    }

    for (int index = 0; index < bool_matcher_ret; index++) {
        uuid_copy(result_array[index].rule_uuid, match_buff[index].expr_uuid);
        result_array[index].user_tag = match_buff[index].user_tag;
    }
    *n_hit_result = bool_matcher_ret;

next:
    return bool_matcher_ret;
}

int expr_matcher_match(struct expr_matcher *matcher, int thread_id,
                       const char *data, size_t data_len,
                       struct expr_scan_result *result_array,
                       size_t array_size, size_t *n_hit_result,
                       size_t *n_hit_pattern)
{
    if (NULL == matcher || thread_id < 0 || NULL == data || 0 == data_len
        || NULL == result_array || 0 == array_size || NULL == n_hit_result) {
        return -1;
    }

    int err_count = 0;
    unsigned long long lit_pat_ids[MAX_HIT_PATTERN_NUM];
    unsigned long long regex_pat_ids[MAX_HIT_PATTERN_NUM];
    size_t lit_pat_cnt = 0;
    size_t regex_pat_cnt = 0;
    size_t pat_cnt = 0;

    int ret = engine_ops[matcher->engine_type].engine_scan(matcher->lit_runtime, thread_id,
                                                           data, data_len, lit_pat_ids,
                                                           MAX_HIT_PATTERN_NUM, &lit_pat_cnt);
    if (ret < 0) {
        err_count++;
    }

    ret = hs_regex_engine_scan(matcher->regex_runtime, thread_id, data, data_len,
                               regex_pat_ids, MAX_HIT_PATTERN_NUM, &regex_pat_cnt);
    if (ret < 0) {
        err_count++;
    }

    if (err_count == 2) {
        return -1;
    }

    pat_cnt = lit_pat_cnt + regex_pat_cnt;
    *n_hit_pattern = pat_cnt;

    if (pat_cnt > MAX_HIT_PATTERN_NUM) {
        pat_cnt = MAX_HIT_PATTERN_NUM;
    }

    size_t j = 0;
    for (size_t i = lit_pat_cnt; i < pat_cnt; i++, j++) {
        lit_pat_ids[i] = regex_pat_ids[j];
    }
    
    struct bool_expr_match *match_buff = matcher->bool_match_buffs[thread_id];

    return expr_matcher_bool_matcher_match(matcher->bm, match_buff, MAX_HIT_PATTERN_NUM,
                                           lit_pat_ids, pat_cnt, result_array,
                                           array_size, n_hit_result);
}

struct expr_matcher_stream *
expr_matcher_stream_open(struct expr_matcher *matcher, int thread_id)
{
    if (NULL == matcher || thread_id < 0) {
        return NULL;
    }

    size_t err_count = 0;
    void *lit_stream = engine_ops[matcher->engine_type].stream_open(matcher->lit_runtime,
                                                                     thread_id);
    if (NULL == lit_stream && matcher->lit_runtime != NULL) {
        log_fatal(matcher->logger, MODULE_EXPR_MATCHER,
                  "[%s:%d] expr_matcher open lit engine stream failed.",
                  __FUNCTION__, __LINE__);
        err_count++;
    }

    void *regex_stream = hs_regex_stream_open(matcher->regex_runtime, thread_id);
    if (NULL == regex_stream && matcher->regex_runtime != NULL) {
        engine_ops[matcher->engine_type].stream_close(lit_stream);
        log_fatal(matcher->logger, MODULE_EXPR_MATCHER,
                  "[%s:%d] expr_matcher open regex engine stream failed.",
                  __FUNCTION__, __LINE__);
        err_count++;
    }

    if (err_count == 2) {
        return NULL;
    }

    struct expr_matcher_stream *stream = ALLOC(struct expr_matcher_stream, 1);
    stream->engine_type = matcher->engine_type;
    stream->thread_id = thread_id;
    stream->lit_stream = lit_stream;
    stream->regex_stream = regex_stream;
    stream->ref_matcher = matcher;

    return stream;
}

int expr_matcher_stream_match(struct expr_matcher_stream *stream,
                              const char *data, size_t data_len,
                              struct expr_scan_result *result_array, 
						      size_t array_size, size_t *n_hit_result,
                              size_t *n_hit_pattern)
{
    if (NULL == stream || NULL == data || 0 == data_len ||
        NULL == result_array || 0 == array_size ||
        NULL == n_hit_result) {
        return -1;
    }

    int err_count = 0;
    unsigned long long lit_pat_ids[MAX_HIT_PATTERN_NUM];
    unsigned long long regex_pat_ids[MAX_HIT_PATTERN_NUM];
    size_t lit_pat_cnt = 0;
    size_t regex_pat_cnt = 0;
    size_t pat_cnt = 0;

    int ret = engine_ops[stream->engine_type].scan_stream(stream->lit_stream, data, data_len,
                                                           lit_pat_ids, MAX_HIT_PATTERN_NUM,
                                                           &lit_pat_cnt);
    if (ret < 0) {
        err_count++;
    }

    ret = hs_regex_stream_scan(stream->regex_stream, data, data_len, regex_pat_ids,
                               MAX_HIT_PATTERN_NUM, &regex_pat_cnt);
    if (ret < 0) {
        err_count++;
    }

    if (err_count == 2) {
        return -1;
    }

    pat_cnt = lit_pat_cnt + regex_pat_cnt;
    *n_hit_pattern = pat_cnt;
    if (pat_cnt > MAX_HIT_PATTERN_NUM) {
        pat_cnt = MAX_HIT_PATTERN_NUM;
    }

    size_t j = 0;
    for (size_t i = lit_pat_cnt; i < pat_cnt; i++, j++) {
        lit_pat_ids[i] = regex_pat_ids[j];
    }
    
    struct expr_matcher *matcher = stream->ref_matcher;
    struct bool_expr_match *match_buff = matcher->bool_match_buffs[stream->thread_id];

    return expr_matcher_bool_matcher_match(matcher->bm, match_buff, MAX_HIT_PATTERN_NUM,
                                           lit_pat_ids, pat_cnt, result_array, array_size,
                                           n_hit_result);
}

void expr_matcher_stream_close(struct expr_matcher_stream *stream)
{
    if (NULL == stream) {
        return;
    }

    if (stream->lit_stream != NULL) {
        engine_ops[stream->engine_type].stream_close(stream->lit_stream);
        stream->lit_stream = NULL;
    }
    
    if (stream->regex_stream != NULL) {
        hs_regex_stream_close(stream->regex_stream);
        stream->regex_stream = NULL;
    }

    FREE(stream);
}