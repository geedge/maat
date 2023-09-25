/*
**********************************************************************************************
*	File: adapter_rs.cpp
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h> 

#include "rulescan.h"
#include "adapter_rs.h"
#include "uthash/utarray.h"
#include "uthash/uthash.h"
#include "maat_utils.h"
#include "../../bool_matcher/bool_matcher.h"

#define MAX_HIT_PATTERN_NUM  1024

pid_t rs_gettid()
{
	return syscall(SYS_gettid);
}

static const char *rs_module_name_str(const char *name)
{
	static __thread char module[64];
	snprintf(module, sizeof(module), "%s(%d)", name, rs_gettid());
    
	return module;
}

#define MODULE_ADAPTER_RS	 rs_module_name_str("maat.adapter_rs")

struct adpt_rs_compile_data {
    struct scan_pattern *patterns;
    size_t n_patterns;
};

struct adapter_rs_stream {
    int thread_id;
    size_t offset;  /* current stream offset */
    rs_stream_t *literal_stream;
    rs_stream_t *regex_stream;
    struct adapter_rs_runtime *ref_rs_rt;
    
    struct log_handle *logger;
};

/* adapter_rs runtime */
struct adapter_rs_runtime {
    rs_database_t *literal_db;
    rs_database_t *regex_db;

    struct bool_expr_match **bool_match_buffs; /* per thread */
    struct adapter_rs_stream **streams;        /* per thread */
    struct matched_pattern **matched_pats;     /* per thread */
    struct bool_matcher *bm;
};

/* adapter_rs instance */
struct adapter_rs {
    size_t n_worker_thread;
    size_t n_expr;
    size_t n_patterns;
    struct adapter_rs_runtime *rs_rt;
    struct pattern_attribute *rs_attr;
    struct log_handle *logger;
};

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
    size_t n_patterns;
    struct pattern_attribute *ref_rs_attr;
};

int adapter_rs_verify_regex_expression(const char *regex_expr,
                                       struct log_handle *logger)
{
    int ret = rs_verify_regex(regex_expr);
    if (ret == 0) {
        log_error(logger, MODULE_ADAPTER_RS,
                      "[%s:%d] illegal regex expression: \"%s\"",
                      __FUNCTION__, __LINE__, regex_expr);
    }

    return ret;
}
/**
 * @brief build rs database for literal string and regex expression respectively
 * 
 * @retval 0(success) -1(failed)
*/
static int adpt_rs_build_database(struct adapter_rs_runtime *rs_rt,
                                  size_t n_worker_thread,
                                  struct adpt_rs_compile_data *literal_cd,
                                  struct adpt_rs_compile_data *regex_cd,
                                  struct log_handle *logger)
{
    if (NULL == rs_rt) {
        return -1;
    }

    int ret = 0;
    if (literal_cd != NULL) {
        ret = rs_compile_lit(literal_cd->patterns, literal_cd->n_patterns,
                             &rs_rt->literal_db);
        if (ret < 0) {
            log_error(logger, MODULE_ADAPTER_RS, "[%s:%d] compile error", 
                       __FUNCTION__, __LINE__);
            return -1;
        }
    }
    
    if (regex_cd != NULL) {
        size_t n_failed_pats = 0;
        ret = rs_compile_regex(regex_cd->patterns, regex_cd->n_patterns,
                               n_worker_thread, &rs_rt->regex_db, &n_failed_pats);
        if (ret < 0) {
            log_error(logger, MODULE_ADAPTER_RS, "[%s:%d] compile error",
                      __FUNCTION__, __LINE__);
            return -1;
        }
    }
    
    return 0;
}

static struct adpt_rs_compile_data *adpt_rs_compile_data_new(size_t n_patterns)
{
    struct adpt_rs_compile_data *rs_cd = ALLOC(struct adpt_rs_compile_data, 1);
    rs_cd->patterns = ALLOC(struct scan_pattern, n_patterns);
    rs_cd->n_patterns = n_patterns;

    return rs_cd;
}

static void adpt_rs_compile_data_free(struct adpt_rs_compile_data *rs_cd)
{
    if (NULL == rs_cd) {
        return;
    }

    if (rs_cd->patterns != NULL) {
        for (size_t i = 0; i < rs_cd->n_patterns; i++) {
            if (rs_cd->patterns[i].pattern != NULL) {
                FREE(rs_cd->patterns[i].pattern);
            }
        }

        FREE(rs_cd->patterns); 
    }

    FREE(rs_cd);
}

static void populate_compile_data(struct adpt_rs_compile_data *compile_data,
                                  size_t index, long long pattern_id, char *pat,
                                  size_t pat_len, int case_sensitive)
{
    compile_data->patterns[index].id = pattern_id;
    compile_data->patterns[index].case_sensitive = case_sensitive;
    compile_data->patterns[index].pattern = ALLOC(char, pat_len + 1);
    memcpy(compile_data->patterns[index].pattern, pat, pat_len);
    compile_data->patterns[index].pattern_len = pat_len;
}

static struct bool_expr *bool_exprs_new(struct expr_rule *rules, size_t n_rule,
                                        struct pattern_attribute *pattern_attr,
                                        struct adpt_rs_compile_data *literal_cd,
                                        struct adpt_rs_compile_data *regex_cd,
                                        size_t *n_pattern)
{
    long long pattern_idx = 0;
    size_t literal_idx = 0;
    size_t regex_idx = 0;

    struct bool_expr *bool_exprs = ALLOC(struct bool_expr, n_rule);

    /* populate adpt_rs_compile_data and bool_expr */
    for (size_t i = 0; i < n_rule; i++) {

        for (size_t j = 0; j < rules[i].n_patterns; j++) {
            pattern_attr[pattern_idx].pattern_id = pattern_idx;
            pattern_attr[pattern_idx].match_mode = rules[i].patterns[j].match_mode;
            pattern_attr[pattern_idx].pattern_len = rules[i].patterns[j].pat_len;

            if (pattern_attr[pattern_idx].match_mode == EXPR_MATCH_MODE_SUB || 
                pattern_attr[pattern_idx].match_mode == EXPR_MATCH_MODE_EXACTLY) {
                pattern_attr[pattern_idx].offset.start = rules[i].patterns[j].start_offset;
                pattern_attr[pattern_idx].offset.end = rules[i].patterns[j].end_offset;
            }

            /* literal pattern */
            if (rules[i].patterns[j].type == EXPR_PATTERN_TYPE_STR) {
                populate_compile_data(literal_cd, literal_idx, pattern_idx, 
                                      rules[i].patterns[j].pat, rules[i].patterns[j].pat_len,
                                      rules[i].patterns[j].case_sensitive);
                literal_idx++;
            } else {
                /* regex pattern */
                populate_compile_data(regex_cd, regex_idx, pattern_idx, 
                                      rules[i].patterns[j].pat, rules[i].patterns[j].pat_len,
                                      rules[i].patterns[j].case_sensitive);
                regex_idx++;
            }

            bool_exprs[i].items[j].item_id = pattern_idx++;
            bool_exprs[i].items[j].not_flag = 0;
        }
        
        bool_exprs[i].expr_id = rules[i].expr_id;
        bool_exprs[i].item_num = rules[i].n_patterns;
        bool_exprs[i].user_tag = rules[i].tag;
    }

    *n_pattern = pattern_idx;

    return bool_exprs;
}

UT_icd ut_rs_pattern_id_icd = {sizeof(unsigned long long), NULL, NULL, NULL};
void *adapter_rs_new(struct expr_rule *rules, size_t n_rule,
                     size_t n_literal_pattern, size_t n_regex_pattern,
                     size_t n_worker_thread, struct log_handle *logger)
{
    /* get the sum of pattern */
    size_t i = 0;
    struct adpt_rs_compile_data *literal_cd = NULL;
    struct adpt_rs_compile_data *regex_cd = NULL;

    if (n_literal_pattern > 0) {
        literal_cd = adpt_rs_compile_data_new(n_literal_pattern);
    }
   
    if (n_regex_pattern > 0) {
        regex_cd = adpt_rs_compile_data_new(n_regex_pattern);
    }
    
    size_t pattern_cnt = n_literal_pattern + n_regex_pattern;
    struct adapter_rs *rs_inst = ALLOC(struct adapter_rs, 1);
    rs_inst->rs_attr = ALLOC(struct pattern_attribute, pattern_cnt);
    rs_inst->logger = logger;
    rs_inst->n_worker_thread = n_worker_thread;
    rs_inst->n_expr = n_rule;

    struct bool_expr *bool_exprs = bool_exprs_new(rules, n_rule, rs_inst->rs_attr,
                                                  literal_cd, regex_cd, &pattern_cnt);
    if (NULL == bool_exprs) {
        return NULL;
    }
    rs_inst->n_patterns = pattern_cnt;
    
    /* create bool matcher */
    size_t mem_size = 0;
    int rs_ret = 0;

    rs_inst->rs_rt = ALLOC(struct adapter_rs_runtime, 1);

    //rs_rt->bm
    rs_inst->rs_rt->bm = bool_matcher_new(bool_exprs, n_rule, &mem_size);
    if (rs_inst->rs_rt->bm != NULL) {
        log_info(logger, MODULE_ADAPTER_RS, 
                 "Adapter_rs module: build bool matcher of %zu expressions"
                 " with %zu bytes memory", n_rule, mem_size);
    } else {
        log_error(logger, MODULE_ADAPTER_RS,
                  "[%s:%d] Adapter_rs module: build bool matcher failed",
                  __FUNCTION__, __LINE__);
        
        rs_ret = -1;
    }
    FREE(bool_exprs);

    /* build rs database rs_rt->literal_db & rs_rt->regex_db */
    int ret = adpt_rs_build_database(rs_inst->rs_rt, n_worker_thread,
                                     literal_cd, regex_cd, logger);
    if (ret < 0) {
        rs_ret = -1;
    }

    if (literal_cd != NULL) {
        adpt_rs_compile_data_free(literal_cd);
    }

    if (regex_cd != NULL) {
        adpt_rs_compile_data_free(regex_cd);
    }

    if (rs_ret < 0) {
        goto error;
    }

    /* alloc scratch */
    rs_inst->rs_rt->bool_match_buffs = ALLOC(struct bool_expr_match *, n_worker_thread);
    for (i = 0; i < n_worker_thread; i++) {
        rs_inst->rs_rt->bool_match_buffs[i] = ALLOC(struct bool_expr_match, MAX_HIT_EXPR_NUM);
    }

    rs_inst->rs_rt->streams = ALLOC(struct adapter_rs_stream *, n_worker_thread);
    for (i = 0; i < n_worker_thread; i++) {
        rs_inst->rs_rt->streams[i] = (struct adapter_rs_stream *)adapter_rs_stream_open(rs_inst, i);
    }

    rs_inst->rs_rt->matched_pats = ALLOC(struct matched_pattern *, n_worker_thread);
    for (i = 0; i < n_worker_thread; i++) {
        rs_inst->rs_rt->matched_pats[i] = ALLOC(struct matched_pattern, 1);
        rs_inst->rs_rt->matched_pats[i]->ref_rs_attr = rs_inst->rs_attr;
        rs_inst->rs_rt->matched_pats[i]->n_patterns = rs_inst->n_patterns;
        utarray_new(rs_inst->rs_rt->matched_pats[i]->pattern_ids, &ut_rs_pattern_id_icd);
        utarray_reserve(rs_inst->rs_rt->matched_pats[i]->pattern_ids, MAX_HIT_PATTERN_NUM);
    }

    return rs_inst;
error:
    adapter_rs_free(rs_inst);
    return NULL;
}

void adapter_rs_free(void *rs_instance)
{
    if (NULL == rs_instance) {
        return;
    }

    size_t i = 0;
    struct adapter_rs *rs_inst = (struct adapter_rs *)rs_instance;

    if (rs_inst->rs_rt != NULL) {
        if (rs_inst->rs_rt->literal_db != NULL) {
            rs_free_database(rs_inst->rs_rt->literal_db);
            rs_inst->rs_rt->literal_db = NULL;
        }

        if (rs_inst->rs_rt->regex_db != NULL) {
            rs_free_database(rs_inst->rs_rt->regex_db);
            rs_inst->rs_rt->regex_db = NULL;
        }

        if (rs_inst->rs_rt->bool_match_buffs != NULL) {
            for (i = 0; i < rs_inst->n_worker_thread; i++) {
                if (rs_inst->rs_rt->bool_match_buffs[i] != NULL) {
                  FREE(rs_inst->rs_rt->bool_match_buffs[i]);
                }
            }

            FREE(rs_inst->rs_rt->bool_match_buffs);
        }

        if (rs_inst->rs_rt->bm != NULL) {
            bool_matcher_free(rs_inst->rs_rt->bm);
            rs_inst->rs_rt->bm = NULL;
        }

        if (rs_inst->rs_rt->streams != NULL) {
            for (i = 0; i < rs_inst->n_worker_thread; i++) {
                if (rs_inst->rs_rt->streams[i] != NULL) {
                    adapter_rs_stream_close(rs_inst->rs_rt->streams[i]);
                    rs_inst->rs_rt->streams[i] = NULL;
                }
            }
            FREE(rs_inst->rs_rt->streams);
        }

        if (rs_inst->rs_rt->matched_pats != NULL) {
            for (i = 0; i < rs_inst->n_worker_thread; i++) {
                if (rs_inst->rs_rt->matched_pats[i] != NULL) {
                    utarray_free(rs_inst->rs_rt->matched_pats[i]->pattern_ids);
                    FREE(rs_inst->rs_rt->matched_pats[i]);
                }
            }
            FREE(rs_inst->rs_rt->matched_pats);
        }

        FREE(rs_inst->rs_rt);
    }

    if (rs_inst->rs_attr != NULL) {
        FREE(rs_inst->rs_attr);
    }

    FREE(rs_inst);
}

static inline int compare_pattern_id(const void *a, const void *b)
{
	long long ret = *(const unsigned long long *)a - *(const unsigned long long *)b;
	if (ret == 0) {
		return 0;
	} else if(ret < 0) {
		return -1;
	} else {
		return 1;
	}
}

/**
 * @param id: pattern id
*/
static int matched_event_cb(unsigned int id, int pos_offset, int from, int to,
                            size_t data_len, void *ctx)
{
    // put id in set
    unsigned long long pattern_id = id;
    struct matched_pattern *matched_pat = (struct matched_pattern *)ctx;
    
    if (pattern_id > matched_pat->n_patterns || id < 0) {
        return 0;
    }

    if (utarray_len(matched_pat->pattern_ids) >= MAX_HIT_PATTERN_NUM) {
        return 0;
    }
    
    int ret = 0;
    struct pattern_attribute pat_attr = matched_pat->ref_rs_attr[id];

    switch (pat_attr.match_mode) {
        case EXPR_MATCH_MODE_EXACTLY:
            if (0 == (from + pos_offset) && (int)data_len == (to + pos_offset)) {
                ret = 1;
            }
            break;
        case EXPR_MATCH_MODE_SUB:
            if (pat_attr.offset.start == -1 && 
                pat_attr.offset.end == -1) {
                    ret = 1;
                    break;
            }

            if (pat_attr.offset.start == -1) {
                if ((long long)(to + pos_offset - 1) <= pat_attr.offset.end) {
                    ret = 1;
                    break;
                }
            }

            if (pat_attr.offset.end == -1) {
                if ((long long)(from + pos_offset) >= pat_attr.offset.start) {
                    ret = 1;
                    break;
                }
            }

            if ((long long)(from + pos_offset) >= pat_attr.offset.start && 
                (long long)(to + pos_offset - 1) <= pat_attr.offset.end) {
                ret = 1;
            }
            break;
        case EXPR_MATCH_MODE_PREFIX:
            if (0 == (from + pos_offset)) {
                ret = 1;
            }
            break;
        case EXPR_MATCH_MODE_SUFFIX:
            if ((to + pos_offset) == (int)data_len) {
                ret = 1;
            }
            break;
        default:
            break;
    }
   
    if (1 == ret) {
        utarray_push_back(matched_pat->pattern_ids, &pattern_id);
    }

    return 0;
}

void *adapter_rs_stream_open(void *rs_instance, int thread_id)
{
    if (NULL == rs_instance || thread_id < 0) {
        return NULL;
    }
    
    struct adapter_rs *rs_inst = (struct adapter_rs *)rs_instance;
    struct adapter_rs_stream *rs_stream = ALLOC(struct adapter_rs_stream, 1);

    rs_stream->logger = rs_inst->logger;
    rs_stream->thread_id = thread_id;
    rs_stream->ref_rs_rt = rs_inst->rs_rt;
    
    int err_count = 0;
    if (rs_inst->rs_rt->literal_db != NULL) {
        rs_stream->literal_stream = rs_open_stream(rs_inst->rs_rt->literal_db, 0, 128);
        if (NULL == rs_stream->literal_stream) {
            log_error(rs_inst->logger, MODULE_ADAPTER_RS, "rs_open_stream failed");
            err_count++;
        }
    }

    if (rs_inst->rs_rt->regex_db != NULL) {
        rs_stream->regex_stream = rs_open_stream(rs_inst->rs_rt->regex_db, 0, 128);
        if (NULL == rs_stream->regex_stream) {
            log_error(rs_inst->logger, MODULE_ADAPTER_RS, "rs_open_stream failed");
            err_count++;
        }
    }

    if (err_count > 0) {
        goto error;
    }

    return rs_stream;
error:
    if (rs_stream->literal_stream != NULL) {
        rs_close_stream(rs_stream->literal_stream);
        rs_stream->literal_stream = NULL;
    }

    if (rs_stream->regex_stream != NULL) {
        rs_close_stream(rs_stream->regex_stream);
        rs_stream->regex_stream = NULL;
    }

    FREE(rs_stream);
    return NULL;
}

void adapter_rs_stream_close(void *rs_stream)
{
    if (NULL == rs_stream) {
        return;
    }

    struct adapter_rs_stream *stream = (struct adapter_rs_stream *)rs_stream;
    if (stream->ref_rs_rt != NULL) {
        if (stream->literal_stream != NULL) {
            rs_close_stream(stream->literal_stream);
            stream->literal_stream = NULL;
        }
        
        if (stream->regex_stream != NULL) {
            rs_close_stream(stream->regex_stream);
            stream->regex_stream = NULL;
        }
    }

    /* rs_stream->rs_rt point to rs_instance->rs_rt which will call free 
        same as rs_attr */
    stream->ref_rs_rt = NULL;
    FREE(stream);
}

int adapter_rs_scan_match(struct bool_matcher *bm, UT_array *pattern_ids,
                          struct bool_expr_match *match_buff, size_t buff_size,
                          struct expr_scan_result *results, size_t n_result,
                          size_t *n_hit_result)
{
    size_t n_pattern_id = utarray_len(pattern_ids);
    if (0 == n_pattern_id) {
        *n_hit_result = 0;
        return 0;
    }

    utarray_sort(pattern_ids, compare_pattern_id);

    unsigned long long prev_pattern_id = 0xFFFFFFFFFFFFFFFF;
    unsigned long long tmp_pattern_id = 0;
    size_t n_unique_pattern_id = 0;
    unsigned long long unique_pattern_ids[n_pattern_id];

    for (size_t i = 0; i < n_pattern_id; i++) {
        tmp_pattern_id = *(unsigned long long *)utarray_eltptr(pattern_ids, i);
        if (tmp_pattern_id != prev_pattern_id) {
            unique_pattern_ids[n_unique_pattern_id++] = tmp_pattern_id;
            prev_pattern_id = tmp_pattern_id;
        }
    }

    int bool_matcher_ret = bool_matcher_match(bm, unique_pattern_ids,
                                              n_unique_pattern_id,
                                              match_buff, buff_size);
    if (bool_matcher_ret < 0) {
        goto next;
    }

    if (bool_matcher_ret > (int)n_result) {
        bool_matcher_ret = n_result;
    }

    for (int index = 0; index < bool_matcher_ret; index++) {
        results[index].rule_id = match_buff[index].expr_id;
        results[index].user_tag = match_buff[index].user_tag;
    }
    *n_hit_result = bool_matcher_ret;

next:
    utarray_clear(pattern_ids);
    return bool_matcher_ret;
}

int adapter_rs_scan_stream(void *rs_stream, const char *data, size_t data_len,
                           struct expr_scan_result *results, size_t n_result,
                           size_t *n_hit_result)
{
    if (NULL == rs_stream || NULL == data || 0 == data_len ||
        NULL == results || 0 == n_result || NULL == n_hit_result) {
        return -1;
    }
    
    int ret = 0, err_count = 0;
    struct adapter_rs_stream *stream = (struct adapter_rs_stream *)rs_stream;
    int thread_id = stream->thread_id;
    struct adapter_rs_runtime *rs_rt = stream->ref_rs_rt;
    struct matched_pattern *matched_pat = rs_rt->matched_pats[thread_id];

    if (stream->literal_stream != NULL) {
        ret = rs_scan_stream(stream->literal_stream, data, data_len,
                             matched_event_cb, matched_pat);
        if (ret < 0) {
            err_count++;
        }
    }

    if (stream->regex_stream != NULL) {
        ret = rs_scan_stream(stream->regex_stream, data, data_len,
                             matched_event_cb, matched_pat);
        if (ret < 0) {
            err_count++;
        }
    }

    if (err_count == 2) {
        return -1;
    }

    return adapter_rs_scan_match(rs_rt->bm, matched_pat->pattern_ids,
                                 rs_rt->bool_match_buffs[thread_id],
                                 MAX_HIT_EXPR_NUM, results, n_result,
                                 n_hit_result);
}

int adapter_rs_scan(void *rs_instance, int thread_id, const char *data, size_t data_len,
                    struct expr_scan_result *results, size_t n_result, size_t *n_hit_result)
{
    if (NULL == rs_instance || NULL == data || (0 == data_len) || 
        NULL == results || 0 == n_result || NULL == n_hit_result) {
        return -1;
    }

    int ret = 0, err_count = 0;
    struct adapter_rs *rs_inst = (struct adapter_rs *)rs_instance;
    struct adapter_rs_runtime *rs_rt = rs_inst->rs_rt;
    struct matched_pattern *matched_pat = rs_rt->matched_pats[thread_id];

    if (rs_rt->literal_db != NULL) {
        ret = rs_scan(rs_rt->literal_db, thread_id, data, data_len,
                      0, matched_event_cb, matched_pat);
        if (ret < 0) {
            err_count++;
        }
    }
    
    if (rs_rt->regex_db != NULL) {
        ret = rs_scan(rs_rt->regex_db, thread_id, data, data_len,
                      0, matched_event_cb, matched_pat);
        if (ret < 0) {
            err_count++;
        }
    }

    if (err_count == 2) {
        return -1;
    }

    return adapter_rs_scan_match(rs_rt->bm, matched_pat->pattern_ids,
                                 rs_rt->bool_match_buffs[thread_id],
                                 MAX_HIT_EXPR_NUM, results, n_result,
                                 n_hit_result);
}