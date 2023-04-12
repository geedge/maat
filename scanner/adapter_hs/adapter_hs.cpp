/*
**********************************************************************************************
*	File: adapter_hs.cpp
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <hs/hs.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h> 

#include "adapter_hs.h"
#include "uthash/utarray.h"
#include "uthash/uthash.h"
#include "maat_utils.h"
#include "../bool_matcher/bool_matcher.h"

#define MAX_OFFSET_NUM 1024

pid_t hs_gettid() 
{
	return syscall(SYS_gettid);
}

static const char *hs_module_name_str(const char *name)
{
	static __thread char module[64];
	snprintf(module,sizeof(module),"%s(%d)", name, hs_gettid());
    
	return module;
}

#define MODULE_ADAPTER_HS	 hs_module_name_str("maat.adapter_hs")

struct adpt_hs_compile_data {
    unsigned int *ids;
    unsigned int *flags;
    char **patterns;
    size_t *pattern_lens;
    unsigned int n_patterns;
};

/* adapter_hs runtime */
struct adapter_hs_runtime {
    hs_database_t *literal_db;
    hs_database_t *regex_db;

    hs_scratch_t **literal_scratches;
    hs_scratch_t **regex_scratches;

    struct bool_matcher *bm;
};

/* adapter_hs instance */
struct adapter_hs {
    size_t n_worker_thread;
    size_t n_expr;
    size_t n_patterns;
    struct adapter_hs_runtime *hs_rt;
    struct pattern_attribute *hs_attr;
    struct log_handle *logger;
};

struct pattern_offset {
    long long start;
    long long end;
};

struct pattern_attribute {
    long long pattern_id;
    enum hs_match_mode match_mode;
    struct pattern_offset offset;
};

struct matched_pattern {
    UT_array *pattern_ids;
    size_t n_patterns;
    struct pattern_attribute *ref_hs_attr;
    size_t scan_data_len;
};

struct adapter_hs_stream {
    int thread_id;
    size_t n_expr;
    hs_stream_t *literal_stream;
    hs_stream_t *regex_stream;
    struct adapter_hs_runtime *ref_hs_rt;
    struct matched_pattern *matched_pat;
    struct log_handle *logger;
};

int _hs_alloc_scratch(hs_database_t *db, hs_scratch_t **scratches, size_t n_worker_thread,
                      struct log_handle *logger)
{
    size_t scratch_size = 0;

    if (hs_alloc_scratch(db, &scratches[0]) != HS_SUCCESS) {
        log_error(logger, MODULE_ADAPTER_HS,
                  "[%s:%d] Unable to allocate scratch space. Exiting.",
                  __FUNCTION__, __LINE__);
        return -1;
    }

    for (size_t i = 1; i < n_worker_thread; i++) {
        hs_error_t err = hs_clone_scratch(scratches[0], &scratches[i]);
        if (err != HS_SUCCESS) {
            log_error(logger, MODULE_ADAPTER_HS,
                      "[%s:%d] Unable to clone scratch", __FUNCTION__, __LINE__);
            return -1;
        }

        err = hs_scratch_size(scratches[i], &scratch_size);
        if (err != HS_SUCCESS) {
            log_error(logger, MODULE_ADAPTER_HS,
                      "[%s:%d] Unable to query scratch size", __FUNCTION__, __LINE__);
            return -1;
        } else {
            log_info(logger, MODULE_ADAPTER_HS,
                     "[%s:%d] scratch[%d] size:%zu", __FUNCTION__, __LINE__, i, scratch_size);
        }
    }

    return 0;
}

static int adpt_hs_alloc_scratch(struct adapter_hs_runtime *hs_rt, size_t n_worker_thread,
                                 enum hs_pattern_type pattern_type, struct log_handle *logger)
{
    int ret = 0;

    if (pattern_type == HS_PATTERN_TYPE_STR) {
        hs_rt->literal_scratches = ALLOC(hs_scratch_t *, n_worker_thread);
        ret = _hs_alloc_scratch(hs_rt->literal_db, hs_rt->literal_scratches, n_worker_thread, logger);
        if (ret < 0) {
            FREE(hs_rt->literal_scratches);
            return -1;
        }
    } else {
        hs_rt->regex_scratches = ALLOC(hs_scratch_t *, n_worker_thread);
        ret = _hs_alloc_scratch(hs_rt->regex_db, hs_rt->regex_scratches, n_worker_thread, logger);
        if (ret < 0) {
            FREE(hs_rt->regex_scratches);
            return -1;
        }
    }

    return 0;
}

/**
 * @brief build hs block database for literal string and regex expression respectively
 * 
 * @retval 0(success) -1(failed)
*/
static int adpt_hs_build_database(struct adapter_hs_runtime *hs_rt, 
                                  struct adpt_hs_compile_data *literal_cd, 
                                  struct adpt_hs_compile_data *regex_cd, 
                                  struct log_handle *logger)
{
    hs_error_t err;
    hs_compile_error_t *compile_err = NULL;

    if (NULL == hs_rt || (NULL == literal_cd && NULL == regex_cd)) {
        return -1;
    }

    if (literal_cd != NULL) {
        err = hs_compile_lit_multi((const char *const *)literal_cd->patterns, literal_cd->flags,
                                    literal_cd->ids, literal_cd->pattern_lens, literal_cd->n_patterns, 
                                    HS_MODE_STREAM, NULL, &hs_rt->literal_db, &compile_err);
        if (err != HS_SUCCESS) {
            if (compile_err) {
                log_error(logger, MODULE_ADAPTER_HS, "[%s:%d] compile error: %s", 
                          __FUNCTION__, __LINE__, compile_err->message);
            }

            hs_free_compile_error(compile_err);
            return -1;
        }
    }
    
    if (regex_cd != NULL) {
        err = hs_compile_multi((const char *const *)regex_cd->patterns, regex_cd->flags, regex_cd->ids, 
                                regex_cd->n_patterns, HS_MODE_STREAM | HS_MODE_SOM_HORIZON_SMALL, NULL, 
                                &hs_rt->regex_db, &compile_err);
        if (err != HS_SUCCESS) {
            if (compile_err) {
                log_error(logger, MODULE_ADAPTER_HS, "[%s:%d] compile error: %s",
                          __FUNCTION__, __LINE__, compile_err->message);
            }
            hs_free_compile_error(compile_err);
            return -1;
        }
    }
    
    return 0;
}

struct adpt_hs_compile_data *adpt_hs_compile_data_new(size_t n_patterns)
{
    struct adpt_hs_compile_data *hs_cd = ALLOC(struct adpt_hs_compile_data, 1);
    hs_cd->patterns = ALLOC(char *, n_patterns);
    hs_cd->pattern_lens = ALLOC(size_t, n_patterns);
    hs_cd->n_patterns = n_patterns;
    hs_cd->ids = ALLOC(unsigned int, n_patterns);
    hs_cd->flags = ALLOC(unsigned int, n_patterns);

    return hs_cd;
}

void adpt_hs_compile_data_free(struct adpt_hs_compile_data *hs_cd)
{
    if (NULL == hs_cd) {
        return;
    }

    if (hs_cd->patterns != NULL) {
        for (size_t i = 0; i < hs_cd->n_patterns; i++) {
            FREE(hs_cd->patterns[i]);
        }

        FREE(hs_cd->patterns);
        FREE(hs_cd->pattern_lens);
        FREE(hs_cd->ids);
        FREE(hs_cd->flags);
    }

    FREE(hs_cd);
}

void populate_compile_data(struct adpt_hs_compile_data *compile_data, int index, int pattern_id,
                          char *pat, size_t pat_len, int case_sensitive)
{
    compile_data->ids[index] = pattern_id;

    /* set flags */
    compile_data->flags[index] |= HS_FLAG_SOM_LEFTMOST;
    if (case_sensitive == HS_CASE_INSESITIVE) {
        compile_data->flags[index] |= HS_FLAG_CASELESS;
    }

    compile_data->pattern_lens[index] = pat_len;
    compile_data->patterns[index] = ALLOC(char, pat_len + 1);
    memcpy(compile_data->patterns[index], pat, pat_len);
}

struct bool_expr *bool_exprs_new(struct hs_expr *exprs, size_t n_expr, struct pattern_attribute *pattern_attr,
                                 struct adpt_hs_compile_data *literal_cd, struct adpt_hs_compile_data *regex_cd,
                                 size_t *n_pattern)
{
    uint32_t pattern_index = 0;
    uint32_t literal_index = 0;
    uint32_t regex_index = 0;

    struct bool_expr *bool_exprs = ALLOC(struct bool_expr, n_expr);
    if (NULL == bool_exprs) {
        return NULL;
    }

    /* populate adpt_hs_compile_data and bool_expr */
    for (size_t i = 0; i < n_expr; i++) {

        for (size_t j = 0; j < exprs[i].n_patterns; j++) {
            pattern_attr[pattern_index].pattern_id = pattern_index;
            pattern_attr[pattern_index].match_mode = exprs[i].patterns[j].match_mode;
            
            if (pattern_attr[pattern_index].match_mode == HS_MATCH_MODE_SUB || 
                pattern_attr[pattern_index].match_mode == HS_MATCH_MODE_EXACTLY) {
                pattern_attr[pattern_index].offset.start = exprs[i].patterns[j].start_offset;
                pattern_attr[pattern_index].offset.end = exprs[i].patterns[j].end_offset;
            }

            /* literal pattern */
            if (exprs[i].patterns[j].pattern_type == HS_PATTERN_TYPE_STR) {
                populate_compile_data(literal_cd, literal_index, pattern_index, 
                                      exprs[i].patterns[j].pat, exprs[i].patterns[j].pat_len,
                                      exprs[i].patterns[j].case_sensitive);
                literal_index++;
            } else {
                /* regex pattern */
                populate_compile_data(regex_cd, regex_index, pattern_index, 
                                      exprs[i].patterns[j].pat, exprs[i].patterns[j].pat_len,
                                      exprs[i].patterns[j].case_sensitive);
                regex_index++;
            }

            bool_exprs[i].items[j].item_id = pattern_index++;
            bool_exprs[i].items[j].not_flag = 0;
            // printf("item_id:%llu, pat:%s pat_len:%zu\n", 
            //         bool_exprs[i].items[j].item_id, exprs[i].patterns[j].pat, exprs[i].patterns[j].pat_len);
        }
        //printf("expr_id:%lld item_num:%zu\n", exprs[i].expr_id, exprs[i].n_patterns);
        bool_exprs[i].expr_id = exprs[i].expr_id;
        bool_exprs[i].item_num = exprs[i].n_patterns;
        bool_exprs[i].user_tag = exprs[i].user_tag;
    }

    *n_pattern = pattern_index;

    return bool_exprs;
}

struct adapter_hs *adapter_hs_new(size_t n_worker_thread,
                                  struct hs_expr *exprs, size_t n_expr,
                                  struct log_handle *logger)
{
    if (0 == n_worker_thread || NULL == exprs || 0 == n_expr) {
        log_error(logger, MODULE_ADAPTER_HS, "[%s:%d] input parameters illegal!",
                  __FUNCTION__, __LINE__);
        return NULL;
    }

    /* get the sum of pattern */
    size_t literal_pattern_num = 0;
    size_t regex_pattern_num = 0;
    for (size_t i = 0; i < n_expr; i++) {
        if (exprs[i].n_patterns > MAX_EXPR_PATTERN_NUM) {
            log_error(logger, MODULE_ADAPTER_HS, 
                      "[%s:%d] the number of patterns in one expression should less than %d",
                      __FUNCTION__, __LINE__, MAX_EXPR_PATTERN_NUM);
            return NULL;
        }

        for (size_t j = 0; j < exprs[i].n_patterns; j++) {
            /* pat_len should not 0 */
            if (0 == exprs[i].patterns[j].pat_len) {
                log_error(logger, MODULE_ADAPTER_HS,
                          "[%s:%d] expr pattern length should not 0", __FUNCTION__, __LINE__);
                return NULL;
            }

            if (exprs[i].patterns[j].pattern_type == HS_PATTERN_TYPE_STR) {
                literal_pattern_num++;
            } else {
                regex_pattern_num++;
            }
        }
    }

    if (0 == literal_pattern_num && 0 == regex_pattern_num) {
        log_error(logger, MODULE_ADAPTER_HS, "[%s:%d] exprs has no valid pattern",
                  __FUNCTION__, __LINE__);
        return NULL;
    }

    struct adpt_hs_compile_data *literal_cd = NULL;
    struct adpt_hs_compile_data *regex_cd = NULL;
    if (literal_pattern_num > 0) {
        literal_cd = adpt_hs_compile_data_new(literal_pattern_num);
    }
   
    if (regex_pattern_num > 0) {
        regex_cd = adpt_hs_compile_data_new(regex_pattern_num);
    }
    
    size_t pattern_cnt = literal_pattern_num + regex_pattern_num;
    struct adapter_hs *hs_instance = ALLOC(struct adapter_hs, 1);
    hs_instance->hs_attr = ALLOC(struct pattern_attribute, pattern_cnt);
    hs_instance->logger = logger;
    hs_instance->n_worker_thread = n_worker_thread;
    hs_instance->n_expr = n_expr;

    struct bool_expr *bool_exprs = bool_exprs_new(exprs, n_expr, hs_instance->hs_attr,
                                                  literal_cd, regex_cd, &pattern_cnt);
    if (NULL == bool_exprs) {
        return NULL;
    }
    hs_instance->n_patterns = pattern_cnt;
    
    //mytest
    // for (size_t i = 0; i < n_expr; i++) {
    //     {
    //         printf("<before bool_matcher_new> exprs[%zu] expr_id:%llu, item_num:%zu\n",
    //                i, bool_exprs[i].expr_id, bool_exprs[i].item_num);
    //         printf("item_id: ");
    //         for (size_t j = 0; j < bool_exprs[i].item_num; j++)
    //         {
    //             printf("%llu ", bool_exprs[i].items[j].item_id);
    //         }
    //     }
    //     printf("\n");
    // }
    
    
    /* create bool matcher */
    size_t mem_size = 0;
    int hs_ret = 0;
    hs_instance->hs_rt = ALLOC(struct adapter_hs_runtime, 1);
    hs_instance->hs_rt->bm = bool_matcher_new(bool_exprs, n_expr, &mem_size);
    if (hs_instance->hs_rt->bm != NULL) {
        log_info(logger, MODULE_ADAPTER_HS, 
                 "Adapter_hs module: build bool matcher of %zu expressions with %zu bytes memory", 
                 n_expr, mem_size);
    } else {
        log_error(logger, MODULE_ADAPTER_HS, "[%s:%d] Adapter_hs module: build bool matcher failed",
                  __FUNCTION__, __LINE__);
        
        hs_ret = -1;
    }
    FREE(bool_exprs);

    /* build hs database */
    int ret = adpt_hs_build_database(hs_instance->hs_rt, literal_cd, regex_cd, logger);
    if (ret < 0) {
        hs_ret = -1;
    }

    if (literal_cd != NULL) {
        adpt_hs_compile_data_free(literal_cd);
    }

    if (regex_cd != NULL) {
        adpt_hs_compile_data_free(regex_cd);
    }

    if (hs_ret < 0) {
        goto error;
    }

    /* literal and regex scratch can't reuse */
    if (literal_pattern_num > 0) {
        ret = adpt_hs_alloc_scratch(hs_instance->hs_rt, n_worker_thread, HS_PATTERN_TYPE_STR, logger);
        if (ret < 0) {
            goto error;
        }
    }

    if (regex_pattern_num > 0) {
        ret = adpt_hs_alloc_scratch(hs_instance->hs_rt, n_worker_thread, HS_PATTERN_TYPE_REG, logger);
        if (ret < 0) {
            goto error;
        }
    }

    return hs_instance;
error:
    adapter_hs_free(hs_instance);
    return NULL;
}

void adapter_hs_free(struct adapter_hs *hs_instance)
{
    if (NULL == hs_instance) {
        return;
    }

    if (hs_instance->hs_rt != NULL) {
        if (hs_instance->hs_rt->literal_db != NULL) {
            hs_free_database(hs_instance->hs_rt->literal_db);
            hs_instance->hs_rt->literal_db = NULL;
        }

        if (hs_instance->hs_rt->regex_db != NULL) {
            hs_free_database(hs_instance->hs_rt->regex_db);
            hs_instance->hs_rt->regex_db = NULL;
        }

        if (hs_instance->hs_rt->literal_scratches != NULL) {
            for (size_t i = 0; i < hs_instance->n_worker_thread; i++) {
                if (hs_instance->hs_rt->literal_scratches[i] != NULL) {
                    hs_free_scratch(hs_instance->hs_rt->literal_scratches[i]);
                    hs_instance->hs_rt->literal_scratches[i] = NULL;
                }
            }

            FREE(hs_instance->hs_rt->literal_scratches);
            hs_instance->hs_rt->literal_scratches = NULL;
        }
        

        if (hs_instance->hs_rt->regex_scratches != NULL) {
            for (size_t i = 0; i < hs_instance->n_worker_thread; i++) {
                if (hs_instance->hs_rt->regex_scratches[i] != NULL) {
                    hs_free_scratch(hs_instance->hs_rt->regex_scratches[i]);
                    hs_instance->hs_rt->regex_scratches[i] = NULL;
                }
            }

            FREE(hs_instance->hs_rt->regex_scratches);
            hs_instance->hs_rt->regex_scratches = NULL;
        }
        
        if (hs_instance->hs_rt->bm != NULL) {
            bool_matcher_free(hs_instance->hs_rt->bm);
            hs_instance->hs_rt->bm = NULL;
        }

        FREE(hs_instance->hs_rt);
    }

    if (hs_instance->hs_attr != NULL) {
        FREE(hs_instance->hs_attr);
    }

    FREE(hs_instance);
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
int matched_event_cb(unsigned int id, unsigned long long from,
                     unsigned long long to, unsigned int flags, 
                     void *ctx) {
    // put id in set
    unsigned long long pattern_id = id;
    struct matched_pattern *matched_pat = (struct matched_pattern *)ctx;

    if (id > matched_pat->n_patterns || id < 0) {
        return 0;
    }

    // duplicate pattern_id
    if (utarray_find(matched_pat->pattern_ids, &pattern_id, compare_pattern_id)) {
        return 0;
    }
    
    int ret = 0;
    struct pattern_attribute pat_attr = matched_pat->ref_hs_attr[id];
    switch (pat_attr.match_mode) {
        case HS_MATCH_MODE_EXACTLY:
            if (0 == from && matched_pat->scan_data_len == to) {
                ret = 1;
            }
            break;
        case HS_MATCH_MODE_SUB:
            if (pat_attr.offset.start == -1 && 
                pat_attr.offset.end == -1) {
                    ret = 1;
                    break;
            }

            if (pat_attr.offset.start == -1) {
                if ((long long)(to - 1) <= pat_attr.offset.end) {
                    ret = 1;
                    break;
                }
            }

            if (pat_attr.offset.end == -1) {
                if ((long long)from >= pat_attr.offset.start) {
                    ret = 1;
                    break;
                }
            }

            if ((long long)from >= pat_attr.offset.start && 
                (long long)(to - 1) <= pat_attr.offset.end) {
                ret = 1;
            }
            break;
        case HS_MATCH_MODE_PREFIX:
            if (0 == from) {
                ret = 1;
            }
            break;
        case HS_MATCH_MODE_SUFFIX:
            if (to == matched_pat->scan_data_len) {
                ret = 1;
            }
            break;
        default:
            break;
    }
   
    if (1 == ret) {
        utarray_push_back(matched_pat->pattern_ids, &pattern_id);
        utarray_sort(matched_pat->pattern_ids, compare_pattern_id);
    }
    
    return 0;
}

UT_icd ut_pattern_id_icd = {sizeof(unsigned long long), NULL, NULL, NULL};
struct adapter_hs_stream *adapter_hs_stream_open(struct adapter_hs *hs_instance, int thread_id)
{
    if (NULL == hs_instance || thread_id < 0) {
        return NULL;
    }
    
    struct adapter_hs_stream *hs_stream = ALLOC(struct adapter_hs_stream, 1);
    hs_error_t err;

    hs_stream->logger = hs_instance->logger;
    hs_stream->thread_id = thread_id;
    hs_stream->n_expr = hs_instance->n_expr;
    hs_stream->ref_hs_rt = hs_instance->hs_rt;
    hs_stream->matched_pat = ALLOC(struct matched_pattern, 1);
    hs_stream->matched_pat->ref_hs_attr = hs_instance->hs_attr;
    hs_stream->matched_pat->n_patterns = hs_instance->n_patterns;
    utarray_new(hs_stream->matched_pat->pattern_ids, &ut_pattern_id_icd);
    utarray_reserve(hs_stream->matched_pat->pattern_ids, hs_instance->n_patterns);

    int err_count = 0;
    if (hs_instance->hs_rt->literal_db != NULL) {
        err = hs_open_stream(hs_instance->hs_rt->literal_db, 0, &hs_stream->literal_stream);
        if (err != HS_SUCCESS) {
            log_error(hs_instance->logger, MODULE_ADAPTER_HS, "hs_open_stream failed, hs err:%d", err);
            err_count++;
        }
    }

    if (hs_instance->hs_rt->regex_db != NULL) {
        err = hs_open_stream(hs_instance->hs_rt->regex_db, 0, &hs_stream->regex_stream);
        if (err != HS_SUCCESS) {
            log_error(hs_instance->logger, MODULE_ADAPTER_HS, "hs_open_stream failed, hs err:%d", err);
            err_count++;
        }
    }

    if (err_count > 0) {
        goto error;
    }

    return hs_stream;
error:
    //TODO: hs_stream->hs_rt->scratches[thread_id] may be free twice
    if (hs_stream->literal_stream != NULL) {
        hs_close_stream(hs_stream->literal_stream, NULL, NULL, NULL);
        hs_stream->literal_stream = NULL;
    }

    if (hs_stream->regex_stream != NULL) {
        hs_close_stream(hs_stream->regex_stream, NULL, NULL, NULL);
        hs_stream->regex_stream = NULL;
    }

    FREE(hs_stream);
    return NULL;
}

void adapter_hs_stream_close(struct adapter_hs_stream *hs_stream)
{
    if (NULL == hs_stream) {
        return;
    }

    if (hs_stream->ref_hs_rt != NULL) {
        if (hs_stream->literal_stream != NULL) {
            hs_close_stream(hs_stream->literal_stream, NULL, NULL, NULL);
            hs_stream->literal_stream = NULL;
        }
        
        if (hs_stream->regex_stream != NULL) {
            hs_close_stream(hs_stream->regex_stream, NULL, NULL, NULL);
            hs_stream->regex_stream = NULL;
        }
    }

    /* hs_stream->hs_rt point to hs_instance->hs_rt which will call free 
        same as hs_attr */
    hs_stream->ref_hs_rt = NULL;
    hs_stream->matched_pat->ref_hs_attr = NULL;
    utarray_free(hs_stream->matched_pat->pattern_ids);

    FREE(hs_stream->matched_pat);
    FREE(hs_stream);
}

int adapter_hs_scan_stream(struct adapter_hs_stream *hs_stream, const char *data, size_t data_len,
                           struct hs_scan_result *results, size_t n_result, size_t *n_hit_result)
{
    hs_error_t err;

    if (NULL == hs_stream || NULL == data || 0 == data_len ||
        NULL == results || 0 == n_result || NULL == n_hit_result) {
        return -1;
    }
    
    /* 
        In streaming mode, a non-zero return from the user-specified event-handler
        function has consequences for the rest of that stream's lifetime: when a
        non-zero return occurs, it signals that no more of the stream should be
        scanned. Consequently if the user makes a subsequent call to
        `hs_scan_stream` on a stream whose processing was terminated in this way,
        hs_scan_stream will return `HS_SCAN_TERMINATED`. This case has not been
        demonstrated in pcapscan, as its callback always returns 0. 
    */

    int err_count = 0;
    int thread_id = hs_stream->thread_id;
    hs_stream->matched_pat->scan_data_len = data_len;

    int err_scratch_flag = 0;
    if (hs_stream->literal_stream != NULL) {
        if (hs_stream->ref_hs_rt->literal_scratches != NULL) {
            err = hs_scan_stream(hs_stream->literal_stream, data, data_len,
                                 0, hs_stream->ref_hs_rt->literal_scratches[thread_id],
                                 matched_event_cb, hs_stream->matched_pat);
            if (err != HS_SUCCESS) {
                err_count++;
            }
        } else {
            log_error(hs_stream->logger, MODULE_ADAPTER_HS, "literal_scratches is null, thread_id:%d", 
                     thread_id);
            err_scratch_flag++;
        }
    }

    if (hs_stream->regex_stream != NULL) {
        if (hs_stream->ref_hs_rt->regex_scratches != NULL) {
            err = hs_scan_stream(hs_stream->regex_stream, data, data_len,
                                 0, hs_stream->ref_hs_rt->regex_scratches[thread_id],
                                 matched_event_cb, hs_stream->matched_pat);
            if (err != HS_SUCCESS) {
                err_count++;
            }
        } else {
            log_error(hs_stream->logger, MODULE_ADAPTER_HS, "regex_scratches is null, thread_id:%d",
                      thread_id);
            err_scratch_flag++;
        }
    }

    if (err_count == 2) {
        return -1;
    }

    if (err_scratch_flag != 0) {
        return -1;
    }

    size_t n_pattern_id = utarray_len(hs_stream->matched_pat->pattern_ids);
    if (0 == n_pattern_id) {
        *n_hit_result = 0;
        return 0;
    }

    if (n_pattern_id > MAX_SCANNER_HIT_PATTERN_NUM) {
        n_pattern_id = MAX_SCANNER_HIT_PATTERN_NUM;
    }

    unsigned long long pattern_ids[MAX_SCANNER_HIT_PATTERN_NUM];
    memset(pattern_ids, 0, sizeof(unsigned long long) * MAX_SCANNER_HIT_PATTERN_NUM);

    for (size_t i = 0; i < n_pattern_id; i++) {
        if (i >= MAX_SCANNER_HIT_PATTERN_NUM) {
            break;
        }

        unsigned long long pattern_id = *(unsigned long long *)utarray_eltptr(hs_stream->matched_pat->pattern_ids, i);
        pattern_ids[i] = pattern_id;
    }

    int ret = 0;
    struct bool_expr_match *bool_matcher_results = ALLOC(struct bool_expr_match, hs_stream->n_expr);
    int bool_matcher_ret = bool_matcher_match(hs_stream->ref_hs_rt->bm, pattern_ids, n_pattern_id,
                                              bool_matcher_results, hs_stream->n_expr);
    if (bool_matcher_ret < 0) {
        ret = -1;
        goto next;
    }

    if (bool_matcher_ret > (int)n_result) {
        bool_matcher_ret = n_result;
    }

    for (int index = 0; index < bool_matcher_ret; index++) {
        results[index].item_id = bool_matcher_results[index].expr_id;
        results[index].user_tag = bool_matcher_results[index].user_tag;
    }
    *n_hit_result = bool_matcher_ret;
next:
    FREE(bool_matcher_results);
    utarray_clear(hs_stream->matched_pat->pattern_ids);

    return ret;
}

int adapter_hs_scan(struct adapter_hs *hs_instance, int thread_id,
                    const char *data, size_t data_len, 
                    struct hs_scan_result *results,
                    size_t n_result, size_t *n_hit_result)
{
    if (NULL == hs_instance || NULL == data || (0 == data_len) || 
        NULL == results || 0 == n_result || NULL == n_hit_result) {
        return -1;
    }

    struct adapter_hs_stream *hs_stream = adapter_hs_stream_open(hs_instance, thread_id);
    if (NULL == hs_stream) {
        return -1;
    }

    int ret = adapter_hs_scan_stream(hs_stream, data, data_len, results, n_result, n_hit_result);
    adapter_hs_stream_close(hs_stream);

    return ret;
}