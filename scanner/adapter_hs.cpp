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

#include "adapter_hs.h"
#include "uthash/utarray.h"
#include "uthash/uthash.h"
#include "utils.h"
#include "maat_utils.h"
#include "bool_matcher.h"

#define MODULE_ADAPTER_HS	 module_name_str("maat.adapter_hs")

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

    hs_scratch_t **scratchs;
    size_t scratch_size;

    struct bool_matcher *bm;
};

/* adapter_hs instance */
struct adapter_hs {
    size_t nr_worker_threads;
    size_t n_expr;
    size_t n_patterns;
    struct adapter_hs_runtime *hs_rt;
};

struct adapter_hs_stream {
    int thread_id;
    size_t n_expr;
    size_t n_patterns;
    hs_stream_t *literal_stream;
    hs_stream_t *regex_stream;
    struct adapter_hs_runtime *hs_rt;
    UT_array *pattern_id_set;
};

static int adpt_hs_alloc_scratch(struct adapter_hs_runtime *hs_rt, size_t nr_worker_threads, int max_pattern_type,
                                 struct log_handle *logger)
{
    hs_database_t *database = NULL;
    hs_rt->scratchs = ALLOC(hs_scratch_t *, nr_worker_threads);

    if (max_pattern_type == PATTERN_TYPE_STR) {
        database = hs_rt->literal_db;
    } else {
        database = hs_rt->regex_db;
    }

    if (hs_alloc_scratch(database, &hs_rt->scratchs[0]) != HS_SUCCESS) {
        log_error(logger, MODULE_ADAPTER_HS, "ERROR: Unable to allocate scratch space. Exiting.");
        hs_free_database(database);
        return -1;
    }

    for (size_t i = 1; i < nr_worker_threads; i++) {
        hs_error_t err = hs_clone_scratch(hs_rt->scratchs[0], &hs_rt->scratchs[i]);
        if (err != HS_SUCCESS) {
            log_error(logger, MODULE_ADAPTER_HS, "Unable to clone scratch prototype");
            hs_free_database(database);
            return -1;
        }

        err = hs_scratch_size(hs_rt->scratchs[i], &hs_rt->scratch_size);
        if (err != HS_SUCCESS) {
            log_error(logger, MODULE_ADAPTER_HS, "Unable to query scratch size");
            hs_free_database(database);
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
                                  int scan_mode, struct log_handle *logger)
{
    hs_error_t err;
    hs_compile_error_t *compile_err = NULL;

    if (NULL == hs_rt) {
        return -1;
    }

    if (literal_cd != NULL) {
        err = hs_compile_lit_multi((const char *const *)literal_cd->patterns, literal_cd->flags,
                                   literal_cd->ids, literal_cd->pattern_lens, literal_cd->n_patterns, 
                                   scan_mode, NULL, &hs_rt->literal_db, &compile_err);
        if (err != HS_SUCCESS) {
            if (compile_err) {
                log_error(logger, MODULE_ADAPTER_HS, "%s compile error: %s", __func__, compile_err->message);
            }

            hs_free_compile_error(compile_err);
            goto error;
        }
    }

    if (regex_cd != NULL) {
        err = hs_compile_ext_multi((const char *const *)regex_cd->patterns, regex_cd->flags,
                                   regex_cd->ids, NULL, regex_cd->n_patterns, 
                                   scan_mode, NULL, &hs_rt->regex_db, &compile_err);
        if (err != HS_SUCCESS) {
            if (compile_err) {
                log_error(logger, MODULE_ADAPTER_HS, "%s compile error: %s", __func__, compile_err->message);
            }
            hs_free_compile_error(compile_err);
            goto error;
        }
    }

    return 0;
error:
    if (hs_rt->literal_db != NULL) {
        hs_free_database(hs_rt->literal_db);
        hs_rt->literal_db = NULL;
    }

    if (hs_rt->regex_db != NULL) {
        hs_free_database(hs_rt->regex_db);
        hs_rt->regex_db = NULL;
    }
    
    return -1;
}

struct adpt_hs_compile_data *adpt_hs_compile_data_new(size_t n_patterns)
{
    struct adpt_hs_compile_data *hs_cd = ALLOC(struct adpt_hs_compile_data, 1);
    hs_cd->patterns = ALLOC(char *, n_patterns);
    hs_cd->pattern_lens = ALLOC(size_t, n_patterns);
    hs_cd->ids = ALLOC(unsigned int, n_patterns);
    hs_cd->flags = ALLOC(unsigned int, n_patterns);

    return hs_cd;
}

void adpt_hs_compile_data_free(struct adpt_hs_compile_data *hs_cd, size_t n_patterns)
{
    if (NULL == hs_cd) {
        return;
    }

    if (hs_cd->patterns != NULL) {
        for (size_t i = 0; i < n_patterns; i++) {
            FREE(hs_cd->patterns[i]);
        }

        FREE(hs_cd->patterns);
        FREE(hs_cd->pattern_lens);
        FREE(hs_cd->ids);
        FREE(hs_cd->flags);
    }

    FREE(hs_cd);
}

struct adapter_hs *adapter_hs_initialize(int scan_mode, size_t nr_worker_threads, and_expr_t *expr_array, size_t n_expr_array,
                                         struct log_handle *logger)
{
    if ((scan_mode != HS_SCAN_MODE_BLOCK && scan_mode != HS_SCAN_MODE_STREAM) || 
         0 == nr_worker_threads || NULL == expr_array || 0 == n_expr_array) {
        log_error(logger, MODULE_ADAPTER_HS, "%s input parameters illegal!", __func__);
        return NULL;
    }

    /* get the sum of pattern */
    size_t literal_pattern_num = 0;
    size_t regex_pattern_num = 0;

    for (size_t i = 0; i < n_expr_array; i++) {
        if (expr_array[i].n_patterns > MAX_EXPR_PATTERN_NUM) {
            log_error(logger, MODULE_ADAPTER_HS, 
                      "the number of patterns in one expression should less than %d", MAX_EXPR_PATTERN_NUM);
            return NULL;
        }

        for (size_t j = 0; j < expr_array[i].n_patterns; j++) {
            if (expr_array[i].patterns[j].type == PATTERN_TYPE_STR) {
                literal_pattern_num++;
            } else if (expr_array[i].patterns[j].type == PATTERN_TYPE_REG) {
                regex_pattern_num++;
            } else {
                log_error(logger, MODULE_ADAPTER_HS, "unknown pattern type: %d", expr_array[i].patterns[j].type);
                return NULL;
            }
        }
    }

    struct adpt_hs_compile_data *literal_cd = NULL;
    struct adpt_hs_compile_data *regex_cd = NULL;
    if (literal_pattern_num > 0) {
        literal_cd = adpt_hs_compile_data_new(literal_pattern_num);
    }
    
    if (regex_pattern_num > 0) {
        regex_cd = adpt_hs_compile_data_new(regex_pattern_num);
    }
    
    uint32_t literal_index = 0;
    uint32_t regex_index = 0;
    uint32_t pattern_id = 0;

    /* alloc exprs for bool matcher*/
    struct bool_expr *exprs = ALLOC(struct bool_expr, n_expr_array);

    /* populate adpt_hs_compile_data and bool_expr */
    for (size_t i = 0; i < n_expr_array; i++) {
        for (size_t j = 0; j < expr_array[i].n_patterns; j++) {
            size_t pat_len = 0;

            if (expr_array[i].patterns[j].type == PATTERN_TYPE_STR) {
                literal_cd->ids[literal_index] = pattern_id;
                literal_cd->flags[literal_index] = HS_FLAG_CASELESS;
                
                pat_len = expr_array[i].patterns[j].pat_len;
                literal_cd->pattern_lens[literal_index] = pat_len;
                literal_cd->patterns[literal_index] = ALLOC(char, pat_len);
                memcpy(literal_cd->patterns[literal_index], 
                       expr_array[i].patterns[j].pat, 
                       expr_array[i].patterns[j].pat_len);
                literal_index++; 
            } else {
                regex_cd->ids[regex_index] = pattern_id;
                regex_cd->flags[regex_index] = HS_FLAG_CASELESS;

                pat_len = expr_array[i].patterns[j].pat_len;
                regex_cd->pattern_lens[regex_index] = pat_len;
                regex_cd->patterns[regex_index] = ALLOC(char, pat_len);
                memcpy(regex_cd->patterns[regex_index], 
                       expr_array[i].patterns[j].pat, 
                       expr_array[i].patterns[j].pat_len);
                regex_index++;
            }
            exprs[i].items[j].item_id = pattern_id;
            pattern_id++;
        }
        exprs[i].expr_id = expr_array[i].expr_id;
        exprs[i].item_num = expr_array[i].n_patterns;
    }

    if (literal_cd != NULL) {
        literal_cd->n_patterns = literal_index;
    }
    
    if (regex_cd != NULL) {
        regex_cd->n_patterns = regex_index;
    }

    int ret = -1;
    int max_patterns_type = 0;
    size_t mem_size = 0;
    struct adapter_hs *hs_instance = ALLOC(struct adapter_hs, 1);

    hs_instance->nr_worker_threads = nr_worker_threads;
    hs_instance->n_patterns = pattern_id;
    hs_instance->n_expr = n_expr_array;
    hs_instance->hs_rt = ALLOC(struct adapter_hs_runtime, 1);

    /* create bool matcher */
    hs_instance->hs_rt->bm = bool_matcher_new(exprs, n_expr_array, &mem_size);
    if (hs_instance->hs_rt->bm != NULL) {
        log_info(logger, MODULE_ADAPTER_HS, 
                 "Adapter_hs module: build bool matcher of %zu expressions with %zu bytes memory", 
                 n_expr_array, mem_size);
    } else {
        log_error(logger, MODULE_ADAPTER_HS, "Adapter_hs module: build bool matcher failed");
        goto error;
    }
    FREE(exprs);

    /* build hs database */
    ret = adpt_hs_build_database(hs_instance->hs_rt, literal_cd, regex_cd, scan_mode, logger);
    if (ret < 0) {
        goto error;
    }

    if (literal_cd != NULL) {
        adpt_hs_compile_data_free(literal_cd, literal_index);
    }

    if (regex_cd != NULL) {
        adpt_hs_compile_data_free(regex_cd, regex_index);
    }

    /* which pattern type has more patterns, use it as hs_alloc_scratch's input parameter */
    if (literal_pattern_num > regex_pattern_num) {
        max_patterns_type = PATTERN_TYPE_STR;
    } else {
        max_patterns_type = PATTERN_TYPE_REG;
    }

    ret = adpt_hs_alloc_scratch(hs_instance->hs_rt, nr_worker_threads, max_patterns_type, logger);
    if (ret < 0) {
        goto error;
    }

    return hs_instance;
error:
    adapter_hs_destroy(hs_instance);

    return NULL;
}

void adapter_hs_destroy(struct adapter_hs *hs_instance)
{
    if (NULL == hs_instance) {
        return;
    }

    if (hs_instance->hs_rt != NULL) {
        if (hs_instance->hs_rt->literal_db != NULL) {
            hs_free_database(hs_instance->hs_rt->literal_db);
        }

        if (hs_instance->hs_rt->regex_db != NULL) {
            hs_free_database(hs_instance->hs_rt->regex_db);
        }

        if (hs_instance->hs_rt->scratchs != NULL) {
            for (size_t i = 0; i < hs_instance->nr_worker_threads; i++) {
                if (hs_instance->hs_rt->scratchs[i] != NULL) {
                    hs_free_scratch(hs_instance->hs_rt->scratchs[i]);
                }
            }
        }
        FREE(hs_instance->hs_rt->scratchs);

        if (hs_instance->hs_rt->bm != NULL) {
            bool_matcher_free(hs_instance->hs_rt->bm);
        }

        FREE(hs_instance->hs_rt);
    }

    FREE(hs_instance);
}

static inline int compare_pattern_id(const void* a, const void* b)
{
	long long ret= *(unsigned long long *)a - *(unsigned long long *)b;

    if (0 == ret) {
		return 0;
	} else if (ret < 0) {
		return -1;
	} else {
		return 1;
	}
}

UT_icd ut_pattern_id_icd = {sizeof(unsigned long long), NULL, NULL, NULL};

/**
 * @param id: pattern id
*/
int matched_event_cb(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx) {
    // put id in set
    UT_array *pattern_id_set = (UT_array *)ctx;
    unsigned long long pattern_id = (unsigned long long)id;
    if (utarray_find(pattern_id_set, &pattern_id, compare_pattern_id)) {
        return -1;
    }
    utarray_push_back(pattern_id_set, &pattern_id);
    utarray_sort(pattern_id_set, compare_pattern_id);

    return 0;
}

int adapter_hs_scan(struct adapter_hs *hs_instance, int thread_id, const char *data, size_t data_len, 
                    int results[], size_t *n_results)
{
    if (NULL == hs_instance || NULL == data || (0 == data_len) || NULL == results || NULL == n_results) {
        return -1;
    }

    struct adapter_hs_runtime *hs_rt = hs_instance->hs_rt;
    hs_scratch_t *scratch = hs_rt->scratchs[thread_id];
    UT_array *pattern_id_set;
    hs_error_t err;

    utarray_new(pattern_id_set, &ut_pattern_id_icd);
	utarray_reserve(pattern_id_set, hs_instance->n_patterns);

    int err_count = 0;
    if (hs_rt->literal_db != NULL) {
        err = hs_scan(hs_rt->literal_db, data, data_len, 0, scratch, matched_event_cb, pattern_id_set);
        if (err != HS_SUCCESS) {
            //log_error()
            err_count++;
        }
    }
    
    if (hs_rt->regex_db != NULL) {
        err = hs_scan(hs_rt->regex_db, data, data_len, 0, scratch, matched_event_cb, pattern_id_set);
        if (err != HS_SUCCESS) {
            //log_error()
            err_count++;
        }
    }
    
    if (2 == err_count) {
        return -1;
    }

    size_t pattern_set_size = utarray_len(pattern_id_set);
    unsigned long long items[pattern_set_size];
    memset(items, 0, sizeof(unsigned long long) * pattern_set_size);
    for (size_t i = 0; i < pattern_set_size; i++) {
        items[i] = *(unsigned long long *)utarray_eltptr(pattern_id_set, i);
    }

    size_t matched_index = 0;
    struct bool_expr_match *bool_matcher_results = ALLOC(struct bool_expr_match, hs_instance->n_expr);
    size_t bool_matcher_ret = bool_matcher_match(hs_rt->bm, items, pattern_set_size, bool_matcher_results, hs_instance->n_expr);
    for (matched_index = 0; matched_index < bool_matcher_ret; matched_index++) {
        results[matched_index] = bool_matcher_results[matched_index].expr_id;
    }
    *n_results = bool_matcher_ret;

    FREE(bool_matcher_results);
    utarray_free(pattern_id_set);

    return 0;
}

struct adapter_hs_stream *adapter_hs_stream_open(struct adapter_hs *hs_instance, int thread_id)
{
    struct adapter_hs_stream *hs_stream = ALLOC(struct adapter_hs_stream, 1);
    hs_error_t err;

    hs_stream->thread_id = thread_id;
    hs_stream->n_expr = hs_instance->n_expr;
    hs_stream->n_patterns = hs_instance->n_patterns;
    hs_stream->hs_rt = hs_instance->hs_rt;
    utarray_new(hs_stream->pattern_id_set, &ut_pattern_id_icd);
    utarray_reserve(hs_stream->pattern_id_set, hs_stream->n_patterns);

    if (hs_instance->hs_rt->literal_db != NULL) {
        err = hs_open_stream(hs_instance->hs_rt->literal_db, 0, &hs_stream->literal_stream);
        if (err != HS_SUCCESS) {
            // log_error
            return NULL;
        }
    }

    if (hs_instance->hs_rt->regex_db != NULL) {
        err = hs_open_stream(hs_instance->hs_rt->regex_db, 0, &hs_stream->regex_stream);
        if (err != HS_SUCCESS) {
            // log_error
            return NULL;
        }
    }

    return hs_stream;
}

int adapter_hs_scan_stream(struct adapter_hs_stream *hs_stream, const char *data, size_t data_len,
                           int results[], size_t *n_results)
{
    hs_error_t err;

    int thread_id = hs_stream->thread_id;
    if (hs_stream->literal_stream != NULL) {
        err = hs_scan_stream(hs_stream->literal_stream, data, data_len, 0, hs_stream->hs_rt->scratchs[thread_id],
                             matched_event_cb, hs_stream->pattern_id_set);
        if (err != HS_SUCCESS) {
            //log_error()
            return -1;
        }
    }
    
    if (hs_stream->regex_stream != NULL) {
        err = hs_scan_stream(hs_stream->regex_stream, data, data_len, 0, hs_stream->hs_rt->scratchs[thread_id],
                             matched_event_cb, hs_stream->pattern_id_set);
        if (err != HS_SUCCESS) {
            //log_error()
            return -1;
        }
    }

    size_t pattern_set_size = utarray_len(hs_stream->pattern_id_set);
    unsigned long long items[pattern_set_size];
    memset(items, 0, sizeof(unsigned long long) * pattern_set_size);
    for (size_t i = 0; i < pattern_set_size; i++) {
        items[i] = *(unsigned long long *)utarray_eltptr(hs_stream->pattern_id_set, i);
    }

    size_t matched_index = 0;
    struct bool_expr_match *bool_matcher_results = ALLOC(struct bool_expr_match, hs_stream->n_expr);
    size_t bool_matcher_ret = bool_matcher_match(hs_stream->hs_rt->bm, items, pattern_set_size, bool_matcher_results, hs_stream->n_expr);
    for (matched_index = 0; matched_index < bool_matcher_ret; matched_index++) {
        results[matched_index] = bool_matcher_results[matched_index].expr_id;
    }
    *n_results = bool_matcher_ret;

    FREE(bool_matcher_results);

    return 0;
}

void adapter_hs_stream_close(struct adapter_hs_stream *hs_stream)
{
    int thread_id = hs_stream->thread_id;

    hs_close_stream(hs_stream->literal_stream, hs_stream->hs_rt->scratchs[thread_id], NULL, NULL);
    hs_close_stream(hs_stream->regex_stream, hs_stream->hs_rt->scratchs[thread_id], NULL, NULL);
    utarray_free(hs_stream->pattern_id_set);

    /* hs_stream->hs_rt point to hs_instance->hs_rt which will call free */
    hs_stream->hs_rt = NULL;
    FREE(hs_stream);
}