/*
**********************************************************************************************
*	File: adapter_hs.c
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
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
#include "uthash/uthash.h"
#include "maat_utils.h"
#include "../../bool_matcher/bool_matcher.h"

pid_t hs_gettid()
{
	return syscall(SYS_gettid);
}

static const char *hs_module_name_str(const char *name)
{
	static __thread char module[64];
	snprintf(module, sizeof(module), "%s(%d)", name, hs_gettid());
    
	return module;
}

#define MODULE_ADAPTER_HS	 hs_module_name_str("maat.adapter_hs")

struct hs_compile_data {
    enum expr_pattern_type pat_type;
    unsigned int *ids;
    unsigned int *flags;
    char **patterns;
    size_t *pattern_lens;
    unsigned int n_patterns;
};

struct hs_lit_stream {
    int thread_id;
    hs_stream_t *hs_stream;
    struct hs_lit_engine *ref_hs_rt;
    struct matched_pattern *matched_pat;
    struct log_handle *logger;
};

struct hs_regex_stream {
    int thread_id;
    hs_stream_t *hs_stream;
    struct hs_regex_engine *ref_hs_rt;
    struct matched_pattern *matched_pat;
    struct log_handle *logger;
};

/* hs literal runtime */
struct hs_lit_engine {
    size_t n_thread;
    hs_database_t *hs_db;
    hs_scratch_t **hs_scratches;
    struct hs_lit_stream **streams;
    struct pattern_attribute *ref_pat_attr;
    struct log_handle *logger;
};

/* hs regex runtime */
struct hs_regex_engine {
    size_t n_thread;
    hs_database_t *hs_db;
    hs_scratch_t **hs_scratches;
    struct hs_regex_stream **streams;
    struct pattern_attribute *ref_pat_attr;
    struct log_handle *logger;
};

static int hs_alloc_scratches(hs_database_t *db, hs_scratch_t **scratches,
                              size_t n_worker_thread, struct log_handle *logger)
{
    size_t scratch_size = 0;

    if (hs_alloc_scratch(db, &scratches[0]) != HS_SUCCESS) {
        log_fatal(logger, MODULE_ADAPTER_HS,
                  "[%s:%d] Unable to allocate scratch space. Exiting.",
                  __FUNCTION__, __LINE__);
        return -1;
    }

    for (size_t i = 1; i < n_worker_thread; i++) {
        hs_error_t err = hs_clone_scratch(scratches[0], &scratches[i]);
        if (err != HS_SUCCESS) {
            log_fatal(logger, MODULE_ADAPTER_HS,
                      "[%s:%d] Unable to clone scratch",
                      __FUNCTION__, __LINE__);
            return -1;
        }

        err = hs_scratch_size(scratches[i], &scratch_size);
        if (err != HS_SUCCESS) {
            log_fatal(logger, MODULE_ADAPTER_HS,
                      "[%s:%d] Unable to query scratch size",
                      __FUNCTION__, __LINE__);
            return -1;
        }
    }

    return 0;
}

static int verify_regex_expression(const char *regex_str, struct log_handle *logger)
{
    hs_expr_info_t *info = NULL;
    hs_compile_error_t *error = NULL;

    hs_error_t err = hs_expression_info(regex_str, HS_FLAG_CASELESS, &info, &error);
    if (err != HS_SUCCESS) {
        // Expression will fail compilation and report error elsewhere.
        if (logger != NULL) {
            log_fatal(logger, MODULE_ADAPTER_HS,
                      "[%s:%d] illegal regex expression: \"%s\": %s",
                      __FUNCTION__, __LINE__, regex_str, error->message);
        }
        
        FREE(info);
        hs_free_compile_error(error);
        return 0;
    }

    if (info != NULL) {
        FREE(info);
    }

    return 1;
}

int hs_verify_regex_expression(const char *regex_expr, struct log_handle *logger)
{
    if (NULL == regex_expr) {
        return 0;
    }

    return verify_regex_expression(regex_expr, logger);
}

void hs_lit_engine_free(void *hs_lit_engine)
{
    if (NULL == hs_lit_engine) {
        return;
    }

    struct hs_lit_engine *hs_lit_inst = (struct hs_lit_engine *)hs_lit_engine;
    size_t i = 0;

    if (hs_lit_inst->hs_db != NULL) {
        hs_free_database(hs_lit_inst->hs_db);
        hs_lit_inst->hs_db = NULL;
    }

    if (hs_lit_inst->hs_scratches != NULL) {
        for (i = 0; i < hs_lit_inst->n_thread; i++) {
            if (hs_lit_inst->hs_scratches[i] != NULL) {
                hs_free_scratch(hs_lit_inst->hs_scratches[i]);
                hs_lit_inst->hs_scratches[i] = NULL;
            }
        }
        FREE(hs_lit_inst->hs_scratches);
    }

    if (hs_lit_inst->streams != NULL) {
        for (i = 0; i < hs_lit_inst->n_thread; i++) {
            if (hs_lit_inst->streams[i] != NULL) {
                hs_lit_stream_close(hs_lit_inst->streams[i]);
                hs_lit_inst->streams[i] = NULL;
            }
        }
        FREE(hs_lit_inst->streams);
    }

    FREE(hs_lit_inst);
}

void *hs_lit_engine_new(struct expr_rule *rules, size_t n_rule,
                         struct pattern_attribute *pat_attr,
                         void *hs_lit_db, size_t n_thread,
                         struct log_handle *logger)
{
    struct hs_lit_engine *hs_lit_inst = ALLOC(struct hs_lit_engine, 1);
    
    hs_lit_inst->n_thread = n_thread;
    hs_lit_inst->hs_db = (hs_database_t *)hs_lit_db;
    hs_lit_inst->logger = logger;
    hs_lit_inst->ref_pat_attr = pat_attr;
    hs_lit_inst->hs_scratches = ALLOC(hs_scratch_t *, n_thread);
    int ret = hs_alloc_scratches((hs_database_t *)hs_lit_db, hs_lit_inst->hs_scratches,
                                 n_thread, logger);
    if (ret < 0) {
        log_fatal(logger, MODULE_ADAPTER_HS,
                  "[%s:%d]alloc scratches for hs lit runtime failed.",
                  __FUNCTION__, __LINE__);
        FREE(hs_lit_inst->hs_scratches);
        FREE(hs_lit_inst);
        return NULL;
    }

    hs_lit_inst->streams = ALLOC(struct hs_lit_stream *, n_thread);
    for (size_t i = 0; i < n_thread; i++) {
        hs_lit_inst->streams[i] = (struct hs_lit_stream *)hs_lit_stream_open(hs_lit_inst, i);
    }

    return hs_lit_inst;
}

/**
 * @param id: pattern id
*/
static int matched_event_cb(unsigned int id, unsigned long long from,
                            unsigned long long to, unsigned int flags, 
                            void *ctx)
{
    // put id in set
    unsigned long long pattern_id = id;
    struct matched_pattern *matched_pat = (struct matched_pattern *)ctx;

    if (utarray_len(matched_pat->pattern_ids) >= MAX_HIT_PATTERN_NUM) {
        return 0;
    }
    
    int ret = 0;
    struct pattern_attribute pat_attr = matched_pat->ref_pat_attr[id];
    switch (pat_attr.match_mode) {
        case EXPR_MATCH_MODE_EXACTLY:
            if (0 == from && matched_pat->scan_data_len == to) {
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
        case EXPR_MATCH_MODE_PREFIX:
            if (0 == from) {
                ret = 1;
            }
            break;
        case EXPR_MATCH_MODE_SUFFIX:
            if (to == matched_pat->scan_data_len) {
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

UT_icd ut_hs_pattern_id_icd = {sizeof(unsigned long long), NULL, NULL, NULL};
void *hs_lit_stream_open(void *hs_lit_engine, int thread_id)
{
    if (NULL == hs_lit_engine || thread_id < 0) {
        return NULL;
    }
    
    struct hs_lit_engine *hs_lit_inst = (struct hs_lit_engine *)hs_lit_engine;
    struct hs_lit_stream *lit_stream = ALLOC(struct hs_lit_stream, 1);
    hs_error_t err;

    lit_stream->logger = hs_lit_inst->logger;
    lit_stream->thread_id = thread_id;
    lit_stream->ref_hs_rt = hs_lit_inst;
    lit_stream->matched_pat = ALLOC(struct matched_pattern, 1);
    lit_stream->matched_pat->ref_pat_attr = hs_lit_inst->ref_pat_attr;
    utarray_new(lit_stream->matched_pat->pattern_ids, &ut_hs_pattern_id_icd);
    utarray_reserve(lit_stream->matched_pat->pattern_ids, MAX_HIT_PATTERN_NUM);

    if (hs_lit_inst->hs_db != NULL) {
        err = hs_open_stream(hs_lit_inst->hs_db, 0, &lit_stream->hs_stream);
        if (err != HS_SUCCESS) {
            log_fatal(hs_lit_inst->logger, MODULE_ADAPTER_HS,
                      "hs_open_stream failed, hs err:%d", err);
            goto error;
        }
    }

    return lit_stream;
error:
    if (lit_stream->hs_stream != NULL) {
        hs_close_stream(lit_stream->hs_stream, NULL, NULL, NULL);
        lit_stream->hs_stream = NULL;
    }

    FREE(lit_stream);
    return NULL;
}

void hs_lit_stream_close(void *hs_lit_stream)
{
    if (NULL == hs_lit_stream) {
        return;
    }

    struct hs_lit_stream *stream = (struct hs_lit_stream *)hs_lit_stream;
    if (stream->ref_hs_rt != NULL) {
        if (stream->hs_stream != NULL) {
            hs_close_stream(stream->hs_stream, NULL, NULL, NULL);
            stream->hs_stream = NULL;
        }
    }

    /* stream->hs_rt point to hs_instance->hs_rt which will call free 
        same as hs_attr */
    stream->ref_hs_rt = NULL;
    stream->matched_pat->ref_pat_attr = NULL;

    if (stream->matched_pat->pattern_ids != NULL) {
        utarray_free(stream->matched_pat->pattern_ids);
        stream->matched_pat->pattern_ids = NULL;
    }

    FREE(stream->matched_pat);
    FREE(stream);
}

static void hs_lit_stream_reset(struct hs_lit_stream *hs_lit_stream)
{
    if (NULL == hs_lit_stream) {
        return;
    }

    hs_scratch_t **scratches = hs_lit_stream->ref_hs_rt->hs_scratches;
    if (hs_lit_stream->hs_stream != NULL) {
        hs_reset_stream(hs_lit_stream->hs_stream, 0,
                        scratches[hs_lit_stream->thread_id],
                        matched_event_cb, hs_lit_stream->matched_pat);
    }
}

static void hs_regex_stream_reset(struct hs_regex_stream *hs_regex_stream)
{
    if (NULL == hs_regex_stream) {
        return;
    }

    hs_scratch_t **scratches = hs_regex_stream->ref_hs_rt->hs_scratches;
    if (hs_regex_stream->hs_stream != NULL) {
        hs_reset_stream(hs_regex_stream->hs_stream, 0,
                        scratches[hs_regex_stream->thread_id],
                        matched_event_cb, hs_regex_stream->matched_pat);
    }
}

static int gather_hit_pattern_id(struct matched_pattern *matched_pat,
                                 unsigned long long *pattern_id_array,
                                 size_t array_size, size_t *n_pattern_id)
{
    size_t pattern_id_cnt = utarray_len(matched_pat->pattern_ids);
    if (0 == pattern_id_cnt) {
        *n_pattern_id = 0;
        return 0;
    }

    size_t array_index = 0;
    for (size_t i = 0; i < pattern_id_cnt && array_index < array_size; i++) {
        pattern_id_array[array_index++] = *(unsigned long long *)utarray_eltptr(matched_pat->pattern_ids, i);
    }

    *n_pattern_id = array_index;
    utarray_clear(matched_pat->pattern_ids);

    return 0;
}

int hs_lit_stream_scan(void *hs_lit_stream, const char *data, size_t data_len,
                       unsigned long long *pattern_id_array, size_t array_size,
                       size_t *n_pattern_id)
{
    hs_error_t err;

    if (NULL == hs_lit_stream || NULL == data || 0 == data_len ||
        NULL == pattern_id_array || 0 == array_size || NULL == n_pattern_id) {
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
    struct hs_lit_stream *lit_stream = (struct hs_lit_stream *)hs_lit_stream;
    int thread_id = lit_stream->thread_id;
    hs_scratch_t **scratches = lit_stream->ref_hs_rt->hs_scratches;
    lit_stream->matched_pat->scan_data_len = data_len;

    if (lit_stream->hs_stream != NULL) {
        if (scratches != NULL) {
            err = hs_scan_stream(lit_stream->hs_stream, data, data_len,
                                 0, scratches[thread_id], matched_event_cb,
                                 lit_stream->matched_pat);
            if (err != HS_SUCCESS) {
                return -1;
            }
        } else {
            log_fatal(lit_stream->logger, MODULE_ADAPTER_HS,
                      "literal scratches is null, thread_id:%d", thread_id);
            return -1;
        }
    }

    return gather_hit_pattern_id(lit_stream->matched_pat, pattern_id_array,
                                 array_size, n_pattern_id);
}

int hs_lit_engine_scan(void *hs_lit_engine, int thread_id,
                        const char *data, size_t data_len,
                        unsigned long long *pattern_id_array,
                        size_t array_size, size_t *n_pattern_id)
{
    if (NULL == hs_lit_engine || NULL == data || 0 == data_len) {
        return -1;
    }

    struct hs_lit_engine *hs_lit_inst = (struct hs_lit_engine *)hs_lit_engine;
    struct hs_lit_stream *hs_lit_stream = hs_lit_inst->streams[thread_id];
    assert(hs_lit_stream != NULL);

    hs_lit_stream_reset(hs_lit_stream);
    return hs_lit_stream_scan(hs_lit_stream, data, data_len, pattern_id_array,
                              array_size, n_pattern_id);
}

void hs_regex_engine_free(void *hs_regex_engine)
{
    if (NULL == hs_regex_engine) {
        return;
    }

    struct hs_regex_engine *hs_regex_inst = (struct hs_regex_engine *)hs_regex_engine;
    size_t i = 0;

    if (hs_regex_inst->hs_db != NULL) {
        hs_free_database(hs_regex_inst->hs_db);
        hs_regex_inst->hs_db = NULL;
    }

    if (hs_regex_inst->hs_scratches != NULL) {
        for (i = 0; i < hs_regex_inst->n_thread; i++) {
            if (hs_regex_inst->hs_scratches[i] != NULL) {
                hs_free_scratch(hs_regex_inst->hs_scratches[i]);
                hs_regex_inst->hs_scratches[i] = NULL;
            }
        }
        FREE(hs_regex_inst->hs_scratches);
    }

    if (hs_regex_inst->streams != NULL) {
        for (i = 0; i < hs_regex_inst->n_thread; i++) {
            if (hs_regex_inst->streams[i] != NULL) {
                hs_regex_stream_close(hs_regex_inst->streams[i]);
                hs_regex_inst->streams[i] = NULL;
            }
        }
        FREE(hs_regex_inst->streams);
    }

    FREE(hs_regex_inst);
}

void *hs_regex_engine_new(struct expr_rule *rules, size_t n_rule,
                           struct pattern_attribute *pat_attr,
                           void *hs_regex_db, size_t n_thread,
                           struct log_handle *logger)
{
    struct hs_regex_engine *hs_regex_inst = ALLOC(struct hs_regex_engine, 1);
    
    hs_regex_inst->n_thread = n_thread;
    hs_regex_inst->hs_db = (hs_database_t *)hs_regex_db;
    hs_regex_inst->ref_pat_attr = pat_attr;
    hs_regex_inst->logger = logger;
    hs_regex_inst->hs_scratches = ALLOC(hs_scratch_t *, n_thread);

    int ret = hs_alloc_scratches((hs_database_t *)hs_regex_db,
                                 hs_regex_inst->hs_scratches,
                                 n_thread, logger);
    if (ret < 0) {
        log_fatal(logger, MODULE_ADAPTER_HS,
                  "[%s:%d]alloc scratches for hs regex runtime failed.",
                  __FUNCTION__, __LINE__);
        FREE(hs_regex_inst->hs_scratches);
        FREE(hs_regex_inst);
        return NULL;
    }

    hs_regex_inst->streams = ALLOC(struct hs_regex_stream *, n_thread);
    for (size_t i = 0; i < n_thread; i++) {
        hs_regex_inst->streams[i] = (struct hs_regex_stream *)hs_regex_stream_open(hs_regex_inst, i);
    }

    return hs_regex_inst;
}

int hs_regex_engine_scan(void *hs_regex_engine, int thread_id,
                          const char *data, size_t data_len,
                          unsigned long long *pattern_id_array,
                          size_t array_size, size_t *n_pattern_id)
{
    if (NULL == hs_regex_engine || NULL == data || 0 == data_len) {
        return -1;
    }

    struct hs_regex_engine *hs_regex_inst = (struct hs_regex_engine *)hs_regex_engine;
    struct hs_regex_stream *hs_regex_stream = hs_regex_inst->streams[thread_id];
    assert(hs_regex_stream != NULL);

    hs_regex_stream_reset(hs_regex_stream);
    return hs_regex_stream_scan(hs_regex_stream, data, data_len, pattern_id_array,
                                array_size, n_pattern_id);
}

void hs_regex_stream_close(void *hs_regex_stream)
{
    if (NULL == hs_regex_stream) {
        return;
    }

    struct hs_regex_stream *stream = (struct hs_regex_stream *)hs_regex_stream;
    if (stream->ref_hs_rt != NULL) {
        if (stream->hs_stream != NULL) {
            hs_close_stream(stream->hs_stream, NULL, NULL, NULL);
            stream->hs_stream = NULL;
        }
    }

    /* stream->hs_rt point to hs_instance->hs_rt which will call free 
        same as hs_attr */
    stream->ref_hs_rt = NULL;
    stream->matched_pat->ref_pat_attr = NULL;

    if (stream->matched_pat->pattern_ids != NULL) {
        utarray_free(stream->matched_pat->pattern_ids);
        stream->matched_pat->pattern_ids = NULL;
    }

    FREE(stream->matched_pat);
    FREE(stream);
}

void *hs_regex_stream_open(void *hs_regex_engine, int thread_id)
{
    if (NULL == hs_regex_engine || thread_id < 0) {
        return NULL;
    }
    
    struct hs_regex_engine *hs_regex_inst = (struct hs_regex_engine *)hs_regex_engine;
    struct hs_regex_stream *regex_stream = ALLOC(struct hs_regex_stream, 1);
    hs_error_t err;

    regex_stream->logger = hs_regex_inst->logger;
    regex_stream->thread_id = thread_id;
    regex_stream->ref_hs_rt = hs_regex_inst;
    regex_stream->matched_pat = ALLOC(struct matched_pattern, 1);
    regex_stream->matched_pat->ref_pat_attr = hs_regex_inst->ref_pat_attr;
    utarray_new(regex_stream->matched_pat->pattern_ids, &ut_hs_pattern_id_icd);
    utarray_reserve(regex_stream->matched_pat->pattern_ids, MAX_HIT_PATTERN_NUM);

    if (hs_regex_inst->hs_db != NULL) {
        err = hs_open_stream(hs_regex_inst->hs_db, 0, &regex_stream->hs_stream);
        if (err != HS_SUCCESS) {
            log_fatal(hs_regex_inst->logger, MODULE_ADAPTER_HS,
                      "hs_open_stream failed, hs err:%d", err);
            goto error;
        }
    }

    return regex_stream;
error:
    hs_regex_stream_close(regex_stream); 
    return NULL;
}

int hs_regex_stream_scan(void *hs_regex_stream, const char *data, size_t data_len,
                         unsigned long long *pattern_id_array, size_t array_size,
                         size_t *n_pattern_id)
{
    hs_error_t err;

    if (NULL == hs_regex_stream || NULL == data || 0 == data_len) {
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
    struct hs_regex_stream *regex_stream = (struct hs_regex_stream *)hs_regex_stream;
    int thread_id = regex_stream->thread_id;
    hs_scratch_t **scratches = regex_stream->ref_hs_rt->hs_scratches;
    regex_stream->matched_pat->scan_data_len = data_len;

    if (regex_stream->hs_stream != NULL) {
        if (scratches != NULL) {
            err = hs_scan_stream(regex_stream->hs_stream, data, data_len,
                                 0, scratches[thread_id], matched_event_cb,
                                 regex_stream->matched_pat);
            if (err != HS_SUCCESS) {
                return -1;
            }
        } else {
            log_fatal(regex_stream->logger, MODULE_ADAPTER_HS,
                      "literal scratches is null, thread_id:%d", thread_id);
            return -1;
        }
    }

    return gather_hit_pattern_id(regex_stream->matched_pat, pattern_id_array,
                                 array_size, n_pattern_id);
}

void *hs_compile_data_new(enum expr_pattern_type pat_type, size_t n_patterns)
{
    struct hs_compile_data *hs_cd = ALLOC(struct hs_compile_data, 1);

    hs_cd->pat_type = pat_type;
    hs_cd->patterns = ALLOC(char *, n_patterns);
    hs_cd->pattern_lens = ALLOC(size_t, n_patterns);
    hs_cd->n_patterns = n_patterns;
    hs_cd->ids = ALLOC(unsigned int, n_patterns);
    hs_cd->flags = ALLOC(unsigned int, n_patterns);

    return hs_cd;
}

void hs_compile_data_free(void *compile_data)
{
    if (NULL == compile_data) {
        return;
    }

    struct hs_compile_data *hs_cd = (struct hs_compile_data *)compile_data;
    if (hs_cd->patterns != NULL) {
        for (size_t i = 0; i < hs_cd->n_patterns; i++) {
            FREE(hs_cd->patterns[i]);
        }

        FREE(hs_cd->patterns); 
    }

    if (hs_cd->pattern_lens != NULL) {
        FREE(hs_cd->pattern_lens);
    }

    if (hs_cd->ids != NULL) {
        FREE(hs_cd->ids);
    }

    if (hs_cd->flags != NULL) {
        FREE(hs_cd->flags);
    }

    FREE(hs_cd);
}

void hs_populate_compile_data(void *compile_data, size_t index, int pattern_id,
                              char *pat, size_t pat_len, int case_sensitive)
{
    struct hs_compile_data *hs_cd = (struct hs_compile_data *)compile_data;

    hs_cd->ids[index] = pattern_id;

    /* set flags */
    if (hs_cd->pat_type == EXPR_PATTERN_TYPE_STR) {
        hs_cd->flags[index] |= HS_FLAG_SOM_LEFTMOST;
    }
    
    if (case_sensitive == EXPR_CASE_INSENSITIVE) {
        hs_cd->flags[index] |= HS_FLAG_CASELESS;
    }

    hs_cd->pattern_lens[index] = pat_len;
    hs_cd->patterns[index] = ALLOC(char, pat_len + 1);
    memcpy(hs_cd->patterns[index], pat, pat_len);
}

int hs_build_lit_db(void **hs_lit_db, void *compile_data, struct log_handle *logger)
{
    if (NULL == hs_lit_db || NULL == compile_data) {
        return -1;
    }

    struct hs_compile_data *lit_cd = (struct hs_compile_data *)compile_data;
    hs_compile_error_t *compile_err = NULL;

    if (lit_cd != NULL) {
        hs_error_t err = hs_compile_lit_multi((const char *const *)lit_cd->patterns,
                                    lit_cd->flags,lit_cd->ids, lit_cd->pattern_lens,
                                    lit_cd->n_patterns, 
                                    HS_MODE_STREAM | HS_MODE_SOM_HORIZON_SMALL,
                                    NULL, (hs_database_t **)hs_lit_db, &compile_err);
        if (err != HS_SUCCESS) {
            if (compile_err) {
                log_fatal(logger, MODULE_ADAPTER_HS, "[%s:%d] compile error: %s", 
                          __FUNCTION__, __LINE__, compile_err->message);
            }

            hs_free_compile_error(compile_err);
            return -1;
        }
    }
    
    return 0;
}

int hs_build_regex_db(void **hs_regex_db, void *compile_data, struct log_handle *logger)
{
    if (NULL == hs_regex_db || NULL == compile_data) {
        return -1;
    }

    struct hs_compile_data *regex_cd = (struct hs_compile_data *)compile_data;
    hs_compile_error_t *compile_err = NULL;

    hs_error_t err = hs_compile_multi((const char *const *)regex_cd->patterns,
                                      regex_cd->flags, regex_cd->ids, regex_cd->n_patterns,
                                      HS_MODE_STREAM, NULL, (hs_database_t **)hs_regex_db,
                                      &compile_err);
    if (err != HS_SUCCESS) {
        if (compile_err) {
            log_fatal(logger, MODULE_ADAPTER_HS, "[%s:%d] compile error: %s",
                      __FUNCTION__, __LINE__, compile_err->message);
        }
        hs_free_compile_error(compile_err);
        return -1;
    }
    
    return 0;
}