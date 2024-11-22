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
#include "uthash/uthash.h"
#include "maat_utils.h"
#include "../../bool_matcher/bool_matcher.h"

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

struct rs_compile_data {
    struct scan_pattern *patterns;
    size_t n_patterns;
};

struct rs_lit_stream {
    int thread_id;
    size_t offset;  /* current stream offset */
    rs_stream_t *rs_stream;
    struct rs_lit_engine *ref_rs_rt;
    struct matched_pattern *ref_matched_pat;
    struct log_handle *logger;
};

struct rs_regex_stream {
    int thread_id;
    size_t offset;  /* current stream offset */
    rs_stream_t *rs_stream;
    struct rs_regex_engine *ref_rs_rt;
    struct matched_pattern *ref_matched_pat;
    struct log_handle *logger;
};

/* adapter_rs literal runtime */
struct rs_lit_engine {
    size_t n_thread;
    rs_database_t *rs_db;
    struct bloom **blooms;
    struct rs_lit_stream **per_thread_scratch_streams; /* per thread */
    struct pattern_attribute *ref_pat_attr;
    struct log_handle *logger;
    struct matched_pattern **matched_pat;
};

/* adapter_rs regex runtime */
struct rs_regex_engine {
    size_t n_thread;
    rs_database_t *rs_db;
    struct bloom **blooms;
    struct rs_regex_stream **streams; /* per thread */
    struct pattern_attribute *ref_pat_attr;
    struct log_handle *logger;
    struct matched_pattern **matched_pat;
};

int rs_verify_regex_expression(const char *regex_expr, struct log_handle *logger)
{
    int ret = rs_verify_regex(regex_expr);
    if (ret == 0) {
        log_fatal(logger, MODULE_ADAPTER_RS,
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
int rs_build_lit_db(void **rs_lit_db, void *compile_data, struct log_handle *logger)
{
    if (NULL == rs_lit_db) {
        return -1;
    }

    struct rs_compile_data *lit_cd = (struct rs_compile_data *)compile_data; 
    if (lit_cd != NULL) {
        int ret = rs_compile_lit(lit_cd->patterns, lit_cd->n_patterns,
                                 (rs_database_t **)rs_lit_db);
        if (ret < 0) {
            log_fatal(logger, MODULE_ADAPTER_RS, "[%s:%d] compile error", 
                       __FUNCTION__, __LINE__);
            return -1;
        }
    }
    
    return 0;
}

int rs_build_regex_db(void **rs_regex_db, size_t n_thread, void *compile_data,
                      struct log_handle *logger)
{
    if (NULL == rs_regex_db) {
        return -1;
    }

    struct rs_compile_data *regex_cd = (struct rs_compile_data *)compile_data; 
    if (regex_cd != NULL) {
        size_t n_failed_pats = 0;
        int ret = rs_compile_regex(regex_cd->patterns, regex_cd->n_patterns,
                                   n_thread, (rs_database_t **)rs_regex_db,
                                   &n_failed_pats);
        if (ret < 0) {
            log_fatal(logger, MODULE_ADAPTER_RS, "[%s:%d] compile error", 
                       __FUNCTION__, __LINE__);
            return -1;
        }
    }
    
    return 0;
}

void *rs_compile_data_new(enum expr_pattern_type pat_type, size_t n_patterns)
{
    struct rs_compile_data *rs_cd = ALLOC(struct rs_compile_data, 1);
    rs_cd->patterns = ALLOC(struct scan_pattern, n_patterns);
    rs_cd->n_patterns = n_patterns;

    return rs_cd;
}

void rs_compile_data_free(void *compile_data)
{
    if (NULL == compile_data) {
        return;
    }

    struct rs_compile_data *rs_cd = (struct rs_compile_data *)compile_data;
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

void rs_populate_compile_data(void *compile_data, size_t index, int pattern_id,
                               char *pat, size_t pat_len, int case_sensitive)
{
    struct rs_compile_data *rs_cd = (struct rs_compile_data *)compile_data;

    rs_cd->patterns[index].id = pattern_id;
    rs_cd->patterns[index].case_sensitive = case_sensitive;
    rs_cd->patterns[index].pattern = ALLOC(char, pat_len + 1);
    memcpy(rs_cd->patterns[index].pattern, pat, pat_len);
    rs_cd->patterns[index].pattern_len = pat_len;
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
    
    size_t n_pat_id = *(matched_pat->n_pattern_id);
    if (n_pat_id < (MAX_HIT_PATTERN_NUM / 10)) {
        for (size_t i = 0; i < n_pat_id; i++) {
            if (matched_pat->pattern_ids[i] == pattern_id) {
                return 0;
            }
        }
    } else {
        if (bloom_check(matched_pat->ref_bloom, (char *)&pattern_id,
                        sizeof(unsigned long long)) == 1) {
            return 0;
        }
        bloom_add(matched_pat->ref_bloom, (char *)&pattern_id,
                  sizeof(unsigned long long));
    }

    if (n_pat_id >= MAX_HIT_PATTERN_NUM) {
        return 0;
    }
    
    int ret = 0;
    struct pattern_attribute pat_attr = matched_pat->ref_pat_attr[id];

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
        matched_pat->pattern_ids[n_pat_id] = pattern_id;
        *(matched_pat->n_pattern_id) = n_pat_id + 1;
    }

    return 0;
}

void rs_lit_engine_free(void *rs_lit_engine)
{
    if (NULL == rs_lit_engine) {
        return;
    }

    struct rs_lit_engine *rs_lit_inst = (struct rs_lit_engine *)rs_lit_engine;

    if (rs_lit_inst->rs_db != NULL) {
        rs_free_database(rs_lit_inst->rs_db);
        rs_lit_inst->rs_db = NULL;
    }

    if (rs_lit_inst->blooms != NULL) {
        for (size_t i = 0; i < rs_lit_inst->n_thread; i++) {
            if (rs_lit_inst->blooms[i] != NULL) {
                bloom_free(rs_lit_inst->blooms[i]);
                FREE(rs_lit_inst->blooms[i]);
            }
        }
        FREE(rs_lit_inst->blooms);
    }

    if (rs_lit_inst->per_thread_scratch_streams != NULL) {
        for (size_t i = 0; i < rs_lit_inst->n_thread; i++) {
            if (rs_lit_inst->per_thread_scratch_streams[i] != NULL) {
                rs_lit_stream_close(rs_lit_inst->per_thread_scratch_streams[i]);
                rs_lit_inst->per_thread_scratch_streams[i] = NULL;
            }
        }
        FREE(rs_lit_inst->per_thread_scratch_streams);
    }

    if (rs_lit_inst->matched_pat != NULL) {
        for (size_t i = 0; i < rs_lit_inst->n_thread; i++) {
            if (rs_lit_inst->matched_pat[i] != NULL) {
                FREE(rs_lit_inst->matched_pat[i]);
            }
        }
        FREE(rs_lit_inst->matched_pat);
    }

    FREE(rs_lit_inst);
}

void *rs_lit_engine_new(struct expr_rule *rules, size_t n_rule,
                         struct pattern_attribute *pat_attr,
                         void *rs_lit_db, size_t n_thread,
                         struct log_handle *logger)
{
    struct rs_lit_engine *rs_lit_inst = ALLOC(struct rs_lit_engine, 1);
    
    rs_lit_inst->n_thread = n_thread;
    rs_lit_inst->rs_db = (rs_database_t *)rs_lit_db;
    rs_lit_inst->ref_pat_attr = pat_attr;
    rs_lit_inst->logger = logger;

    rs_lit_inst->blooms = ALLOC(struct bloom *, n_thread);
    for (size_t i = 0; i < n_thread; i++) {
        rs_lit_inst->blooms[i] = ALLOC(struct bloom, 1);
        bloom_init2(rs_lit_inst->blooms[i], 1024, 0.001);
    }

    rs_lit_inst->matched_pat = ALLOC(struct matched_pattern *, n_thread);
    for (size_t i = 0; i < n_thread; i++) {
        rs_lit_inst->matched_pat[i] = ALLOC(struct matched_pattern, 1);
        rs_lit_inst->matched_pat[i]->ref_bloom = rs_lit_inst->blooms[i];
        rs_lit_inst->matched_pat[i]->ref_pat_attr = pat_attr;
    }

    rs_lit_inst->per_thread_scratch_streams = ALLOC(struct rs_lit_stream *, n_thread);
    for (size_t i = 0; i < n_thread; i++) {
        rs_lit_inst->per_thread_scratch_streams[i] = (struct rs_lit_stream *)rs_lit_stream_open(rs_lit_inst, i);
    }

    return rs_lit_inst;
}

int rs_lit_engine_scan(void *rs_lit_engine, int thread_id,
                        const char *data, size_t data_len,
                        unsigned long long *pattern_id_array,
                        size_t array_size, size_t *n_pattern_id)
{
    if (NULL == rs_lit_engine || NULL == data || (0 == data_len) || 
        NULL == pattern_id_array || 0 == array_size || NULL == n_pattern_id) {
        return -1;
    }

    struct rs_lit_engine *rs_lit_inst = (struct rs_lit_engine *)rs_lit_engine;
    struct rs_lit_stream *rs_lit_stream = rs_lit_inst->per_thread_scratch_streams[thread_id];
    assert(rs_lit_stream != NULL);

    rs_lit_stream->ref_matched_pat->pattern_ids = pattern_id_array;
    rs_lit_stream->ref_matched_pat->n_pattern_id = n_pattern_id;
    rs_lit_stream->ref_matched_pat->pattern_ids_size = array_size;

    if (rs_lit_inst->rs_db != NULL) {
        int ret = rs_scan(rs_lit_inst->rs_db, thread_id, data, data_len,
                      0, matched_event_cb, rs_lit_stream->ref_matched_pat);
        if (ret < 0) {
            return -1;
        }
    }

    bloom_reset(rs_lit_stream->ref_matched_pat->ref_bloom);

    return 0;
}

void *rs_lit_stream_open(void *rs_lit_engine, int thread_id)
{
    if (NULL == rs_lit_engine || thread_id < 0) {
        return NULL;
    }
    
    struct rs_lit_engine *rs_lit_inst = (struct rs_lit_engine *)rs_lit_engine;
    struct rs_lit_stream *lit_stream = ALLOC(struct rs_lit_stream, 1);

    lit_stream->logger = rs_lit_inst->logger;
    lit_stream->thread_id = thread_id;
    lit_stream->ref_rs_rt = rs_lit_inst;
    lit_stream->ref_matched_pat = rs_lit_inst->matched_pat[thread_id];

    if (rs_lit_inst->rs_db != NULL) {
        lit_stream->rs_stream = rs_open_stream(rs_lit_inst->rs_db, 0, 128);
        if (NULL == lit_stream->rs_stream) {
            log_fatal(rs_lit_inst->logger, MODULE_ADAPTER_RS, "rs_open_stream failed");
            FREE(lit_stream);
            return NULL;
        }
    }

    return lit_stream;
}

void rs_lit_stream_close(void *rs_lit_stream)
{
    if (NULL == rs_lit_stream) {
        return;
    }

    struct rs_lit_stream *lit_stream = (struct rs_lit_stream *)rs_lit_stream;
    if (lit_stream->ref_rs_rt != NULL) {
        if (lit_stream->rs_stream != NULL) {
            rs_close_stream(lit_stream->rs_stream);
            lit_stream->rs_stream = NULL;
        }
    }

    /* rs_stream->rs_rt point to rs_instance->rs_rt which will call free 
        same as rs_attr */
    lit_stream->ref_rs_rt = NULL;
    lit_stream->ref_matched_pat = NULL;

    FREE(lit_stream);
}

int rs_lit_stream_scan(void *rs_lit_stream, const char *data, size_t data_len,
                       unsigned long long *pattern_id_array, size_t array_size,
                       size_t *n_pattern_id)
{
    if (NULL == rs_lit_stream || NULL == data || 0 == data_len ||
        NULL == pattern_id_array || 0 == array_size || NULL == n_pattern_id) {
        return -1;
    }
    
    struct rs_lit_stream *lit_stream = (struct rs_lit_stream *)rs_lit_stream;

    lit_stream->ref_matched_pat->pattern_ids = pattern_id_array;
    lit_stream->ref_matched_pat->n_pattern_id = n_pattern_id;
    lit_stream->ref_matched_pat->pattern_ids_size = array_size;

    if (lit_stream->rs_stream != NULL) {
        int ret = rs_scan_stream(lit_stream->rs_stream, data, data_len,
                                 matched_event_cb, lit_stream->ref_matched_pat);
        if (ret < 0) {
            return -1;
        }
    }

    
    bloom_reset(lit_stream->ref_matched_pat->ref_bloom);

    return 0;
}

void rs_regex_engine_free(void *rs_regex_engine)
{
    if (NULL == rs_regex_engine) {
        return;
    }

    struct rs_regex_engine *rs_regex_inst = (struct rs_regex_engine *)rs_regex_engine;

    if (rs_regex_inst->rs_db != NULL) {
        rs_free_database(rs_regex_inst->rs_db);
        rs_regex_inst->rs_db = NULL;
    }

    if (rs_regex_inst->blooms != NULL) {
        for (size_t i = 0; i < rs_regex_inst->n_thread; i++) {
            if (rs_regex_inst->blooms[i] != NULL) {
                bloom_free(rs_regex_inst->blooms[i]);
                FREE(rs_regex_inst->blooms[i]);
            }
        }
        FREE(rs_regex_inst->blooms);
    }

    if (rs_regex_inst->streams != NULL) {
        for (size_t i = 0; i < rs_regex_inst->n_thread; i++) {
            if (rs_regex_inst->streams[i] != NULL) {
                rs_regex_stream_close(rs_regex_inst->streams[i]);
                rs_regex_inst->streams[i] = NULL;
            }
        }

        FREE(rs_regex_inst->streams);
    }

    if (rs_regex_inst->matched_pat != NULL) {
        for (size_t i = 0; i < rs_regex_inst->n_thread; i++) {
            if (rs_regex_inst->matched_pat[i] != NULL) {
                FREE(rs_regex_inst->matched_pat[i]);
            }
        }
        FREE(rs_regex_inst->matched_pat);
    }

    FREE(rs_regex_inst);
}

void *rs_regex_engine_new(struct expr_rule *rules, size_t n_rule,
                           struct pattern_attribute *pat_attr,
                           void *rs_regex_db, size_t n_thread,
                           struct log_handle *logger)
{
    struct rs_regex_engine *rs_regex_inst = ALLOC(struct rs_regex_engine, 1);
    
    rs_regex_inst->n_thread = n_thread;
    rs_regex_inst->rs_db = (rs_database_t *)rs_regex_db;
    rs_regex_inst->ref_pat_attr = pat_attr;
    rs_regex_inst->logger = logger;

    rs_regex_inst->blooms = ALLOC(struct bloom *, n_thread);
    for (size_t i = 0; i < n_thread; i++) {
        rs_regex_inst->blooms[i] = ALLOC(struct bloom, 1);
        bloom_init2(rs_regex_inst->blooms[i], 1024, 0.001);
    }

    rs_regex_inst->matched_pat = ALLOC(struct matched_pattern *, n_thread);
    for (size_t i = 0; i < n_thread; i++) {
        rs_regex_inst->matched_pat[i] = ALLOC(struct matched_pattern, 1);
        rs_regex_inst->matched_pat[i]->ref_bloom = rs_regex_inst->blooms[i];
        rs_regex_inst->matched_pat[i]->ref_pat_attr = pat_attr;
    }

    rs_regex_inst->streams = ALLOC(struct rs_regex_stream *, n_thread);
    for (size_t i = 0; i < n_thread; i++) {
        rs_regex_inst->streams[i] = (struct rs_regex_stream *)rs_regex_stream_open(rs_regex_inst, i);
    }

    return rs_regex_inst;
}

int rs_regex_engine_scan(void *rs_regex_engine, int thread_id,
                          const char *data, size_t data_len,
                          unsigned long long *pattern_id_array,
                          size_t array_size, size_t *n_pattern_id)
{
    if (NULL == rs_regex_engine || NULL == data || (0 == data_len) || 
        NULL == pattern_id_array || 0 == array_size || NULL == n_pattern_id) {
        return -1;
    }

    struct rs_regex_engine *rs_regex_inst = (struct rs_regex_engine *)rs_regex_engine;
    struct rs_regex_stream *rs_regex_stream = rs_regex_inst->streams[thread_id];
    assert(rs_regex_stream != NULL);

    rs_regex_stream->ref_matched_pat->pattern_ids = pattern_id_array;
    rs_regex_stream->ref_matched_pat->n_pattern_id = n_pattern_id;
    rs_regex_stream->ref_matched_pat->pattern_ids_size = array_size;

    if (rs_regex_inst->rs_db != NULL) {
        int ret = rs_scan(rs_regex_inst->rs_db, thread_id, data, data_len,
                      0, matched_event_cb, rs_regex_stream->ref_matched_pat);
        if (ret < 0) {
            return -1;
        }
    }

    bloom_reset(rs_regex_stream->ref_matched_pat->ref_bloom);

    return 0;
}

void *rs_regex_stream_open(void *rs_regex_engine, int thread_id)
{
    if (NULL == rs_regex_engine || thread_id < 0) {
        return NULL;
    }

    struct rs_regex_engine *rs_regex_inst = (struct rs_regex_engine *)rs_regex_engine;
    struct rs_regex_stream *regex_stream = ALLOC(struct rs_regex_stream, 1);

    regex_stream->logger = rs_regex_inst->logger;
    regex_stream->thread_id = thread_id;
    regex_stream->ref_rs_rt = rs_regex_inst;
    regex_stream->ref_matched_pat = rs_regex_inst->matched_pat[thread_id];

    if (rs_regex_inst->rs_db != NULL) {
        regex_stream->rs_stream = rs_open_stream(rs_regex_inst->rs_db, 0, 128);
        if (NULL == regex_stream->rs_stream) {
            log_fatal(rs_regex_inst->logger, MODULE_ADAPTER_RS, "rs_open_stream failed");
            FREE(regex_stream);
            return NULL;
        }
    }

    return regex_stream;
}

void rs_regex_stream_close(void *rs_regex_stream)
{
    if (NULL == rs_regex_stream) {
        return;
    }

    struct rs_regex_stream *regex_stream = (struct rs_regex_stream *)rs_regex_stream;
    if (regex_stream->ref_rs_rt != NULL) {
        if (regex_stream->rs_stream != NULL) {
            rs_close_stream(regex_stream->rs_stream);
            regex_stream->rs_stream = NULL;
        }
    }

    /* rs_stream->rs_rt point to rs_instance->rs_rt which will call free 
        same as rs_attr */
    regex_stream->ref_rs_rt = NULL;
    regex_stream->ref_matched_pat = NULL;

    FREE(regex_stream); 
}

int rs_regex_stream_scan(void *rs_regex_stream, const char *data, size_t data_len,
                         unsigned long long *pattern_id_array, size_t array_size,
                         size_t *n_pattern_id)
{
    if (NULL == rs_regex_stream || NULL == data || 0 == data_len ||
        NULL == pattern_id_array || 0 == array_size || NULL == n_pattern_id) {
        return -1;
    }
    
    struct rs_regex_stream *regex_stream = (struct rs_regex_stream *)rs_regex_stream;

    regex_stream->ref_matched_pat->pattern_ids = pattern_id_array;
    regex_stream->ref_matched_pat->n_pattern_id = n_pattern_id;
    regex_stream->ref_matched_pat->pattern_ids_size = array_size;

    if (regex_stream->rs_stream != NULL) {
        int ret = rs_scan_stream(regex_stream->rs_stream, data, data_len,
                                 matched_event_cb, regex_stream->ref_matched_pat);
        if (ret < 0) {
            return -1;
        }
    }

    bloom_reset(regex_stream->ref_matched_pat->ref_bloom);

    return 0;
}