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

    hs_scratch_t **scratchs;
    size_t scratch_size;

    struct bool_matcher *bm;
};

/* adapter_hs instance */
struct adapter_hs {
    size_t n_worker_thread;
    size_t n_expr;
    size_t n_patterns;
    struct adapter_hs_runtime *hs_rt;
    struct hs_tag *tag_map;
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

struct matched_pattern {
    unsigned long long pattern_id;
    unsigned long matched_l_offset;
    unsigned long matched_r_offset;
    UT_hash_handle hh;
};

struct matched_pattern_container {
    UT_array *pat_ids;
    unsigned long long pattern_id;
    unsigned long long l_matched;
    unsigned long long r_matched;
    struct matched_pattern *pat_hash;
};

struct pattern_attribute {
    unsigned long long pattern_id;
    enum hs_match_mode match_mode;
    int l_offset;
    int r_offset;
};

struct hs_tag {
    char *key;
    size_t key_len;

    size_t n_pat_attr;
    struct pattern_attribute *pat_attr;
    void *user_tag;
    UT_hash_handle hh;
};

static int adpt_hs_alloc_scratch(struct adapter_hs_runtime *hs_rt, size_t n_worker_thread,
                                 enum hs_pattern_type pattern_type, struct log_handle *logger)
{
    hs_database_t *database = NULL;
    hs_rt->scratchs = ALLOC(hs_scratch_t *, n_worker_thread);

    if (pattern_type == HS_PATTERN_TYPE_STR) {
        database = hs_rt->literal_db;
    } else {
        database = hs_rt->regex_db;
    }

    if (hs_alloc_scratch(database, &hs_rt->scratchs[0]) != HS_SUCCESS) {
        log_error(logger, MODULE_ADAPTER_HS,
                  "[%s:%d] Unable to allocate scratch space. Exiting.", 
                  __FUNCTION__, __LINE__);
        hs_free_database(database);
        return -1;
    }

    for (size_t i = 1; i < n_worker_thread; i++) {
        hs_error_t err = hs_clone_scratch(hs_rt->scratchs[0], &hs_rt->scratchs[i]);
        if (err != HS_SUCCESS) {
            log_error(logger, MODULE_ADAPTER_HS, 
                      "[%s:%d] Unable to clone scratch prototype", __FUNCTION__, __LINE__);
            hs_free_database(database);
            return -1;
        }

        err = hs_scratch_size(hs_rt->scratchs[i], &hs_rt->scratch_size);
        if (err != HS_SUCCESS) {
            log_error(logger, MODULE_ADAPTER_HS, 
                      "[%s:%d] Unable to query scratch size", __FUNCTION__, __LINE__);
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
                                  struct adpt_hs_compile_data *compile_data, 
                                  enum hs_pattern_type pattern_type,
                                  enum hs_scan_mode scan_mode, 
                                  struct log_handle *logger)
{
    hs_error_t err;
    hs_compile_error_t *compile_err = NULL;

    if (NULL == hs_rt || NULL == compile_data) {
        return -1;
    }

    if (pattern_type == HS_PATTERN_TYPE_STR) {
        err = hs_compile_lit_multi((const char *const *)compile_data->patterns, compile_data->flags,
                                    compile_data->ids, compile_data->pattern_lens, compile_data->n_patterns, 
                                    scan_mode, NULL, &hs_rt->literal_db, &compile_err);
        if (err != HS_SUCCESS) {
            if (compile_err) {
                log_error(logger, MODULE_ADAPTER_HS, "[%s:%d] compile error: %s", 
                          __FUNCTION__, __LINE__, compile_err->message);
            }

            hs_free_compile_error(compile_err);
            return -1;
        }
    } else {
          err = hs_compile_ext_multi((const char *const *)compile_data->patterns, compile_data->flags,
                                      compile_data->ids, NULL, compile_data->n_patterns, 
                                      scan_mode, NULL, &hs_rt->regex_db, &compile_err);
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

struct hs_tag *hs_tag_new(long long expr_id, size_t n_pattern)
{
    struct hs_tag *tag = ALLOC(struct hs_tag, 1);

    tag->key = ALLOC(char, sizeof(long long));
    memcpy(tag->key, (char *)&expr_id, sizeof(long long));
    tag->key_len = sizeof(long long);
    tag->pat_attr = ALLOC(struct pattern_attribute, n_pattern);
    tag->n_pat_attr = n_pattern;

    return tag;
}

void hs_tag_free(struct hs_tag *tag)
{
    if (NULL == tag) {
        return;
    }

    if (tag->key != NULL) {
        FREE(tag->key);
    }

    if (tag->pat_attr != NULL) {
        FREE(tag->pat_attr);
    }

    FREE(tag);
}

struct adapter_hs *adapter_hs_initialize(enum hs_scan_mode scan_mode, 
                                         enum hs_pattern_type pattern_type,
                                         size_t n_worker_thread,
                                         struct hs_expr *exprs, size_t n_expr,
                                         struct log_handle *logger)
{
    if ((scan_mode != HS_SCAN_MODE_BLOCK && scan_mode != HS_SCAN_MODE_STREAM) || 
        (pattern_type != HS_PATTERN_TYPE_STR && pattern_type != HS_PATTERN_TYPE_REG) || 
        0 == n_worker_thread || NULL == exprs || 0 == n_expr) {
        log_error(logger, MODULE_ADAPTER_HS, "[%s:%d] input parameters illegal!",
                  __FUNCTION__, __LINE__);
        return NULL;
    }

    /* get the sum of pattern */
    size_t pattern_num = 0;

    for (size_t i = 0; i < n_expr; i++) {
        if (exprs[i].n_patterns > MAX_EXPR_PATTERN_NUM) {
            log_error(logger, MODULE_ADAPTER_HS, 
                      "[%s:%d] the number of patterns in one expression should less than %d",
                      __FUNCTION__, __LINE__, MAX_EXPR_PATTERN_NUM);
            return NULL;
        }

        for (size_t j = 0; j < exprs[i].n_patterns; j++) {
            if (0 == exprs[i].patterns[j].pat_len) {
                log_error(logger, MODULE_ADAPTER_HS, 
                          "[%s:%d] expr pattern length should not 0", __FUNCTION__, __LINE__);
                return NULL;
            }

            pattern_num++;
        }
    }

    if (0 == pattern_num) {
        log_error(logger, MODULE_ADAPTER_HS, "[%s:%d] expr array has no valid pattern",
                  __FUNCTION__, __LINE__);
        return NULL;
    }

    struct adpt_hs_compile_data *compile_data = NULL;
    compile_data = adpt_hs_compile_data_new(pattern_num);
    
    uint32_t pattern_index = 0;
    struct adapter_hs *hs_instance = ALLOC(struct adapter_hs, 1);
    hs_instance->tag_map = NULL;

    struct bool_expr *bool_exprs = ALLOC(struct bool_expr, n_expr);
    /* populate adpt_hs_compile_data and bool_expr */
    for (size_t i = 0; i < n_expr; i++) {
        struct hs_tag *hs_tag = hs_tag_new(exprs[i].expr_id, exprs[i].n_patterns);
        hs_tag->user_tag = exprs[i].user_tag;

        for (size_t j = 0; j < exprs[i].n_patterns; j++) {
            size_t pat_len = 0;

            hs_tag->pat_attr[j].pattern_id = pattern_index;
            hs_tag->pat_attr[j].match_mode = exprs[i].patterns[j].match_mode;
            if (exprs[i].patterns[j].match_mode == HS_MATCH_MODE_SUB) {
                hs_tag->pat_attr[j].l_offset = exprs[i].patterns[j].l_offset;
                hs_tag->pat_attr[j].r_offset = exprs[i].patterns[j].r_offset;
            }

            compile_data->ids[pattern_index] = pattern_index;
            compile_data->flags[pattern_index] = HS_FLAG_SOM_LEFTMOST;
            if (exprs[i].patterns[j].case_sensitive == HS_CASE_INSESITIVE) {
                compile_data->flags[pattern_index] |= HS_FLAG_CASELESS;
            }

            pat_len = exprs[i].patterns[j].pat_len;
            compile_data->pattern_lens[pattern_index] = pat_len;
            compile_data->patterns[pattern_index] = ALLOC(char, pat_len);
            memcpy(compile_data->patterns[pattern_index], exprs[i].patterns[j].pat,
                   exprs[i].patterns[j].pat_len);

            bool_exprs[i].items[j].item_id = pattern_index;
            pattern_index++;
        }

        bool_exprs[i].expr_id = exprs[i].expr_id;
        bool_exprs[i].item_num = exprs[i].n_patterns;
        bool_exprs[i].user_tag = hs_tag;
        HASH_ADD_KEYPTR(hh, hs_instance->tag_map, hs_tag->key, hs_tag->key_len, hs_tag);
    }
    compile_data->n_patterns = pattern_index;

    int ret = -1;
    size_t mem_size = 0;
    
    hs_instance->n_worker_thread = n_worker_thread;
    hs_instance->n_patterns = pattern_index;
    hs_instance->n_expr = n_expr;
    hs_instance->hs_rt = ALLOC(struct adapter_hs_runtime, 1);

    //mytest
    // for (size_t i = 0; i < n_expr_array; i++) {
    //     printf("exprs[%zu] expr_id:%llu, item_num:%zu\n", i, exprs[i].expr_id, exprs[i].item_num);
    //     for (size_t j = 0; j < exprs[i].item_num; j++) {
    //         printf("item[%zu] item_id: %llu\n", j, exprs[i].items[j].item_id);
    //     }
    // }
    
    /* create bool matcher */
    hs_instance->hs_rt->bm = bool_matcher_new(bool_exprs, n_expr, &mem_size);
    if (hs_instance->hs_rt->bm != NULL) {
        log_info(logger, MODULE_ADAPTER_HS, 
                 "Adapter_hs module: build bool matcher of %zu expressions with %zu bytes memory", 
                 n_expr, mem_size);
    } else {
        log_error(logger, MODULE_ADAPTER_HS, "[%s:%d] Adapter_hs module: build bool matcher failed",
                  __FUNCTION__, __LINE__);
        adpt_hs_compile_data_free(compile_data, pattern_index);
        FREE(bool_exprs);
        adapter_hs_destroy(hs_instance);
        return NULL;
    }
    FREE(bool_exprs);

    /* build hs database */
    ret = adpt_hs_build_database(hs_instance->hs_rt, compile_data, pattern_type, scan_mode, logger);
    if (ret < 0) {
        goto error;
    }

    ret = adpt_hs_alloc_scratch(hs_instance->hs_rt, n_worker_thread, pattern_type, logger);
    if (ret < 0) {
        goto error;
    }

    adpt_hs_compile_data_free(compile_data, pattern_index);
    return hs_instance;
error:
    adpt_hs_compile_data_free(compile_data, pattern_index);
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
            for (size_t i = 0; i < hs_instance->n_worker_thread; i++) {
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

    if (hs_instance->tag_map != NULL) {
        struct hs_tag *tag = NULL, *tmp_tag = NULL;
        HASH_ITER(hh, hs_instance->tag_map, tag, tmp_tag) {
            HASH_DEL(hs_instance->tag_map, tag);
            hs_tag_free(tag);
        }
    }

    FREE(hs_instance);
}

static inline int compare_pattern_id(const void *a, const void *b)
{
	long long ret = *(unsigned long long *)a - *(unsigned long long *)b;

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
                     unsigned long long to, unsigned int flags, 
                     void *ctx) {
    // put id in set
    struct matched_pattern_container *matched_pat_container = (struct matched_pattern_container *)ctx;
    unsigned long long pattern_id = id;
    
    if (utarray_find(matched_pat_container->pat_ids, &pattern_id, compare_pattern_id)) {
        return -1;
    }

    utarray_push_back(matched_pat_container->pat_ids, &pattern_id);
    utarray_sort(matched_pat_container->pat_ids, compare_pattern_id);

    struct matched_pattern *matched_pat = ALLOC(struct matched_pattern, 1);
    matched_pat->pattern_id = pattern_id;
    matched_pat->matched_l_offset = from;
    matched_pat->matched_r_offset = to;
    
    HASH_ADD(hh, matched_pat_container->pat_hash, pattern_id, sizeof(unsigned long long), matched_pat);
    return 0;
}

int is_real_matched_pattern(struct matched_pattern *matched_pat, enum hs_match_mode match_mode,
                            size_t data_len, int attr_l_offset, int attr_r_offset)
{
    if (match_mode == HS_MATCH_MODE_EXACTLY) {
        if (matched_pat->matched_l_offset == 0 &&
            matched_pat->matched_r_offset == data_len) {
            return 0;
        }
    } else if (match_mode == HS_MATCH_MODE_PREFIX) {
        if (matched_pat->matched_l_offset == 0) {
            return 0;
        }
    } else if (match_mode == HS_MATCH_MODE_SUFFIX) {
        if (matched_pat->matched_r_offset == data_len) {
            return 0;
        }
    } else if (match_mode == HS_MATCH_MODE_SUB) {
        if (attr_l_offset == -1) {
            attr_l_offset = 0;
        }

        if (attr_r_offset == -1) {
            attr_r_offset = (int)data_len;
        }

        if (matched_pat->matched_l_offset >= (unsigned long)attr_l_offset &&
            matched_pat->matched_r_offset <= (unsigned long)attr_r_offset) {
            return 0;
        }
    } else {
        assert(0);
    }

    return -1;
}

int hs_tag_validate(struct hs_tag *hs_tag, struct matched_pattern_container *matched_pat_container,
                    size_t data_len)
{
    /* check if real matched pattern, because pattern match_mode is different */
    for (size_t i = 0; i < hs_tag->n_pat_attr; i++) {
        struct matched_pattern *tmp_matched_pat = NULL;
        unsigned long long pattern_id = hs_tag->pat_attr[i].pattern_id;
        HASH_FIND(hh, matched_pat_container->pat_hash, &pattern_id, sizeof(unsigned long long), tmp_matched_pat);
        if (tmp_matched_pat) {
            int matched_ret = is_real_matched_pattern(tmp_matched_pat,
                                                      hs_tag->pat_attr[i].match_mode,
                                                      data_len,
                                                      hs_tag->pat_attr[i].l_offset,
                                                      hs_tag->pat_attr[i].r_offset);
            if (matched_ret < 0) {
                return -1;
            }
        }
    }

    return 0;
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

    struct adapter_hs_runtime *hs_rt = hs_instance->hs_rt;
    hs_scratch_t *scratch = hs_rt->scratchs[thread_id];
    hs_error_t err;

    struct matched_pattern_container matched_pat_container;
   
    matched_pat_container.pat_hash = NULL;
    utarray_new(matched_pat_container.pat_ids, &ut_pattern_id_icd);
    utarray_reserve(matched_pat_container.pat_ids, hs_instance->n_patterns);

    int err_count = 0;
    if (hs_rt->literal_db != NULL) {
        err = hs_scan(hs_rt->literal_db, data, data_len, 0, scratch,
                      matched_event_cb, &matched_pat_container);
        if (err != HS_SUCCESS) {
            err_count++;
        }
    }
    
    if (hs_rt->regex_db != NULL) {
        err = hs_scan(hs_rt->regex_db, data, data_len, 0, scratch,
                      matched_event_cb, &matched_pat_container);
        if (err != HS_SUCCESS) {
            err_count++;
        }
    }
    
    if (2 == err_count) {
        return -1;
    }

    size_t matched_pattern_ids_cnt = utarray_len(matched_pat_container.pat_ids);
    size_t i = 0;
    unsigned long long items[matched_pattern_ids_cnt];
    memset(items, 0, sizeof(unsigned long long) * matched_pattern_ids_cnt);
    
    for (i = 0; i < matched_pattern_ids_cnt; i++) {
        items[i] = *(unsigned long long *)utarray_eltptr(matched_pat_container.pat_ids, i);
    }

    int ret = 0;
    int real_matched_index = 0;
    struct hs_tag *hs_tag = NULL;
    struct bool_expr_match *bool_matcher_results = ALLOC(struct bool_expr_match, hs_instance->n_expr);
    int bool_matcher_ret = bool_matcher_match(hs_rt->bm, items, matched_pattern_ids_cnt,
                                              bool_matcher_results, hs_instance->n_expr);
    if (bool_matcher_ret < 0) {
        ret = -1;
        goto next;
    }

    if (bool_matcher_ret > (int)n_result) {
        bool_matcher_ret = n_result;
    }

    for (int index = 0; index < bool_matcher_ret; index++) {
        hs_tag = (struct hs_tag *)bool_matcher_results[index].user_tag;

        int tag_ret = hs_tag_validate(hs_tag, &matched_pat_container, data_len);
        if (tag_ret < 0) {
            //bool_matcher_results[index] is invalid hit, continue
            continue;
        }

        results[real_matched_index].item_id = bool_matcher_results[index].expr_id;
        results[real_matched_index].user_tag = hs_tag->user_tag;
        real_matched_index++;
    }
    
    *n_hit_result = real_matched_index;
next:
    FREE(bool_matcher_results);
    struct matched_pattern *pattern = NULL, *tmp_pattern = NULL;
    HASH_ITER(hh, matched_pat_container.pat_hash, pattern, tmp_pattern) {
        HASH_DELETE(hh, matched_pat_container.pat_hash, pattern);
        FREE(pattern); 
    }
    utarray_free(matched_pat_container.pat_ids);

    return ret;
}

struct adapter_hs_stream *adapter_hs_stream_open(struct adapter_hs *hs_instance, int thread_id)
{
    if (NULL == hs_instance || thread_id < 0) {
        return NULL;
    }
    
    struct adapter_hs_stream *hs_stream = ALLOC(struct adapter_hs_stream, 1);
    hs_error_t err;

    hs_stream->thread_id = thread_id;
    hs_stream->n_expr = hs_instance->n_expr;
    hs_stream->n_patterns = hs_instance->n_patterns;
    hs_stream->hs_rt = hs_instance->hs_rt;
    utarray_new(hs_stream->pattern_id_set, &ut_pattern_id_icd);
    utarray_reserve(hs_stream->pattern_id_set, hs_stream->n_patterns);

    int err_count = 0;
    if (hs_instance->hs_rt->literal_db != NULL) {
        err = hs_open_stream(hs_instance->hs_rt->literal_db, 0, &hs_stream->literal_stream);
        if (err != HS_SUCCESS) {
           err_count++;
        }
    }

    if (hs_instance->hs_rt->regex_db != NULL) {
        err = hs_open_stream(hs_instance->hs_rt->regex_db, 0, &hs_stream->regex_stream);
        if (err != HS_SUCCESS) {
            err_count++;
        }
    }

    if (2 == err_count) {
        return NULL;
    }

    return hs_stream;
}

int adapter_hs_scan_stream(struct adapter_hs_stream *hs_stream, const char *data, size_t data_len,
                           struct hs_scan_result *results, size_t n_result, size_t *n_hit_result)
{
    hs_error_t err;

    if (NULL == hs_stream || NULL == data || 0 == data_len ||
        NULL == results || 0 == n_result || NULL == n_hit_result) {
        return -1;
    }
    
    int err_count = 0;
    int thread_id = hs_stream->thread_id;
    if (hs_stream->literal_stream != NULL) {
        err = hs_scan_stream(hs_stream->literal_stream, data, data_len, 
                             0, hs_stream->hs_rt->scratchs[thread_id],
                             matched_event_cb, hs_stream->pattern_id_set);
        if (err != HS_SUCCESS) {
            err_count++;
        }
    }
    
    if (hs_stream->regex_stream != NULL) {
        err = hs_scan_stream(hs_stream->regex_stream, data, data_len,
                             0, hs_stream->hs_rt->scratchs[thread_id],
                             matched_event_cb, hs_stream->pattern_id_set);
        if (err != HS_SUCCESS) {
            err_count++;
        }
    }

    if (2 == err_count) {
        return -1;
    }

    size_t pattern_set_size = utarray_len(hs_stream->pattern_id_set);
    unsigned long long items[pattern_set_size];
    memset(items, 0, sizeof(unsigned long long) * pattern_set_size);
    for (size_t i = 0; i < pattern_set_size; i++) {
        items[i] = *(unsigned long long *)utarray_eltptr(hs_stream->pattern_id_set, i);
    }

    int ret = 0;
    int matched_index = 0;
    struct bool_expr_match *bool_matcher_results = NULL;

    bool_matcher_results = ALLOC(struct bool_expr_match, hs_stream->n_expr);
    int bool_matcher_ret = bool_matcher_match(hs_stream->hs_rt->bm, items, pattern_set_size,
                                              bool_matcher_results, hs_stream->n_expr);
    if (bool_matcher_ret < 0) {
        ret = -1;
        goto next;
    }

    if (bool_matcher_ret > (int)n_result) {
        bool_matcher_ret = n_result;
    }

    for (matched_index = 0; matched_index < bool_matcher_ret; matched_index++) {
        results[matched_index].item_id = bool_matcher_results[matched_index].expr_id;
        results[matched_index].user_tag = bool_matcher_results[matched_index].user_tag;
    }
    *n_hit_result = bool_matcher_ret;
next:
    FREE(bool_matcher_results);
    return ret;
}

void adapter_hs_stream_close(struct adapter_hs_stream *hs_stream)
{
    if (NULL == hs_stream) {
        return;
    }

    int thread_id = hs_stream->thread_id;

    if (hs_stream->hs_rt != NULL) {
        if (hs_stream->literal_stream != NULL) {
            hs_close_stream(hs_stream->literal_stream,
                            hs_stream->hs_rt->scratchs[thread_id], 
                            NULL, NULL);
            hs_stream->literal_stream = NULL;
        }
        
        if (hs_stream->regex_stream != NULL) {
            hs_close_stream(hs_stream->regex_stream,
                            hs_stream->hs_rt->scratchs[thread_id], 
                            NULL, NULL);
            hs_stream->regex_stream = NULL;
        }
    }
   
    utarray_free(hs_stream->pattern_id_set);

    /* hs_stream->hs_rt point to hs_instance->hs_rt which will call free */
    hs_stream->hs_rt = NULL;
    FREE(hs_stream);
}