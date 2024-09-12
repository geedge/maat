/*
**********************************************************************************************
*	File: maat_attribute.c
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>

#include "maat_kv.h"
#include "maat_utils.h"
#include "log/log.h"
#include "alignment.h"
#include "maat_core.h"
#include "maat_table.h"

#define MODULE_ATTRIBUTE	 module_name_str("maat.attribute")

struct attribute_schema {
    int attribute_id;
    int physical_table_id;
    struct table_manager *ref_tbl_mgr;
};

struct attribute_runtime {
    size_t n_worker_thread;
    long long *scan_times;
    long long *scan_bytes;
    long long *scan_cpu_time;
    long long *hit_times;
    long long *hit_item_num;
};

void *attribute_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                         const char *table_name, struct log_handle *logger)
{
    struct attribute_schema *schema = ALLOC(struct attribute_schema, 1);
    schema->ref_tbl_mgr = tbl_mgr;
   
    cJSON *item = cJSON_GetObjectItem(json, "table_id");
    if (NULL == item || item->type != cJSON_Number) {
        log_fatal(logger, MODULE_ATTRIBUTE, 
                  "[%s:%d] attribute:<%s> schema has no table_id column", 
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }
    schema->attribute_id = item->valueint;

    item = cJSON_GetObjectItem(json, "physical_table");
    if (NULL == item || item->type != cJSON_String) {
        log_fatal(logger, MODULE_ATTRIBUTE, 
                  "[%s:%d] attribute:<%s> schema has no physical_table column",
                  __FUNCTION__, __LINE__, table_name);
        goto error;
    }

    schema->physical_table_id = table_manager_get_table_id(tbl_mgr, item->valuestring);
    if (schema->physical_table_id < 0) {
        log_fatal(logger, MODULE_ATTRIBUTE, 
                  "[%s:%d] attribute:<%s>'s physical table:<%s> unregistered.",
                  __FUNCTION__, __LINE__, table_name, item->valuestring);
        goto error;
    }

    return schema;
error:
    FREE(schema);
    return NULL;
}

void attribute_schema_free(void *attribute_schema)
{
    FREE(attribute_schema);
}

void *attribute_runtime_new(void *attribute_schema, size_t max_thread_num,
                          struct maat_garbage_bin *garbage_bin,
                          struct log_handle *logger)
{
    if (NULL == attribute_schema) {
        return NULL;
    }

    struct attribute_runtime *virt_rt = ALLOC(struct attribute_runtime, 1);

    virt_rt->n_worker_thread = max_thread_num;
    virt_rt->scan_times = alignment_int64_array_alloc(max_thread_num);
    virt_rt->scan_bytes = alignment_int64_array_alloc(max_thread_num);
    virt_rt->scan_cpu_time = alignment_int64_array_alloc(max_thread_num);
    virt_rt->hit_times = alignment_int64_array_alloc(max_thread_num);
    virt_rt->hit_item_num = alignment_int64_array_alloc(max_thread_num);

    return virt_rt;
}

void attribute_runtime_free(void *attribute_runtime)
{
    if (NULL == attribute_runtime) {
        return;
    }

    struct attribute_runtime *virt_rt = (struct attribute_runtime *)attribute_runtime; 

    if (virt_rt->scan_times != NULL) {
        alignment_int64_array_free(virt_rt->scan_times);
        virt_rt->scan_times = NULL;
    }

    if (virt_rt->scan_bytes != NULL) {
        alignment_int64_array_free(virt_rt->scan_bytes);
        virt_rt->scan_bytes = NULL;
    }

    if (virt_rt->scan_cpu_time != NULL) {
        alignment_int64_array_free(virt_rt->scan_cpu_time);
        virt_rt->scan_cpu_time = NULL;
    }

    if (virt_rt->hit_times != NULL) {
        alignment_int64_array_free(virt_rt->hit_times);
        virt_rt->hit_times = NULL;
    }

    if (virt_rt->hit_item_num != NULL) {
        alignment_int64_array_free(virt_rt->hit_item_num);
        virt_rt->hit_item_num = NULL;
    }

    FREE(virt_rt);
}

void attribute_runtime_scan_bytes_add(struct attribute_runtime *virt_rt,
                                    int thread_id, long long val)
{
    if (NULL == virt_rt || thread_id < 0) {
        return;
    } 

    alignment_int64_array_add(virt_rt->scan_bytes, thread_id, val);
}

long long attribute_runtime_scan_bytes(void *attribute_runtime)
{
    if (NULL == attribute_runtime) {
        return 0;
    }

    struct attribute_runtime *virt_rt = (struct attribute_runtime *)attribute_runtime; 
    long long sum = alignment_int64_array_sum(virt_rt->scan_bytes,
                                              virt_rt->n_worker_thread);
    alignment_int64_array_reset(virt_rt->scan_bytes,
                                virt_rt->n_worker_thread);

    return sum; 
}

void attribute_runtime_scan_times_inc(struct attribute_runtime *virt_rt,
                                    int thread_id)
{
    if (NULL == virt_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(virt_rt->scan_times, thread_id, 1);
}

long long attribute_runtime_scan_times(void *attribute_runtime)
{
    if (NULL == attribute_runtime) {
        return 0;
    }

    struct attribute_runtime *virt_rt = (struct attribute_runtime *)attribute_runtime; 
    long long sum = alignment_int64_array_sum(virt_rt->scan_times,
                                              virt_rt->n_worker_thread);
    alignment_int64_array_reset(virt_rt->scan_times,
                                virt_rt->n_worker_thread);

    return sum; 
}

long long attribute_runtime_scan_cpu_time(void *attribute_runtime)
{
    if (NULL == attribute_runtime) {
        return 0;
    }

    struct attribute_runtime *virt_rt = (struct attribute_runtime *)attribute_runtime; 
    long long sum = alignment_int64_array_sum(virt_rt->scan_cpu_time,
                                              virt_rt->n_worker_thread);
    alignment_int64_array_reset(virt_rt->scan_cpu_time,
                                virt_rt->n_worker_thread);

    return sum; 
}

void attribute_runtime_hit_times_inc(struct attribute_runtime *virt_rt,
                                   int thread_id)
{
    if (NULL == virt_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(virt_rt->hit_times, thread_id, 1);
}

long long attribute_runtime_hit_times(void *attribute_runtime)
{
    if (NULL == attribute_runtime) {
        return 0;
    }

    struct attribute_runtime *virt_rt = (struct attribute_runtime *)attribute_runtime;
    long long sum = alignment_int64_array_sum(virt_rt->hit_times,
                                              virt_rt->n_worker_thread);
    alignment_int64_array_reset(virt_rt->hit_times,
                                virt_rt->n_worker_thread);

    return sum;
}

void attribute_runtime_hit_item_num_add(struct attribute_runtime *virt_rt,
                                      int thread_id, long long val)
{
    if (NULL == virt_rt || thread_id < 0) {
        return;
    }

    alignment_int64_array_add(virt_rt->hit_item_num, thread_id, val);
}

long long attribute_runtime_hit_item_num(void *attribute_runtime)
{
    if (NULL == attribute_runtime) {
        return 0;
    } 

    struct attribute_runtime *virt_rt = (struct attribute_runtime *)attribute_runtime; 
    long long sum = alignment_int64_array_sum(virt_rt->hit_item_num,
                                              virt_rt->n_worker_thread);
    alignment_int64_array_reset(virt_rt->hit_item_num,
                                virt_rt->n_worker_thread);
    
    return sum;
}
