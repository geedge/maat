/*
**********************************************************************************************
*	File: maat_ex_data.cpp
*   Description: ex data
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <stddef.h>

#include "uthash/uthash.h"
#include "uthash/utarray.h"
#include "maat_rhash.h"
#include "maat_utils.h"

typedef void ex_data_schema_new_func_t(int table_id, const char *key, const char *table_line, void* ad, long argl, void *argp);
typedef void ex_data_schema_free_func_t(int table_id, void* ad, long argl, void *argp);
typedef void ex_data_schema_dup_func_t(int table_id, void *to, void *from, long argl, void *argp);
/*
struct ex_data_schema
{
	ex_data_schema_new_func_t* new_func;
	ex_data_schema_free_func_t* free_func;
	ex_data_schema_dup_func_t* dup_func;
	//Maat_plugin_EX_key2index_func_t* key2index_func;
	long argl;
	void *argp;
}; */

struct ex_data_runtime {
    UT_array *cache_rows;
    size_t cache_row_num;
    size_t cache_size;

    struct rhash_table *htable;
	//const struct ex_data_schema* ex_schema;
	int table_id;
};

void cache_row_free(void*p)
{
	free(*(char**)p);
}

UT_icd ut_cache_row_icd = {sizeof(char*), NULL, NULL, cache_row_free};

struct ex_data_runtime *ex_data_runtime_new(void (* data_free)(void *data))
{
    struct ex_data_runtime *ex_data_rt = ALLOC(struct ex_data_runtime, 1);

    utarray_new(ex_data_rt->cache_rows, &ut_cache_row_icd);
    ex_data_rt->htable = rhash_table_create(data_free);
}

void ex_data_runtime_free(struct ex_data_runtime *ex_data_rt)
{
    if (ex_data_rt->cache_rows != NULL) {
		utarray_free(ex_data_rt->cache_rows);
		ex_data_rt->cache_rows=NULL;
		ex_data_rt->cache_row_num=0;
	}

    if (ex_data_rt->htable != NULL) {
        rhash_table_destroy(ex_data_rt->htable);
    }

    free(ex_data_rt);
}