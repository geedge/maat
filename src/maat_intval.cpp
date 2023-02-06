/*
**********************************************************************************************
*	File: maat_intval.cpp
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include "maat_intval.h"

struct intval_schema {

};

struct intval_runtime {

};

void *intval_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                      const char *table_name, struct log_handle *logger)
{

}

void _schema_free(void *intval_schema)
{

}

/* intval runtime API */
void *intval_runtime_new(void *intval_schema, int max_thread_num, 
                       struct maat_garbage_bin *garbage_bin,
                       struct log_handle *logger)
{

}

void intval_runtime_free(void *intval_runtime)
{

}

int intval_runtime_update(void *intval_runtime, void *intval_schema, 
                        const char *line, int valid_column)
{

}

int intval_runtime_commit(void *intval_runtime)
{

}

int intval_runtime_scan_intval(struct intval_runtime *intval_rt, int thread_id, 
                             const char *data, size_t data_len, 
                             int *group_ids, size_t group_ids_size, 
                             int vtable_id, struct maat_state *state)
{

}

void intval_runtime_scan_hit_inc(struct intval_runtime *intval_rt, int thread_id)
{

}

long long intval_runtime_scan_hit_sum(struct intval_runtime *intval_rt, int n_thread)
{
    
}