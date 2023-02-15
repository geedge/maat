/*
**********************************************************************************************
*	File: maat_fqdn.cpp
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include "maat_fqdn.h"
#include "log/log.h"

struct fqdn_runtime {

};

void *fqdn_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                    const char *table_name, struct log_handle *logger)
{
    return NULL;
}

void fqdn_schema_free(void *fqdn_schema)
{

}

void *fqdn_runtime_new(void *fqdn_schema, int max_thread_num, 
                     struct maat_garbage_bin *garbage_bin,
                     struct log_handle *logger)
{
    return NULL;
}

void fqdn_runtime_free(void *fqdn_runtime)
{

}

int fqdn_runtime_update(void *fqdn_runtime, void *fqdn_schema, 
                      const char *line, int valid_column)
{
    return 0;
}

int fqdn_runtime_commit(void *fqdn_runtime, const char *table_name)
{
    return 0;
}

struct ex_data_runtime *fqdn_runtime_get_ex_data_rt(struct fqdn_runtime *fqdn_rt)
{
    return NULL;
}

int fqdn_runtime_scan(struct fqdn_runtime *fqdn_rt, int thread_id, int port, 
                    int proto, int *group_ids, size_t group_id_size, 
                    int vtable_id, struct maat_state *state)
{
    return 0;
}

void fqdn_runtime_scan_hit_inc(struct fqdn_runtime *fqdn_rt, int thread_id)
{

}

long long fqdn_runtime_scan_hit_sum(struct fqdn_runtime *fqdn_rt, int n_thread)
{
    return 0;
}