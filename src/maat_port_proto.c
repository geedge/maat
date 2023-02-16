/*
**********************************************************************************************
*	File: maat_ip.cpp
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include "maat_port_proto.h"
#include "log/log.h"

void *pp_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                    const char *table_name, struct log_handle *logger)
{
    return NULL;
}

void pp_schema_free(void *pp_schema)
{

}

/* ip runtime API */
void *pp_runtime_new(void *pp_schema, int max_thread_num, 
                     struct maat_garbage_bin *garbage_bin,
                     struct log_handle *logger)
{
    return NULL;
}

void pp_runtime_free(void *pp_runtime)
{

}

int pp_runtime_update(void *pp_runtime, void *pp_schema, 
                      const char *line, int valid_column)
{
    return 0;
}

int pp_runtime_commit(void *pp_runtime, const char *table_name)
{
    return 0;
}

struct ex_data_runtime *pp_runtime_get_ex_data_rt(struct pp_runtime *pp_rt)
{
    return NULL;
}

int pp_runtime_scan(struct pp_runtime *pp_rt, int thread_id, int port, 
                    int proto, int *group_ids, size_t group_id_size, 
                    int vtable_id, struct maat_state *state)
{
    return 0;
}

void pp_runtime_scan_hit_inc(struct pp_runtime *pp_rt, int thread_id)
{

}

long long pp_runtime_scan_hit_sum(struct pp_runtime *pp_rt, int n_thread)
{
    return 0;
}