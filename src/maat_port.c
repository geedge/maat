/*
**********************************************************************************************
*	File: maat_port.c
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include "maat_port.h"

void *port_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                    const char *table_name, struct log_handle *logger)
{
    return NULL;
}

void port_schema_free(void *port_schema)
{

}

/* ip runtime API */
void *port_runtime_new(void *port_schema, int max_thread_num, 
                     struct maat_garbage_bin *garbage_bin,
                     struct log_handle *logger)
{
    return NULL;
}

void port_runtime_free(void *port_runtime)
{

}

int port_runtime_update(void *port_runtime, void *port_schema, 
                      const char *line, int valid_column)
{
    return 0;
}

int port_runtime_commit(void *port_runtime, const char *table_name)
{
    return 0;
}

struct ex_data_runtime *port_runtime_get_ex_data_rt(struct port_runtime *port_rt)
{
    return NULL;
}

int port_runtime_scan(struct port_runtime *port_rt, int thread_id, int port, 
                    int proto, int *group_ids, size_t group_id_size, 
                    int vtable_id, struct maat_state *state)
{
    return 0;
}

void port_runtime_scan_hit_inc(struct port_runtime *port_rt, int thread_id)
{

}

long long port_runtime_scan_hit_sum(struct port_runtime *port_rt, int n_thread)
{
    return 0;
}
