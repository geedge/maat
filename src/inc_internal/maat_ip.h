/*
**********************************************************************************************
*	File: maat_ip.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_IP_H_
#define _MAAT_IP_H_

#ifdef __cpluscplus
extern "C"
{
#endif

struct ip_plus_runtime;

void *ip_plus_schema_new(cJSON *json, const char *table_name, struct log_handle *logger);
void ip_plus_schema_free(void *ip_plus_schema);

/* ip plus runtime API */
void *ip_plus_runtime_new(void *ip_plus_schema, struct maat_garbage_bin *garbage_bin, struct log_handle *logger);
void ip_plus_runtime_free(void *ip_plus_runtime);

int ip_plus_runtime_update(void *ip_plus_runtime, void *ip_plus_schema, const char *line);
int ip_plus_runtime_commit(void *ip_plus_runtime);

struct ex_data_runtime *ip_plus_runtime_get_ex_data_rt(struct ip_plus_runtime *ip_plus_rt);

/* ip runtime scan API */
int ip_runtime_scan_ip(struct ip_runtime *ip_rt, int thread_id, struct ip_addr *data, 
                          int *group_id_array, size_t n_group_id_array, int virtual_table_id,
                          struct maat_state *state);

#ifdef __cpluscplus
}
#endif

#endif