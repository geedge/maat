/*
**********************************************************************************************
*	File: maat_fqdn.h
*   Description: 
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_FQDN_H_
#define _MAAT_FQDN_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "maat_rule.h"
#include "cJSON/cJSON.h"

struct fqdn_runtime;
struct table_manager;
struct log_handle;
struct maat_garbage_bin;

void *fqdn_schema_new(cJSON *json, struct table_manager *tbl_mgr, 
                      const char *table_name, struct log_handle *logger);
void fqdn_schema_free(void *fqdn_schema);

/* fqdn runtime API */
void *fqdn_runtime_new(void *fqdn_schema, int max_thread_num, 
                     struct maat_garbage_bin *garbage_bin,
                     struct log_handle *logger);
void fqdn_runtime_free(void *fqdn_runtime);

int fqdn_runtime_update(void *fqdn_runtime, void *fqdn_schema, 
                      const char *line, int valid_column);
int fqdn_runtime_commit(void *fqdn_runtime, const char *table_name);

struct ex_data_runtime *fqdn_runtime_get_ex_data_rt(struct fqdn_runtime *fqdn_rt);

/* fqdn runtime scan API */
int fqdn_runtime_scan(struct fqdn_runtime *fqdn_rt, int thread_id, int port, 
                    int proto, int *group_ids, size_t group_id_size, 
                    int vtable_id, struct maat_state *state);

void fqdn_runtime_scan_hit_inc(struct fqdn_runtime *fqdn_rt, int thread_id);
long long fqdn_runtime_scan_hit_sum(struct fqdn_runtime *fqdn_rt, int n_thread);

#ifdef __cplusplus
}
#endif

#endif
