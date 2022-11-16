/*
**********************************************************************************************
*	File: maat_table_runtime.cpp
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <hs/hs.h>

#include "maat_utils.h"
#include "maat_table_runtime.h"
#include "uthash/uthash.h"
#include "maat_ex_data.h"
#include "adapter_hs.h"

struct maat_expr_runtime {
    struct adapter_hs *hs;
    //rcu_hash *htable;
};

struct maat_ip_plugin_runtime {
	//struct ip_matcher* ip_matcher;
    struct ex_data_runtime* ex_data_rt;
};

struct maat_table_runtime {
    enum maat_table_type table_type; // table schema已有type?? 
    uint32_t rule_num;
    
    union {
        struct maat_expr_runtime *expr_rt;
        struct maat_ip_plugin_runtime *ip_plugin_rt;
    };

    //ex_data_rt
    //table相关指针
};

struct maat_table_runtime_manager {
    struct maat_table_runtime **table_rt;
    size_t n_table_rt;
};

struct maat_table_runtime *table_runtime_new(enum maat_table_type table_type, int max_thread_num, struct maat_garbage_bin* bin)
{
    struct maat_table_runtime *table_rt = ALLOC(struct maat_table_runtime, 1);
    table_rt->table_type = table_type;
    switch (table_type) {
        case TABLE_TYPE_EXPR:
            table_rt->expr_rt->ex_data_rt = ex_data_runtime_new(NULL);
            break;
        case TABLE_TYPE_IP_PLUGIN:
            table_rt->ip_plugin_rt->ex_data_rt = ex_data_runtime_new(NULL);
            break;
        default:
            break;
    }

    return table_rt;
}

void table_runtime_free(struct maat_table_runtime * table_rt)
{
    switch (table_rt->table_type)
    {
    case TABLE_TYPE_EXPR:
        ex_data_runtime_free(table_rt->expr_rt->ex_data_rt);
        break;
    case TABLE_TYPE_IP_PLUGIN:
        ex_data_runtime_free(table_rt->ip_plugin_rt->ex_data_rt);
    default:
        break;
    }

    free(table_rt);
}

struct maat_table_runtime_manager *maat_table_runtime_manager_create(struct maat_table_manager *table_mgr, int max_thread_num, struct maat_garbage_bin* garbage_bin)
{
    if (NULL == table_mgr) {
        return NULL;
    }

    struct maat_table_runtime_manager *table_rt_mgr = ALLOC(struct maat_table_runtime_manager, 1);
    table_rt_mgr->n_table_rt = maat_table_manager_get_size(table_mgr);
    table_rt_mgr->table_rt = ALLOC(struct maat_table_runtime *, table_rt_mgr->n_table_rt);

    for (size_t i = 0; i < table_rt_mgr->n_table_rt; i++) {
        enum maat_table_type table_type = maat_table_manager_get_table_type(table_mgr, i);
        if (table_type == TABLE_TYPE_MAX) {
            continue;
        }
        table_rt_mgr->table_rt[i] = table_runtime_new(table_type, max_thread_num, garbage_bin);
    }

    return table_rt_mgr;
}

void maat_table_runtime_manager_destroy(struct maat_table_runtime_manager *table_rt_mgr)
{
	for(size_t i = 0; i < table_rt_mgr->n_table_rt; i++) {
		table_runtime_free(table_rt_mgr->table_rt[i]);
		table_rt_mgr->table_rt[i] = NULL;
	}

	free(table_rt_mgr->table_rt);
	table_rt_mgr->table_rt = NULL;
	free(table_rt_mgr);
}

struct maat_table_runtime *maat_table_runtime_get(struct maat_table_runtime_manager *table_rt_mgr, int table_id)
{
    assert(table_id < (int)table_rt_mgr->n_table_rt);
	return table_rt_mgr->table_rt[table_id];
}

enum maat_table_type maat_table_runtime_get_type(struct maat_table_runtime* table_rt)
{
    return table_rt->table_type;
}
