/*
**********************************************************************************************
*	File: rcu_hash.h
*   Description: rcu hashtable
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _RCU_HASH_H_
#define _RCU_HASH_H_

#ifdef __cpluscplus
extern "C"
{
#endif

#include "uthash/uthash.h"

typedef void rcu_hash_data_free_fn(void *user_ctx, void *data);

/* rcu hash table */
struct rcu_hash_table;

struct rcu_hash_table *rcu_hash_new(rcu_hash_data_free_fn *free_fn);

void rcu_hash_free(struct rcu_hash_table *htable);

void rcu_hash_set_user_ctx(struct rcu_hash_table *htable, void *user_ctx);

void *rcu_hash_get_user_ctx(struct rcu_hash_table *htable);

/**
 * @brief just means add to the updating nodes
 *        after call rcu_hash_commit, they become effective nodes
*/
void rcu_hash_add(struct rcu_hash_table *htable, const char *key, size_t key_len, void *data);

void rcu_hash_del(struct rcu_hash_table *htable, const char *key, size_t key_len);

/**
 * @brief find in effective nodes
 * 
 * @param htable:  the rcu_hash_table
 * @param key:     the key used for searching in the hash table
 * @param key_len: the key's length
 * 
 * @retval NULL or 
*/
void *rcu_hash_find(struct rcu_hash_table *htable, const char *key, size_t key_len);

size_t rcu_hash_count(struct rcu_hash_table *htable);

/**
 * @brief make add/del effective
*/
void rcu_hash_commit(struct rcu_hash_table *htable);

size_t rcu_hash_garbage_queue_len(struct rcu_hash_table *htable);

size_t rcu_hash_list_updating_data(struct rcu_hash_table *htable, void ***data_array);

/**
 * @brief check if rcu hash table is updating
 * 
 * @retval 1 means htable is updating, otherwise 0
*/
int rcu_hash_updating_flag(struct rcu_hash_table *htable);

#ifdef __cpluscplus
}
#endif

#endif