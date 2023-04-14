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

#ifdef __cplusplus
extern "C"
{
#endif

#include "uthash/uthash.h"

typedef void data_free_fn(void *user_ctx, void *data);

/* rcu hash table */
struct rcu_hash_table;

struct rcu_hash_table *rcu_hash_new(data_free_fn *free_fn, void *arg);

void rcu_hash_free(struct rcu_hash_table *htable);

/**
 * @brief Adding the updating nodes which will become effective nodes after call rcu_hash_commit
 *    
 * @retval 0(success) -1(failed)
*/
int rcu_hash_add(struct rcu_hash_table *htable, const char *key, size_t key_len, void *data);

/**
 * @brief Deleting
*/
int rcu_hash_del(struct rcu_hash_table *htable, const char *key, size_t key_len);

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

void *rcu_updating_hash_find(struct rcu_hash_table *htable, const char *key, size_t key_len);

/**
 * @brief list all effective nodes
 * 
 * @retval the number of effective nodes
*/
size_t rcu_hash_list(struct rcu_hash_table *htable, void ***data_array);

size_t rcu_updating_hash_list(struct rcu_hash_table *htable, void ***data_array);

size_t rcu_hash_count(struct rcu_hash_table *htable);

/**
 * @brief if rcu hash is updating
 * 
 * @retval True(1) False(0) 
*/
int rcu_hash_is_updating(struct rcu_hash_table *htable);

/**
 * @brief make add/del effective
*/
void rcu_hash_commit(struct rcu_hash_table *htable);

#ifdef __cplusplus
}
#endif

#endif