/*
**********************************************************************************************
*	File: maat_rhash.h
*   Description: maat rcu hashtable
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

/* rcu hash table */
struct rcu_hash_table;

struct rcu_hash_table *rcu_hash_new(void (* data_free)(void *data));

void rcu_hash_free(struct rcu_hash_table *htable);

/**
 * @brief the data added just in updating stage
 *        after call rcu_hash_commit, it in effective stage
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

size_t rcu_hash_counts(struct rcu_hash_table *htable);


/**
 * @brief make add/del effective
*/
void rcu_hash_commit(struct rcu_hash_table *htable);

#ifdef __cpluscplus
}
#endif

#endif