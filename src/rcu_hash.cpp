/*
**********************************************************************************************
*	File: maat_rhash.cpp
*   Description:
*	Authors: Liu WenTan <liuwentan@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <assert.h>
#include <pthread.h>
#include <unistd.h>

#include "rcu_hash.h"
#include "maat_utils.h"
#include "maat_garbage_collection.h"

#define GARBAGE_DEFAULT_TIMEOUT 60

struct rcu_hash_table {
    int is_updating;
    char effective_hash; // 'a' or 'b'

    /* two hash map for rcu */
    struct rcu_hash_node *hashmap_a;
    struct rcu_hash_node *hashmap_b;

    void (* data_free)(void *data);
    struct maat_garbage_bin *garbage_bin;

    pthread_mutex_t update_mutex;
};

struct rcu_hash_node {
    char *key;
    size_t key_len;
    void *data; //table_runtime解析成两个成员

    UT_hash_handle hh_a;
    UT_hash_handle hh_b;   
};

void rcu_hash_node_free(struct rcu_hash_node *node, void (* data_free)(void *data))
{
    if (node->key != NULL) {
        free(node->key);
    }

    if (node->data != NULL) {
        data_free(node->data);
    }

    free(node);
}

struct rcu_hash_table *rcu_hash_new(void (* data_free)(void *data))
{
    if (NULL == data_free) {
        return NULL;
    }
    
    struct rcu_hash_table *htable = ALLOC(struct rcu_hash_table, 1);

    htable->is_updating = 0;
    htable->effective_hash = 'a';
    htable->garbage_bin = maat_garbage_bin_new(GARBAGE_DEFAULT_TIMEOUT);
    htable->data_free = data_free;
    pthread_mutex_init(&htable->update_mutex, NULL);

    return htable;
}

void rcu_hash_free(struct rcu_hash_table *htable)
{
    struct rcu_hash_node *tmp = NULL;
    struct rcu_hash_node *item = NULL;

    if (htable != NULL) {
        HASH_ITER(hh_a, htable->hashmap_a, item, tmp) {
            HASH_DELETE(hh_a, htable->hashmap_a, item);
            rcu_hash_node_free(item, htable->data_free);
        }

        HASH_ITER(hh_b, htable->hashmap_b, item, tmp) {
            HASH_DELETE(hh_b, htable->hashmap_b, item);
            rcu_hash_node_free(item, htable->data_free);
        }
    }

    maat_garbage_bin_free(htable->garbage_bin);
    pthread_mutex_destroy(&htable->update_mutex);

    free(htable);
}

void rcu_hash_update_prepare(struct rcu_hash_table *htable)
{
    struct rcu_hash_node *node = NULL;
    struct rcu_hash_node *tmp = NULL;

    if (htable->effective_hash == 'a') {
        assert(htable->hashmap_b == NULL);
        HASH_ITER(hh_a, htable->hashmap_a, node, tmp) {
            HASH_ADD_KEYPTR(hh_b, htable->hashmap_b, node->key, node->key_len, node);
        }
    } else {
         assert(htable->hashmap_a == NULL);
         HASH_ITER(hh_b, htable->hashmap_b, node, tmp) {
            HASH_ADD_KEYPTR(hh_a, htable->hashmap_a, node->key, node->key_len, node);
         }
    }

    htable->is_updating = 1;
}

void rcu_hash_add(struct rcu_hash_table *htable, const char *key, size_t key_len, void *data)
{
    struct rcu_hash_node *node = ALLOC(struct rcu_hash_node, 1);
    memcpy(node->key, key, key_len);
    node->key_len = key_len;
    node->data = data;

    if (!htable->is_updating) {
        rcu_hash_update_prepare(htable);
    }

    if (htable->effective_hash == 'a') {
        HASH_FIND(hh_b, htable->hashmap_b, key, key_len, node);
        if (NULL == node) {
            HASH_ADD_KEYPTR(hh_b, htable->hashmap_b, key, key_len, node);
        }
    } else {
        HASH_FIND(hh_a, htable->hashmap_a, key, key_len, node);
        if (NULL == node) {
            HASH_ADD_KEYPTR(hh_a, htable->hashmap_a, key, key_len, node);
        }
    }
}

void rcu_hash_del(struct rcu_hash_table *htable, const char *key, size_t key_len)
{
    struct rcu_hash_node *node = NULL;

    if (!htable->is_updating) {
        rcu_hash_update_prepare(htable);
    }
    
    if (htable->effective_hash == 'a') {
        HASH_FIND(hh_b, htable->hashmap_b, key, key_len, node);
        if (node != NULL) {
            HASH_DELETE(hh_b, htable->hashmap_b, node);
        }
    } else {
        HASH_FIND(hh_a, htable->hashmap_a, key, key_len, node);
        if (node != NULL) {
            HASH_DELETE(hh_a, htable->hashmap_a, node);
        }
    }

    if (node != NULL) {
        maat_garbage_bagging(htable->garbage_bin, node, (void (*)(void*))rcu_hash_node_free);
    }
}

void *rcu_hash_find(struct rcu_hash_table *htable, const char *key, size_t key_len)
{
    struct rcu_hash_node *node = NULL;

    if (htable->effective_hash == 'a') {
        HASH_FIND(hh_a, htable->hashmap_a, key, key_len, node);
        if (node != NULL) {
            return node->data;
        }
    } else {
        HASH_FIND(hh_b, htable->hashmap_b, key, key_len, node);
        if (node != NULL) {
            return node->data;
        }
    }
    
    return NULL;
}

size_t rcu_hash_counts(struct rcu_hash_table *htable)
{
    if (htable->effective_hash == 'a') {
        return HASH_CNT(hh_a, htable->hashmap_a);
    } else {
         return HASH_CNT(hh_b, htable->hashmap_b);
    }
}

void rcu_hash_commit(struct rcu_hash_table *htable)
{
    if (!htable->is_updating) {
        return;
    }

    struct rcu_hash_node *node = NULL;
    struct rcu_hash_node *tmp = NULL;

    pthread_mutex_lock(&htable->update_mutex);
    if (!htable->is_updating) {
        pthread_mutex_unlock(&htable->update_mutex);
        return;
    }

    /* updating hash_map is ready, so change effective hash_map */
    if (htable->effective_hash == 'a') {
        htable->effective_hash = 'b';
        usleep(100);
        HASH_ITER(hh_a, htable->hashmap_a, node, tmp) {
            HASH_DELETE(hh_a, htable->hashmap_a, node);
        }
    } else {
        htable->effective_hash = 'a';
        usleep(100);
        HASH_ITER(hh_b, htable->hashmap_b, node, tmp) {
            HASH_DELETE(hh_b, htable->hashmap_b, node);
        }
    }
    htable->is_updating = 0;
    //maat_garbage_collect_by_force(htable->garbage_bin);
    //rcu_garbage
    pthread_mutex_unlock(&htable->update_mutex);
}