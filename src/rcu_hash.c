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
#include <sys/queue.h>
#include <stdio.h>

#include "rcu_hash.h"
#include "maat_utils.h"

struct rcu_hash_garbage_bag {
	void *garbage;
	void (* garbage_free)(void *garbage);
	TAILQ_ENTRY(rcu_hash_garbage_bag) entries;
};
TAILQ_HEAD(rcu_hash_garbage_q, rcu_hash_garbage_bag);

struct rcu_hash_table {
    int is_updating;
    char effective_hash; // 'a' or 'b'

    /* two hash map for rcu */
    struct rcu_hash_node *hashmap_a;
    struct rcu_hash_node *hashmap_b;

    void (*data_free_fn)(void *user_ctx, void *data);
    void *user_ctx;

    struct rcu_hash_garbage_q garbage_q;
    size_t garbage_q_len;

    pthread_mutex_t update_mutex;
};

struct rcu_hash_node {
    char *key;
    size_t key_len;
    void *data; //table_runtime解析成两个成员

    /* htable the node belongs to */
    struct rcu_hash_table *htable;

    UT_hash_handle hh_a;
    UT_hash_handle hh_b;
};

void rcu_hash_garbage_queue_free(struct rcu_hash_garbage_q *garbage_q)
{
	struct rcu_hash_garbage_bag *p = NULL;

	while ((p = TAILQ_FIRST(garbage_q)) != NULL) {
		p->garbage_free(p->garbage);
		TAILQ_REMOVE(garbage_q, p, entries);
		FREE(p);
	}
}

void rcu_hash_garbage_bagging(struct rcu_hash_garbage_q* garbage_q, 
                              void* garbage, void (* func)(void *))
{
	struct rcu_hash_garbage_bag *bag = ALLOC(struct rcu_hash_garbage_bag, 1);

	bag->garbage = garbage;
	bag->garbage_free = func;
	TAILQ_INSERT_TAIL(garbage_q, bag, entries);
}

void rcu_hash_node_free(struct rcu_hash_node *node)
{
    if (NULL == node) {
        return;
    }
    
    if (node->key != NULL) {
        FREE(node->key);
    }

    if (node->data != NULL) {
        node->htable->data_free_fn(node->htable->user_ctx, node->data);
    }
    FREE(node);
}

struct rcu_hash_table *rcu_hash_new(data_free_fn *free_fn, void *user_ctx)
{
    if (NULL == free_fn) {
        return NULL;
    }

    struct rcu_hash_table *htable = ALLOC(struct rcu_hash_table, 1);

    htable->is_updating = 0;
    htable->effective_hash = 'a';
    TAILQ_INIT(&htable->garbage_q);
    htable->garbage_q_len = 0;
    htable->data_free_fn = free_fn;
    htable->user_ctx = user_ctx;
    pthread_mutex_init(&htable->update_mutex, NULL);

    return htable;
}

void rcu_hash_free(struct rcu_hash_table *htable)
{
    if (NULL == htable) {
        return;
    }

    struct rcu_hash_node *tmp = NULL;
    struct rcu_hash_node *item = NULL;
    if (htable->effective_hash == 'a') {
        HASH_ITER(hh_a, htable->hashmap_a, item, tmp) {
            HASH_DELETE(hh_a, htable->hashmap_a, item);
            rcu_hash_node_free(item);
        }
    } else {
        HASH_ITER(hh_b, htable->hashmap_b, item, tmp) {
            HASH_DELETE(hh_b, htable->hashmap_b, item);
            rcu_hash_node_free(item);
        }
    }

    rcu_hash_garbage_queue_free(&(htable->garbage_q));
    pthread_mutex_destroy(&htable->update_mutex);

    FREE(htable);
}

void rcu_hash_commit_prepare(struct rcu_hash_table *htable)
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

int rcu_hash_add(struct rcu_hash_table *htable, const char *key, 
                  size_t key_len, void *data)
{
    if (NULL == htable || NULL == key || 0 == key_len) {
        return -1;
    }

    if (!htable->is_updating) {
        rcu_hash_commit_prepare(htable);
    }

    struct rcu_hash_node *tmp = NULL;
    if (htable->effective_hash == 'a') {
        HASH_FIND(hh_b, htable->hashmap_b, key, key_len, tmp);
    } else {
        HASH_FIND(hh_a, htable->hashmap_a, key, key_len, tmp);
    }

    if (tmp != NULL) {
        return -1;
    }

    struct rcu_hash_node *node = ALLOC(struct rcu_hash_node, 1);
    node->key = ALLOC(char, key_len);
    memcpy(node->key, key, key_len);
    node->key_len = key_len;
    node->data = data;
    node->htable = htable;

    if (htable->effective_hash == 'a') {
        HASH_ADD_KEYPTR(hh_b, htable->hashmap_b, node->key, node->key_len, node);
    } else {
        HASH_ADD_KEYPTR(hh_a, htable->hashmap_a, node->key, node->key_len, node);
    }

    return 0;
}

int rcu_hash_del(struct rcu_hash_table *htable, const char *key, size_t key_len)
{
    if (NULL == htable || NULL == key || 0 == key_len) {
        return -1;
    }

    if (!htable->is_updating) {
        rcu_hash_commit_prepare(htable);
    }
    
    struct rcu_hash_node *node = NULL;
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
        rcu_hash_garbage_bagging(&(htable->garbage_q), node, 
                                 (void (*)(void*))rcu_hash_node_free);
        htable->garbage_q_len++;
    }

    return 0;
}

void *rcu_hash_find(struct rcu_hash_table *htable, const char *key, size_t key_len)
{
    if (NULL == htable || NULL == key || 0 == key_len) {
        return NULL;
    }

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

void *rcu_updating_hash_find(struct rcu_hash_table *htable, const char *key, size_t key_len)
{
     if (NULL == htable || NULL == key || 0 == key_len) {
        return NULL;
    }

    struct rcu_hash_node *node = NULL;
    if (htable->effective_hash == 'a') {
        HASH_FIND(hh_b, htable->hashmap_b, key, key_len, node);
        if (node != NULL) {
            return node->data;
        }
    } else {
        HASH_FIND(hh_a, htable->hashmap_a, key, key_len, node);
        if (node != NULL) {
            return node->data;
        }
    }

    return NULL;
}

size_t rcu_hash_count(struct rcu_hash_table *htable)
{
    if (NULL == htable) {
        return 0;
    }

    if (htable->effective_hash == 'a') {
        return HASH_CNT(hh_a, htable->hashmap_a);
    } else {
        return HASH_CNT(hh_b, htable->hashmap_b);
    }
}

int rcu_hash_is_updating(struct rcu_hash_table *htable)
{
    if (NULL == htable) {
        return 0;
    }

    return htable->is_updating;
}

void rcu_hash_commit(struct rcu_hash_table *htable)
{
    if (NULL == htable) {
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

    rcu_hash_garbage_queue_free(&(htable->garbage_q));
    htable->garbage_q_len = 0;
    
    pthread_mutex_unlock(&htable->update_mutex);
}

size_t rcu_hash_list(struct rcu_hash_table *htable, void ***data_array)
{
    size_t i = 0;
    size_t node_cnt = 0;
	struct rcu_hash_node *node = NULL, *tmp = NULL;
	
    if (htable->effective_hash == 'a') {
        node_cnt = HASH_CNT(hh_a, htable->hashmap_a);
        *data_array = ALLOC(void *, node_cnt);
        HASH_ITER(hh_a, htable->hashmap_a, node, tmp) {
            (*data_array)[i] = node->data;
            i++;
        }
    } else {
        node_cnt = HASH_CNT(hh_b, htable->hashmap_b);
        *data_array = ALLOC(void *, node_cnt);
        HASH_ITER(hh_b, htable->hashmap_b, node, tmp) {
            (*data_array)[i] = node->data;
            i++;
        }
    }

	return node_cnt;
}

size_t rcu_updating_hash_list(struct rcu_hash_table *htable, void ***data_array)
{
    if (NULL == htable || NULL == data_array) {
        return 0;
    }
    
    size_t i = 0;
    size_t node_cnt = 0;
	struct rcu_hash_node *node = NULL, *tmp = NULL;
	
    if (htable->effective_hash == 'a') {
        node_cnt = HASH_CNT(hh_b, htable->hashmap_b);
        *data_array = ALLOC(void *, node_cnt);
        HASH_ITER(hh_b, htable->hashmap_b, node, tmp) {
            (*data_array)[i] = node->data;
            i++;
        }
    } else {
        node_cnt = HASH_CNT(hh_a, htable->hashmap_a);
        *data_array = ALLOC(void *, node_cnt);
        HASH_ITER(hh_a, htable->hashmap_a, node, tmp) {
            (*data_array)[i] = node->data;
            i++;
        }
    }

    return node_cnt;
}