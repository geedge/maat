/*
**********************************************************************************************
*	File: maat_kv_map.h
*   Description: str2int map api
*	Authors: Zheng chao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_KV_H_
#define _MAAT_KV_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

struct maat_kv_store;

struct maat_kv_store *maat_kv_store_new(void);

void maat_kv_store_free(struct maat_kv_store *store);

int maat_kv_register(struct maat_kv_store *store, const char *key, int value);

int maat_kv_read(struct maat_kv_store *store, const char *key, int *value);

int maat_kv_read_unNull(struct maat_kv_store *store, const char *key, size_t key_sz, int *value);

struct maat_kv_store *maat_kv_store_duplicate(struct maat_kv_store *store);

#ifdef __cplusplus
}
#endif

#endif