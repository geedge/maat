/*
**********************************************************************************************
*	File: maat_kv_map.cpp
*   Description:
*	Authors: Zheng chao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include <stddef.h>
#include <ctype.h>

#include "uthash/uthash.h"
#include "utils.h"

#define MAAT_KV_MAX_KEY_LEN 512

struct maat_kv_pair
{
	char* key;	//must be lower case.
	size_t keylen;
	int val;
	UT_hash_handle hh;
};

struct maat_kv_store
{
	struct maat_kv_pair* hash;
};

void strlowercase(const char* src, size_t src_len, char* dst, size_t dst_sz)
{
	for (size_t i = 0; i < src_len && i < dst_sz; i++) {
		dst[i] = tolower(src[i]);
	}
}

struct maat_kv_pair* maat_kv_pair_new(const char* key, size_t keylen, int value)
{	
	struct maat_kv_pair *kv = ALLOC(struct maat_kv_pair, 1);

	kv->key = ALLOC(char, keylen);
	kv->keylen = keylen;
	kv->val = value;

	strlowercase(key, keylen, kv->key, kv->keylen);

	return kv;
}

void maat_kv_pair_free(struct maat_kv_pair* kv)
{
	free(kv->key);
	kv->key = NULL;

	free(kv);
}

struct maat_kv_store* maat_kv_store_new(void)
{
	struct maat_kv_store* store = ALLOC(struct maat_kv_store, 1);
	return store;
}

void maat_kv_store_free(struct maat_kv_store* store)
{
	if (NULL == store) {
		return;
	}

	struct maat_kv_pair *kv = NULL; 
	struct maat_kv_pair *tmp_kv = NULL;
	
	HASH_ITER(hh, store->hash, kv, tmp_kv) {
		HASH_DEL(store->hash, kv);
		maat_kv_pair_free(kv);
	}

	free(store);
}

int maat_kv_register_unNull(struct maat_kv_store* store, const char* key, size_t keylen, int value)
{
	if (keylen > MAAT_KV_MAX_KEY_LEN) {
		return -1;
	}

	struct maat_kv_pair *kv = NULL;
	struct maat_kv_pair *tmp_kv = NULL;

	kv = maat_kv_pair_new(key, keylen, value);
	HASH_FIND(hh, store->hash, kv->key, keylen, tmp_kv);
	if (tmp_kv) {
		maat_kv_pair_free(kv);
		return -1;
	}

	HASH_ADD_KEYPTR(hh, store->hash, kv->key, keylen, kv);
	return 1;
}

int maat_kv_register(struct maat_kv_store* store, const char* key, int value)
{
	int ret = 0;
	ret = maat_kv_register_unNull(store, key, strlen(key), value);

	return ret;
}

int maat_kv_read_unNull(struct maat_kv_store* store, const char* key, size_t keylen, int* value)
{
	struct maat_kv_pair *kv = NULL;
	char key_lowercase[MAAT_KV_MAX_KEY_LEN] = {0};

	if (keylen > MAAT_KV_MAX_KEY_LEN) {
		return -1;
	}

	strlowercase(key, keylen, key_lowercase, sizeof(key_lowercase));
	HASH_FIND(hh, store->hash, key_lowercase, keylen, kv);
	if (kv) {
		*value=kv->val;
		return 1;
	} else {
		return -1;
	}
}

int maat_kv_read(struct maat_kv_store * store, const char * key, int * value)
{
	return maat_kv_read_unNull(store, key, strlen(key), value);
}