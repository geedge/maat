/*
**********************************************************************************************
*	File: maat_kv.c
*   Description:
*	Authors: Zheng chao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <ctype.h>

#include "uthash/uthash.h"
#include "maat_utils.h"
#include "maat_kv.h"

#define MAAT_KV_MAX_KEY_LEN 512
#define MAX_ENTITY_ID_CNT 4

struct kv_entity {
    long long id[MAX_ENTITY_ID_CNT];
    int id_cnt; //0~4
};

struct maat_kv_pair
{
	char* key;	//must be lower case.
	size_t key_len;
	struct kv_entity *val;
	UT_hash_handle hh;
};

struct maat_kv_store
{
	struct maat_kv_pair* hash;
};

static void strlowercase(const char* src, size_t src_len, char* dst, size_t dst_sz)
{
	for (size_t i = 0; i < src_len && i < dst_sz; i++) {
		dst[i] = tolower(src[i]);
	}
}

static struct maat_kv_pair *
maat_kv_pair_new(const char* key, size_t keylen, long long value)
{	
	struct maat_kv_pair *kv = ALLOC(struct maat_kv_pair, 1);

	kv->key = ALLOC(char, keylen);
	kv->key_len = keylen;
	kv->val = ALLOC(struct kv_entity, 1);

	strlowercase(key, keylen, kv->key, kv->key_len);
	kv->val->id[0] = value;
	kv->val->id_cnt = 1;

	return kv;
}

static struct maat_kv_pair *
maat_kv_pair_clone(const char *key, size_t key_len, struct kv_entity *entity)
{
	struct maat_kv_pair *kv = ALLOC(struct maat_kv_pair, 1);

	kv->key = ALLOC(char, key_len);
	kv->key_len = key_len;
	kv->val = ALLOC(struct kv_entity, 1);

	strlowercase(key, key_len, kv->key, kv->key_len);
	*(kv->val) = *entity;

	return kv;
}

static void maat_kv_pair_free(struct maat_kv_pair *kv)
{
    if (NULL == kv) {
        return;
    }

	if (kv->key != NULL) {
        FREE(kv->key);
    }

	if (kv->val != NULL) {
		FREE(kv->val);
	}

	FREE(kv);
}

struct maat_kv_store* maat_kv_store_new(void)
{
	struct maat_kv_store *store = ALLOC(struct maat_kv_store, 1);
	return store;
}

void maat_kv_store_free(struct maat_kv_store *store)
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

	FREE(store);
}

static int maat_kv_register_unNull(struct maat_kv_store *store, const char *key,
                            	   size_t keylen, long long value)
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

int maat_kv_register(struct maat_kv_store* store, const char *key, long long value)
{
	int ret = 0;
	ret = maat_kv_register_unNull(store, key, strlen(key), value);

	return ret;
}

int maat_kv_read_unNull(struct maat_kv_store *store, const char *key, size_t keylen,
						long long *value_array, size_t n_array)
{
	struct maat_kv_pair *kv = NULL;
	char key_lowercase[MAAT_KV_MAX_KEY_LEN] = {0};

	if (keylen > MAAT_KV_MAX_KEY_LEN) {
		return -1;
	}

	strlowercase(key, keylen, key_lowercase, sizeof(key_lowercase));
	HASH_FIND(hh, store->hash, key_lowercase, keylen, kv);

	int i = 0;
	if (kv) {
		for (i = 0; i < kv->val->id_cnt && i < (int)n_array; i++) {
			value_array[i] = kv->val->id[i];
		}
		return i;
	} else {
		return -1;
	}
}

int maat_kv_read(struct maat_kv_store *store, const char * key,
				 long long *value_array, size_t n_array)
{
	return maat_kv_read_unNull(store, key, strlen(key), value_array, n_array);
}

int maat_kv_write_unNull(struct maat_kv_store* store, const char* key,
                         size_t key_len, long long value)
{
    struct maat_kv_pair *kv = NULL;
	char key_lowercase[MAAT_KV_MAX_KEY_LEN] = {0};

	if (key_len > MAAT_KV_MAX_KEY_LEN) {
		return -1;
	}

    strlowercase(key, key_len, key_lowercase, sizeof(key_lowercase));
    HASH_FIND(hh, store->hash, key_lowercase, key_len, kv);
    if (kv) {
		kv->val->id[0] = value;
		kv->val->id_cnt = 1;
    } else {
        kv = maat_kv_pair_new(key, key_len, value);
        HASH_ADD_KEYPTR(hh, store->hash, kv->key, key_len, kv);
    }

    return 1;
}

int maat_kv_write(struct maat_kv_store *store, const char *key, long long value)
{
    return maat_kv_write_unNull(store, key, strlen(key), value);
}

int maat_kv_append_unNull(struct maat_kv_store* store, const char* key,
                          size_t key_len, long long value)
{
    struct maat_kv_pair *kv = NULL;
	char key_lowercase[MAAT_KV_MAX_KEY_LEN] = {0};

	if (key_len > MAAT_KV_MAX_KEY_LEN) {
		return -1;
	}

    strlowercase(key, key_len, key_lowercase, sizeof(key_lowercase));
    HASH_FIND(hh, store->hash, key_lowercase, key_len, kv);
    if (kv) {
        size_t id_cnt = kv->val->id_cnt;
		if (id_cnt >= MAX_ENTITY_ID_CNT) {
			return -1;
		}

		kv->val->id[id_cnt] = value;
		kv->val->id_cnt++;
    } else {
        kv = maat_kv_pair_new(key, key_len, value);
        HASH_ADD_KEYPTR(hh, store->hash, kv->key, key_len, kv);
    }

    return 1;
}

int maat_kv_append(struct maat_kv_store *store, const char *key, long long value)
{
	return maat_kv_append_unNull(store, key, strlen(key), value);
}

struct maat_kv_store *maat_kv_store_duplicate(struct maat_kv_store *origin_map)
{
	struct maat_kv_store *target = maat_kv_store_new();
	struct maat_kv_pair *kv = NULL, *tmp_kv = NULL, *copy_kv = NULL;

	HASH_ITER (hh, origin_map->hash, kv, tmp_kv) {
		copy_kv = maat_kv_pair_clone(kv->key, kv->key_len, kv->val);
		HASH_ADD_KEYPTR(hh, target->hash, copy_kv->key, copy_kv->key_len, copy_kv);
	}
	
	return target;
}