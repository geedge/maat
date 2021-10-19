#pragma once

struct maat_kv_store;
struct maat_kv_store* maat_kv_store_new(void);
void maat_kv_store_free(struct maat_kv_store* store);
int maat_kv_register(struct maat_kv_store* store, const char* key, int value);
int maat_kv_read(struct maat_kv_store* store, const char* key, int* value);
int maat_kv_read_unNull(struct maat_kv_store* store, const char* key, size_t key_sz, int* value);
struct maat_kv_store* maat_kv_store_duplicate(struct maat_kv_store* store);


