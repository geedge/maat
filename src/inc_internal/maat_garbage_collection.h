/*
**********************************************************************************************
*	File: maat_garbage_collection.h
*   Description: maat gc
*	Authors: Zhengchao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#ifndef _MAAT_GARBAGE_COLLECTION_H_
#define _MAAT_GARBAGE_COLLECTION_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

struct maat_garbage_bin;

struct maat_garbage_bin *maat_garbage_bin_new(int default_timeout);

void maat_garbage_bin_free(struct maat_garbage_bin *bin);

void maat_garbage_bagging(struct maat_garbage_bin *bin, void *garbage, void *arg,
                          void (* func)(void *, void *));

void maat_garbage_collect_routine(struct maat_garbage_bin *bin);

size_t maat_garbage_bin_get_size(struct maat_garbage_bin *bin);

void maat_garbage_collect_by_force(struct maat_garbage_bin *bin);

#ifdef __cplusplus
}
#endif

#endif