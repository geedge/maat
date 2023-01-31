/*
**********************************************************************************************
*	File: maat_garbage_collection.h
*   Description:
*	Authors: Zhengchao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) 2018-2022 Geedge Networks, Inc. All rights reserved.
***********************************************************************************************
*/

#include "utils.h"

#include <time.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <assert.h>

struct maat_garbage_bag {
	time_t create_time;
	int timeout;
	int ok_times;
	void *garbage;
	void (* garbage_free)(void *garbage);
	TAILQ_ENTRY(maat_garbage_bag) entries;
};
TAILQ_HEAD(maat_garbage_q, maat_garbage_bag);

struct maat_garbage_bin {
	struct maat_garbage_q garbage_q;
	size_t bag_cnt;
	int timeout_seconds;
};

struct maat_garbage_bin *maat_garbage_bin_new(int default_timeout)
{
	struct maat_garbage_bin* bin = ALLOC(struct maat_garbage_bin, 1);

	TAILQ_INIT(&bin->garbage_q);
	bin->timeout_seconds = default_timeout;

	return bin;
}

void maat_garbage_bin_free(struct maat_garbage_bin* bin)
{
	struct maat_garbage_bag *p = NULL;

	while (p = TAILQ_FIRST(&bin->garbage_q)) {
		p->garbage_free(p->garbage);
		TAILQ_REMOVE(&bin->garbage_q, p, entries);
		FREE(p);
		bin->bag_cnt--;
	}

	FREE(bin);
}

size_t  maat_garbage_bin_get_size(struct maat_garbage_bin* bin)
{
	return bin->bag_cnt;
}

void maat_garbage_bagging(struct maat_garbage_bin* bin, void* garbage, void (* func)(void *))
{
	struct maat_garbage_bag *bag = ALLOC(struct maat_garbage_bag, 1);

	bag->create_time = time(NULL);
	bag->timeout = bin->timeout_seconds;
	bag->garbage = garbage;
	bag->garbage_free = func;
	TAILQ_INSERT_TAIL(&bin->garbage_q, bag, entries);
	bin->bag_cnt++;
}
void maat_garbage_collect_routine(struct maat_garbage_bin* bin)
{
	struct maat_garbage_bag *p = NULL, *tmp = NULL;
	size_t n_clollected = 0, n_bag = 0;
	time_t now = time(NULL);

	for (p = TAILQ_FIRST(&bin->garbage_q); p != NULL; p = tmp) {
		tmp = TAILQ_NEXT(p, entries);
		if ((now - p->create_time) > p->timeout || p->timeout == 0) {
			p->garbage_free(p->garbage);
			TAILQ_REMOVE(&bin->garbage_q, p, entries);
			FREE(p);
			n_clollected++;
		}
		n_bag++;
	}

	assert(bin->bag_cnt == n_bag);
	bin->bag_cnt -= n_clollected;
}

void maat_garbage_collect_by_force(struct maat_garbage_bin* bin)
{
	struct maat_garbage_bag *p = NULL;
	while (p = TAILQ_FIRST(&bin->garbage_q)) {
		p->garbage_free(p->garbage);
		TAILQ_REMOVE(&bin->garbage_q, p, entries);
		FREE(p);
		bin->bag_cnt--;
	}
}