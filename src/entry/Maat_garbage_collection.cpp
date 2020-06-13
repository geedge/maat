
#include "Maat_utils.h"

#include <time.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <assert.h>

struct Maat_garbage_bag
{
	time_t create_time;
	int timeout;
	int ok_times;
	void *garbage;
	void (* garbage_free)(void *garbage);
	TAILQ_ENTRY(Maat_garbage_bag) entries;
};
TAILQ_HEAD(Maat_garbage_q, Maat_garbage_bag);

struct Maat_garbage_bin
{
	Maat_garbage_q garbage_q;
	size_t bag_cnt;
	int timeout_seconds;
};
struct Maat_garbage_bin* Maat_garbage_bin_new(int default_timeout)
{
	struct Maat_garbage_bin* bin=ALLOC(struct Maat_garbage_bin, 1);
	TAILQ_INIT(&bin->garbage_q);
	bin->timeout_seconds=default_timeout;
	return bin;
}
void Maat_garbage_bin_free(struct Maat_garbage_bin* bin)
{
	struct Maat_garbage_bag* p=NULL;
	while (p=TAILQ_FIRST(&bin->garbage_q))
	{
		p->garbage_free(p->garbage);
		TAILQ_REMOVE(&bin->garbage_q, p, entries);
		free(p);
	}

	free(bin);
	return;
}
void Maat_garbage_bagging(struct Maat_garbage_bin* bin, void* garbage, void (* func)(void *))
{
	struct Maat_garbage_bag* bag=ALLOC(	struct Maat_garbage_bag, 1);
	bag->create_time=time(NULL);
	bag->timeout=bin->timeout_seconds;
	bag->garbage=garbage;
	bag->garbage_free=func;
	TAILQ_INSERT_TAIL(&bin->garbage_q, bag, entries);
	bin->bag_cnt++;
}
void Maat_garbage_collect_routine(struct Maat_garbage_bin* bin)
{
	struct Maat_garbage_bag* p=NULL, *tmp=NULL;
	size_t n_clollected=0, n_bag=0;
	time_t now=time(NULL);

	for(p=TAILQ_FIRST(&bin->garbage_q); p!=NULL; p=tmp)
	{
		tmp=TAILQ_NEXT(p, entries);
		if(now-p->create_time>p->timeout)
		{
			p->garbage_free(p->garbage);
			TAILQ_REMOVE(&bin->garbage_q, p, entries);
			free(p);
			n_clollected++;
		}
		n_bag++;
	}

	assert(bin->bag_cnt==n_bag);
	bin->bag_cnt-=n_clollected;
	return;
}

