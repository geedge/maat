#include <stdio.h>
#include <stdlib.h>

#include "interval_matcher.h"
#include "cgranges.h"

#ifndef        MIN
#define        MIN(a,b)        ((a)>(b) ? (b) : (a))
#endif

struct interval_matcher 
{
	cgranges_t *cr;
	size_t      n_rule;
};

struct interval_matcher *interval_matcher_new(struct interval_rule *rule, size_t n_rule)
{
	if (!rule || !n_rule)
	{
		return NULL;
	}

	struct interval_matcher *matcher = (struct interval_matcher *)calloc(sizeof(struct interval_matcher), 1);
	user_label_t label;
	matcher->cr = cr_init();
	matcher->n_rule = n_rule;

	for(size_t i = 0; i < n_rule; i ++)
	{	
		label = rule[i].result;

		cr_add(matcher->cr, rule[i].start, rule[i].end + 1, label);
	}

	cr_index(matcher->cr);
	if (matcher->cr->root_k == -1)
	{
		return NULL;
	}

	return matcher;
}

void interval_matcher_free(struct interval_matcher *interval_matcher)
{
	if (!interval_matcher)
	{
		return;
	}

	cr_destroy(interval_matcher->cr);
	free(interval_matcher);
	interval_matcher = NULL;

	return;
}


int interval_matcher_match(struct interval_matcher *interval_matcher, uint64_t target, struct interval_result *result, size_t n_result)
{
	if (interval_matcher == NULL || result == NULL || n_result == 0 || target == (uint64_t)(-1)) 
	{
		return -1;
	}

	int64_t i, n, *b = 0, max_b = 0;

	n = cr_overlap(interval_matcher->cr, target, target + 1, &b, &max_b);
	if (n <= 0 || b == NULL || max_b == 0)
	{
		return 0;
	} 
	
	n = MIN(MIN((uint64_t)n, n_result), (uint32_t)(-1));
	
	for (i = 0; i < n; i ++)
	{
		result[i] = interval_matcher->cr->r[b[i]].label;
	}

	free(b);
	b = NULL;

	return (int)n;
}
