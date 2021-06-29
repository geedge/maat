#include "bool_matcher.h"
#include <map>
#include <vector>
#include <algorithm>
using namespace std;
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct bool_expr_item
{
	size_t item_num;
	struct bool_item * items;
};

struct bool_matcher
{
	unsigned int             bool_expr_num;
	struct bool_expr_match * bool_expr_ids;
	struct bool_expr_item *  bool_expr_items;
	unsigned int             bool_item_num;
	unsigned long long *     bool_items;
	unsigned int *           mapped_ptr;
	unsigned int *           mapped_ids;
	unsigned int             bitmap_size;
	unsigned char *          bitmap;
};

bool operator<(const struct bool_item & lhs, const struct bool_item & rhs)
{
	return lhs.item_id<rhs.item_id;
}

struct bool_matcher * bool_matcher_new(struct bool_expr * exprs, size_t expr_num, unsigned int max_thread_num, size_t * mem_size)
{
	if(exprs==NULL || expr_num==0 || max_thread_num==0) return NULL;

	unsigned int mem_bytes=0;

	struct bool_matcher * matcher=new struct bool_matcher;
	mem_bytes+=sizeof(bool_matcher);

	matcher->bool_expr_num=(unsigned int)expr_num;
	matcher->bool_expr_ids  =new struct bool_expr_match[expr_num];
	matcher->bool_expr_items=new struct bool_expr_item[expr_num];
	mem_bytes+=(unsigned int)expr_num*(sizeof(struct bool_expr_match)+sizeof(struct bool_expr_item));
	for(unsigned int i=0; i<expr_num; i++)
	{
		matcher->bool_expr_ids[i].expr_id   =exprs[i].expr_id;
		matcher->bool_expr_ids[i].user_tag  =exprs[i].user_tag;
		matcher->bool_expr_items[i].item_num=exprs[i].item_num;
		matcher->bool_expr_items[i].items=new struct bool_item[exprs[i].item_num];
		mem_bytes+=(unsigned int)exprs[i].item_num*sizeof(struct bool_item);
		copy(exprs[i].items, exprs[i].items+exprs[i].item_num, matcher->bool_expr_items[i].items);
		sort(matcher->bool_expr_items[i].items, matcher->bool_expr_items[i].items+exprs[i].item_num);
	}

	map<unsigned long long, unsigned int> M1;
	for(unsigned int i=0; i<expr_num; i++)
	{
		for(unsigned int j=0; j<exprs[i].item_num; j++)
		{
			if(exprs[i].items[j].not_flag==0) M1[exprs[i].items[j].item_id]++;
		}
	}

	map< unsigned long long, vector<unsigned int> > M2;
	for(unsigned int i=0; i<expr_num; i++)
	{
		unsigned int min_count=-1;
		unsigned long long item_id;
		for(unsigned int j=0; j<exprs[i].item_num; j++)
		{
			if(exprs[i].items[j].not_flag==0)
			{
				unsigned int c=M1[exprs[i].items[j].item_id];
				if(c<min_count)
				{
					min_count=c;
					item_id=exprs[i].items[j].item_id;
				}
			}
		}
		M2[item_id].push_back(i);
	}

	matcher->bool_item_num=(unsigned int)M2.size();
	matcher->bool_items   =new unsigned long long[M2.size()];
	matcher->mapped_ptr   =new unsigned int[M2.size()+1];
	matcher->mapped_ids   =new unsigned int[matcher->bool_expr_num];
	mem_bytes+=((unsigned int)M2.size()+1+matcher->bool_expr_num)*sizeof(unsigned int)+(unsigned int)M2.size()*sizeof(unsigned long long);

	matcher->mapped_ptr[0]=0;
	map< unsigned long long, vector<unsigned int> >::const_iterator it=M2.begin();
	for(unsigned int k=0; k<M2.size(); ++k, ++it)
	{
		matcher->bool_items[k]=it->first;
		copy(it->second.begin(), it->second.end(), matcher->mapped_ids+matcher->mapped_ptr[k]);
		matcher->mapped_ptr[k+1]=matcher->mapped_ptr[k]+(unsigned int)it->second.size();
	}

	M1.clear();
	M2.clear();

	matcher->bitmap_size=(1U<<27);
	matcher->bitmap=new unsigned char[(matcher->bitmap_size)>>3];
	mem_bytes+=(matcher->bitmap_size)>>3;
	memset(matcher->bitmap, 0, (matcher->bitmap_size)>>3);

	for(unsigned int i=0; i<matcher->bool_item_num; i++)
	{
		unsigned int j=matcher->bool_items[i]&(matcher->bitmap_size-1);
		matcher->bitmap[j>>3]|=(1U<<(j&7));
	}

	if(mem_size!=NULL) *mem_size=mem_bytes;
	return matcher;
}

int res_comp(const void * lhs, const void * rhs)
{
	bool_expr_match * _lhs=(bool_expr_match *)lhs;
	bool_expr_match * _rhs=(bool_expr_match *)rhs;
	return (_lhs->expr_id<_rhs->expr_id) ? 1 : -1;
}

int do_match(struct bool_expr_item * expr, unsigned long long * item_ids, size_t item_num)
{
	unsigned int i=0;
	for(unsigned int j=0; j<expr->item_num; ++j)
	{
		if(expr->items[j].not_flag==0)
		{
			while(i<item_num && item_ids[i]<expr->items[j].item_id) ++i;
			if(i==item_num || item_ids[i]>expr->items[j].item_id) return 0;
			++i;
		}
		else
		{
			while(i<item_num && item_ids[i]<expr->items[j].item_id) ++i;
			if(i<item_num && item_ids[i]==expr->items[j].item_id) return 0;
		}
	}

	return 1;
}

int bool_matcher_match(struct bool_matcher * matcher, unsigned int thread_id, unsigned long long * item_ids, size_t item_num, struct bool_expr_match * results, size_t n_result)
{
	if(matcher==NULL) return -1;
	if(item_num==0) return 0;

//	sort(item_ids, item_ids+item_num);
//	size_t J=0;
//	for(unsigned int i=1; i<item_num; i++)
//	{
//		if(item_ids[i]!=item_ids[J]) item_ids[++J]=item_ids[i];
//	}
//	item_num=J+1;

	unsigned int r=0;

	for(unsigned int i=0; i<item_num; i++)
	{
		unsigned int t=item_ids[i]&(matcher->bitmap_size-1);
		if((matcher->bitmap[t>>3]&(1U<<(t&7)))==0) continue;

		int l=0, h=(int)matcher->bool_item_num-1;
		while(l<=h)
		{
			int m=(l+h)/2;
			if(item_ids[i]==matcher->bool_items[m])
			{
				for(unsigned int j=matcher->mapped_ptr[m]; j<matcher->mapped_ptr[m+1]; j++)
				{
					unsigned int idx=matcher->mapped_ids[j];
					int ret=do_match(matcher->bool_expr_items+idx, item_ids, item_num);
					if(ret==1)
					{
						if(r==n_result) goto END;
						results[r++]=matcher->bool_expr_ids[idx];
					}
				}
				break;
			}
			else if(item_ids[i]<matcher->bool_items[m])
			{
				h=m-1;
			}
			else
			{
				l=m+1;
			}
		}
	}

END:
	qsort(results, r, sizeof(bool_expr_match), res_comp);
	return r;
}

void bool_matcher_free(struct bool_matcher * matcher)
{
	if(matcher==NULL) return;

	delete [] matcher->bool_expr_ids;
	for(unsigned int i=0; i<matcher->bool_expr_num; i++) delete [] matcher->bool_expr_items[i].items;
	delete [] matcher->bool_expr_items;

	delete [] matcher->bool_items;
	delete [] matcher->mapped_ptr;
	delete [] matcher->mapped_ids;
	delete [] matcher->bitmap;
	delete matcher;
	return;
}
