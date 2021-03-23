#include "bool_matcher.h"
#include <map>
#include <vector>
#include <algorithm>
using namespace std;
#include <stdlib.h>
#include <stdio.h>

static const unsigned int MAX_ARRAY_SIZE=65536;

struct thread_local_data_t
{
	unsigned int    mapped_ids[MAX_ARRAY_SIZE];
	unsigned int    used_cells[MAX_ARRAY_SIZE];
	bool_expr_match cached_results[MAX_ARRAY_SIZE];
	unsigned char * multiexpr_bitmap;
	unsigned int *  singlexpr_bitmap;
};

struct bool_matcher
{
	unsigned int          max_thread_num;
	unsigned int          bool_expr_num;
	unsigned int          multi_expr_num;
	bool_expr_match *     bool_expr_ids;
	unsigned char *       multi_expr_size;
	unsigned char *       multi_expr_mask;
	unsigned int          bool_item_id_num;
	unsigned long long    min_item_id;
	unsigned long long    max_item_id;
	unsigned long long *  bool_item_ids;
	unsigned int *        mapped_ptr;
	unsigned int *        mapped_ids;
	unsigned int          theta;
	unsigned int          L[65537];
	thread_local_data_t * thread_data;
};

struct bool_matcher * bool_matcher_new(struct bool_expr * exprs, size_t expr_num, unsigned int max_thread_num, size_t * mem_size)
{
	if(exprs==NULL || expr_num==0 || max_thread_num==0) return NULL;

	for(unsigned int i=0; i<expr_num; i++)
	{
		if(exprs[i].item_num==0 || exprs[i].item_num>MAX_ITEMS_PER_BOOL_EXPR)
		{
			return NULL;
		}
	}

	int I=-1, J=(int)expr_num;
	while(I<J)
	{
		I++;
		while(I<J && exprs[I].item_num>1) I++;
		if(I==J) break;
		J--;
		while(J>I && exprs[J].item_num==1) J--;
		if(J==I) break;
		swap(exprs[I], exprs[J]);
	}

	for(int k=0; k<(int)expr_num; k++)
	{
		if((k<I && exprs[k].item_num==1) || (k>=I && exprs[k].item_num>1))
		{
			printf("[%s:%d]: fatal error!\n", __FILE__, __LINE__);
			return NULL;
		}
	}

	unsigned int mem_bytes=0;

	struct bool_matcher * matcher=new struct bool_matcher;
	mem_bytes+=sizeof(bool_matcher);

	matcher->max_thread_num=max_thread_num;
	matcher->bool_expr_num=(unsigned int)expr_num;
	matcher->multi_expr_num=I;

	matcher->bool_expr_ids=new bool_expr_match[expr_num];
	mem_bytes+=(unsigned int)expr_num*sizeof(bool_expr_match);

	matcher->multi_expr_size=new unsigned char[matcher->multi_expr_num+1];
	mem_bytes+=(matcher->multi_expr_num+1)*sizeof(unsigned char);

	matcher->multi_expr_mask=new unsigned char[matcher->multi_expr_num+1];
	mem_bytes+=(matcher->multi_expr_num+1)*sizeof(unsigned char);

	matcher->thread_data=new thread_local_data_t[max_thread_num];
	mem_bytes+=max_thread_num*sizeof(thread_local_data_t);

	for(unsigned int i=0; i<max_thread_num; i++)
	{		
		matcher->thread_data[i].multiexpr_bitmap=new unsigned char[matcher->multi_expr_num+1];
		mem_bytes+=(matcher->multi_expr_num+1)*sizeof(unsigned char);

		unsigned int size=(unsigned int)(expr_num-matcher->multi_expr_num);
		size=(size>>5)+1;
		matcher->thread_data[i].singlexpr_bitmap=new unsigned int[size];
		mem_bytes+=size*sizeof(unsigned int);
	}

	map< unsigned long long, vector<unsigned int> > M;
	unsigned int count=0;
	for(unsigned int i=0; i<expr_num; i++)
	{
		matcher->bool_expr_ids[i].expr_id=exprs[i].expr_id;
		matcher->bool_expr_ids[i].user_tag=exprs[i].user_tag;
		if(i<matcher->multi_expr_num)
		{
			matcher->multi_expr_size[i]=(unsigned int)exprs[i].item_num;
		}
		count+=(unsigned int)exprs[i].item_num;
		unsigned char mask=0;
		for(unsigned int j=0; j<exprs[i].item_num; j++)
		{
			if(exprs[i].items[j].not_flag==1) mask|=(1U<<j);
			M[exprs[i].items[j].item_id].push_back((i<<3)|j);
		}
		if(i<matcher->multi_expr_num) matcher->multi_expr_mask[i]=mask;
	}

	matcher->bool_item_id_num=(unsigned int)M.size();
	matcher->bool_item_ids=new unsigned long long[M.size()];
	matcher->mapped_ptr   =new unsigned int[M.size()+1];
	matcher->mapped_ids   =new unsigned int[count];
	mem_bytes+=((unsigned int)M.size()+1+count)*sizeof(unsigned int)+(unsigned int)M.size()*sizeof(unsigned long long);

	matcher->mapped_ptr[0]=0;
	map< unsigned long long, vector<unsigned int> >::const_iterator it=M.begin();
	for(unsigned int k=0; k<M.size(); ++k, ++it)
	{
		matcher->bool_item_ids[k]=it->first;
		copy(it->second.begin(), it->second.end(), matcher->mapped_ids+matcher->mapped_ptr[k]);
		matcher->mapped_ptr[k+1]=matcher->mapped_ptr[k]+(unsigned int)it->second.size();
	}

	matcher->min_item_id=matcher->bool_item_ids[0];
	matcher->max_item_id=matcher->bool_item_ids[M.size()-1];
	for(unsigned int k=0; k<M.size(); ++k)
	{
		matcher->bool_item_ids[k]-=matcher->min_item_id;
	}

	const unsigned long long ONE=1;
	unsigned int theta=0;
	while((ONE<<(theta+16))<=matcher->bool_item_ids[M.size()-1]) theta++;
	matcher->theta=theta;
	
	matcher->L[0]=0;
	for(unsigned int i=1; i<65536; i++)
	{
		matcher->L[i]=(unsigned int)(lower_bound(matcher->bool_item_ids, matcher->bool_item_ids+M.size(), i*(ONE<<theta))-matcher->bool_item_ids);
	}
	matcher->L[65536]=(unsigned int)M.size();

	M.clear();

	*mem_size=mem_bytes;
	return matcher;
}

int res_comp(const void * lhs, const void * rhs)
{
	bool_expr_match * _lhs=(bool_expr_match *)lhs;
	bool_expr_match * _rhs=(bool_expr_match *)rhs;
	return (_lhs->expr_id<_rhs->expr_id) ? 1 : -1;
}

int bool_matcher_match(struct bool_matcher * matcher, unsigned int thread_id, const unsigned long long * item_ids, size_t item_num, struct bool_expr_match * results, size_t n_result)
{
	if(matcher==NULL) return -1;
	if(thread_id>=matcher->max_thread_num) return -1;

	unsigned int * mapped_ids=matcher->thread_data[thread_id].mapped_ids;
	unsigned int ids_num=0;
	for(unsigned int i=0; i<item_num; i++)
	{
		if(item_ids[i]<matcher->min_item_id || item_ids[i]>matcher->max_item_id) continue;

		unsigned long long id=item_ids[i]-matcher->min_item_id;
		unsigned int k=(unsigned int)(id>>matcher->theta);

		int l=matcher->L[k], h=(int)matcher->L[k+1]-1;
		if(h<l) continue;
		while(l<=h)
		{
			int m=(l+h)/2;
			if(id<matcher->bool_item_ids[m]) h=m-1;
			else l=m+1;
		}
		if(h<(int)matcher->L[k] || matcher->bool_item_ids[h]!=id) continue;

		for(unsigned int j=matcher->mapped_ptr[h]; j<matcher->mapped_ptr[h+1]; j++)
		{
			if(ids_num==MAX_ARRAY_SIZE) return -1;
			mapped_ids[ids_num++]=matcher->mapped_ids[j];
		}
	}

	unsigned int * used_cells=matcher->thread_data[thread_id].used_cells;
	unsigned int used_num=0;
	for(unsigned int i=0; i<ids_num; i++)
	{
		if(used_num==MAX_ARRAY_SIZE) return -1;
		used_cells[used_num++]=(mapped_ids[i]>>3);
	}

	unsigned char * m_bitmap=matcher->thread_data[thread_id].multiexpr_bitmap;
	unsigned int *  s_bitmap=matcher->thread_data[thread_id].singlexpr_bitmap;
	unsigned char * m_mask=matcher->multi_expr_mask;
	for(unsigned int i=0; i<used_num; i++)
	{
		if(used_cells[i]<matcher->multi_expr_num)
		{
			m_bitmap[used_cells[i]]=m_mask[used_cells[i]];
		}
		else
		{
			unsigned int j=used_cells[i]-matcher->multi_expr_num;
			s_bitmap[j>>5]&=~(1U<<(j&31));
		}
	}

	for(unsigned int i=0; i<ids_num; i++)
	{
		unsigned int x=(mapped_ids[i]>>3);
		if(x<matcher->multi_expr_num)
		{
			unsigned int y=(mapped_ids[i]&7);
			if(m_mask[x]&(1U<<y))
			{
				m_bitmap[x]&=~(1U<<y);
			}
			else
			{
				m_bitmap[x]|=(1U<<y);
			}
		}
		else
		{
			unsigned int j=x-matcher->multi_expr_num;
			s_bitmap[j>>5]|=(1U<<(j&31));
		}
	}

	unsigned int r=0;
	bool_expr_match * cached_results=matcher->thread_data[thread_id].cached_results;

	for(unsigned int i=0; i<used_num; i++)
	{
		unsigned int x=used_cells[i];
		if(x<matcher->multi_expr_num)
		{
			if(m_bitmap[x]==(1U<<matcher->multi_expr_size[x])-1)
			{
				if(r<MAX_ARRAY_SIZE) cached_results[r++]=matcher->bool_expr_ids[x];
			}
		}
		else
		{
			unsigned int j=used_cells[i]-matcher->multi_expr_num;
			if((s_bitmap[j>>5]&(1U<<(j&31)))!=0)
			{
				if(r<MAX_ARRAY_SIZE) cached_results[r++]=matcher->bool_expr_ids[x];
			}
		}
	}

	qsort(cached_results, r, sizeof(bool_expr_match), res_comp);

	int I=0;
	for(unsigned int J=0; J<r; ++J)
	{
		if(I==0 || cached_results[J].expr_id!=results[I-1].expr_id)
		{
			if(I==(int)n_result) return I;
			results[I++]=cached_results[J];
		}
	}

	return I;
}

void bool_matcher_free(struct bool_matcher * matcher)
{
	if(matcher==NULL) return;

	delete [] matcher->bool_expr_ids;
	delete [] matcher->multi_expr_size;
	delete [] matcher->multi_expr_mask;
	delete [] matcher->bool_item_ids;
	delete [] matcher->mapped_ptr;
	delete [] matcher->mapped_ids;
	for(unsigned int i=0; i<matcher->max_thread_num; i++)
	{
		delete [] matcher->thread_data[i].multiexpr_bitmap;
		delete [] matcher->thread_data[i].singlexpr_bitmap;
	}
	delete [] matcher->thread_data;
	delete matcher;
	return;
}
