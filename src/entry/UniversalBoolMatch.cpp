#include "UniversalBoolMatch.h"
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
	unsigned char * bitmap;
	unsigned int *  matched_bitmap;
};

struct boolexpr_matcher_t
{
	unsigned int          max_thread_num;
	unsigned int          bool_expr_num;
	unsigned int          multi_expr_num;
	void **               bool_expr_ids;
	unsigned char *       multi_expr_size;
	unsigned int          bool_item_id_num;
	unsigned int          min_item_id;
	unsigned int          max_item_id;
	unsigned int *        bool_item_ids;
	unsigned int *        mapped_ptr;
	unsigned int *        mapped_ids;
	unsigned int          theta;
	unsigned int          L[65537];
	thread_local_data_t * thread_data;
};

void * boolexpr_initialize(universal_bool_expr_t * bool_exprs, unsigned int bool_expr_num, unsigned int max_thread_num, unsigned int * mem_size)
{
	if(bool_exprs==NULL || bool_expr_num==0 || max_thread_num==0) return NULL;

	for(unsigned int i=0; i<bool_expr_num; i++)
	{
		if(bool_exprs[i].bool_item_num==0 || bool_exprs[i].bool_item_num>MAX_ITEMS_PER_BOOL_EXPR)
		{
			return NULL;
		}
	}

	int I=-1, J=(int)bool_expr_num;
	while(I<J)
	{
		I++;
		while(I<J && bool_exprs[I].bool_item_num>1) I++;
		if(I==J) break;
		J--;
		while(J>I && bool_exprs[J].bool_item_num==1) J--;
		if(J==I) break;
		swap(bool_exprs[I], bool_exprs[J]);
	}

	for(int k=0; k<(int)bool_expr_num; k++)
	{
		if((k<I && bool_exprs[k].bool_item_num==1) || (k>=I && bool_exprs[k].bool_item_num>1))
		{
			printf("[%s:%d]: fatal error!\n", __FILE__, __LINE__);
			return NULL;
		}
	}

	unsigned int mem_bytes=0;

	boolexpr_matcher_t * matcher=new boolexpr_matcher_t;
	mem_bytes+=sizeof(boolexpr_matcher_t);

	matcher->max_thread_num=max_thread_num;
	matcher->bool_expr_num=bool_expr_num;
	matcher->multi_expr_num=I;

	matcher->bool_expr_ids=new void *[bool_expr_num];
	mem_bytes+=bool_expr_num*sizeof(void *);

	matcher->multi_expr_size=new unsigned char[matcher->multi_expr_num+1];
	mem_bytes+=(matcher->multi_expr_num+1)*sizeof(unsigned char);

	matcher->thread_data=new thread_local_data_t[max_thread_num];
	mem_bytes+=max_thread_num*sizeof(thread_local_data_t);

	for(unsigned int i=0; i<max_thread_num; i++)
	{		
		matcher->thread_data[i].bitmap=new unsigned char[matcher->multi_expr_num+1];
		mem_bytes+=(matcher->multi_expr_num+1)*sizeof(unsigned char);

		unsigned int size=(bool_expr_num-matcher->multi_expr_num);
		size=(size>>5)+1;
		matcher->thread_data[i].matched_bitmap=new unsigned int[size];
		mem_bytes+=size*sizeof(unsigned int);
	}

	map< unsigned int, vector<unsigned int> > M;
	unsigned int count=0;
	for(unsigned int i=0; i<bool_expr_num; i++)
	{
		matcher->bool_expr_ids[i] =bool_exprs[i].bool_expr_id;
		if(i<matcher->multi_expr_num)
		{
			matcher->multi_expr_size[i]=bool_exprs[i].bool_item_num;
		}
		count+=bool_exprs[i].bool_item_num;
		for(unsigned int j=0; j<bool_exprs[i].bool_item_num; j++)
		{
			M[bool_exprs[i].bool_item_ids[j]].push_back((i<<3)|j);
		}
	}

	matcher->bool_item_id_num=(unsigned int)M.size();
	matcher->bool_item_ids=new unsigned int[M.size()];
	matcher->mapped_ptr   =new unsigned int[M.size()+1];
	matcher->mapped_ids   =new unsigned int[count];
	mem_bytes+=(2*(unsigned int)M.size()+1+count)*sizeof(unsigned int);

	matcher->mapped_ptr[0]=0;
	map< unsigned int, vector<unsigned int> >::const_iterator it=M.begin();
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

	unsigned long long ONE=1;
	unsigned int theta=0;
	while((ONE<<(theta+16))<=matcher->bool_item_ids[M.size()-1]) theta++;
	matcher->theta=theta;
	
	matcher->L[0]=0;
	for(unsigned int i=1; i<65536; i++)
	{
		matcher->L[i]=(unsigned int)(lower_bound(matcher->bool_item_ids, matcher->bool_item_ids+M.size(), i*(1U<<theta))-matcher->bool_item_ids);
	}
	matcher->L[65536]=(unsigned int)M.size();

	M.clear();

	*mem_size=mem_bytes;
	return matcher;
}

int boolexpr_match(void * instance, unsigned int thread_id, unsigned int * item_ids, unsigned int item_num, void ** result, unsigned int size)
{
	if(instance==NULL) return -1;

	boolexpr_matcher_t * matcher=(boolexpr_matcher_t *)instance;
	if(thread_id>=matcher->max_thread_num) return -1;

	unsigned int * mapped_ids=matcher->thread_data[thread_id].mapped_ids;
	unsigned int ids_num=0;
	for(unsigned int i=0; i<item_num; i++)
	{
		if(item_ids[i]<matcher->min_item_id || item_ids[i]>matcher->max_item_id) continue;

		unsigned int id=item_ids[i]-matcher->min_item_id;
		unsigned int k=id>>matcher->theta;

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

	unsigned char * bitmap=matcher->thread_data[thread_id].bitmap;
	unsigned int * matched_bitmap=matcher->thread_data[thread_id].matched_bitmap;
	for(unsigned int i=0; i<used_num; i++)
	{
		if(used_cells[i]<matcher->multi_expr_num)
		{
			bitmap[used_cells[i]]=0;
		}
		else
		{
			unsigned int j=used_cells[i]-matcher->multi_expr_num;
			matched_bitmap[j>>5]&=~(1U<<(j&31));
		}
	}

	unsigned int r=0;

	for(unsigned int i=0; i<ids_num; i++)
	{
		unsigned int x=(mapped_ids[i]>>3);
		if(x<matcher->multi_expr_num)
		{
			unsigned int y=(mapped_ids[i]&7);
			if((bitmap[x]&(1U<<y))==0)
			{
				bitmap[x]|=(1U<<y);
				if(bitmap[x]==(1U<<matcher->multi_expr_size[x])-1)
				{
					if(r<size) result[r++]=matcher->bool_expr_ids[x];
				}
			}
		}
		else
		{
			unsigned int j=x-matcher->multi_expr_num;
			if((matched_bitmap[j>>5]&(1U<<(j&31)))==0)
			{
				if(r<size) result[r++]=matcher->bool_expr_ids[x];
				matched_bitmap[j>>5]|=(1U<<(j&31));
			}
		}
	}

	return r;
}

void boolexpr_destroy(void * instance)
{
	if(instance!=NULL)
	{
		boolexpr_matcher_t * matcher=(boolexpr_matcher_t *)instance;
		delete [] matcher->bool_expr_ids;
		delete [] matcher->multi_expr_size;
		delete [] matcher->bool_item_ids;
		delete [] matcher->mapped_ptr;
		delete [] matcher->mapped_ids;
		for(unsigned int i=0; i<matcher->max_thread_num; i++)
		{
			delete [] matcher->thread_data[i].bitmap;
		}
		delete [] matcher->thread_data;
		delete matcher;
	}
}
