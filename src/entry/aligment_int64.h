#ifndef H_ALIGMENT_INT64_H_INCLUDE
#define H_ALIGMENT_INT64_H_INCLUDE

#include <stdlib.h>

#define	CPU_CACHE_ALIGMENT	64
typedef	long long*	mcore_long_t;

inline long long *aligment_int64_array_alloc(int size)
{
	long long *ret=NULL;
	ret=(long long*)calloc(CPU_CACHE_ALIGMENT,size);
	return ret;
}
inline long long aligment_int64_array_sum(mcore_long_t array,int size)
{	
	long long sum=0;
	int offset=0,i=0;
	for(i=0;i<size;i++)
	{
		offset=(CPU_CACHE_ALIGMENT/sizeof(long long))*i;
		sum+=array[offset];
	}
	return sum;
}
inline long long aligment_int64_array_add(mcore_long_t array,int offset,long long op_val)
{
	int idx=(CPU_CACHE_ALIGMENT/sizeof(long long))*offset;
	array[idx]+=op_val;
	return array[idx];
}
inline long long aligment_int64_array_cnt(mcore_long_t array,int size)
{
	int offset=0,i=0;
	int cnt=0;
	for(i=0;i<size;i++)
	{
		offset=(CPU_CACHE_ALIGMENT/sizeof(long long))*i;
		if(array[offset]>0)
		{
			cnt++;
		}
	}
	return cnt;
}
inline void aligment_int64_array_free(mcore_long_t array)
{
	free(array);
}

#endif

