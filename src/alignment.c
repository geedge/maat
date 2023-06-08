/*
**********************************************************************************************
*	File: alignment.c
*   Description:
*	Authors: Zheng Chao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include <stdlib.h>
#include <string.h>

#include "alignment.h"

#define	CPU_CACHE_ALIGMENT	64

inline long long *alignment_int64_array_alloc(int size)
{
	return (long long *)calloc(CPU_CACHE_ALIGMENT, size);
}

inline long long alignment_int64_array_sum(long long *array, int size)
{	
    int offset = 0;
	long long sum = 0;
	
	for (int i = 0; i < size; i++) {
		offset = (CPU_CACHE_ALIGMENT / sizeof(long long)) * i;
		sum += array[offset];
	}

	return sum;
}

inline long long alignment_int64_array_add(long long *array, int offset,
                                           long long op_val)
{
	int idx = (CPU_CACHE_ALIGMENT / sizeof(long long)) * offset;
	array[idx] += op_val;

	return array[idx];
}

inline long long alignment_int64_array_cnt(long long *array, int size)
{
	int offset = 0;
	int cnt = 0;

	for (int i = 0; i < size; i++) {
		offset = (CPU_CACHE_ALIGMENT / sizeof(long long)) * i;
		if (array[offset] > 0) {
			cnt++;
		}
	}

	return cnt;
}

inline void alignment_int64_array_reset(long long *array, int size)
{
	memset(array, 0, CPU_CACHE_ALIGMENT * size);
}

inline void alignment_int64_array_free(long long *array)
{
	free(array);
}