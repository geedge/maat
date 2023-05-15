/*
**********************************************************************************************
*	File: alignment.h
*   Description: alignment statistics 
*	Authors: Zheng Chao <zhengchao@geedgenetworks.com>
*	Date:    2022-10-31
*   Copyright: (c) Since 2022 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _ALIGNMENT_H_
#define _ALIGNMENT_H_

#ifdef __cplusplus
extern "C"
{
#endif

long long *alignment_int64_array_alloc(int size);

long long alignment_int64_array_sum(long long *array, int size);

long long alignment_int64_array_add(long long *array, int offset, long long op_val);

long long alignment_int64_array_cnt(long long *array, int size);

void alignment_int64_array_reset(long long *array, int size);

void alignment_int64_array_free(long long *array);

#ifdef __cplusplus
}
#endif

#endif