/*
 *
 * Copyright (c) 2008-2016
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2016-05-31
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef H_SIGMA_STAR_TOOLS_H
#define H_SIGMA_STAR_TOOLS_H

#include <stdlib.h>
#include <vector>
#include <string>
#include <map>
//#include "./StringMatch/include/string_matching.h"
using namespace std;

//#define DEBUG_PARTITION

int initialize_sigmastar_tools();

struct packedRT_t
{
	unsigned long long bitmap[4];
	unsigned int A;
	unsigned char B[4];
};

void * aligned_malloc(size_t size, size_t align);

void aligned_free(void * aligned_ptr);

#if (defined __linux__) && (defined __SSE4_2__)
#define USE_SSE_INSTR
#endif

#ifdef USE_SSE_INSTR
#include <nmmintrin.h>
#define popcnt_u64 _mm_popcnt_u64
#else
int popcnt_u64(unsigned long long x);
#endif

#define FOR(i, n) for(int i=0, _n=(int)(n); i<_n; i++)

#endif
