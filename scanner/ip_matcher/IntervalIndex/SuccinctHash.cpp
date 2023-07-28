/*
 *
 * Copyright (c) 2008--2015
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2015-12-9
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#include "SuccinctHash.h"
#include <stdlib.h>
#include <stdio.h>
#include <math.h>


static const unsigned long long ONE=1;
static const unsigned int B=22695477;

inline unsigned int myhash(unsigned int key)
{
	//return key;
	unsigned int h=0;
	FOR(j, 4)
	{
		h=h*B+(key&255);
		key>>=8;
	}
	return h;
}

static void * aligned_malloc(size_t size, size_t align)
{
	void * malloc_ptr;
	void * aligned_ptr;

	/* Error if align is not a power of two.  */
	if (align & (align - 1))
	{
		return ((void*) 0);
	}

	if (align==0 || size == 0)
	{
		return ((void *) 0);
	}

	malloc_ptr = malloc (sizeof(void *) + align - 1 + size);
	if (!malloc_ptr)
	{
		return ((void *) 0);
	}

	aligned_ptr = (void *) (((size_t)malloc_ptr + sizeof(void *) + align-1) & ~(align-1));
  
	((void **) aligned_ptr) [-1] = malloc_ptr;

	return aligned_ptr;
}

static void aligned_free(void * aligned_ptr)
{
	if (aligned_ptr)
	{
		free (((void **) aligned_ptr) [-1]);
	}
}

CSuccinctHash::CSuccinctHash()
{
	m_RT=NULL;
	m_kv_array=NULL;
	m_kv_ptr = NULL;
}

CSuccinctHash::~CSuccinctHash()
{
	if(m_RT!=NULL)
	{
		aligned_free(m_RT);
	}

	if(m_kv_array!=NULL)
	{
		delete [] m_kv_array;
	}
	if(m_kv_ptr != NULL)
	{
		delete []m_kv_ptr;
	}
}

long long CSuccinctHash::init(unsigned int keys[], unsigned int values[], unsigned int num)
{
	m_hash_bits=(int)(log10((double)num)/log10(2.0))+4;
	if(m_hash_bits<8) m_hash_bits=8;

	//printf("m_hash_bits=%d\n", m_hash_bits);

	m_RT=(packedRT_t *)aligned_malloc(sizeof(packedRT_t)*((1U<<(m_hash_bits-8))+1), 64);

	FOR(i, (1U<<(m_hash_bits-8)))
	{
		FOR(j, 4) m_RT[i].bitmap[j]=0;
	}

	FOR(i, num)
	{
		unsigned int h=myhash(keys[i]);

		h&=((1U<<m_hash_bits)-1);
		int q=h&255;
		m_RT[h>>8].bitmap[q>>6]|=(ONE<<(q&63));
	}

	m_RT[0].A=0;
	FOR(i, (1U<<(m_hash_bits-8)))
	{
		m_RT[i].B[0]=0;
		m_RT[i].B[1]=                      popcnt_u64(m_RT[i].bitmap[0]);
		m_RT[i].B[2]=         m_RT[i].B[1]+popcnt_u64(m_RT[i].bitmap[1]);
		m_RT[i].B[3]=         m_RT[i].B[2]+popcnt_u64(m_RT[i].bitmap[2]);
		m_RT[i+1].A=m_RT[i].A+m_RT[i].B[3]+popcnt_u64(m_RT[i].bitmap[3]);
	}
	int tn=m_RT[(1U<<(m_hash_bits-8))].A;

	m_kv_ptr=new unsigned int[tn+2]();

	FOR(i, tn+1) m_kv_ptr[i]=0;
	FOR(i, num)
	{
		unsigned int h=myhash(keys[i]);
		h&=((1U<<m_hash_bits)-1);
		unsigned int idx=rank(h);
		m_kv_ptr[idx]++;
	}
	FOR(i, tn+1) m_kv_ptr[i+1]+=m_kv_ptr[i];

	m_kv_array=new unsigned int[2*num];
	FOR(i, num)
	{
		unsigned int h=myhash(keys[i]);
		h&=((1U<<m_hash_bits)-1);
		unsigned int idx=rank(h);
		unsigned int j=--m_kv_ptr[idx];
		m_kv_array[2*j]=keys[i];
		m_kv_array[2*j+1]=values[i];
	}

	long long mem_bytes=(1U<<(m_hash_bits-3))*sizeof(char)*5/4+(tn+1+2*num)*sizeof(unsigned int);
	return mem_bytes;
}

unsigned int CSuccinctHash::rank(unsigned int h)
{
	int p=(h>>8);
	int r=((h&255)>>6);
	int s=(h&63);
	unsigned long long e=m_RT[p].bitmap[r]&((ONE<<s)-1);

	return m_RT[p].A+m_RT[p].B[r]+popcnt_u64(e);
}

int CSuccinctHash::find(unsigned int key, unsigned int * value, unsigned int size)
{
	unsigned int h=myhash(key);
	h&=((1U<<m_hash_bits)-1);
	int q=h&255;
	unsigned int r=0;

	if(m_RT[h>>8].bitmap[q>>6]&(ONE<<(q&63)))
	{
		unsigned int idx=rank(h);

		for(unsigned int j=m_kv_ptr[idx]; j<m_kv_ptr[idx+1]; j++)
		{
			if(m_kv_array[2*j]==key)
			{
				if(r==size) return r;
				*value++=m_kv_array[2*j+1];
				r++;
			}
		}
	}

	return r;
}
