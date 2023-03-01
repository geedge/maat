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
#include "IPMaskIndex.h"
#include <stdio.h>
using namespace std;

//#define DEBUG_IPMASK_INDEX

bool is_8bit_ipmask(const vector<unsigned int>& a, const vector<unsigned int>& b)
{
	for(unsigned int i=0; i<a.size(); i++)
	{
		if( !(a[i]==b[i]) && !((a[i]&0xFF)==0 && b[i]==a[i]+255) ) return false;
	}
	return true;
}

CIPMaskIndex::CIPMaskIndex()
{
	m_values=NULL;
	m_ip_hash=NULL;
	m_is_single=false;
}

CIPMaskIndex::~CIPMaskIndex()
{
	if(m_values!=NULL) delete [] m_values;
	if(m_ip_hash!=NULL) delete m_ip_hash;
}

/*
	closed interval: [a[i], b[i]] such that a[i]<=b[i]
*/
long long CIPMaskIndex::PreProcessing(const vector<unsigned int>& a, const vector<unsigned int>& b)
{
	if(a.size()==0) return -1;
	long long mem_bytes=0;

	unsigned int J=0;
	for(unsigned int i=0; i<a.size(); i++)
	{
		if(a[i]==b[i]) J++;
	}

	m_is_single=(J==a.size());

	if(J>0)
	{
		unsigned int * keys  =new unsigned int[J];
		unsigned int * values=new unsigned int[J];
		J=0;
		for(unsigned int i=0; i<a.size(); i++)
		{
			if(a[i]==b[i])
			{
				keys[J]=a[i];
				values[J]=i;
				J++;
			}
		}

		m_ip_hash=new CSuccinctHash;
		long long ret=m_ip_hash->init(keys, values, J);
		delete [] keys;
		delete [] values;
		if(ret<0)
		{
			delete m_ip_hash;
			m_ip_hash=NULL;
			return -1;
		}
		mem_bytes+=ret;
	}

	if(m_is_single) return mem_bytes;

	for(unsigned int i=0; i<=(1U<<24); i++) m_L[i]=0;

	for(unsigned int i=0; i<a.size(); i++)
	{
		if((a[i]&0xFF)==0 && b[i]==a[i]+255) // 8-bitÑÚÂëÇø¼ä
		{
			m_L[a[i]>>8]++;
		}
	}

	for(unsigned int i=1; i<=(1U<<24); i++) m_L[i]+=m_L[i-1];

	m_values=new unsigned int[m_L[1<<24]];
	mem_bytes+=sizeof(unsigned int)*m_L[1<<24]+sizeof(m_L)+sizeof(m_bitmap);

	for(unsigned int i=0; i<a.size(); i++)
	{
		if((a[i]&0xFF)==0 && b[i]==a[i]+255)
		{
			m_values[--m_L[a[i]>>8]]=i;
		}
	}

	for(unsigned int i=0; i<(1<<24); i++)
	{
		if(m_L[i]<m_L[i+1]) m_bitmap[i>>3]|=(1U<<(i&7));
	}

#ifdef DEBUG_IPMASK_INDEX
	printf("IPMask Index membyte=%5.3lf (MB).\n", (double)mem_bytes/(1U<<20));
#endif

	return mem_bytes;
}

int CIPMaskIndex::Find(unsigned int key, unsigned int * result, unsigned int size)
{
	int ret=0;
	if(m_ip_hash!=NULL)
	{
		ret=m_ip_hash->find(key, result, size);
		if(ret<0) return -1;
	}

	if(m_is_single) return ret;
	result+=ret;
	size-=ret;

	key>>=8;
	if((m_bitmap[key>>3]&(1U<<(key&7)))==0) return ret;
	unsigned int n=m_L[key+1]-m_L[key];
	if(n>size) n=size;
	unsigned int * p=m_values+m_L[key];
	for(unsigned int i=0; i<n; i++) *result++=*p++;
	ret+=n;

	return ret;
}

