/*
 *
 * Copyright (c) 2008--2012
 * Advanced Algorithm and Algorithm Engineering Group
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2012-11-27
 *
 * This code is the exclusive and proprietary property of NELIST and IIE-CAS. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#include "DirectIndex.h"
#include <algorithm>
#include <map>
using namespace std;

//#define DEBUG_DIRECT_INDEX

CDirectIndex::CDirectIndex()
{
	m_keys=NULL;
	m_ptr=NULL;
	m_values=NULL;
}

CDirectIndex::~CDirectIndex()
{
	if(m_keys!=NULL)   delete [] m_keys;
	if(m_ptr!=NULL)    delete [] m_ptr;
	if(m_values!=NULL) delete [] m_values;
}

/*
	closed interval: [a[i], b[i]] such that a[i]<=b[i]
*/
long long CDirectIndex::PreProcessing(const vector<unsigned int>& a, const vector<unsigned int>& b)
{
	long long mem_bytes=0;

	unsigned long long count=0;
	for(unsigned int i=0; i<a.size(); i++)
	{
		count+=((unsigned long long)b[i]-a[i]+1);
	}
	if(count>2*a.size()) return -1;

	map<unsigned int, unsigned int> M;
	for(unsigned int i=0; i<a.size(); i++)
	{
		for(unsigned long long t=a[i]; t<=b[i]; t++)
		{
			M[(unsigned int)t]++;
		}
	}

	m_keys  =new unsigned int[M.size()];
	m_ptr   =new unsigned int[M.size()+1];
	m_values=new unsigned int[(unsigned int)count];
	mem_bytes+=sizeof(unsigned int)*(2*M.size()+(unsigned int)count);

	m_ptr[0]=0;
	map<unsigned int, unsigned int>::const_iterator it=M.begin();
	for(unsigned int k=0; k<M.size(); k++, ++it)
	{
		m_keys[k]=it->first;
		m_ptr[k+1]=m_ptr[k]+it->second;
	}

	for(unsigned int i=0; i<a.size(); i++)
	{
		for(unsigned long long t=a[i]; t<=b[i]; t++)
		{
			unsigned int k=(unsigned int)(lower_bound(m_keys, m_keys+M.size(), (unsigned int)t)-m_keys);
			m_values[m_ptr[k]++]=i;
		}
	}

	for(int k=(int)M.size(); k>0; k--)
	{
		m_ptr[k]=m_ptr[k-1];
	}
	m_ptr[0]=0;

	m_min_key=m_keys[0];
	m_max_key=m_keys[M.size()-1];
	for(unsigned int k=0; k<M.size(); k++)
	{
		m_keys[k]-=m_min_key;
	}

	unsigned long long ONE=1;
	unsigned int theta=0;
	while((ONE<<(theta+16))<=m_keys[M.size()-1]) theta++;
	m_theta=theta;
	
	m_L[0]=0;
	for(unsigned int i=1; i<65536; i++)
	{
		m_L[i]=(unsigned int)(lower_bound(m_keys, m_keys+M.size(), i*(1U<<theta))-m_keys);
	}
	m_L[65536]=(unsigned int)M.size();

	mem_bytes+=sizeof(m_L);

	M.clear();

#ifdef DEBUG_DIRECT_INDEX
	printf("Direct Index membyte=%5.3lf (MB).\n", (double)mem_bytes/(1u<<20));
#endif

	return mem_bytes;
}

int CDirectIndex::Find(unsigned int key, unsigned int * result, unsigned int size)
{
	if(key<m_min_key || key>m_max_key) 
		return 0;

	key-=m_min_key;
	unsigned int k=key>>m_theta;
	int l=m_L[k], h=(int)m_L[k+1]-1;
	if(h<l) 
		return 0;

	while(l<=h)
	{
		int m=(l+h)/2;
		if(key<m_keys[m]) h=m-1;
		else l=m+1;
	}

	unsigned int n = 0;
	if(h<(int)m_L[k] || m_keys[h]!=key)
	{
		return 0;
	}
	else
	{
		int s = m_ptr[h+1] - m_ptr[h];
		unsigned int * values = m_values+m_ptr[h];
		for(int i = 0; i < s; i++)
		{
			if(n >= size)
			{
				return n;
			}
			result[n++] = values[i];
		}
	}

	return n;
}

