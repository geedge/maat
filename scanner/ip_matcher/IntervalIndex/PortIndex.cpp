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

#include "PortIndex.h"
#include <stdlib.h>
#include <string.h>
using namespace std;

//#define DEBUG_PORT_INDEX

CPortIndex::CPortIndex()
{
	m_values=NULL;
	memset(m_bitmap, 0, sizeof(m_bitmap));
}

CPortIndex::~CPortIndex()
{
	if(m_values!=NULL) delete [] m_values;
}

/*
	closed interval: [a[i], b[i]] such that a[i]<=b[i]
*/
long long CPortIndex::PreProcessing(const vector<unsigned int>& a, const vector<unsigned int>& b)
{
	long long mem_bytes=0;

	for(unsigned int i=0; i<=65536; i++) m_L[i]=0;

	for(unsigned int i=0; i<a.size(); i++)
	{
		for(unsigned int t=a[i]; t<=b[i]; t++) m_L[t]++;
	}

	for(unsigned int i=1; i<=65536; i++) m_L[i]+=m_L[i-1];

	m_values=new unsigned int[m_L[65536]];
	mem_bytes+=sizeof(unsigned int)*m_L[65536]+sizeof(m_L)+sizeof(m_bitmap);

	for(unsigned int i=0; i<a.size(); i++)
	{
		for(unsigned int t=a[i]; t<=b[i]; t++) m_values[--m_L[t]]=i;
	}

	for(unsigned int i=0; i<65536; i++)
	{
		if(m_L[i]<m_L[i+1]) m_bitmap[i>>3]|=(1U<<(i&7));
	}

#ifdef DEBUG_PORT_INDEX
	printf("Port Index membyte=%5.3lf (MB).\n", (double)mem_bytes/(1U<<20));
#endif

	return mem_bytes;
}

int CPortIndex::Find(unsigned int key, unsigned int * result, unsigned int size)
{
	if((m_bitmap[key>>3]&(1U<<(key&7)))==0) return 0;
	unsigned int n=m_L[key+1]-m_L[key];
	if(n>size) n=size;
	unsigned int * p=m_values+m_L[key];
	for(unsigned int i=0; i<n; i++) *result++=*p++;
	return n;
}

