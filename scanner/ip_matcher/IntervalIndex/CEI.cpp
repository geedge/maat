/*
 *
 * Copyright (c) 2008--2012
 * String Matching Group, Lab for Intelligent Information Processing Technology,
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS).
 * All rights reserved.
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2012-07-10
 *
 * This code is the exclusive and proprietary property of IIE-CAS. Usage for direct 
 * or indirect commercial advantage is not allowed without written permission from 
 * the authors.
 *
 */

//#define DEBUG_CEI

#include "CEI.h"

#include <algorithm>
#include <iterator>
#include <cstdlib>
#include <cassert>
using namespace std;

unsigned int RoundToPowerOfTwo(unsigned int n)
{
	unsigned int N=1;
	while(n>N) N<<=1;
	return N;
}

// r must be no greater than 2^31
CEI::CEI(unsigned int r, unsigned int L)
{
	if(r==0 || (r&(r-1))!=0)
	{
		r=RoundToPowerOfTwo(r);
	}

	if(L==0 || (L&(L-1))!=0)
	{
		L=RoundToPowerOfTwo(L);
	}

	m_r=r;
	m_L=L;
	m_pIDList=new unsigned int[(r<<1)+1];
	m_pIDArray=NULL;
}

CEI::~CEI()
{
	if(m_pIDList!=NULL) delete [] m_pIDList;
	if(m_pIDArray!=NULL) delete [] m_pIDArray;
}

long long CEI::PreProcessing(const std::vector<unsigned int>& a, const std::vector<unsigned int>& b)
{
	vector<unsigned int> A=a, B=b;
	std::vector< std::vector<unsigned int> > IDList(m_r<<1);

	for(int i=0; i<(int)A.size(); i++)
	{
		B[i]++;
		if(A[i]>=B[i]) continue;

		unsigned int inf=(A[i]+m_L-1)&-m_L;
		unsigned int sup=B[i]&-m_L;

		if(inf>sup)
		{
			this->BestPartition(i, A[i], B[i], IDList);
		}
		else
		{
			for(unsigned int p=inf; p<sup; p+=m_L)
			{
				IDList[(p<<1)+1].push_back(i);
			}

			if(A[i]<inf) this->BestPartition(i, A[i], inf, IDList);
			if(sup<B[i]) this->BestPartition(i, sup, B[i], IDList);
		}
	}

	m_pIDList[0]=0;
	for(int i=0; i<(int)IDList.size(); i++)
	{
		m_pIDList[i+1]=m_pIDList[i]+IDList[i].size();
	}

	m_pIDArray=new unsigned int[m_pIDList[2*m_r]];
	for(int i=0; i<(int)IDList.size(); i++)
	{
		copy(IDList[i].begin(), IDList[i].end(), m_pIDArray+m_pIDList[i]);
	}

	long long iMemBytes=sizeof(unsigned int)*(2*m_r+1+m_pIDList[2*m_r]);

#ifdef DEBUG_CEI
	printf("CEI membyte=%5.3lf (MB).\n", (double)iMemBytes/(1u<<20));
#endif

	return iMemBytes;
}

void CEI::BestPartition(unsigned int id, unsigned int a, unsigned int b, std::vector< std::vector<unsigned int> >& IDList)
{
	unsigned int g=(a&-m_L)<<1;

	while(a<b)
	{
		unsigned int t=(a&(m_L-1))+m_L;
		unsigned int delta=1;
		while((t&1)==0 && a+(delta<<1)<=b)
		{
			t>>=1;
			delta<<=1;
		}

		IDList[g+t].push_back(id);
		a+=delta;
	}
}

static int compare(const void * a, const void * b)
{
	return(*(unsigned int *)a - *(unsigned int *)b);
}

int CEI::Find(unsigned int key, unsigned int * result, unsigned int size)
{
	unsigned int g=(key&-m_L)<<1;
	unsigned int n = 0;
	for(unsigned int t=(key&(m_L-1))+m_L; t; t>>=1)
	{
		unsigned int c=g+t;
		if(m_pIDList[c]<m_pIDList[c+1])
		{
			int s = m_pIDList[c+1] - m_pIDList[c];
			unsigned int * id_array = m_pIDArray + m_pIDList[c]; 
			for(int i = 0; i < s; i++)
			{
				if(n >= size)
				{
					qsort(result, n, sizeof(unsigned int), compare);
					return n;
				}
				result[n++] = id_array[i];
			}
		}
	}

	qsort(result, n, sizeof(unsigned int), compare);

	return n;
}
