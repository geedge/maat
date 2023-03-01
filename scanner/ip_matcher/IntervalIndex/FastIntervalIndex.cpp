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

//#define DEBUG_FAST_INTERVAL_INDEX

#include "FastIntervalIndex.h"
#include "NaiveIntervalIndex.h"
#include "NaiveIntervalIndex2.h"
#include <climits>
#include <algorithm>
#include <set>
#include <cassert>
using namespace std;

CFastIntervalIndex::CFastIntervalIndex(unsigned int r, unsigned int l)
{
	assert(r>=l);
	this->m_r=r;
	this->m_l=l;
	this->m_pIndexer=new CIntervalIndex*[1u<<(r-l)];
	for(unsigned int i=0; i<(1u<<(r-l)); i++)
	{
		this->m_pIndexer[i]=NULL;
	}
}

CFastIntervalIndex::~CFastIntervalIndex()
{
	for(unsigned int i=0; i<(1u<<(m_r-m_l)); i++)
	{
		if(this->m_pIndexer[i]!=NULL)
		{
			delete this->m_pIndexer[i];
		}
	}
	delete [] this->m_pIndexer;
}

long long CFastIntervalIndex::PreProcessing(const vector<unsigned int>& a, const vector<unsigned int>& b)
{
	vector<unsigned int> A=a, B=b;
	long long iMemBytes=0;

	m_IDs.resize(1u<<(m_r-m_l));

	for(int i=0; i<(int)A.size(); i++) 
	{
		assert(A[i]<=B[i]);

		if(B[i]==UINT_MAX)
		{
			this->m_IndexForMaxInt.push_back(i);
			--B[i];
		}
		B[i]++; // now A[i], B[i] is half closed interval.
		if(A[i]>=B[i]) continue;
		unsigned int p, q;
		if(m_l==32) // in this case, the bit shift operator will mod 32 to 0.
		{
			p=0;
			q=1;
		}
		else
		{
			p=A[i]>>m_l;
			q= (B[i]&((1u<<m_l)-1))==0 ? (B[i]>>m_l) : (B[i]>>m_l)+1;
		}
		for(unsigned int j=p; j<q; j++) m_IDs[j].push_back(i);
	}

	for(int i=0, n=1<<(m_r-m_l); i<n; i++) 
	{
		if(m_IDs[i].size()==0) continue;
		vector<unsigned int> C, D;
		for(int j=0; j<(int)m_IDs[i].size(); j++)
		{
			int id=m_IDs[i][j];
			C.push_back(A[id]);
			D.push_back(B[id]-1);
		}
		this->m_pIndexer[i]=new CNaiveIntervalIndex2;
		iMemBytes+=this->m_pIndexer[i]->PreProcessing(C, D);
	}

	iMemBytes+=(1<<(m_r-m_l))*(int)sizeof(CIntervalIndex *);

#ifdef DEBUG_FAST_INTERVAL_INDEX
	printf("Fast Interval Index membyte=%5.3lf (MB).\n", (double)iMemBytes/(1u<<20));
#endif

	return iMemBytes;
}

int CFastIntervalIndex::Find(unsigned int key, unsigned int * result, unsigned int size)
{
	unsigned int n = 0;
	int s = 0;
	if(key==UINT_MAX)
	{
		s = m_IndexForMaxInt.size();
		for(int i = 0; i < s; i++)
		{
			if (n >= size)
			{
				return n;
			}
			result[n++] = m_IndexForMaxInt[i];
		}
	}
	else
	{
		vector<unsigned int> v;

		unsigned int t=(m_l<32) ? (key>>m_l) : 0;
		CIntervalIndex * pIndexer=this->m_pIndexer[t];
		if(pIndexer!=NULL)
		{
			int k = pIndexer->Find(key, result, size);
			int i = 0;
			for( i=0; i < k; i++)  
				result[i]=m_IDs[t][result[i]];

			n = i;
		}
	}

	return n;
}
