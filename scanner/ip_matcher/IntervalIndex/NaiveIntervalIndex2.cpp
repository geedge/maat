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

//#define DEBUG_NAIVE_INTERVAL_INDEX2

#include "NaiveIntervalIndex2.h"
#include <climits>
#include <algorithm>
#include <iterator>
#include <set>
#include <cassert>
using namespace std;

CNaiveIntervalIndex2::CNaiveIntervalIndex2()
{
	this->m_N=1;
	this->m_pEndPoints=NULL;
	this->m_pIDList=NULL;
}

CNaiveIntervalIndex2::~CNaiveIntervalIndex2()
{
	if(this->m_pEndPoints!=NULL)
	{
		delete [] this->m_pEndPoints;
	}

	if(this->m_pIDList!=NULL)
	{
		delete [] this->m_pIDList;
	}
}

long long CNaiveIntervalIndex2::PreProcessing(const vector<unsigned int>& a, const vector<unsigned int>& b)
{
	vector<unsigned int> A=a, B=b;
	long long iMemBytes=0;

	set<unsigned int> s;

	for(int i=0, n=(int)A.size(); i<n; i++) 
	{
		assert(A[i]<=B[i]);

		if(B[i]==UINT_MAX)
		{
			this->m_IndexForMaxInt.push_back(i);
			--B[i];
		}
		B[i]++; // now A[i], B[i] is half closed interval.
		if(A[i]>=B[i]) continue;
		s.insert(A[i]);
		s.insert(B[i]);
	}

	iMemBytes+=(long long)(sizeof(unsigned int)*this->m_IndexForMaxInt.size());

	int M=(int)s.size();
	this->m_N=1;
	while(m_N<=M) m_N<<=1;

	this->m_pEndPoints=new unsigned int[m_N];
	this->m_pIDList=new vector<unsigned int>[m_N];

	vector<unsigned int> v;
	copy(s.begin(), s.end(), back_inserter(v));
	for(int i=M; i<m_N-1; i++) v.push_back(UINT_MAX);

	int k=1;
	for(int d=m_N>>1; d>0; d>>=1)
	{
		for(int j=1; d*j<m_N; j+=2)
		{
			this->m_pEndPoints[k++]=v[d*j-1];
		}
	}
	assert(k==m_N);

	iMemBytes+=m_N*(int)(sizeof(unsigned int)+sizeof(vector<unsigned int>));

	for(int i=0, n=(int)A.size(); i<n; i++) 
	{
		if(A[i]>=B[i]) continue;

		int p =1;
		while(p<m_N)
		{
			if(A[i]<m_pEndPoints[p])
			{
				p<<=1;
			}
			else
			{
				p=(p<<1)+1;
			}
		}
		
		int q =1;
		while(q<m_N)
		{
			if(B[i]<m_pEndPoints[q])
			{
				q<<=1;
			}
			else
			{
				q=(q<<1)+1;
			}
		}

		for(int j=p; j<q; j++) this->m_pIDList[j-m_N].push_back(i);

		iMemBytes+=(q-p)*(int)sizeof(unsigned int);
	}

#ifdef DEBUG_NAIVE_INTERVAL_INDEX2
	printf("Naive Interval Index-2 membyte=%5.3lf (MB).\n", (double)iMemBytes/(1u<<20));
#endif

	return iMemBytes;
}

int CNaiveIntervalIndex2::Find(unsigned int key, unsigned int * result, unsigned int size)
{
	unsigned int n = 0;
	int s = 0;
	if(key==UINT_MAX)
	{
		s = m_IndexForMaxInt.size();
		for(int i = 0; i < s; i++)
		{
			if(n >= size)
			{
				return n;
			}
			result[n++] = m_IndexForMaxInt[i];
		}
	}
	else
	{
		int i=1;
		while(i<m_N)
		{
			if(key<m_pEndPoints[i])
			{
				i<<=1;
			}
			else
			{ 
				i=(i<<1)+1;
			}
		}

		s = m_pIDList[i - m_N].size();
		for(int j = 0; j < s; j++)
		{
			if(n >= size)
			{
				return n;
			}
			result[n++] = m_pIDList[i - m_N][j];
		}
	}

	return n;
}
