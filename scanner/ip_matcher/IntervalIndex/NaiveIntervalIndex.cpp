/*
 *
 * Copyright (c) 2008--2012
 * String Matching Group, Lab for Intelligent Information Processing Technology,
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS).
 * All rights reserved.
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2014-11-19
 *
 * This code is the exclusive and proprietary property of IIE-CAS. Usage for direct 
 * or indirect commercial advantage is not allowed without written permission from 
 * the authors.
 *
 */

//#define DEBUG_NAIVE_INTERVAL_INDEX

#include "NaiveIntervalIndex.h"
#include <climits>
#include <algorithm>
#include <set>
#include <cassert>
using namespace std;

CNaiveIntervalIndex::CNaiveIntervalIndex()
{
	this->m_pDirectIndexer=NULL;
	this->m_iEndPointsNum=0;
	this->m_pEndPoints=NULL;
	this->m_pIDPtr=NULL;
	this->m_pIDList=NULL;
	this->m_IndexForMaxInt=NULL;
	this->m_IndexForWholeInterval = NULL;
}

CNaiveIntervalIndex::~CNaiveIntervalIndex()
{
	if(this->m_pDirectIndexer!=NULL)
	{
		delete this->m_pDirectIndexer;
	}

	if(this->m_pEndPoints!=NULL)
	{
		delete [] this->m_pEndPoints;
	}

	if(this->m_pIDList!=NULL)
	{
		delete [] this->m_pIDList;
	}

	if(this->m_pIDPtr!=NULL)
	{
		delete [] this->m_pIDPtr;
	}

	if(this->m_IndexForMaxInt!=NULL)
	{
		delete [] this->m_IndexForMaxInt;
	}

	if(this->m_IndexForWholeInterval != NULL)
	{
		delete [] this->m_IndexForWholeInterval;
	}
}

long long CNaiveIntervalIndex::PreProcessing(const vector<unsigned int>& a, const vector<unsigned int>& b)
{
	CDirectIndex * instance=new CDirectIndex;
	long long ret=instance->PreProcessing(a, b);
	if(ret>=0)
	{
		m_pDirectIndexer=instance;
		return ret;
	}
	delete instance;

	vector<unsigned int> A=a, B=b;
	long long iMemBytes=0;

	set<unsigned int> s;
	vector<unsigned int> IndexForMaxInt;
	vector<unsigned int> IndexForWholeInterval;
	for(int i=0, n=(int)A.size(); i<n; i++) 
	{
		if(A[i]>B[i]) continue;

		if(B[i]==UINT_MAX)
		{
			IndexForMaxInt.push_back(i);
			--B[i];
		}
		B[i]++; // now A[i], B[i] is half closed interval.
		if(A[i]>=B[i]) continue;

		if(A[i]==0 && B[i]==UINT_MAX)
		{
			IndexForWholeInterval.push_back(i);
			continue;
		}
		s.insert(A[i]);
		s.insert(B[i]);

	}

	m_IndexForWholeInterval=new unsigned int[IndexForWholeInterval.size()+1];
	m_IndexForWholeInterval[0]=IndexForWholeInterval.size();
	copy(IndexForWholeInterval.begin(), IndexForWholeInterval.end(), m_IndexForWholeInterval+1);
	iMemBytes+=(long long)(sizeof(unsigned int)*(IndexForWholeInterval.size()+1));

	m_IndexForMaxInt=new unsigned int[IndexForMaxInt.size()+1];
	m_IndexForMaxInt[0]=IndexForMaxInt.size();
	copy(IndexForMaxInt.begin(), IndexForMaxInt.end(), m_IndexForMaxInt+1);
	iMemBytes+=(long long)(sizeof(unsigned int)*(IndexForMaxInt.size()+1));

	this->m_iEndPointsNum=(int)s.size();
	this->m_pEndPoints=new unsigned int[m_iEndPointsNum];
	copy(s.begin(), s.end(), m_pEndPoints);
	iMemBytes+=(long long)(m_iEndPointsNum*sizeof(unsigned int));

	vector<unsigned int> count(m_iEndPointsNum, 0);
	for(int i=0, n=(int)A.size(); i<n; i++) 
	{
		if(A[i]>=B[i] || (A[i] == 0 && B[i] == UINT_MAX)) continue;
		int l=(int)(lower_bound(m_pEndPoints, m_pEndPoints+m_iEndPointsNum, A[i])-m_pEndPoints);
		int h=(int)(lower_bound(m_pEndPoints, m_pEndPoints+m_iEndPointsNum, B[i])-m_pEndPoints);
		assert(m_pEndPoints[l]==A[i] && m_pEndPoints[h]==B[i]);
		for(int j=l; j<h; j++) count[j]++;
	}

	m_pIDPtr=new unsigned int[m_iEndPointsNum+1];
	m_pIDPtr[0]=0;
	for(int i=0; i<m_iEndPointsNum; i++)
	{
		m_pIDPtr[i+1]=m_pIDPtr[i]+count[i];
	}
	iMemBytes+=(long long)((m_iEndPointsNum+1)*sizeof(unsigned int));

	m_pIDList=new unsigned int[m_pIDPtr[m_iEndPointsNum]];
	for(int i=0, n=(int)A.size(); i<n; i++) 
	{
		if(A[i]>=B[i] || (A[i] == 0 && B[i] == UINT_MAX)) continue;
		int l=(int)(lower_bound(m_pEndPoints, m_pEndPoints+m_iEndPointsNum, A[i])-m_pEndPoints);
		int h=(int)(lower_bound(m_pEndPoints, m_pEndPoints+m_iEndPointsNum, B[i])-m_pEndPoints);
		assert(m_pEndPoints[l]==A[i] && m_pEndPoints[h]==B[i]);
		for(int j=l; j<h; j++) 
		{
			m_pIDList[m_pIDPtr[j]++]=i;
		}
	}
	iMemBytes+=(long long)(m_pIDPtr[m_iEndPointsNum]*sizeof(unsigned int));

	for(int i=0; i<m_iEndPointsNum; i++)
	{
		m_pIDPtr[i]-=count[i];
	}

	int k=0;
	for(unsigned int i=0; i<65536; i++)
	{
		unsigned int x=(i<<16);
		while(k<m_iEndPointsNum && x>=m_pEndPoints[k]) k++;
		m_L[i] = (k>=1)? k-1 : 0;
	}
	m_L[65536]=m_iEndPointsNum-1;	

	iMemBytes+=(long long)sizeof(m_L);

#ifdef DEBUG_NAIVE_INTERVAL_INDEX
	printf("Naive Interval Index membyte=%5.3lf (MB).\n", (double)iMemBytes/(1u<<20));
#endif

	A.clear();
	B.clear();
	s.clear();
	IndexForMaxInt.clear();
	return iMemBytes;
}

int CNaiveIntervalIndex::Find(unsigned int key, unsigned int * result, unsigned int size)
{
	if(m_pDirectIndexer!=NULL) return m_pDirectIndexer->Find(key, result, size);

	if(key==UINT_MAX)
	{
		unsigned int s=m_IndexForMaxInt[0];
		if(s>size) s=size;
		for(unsigned int i=1; i<=s; i++) *result++=m_IndexForMaxInt[i];
		return s;
	}
	else
	{
		unsigned int s=m_IndexForWholeInterval[0];
		if(s>size) s=size;
		for(unsigned int i=1; i<=s; i++)
		{
			*result++=m_IndexForWholeInterval[i];
		}
		size-=s;

		unsigned int k=(key>>16);
		int l=m_L[k], h=m_L[k+1];
		int m=0;
		while(l<=h && m<m_iEndPointsNum)
		{
			m=(l+h)>>1;
			if(key>=m_pEndPoints[m]) l=m+1;
			else h=m-1;			
		}

		if(h>=m_L[k] && h<m_iEndPointsNum)
		{
			unsigned int n=m_pIDPtr[h+1]-m_pIDPtr[h];
			if(n>size) n=size;
			unsigned int * id_list=m_pIDList+m_pIDPtr[h];
			for(unsigned int i=0; i<n; i++) *result++=*id_list++;
			s+=n;
		}

		return s;
	}
}
