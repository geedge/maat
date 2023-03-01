/*
 *
 * Copyright (c) 2008-2016
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2016-06-03
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#include "Int128IntervalIndex.h"
#include <algorithm>
#include <set>
#include <cassert>
#include <limits.h>
using namespace std;

//#define DEBUG_INT128_INTERVAL_INDEX

bool operator<(const uint128_t& lhs, const uint128_t& rhs)
{
	int i=1;
	while(i>=0 && lhs.I[i]==rhs.I[i]) --i;
	return (i>=0 && lhs.I[i]<rhs.I[i]);
}

bool operator>(const uint128_t& lhs, const uint128_t& rhs)
{
	return rhs<lhs;
}

bool operator>=(const uint128_t& lhs, const uint128_t& rhs)
{
	return !(lhs<rhs);
}

bool operator==(const uint128_t& lhs, const uint128_t& rhs)
{
	for(int i=0; i<2; i++)
	{
		if(lhs.I[i]!=rhs.I[i]) return false;
	}
	return true;
}

bool operator!=(const uint128_t& lhs, const uint128_t& rhs)
{
	return !(lhs==rhs);
}

//执行a-b，a为lhs，b为rhs
uint128_t operator-(const uint128_t& lhs, const uint128_t& rhs)
{
	uint128_t l = rhs;
	uint128_t h = lhs;
	unsigned long long I[2] = {0};
	if(h.I[0] < l.I[0])//低位的数更小，需要借位
	{
		I[0] = ULONG_MAX - (l.I[0] - h.I[0]);
		h.I[1]--;//被借位了，高位需要减1
	}
	else
	{
		I[0] = h.I[0] - l.I[0];
	}
	I[1] = h.I[1] - l.I[1];

	unsigned int a[4];
	a[3] = I[0] & 0xFFFFFFFF;
	a[2] = (I[0]>>32) & 0xFFFFFFFF;
	a[1] = I[1] & 0xFFFFFFFF;
	a[0] = (I[1]>>32) & 0xFFFFFFFF;
	uint128_t b(a);
	return b;
}

unsigned int ipv6_hash(const uint128_t * ip)
{
	unsigned long long I=(ip->I[0])^(ip->I[1]);
	return (I&0xFFFFFFFF)^(I>>32);
}

CInt128IntervalIndex::CInt128IntervalIndex()
{
	m_array=NULL;

	m_iEndPointsNum=0;
	m_pEndPoints=NULL;
	m_pIDPtr=NULL;
	m_pIDList=NULL;
	m_IndexForMaxInt=NULL;
	m_IndexForWholeInterval = NULL;
}

CInt128IntervalIndex::~CInt128IntervalIndex()
{
	if(m_array!=NULL) delete [] m_array;

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

long long CInt128IntervalIndex::PreProcessing(const vector<uint128_t>& a, const vector<uint128_t>& b)
{
	if(a.size()==0) return -1;

	m_is_single=true;
	for(unsigned int i=0; i<a.size(); i++)
	{
		if(a[i]!=b[i])
		{
			m_is_single=false;
			break;
		}
	}

	if(m_is_single)
	{
		return process_single(a);
	}
	else
	{
		return process_interval(a, b);
	}
}

long long CInt128IntervalIndex::process_single(const vector<uint128_t>& a)
{
	long long mem_bytes=0;
	unsigned int num=a.size();
	unsigned int * keys  =new unsigned int[num];
	unsigned int * values=new unsigned int[num];
	m_array=new uint128_t[num];

	mem_bytes+=(2*sizeof(unsigned int)+sizeof(uint128_t))*num;

	for(unsigned int i=0; i<num; i++)
	{
		keys[i]=ipv6_hash(&a[i]);
		values[i]=i;
		m_array[i]=a[i];
	}

	long long ret=m_ip_hash.init(keys, values, num);
	delete [] keys;
	delete [] values;
	if(ret<0) return -1;
	mem_bytes+=ret;
	return mem_bytes;
}

long long CInt128IntervalIndex::process_interval(const vector<uint128_t>& a, const vector<uint128_t>& b)
{
	vector<uint128_t> A=a, B=b;
	long long iMemBytes=0;

	set<uint128_t> s;
	vector<unsigned int> IndexForMaxInt;
	vector<unsigned int> IndexForWholeInterval;
	for(int i=0, n=(int)A.size(); i<n; i++) 
	{
		if(A[i]>B[i]) continue;

		if(B[i].is_all_ones())
		{
			IndexForMaxInt.push_back(i);
			--B[i];
		}
		++B[i]; // now A[i], B[i] is half closed interval.
		if(A[i]>=B[i]) continue;

		if(A[i].is_all_zeros() && B[i].is_all_ones())
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

	this->m_iEndPointsNum=(long long)s.size();
	this->m_pEndPoints=new uint128_t[m_iEndPointsNum];
	copy(s.begin(), s.end(), m_pEndPoints);
	iMemBytes+=(long long)(m_iEndPointsNum*sizeof(uint128_t));

	vector<long long> count(m_iEndPointsNum, 0);
	for(int i=0, n=(int)A.size(); i<n; i++) 
	{
		if(A[i]>=B[i] || (A[i].is_all_zeros() && B[i].is_all_ones())) continue;
		long long l=(int)(lower_bound(m_pEndPoints, m_pEndPoints+m_iEndPointsNum, A[i])-m_pEndPoints);
		long long h=(int)(lower_bound(m_pEndPoints, m_pEndPoints+m_iEndPointsNum, B[i])-m_pEndPoints);
		assert(m_pEndPoints[l]==A[i] && m_pEndPoints[h]==B[i]);
		for(long long j=l; j<h; j++) count[j]++;
	}

	m_pIDPtr=new long long[m_iEndPointsNum+1];
	m_pIDPtr[0]=0;
	for(long long i=0; i<m_iEndPointsNum; i++)
	{
		m_pIDPtr[i+1]=m_pIDPtr[i]+count[i];
	}
	iMemBytes+=(long long)((m_iEndPointsNum+1)*sizeof(unsigned int));

	m_pIDList=new unsigned int[m_pIDPtr[m_iEndPointsNum]];
	for(int i=0, n=(int)A.size(); i<n; i++) 
	{
		if(A[i]>=B[i] || (A[i].is_all_zeros() && B[i].is_all_ones())) continue;
		long long l=(int)(lower_bound(m_pEndPoints, m_pEndPoints+m_iEndPointsNum, A[i])-m_pEndPoints);
		long long h=(int)(lower_bound(m_pEndPoints, m_pEndPoints+m_iEndPointsNum, B[i])-m_pEndPoints);
		assert(m_pEndPoints[l]==A[i] && m_pEndPoints[h]==B[i]);
		for(long long j=l; j<h; j++) 
		{
			m_pIDList[m_pIDPtr[j]++]=i;
		}
	}
	iMemBytes+=(long long)(m_pIDPtr[m_iEndPointsNum]*sizeof(unsigned int));

	for(long long i=0; i<m_iEndPointsNum; i++)
	{
		m_pIDPtr[i]-=count[i];
	}

	int k=0;
	unsigned int t[4] = {0,0,0,0};
	for(unsigned int i=0; i<65536; i++)
	{
		t[3] = i;
		uint128_t x(t);
		x = x<<112;
		while(k<m_iEndPointsNum && x>=m_pEndPoints[k]) 
			k++;
		m_L[i] = (k>=1)? k-1 : 0;
	}
	m_L[65536]=m_iEndPointsNum-1;	

	iMemBytes+=(long long)sizeof(m_L);

#ifdef DEBUG_INT128_INTERVAL_INDEX
	printf("Int128 Interval Index membyte=%5.3lf (MB).\n", (double)iMemBytes/(1u<<20));
#endif

	A.clear();
	B.clear();
	s.clear();
	IndexForMaxInt.clear();
	return iMemBytes;
}

int CInt128IntervalIndex::Find(const uint128_t * key, unsigned int * result, unsigned int size)
{
	if(m_is_single)
	{
		return Find_single(key, result, size);
	}
	else
	{
		return Find_interval(key, result, size);
	}
}

int CInt128IntervalIndex::Find_single(const uint128_t * key, unsigned int * result, unsigned int size)
{
	unsigned int h=ipv6_hash(key);
	int ret=m_ip_hash.find(h, result, size);
	int j=0;
	for(int i=0; i<ret; i++)
	{
		if(*key==m_array[result[i]]) result[j++]=result[i];
	}
	return j;
}

int CInt128IntervalIndex::Find_interval(const uint128_t * key, unsigned int * result, unsigned int size)
{
	if(key->is_all_ones())
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
		uint128_t t = (*key)>>112;
		unsigned int k = t.I[0]&0xffff;
		long long l=m_L[k], h=m_L[k+1];
		long long m=0;
		while(l<=h && m<m_iEndPointsNum)
		{
			m=(l+h)>>1;
			if(*key>=m_pEndPoints[m]) l=m+1;
			else h=m-1;			
		}

		if(h>=m_L[k] && h<m_iEndPointsNum)
		{
			long long n=m_pIDPtr[h+1]-m_pIDPtr[h];
			if(n>size) n=size;
			unsigned int * id_list=m_pIDList+m_pIDPtr[h];
			for(unsigned int i=0; i<n; i++) *result++=*id_list++;
			s+=n;
		}
		return s;
	}
}
