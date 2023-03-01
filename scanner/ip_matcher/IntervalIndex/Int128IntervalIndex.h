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

#ifndef H_INT128_INTERVAL_INDEX_CPP_H
#define H_INT128_INTERVAL_INDEX_CPP_H

#include "SuccinctHash.h"
#include <vector>
using namespace std;

struct uint128_t
{
	unsigned long long I[2];//¸ßÎ»->µÍÎ»£ºI[1]I[0]

	uint128_t(const unsigned int * a=NULL)
	{ 
		if(a!=NULL)
		{
			I[0] = a[2];
			I[0] = (I[0]<<32)|a[3];
			I[1] = a[0];
			I[1] = (I[1]<<32)|a[1];
		}
	}

	uint128_t& operator=(const uint128_t& rhs)
	{
		for(int i=0; i<2; i++) I[i]=rhs.I[i];
		return *this;
	}

	uint128_t& operator--()
	{
		if(I[0]==0) I[1]--;
		I[0]--;
		return *this;
	}

	uint128_t& operator++()
	{
		I[0]++;
		if(I[0]==0) I[1]++;
		return *this;
	}

	uint128_t operator<<(int n) const
	{
		uint128_t t = *this;
		int k=n>>6;
		n&=63;
		t.I[1]=(t.I[1]<<n)|(t.I[0]>>(64-n));
		t.I[0]<<=n;

		for(int j=1; j>=k; j--) t.I[j]=t.I[j-k];
		for(int i = k -1; i>=0; i--) t.I[i] = 0;

		return t;
	}

	uint128_t operator>>(int n) const
	{
		uint128_t t = *this;
		int k=n>>6;
		n&=63;
		t.I[0]=(t.I[0]>>n)|(t.I[1]<<(64-n));
		t.I[1]>>=n;

		for(int j = 0; j <= 1-k; j++) t.I[j] = t.I[j+k];
		for(int i = 1; i > 1-k; i--) t.I[i] = 0;

		return t;

	}

	void ornot(unsigned int * mask)
	{
		unsigned long long m = mask[1];
		m = (m<<32)|mask[0];
		unsigned long long n = mask[3];
		n = (n<<32)|mask[2];
		I[0] |= ~m;
		I[1] |= ~n;
	}

	bool is_all_zeros() const
	{
		return (I[0] == 0)&&(I[1] == 0);
	}

	bool is_all_ones() const
	{
		return ((~I[0])==0)&&((~I[1])==0);
	}
};

bool operator<(const uint128_t& lhs, const uint128_t& rhs);
bool operator>(const uint128_t& lhs, const uint128_t& rhs);
bool operator==(const uint128_t& lhs, const uint128_t& rhs);
bool operator!=(const uint128_t& lhs, const uint128_t& rhs);
bool operator>=(const uint128_t& lhs, const uint128_t& rhs);
uint128_t operator-(const uint128_t& lhs, const uint128_t& rhs);

class CInt128IntervalIndex
{
public:
	CInt128IntervalIndex();

	~CInt128IntervalIndex();

	long long PreProcessing(const vector<uint128_t>& a, const vector<uint128_t>& b);

	int Find(const uint128_t * key, unsigned int * result, unsigned int size);

private:
	long long process_single(const vector<uint128_t>& a);
	int Find_single(const uint128_t * key, unsigned int * result, unsigned int size);

	long long process_interval(const vector<uint128_t>& a, const vector<uint128_t>& b);
	int Find_interval(const uint128_t * key, unsigned int * result, unsigned int size);

private:
	bool          m_is_single;
	CSuccinctHash m_ip_hash;
	uint128_t *   m_array;

	unsigned int *	m_IndexForMaxInt;
	long long		m_iEndPointsNum;
	uint128_t *		m_pEndPoints;
	long long *		m_pIDPtr;
	unsigned int *	m_pIDList;
	int				m_L[65537];
	unsigned int *	m_IndexForWholeInterval;
};

#endif
