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

//#define DEBUG_INTERVAL_TREE

#include "IntervalTree.h"
#include <climits>
#include <queue>
#include <algorithm>
#include <iterator>
#include <set>
#include <cassert>
using namespace std;

CIntervalTree::CIntervalTree()
{
	this->m_pstRoot=NULL;
	this->m_uiNodeNum=0;
}

CIntervalTree::~CIntervalTree()
{
	if(m_pstRoot==NULL) return;

	queue<stIntervalNode *> Q;

	for(Q.push(this->m_pstRoot); !Q.empty(); Q.pop())
	{
		stIntervalNode * pstCurrNode=Q.front();
		if(pstCurrNode->lchild!=NULL) Q.push(pstCurrNode->lchild);
		if(pstCurrNode->rchild!=NULL) Q.push(pstCurrNode->rchild);
		delete pstCurrNode;
		this->m_uiNodeNum--;
	}

	assert(this->m_uiNodeNum==0);
}

CIntervalTree::stIntervalNode * CIntervalTree::BuildBalancedTree(unsigned int a[], unsigned int n)
{
	stIntervalNode * pstNode=new stIntervalNode;
	this->m_uiNodeNum++;

	if(n==0)
	{
		pstNode->isleaf=true;
		pstNode->seperator=0;
		pstNode->lchild=NULL;
		pstNode->rchild=NULL;
	}
	else
	{
		unsigned int i=(n-1)/2;
		pstNode->isleaf=false;
		pstNode->seperator=a[i];
		pstNode->lchild=this->BuildBalancedTree(a, i);
		pstNode->rchild=this->BuildBalancedTree(a+i+1, n-i-1);
	}
	return pstNode;
}

void CIntervalTree::AddInterval(stIntervalNode * pstCurrNode, unsigned int inf, unsigned int sup, 
								 unsigned int a, unsigned int b, unsigned int id)
{
	assert(inf<=a && b<=sup);

	while(1)
	{
		assert(pstCurrNode!=NULL);

		if(a==inf && b==sup)
		{
			pstCurrNode->ids.push_back(id);
			this->m_iMemBytes+=sizeof(unsigned int);
			return;
		}
		else if(a>=pstCurrNode->seperator)
		{
			inf=pstCurrNode->seperator;
			pstCurrNode=pstCurrNode->rchild;			
		}
		else if(b<=pstCurrNode->seperator)
		{
			sup=pstCurrNode->seperator;
			pstCurrNode=pstCurrNode->lchild;
		}
		else
		{
			this->AddInterval(pstCurrNode->lchild, inf, pstCurrNode->seperator, a, pstCurrNode->seperator, id);
			this->AddInterval(pstCurrNode->rchild, pstCurrNode->seperator, sup, pstCurrNode->seperator, b, id);
			return;
		}
	}
}

long long CIntervalTree::PreProcessing(const vector<unsigned int>& a, const vector<unsigned int>& b)
{
	vector<unsigned int> A=a, B=b;
	this->m_iMemBytes=0;

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

	this->m_iMemBytes+=(long long)(sizeof(unsigned int)*this->m_IndexForMaxInt.size());

	vector<unsigned int> endpoints;

	copy(s.begin(), s.end(), back_inserter(endpoints));

	this->m_pstRoot=this->BuildBalancedTree(&endpoints[0], (unsigned int)endpoints.size());
	assert(this->m_uiNodeNum==2*(unsigned int)endpoints.size()+1);

	this->m_iMemBytes+=sizeof(stIntervalNode)*m_uiNodeNum;
		
	for(int i=0, n=(int)A.size(); i<n; i++)
	{
		if(A[i]>=B[i]) continue;
		this->AddInterval(m_pstRoot, 0, UINT_MAX, A[i], B[i], i);
	}

#ifdef DEBUG_INTERVAL_TREE
	printf("Interval Tree membyte=%5.3lf (MB).\n", (double)m_iMemBytes/(1u<<20));
#endif

	return m_iMemBytes;
}

static int compare(const void * a, const void * b)
{
	return(*(unsigned int *)a - *(unsigned int *)b);
}

int CIntervalTree::Find(unsigned int key, unsigned int * result, unsigned int size)
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
		stIntervalNode * pstCurrNode=this->m_pstRoot;
		while(true)
		{
			vector<unsigned int>::iterator it = pstCurrNode->ids.begin();
			while(it != pstCurrNode->ids.end())
			{
				if(n >= size)
				{
					qsort(result, n, sizeof(unsigned int), compare);
					return n;
				}
				result[n++] = *it;
				it++;
			}

			if(pstCurrNode->isleaf) break;
			pstCurrNode= (key<pstCurrNode->seperator) ? pstCurrNode->lchild : pstCurrNode->rchild;
		}

		qsort(result, n, sizeof(unsigned int), compare);
	}

	return n;
}

