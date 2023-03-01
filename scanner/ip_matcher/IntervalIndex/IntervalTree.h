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

#ifndef H_INTERVAL_TREE_CPP_H
#define H_INTERVAL_TREE_CPP_H

#include "IntervalIndex.h"

class CIntervalTree : public CIntervalIndex
{
public:
	struct stIntervalNode
	{
		bool isleaf;
		unsigned int seperator;
		std::vector<unsigned int> ids;
		stIntervalNode * lchild;
		stIntervalNode * rchild;
	};

public:
	CIntervalTree();

	virtual ~CIntervalTree();

	virtual long long PreProcessing(const std::vector<unsigned int>& a, const std::vector<unsigned int>& b);

	virtual int Find(unsigned int key, unsigned int * result, unsigned int size);

private:
	stIntervalNode * BuildBalancedTree(unsigned int a[], unsigned int n);

	void AddInterval(stIntervalNode * pstCurrNode, unsigned int inf, unsigned int sup, 
		unsigned int a, unsigned int b, unsigned int id);

private:
	stIntervalNode * m_pstRoot;
	unsigned int m_uiNodeNum;
	long long m_iMemBytes;
	std::vector<unsigned int> m_IndexForMaxInt;
};

#endif
