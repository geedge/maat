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

#ifndef H_FAST_INTERVAL_INDEX_CPP_H
#define H_FAST_INTERVAL_INDEX_CPP_H

#include "IntervalIndex.h"

class CFastIntervalIndex : public CIntervalIndex
{
public:
	// the range is [0, 2^r), and we partition it into intervals of size 2^l
	CFastIntervalIndex(unsigned int r=32, unsigned int l=16);

	virtual ~CFastIntervalIndex();

	virtual long long PreProcessing(const std::vector<unsigned int>& a, const std::vector<unsigned int>& b);

	virtual int Find(unsigned int key, unsigned int * result, unsigned int size);

private:
	std::vector<unsigned int> m_IndexForMaxInt;
	unsigned int m_r;
	unsigned int m_l;
	CIntervalIndex ** m_pIndexer;
	std::vector< std::vector<unsigned int> > m_IDs;
};

#endif
