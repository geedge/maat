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

#ifndef H_NAIVE_INTERVAL_INDEX_CPP_H
#define H_NAIVE_INTERVAL_INDEX_CPP_H

#include "IntervalIndex.h"
#include "DirectIndex.h"

class CNaiveIntervalIndex : public CIntervalIndex
{
public:
	CNaiveIntervalIndex();

	virtual ~CNaiveIntervalIndex();

	virtual long long PreProcessing(const std::vector<unsigned int>& a, const std::vector<unsigned int>& b);

	virtual int Find(unsigned int key, unsigned int * result, unsigned int size);

private:
	CDirectIndex * m_pDirectIndexer;
	unsigned int * m_IndexForMaxInt;
	int            m_iEndPointsNum;
	unsigned int * m_pEndPoints;
	unsigned int * m_pIDPtr;
	unsigned int * m_pIDList;
	int            m_L[65537];
	unsigned int * m_IndexForWholeInterval;
};

#endif
