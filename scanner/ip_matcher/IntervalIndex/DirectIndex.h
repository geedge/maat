/*
 *
 * Copyright (c) 2008--2012
 * Advanced Algorithm and Algorithm Engineering Group
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2012-11-27
 *
 * This code is the exclusive and proprietary property of NELIST and IIE-CAS. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef H_DIRECT_INDEX_CPP_H
#define H_DIRECT_INDEX_CPP_H

#include "IntervalIndex.h"

class CDirectIndex : public CIntervalIndex
{
public:
	CDirectIndex();

	virtual ~CDirectIndex();

	virtual long long PreProcessing(const std::vector<unsigned int>& a, const std::vector<unsigned int>& b);

	virtual int Find(unsigned int key, unsigned int * result, unsigned int size);

private:
	unsigned int   m_L[65537];
	unsigned int   m_theta;
	unsigned int   m_min_key;
	unsigned int   m_max_key;
	unsigned int * m_keys;
	unsigned int * m_ptr;
	unsigned int * m_values;
};

#endif
