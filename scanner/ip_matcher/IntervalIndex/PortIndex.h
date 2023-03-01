/*
 *
 * Copyright (c) 2008-2016
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2016-05-31
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef H_PORT_INDEX_CPP_H
#define H_PORT_INDEX_CPP_H

#include "IntervalIndex.h"

class CPortIndex : public CIntervalIndex
{
public:
	CPortIndex();

	virtual ~CPortIndex();

	virtual long long PreProcessing(const std::vector<unsigned int>& a, const std::vector<unsigned int>& b);

	virtual int Find(unsigned int key, unsigned int * result, unsigned int size);

private:
	unsigned char  m_bitmap[8192];
	unsigned int   m_L[65537];
	unsigned int * m_values;
};

#endif
