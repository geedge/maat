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

/* 仅适用于IP字段，并且为单点IP或者8-bit掩码的IP */

#ifndef H_IPMASK_INDEX_CPP_H
#define H_IPMASK_INDEX_CPP_H

#include "IntervalIndex.h"
#include "SuccinctHash.h"
#include <vector>
using namespace std;

bool is_8bit_ipmask(const vector<unsigned int>& a, const vector<unsigned int>& b);

class CIPMaskIndex : public CIntervalIndex
{
public:
	CIPMaskIndex();

	virtual ~CIPMaskIndex();

	virtual long long PreProcessing(const std::vector<unsigned int>& a, const std::vector<unsigned int>& b);

	virtual int Find(unsigned int key, unsigned int * result, unsigned int size);

private:
	bool                m_is_single;
	unsigned char       m_bitmap[1U<<21];
	unsigned int        m_L[(1U<<24)+1];
	unsigned int *      m_values;
	CSuccinctHash *     m_ip_hash;
};

#endif
