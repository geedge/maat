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

#ifndef H_CEI_CPP_H
#define H_CEI_CPP_H

#include <limits.h>
#include "IntervalIndex.h"

#include <vector>

class CEI : public CIntervalIndex
{
public:
	CEI(unsigned int r=65536, unsigned int L=64);

	virtual ~CEI();

	virtual long long PreProcessing(const std::vector<unsigned int>& a, const std::vector<unsigned int>& b);

	virtual int Find(unsigned int key, unsigned int * result, unsigned int size);

private:
	void BestPartition(unsigned int id, unsigned int a, unsigned int b, std::vector< std::vector<unsigned int> >& IDList);

private:
	unsigned int m_r; // maximum range of integer
	unsigned int m_L; // segment size for each CEI virtual construct
	unsigned int * m_pIDList;
	unsigned int * m_pIDArray;
	
};

#endif
