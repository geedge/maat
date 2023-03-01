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

#ifndef H_INTERVAL_INDEX_CPP_H
#define H_INTERVAL_INDEX_CPP_H

#include <vector>

class CIntervalIndex
{
public:
	CIntervalIndex();

	virtual ~CIntervalIndex();

	/*
	closed interval: [ a[i] , b[i] ] such that a[i]<=b[i]
	*/
	virtual long long PreProcessing(const std::vector<unsigned int>& a, const std::vector<unsigned int>& b)=0;

	/*
	report the indexes of intervals that contain the key.
	*/
	virtual int Find(unsigned int key, unsigned int * result, unsigned int size)=0;//changed by luyuhai, 2015.11.09
};

#endif
