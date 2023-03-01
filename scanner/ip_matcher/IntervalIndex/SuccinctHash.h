/*
 *
 * Copyright (c) 2008--2015
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2015-12-9
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef H_SUCCINCT_HASH_CPP_H
#define H_SUCCINCT_HASH_CPP_H

#include "sigmastar_tools.h"

class CSuccinctHash
{
public:
	CSuccinctHash();
	~CSuccinctHash();

	long long init(unsigned int keys[], unsigned int values[], unsigned int num);
	int find(unsigned int key, unsigned int * value, unsigned int size);

protected:
	unsigned int rank(unsigned int h);

protected:
	unsigned int   m_hash_bits;
	packedRT_t *   m_RT;
	unsigned int * m_kv_ptr;
	unsigned int * m_kv_array;
};

#endif // H_SUCCINCT_HASH_CPP_H
