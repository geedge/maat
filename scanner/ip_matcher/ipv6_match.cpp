/*
 *
 * Copyright (c) 2008-2016
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2016-06-03
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#include "ipv6_match.h"
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <algorithm>
#include "IntervalIndex/Int128IntervalIndex.h"
using namespace std;

//#define DEBUG_IPV6_MATCH

bool cmp_ipv6_rule(ipv6_rule_t a, ipv6_rule_t b)
{

	uint128_t l_a(a.rule.start_ip);
	uint128_t h_a(a.rule.end_ip);
	uint128_t l_b(b.rule.start_ip);
	uint128_t h_b(b.rule.end_ip);

	uint128_t interval_a = h_a - l_a;
	uint128_t interval_b = h_b - l_b;

	return interval_a < interval_b;
}

CIPv6Match::CIPv6Match()
{
	m_ipv6Indexer=NULL;
	m_rnum=0;
	m_rules=NULL;
}

CIPv6Match::~CIPv6Match()
{

	if(m_ipv6Indexer!=NULL) delete m_ipv6Indexer;

	if(m_rules!=NULL)
	{
		delete [] m_rules;
	}

}


long long CIPv6Match::initialize(const map<long long, struct ip_rule>& rules)
{
	m_rnum = rules.size();
	if (m_rnum == 0) {
        return 0;
    }

	long long mem_bytes = 0;

	m_rules = new ipv6_rule_t[m_rnum];
	mem_bytes += (sizeof(struct ipv6_range) + sizeof(unsigned int) + sizeof(void *)) * m_rnum;

	unsigned int i = 0;
	for (map<long long, struct ip_rule>::const_iterator it = rules.begin(); it != rules.end(); ++it) {
		struct ipv6_range arule = it->second.ipv6_rule;;
		m_rules[i].rule = arule;
		uuid_copy(m_rules[i].rule_uuid, it->second.rule_uuid);
		m_rules[i++].tag = it->second.user_tag;
	}

	sort(&m_rules[0], &m_rules[m_rnum], cmp_ipv6_rule);

	vector<uint128_t> A, B;
	for (i = 0; i < m_rnum; i++) {
		uint128_t a(m_rules[i].rule.start_ip);
		uint128_t b(m_rules[i].rule.end_ip);
		A.push_back(a);
		B.push_back(b);
	}

	m_ipv6Indexer = new CInt128IntervalIndex;
	mem_bytes += sizeof(CInt128IntervalIndex);
    
	long long ret = m_ipv6Indexer->PreProcessing(A, B);
	if (ret < 0) {
        return -1;
    }

	mem_bytes += ret;

	return mem_bytes;
}

int CIPv6Match::search_rule(const struct ip_data * data, struct scan_result * presult, unsigned int size)
{
	if(m_rnum==0) return 0;

	unsigned int hit_num=0;
	unsigned int m_v[size];
	uint128_t key(data->ipv6);
	int ret=m_ipv6Indexer->Find(&key, m_v, size);
	if(ret<0) return -1;

	sort(&m_v[0], &m_v[ret]);

	for(int i = 0; i < ret; i++)
	{
		if(hit_num == size)
			return hit_num;
		unsigned int index = m_v[i];
		uuid_copy(presult[hit_num].rule_uuid, m_rules[index].rule_uuid);
		presult[hit_num++].tag = m_rules[index].tag;
	}

	return hit_num;
}
