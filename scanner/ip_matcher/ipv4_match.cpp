/*
 *
 * Copyright (c)2020
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YUHAI    (luyuhai@iie.ac.cn)
 * Last modification: 2020-04-16
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#include "ipv4_match.h"
#include "IntervalIndex/NaiveIntervalIndex.h"
#include "IntervalIndex/IPMaskIndex.h"
#include "IntervalIndex/PortIndex.h"
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <algorithm>
using namespace std;

//#define DEBUG_IPV4_MATCH

bool cmp(ipv4_rule_t a, ipv4_rule_t b)
{
	unsigned int inteval_a = a.rule.end_ip - a.rule.start_ip;
	unsigned int inteval_b = b.rule.end_ip - b.rule.start_ip;
	return inteval_a < inteval_b;
}

CIPv4Match::CIPv4Match()
{
	m_pIndexer=NULL;
	m_rnum=0;
	m_rules=NULL;
}

CIPv4Match::~CIPv4Match()
{
	if(m_pIndexer!=NULL) delete m_pIndexer;
	
	if(m_rules!=NULL)
		delete [] m_rules;

}

long long CIPv4Match::initialize(const map<long long, struct ip_rule>& rules)
{
	m_rnum=rules.size();
	if(m_rnum==0) return 0;

	long long mem_bytes=0;

	m_rules = new ipv4_rule_t[m_rnum];
	mem_bytes+=(sizeof(struct ipv4_range)+sizeof(unsigned int)+sizeof(void *))*m_rnum;

	vector<unsigned int> a, b;
	unsigned int i=0;
	for(map<long long, struct ip_rule>::const_iterator it=rules.begin(); it!=rules.end(); ++it)
	{
		struct ipv4_range arule = it->second.ipv4_rule;
		m_rules[i].rule = arule;
		uuid_copy(m_rules[i].rule_uuid, it->second.rule_uuid);
		m_rules[i++].tag = it->second.user_tag;
	}

	//���ݵ���ip�ķ�Χ��С����
	sort(&m_rules[0], &m_rules[m_rnum],cmp);

	for(unsigned int i = 0; i < m_rnum; i++)
	{
		a.push_back(m_rules[i].rule.start_ip);
		b.push_back(m_rules[i].rule.end_ip);;
	}

	m_pIndexer = new CNaiveIntervalIndex;
	mem_bytes+=sizeof(CNaiveIntervalIndex);
	int ret=m_pIndexer->PreProcessing(a, b);
	if(ret<0) return -1;
	mem_bytes+=ret;
	a.clear();
	b.clear();


	return mem_bytes;
}

int CIPv4Match::search_rule(const struct ip_data * data, struct scan_result * presult, unsigned int size)
{
	unsigned int hit_num=0;
	unsigned int m_v[size];
	int ret=m_pIndexer->Find(data->ipv4, m_v, size);
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
