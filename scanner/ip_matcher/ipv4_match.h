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

#ifndef H_IPV4_MATCH_H
#define H_IPV4_MATCH_H

#include "rule_match.h"
#include "IntervalIndex/IntervalIndex.h"
#include "ip_matcher.h"

typedef struct _ipv4_rule_t{

	struct ipv4_range 	rule;
	void *				tag;
	uuid_t 		    rule_uuid;
}ipv4_rule_t;

class CIPv4Match : public CRuleMatch
{
public:
	CIPv4Match();

	~CIPv4Match();

	virtual long long initialize(const map<long long, struct ip_rule>& rules);

	virtual int search_rule(const struct ip_data * data, struct scan_result * presult, unsigned int size);

private:
	unsigned int			m_rnum;
	ipv4_rule_t *			m_rules;
	CIntervalIndex *		m_pIndexer;
};

#endif
