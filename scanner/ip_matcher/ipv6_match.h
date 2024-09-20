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

#ifndef H_IPV6_MATCH_H
#define H_IPV6_MATCH_H

#include "rule_match.h"
#include "IntervalIndex/PortIndex.h"
#include "IntervalIndex/Int128IntervalIndex.h"
#include "ip_matcher.h"

typedef struct _ipv6_rule_t{

	struct ipv6_range 	rule;
	uuid_t		    rule_uuid;
	void *				tag;
}ipv6_rule_t;

class CIPv6Match : public CRuleMatch
{
public:
	CIPv6Match();

	~CIPv6Match();

	virtual long long initialize(const map<long long, struct ip_rule>& rules);

	virtual int search_rule(const struct ip_data * data, struct scan_result * presult, unsigned int size);

private:
	unsigned int			m_rnum;
	ipv6_rule_t *			m_rules;
	CInt128IntervalIndex *	m_ipv6Indexer;
};

#endif
