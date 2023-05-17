/*
 *
 * Copyright (c) 2020
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LU YUHAI    (luyuhai@iie.ac.cn)
 * Last modification: 2020-04-20
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef H_IP_MATCHER_H
#define H_IP_MATCHER_H

#include <stddef.h>

#include "../../deps/log/log.h"

#ifdef __cplusplus
extern "C"
{
#endif

	 enum IP_TYPE {
		IPv4 = 4,
		IPv6 = 6
	};

	struct ipv4_range {
		unsigned int start_ip;   /* lower boundary(network-order) */
		unsigned int end_ip;     /* upper boundary(network-order) */
	};

	struct ipv6_range {
		unsigned int start_ip[4];  /* lower boundary(network-order) */
		unsigned int end_ip[4];    /* upper boundary(network-order) */
	};

	/* common type for ip rule */
	struct ip_rule {
		enum IP_TYPE type;          /* IPv4 or IPv6 */
		long long rule_id;		    /* rule id */
		void *user_tag;             /* point to user-defined data which will return with hit results */
		union {
			struct ipv4_range ipv4_rule;
			struct ipv6_range ipv6_rule;
		};
	};

	/* common type for scan data */
	struct ip_data {
		enum IP_TYPE type;			/* IPv4 or IPv6 */
		union {
			unsigned int ipv4;      /* network order */
			unsigned int ipv6[4];   /* network order */
		};
	};

	/* data type for scan result */
	struct scan_result {
		long long rule_id;	/* rule id */		
		void *tag;		    /* point to the same address as user_tag in struct ip_rule which has same rule_id */
	};

	struct ip_matcher;

	/**
     * @brief create an ip_matcher instance
     * 
     * @param rules[input]:    a set of ip rules
     * @param rule_num[input]: the number of ip rules
     * @param mem_use[output]: memory used by ip_matcher
    */
	struct ip_matcher *ip_matcher_new(struct ip_rule *rules, size_t rule_num, size_t *mem_use);

	/**
     * @brief scan ip_data to find out if has matched rules in ip_matcher
     * 
     * @param matcher[intput]: ip_matcher which created by ip_matcher_new
     * @param data[intput]:    ip_data to be scanned
     * @param result[input]:   result array to store the rule_id and user_tag if there are matching rules
     * @param size[input]:     result array size
    */
	int ip_matcher_match(struct ip_matcher *matcher, struct ip_data *data, 
                         struct scan_result *result, size_t size);

	/**
     * @brief destroy ip_matcher instance
    */
	void ip_matcher_free(struct ip_matcher *matcher);

#ifdef __cplusplus
}
#endif

#endif /* !defined(H_IP_MATCHER_H) */
