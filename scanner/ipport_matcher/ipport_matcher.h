/*
**********************************************************************************************
*	File: ipport_matcher.h
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2023-10-09
*   Copyright: (c) Since 2023 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#ifndef _IPPORT_MATCHER_H_
#define _IPPORT_MATCHER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

#include "maat.h"

struct ipport_rule {
    long long rule_id; /* rule id */
    void *user_tag;    /* point to user-defined data which will return with hit results */
    struct ip_addr ip;
    uint16_t min_port; /* host order */
    uint16_t max_port; /* host order */
};

struct ipport_result {
    long long rule_id; /* matched rule id */
    void *tag;         /* point to the same address as user_tag in struct ipport_rule which has same rule_id */
};

struct ipport_matcher;

/**
 * @brief create an ipport_matcher instance
 *
 * @param rules   [input]: a set of ipport rules
 * @param rule_num[input]: the number of ipport rules
 */
struct ipport_matcher *ipport_matcher_new(struct ipport_rule *rules, size_t rule_num);

/**
 * @brief scan ip_addr to find out if has matched rules in ipport_matcher
 *
 * @param matcher [intput]: ipport_matcher which created by ipport_matcher_new
 * @param data    [intput]: ip_addr to be scanned
 * @param result  [output]: result array to store the rule_id and user_tag of the matching rules
 * @param size    [input]:  result array size
 */
int ipport_matcher_match(struct ipport_matcher *matcher, const struct ip_addr *ip_addr,
                         uint16_t port, struct ipport_result *result_array, size_t array_size);

/**
 * @brief destroy ipport_matcher instance
 */
void ipport_matcher_free(struct ipport_matcher *matcher);

#ifdef __cplusplus
}
#endif

#endif