/*
**********************************************************************************************
*	File: ipport_matcher.cpp
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2023-10-09
*   Copyright: (c) Since 2023 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/
#include <assert.h>

#include "uthash/utarray.h"
#include "uthash/uthash.h"
#include "maat_utils.h"
#include "maat_limits.h"
#include "ipport_matcher.h"

struct port_range {
    uuid_t rule_uuid;
    void *tag;
    uint16_t min_port; /* host order */
    uint16_t max_port; /* host order */
};

struct ipport_node {
    int ip_type; //IPV4 or IPV6
    uint32_t start_ip_addr[4];
    uint32_t end_ip_addr[4];
    UT_array *port_range_list; //array to store <struct port_range>
    UT_hash_handle hh;
};

struct ipport_matcher {
    struct ipport_node *ipport_hash;
    struct ip_matcher *ip_matcher;
};

UT_icd ut_port_range_icd = {sizeof(struct port_range), NULL, NULL, NULL};
static inline int compare_port_range_for_sort(const void *a, const void *b)
{
    struct port_range range_a = *(const struct port_range *)a;
    struct port_range range_b = *(const struct port_range *)b;

    int ret = range_a.min_port - range_b.min_port;
    if (0 == ret) {
        ret = range_a.max_port - range_b.max_port;
    }

    return ret;
}

static inline int compare_port_range_for_find(const void *a, const void *b)
{
    struct port_range range_a = *(const struct port_range *)a;
    struct port_range range_b = *(const struct port_range *)b;

    int ret = -1;
    if (range_a.min_port >= range_b.min_port &&
        range_a.min_port <= range_b.max_port) {
        ret = 0;
    } else if (range_a.max_port < range_b.min_port) {
        ret = -1;
    } else {
        ret = 1;
    }

    return ret;
}

struct ipport_matcher *ipport_matcher_new(struct ipport_rule *rules, size_t rule_num)
{
    if (NULL == rules || 0 == rule_num) {
        return NULL;
    }

    struct ipport_matcher *matcher = ALLOC(struct ipport_matcher, 1);
    struct ipport_node *node = NULL;
    struct ip_rule *ip_rules = NULL;
    char *key = NULL;
    size_t key_len = 0;

    for (size_t i = 0; i < rule_num; i++) {
        if (rules[i].ip_type == IPV4) {
            key = (char *)&rules[i].ipv4;
            key_len = sizeof(rules[i].ipv4);
        } else {
            key = (char *)&rules[i].ipv6;
            key_len = sizeof(rules[i].ipv6);
        }

        HASH_FIND(hh, matcher->ipport_hash, key, key_len, node);
        if (NULL == node) {
            node = ALLOC(struct ipport_node, 1);

            if (rules[i].ip_type == IPV4) {
                node->ip_type = IPV4;
                node->start_ip_addr[0] = rules[i].ipv4.start_ip;
                node->end_ip_addr[0] = rules[i].ipv4.end_ip;
            } else {
                node->ip_type = IPV6;
                for (size_t j = 0; j < 4; j++) {
                    node->start_ip_addr[j] = rules[i].ipv6.start_ip[j];
                    node->end_ip_addr[j] = rules[i].ipv6.end_ip[j];
                }
            }

            utarray_new(node->port_range_list, &ut_port_range_icd);
            HASH_ADD_KEYPTR(hh, matcher->ipport_hash, key, key_len, node);
        }
        
        struct port_range range;
        range.min_port = rules[i].min_port;
        range.max_port = rules[i].max_port;
        uuid_copy(range.rule_uuid, rules[i].rule_uuid);
        range.tag = rules[i].user_tag;
        utarray_push_back(node->port_range_list, &range);
    }

    int ip_matcher_cnt = HASH_COUNT(matcher->ipport_hash);
    int ip_matcher_idx = 0;
    ip_rules = ALLOC(struct ip_rule, ip_matcher_cnt);

    struct ipport_node *tmp_node = NULL;
    HASH_ITER(hh, matcher->ipport_hash, node, tmp_node) {
        utarray_sort(node->port_range_list, compare_port_range_for_sort);

        struct port_range *range = utarray_front(node->port_range_list);
        ip_rules[ip_matcher_idx].type = node->ip_type;
        uuid_copy(ip_rules[ip_matcher_idx].rule_uuid, range->rule_uuid);
        ip_rules[ip_matcher_idx].user_tag = node;
        if (node->ip_type == IPV4) {
            ip_rules[ip_matcher_idx].ipv4_rule.start_ip = node->start_ip_addr[0];
            ip_rules[ip_matcher_idx].ipv4_rule.end_ip = node->end_ip_addr[0];
        } else {
            for (size_t j = 0; j < 4; j++) {
                ip_rules[ip_matcher_idx].ipv6_rule.start_ip[j] = node->start_ip_addr[j];
                ip_rules[ip_matcher_idx].ipv6_rule.end_ip[j] = node->end_ip_addr[j];
            }
        }
        ip_matcher_idx++;
    }

    assert(ip_matcher_idx == ip_matcher_cnt);

    size_t mem_used = 0;
    struct ip_matcher *ip_matcher = ip_matcher_new(ip_rules, ip_matcher_cnt, &mem_used);
    if (NULL == ip_matcher) {
        FREE(ip_rules);
        ipport_matcher_free(matcher);
        return NULL;
    }

    FREE(ip_rules);

    matcher->ip_matcher = ip_matcher;

    return matcher;
}

int ipport_matcher_match(struct ipport_matcher *matcher, const struct ip_addr *ip_addr,
                         uint16_t port, struct ipport_result *result_array, size_t array_size)
{
    if (NULL == matcher || NULL == ip_addr || NULL == result_array || 0 == array_size) {
        return -1;
    }

    struct scan_result result;
    struct ip_data ip_data = *(const struct ip_data *)ip_addr;

    int n_result = ip_matcher_match(matcher->ip_matcher, &ip_data, &result, 1);
    if (n_result <= 0) {
        return 0;
    }

    struct ipport_node *node = result.tag;

    uint16_t host_port = ntohs(port);
    struct port_range range;
    range.min_port = host_port;
    range.max_port = host_port;

    struct port_range *tmp_range = NULL;
    tmp_range = (struct port_range *)utarray_find(node->port_range_list,
                                                  &range, compare_port_range_for_find);
    if (tmp_range != NULL) {
        uuid_copy(result_array[0].rule_uuid, tmp_range->rule_uuid);
        result_array[0].tag = tmp_range->tag;
        return 1;
    }
    
    return 0;
}

void ipport_matcher_free(struct ipport_matcher *matcher)
{
    if (NULL == matcher) {
        return;
    }

    struct ipport_node *node = NULL, *tmp_node = NULL;
    HASH_ITER(hh, matcher->ipport_hash, node, tmp_node) {
        if (node->port_range_list != NULL) {
            utarray_free(node->port_range_list);
            node->port_range_list = NULL;
        }
        HASH_DEL(matcher->ipport_hash, node);

        FREE(node);
    }

    if (matcher->ip_matcher != NULL) {
        ip_matcher_free(matcher->ip_matcher);
        matcher->ip_matcher = NULL;
    }

    FREE(matcher);
}