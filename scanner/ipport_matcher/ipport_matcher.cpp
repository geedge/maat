/*
**********************************************************************************************
*	File: ipport_matcher.cpp
*   Description: 
*	Authors: Liu wentan <liuwentan@geedgenetworks.com>
*	Date:    2023-10-09
*   Copyright: (c) Since 2023 Geedge Networks, Ltd. All rights reserved.
***********************************************************************************************
*/

#include "uthash/utarray.h"
#include "uthash/uthash.h"
#include "maat_utils.h"
#include "maat_limits.h"
#include "ipport_matcher.h"

struct port_range_entity {
    long long rule_id;
    void *tag;
    struct port_range range;
};

struct ipport_node {
    char *key;      //key must be ipv4/ipv6 string
    size_t key_len;
    UT_array *port_range_entities; //array to store <struct port_range_entity>
    UT_hash_handle hh;
};

struct ipport_matcher {
    struct ipport_node *ipport_hash;
};

UT_icd ut_port_range_entity_icd = {sizeof(struct port_range_entity), NULL, NULL, NULL};
static inline int compare_port_range_entity_for_sort(const void *a, const void *b)
{
    struct port_range_entity entity_a = *(const struct port_range_entity *)a;
    struct port_range_entity entity_b = *(const struct port_range_entity *)b;

    int ret = entity_a.range.min_port - entity_b.range.min_port;
    if (0 == ret) {
        ret = entity_a.range.max_port - entity_b.range.max_port;
    }

    return ret;
}

static inline int compare_port_range_entity_for_find(const void *a, const void *b)
{
    struct port_range_entity entity_a = *(const struct port_range_entity *)a;
    struct port_range_entity entity_b = *(const struct port_range_entity *)b;

    int ret = -1;
    if (entity_a.range.min_port >= entity_b.range.min_port &&
        entity_a.range.min_port <= entity_b.range.max_port) {
        ret = 0;
    } else if (entity_a.range.max_port < entity_b.range.min_port) {
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
    char *key = NULL;
    size_t key_len = 0;

    for (size_t i = 0; i < rule_num; i++) {

        if (rules[i].ip.ip_type == IPV4) {
            key = (char *)&rules[i].ip.ipv4;
            key_len = 4;
        } else {
            key = (char *)&rules[i].ip.ipv6;
            key_len = 16;
        }

        HASH_FIND(hh, matcher->ipport_hash, key, key_len, node);

        if (NULL == node) {
            node = ALLOC(struct ipport_node, 1);
            node->key = ALLOC(char, key_len);
            memcpy(node->key, key, key_len);
            node->key_len = key_len;
            utarray_new(node->port_range_entities, &ut_port_range_entity_icd);
            HASH_ADD_KEYPTR(hh, matcher->ipport_hash, node->key, node->key_len, node);
        }
        
        struct port_range_entity entity;
        entity.range = rules[i].port_range;
        entity.rule_id = rules[i].rule_id;
        entity.tag = rules[i].user_tag;
        utarray_push_back(node->port_range_entities, &entity);
    }

    struct ipport_node *tmp_node = NULL;
    HASH_ITER(hh, matcher->ipport_hash, node, tmp_node) {
        utarray_sort(node->port_range_entities, compare_port_range_entity_for_sort);
    }

    return matcher;
}

int ipport_matcher_match(struct ipport_matcher *matcher, const struct ip_addr *ip_addr,
                         uint16_t port, struct ipport_result *result_array, size_t array_size)
{
    if (NULL == matcher || NULL == ip_addr || NULL == result_array || 0 == array_size) {
        return -1;
    }

    char *key = NULL;
    size_t key_len = 0;

    if (ip_addr->ip_type == IPV4) {
        key = (char *)&ip_addr->ipv4;
        key_len = 4;
    } else {
        key = (char *)ip_addr->ipv6;
        key_len = 16;
    }

    struct ipport_node *node = NULL;
    HASH_FIND(hh, matcher->ipport_hash, key, key_len, node);
    if (NULL == node) {
        return 0;
    }

    uint16_t host_port = ntohs(port);
    struct port_range_entity entity;
    entity.range.min_port = host_port;
    entity.range.max_port = host_port;

    struct port_range_entity *tmp_entity = NULL;
    tmp_entity = (struct port_range_entity *)utarray_find(node->port_range_entities,
                                                          &entity, compare_port_range_entity_for_find);
    if (tmp_entity != NULL) {
        result_array[0].rule_id = tmp_entity->rule_id;
        result_array[0].tag = tmp_entity->tag;
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
        if (node->key != NULL) {
            FREE(node->key);
        }

        if (node->port_range_entities != NULL) {
            utarray_free(node->port_range_entities);
            node->port_range_entities = NULL;
        }
        HASH_DEL(matcher->ipport_hash, node);

        FREE(node);
    }

    FREE(matcher);
}