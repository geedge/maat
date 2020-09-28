/*
 *
 * Copyright (c) 2020
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by: LIU YANBING    (liuyanbing@iie.ac.cn)
 * Last modification: 2020-09-01
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef H_FQDN_ENGINE_H
#define H_FQDN_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

    #include <stddef.h>

    struct FQDN_rule
    {
              unsigned int id;
              int is_suffix_match; /* is_suffix_match==0: exact match; is_suffix_match==1: longest suffix matching. */
              size_t len;
              char * FQDN;         /* Non-ASCII character is allowed. */
              void * user_tag;     /* A transparent user tag for convenient accessing, the caller is responsible for its memory management. */
    };

    struct FQDN_engine;

    struct FQDN_engine * FQDN_engine_new(const struct FQDN_rule * rules, size_t n_rule);

    struct FQDN_match
    {
              unsigned int id;
              unsigned int offset;  /* offset==0 for exact matching; offset>0 for longest suffix matching. */
              void * user_tag;
    };

    /*
    *Function:
    *        Search FQDN in the rule base
    *Paramters:
    *        instance[in]: Instance of FQDN engine
    *        FQDN[in]: FQDN for search
    *        FQDN_len[in]: Length of FQDN
    *        results[out]: An array to store matched FQDNs
    *        n_result[in]: Number of element in the result array
    * Return:
    *        0:  No matched FQDN;
    *        >0: Number of matched FQNDs which were stored in results;
    *        <0: Error.
    */
    int FQDN_engine_search(struct FQDN_engine * instance, const char * FQDN, size_t FQDN_len, struct FQDN_match * results, size_t n_result);

    void FQDN_engine_free(struct FQDN_engine * instance);

#ifdef __cplusplus
}
#endif

#endif
