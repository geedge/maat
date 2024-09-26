/*
 * @Author: Yang Yubo yangyubo@geedgenetworks.com
 * @Date: 2022-12-19 22:10:26
 * @LastEditors: Yang Yubo yangyubo@geedgenetworks.com
 * @LastEditTime: 2022-12-19 22:13:57
 * @FilePath: /flag_matcher/src/flag_matcher.cpp
 * @Description: Here is the implementation of flag matcher.
 */

#include <malloc.h>
#include <string.h>
#include <assert.h>
#include "flag_matcher.h"

#define ALLOC(type, number) (type *)calloc(sizeof(type), number)
#define FREE(p)             {free(p);p=NULL;}

struct flag_matcher
{
    struct flag_rule *rule_table;
    uint32_t          number;
};



struct flag_matcher *flag_matcher_new(struct flag_rule *rule, size_t n_rule)
{
    if (!rule || !n_rule)
        return NULL;

    struct flag_matcher *flag_matcher;

    flag_matcher = ALLOC(struct flag_matcher , 1);
    assert(flag_matcher);

    flag_matcher->number = n_rule;
    flag_matcher->rule_table = ALLOC(struct flag_rule , n_rule);
    assert(flag_matcher->rule_table);

    memcpy(flag_matcher->rule_table, rule, sizeof(struct flag_rule) * n_rule); 

    return flag_matcher;
}


void flag_matcher_free(struct flag_matcher *flag_matcher)
{   
    if (!flag_matcher)
    {
        return;
    }

    FREE(flag_matcher->rule_table);
    FREE(flag_matcher);

    return;
}


int flag_matcher_match(struct flag_matcher *flag_matcher, uint64_t flag, struct flag_result *result, size_t n_result)
{
    if (!flag_matcher || !result)
    {
        return -1;
    }

    uint32_t result_number = 0;
    uint32_t rules_number = flag_matcher->number;

    for (uint32_t i = 0; i < rules_number; i ++)
    {
        if (!((flag ^ flag_matcher->rule_table[i].flag) & flag_matcher->rule_table[i].mask))
        {
            uuid_copy(result[result_number].rule_uuid, flag_matcher->rule_table[i].rule_uuid);

            if (result_number >= n_result)
            {
                return result_number;
            }
        }
    }

    return result_number;
}
