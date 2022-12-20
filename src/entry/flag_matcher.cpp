#include <malloc.h>
#include <string.h>
#include "flag_matcher.h"

#define RULE_BIT_SIZE_MASK 0x8000000000000000

struct flag_matcher
{
    struct flag_rule  *rule_table;
    uint32_t          number;
};

struct flag_matcher *flag_matcher_new(struct flag_rule *rule, uint32_t n_rule)
{
    if (!rule)
    {
        fprintf(stderr, "Invalid argument: struct flag_rule *rule\n");
        return NULL;
    }

    if (!n_rule)
    {
        fprintf(stderr, "Invalid argument: uint32_t n_rule\n");
        return NULL;
    }

    struct flag_matcher *flag_matcher;

    flag_matcher = (struct flag_matcher *)malloc(sizeof(struct flag_matcher));
    memset(flag_matcher, 0, sizeof(struct flag_matcher));
    flag_matcher->number = n_rule;

    flag_matcher->rule_table = (struct flag_rule *)malloc(sizeof(struct flag_rule) * n_rule);
    memmove(flag_matcher->rule_table, rule, sizeof(struct flag_rule) * n_rule);

    return flag_matcher;
}


void flag_matcher_free(struct flag_matcher *flag_matcher)
{   
    if (!flag_matcher)
    {
        fprintf(stderr, "Invalid argument: struct flag_matcher *flag_matcher\n");
        return;
    }

    free(flag_matcher->rule_table);
    free(flag_matcher);
    return;
}


int flag_matcher_match(struct flag_matcher *flag_matcher,  uint64_t flag, struct flag_match *result, uint32_t n_result)
{
    if (!flag_matcher)
    {
        fprintf(stderr, "Invalid argument: struct flag_matcher *flag_matcher\n");
        return -1;
    }

    uint32_t result_number = 0;

    for (uint32_t i = 0; i < flag_matcher->number; i ++)
    {
        if (!((flag ^ flag_matcher->rule_table[i].flag) & flag_matcher->rule_table[i].mask))
        {
            result[result_number].flag_rule_id = flag_matcher->rule_table[i].flag_rule_id;
            result[result_number].user_tag = flag_matcher->rule_table[i].user_tag;
            result_number++;
            if (result_number == n_result)
            {
                fprintf(stderr, "result array is full\n");
                return result_number;
            }
        }
    }

    return result_number;
}