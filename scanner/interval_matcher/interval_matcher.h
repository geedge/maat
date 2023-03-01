/*
 * @Author: Yang Yubo yangyubo@geedgenetworks.com
 * @Date: 2023-1-18 
 * @LastEditors: Yang Yubo yangyubo@geedgenetworks.com
 * @FilePath: /interval_matcher/include/interval_matcher.h
 */
#ifndef INTERVAL_MATCHER_H
#define INTERVAL_MATCHER_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

// if matched, return id and tag;
struct interval_result
{
    uint64_t rule_id; 

    /* A transparent user tag for convenient accessing, 
    the caller is responsible for its memory management. */
    void    *user_tag;    
};

struct interval_rule
{
    uint64_t start; // interval's start
    uint64_t end; // interval's end the max is ((uint64_t)(-1) - 1)
    struct interval_result result;
};


/* forward declaration;
   The internal structure 
   is not open to the outside */
struct interval_matcher;


/**
 * @description: to build a interval_matcher for matching;
 * @param {struct interval_rule} *rule: it's a array for rules;
 * @param {size_t} n_rule: it's the number of rules;
 * @return {struct interval_matcher*}: if NULL, build failed!
 */
struct interval_matcher *interval_matcher_new(struct interval_rule *rule, size_t n_rule);


/**
 * @description: to destroy interval_matcher after used;
 * @param {interval_matcher} *interval_matcher: the target need to free, can't be NULL;
 * @return {*}
 */
void interval_matcher_free(struct interval_matcher *interval_matcher);


/**
 * @description: matching, after this api, user can get an array of rules matched;
 * @param {struct interval_matcher} *interval_matcher: a matcher;
 * @param {struct interval_result} *result: rusult arrays, user alloc memory;
 * @param {size_t} n_result: the MAX number of rules matched;
 * @param {uint64_t} target: need to match, the max is ((uint64_t)(-1) - 1);
 * @return {int}: The return value is the number of matched rules, which may be 0; if -1, invalid parameter;
 */
int interval_matcher_match(struct interval_matcher *interval_matcher, uint64_t target, struct interval_result *result, size_t n_result);

#ifdef __cplusplus
}
#endif

#endif // INTERVAL_MATCHER_H