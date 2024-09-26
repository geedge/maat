/*
 * @Author: Yang Yubo yangyubo@geedgenetworks.com
 * @Date: 2022-12-19 
 * @LastEditors: Yang Yubo yangyubo@geedgenetworks.com
 * @LastEditTime: 2022-12-19 22:14:10
 * @FilePath: /flag_matcher/include/flag_matcher.h
 */

#ifndef FLAG_MATCHER_H
#define FLAG_MATCHER_H
#include <stdint.h>
#include <stddef.h>
#include <uuid/uuid.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct flag_rule
{
    uint64_t flag;
    uint64_t mask;
    uuid_t rule_uuid; // unique for a rule;   
};


// if matched, return id and tag;
struct flag_result
{
    uuid_t rule_uuid; // unique for a rule;    
};


/* forward declaration;
   The internal structure 
   is not open to the outside */
struct flag_matcher;


/**
 * @description: to build a flag matcher for matching;
 * @param {struct flag_rule} *rule: it's a array for rules;
 * @param {uint32_t} n_rule: it's the number of rules;
 * @return {struct flag_matcher*}: if NULL, build failed!
 */
struct flag_matcher *flag_matcher_new(struct flag_rule *rule, size_t n_rule);


/**
 * @description: matching, after this api, user can get an array of rules matched;
 * @param {struct flag_matcher} *flag_matcher: a matcher;
 * @param {struct result_id} *result: rusult arrays, user alloc memory;
 * @param {uint32_t} n_result: the MAX number of rules matched;
 * @param {uint64_t} flag: need to match;
 * @return {int}: The return value is the number of matched rules, which may be 0;
 */
int flag_matcher_match(struct flag_matcher *flag_matcher, uint64_t flag, struct flag_result *result, size_t n_result);


/**
 * @description: to destroy flag matcher after used;
 * @param {flag_matcher} *flag_matcher: the target need to free, can't be NULL;
 * @return {*}
 */
void flag_matcher_free(struct flag_matcher *flag_matcher);


#ifdef __cplusplus
}
#endif

#endif // FLAG_MATCHER_H