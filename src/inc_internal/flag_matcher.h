#ifndef FLAG_MATCHER_H
#define FLAG_MATCHER_H
#include <stdint.h>
#include <stddef.h>

struct flag_rule
{
    uint64_t flag;
    uint64_t mask;
    uint32_t flag_rule_id;
    void *user_tag;
};

struct flag_match {
    uint32_t flag_rule_id;
    void *user_tag;
};

struct flag_matcher;

struct flag_matcher *flag_matcher_new(struct flag_rule *rule, uint32_t n_rule);
void flag_matcher_free(struct flag_matcher *flag_matcher);

int flag_matcher_match(struct flag_matcher *flag_matcher, uint64_t flag, struct flag_match *result, uint32_t n_result);






#endif // FLAG_MATCHER_H