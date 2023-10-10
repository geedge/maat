#include <gtest/gtest.h>

#include "log/log.h"
#include "ipport_matcher.h"
#include "maat_utils.h"
#include "cJSON/cJSON.h"

#define MAX_ARRAY_SIZE 6

struct log_handle *g_logger = NULL;

/* 
    rule port range [100, 150]
    match input port = 110, which is in port range
    match input port = 100, which is on port range boundary
*/
TEST(ipv4port_matcher, MatchedOneRuleInPortRange) {
    const char *ip1_str = "192.168.0.1";
    struct ipport_rule rules[MAX_ARRAY_SIZE];

    rules[0].rule_id = 100;
    rules[0].ip.ip_type = IPV4;
    rules[0].port_range.min_port = 100;
    rules[0].port_range.max_port = 150;
    inet_pton(AF_INET, ip1_str, &rules[0].ip.ipv4);

    struct ipport_matcher *matcher = ipport_matcher_new(rules, 1);
    ASSERT_TRUE(matcher != NULL);

    struct ip_addr ip;
    ip.ip_type = IPV4;
    inet_pton(AF_INET, ip1_str, &ip.ipv4);
    uint16_t port = htons(120);

    struct ipport_result results[MAX_ARRAY_SIZE];
    int ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 100);

    ipport_matcher_free(matcher);
    matcher = NULL;
}

TEST(ipv4port_matcher, MatchedOneRuleOnPortRangeBoundary) {
    const char *ip1_str = "192.168.0.1";
    struct ipport_rule rules[MAX_ARRAY_SIZE];

    rules[0].rule_id = 100;
    rules[0].ip.ip_type = IPV4;
    rules[0].port_range.min_port = 100;
    rules[0].port_range.max_port = 150;
    inet_pton(AF_INET, ip1_str, &rules[0].ip.ipv4);

    struct ipport_matcher *matcher = ipport_matcher_new(rules, 1);
    ASSERT_TRUE(matcher != NULL);

    struct ip_addr ip;
    ip.ip_type = IPV4;
    inet_pton(AF_INET, ip1_str, &ip.ipv4);
    uint16_t port = htons(100);

    struct ipport_result results[MAX_ARRAY_SIZE];
    int ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 100);

    memset(results, 0, sizeof(results));
    port = htons(150);

    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 100);

    ipport_matcher_free(matcher);
    matcher = NULL;
}

TEST(ipv4port_matcher, MatchedMultiRuleInPortRange) {
    const char *ip1_str = "192.168.0.1";
    struct ipport_rule rules[MAX_ARRAY_SIZE];

    memset(rules, 0, sizeof(rules));

    rules[0].rule_id = 100;
    rules[0].ip.ip_type = IPV4;
    rules[0].port_range.min_port = 100;
    rules[0].port_range.max_port = 150;
    inet_pton(AF_INET, ip1_str, &rules[0].ip.ipv4);

    rules[1].rule_id = 200;
    rules[1].ip.ip_type = IPV4;
    rules[1].port_range.min_port = 110;
    rules[1].port_range.max_port = 160;
    inet_pton(AF_INET, ip1_str, &rules[1].ip.ipv4);

    rules[2].rule_id = 300;
    rules[2].ip.ip_type = IPV4;
    rules[2].port_range.min_port = 120;
    rules[2].port_range.max_port = 170;
    inet_pton(AF_INET, ip1_str, &rules[2].ip.ipv4);

    rules[3].rule_id = 400;
    rules[3].ip.ip_type = IPV4;
    rules[3].port_range.min_port = 130;
    rules[3].port_range.max_port = 180;
    inet_pton(AF_INET, ip1_str, &rules[3].ip.ipv4);

    rules[4].rule_id = 500;
    rules[4].ip.ip_type = IPV4;
    rules[4].port_range.min_port = 140;
    rules[4].port_range.max_port = 190;
    inet_pton(AF_INET, ip1_str, &rules[4].ip.ipv4);

    rules[5].rule_id = 600;
    rules[5].ip.ip_type = IPV4;
    rules[5].port_range.min_port = 150;
    rules[5].port_range.max_port = 200;
    inet_pton(AF_INET, ip1_str, &rules[5].ip.ipv4);

    struct ipport_matcher *matcher = ipport_matcher_new(rules, MAX_ARRAY_SIZE);
    ASSERT_TRUE(matcher != NULL);

    struct ip_addr ip;
    ip.ip_type = IPV4;
    inet_pton(AF_INET, ip1_str, &ip.ipv4);
    uint16_t port = htons(90);

    //no match rule_id
    struct ipport_result results[MAX_ARRAY_SIZE];
    int ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 0);

    //match rule_id:100
    memset(results, 0, sizeof(results));
    port = htons(100);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 100);

    /* sorted port range array: [[100,150], [110,160], [120,170], [130,180], [140,190], [150,200]]
                        rule_id: 100,        200,       300,       400,       500,       600

      match rule_id:100, 200, but return only one rule_id:200(reference binary search logic)
     */
    memset(results, 0, sizeof(results));
    port = htons(110);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 200);

    // match rule_id:100, 200, 300, but return only one rule_id:200(reference binary search logic)
    memset(results, 0, sizeof(results));
    port = htons(120);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 200);

    // match rule_id:100, 200, 300, 400, but return only one rule_id:400(reference binary search logic)
    memset(results, 0, sizeof(results));
    port = htons(130);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 400);

    // match rule_id:100, 200, 300, 400, 500, but return only one rule_id:400(reference binary search logic)
    memset(results, 0, sizeof(results));
    port = htons(140);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 400);

    // match rule_id:100, 200, 300, 400, 500, 600, but return only one rule_id:400(reference binary search logic)
    memset(results, 0, sizeof(results));
    port = htons(150);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 400);

    // match rule_id:200, 300, 400, 500, 600, but return only one rule_id:400(reference binary search logic)
    memset(results, 0, sizeof(results));
    port = htons(160);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 400);

    // match rule_id:300, 400, 500, 600, but return only one rule_id:400(reference binary search logic)
    memset(results, 0, sizeof(results));
    port = htons(170);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 400);

    // match rule_id:400, 500, 600, but return only one rule_id:400(reference binary search logic)
    memset(results, 0, sizeof(results));
    port = htons(180);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 400);

    // match rule_id:500, 600, but return only one rule_id:600(reference binary search logic)
    memset(results, 0, sizeof(results));
    port = htons(190);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 600);

    // match rule_id:600, but return only one rule_id:600
    memset(results, 0, sizeof(results));
    port = htons(200);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 600);

    // no match rule_id
    memset(results, 0, sizeof(results));
    port = htons(210);
    ret = ipport_matcher_match(matcher, &ip, port, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 0);

    ipport_matcher_free(matcher);
    matcher = NULL;
}

int main(int argc, char **argv)
{
    int ret = 0;
    ::testing::InitGoogleTest(&argc, argv);
    g_logger = log_handle_create("./ipport_matcher_gtest.log", 0);

    ret = RUN_ALL_TESTS();

    log_handle_destroy(g_logger);

    return ret;
}