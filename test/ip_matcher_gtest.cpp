#include <gtest/gtest.h>

#include "log/log.h"
#include "ip_matcher.h"
#include "maat_utils.h"
#include "cJSON/cJSON.h"

#define MAX_ARRAY_SIZE 6

struct log_handle *g_logger = NULL;

TEST(ipv4_matcher_match, OneSingleIPv4Rule) {
    const char *ip_str = "192.168.0.1";
    struct ip_rule rule;
    rule.rule_id = 100;
    rule.type = IPv4;
    int ret = ip_format2range(ip_str, IPV4, &rule.ipv4_rule.start_ip, &rule.ipv4_rule.end_ip);
    size_t mem_size = 0;
    struct ip_matcher *matcher = ip_matcher_new(&rule, 1, &mem_size);
    ASSERT_TRUE(matcher != NULL);

    struct ip_data data;
    data.type = IPv4;
    inet_pton(AF_INET, ip_str, &data.ipv4);
    data.ipv4 = ntohl(data.ipv4);

    struct scan_result results[MAX_ARRAY_SIZE];
    ret = ip_matcher_match(matcher, &data, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 100);
}

TEST(ipv4_matcher_match, MultiSingleIPv4Rule) {
    const char *ip1_str = "192.168.0.1";
    const char *ip2_str = "192.168.0.2";
    const char *ip3_str = "192.168.0.3";
    struct ip_rule rule[3];
    rule[0].rule_id = 100;
    rule[0].type = IPv4;
    int ret = ip_format2range(ip1_str, IPV4, &rule[0].ipv4_rule.start_ip, &rule[0].ipv4_rule.end_ip);
    EXPECT_EQ(ret, 0);

    rule[1].rule_id = 200;
    rule[1].type = IPv4;
    ret = ip_format2range(ip2_str, IPV4, &rule[1].ipv4_rule.start_ip, &rule[1].ipv4_rule.end_ip);
    EXPECT_EQ(ret, 0);

    rule[2].rule_id = 300;
    rule[2].type = IPv4;
    ret = ip_format2range(ip3_str, IPV4, &rule[2].ipv4_rule.start_ip, &rule[2].ipv4_rule.end_ip);
    EXPECT_EQ(ret, 0);

    size_t mem_size = 0;
    struct ip_matcher *matcher = ip_matcher_new(rule, 3, &mem_size);
    ASSERT_TRUE(matcher != NULL);

    struct ip_data data;
    data.type = IPv4;
    inet_pton(AF_INET, ip1_str, &data.ipv4);
    data.ipv4 = ntohl(data.ipv4);

    struct scan_result results[MAX_ARRAY_SIZE];
    ret = ip_matcher_match(matcher, &data, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 100);

    inet_pton(AF_INET, ip2_str, &data.ipv4);
    data.ipv4 = ntohl(data.ipv4);
    memset(results, 0, sizeof(results));
    ret = ip_matcher_match(matcher, &data, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 200);

    inet_pton(AF_INET, ip3_str, &data.ipv4);
    data.ipv4 = ntohl(data.ipv4);
    memset(results, 0, sizeof(results));
    ret = ip_matcher_match(matcher, &data, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 300);
}

TEST(ipv6_matcher_match, OneSingleIPv6Rule) {
    const char *ip1_str = "1001:da8:205:1::101-1001:da8:205:1::101";
    struct ip_rule rule;
    rule.rule_id = 100;
    rule.type = IPv6;
    int ret = ip_format2range(ip1_str, IPV6, rule.ipv6_rule.start_ip, rule.ipv6_rule.end_ip);
    EXPECT_EQ(ret, 0);

    size_t mem_size = 0;
    struct ip_matcher *matcher = ip_matcher_new(&rule, 1, &mem_size);
    ASSERT_TRUE(matcher != NULL);

    struct ip_data data;
    data.type = IPv6;
    inet_pton(AF_INET6, ip1_str, data.ipv6);
    ipv6_ntoh(data.ipv6);

    struct scan_result results[MAX_ARRAY_SIZE];
    ret = ip_matcher_match(matcher, &data, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 100);
}

TEST(ipv6_matcher_match, MultiSingleIPv6Rule) {
    const char *ip1_str = "2607:5d00:2:2::56:22";
    const char *ip2_str = "2607:5d00:2:2::50:25";
    const char *ip3_str = "2607:5d00:2:2::64:203";
    struct ip_rule rule[3];
    rule[0].rule_id = 100;
    rule[0].type = IPv6;
    int ret = ip_format2range(ip1_str, IPV6, rule[0].ipv6_rule.start_ip, rule[0].ipv6_rule.end_ip);
    EXPECT_EQ(ret, 0);

    rule[1].rule_id = 200;
    rule[1].type = IPv6;
    ret = ip_format2range(ip2_str, IPV6, rule[1].ipv6_rule.start_ip, rule[1].ipv6_rule.end_ip);
    EXPECT_EQ(ret, 0);

    rule[2].rule_id = 300;
    rule[2].type = IPv6;
    ret = ip_format2range(ip3_str, IPV6, rule[2].ipv6_rule.start_ip, rule[2].ipv6_rule.end_ip);
    EXPECT_EQ(ret, 0);

    size_t mem_size = 0;
    struct ip_matcher *matcher = ip_matcher_new(rule, 3, &mem_size);
    ASSERT_TRUE(matcher != NULL);

    struct ip_data data;
    data.type = IPv6;
    inet_pton(AF_INET6, ip1_str, data.ipv6);
    ipv6_ntoh(data.ipv6);

    struct scan_result results[MAX_ARRAY_SIZE];
    ret = ip_matcher_match(matcher, &data, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 100);

    memset(results, 0, sizeof(results));
    inet_pton(AF_INET6, ip2_str, data.ipv6);
    ipv6_ntoh(data.ipv6);
    ret = ip_matcher_match(matcher, &data, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 200);

    memset(results, 0, sizeof(results));
    inet_pton(AF_INET6, ip3_str, data.ipv6);
    ipv6_ntoh(data.ipv6);
    ret = ip_matcher_match(matcher, &data, results, MAX_ARRAY_SIZE);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(results[0].rule_id, 300);
}

int main(int argc, char **argv)
{
    int ret = 0;
    ::testing::InitGoogleTest(&argc, argv);
    g_logger = log_handle_create("./ip_matcher_gtest.log", 0);

    ret = RUN_ALL_TESTS();

    log_handle_destroy(g_logger);

    return ret;
}