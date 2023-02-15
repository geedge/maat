#include <gtest/gtest.h>

#include "maat.h"
#include "maat_rule.h"
#include "maat_utils.h"
#include "maat_command.h"
#include "IPMatcher.h"
#include "json2iris.h"
#include "log/log.h"
#include "maat_config_monitor.h"

#define MODULE_FRAMEWORK_GTEST	 module_name_str("maat.framework_gtest")

const char *table_info_path = "./table_info.conf";
const char *json_path="./maat_json.json";
const char *json_filename = "maat_json.json";
struct maat *g_maat_instance = NULL;

extern int system_cmd_rmdir(const char *dir);

class MaatFlagScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        flag_table_id = maat_table_get_id(g_maat_instance, "FLAG_CONFIG");
        expr_table_id = maat_table_get_id(g_maat_instance, "HTTP_URL");
    }

    static void TearDownTestCase() {
       
    }

    static int flag_table_id;
    static int expr_table_id;
};
int MaatFlagScan::flag_table_id;
int MaatFlagScan::expr_table_id;

TEST_F(MaatFlagScan, basic) {
    int flag_table_id = MaatFlagScan::flag_table_id;

    //compile_id:192 flag: 0000 0001 mask: 0000 0011
    //scan_data: 0000 1001 or 0000 1101 should hit
    uint64_t scan_data = 9;
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, scan_data, results,
                             5, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 192);

    struct maat_hit_path hit_path[128] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, sizeof(hit_path));
    EXPECT_NE(n_read, 0);
    maat_state_free(&state);

    scan_data = 13;
    memset(results, 0, sizeof(results));
    n_hit_result = 0;
    ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, scan_data, results, 
                         5, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 192);
    maat_state_free(&state);

    scan_data = 6;
    memset(results, 0, sizeof(results));
    n_hit_result = 0;
    ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, scan_data, results, 
                         5, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(&state);
}   

TEST_F(MaatFlagScan, withExprRegion) {
    int flag_table_id = MaatFlagScan::flag_table_id;
    int expr_table_id = MaatFlagScan::expr_table_id;

    //compile_id:193 flag: 0000 0010 mask: 0000 0011
    //scan_data: 0000 0010 or 0000 0100 should hit
    uint64_t flag_scan_data = 2;
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;

    int ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, flag_scan_data, results, 
                             5, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    struct maat_hit_path hit_path[128] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, sizeof(hit_path));
    EXPECT_NE(n_read, 0);

    const char *expr_scan_data = "hello world";
    ret = maat_scan_string(g_maat_instance, expr_table_id, 0, expr_scan_data, strlen(expr_scan_data), 
                           results, 5, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 193);
    maat_state_free(&state);
}   

TEST_F(MaatFlagScan, hitMultiCompile) {
    int flag_table_id = MaatFlagScan::flag_table_id;

    //compile_id:192 flag: 0000 0001 mask: 0000 0011
    //compile_id:194 flag: 0001 0101 mask: 0001 1111
    //scan_data: 0001 0101 should hit compile192 and compile194
    uint64_t flag_scan_data = 21;
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;

    int ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, flag_scan_data, results, 
                             5, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 194);
    EXPECT_EQ(results[1], 192);

    struct maat_hit_path hit_path[128] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, sizeof(hit_path));
    EXPECT_NE(n_read, 0);

    maat_state_free(&state);
}  

class MaatStringScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        table_id = maat_table_get_id(g_maat_instance, "KEYWORDS_TABLE");
    }

    static void TearDownTestCase() {
       
    }

    static int table_id;
};
int MaatStringScan::table_id;

TEST_F(MaatStringScan, Expr8) {
    int table_id = MaatStringScan::table_id;
    char scan_data[128] = "string1, string2, string3, string4, string5, string6, string7, string8";
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data, strlen(scan_data), 
                               results, 5, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    struct maat_hit_path hit_path[128] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, sizeof(hit_path));
    EXPECT_NE(n_read, 0);
    maat_state_free(&state);
}

TEST_F(MaatStringScan, Regex) {
    int ret = 0;
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *cookie = "Cookie: Txa123aheadBCAxd";
    int table_id = maat_table_get_id(g_maat_instance, "HTTP_URL");
    ASSERT_GT(table_id, 0);

    ret = maat_scan_string(g_maat_instance, table_id, 0, cookie, strlen(cookie),
                            results, 5, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 146);
    maat_state_free(&state);
    //TODO:
#if 0
    size_t i = 0;
    n_hit_result = 0;
    memset(results, 0, sizeof(results));
    const char *sni_should_not_hit[] = {"instagram.fbcdn.net", "a.instagram.fbcdn.net"};
	const char *sni_should_hit[] = {"xx.fbcdn.net", "ainstagram.fbcdn.net"};
	for (i = 0; i < sizeof(sni_should_not_hit)/sizeof(const char *); i++) {
		ret = maat_scan_string(g_maat_instance, table_id, 0, sni_should_not_hit[i], strlen(sni_should_not_hit[i]), 
							   results, 5, &n_hit_result, &state);
		EXPECT_EQ(ret, 0);		
		maat_state_free(&state);
	}

	for (i = 0; i < sizeof(sni_should_hit)/sizeof(const char *); i++) {
		ret = maat_scan_string(g_maat_instance, table_id, 0, sni_should_hit[i], strlen(sni_should_hit[i]), 
							   results, 5, &n_hit_result, &state);
		EXPECT_GE(ret, 1);	
		EXPECT_EQ(results[0], 149);
		maat_state_free(&state);
	}
#endif	
}

TEST_F(MaatStringScan, ExprPlus) {
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
	const char *region_name1 ="HTTP URL";
	const char *region_name2 ="我的diStricT";
	const char *scan_data1 = "http://www.cyberessays.com/search_results.php?action=search&query=abckkk,1234567";
	const char *scan_data2 = "Addis Sapphire Hotel";

	int table_id = maat_table_get_id(g_maat_instance, "HTTP_SIGNATURE");
	ASSERT_GT(table_id, 0);

	int ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data1, strlen(scan_data1), 
						        results, 5, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_ERR);//Should return error for district not setting.

	ret = maat_state_set_scan_district(g_maat_instance, &state, region_name1, strlen(region_name1));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data1, strlen(scan_data1), 
						   results, 5, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 128);
	maat_state_free(&state);

	ret = maat_state_set_scan_district(g_maat_instance, &state, region_name2, strlen(region_name2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data2, strlen(scan_data2), 
						   results, 5, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 190);
	maat_state_free(&state);
}

//TODO:
#if 0
TEST_F(MaatStringScan, ShouldNotHitExprPlus) {
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
	const char *region_name = "tcp.payload";
	unsigned char udp_payload_not_hit[] = { /* Stun packet */
							0x00, 0x03, 0x00, 0x4a, 0x21, 0x12, 0xa4, 0x42, 
							0x4f, 0xc2, 0xc2, 0x70, 0xb3, 0xa8, 0x4e, 0x22, 
							0xf5, 0x22, 0x87, 0x4c, 0x40, 0x00, 0x00, 0x46, 
							0x03, 0x02, 0xab, 0x39, 0xbb, 0x97, 0xe5, 0x01, 
							0x3a, 0x46, 0x1c, 0x28, 0x5b, 0xab, 0xfa, 0x9a, 
							0xab, 0x2e, 0x71, 0x39, 0x66, 0xa0, 0xd7, 0xb9, 
							0xd8, 0x41, 0xa7, 0xa0, 0x84, 0xa9, 0xf3, 0x1b, 
							0x03, 0x7f, 0xa8, 0x28, 0xa2, 0xd3, 0x64, 0xc2, 
							0x3d, 0x20, 0xe0, 0xb1, 0x41, 0x12, 0x6c, 0x2f, 
							0xc5, 0xbb, 0xc3, 0xba, 0x69, 0x73, 0x52, 0x64, 
							0xf6, 0x30, 0x81, 0xf4, 0x3f, 0xc2, 0x19, 0x6a, 
							0x68, 0x61, 0x93, 0x08, 0xc0, 0x0a, 0xab, 0x00 };

	int table_id = maat_table_get_id(g_maat_instance, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(g_maat_instance, &state, region_name, strlen(region_name));
	ASSERT_EQ(ret, 0);
    
	ret = maat_scan_string(g_maat_instance, table_id, 0, (char *)udp_payload_not_hit, sizeof(udp_payload_not_hit), 
						   results, 5, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	maat_state_free(&state);
}

TEST_F(MaatStringScan, ExprPlusWithHex) {
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
	const char *scan_data1 = "text/html; charset=UTF-8";
	const char *scan_data2 = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *region_name1 = "Content-Type";
	const char *region_name2 = "User-Agent";

	int table_id = maat_table_get_id(g_maat_instance, "HTTP_SIGNATURE");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(g_maat_instance, &state, region_name1, strlen(region_name1));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data1, strlen(scan_data1), 
						   results, 5, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 156);

    ret = maat_state_set_scan_district(g_maat_instance, &state, region_name2, strlen(region_name2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data1, strlen(scan_data1), 
						   results, 5, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    
    table_id = maat_table_get_id(g_maat_instance, "KEYWORDS_TABLE");
    ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data2, strlen(scan_data2),
                            results, 5, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 132);                    
	maat_state_free(&state);
}

TEST_F(MaatStringScan, ExprPlusWithOffset)
{
	int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
	const char *region_name = "Payload";
	unsigned char udp_payload_not_hit[] = { /* Stun packet */
							0x00, 0x03, 0x00, 0x4a, 0x21, 0x12, 0xa4, 0x42, 
							0x4f, 0xc2, 0xc2, 0x70, 0xb3, 0xa8, 0x4e, 0x22, 
							0xf5, 0x22, 0x87, 0x4c, 0x40, 0x00, 0x00, 0x46, 
							0x03, 0x02, 0xab, 0x39, 0xbb, 0x97, 0xe5, 0x01, 
							0x3a, 0x46, 0x1c, 0x28, 0x5b, 0xab, 0xfa, 0x9a, 
							0xab, 0x2e, 0x71, 0x39, 0x66, 0xa0, 0xd7, 0xb9, 
							0xd8, 0x41, 0xa7, 0xa0, 0x84, 0xa9, 0xf3, 0x1b, 
							0x03, 0x7f, 0xa8, 0x28, 0xa2, 0xd3, 0x64, 0xc2, 
							0x3d, 0x20, 0xe0, 0xb1, 0x41, 0x12, 0x6c, 0x2f, 
							0xc5, 0xbb, 0xc3, 0xba, 0x69, 0x73, 0x52, 0x64, 
							0xf6, 0x30, 0x81, 0xf4, 0x3f, 0xc2, 0x19, 0x6a, 
							0x68, 0x61, 0x93, 0x08, 0xc0, 0x0a };
	unsigned char udp_payload_hit[] = { /* Stun packet */					//rule:"1-1:03&9-10:2d&14-16:2d34&19-21:2d&24-25:2d"
							0x00, 0x03, 0x00, 0x4a, 0x21, 0x12, 0xa4, 0x42, //1-1:03
							0x4f, 0xc2, 0x2d, 0x70, 0xb3, 0xa8, 0x4e, 0x2d, //10-10:2d
							0x34, 0x22, 0x87, 0x4c, 0x2d, 0x00, 0x00, 0x46, //15-16:2d34&20-20:2d
							0x2d, 0x34, 0xab, 0x39, 0xbb, 0x97, 0xe5, 0x01, //24-24:2d
							0x03, 0x46, 0x1c, 0x28, 0x5b, 0xab, 0xfa, 0x9a, 
							0xab, 0x2e, 0x71, 0x39, 0x66, 0xa0, 0xd7, 0xb9, 
							0xd8, 0x41, 0xa7, 0xa0, 0x84, 0xa9, 0xf3, 0x1b, 
							0x03, 0x7f, 0xa8, 0x28, 0xa2, 0xd3, 0x64, 0xc2, 
							0x3d, 0x20, 0xe0, 0xb1, 0x41, 0x12, 0x6c, 0x2f, 
							0xc5, 0xbb, 0xc3, 0xba, 0x69, 0x73, 0x52, 0x64, 
							0xf6, 0x30, 0x81, 0xf4, 0x3f, 0xc2, 0x19, 0x6a, 
							0x68, 0x61, 0x93, 0x08, 0xc0, 0x0a };

	int table_id = maat_table_get_id(g_maat_instance, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(g_maat_instance, &state, region_name, strlen(region_name));
	EXPECT_EQ(ret, 0);

	ret = maat_scan_string(g_maat_instance, table_id, 0, (char*)udp_payload_not_hit, sizeof(udp_payload_not_hit), 
						   results, 5, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_scan_string(g_maat_instance, table_id, 0, (char*)udp_payload_hit, sizeof(udp_payload_hit), 
						   results, 5, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 148);
	
	maat_state_free(&state);
}
#endif

class MaatIPScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        table_id = maat_table_get_id(g_maat_instance, "IP_PLUS_CONFIG");
    }

    static void TearDownTestCase() {
       
    }

    static int table_id;
};
int MaatIPScan::table_id;

TEST_F(MaatIPScan, IPv4) {
    int table_id = MaatIPScan::table_id;
    char ip_str[32] = "10.0.7.100";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    int results[3] = {-1};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    ret = maat_scan_ipv4(g_maat_instance, table_id, 0, sip, results, 3,
                         &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 169);
    EXPECT_EQ(results[1], 154);
    maat_state_free(&state);
}

TEST_F(MaatIPScan, IPv6) {
    int table_id = MaatIPScan::table_id;
    char ip_str[32] = "1001:da8:205:1::101";
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    int results[3] = {-1};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    ret = maat_scan_ipv6(g_maat_instance, table_id, 0, sip, results, 3,
                         &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 155);

    maat_state_free(&state);
}

TEST_F(MaatStringScan, dynamic_config) {
    int table_id = maat_table_get_id(g_maat_instance, "HTTP_URL");
   
    char data[128] = "hello world";
    int results[5] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), results, sizeof(results), &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(&state);

    const char *table_name = "HTTP_URL";
    const char *table_line = "9999\t8888\thello world\t0\t0\t0\t1\t";
    struct maat_cmd_line line_rule;
    line_rule.rule_id = 101;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    sleep(2);
    state = NULL;
    ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), results, sizeof(results), &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 9999);
    maat_state_free(&state);
}

TEST_F(MaatIPScan, dynamic_config) {
    int table_id = maat_table_get_id(g_maat_instance, "IP_PLUS_CONFIG");
   
    char ip_str[32] = "10.0.6.201";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    int results[3] = {-1};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    ret = maat_scan_ipv4(g_maat_instance, table_id, 0, sip, results, sizeof(results), &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(&state);

    const char *table_name = "IP_PLUS_CONFIG";
    const char *table_line = "9998\t8887\t4\trange\t10.0.6.201\t255.255.0.0\trange\t0\t65535\t6\t0\t1";
    struct maat_cmd_line line_rule;
    line_rule.rule_id = 101;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 0);

    sleep(2);
    state = NULL;
    ret = maat_scan_ipv4(g_maat_instance, table_id, 0, sip, results, sizeof(results), &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 9998);
    maat_state_free(&state);
}

int count_line_num_cb(const char *table_name, const char *line, void *u_para)
{
	(*((unsigned int *)u_para))++;
	return 0;
}

int line_idx = 0;
long long absolute_expire_time=0;
int make_serial_rule(const char *table_name, const char *line, void *u_para)
{
	struct serial_rule *s_rule=(struct serial_rule *)u_para;
	int rule_id = 0;
	char *buff = ALLOC(char, strlen(line) + 1);
    
    memcpy(buff, line, strlen(line) + 1);

	while (buff[strlen(buff) - 1] == '\n' || buff[strlen(buff) - 1] == '\t') {
		buff[strlen(buff) - 1] = '\0';
	}

    int j = 0;
    char *str1 = NULL;
    char *token = NULL;
    char *saveptr1 = NULL;

	for (j = 0,str1 = buff; ; j++, str1 = NULL) {
		 token = strtok_r(str1, "\t ", &saveptr1);
		 if (token == NULL)
			 break;
		 if (j == 0) {
			sscanf(token,"%d", &rule_id);
		 }
 	}
	
    memcpy(buff, line, strlen(line)+1);
	while(buff[strlen(buff)-1]=='\n'||buff[strlen(buff)-1]=='\t') {
		buff[strlen(buff)-1]='\0';
	}

	maat_cmd_set_serial_rule(s_rule + line_idx, MAAT_OP_ADD, rule_id, table_name, buff, absolute_expire_time);
	line_idx++;
	FREE(str1);

	return 0;
}

int write_config_to_redis(char *redis_ip, int redis_port, int redis_db,
                          struct log_handle *logger)
{
    char json_iris_path[128] = {0};

    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp", json_filename);

    redisContext *c = maat_cmd_connect_redis(redis_ip, redis_port, redis_db, logger);
    if (nullptr == c) {
        return -1;
    }

    redisReply *reply = maat_cmd_wrap_redis_command(c, "flushdb");
    if (nullptr == reply) {
        return -1;
    }
    
    if (0 == access(json_iris_path, F_OK)) {
        system_cmd_rmdir(json_iris_path);
    }

    if (access(json_iris_path, F_OK) < 0) {
        char tmp_iris_path[128] = {0};
        char *json_buff = NULL;
        size_t json_buff_sz = 0;
        
        int ret = load_file_to_memory(json_filename, (unsigned char **)&json_buff, &json_buff_sz);
        if (ret < 0) {
            return -1;
        }

        ret = json2iris(json_buff, json_filename, c, tmp_iris_path, 
                        sizeof(tmp_iris_path), NULL, NULL, logger);
        if (ret < 0) {
            return -1;
        }
    }

    size_t total_line_cnt = 0;
    char tmp_iris_full_idx_path[128] = {0};
    snprintf(tmp_iris_full_idx_path, sizeof(tmp_iris_full_idx_path), "%s/index", json_iris_path);
    config_monitor_traverse(0, tmp_iris_full_idx_path, NULL, count_line_num_cb, NULL, &total_line_cnt, logger);

    struct serial_rule *s_rule = ALLOC(struct serial_rule, total_line_cnt);
    long long server_time = maat_cmd_redis_server_time_s(c);
    if (server_time < 0) {
        return -1;
    }

    absolute_expire_time = server_time + 300;
    config_monitor_traverse(0, tmp_iris_full_idx_path, NULL, make_serial_rule, NULL, s_rule, logger);

    int success_cnt = 0;
    do {
        success_cnt = maat_cmd_write_rule(c, s_rule, total_line_cnt, server_time, logger);
    } while (success_cnt < 0);

    EXPECT_EQ(success_cnt, (int)total_line_cnt);

    for (size_t i = 0; i < total_line_cnt; i++) {
        maat_cmd_clear_rule_cache(s_rule + i);
    }
    FREE(s_rule);
    redisFree(c);

    return 0;
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

    struct log_handle *logger = log_handle_create("./maat_framework_gtest.log", 0);
    if (NULL == logger) {
        printf("create log handle failed.\n");
        return -1;
    }

    char redis_ip[64] = "127.0.0.1";
    int redis_port = 6379;
    int redis_db = 0;

    ret = write_config_to_redis(redis_ip, redis_port, redis_db, logger);
    if (ret < 0) {
        log_error(logger, MODULE_FRAMEWORK_GTEST, "write config to redis failed.");
        log_handle_destroy(logger);
        return -1;
    }
    
    struct maat_options *opts = maat_options_new();
    maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
    maat_options_set_logger(opts, logger);

    g_maat_instance = maat_new(opts, table_info_path);
    maat_options_free(opts);
    if (NULL == g_maat_instance) {
        log_error(logger, MODULE_FRAMEWORK_GTEST, "create maat instance in MaatStringScan failed.");
        log_handle_destroy(logger);
        return -1;
    }

    ret=RUN_ALL_TESTS();

    maat_free(g_maat_instance);
    log_handle_destroy(logger);

	return ret;
}
