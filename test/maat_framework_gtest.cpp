#include <gtest/gtest.h>

#include "maat.h"
#include "maat_rule.h"
#include "maat_utils.h"
#include "maat_command.h"
#include "ip_matcher.h"
#include "json2iris.h"
#include "log/log.h"
#include "maat_config_monitor.h"

#define MODULE_FRAMEWORK_GTEST	 module_name_str("maat.framework_gtest")

#define ARRAY_SIZE    10
#define HIT_PATH_SIZE 128

const char *table_info_path = "./table_info.conf";
const char *json_path="./maat_json.json";
const char *json_filename = "maat_json.json";
struct maat *g_maat_instance = NULL;
struct log_handle *g_logger = NULL;
size_t g_thread_num = 4;

extern int system_cmd_rmdir(const char *dir);

class MaatFlagScan : public testing::Test
{
protected:
    static void SetUpTestCase() {

    }

    static void TearDownTestCase() {
       
    }

};

TEST_F(MaatFlagScan, basic) {
    const char *flag_table_name = "FLAG_CONFIG";
    int flag_table_id = maat_get_table_id(g_maat_instance, flag_table_name);
    //compile_id:192 flag: 0000 0001 mask: 0000 0011
    //scan_data: 0000 1001 or 0000 1101 should hit
    long long scan_data = 9;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, scan_data, results,
                             ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 192);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);
    maat_state_free(&state);

    scan_data = 13;
    memset(results, 0, sizeof(results));
    n_hit_result = 0;
    ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, scan_data, results, 
                         ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 192);
    maat_state_free(&state);

    scan_data = 6;
    memset(results, 0, sizeof(results));
    n_hit_result = 0;
    ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, scan_data, results, 
                         ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(&state);
}   

TEST_F(MaatFlagScan, withExprRegion) {
    const char *flag_table_name = "FLAG_CONFIG";
    const char *expr_table_name = "HTTP_URL_LITERAL";
    int flag_table_id = maat_get_table_id(g_maat_instance, flag_table_name);
    int expr_table_id = maat_get_table_id(g_maat_instance, expr_table_name);
    //compile_id:193 flag: 0000 0010 mask: 0000 0011
    //scan_data: 0000 0010 or 0000 0100 should hit
    long long flag_scan_data = 2;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;

    int ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    const char *expr_scan_data = "hello world";
    ret = maat_scan_string(g_maat_instance, expr_table_id, 0, expr_scan_data, 
                           strlen(expr_scan_data), results, ARRAY_SIZE, 
                           &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 193);
    maat_state_free(&state);
}   

TEST_F(MaatFlagScan, hitMultiCompile) {
    const char *flag_table_name = "FLAG_CONFIG";
    int flag_table_id = maat_get_table_id(g_maat_instance, flag_table_name);
    //compile_id:192 flag: 0000 0001 mask: 0000 0011
    //compile_id:194 flag: 0001 0101 mask: 0001 1111
    //scan_data: 0001 0101 should hit compile192 and compile194
    long long flag_scan_data = 21;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;

    int ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 194);
    EXPECT_EQ(results[1], 192);

    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, flag_scan_data, results, 
                             ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    maat_state_free(&state);
}  

TEST_F(MaatFlagScan, hitRepeatedCompile) {
    const char *flag_table_name = "FLAG_CONFIG";
    int flag_table_id = maat_get_table_id(g_maat_instance, flag_table_name);
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;

    //compile_id:192 flag: 0000 0001 mask: 0000 0011
    //scan_data: 0000 1001 or 0000 1101 should hit
    long long flag_scan_data1 = 9; 
    int ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, flag_scan_data1, results, 
                             ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 192);

    //compile_id:192 flag: 0000 0001 mask: 0000 0011
    //compile_id:194 flag: 0001 0101 mask: 0001 1111
    //scan_data: 0001 0101 should hit compile192 and compile194
	long long flag_scan_data2 = 21;
    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, flag_scan_data2, results, 
                         ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 194);

    memset(results, 0, sizeof(results));
    ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, flag_scan_data2, results, 
                         ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);

    maat_state_free(&state);
}  


TEST_F(MaatFlagScan, FlagPlus) {
    const char *flag_table_name = "FLAG_PLUS_CONFIG";
    const char *region_name = "I love China";
    int flag_table_id = maat_get_table_id(g_maat_instance, flag_table_name);
    //compile_id:196 flag: 0001 1111 mask: 0000 1111
    //scan_data: 0000 1111 or 0001 1111 should hit
    long long scan_data1 = 15;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, scan_data1, results,
                             ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_ERR);
 
    ret = maat_state_set_scan_district(g_maat_instance, &state, region_name, strlen(region_name));
    ASSERT_EQ(ret, 0);

    ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, scan_data1, results,
                             ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 196);

    ret = maat_scan_flag(g_maat_instance, flag_table_id, 0, scan_data1, results,
                             ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);
    maat_state_free(&state);
}

class MaatStringScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
    }

    static void TearDownTestCase() {
       
    }
};

TEST_F(MaatStringScan, Expr8) {
    const char *table_name = "KEYWORDS_TABLE";
    int table_id = maat_get_table_id(g_maat_instance, table_name);
    char scan_data[128] = "string1, string2, string3, string4, string5, string6, string7, string8";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);
    maat_state_free(&state);
}

TEST_F(MaatStringScan, Regex) {
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *cookie = "Cookie: Txa123aheadBCAxd";
    const char *table_name = "HTTP_URL_REGEX";
    int table_id = maat_get_table_id(g_maat_instance, table_name);

    ret = maat_scan_string(g_maat_instance, table_id, 0, cookie, strlen(cookie),
                            results, ARRAY_SIZE, &n_hit_result, &state);
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
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
	const char *region_name1 ="HTTP URL";
	const char *region_name2 ="我的diStricT";
	const char *scan_data1 = "http://www.cyberessays.com/search_results.php?action=search&query=abckkk,1234567";
	const char *scan_data2 = "Addis Sapphire Hotel";
    const char *table_name = "HTTP_SIGNATURE";
    int table_id = maat_get_table_id(g_maat_instance, table_name);

	int ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data1, strlen(scan_data1), 
						        results, ARRAY_SIZE, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_ERR);//Should return error for district not setting.

	ret = maat_state_set_scan_district(g_maat_instance, &state, region_name1, strlen(region_name1));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 128);
	maat_state_free(&state);

	ret = maat_state_set_scan_district(g_maat_instance, &state, region_name2, strlen(region_name2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data2, strlen(scan_data2), 
						   results, ARRAY_SIZE, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 190);
	maat_state_free(&state);
}

TEST_F(MaatStringScan, ExprAndExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *expr_table_name = "HTTP_URL_LITERAL";
    const char *expr_plus_table_name = "HTTP_SIGNATURE";
    const char *region_name = "I love China";
    const char *scan_data = "today is Monday and yesterday is Tuesday";
    int expr_table_id = maat_get_table_id(g_maat_instance, expr_table_name);
    int expr_plus_table_id = maat_get_table_id(g_maat_instance, expr_plus_table_name);

    int ret = maat_scan_string(g_maat_instance, expr_plus_table_id, 0, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_ERR);

    ret = maat_state_set_scan_district(g_maat_instance, &state, region_name, strlen(region_name));
    ASSERT_EQ(ret, 0);
    ret = maat_scan_string(g_maat_instance, expr_plus_table_id, 0, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(g_maat_instance, expr_table_id, 0, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 195);
    maat_state_free(&state);
}
#if 0
TEST_F(MaatStringScan, StreamInput) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
	const char *scan_data = "http://www.cyberessays.com/search_results.php?action=search&query=yulingjing,abckkk,1234567";
	const char *table_name = "HTTP_URL_STREAM";

	int table_id = maat_get_table_id(g_maat_instance, table_name);
	ASSERT_GT(table_id, 0);

	struct maat_stream *sp = maat_scan_stream_open(g_maat_instance, table_id, 0);
	ASSERT_FALSE(sp==NULL);

	int ret = maat_scan_stream(&sp, "www.cyberessays.com", strlen("www.cyberessays.com"),
                                results, ARRAY_SIZE, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_scan_stream(&sp, scan_data, strlen(scan_data), results, ARRAY_SIZE,
                            &n_hit_result, &state);
	maat_scan_stream_close(&sp);

	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 125);
	maat_state_free(&state);
}
#endif
//TODO:
#if 0
TEST_F(MaatStringScan, ShouldNotHitExprPlus) {
    long long results[ARRAY] = {0};
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

	int table_id = maat_get_table_id(g_maat_instance, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(g_maat_instance, &state, region_name, strlen(region_name));
	ASSERT_EQ(ret, 0);
    
	ret = maat_scan_string(g_maat_instance, table_id, 0, (char *)udp_payload_not_hit, sizeof(udp_payload_not_hit), 
						   results, ARRAY_SIZE, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	maat_state_free(&state);
}

TEST_F(MaatStringScan, ExprPlusWithHex) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
	const char *scan_data1 = "text/html; charset=UTF-8";
	const char *scan_data2 = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *region_name1 = "Content-Type";
	const char *region_name2 = "User-Agent";

	int table_id = maat_get_table_id(g_maat_instance, "HTTP_SIGNATURE");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(g_maat_instance, &state, region_name1, strlen(region_name1));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 156);

    ret = maat_state_set_scan_district(g_maat_instance, &state, region_name2, strlen(region_name2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    
    table_id = maat_get_table_id(g_maat_instance, "KEYWORDS_TABLE");
    ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data2, strlen(scan_data2),
                            results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 132);                    
	maat_state_free(&state);
}

TEST_F(MaatStringScan, ExprPlusWithOffset)
{
	long long results[ARRAY_SIZE] = {0};
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

	int table_id = maat_get_table_id(g_maat_instance, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(g_maat_instance, &state, region_name, strlen(region_name));
	EXPECT_EQ(ret, 0);

	ret = maat_scan_string(g_maat_instance, table_id, 0, (char*)udp_payload_not_hit, sizeof(udp_payload_not_hit), 
						   results, ARRAY_SIZE, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_scan_string(g_maat_instance, table_id, 0, (char*)udp_payload_hit, sizeof(udp_payload_hit), 
						   results, ARRAY_SIZE, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 148);
	
	maat_state_free(&state);
}
#endif
TEST_F(MaatStringScan, dynamic_config) {
    const char *table_name = "HTTP_URL_LITERAL";
    int table_id = maat_get_table_id(g_maat_instance, table_name);
    char data[128] = "hello world";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    int ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), results, 
                               ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(&state);

    /* add new line in GROUP2COMPILE table */
    const char *g2c_table_name = "GROUP2COMPILE";
    const char *g2c_table_line_add = "8888\t9999\t1\t0\tnull\t1";
    struct maat_cmd_line line_rule;
    line_rule.rule_id = 8888;
    line_rule.table_line = g2c_table_line_add;
    line_rule.table_name = g2c_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    /* add new line in COMPILE table */
    const char *compile_table_name = "COMPILE";
    const char *compile_table_line_add = "9999\t0\t0\t0\t0\t0\tanything\t1\t1\t0.0";
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9999;
    line_rule.table_line = compile_table_line_add;
    line_rule.table_name = compile_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    /* add new line in HTTP_URL_LITERAL table */
    const char *table_line_add = "9999\t8888\thello world\t0\t0\t0\t1\t";
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9999;
    line_rule.table_line = table_line_add;
    line_rule.table_name = table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    sleep(2);
    state = NULL;
    ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 9999);
    maat_state_free(&state);

    /* del new line from HTTP_URL_LITERAL table */
    const char *table_line_del = "9999\t8888\thello world\t0\t0\t0\t0\t";
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9999;
    line_rule.table_line = table_line_del;
    line_rule.table_name = table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    /* del new line from COMPILE table */
    const char *compile_table_line_del = "9999\t0\t0\t0\t0\t0\tanything\t0\t1\t0.0";
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9999;
    line_rule.table_line = compile_table_line_del;
    line_rule.table_name = compile_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    /* del new line from GROUP2COMPILE table */
    const char *g2c_table_line_del = "8888\t9999\t0\t0\tnull\t1";
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 8888;
    line_rule.table_line = g2c_table_line_del;
    line_rule.table_name = g2c_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    sleep(2);
    state = NULL;
    ret = maat_scan_string(g_maat_instance, table_id, 0, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(&state);
}

class MaatIPScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }
};

TEST_F(MaatIPScan, IPv4) {
    const char *table_name = "IP_PLUS_CONFIG";
    int table_id = maat_get_table_id(g_maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    char ip_str[32] = "10.0.7.100";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    ret = maat_scan_ipv4(g_maat_instance, table_id, 0, sip, results, ARRAY_SIZE,
                         &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 154);
    maat_state_free(&state);
}

TEST_F(MaatIPScan, IPv6) {
    const char *table_name = "IP_PLUS_CONFIG";
    int table_id = maat_get_table_id(g_maat_instance, table_name);
    char ip_str[32] = "1001:da8:205:1::101";
    uint8_t sip[16];
    int ret = inet_pton(AF_INET6, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    ret = maat_scan_ipv6(g_maat_instance, table_id, 0, sip, results, ARRAY_SIZE,
                         &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 155);

    maat_state_free(&state);
}

TEST_F(MaatIPScan, dynamic_config) {
    const char *table_name = "IP_PLUS_CONFIG";
    int table_id = maat_get_table_id(g_maat_instance, table_name);
    char ip_str[32] = "100.100.100.100";
    uint32_t sip;
    int ret = inet_pton(AF_INET, ip_str, &sip);
    EXPECT_EQ(ret, 1);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    ret = maat_scan_ipv4(g_maat_instance, table_id, 0, sip, results, ARRAY_SIZE, 
                         &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(&state);

    /* add new line in GROUP2COMPILE table */
    const char *g2c_table_name = "GROUP2COMPILE";
    const char *g2c_table_line_add = "8887\t9998\t1\t0\tnull\t1";
    struct maat_cmd_line line_rule;
    line_rule.rule_id = 8887;
    line_rule.table_line = g2c_table_line_add;
    line_rule.table_name = g2c_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    /* add new line in COMPILE table */
    const char *compile_table_name = "COMPILE";
    const char *compile_table_line_add = "9998\t0\t0\t0\t0\t0\tanything\t1\t1\t0.0";
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9998;
    line_rule.table_line = compile_table_line_add;
    line_rule.table_name = compile_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    /* add new line in IP_PLUS_CONFIG */
    const char *table_line_add = "9998\t8887\t4\trange\t100.100.100.100\t100.100.100.100\trange\t0\t65535\trange\t10.0.6.201\t255.255.0.0\trange\t0\t65535\t6\t0\t1";
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9998;
    line_rule.table_line = table_line_add;
    line_rule.table_name = table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    sleep(2);
    state = NULL;
    ret = maat_scan_ipv4(g_maat_instance, table_id, 0, sip, results, ARRAY_SIZE, 
                         &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 9998);
    maat_state_free(&state);

    /* del new line in IP_PLUS_CONFIG */
    const char *table_line_del = "9998\t8887\t4\trange\t100.100.100.100\t100.100.100.100\trange\t0\t65535\trange\t10.0.6.201\t255.255.0.0\trange\t0\t65535\t6\t0\t0";
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9998;
    line_rule.table_line = table_line_del;
    line_rule.table_name = table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    /* del new line in COMPILE table */
    const char *compile_table_line_del = "9998\t0\t0\t0\t0\t0\tanything\t0\t1\t0.0";
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9998;
    line_rule.table_line = compile_table_line_del;
    line_rule.table_name = compile_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    /* del new line in GROUP2COMPILE table */
    const char *g2c_table_line_del = "8887\t9998\t0\t0\tnull\t1";
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 8887;
    line_rule.table_line = g2c_table_line_del;
    line_rule.table_name = g2c_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);
}

class MaatIntervalScan : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }
};

TEST_F(MaatIntervalScan, Pure) {	
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *table_name = "CONTENT_SIZE";
    int table_id = maat_get_table_id(g_maat_instance, table_name);
    unsigned int scan_data1 = 2015;

	int ret = maat_scan_integer(g_maat_instance, table_id, 0, scan_data1, results, ARRAY_SIZE, 
                                &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	maat_state_free(&state);

    unsigned int scan_data2 = 300;
    ret = maat_scan_integer(g_maat_instance, table_id, 0, scan_data2, results, ARRAY_SIZE, 
                            &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
	maat_state_free(&state);
}

TEST_F(MaatIntervalScan, IntervalPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *table_name = "INTERGER_PLUS";
    int table_id = maat_get_table_id(g_maat_instance, table_name);
    const char *district_str = "interval.plus";

    int ret = maat_state_set_scan_district(g_maat_instance, &state, district_str, strlen(district_str));
    EXPECT_EQ(ret, 0);

    unsigned int scan_data1 = 2020;
	ret = maat_scan_integer(g_maat_instance, table_id, 0, scan_data1, results, ARRAY_SIZE, 
                                &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 179);
	maat_state_free(&state);
}

class NOTLogic : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }
};

TEST_F(NOTLogic, OneRegion) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-143.";
	const char *string_should_not_hit = "This string contains both must-contained-string-of-rule-143 and must-not-contained-string-of-rule-143.";
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
	const char *table_name = "HTTP_URL_LITERAL";

	int table_id = maat_get_table_id(g_maat_instance, table_name);
    maat_state_set_last_scan(g_maat_instance, &state);
	int ret = maat_scan_string(g_maat_instance, table_id, 0, string_should_hit, strlen(string_should_hit), 
						       results, ARRAY_SIZE, &n_hit_result, &state);
						
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 143);
    maat_state_free(&state);
	
    maat_state_set_last_scan(g_maat_instance, &state);
	ret = maat_scan_string(g_maat_instance, table_id, 0, string_should_not_hit, strlen(string_should_not_hit), 
						   results, ARRAY_SIZE, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	maat_state_free(&state);
}

TEST_F(NOTLogic, ScanNotAtLast) {
    const char *string_should_hit="This string ONLY contains must-contained-string-of-rule-144.";
	const char *string_should_not_hit="This string contains both must-contained-string-of-rule-144 and must-not-contained-string-of-rule-144.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
	const char *hit_table_name = "HTTP_URL_LITERAL";
    const char *not_hit_table_name = "KEYWORDS_TABLE";

    int hit_table_id = maat_get_table_id(g_maat_instance, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    int ret = maat_scan_string(g_maat_instance, hit_table_id, 0, string_should_hit, strlen(string_should_hit), 
						       results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int not_hit_table_id =  maat_get_table_id(g_maat_instance, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

	maat_state_set_last_scan(g_maat_instance, &state);
    ret = maat_scan_string(g_maat_instance, not_hit_table_id, 0, string_should_not_hit, strlen(string_should_not_hit), 
						       results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    maat_state_free(&state);
}

TEST_F(NOTLogic, ScanIrrelavantAtLast) {
    const char *string_should_hit = "This string ONLY contains must-contained-string-of-rule-144.";
	const char *string_irrelevant = "This string contiains nothing to hit.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *hit_table_name = "HTTP_URL_LITERAL";
    const char *not_hit_table_name = "KEYWORDS_TABLE";

    int hit_table_id = maat_get_table_id(g_maat_instance, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    int ret = maat_scan_string(g_maat_instance, hit_table_id, 0, string_should_hit, strlen(string_should_hit), 
						       results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int not_hit_table_id = maat_get_table_id(g_maat_instance, not_hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    maat_state_set_last_scan(g_maat_instance, &state);
    ret = maat_scan_string(g_maat_instance, not_hit_table_id, 0, string_irrelevant, strlen(string_irrelevant), 
						       results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 144);
    maat_state_free(&state);
}

TEST_F(NOTLogic, ScanHitAtLastEmptyExpr) {
    const char *string_should_not_hit = "This string should not hit.";
	const char *string_match_no_region = "This string is matched against a empty table.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *not_hit_table_name = "HTTP_URL_LITERAL";
    const char *hit_table_name = "IP_PLUS_CONFIG";
    const char *empty_table_name = "EMPTY_KEYWORD";

    int not_hit_table_id = maat_get_table_id(g_maat_instance, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

    int ret = maat_scan_string(g_maat_instance, not_hit_table_id, 0, string_should_not_hit, strlen(string_should_not_hit), 
						       results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.8.186", &sip);

    int hit_table_id = maat_get_table_id(g_maat_instance, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    ret = maat_scan_ipv4(g_maat_instance, hit_table_id, 0, sip,
                         results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int empty_table_id = maat_get_table_id(g_maat_instance, empty_table_name);
    ASSERT_GT(empty_table_id, 0);

    maat_state_set_last_scan(g_maat_instance, &state);
    ret = maat_scan_string(g_maat_instance, empty_table_id, 0, string_match_no_region, strlen(string_match_no_region), 
						   results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 186);
    maat_state_free(&state);
}

TEST_F(NOTLogic, ScanHitAtLastEmptyInteger) {
    const char *string_should_not_hit = "This string should not hit.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *not_hit_table_name = "HTTP_URL_LITERAL";
    const char *hit_table_name = "IP_PLUS_CONFIG";
    const char *empty_table_name = "EMPTY_INTERGER";

    int not_hit_table_id = maat_get_table_id(g_maat_instance, not_hit_table_name);
    ASSERT_GT(not_hit_table_id, 0);

    int ret = maat_scan_string(g_maat_instance, not_hit_table_id, 0, string_should_not_hit, strlen(string_should_not_hit), 
						       results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);

    uint32_t sip;
    inet_pton(AF_INET, "10.0.8.187", &sip);

    int hit_table_id = maat_get_table_id(g_maat_instance, hit_table_name);
    ASSERT_GT(hit_table_id, 0);

    ret = maat_scan_ipv4(g_maat_instance, hit_table_id, 0, sip,
                         results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    int empty_table_id = maat_get_table_id(g_maat_instance, empty_table_name);
    ASSERT_GT(empty_table_id, 0);

    maat_state_set_last_scan(g_maat_instance, &state);
    ret = maat_scan_integer(g_maat_instance, empty_table_id, 0, 2015,
                            results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 187);
    maat_state_free(&state);
}

void maat_read_entry_start_cb(int update_type, void *u_para)
{

}

void maat_read_entry_cb(int table_id, const char *table_line, void *u_para)
{
	char ip_str[16] = {0};
	int entry_id = -1, seq = -1;
	unsigned int ip_uint = 0;
	int is_valid = 0;
	unsigned int local_ip_nr = 16820416;//192.168.0.1

	sscanf(table_line, "%d\t%s\t%d\t%d", &seq,ip_str, &entry_id, &is_valid);
	inet_pton(AF_INET, ip_str, &ip_uint);
	if (local_ip_nr == ip_uint) {
		if (is_valid == 1) {
			//printf("Load entry id %d success.\n",entry_id);
			EXPECT_EQ(entry_id, 101);
		} else {
			//printf("Offload entry id %d success.\n",entry_id);
		}
	}
}

void maat_read_entry_finish_cb(void *u_para)
{
	//Maat_feather_t feather=u_para;
	// long long version=0;
	// int ret=0,is_last_updating_table=0;
	// ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version, sizeof(version));
	// EXPECT_EQ(ret, 0);
	// ret=Maat_read_state(feather,MAAT_STATE_LAST_UPDATING_TABLE, &is_last_updating_table, sizeof(is_last_updating_table));
	// EXPECT_EQ(ret, 0);
	//printf("Maat Version %lld at plugin finish callback, is_last_update=%d.\n",version,is_last_updating_table);
}

class PluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }
};

TEST_F(PluginTable, Callback) {
    const char *table_name = "QD_ENTRY_INFO";
    int table_id = maat_get_table_id(g_maat_instance, table_name);

    int ret = maat_table_callback_register(g_maat_instance, table_id, 
                                           maat_read_entry_start_cb,
                                           maat_read_entry_cb, 
                                           maat_read_entry_finish_cb,
                                           g_maat_instance);
    EXPECT_EQ(ret, 0);
}

class IPPluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }
};

struct ip_plugin_ud {
	long long rule_id;
	char *buffer;
	int ref_cnt;
};
void ip_plugin_EX_new_cb(int table_id, const char *key, const char *table_line, 
                         void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	size_t column_offset=0, column_len=0;
	struct ip_plugin_ud *ud = ALLOC(struct ip_plugin_ud, 1);

	int ret = get_column_pos(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);

	ud->rule_id = atoll(table_line + column_offset);

	ret = get_column_pos(table_line, 5, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	ud->buffer = (char *)calloc(sizeof(char), column_len + 1);
	strncpy(ud->buffer, table_line + column_offset, column_len);
	ud->ref_cnt = 1;
	*ad = ud;
	(*counter)++;
}

void ip_plugin_EX_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct ip_plugin_ud *ud = (struct ip_plugin_ud *)(*ad);
	if ((__sync_sub_and_fetch(&ud->ref_cnt, 1) == 0)) {
		free(ud->buffer);
		free(ud);
		*ad = NULL;
	}
}

void ip_plugin_EX_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct ip_plugin_ud *ud = (struct ip_plugin_ud *)(*from);
	__sync_add_and_fetch(&(ud->ref_cnt), 1);
	*to = ud;
}

TEST_F(IPPluginTable, EX_DATA) {
    int ip_plugin_ex_data_counter = 0;
    const char *table_name = "TEST_IP_PLUGIN_WITH_EXDATA";
    int table_id = maat_get_table_id(g_maat_instance, table_name);

    int ret = maat_plugin_table_ex_schema_register(g_maat_instance, table_id,
                                                   ip_plugin_EX_new_cb,
                                                   ip_plugin_EX_free_cb,
                                                   ip_plugin_EX_dup_cb,
                                                   0, &ip_plugin_ex_data_counter);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(ip_plugin_ex_data_counter, 5);

    struct ip_addr ipv4;
    ipv4.ip_type = IPv4;
    ret = inet_pton(AF_INET, "192.168.30.100", &ipv4.ipv4);
    EXPECT_EQ(ret, 1);

    struct ip_plugin_ud *results[ARRAY_SIZE];
    ret = maat_ip_plugin_table_get_ex_data(g_maat_instance, table_id, &ipv4, 
                                           (void **)results, ARRAY_SIZE);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(results[0]->rule_id, 101);
    EXPECT_EQ(results[1]->rule_id, 102);

    int i = 0;
    for (i = 0; i < ret; i++) {
		ip_plugin_EX_free_cb(0, (void**)&(results[i]), 0, NULL);
	}

    struct ip_addr ipv6;
    ipv6.ip_type = IPv6;
    inet_pton(AF_INET6, "2001:db8:1234::5210", &(ipv6.ipv6));
    memset(results, 0, sizeof(results));

	ret = maat_ip_plugin_table_get_ex_data(g_maat_instance, table_id, &ipv6, 
                                           (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 2);
	EXPECT_EQ(results[0]->rule_id, 104);
	EXPECT_EQ(results[1]->rule_id, 103);

	for (i = 0; i < ret; i++) {
		ip_plugin_EX_free_cb(0, (void**)&(results[i]), 0, NULL);
	}

	//Reproduce BugReport-Liumengyan-20210515
	inet_pton(AF_INET6, "240e:97c:4010:104::17", &(ipv6.ipv6));
	ret = maat_ip_plugin_table_get_ex_data(g_maat_instance, table_id, &ipv6, 
                                           (void**)results, ARRAY_SIZE);
	EXPECT_EQ(ret, 0);
}

class FQDNPluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }
};

#define FQDN_PLUGIN_EX_DATA
struct fqdn_plugin_ud
{
	int rule_id;
	int catid;
	int ref_cnt;
};

void fqdn_plugin_ex_new_cb(int table_id, const char *key, const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	size_t column_offset = 0, column_len = 0;
	struct fqdn_plugin_ud *ud = ALLOC(struct fqdn_plugin_ud, 1);

	int ret = get_column_pos(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);

	ud->rule_id = atoi(table_line + column_offset);
	ret = get_column_pos(table_line, 4, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	sscanf(table_line + column_offset, "catid=%d", &ud->catid);
	ud->ref_cnt = 1;
	*ad = ud;
	(*counter)++;
}

void fqdn_plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct fqdn_plugin_ud *u = (struct fqdn_plugin_ud *)(*ad);
	if ((__sync_sub_and_fetch(&u->ref_cnt, 1) == 0)) {
		free(u);
		*ad = NULL;
	}
}

void fqdn_plugin_ex_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct fqdn_plugin_ud *u = (struct fqdn_plugin_ud *)(*from);
	__sync_add_and_fetch(&(u->ref_cnt), 1);
	*to = u;
}

TEST_F(FQDNPluginTable, EX_DATA) {
    const char *table_name = "TEST_FQDN_PLUGIN_WITH_EXDATA";
    int table_id = maat_get_table_id(g_maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int fqdn_plugin_ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(g_maat_instance, table_id,
                                                    fqdn_plugin_ex_new_cb,
                                                    fqdn_plugin_ex_free_cb,
                                                    fqdn_plugin_ex_dup_cb,
                                                    0, &fqdn_plugin_ex_data_counter);
    ASSERT_TRUE(ret>=0);
	EXPECT_EQ(fqdn_plugin_ex_data_counter, 5);

    int i = 0;
    struct fqdn_plugin_ud *result[4];

	ret = maat_fqdn_plugin_table_get_ex_data(g_maat_instance, table_id, "www.example1.com", (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_EQ(result[0]->rule_id, 201);
	EXPECT_EQ(result[1]->rule_id, 202);

	for (i = 0; i < ret; i++) {
		fqdn_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}

	ret = maat_fqdn_plugin_table_get_ex_data(g_maat_instance, table_id, "www.example3.com", (void**)result, 4);
	EXPECT_EQ(ret, 0);

	ret = maat_fqdn_plugin_table_get_ex_data(g_maat_instance, table_id, "r3---sn-i3belne6.example2.com", (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_TRUE(result[0]->rule_id == 205 || result[0]->rule_id == 204);
	
	for (i = 0; i < ret; i++) {
		fqdn_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}
}

struct bool_plugin_ud {
	int id;
	char *name;
	int ref_cnt;
};
void bool_plugin_ex_new_cb(int table_id, const char *key, const char *table_line, void **ad, long argl, void *argp)
{
	int *counter=(int *)argp;
	size_t column_offset=0, column_len=0;
	struct bool_plugin_ud *ud = ALLOC(struct bool_plugin_ud, 1);
	
    int ret = get_column_pos(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);

	ud->id = atoi(table_line + column_offset);
	ret = get_column_pos(table_line, 3, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);

	ud->name = (char *)malloc(column_len+1);
	memcpy(ud->name, table_line+column_offset, column_len);
	ud->ref_cnt = 1;
	*ad = ud;
	(*counter)++;
}
void bool_plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct bool_plugin_ud *u = (struct bool_plugin_ud *)(*ad);
	if ((__sync_sub_and_fetch(&u->ref_cnt, 1) == 0))
	{
		free(u->name);
		free(u);
		*ad = NULL;
	}
}
void bool_plugin_ex_dup_cb(int table_id, void **to, void **from, long argl, void *argp)
{
	struct bool_plugin_ud *u = (struct bool_plugin_ud *)(*from);
	__sync_add_and_fetch(&(u->ref_cnt), 1);
	*to = u;
}

class BoolPluginTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }
};

TEST_F(BoolPluginTable, EX_DATA) {
    int ex_data_counter = 0, i = 0;
	const char *table_name = "TEST_BOOL_PLUGIN_WITH_EXDATA";

	int table_id = maat_get_table_id(g_maat_instance, table_name);
	ASSERT_GT(table_id, 0);

	int ret = maat_plugin_table_ex_schema_register(g_maat_instance, table_id,
								                   bool_plugin_ex_new_cb,
								                   bool_plugin_ex_free_cb,
								                   bool_plugin_ex_dup_cb,
								                   0, &ex_data_counter);
	ASSERT_TRUE(ret >= 0);
	EXPECT_EQ(ex_data_counter, 6);

	struct bool_plugin_ud *result[6];
	unsigned long long items_1[] = {999};
	ret = maat_bool_plugin_table_get_ex_data(g_maat_instance, table_id, items_1, 1, (void**)result, 6);
	EXPECT_EQ(ret, 0);
	for (i = 0; i < ret; i++) {
        bool_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}

	unsigned long long items_2[] = {1, 2, 1000};
	ret = maat_bool_plugin_table_get_ex_data(g_maat_instance, table_id, items_2, 3, (void**)result, 6);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0]->id, 301);
	for (i = 0; i < ret; i++) {
        bool_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}

	unsigned long long items_3[]={101, 102, 1000};
	ret = maat_bool_plugin_table_get_ex_data(g_maat_instance, table_id, items_3, 3, (void**)result, 6);
	EXPECT_EQ(ret, 4);
	for (i = 0; i < ret; i++) {
        bool_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}

	unsigned long long items_4[]={7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 7};
	ret = maat_bool_plugin_table_get_ex_data(g_maat_instance, table_id, items_4, sizeof(items_4)/sizeof(unsigned long long), (void**)result, 6);
	EXPECT_EQ(ret, 1);	
	EXPECT_EQ(result[0]->id, 305);
	for (i = 0; i < ret; i++) {
        bool_plugin_ex_free_cb(0, (void**)&(result[i]), 0, NULL);
	}
}

class VirtualTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }
};

TEST_F(VirtualTable, basic) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *table_name = "HTTP_RESPONSE_KEYWORDS";
    int table_id = maat_get_table_id(g_maat_instance, table_name);
    char scan_data[128] = "string1, string2, string3, string4, string5, string6, string7, string8";
    
    int ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(&state);
}

class CompileTable : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }    
};

struct rule_ex_param {
	int ref_cnt;
	char name[NAME_MAX];
	int id;
	pthread_mutex_t lock;
};

void compile_ex_param_new(int table_id, const char *key, const char *table_line, void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	*ad = NULL;

	struct rule_ex_param *param = (struct rule_ex_param *)calloc(sizeof(struct rule_ex_param), 1);
	
	param->ref_cnt = 1;
	pthread_mutex_init(&(param->lock), NULL);
	
    int compile_id = 0;
    int service_id = 0;
    int action = 0;
    int do_blacklist = 0;
    int do_log = 0;
    char tags[1024] = {0};

	sscanf(table_line, "%d\t%d\t%d\t%d\t%d\t%s\t%*[^:]:%[^,],%d", 
           &compile_id, &service_id, &action, &do_blacklist, &do_log, 
           tags, param->name, &(param->id));
    
	(*counter)++;
	*ad = param;
}

void compile_ex_param_free(int table_id, void **ad, long argl, void *argp)
{
	if (*ad == NULL) {
		return;
	}

	struct rule_ex_param *param = (struct rule_ex_param *)*ad;
	pthread_mutex_lock(&(param->lock));
	param->ref_cnt--;
	if (param->ref_cnt > 0) {	
		pthread_mutex_unlock(&(param->lock));
		return;
	}
	free(param);
}

void compile_ex_param_dup(int table_id, void **to, void **from, long argl, void *argp)
{
	struct rule_ex_param *from_param = *((struct rule_ex_param **)from);
	pthread_mutex_lock(&(from_param->lock));
	from_param->ref_cnt++;
	pthread_mutex_unlock(&(from_param->lock));
	*((struct rule_ex_param**)to) = from_param;
}

TEST_F(CompileTable, CompileRuleUpdate) {
    //9999	0	0	0	0	0	anything	1	1	0.0
    const char *compile_table_name = "COMPILE";
    const char *table_line_add = "9999\t0\t0\t0\t0\t0\tanything\t1\t1\t0.0";
    struct maat_cmd_line line_rule;

    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9999;
    line_rule.table_line = table_line_add;
    line_rule.table_name = compile_table_name;
    int ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    sleep(1);
    const char *table_line_del = "9999\t0\t0\t0\t0\t0\tanything\t0\t1\t0.0";
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9999;
    line_rule.table_line = table_line_del;
    line_rule.table_name = compile_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    sleep(1);
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9999;
    line_rule.table_line = table_line_add;
    line_rule.table_name = compile_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    sleep(1);
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = 9999;
    line_rule.table_line = table_line_del;
    line_rule.table_name = compile_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);
}

TEST_F(CompileTable, Conjunction1) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *scan_data = "i.ytimg.com/vi/OtCNcustg_I/hqdefault.jpg?sqp=-oaymwEZCNACELwBSFXyq4qpAwsIARUAAIhCGAFwAQ==&rs=AOn4CLDOp_5fHMaCA9XZuJdCRv4DNDorMg";
    const char *table_name = "HTTP_URL_LITERAL";
    const char *compile_tables[2] = {"COMPILE", "COMPILE_ALIAS"};

    int table_id = maat_get_table_id(g_maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    maat_state_set_scan_compile_tables(g_maat_instance, &state, compile_tables, 2);
    int ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 197);
    EXPECT_EQ(results[1], 141);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, HIT_PATH_SIZE);
    EXPECT_EQ(n_read, 2);

    maat_state_free(&state);
}

TEST_F(CompileTable, Conjunction2) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *scan_data = "i.ytimg.com/vi/OtCNcustg_I/hqdefault.jpg?sqp=-oaymwEZCNACELwBSFXyq4qpAwsIARUAAIhCGAFwAQ==&rs=AOn4CLDOp_5fHMaCA9XZuJdCRv4DNDorMg";
    const char *table_name = "HTTP_URL_LITERAL";
    const char *compile_tables[2] = {"COMPILE", "COMPILE_ALIAS"};

    int table_id = maat_get_table_id(g_maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 197);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, HIT_PATH_SIZE);
    EXPECT_EQ(n_read, 2);

    maat_state_set_scan_compile_tables(g_maat_instance, &state, compile_tables, 2);
    ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 141);

    memset(hit_path, 0, sizeof(hit_path));
    n_read = maat_state_get_hit_paths(g_maat_instance, &state, hit_path, HIT_PATH_SIZE);
    EXPECT_EQ(n_read, 4);

    maat_state_free(&state);
}

class Policy : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }    
};

void accept_tags_entry_cb(int table_id, const char *table_line, void *u_para)
{
	int* callback_times = (int *)u_para;
	char status[32] = {0};
	int entry_id = -1, seq = -1;
	int is_valid = 0;

	sscanf(table_line, "%d\t%s\t%d\t%d", &seq,status, &entry_id, &is_valid);
	EXPECT_STREQ(status, "SUCCESS");
	(*callback_times)++;
}

TEST_F(Policy, PluginRuleTags1) {
    const char *table_name = "TEST_EFFECTIVE_RANGE_TABLE";
    int table_id = maat_get_table_id(g_maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int callback_times=0;
	int ret = maat_table_callback_register(g_maat_instance, table_id,
							               NULL,
							               accept_tags_entry_cb, 
							               NULL,
							               &callback_times);
	ASSERT_GE(ret, 0);
	EXPECT_EQ(callback_times, 5);
}

void accept_tags_entry2_cb(int table_id, const char *table_line, void *u_para)
{
	int *callback_times = (int *)u_para;
	(*callback_times)++;
}

TEST_F(Policy, PluginRuleTags2) {
    const char *table_name = "IR_INTERCEPT_IP";
	int table_id = maat_get_table_id(g_maat_instance, table_name);
	ASSERT_GT(table_id, 0);

	int callback_times = 0;
	int ret = maat_table_callback_register(g_maat_instance, table_id,
							               NULL,
							               accept_tags_entry2_cb, 
							               NULL,
							               &callback_times);
	ASSERT_GE(ret, 0);
	EXPECT_EQ(callback_times, 2);
}

TEST_F(Policy, CompileRuleTags) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
	const char *should_hit = "string bbb should hit";
	const char *should_not_hit = "string aaa should not hit";
	const char *table_name = "HTTP_URL_LITERAL";
	
    int table_id = maat_get_table_id(g_maat_instance, table_name);
	ASSERT_GT(table_id, 0);

	int ret = maat_scan_string(g_maat_instance, table_id, 0, should_not_hit, 
                               strlen(should_not_hit), results, ARRAY_SIZE,
						        &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	
	ret = maat_scan_string(g_maat_instance, table_id, 0, should_hit, 
                           strlen(should_hit), results, ARRAY_SIZE,
						   &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);

	maat_state_free(&state);
}

TEST_F(Policy, CompileEXData) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *url = "i.ytimg.com/vi/OtCNcustg_I/hqdefault.jpg?sqp=-oaymwEZCNACELwBSFXyq4qpAwsIARUAAIhCGAFwAQ==&rs=AOn4CLDOp_5fHMaCA9XZuJdCRv4DNDorMg";
	const char *table_name = "HTTP_URL_LITERAL";
    const char *compile_table_name = "COMPILE_ALIAS";
	const char *expect_name = "I have a name";
    int table_id = maat_get_table_id(g_maat_instance, table_name);
    int compile_table_id = maat_get_table_id(g_maat_instance, compile_table_name);

    int ex_data_counter = 0;
    int ret = maat_plugin_table_ex_schema_register(g_maat_instance, compile_table_id,
                                                    compile_ex_param_new,
                                                    compile_ex_param_free,
                                                    compile_ex_param_dup,
                                                    0, &ex_data_counter);
    ASSERT_TRUE(ret == 0);
    EXPECT_EQ(ex_data_counter, 1);

    ret = maat_state_set_scan_compile_tables(g_maat_instance, &state, &compile_table_name, 1);
    EXPECT_EQ(ret, 0);

    ret = maat_scan_string(g_maat_instance, table_id, 0, url, strlen(url),
                                results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 141);

    void *ex_data = maat_plugin_table_get_ex_data(g_maat_instance, compile_table_id, 
                                                 (char *)&results[0]);
    ASSERT_TRUE(ex_data!=NULL);
    struct rule_ex_param *param = (struct rule_ex_param *)ex_data;
	EXPECT_EQ(param->id, 7799);

    str_unescape(param->name);
	EXPECT_EQ(strcmp(param->name, expect_name), 0);
	compile_ex_param_free(compile_table_id, &ex_data, 0, NULL);

	maat_state_free(&state);
}
#if 0
TEST_F(Policy, SubGroup) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
	const char *scan_data = "ceshi6@mailhost.cn";
	
	uint32_t sip;
	inet_pton(AF_INET,"10.0.6.205", &sip);

	int table_id = maat_get_table_id(g_maat_instance, "MAIL_ADDR");
	ASSERT_GT(table_id, 0);
	
	int ret = maat_scan_string(g_maat_instance, table_id, 0, scan_data, strlen(scan_data), 
						       results, ARRAY_SIZE, &n_hit_result, &state);
	EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);
	
	table_id = maat_get_table_id(g_maat_instance, "IP_CONFIG");	
	ASSERT_GT(table_id, 0);
	
	ret = maat_scan_ipv4(g_maat_instance, table_id, 0, sip, results, ARRAY_SIZE,
                         &n_hit_result, &state);	
	
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 153);
	
	maat_state_free(&state);
}
#endif
TEST_F(Policy, ReadColumn) {
    const char *ip = "192.168.0.1";
	const char *tmp = "something";
	char line[256] = {0};
    size_t offset=0, len=0;

	snprintf(line, sizeof(line), "1\t%s\t%s", ip, tmp);
	int ret = maat_helper_read_column(line, 2, &offset, &len);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(0, strncmp(ip, line+offset, len));
	
	ret = maat_helper_read_column(line, 3, &offset, &len);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(0, strncmp(tmp, line+offset, len));
}

class TableInfo : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }    
};

TEST_F(TableInfo, Conjunction) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = NULL;
    const char *scan_data = "soq is using table conjunction function.http://www.3300av.com/novel/27122.txt";
    const char *table_name = "HTTP_URL_LITERAL";
    const char *conj_table_name = "HTTP_HOST_LITERAL";

    int table_id = maat_get_table_id(g_maat_instance, table_name);
    ASSERT_GT(table_id, 0);

    int conj_table_id = maat_get_table_id(g_maat_instance, conj_table_name);
    ASSERT_GT(conj_table_id, 0);

    int ret = maat_scan_string(g_maat_instance, conj_table_id, 0, scan_data, strlen(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, &state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 134);
    EXPECT_EQ(results[1], 133);
    maat_state_free(&state);
}

class MaatCmdTest : public testing::Test
{
protected:
    static void SetUpTestCase() {
        
    }

    static void TearDownTestCase() {
       
    }    
};
#if 0
TEST_F(MaatCmdTest, HitPath) {
    const char *g2g_table_name = "GROUP2GROUP";
	const char *g2c_table_name = "GROUP2COMPILE";
	const char *compile_table_name = "COMPILE";
	const char *http_sig_table_name = "HTTP_SIGNATURE";
	const char *ip_table_name = "IP_CONFIG";
	const char *keywords_table_name = "KEYWORDS_TABLE";
    char table_line_add[128] = {0};
    struct maat_cmd_line line_rule;

    /* compile table add line */
    long long compile_id = maat_cmd_incrby(g_maat_instance, "TEST_SEQ", 1);
    sprintf(table_line_add, "%lld\t0\t0\t0\t0\t0\tanything\t1\t1\t0.0", compile_id);
    line_rule.rule_id = compile_id;
    line_rule.table_line = table_line_add;
    line_rule.table_name = compile_table_name;
    int ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    /* group2compile table add line */
    memset(&line_rule, 0, sizeof(line_rule));
    memset(table_line_add, 0, sizeof(table_line_add));

    long long group_id = maat_cmd_incrby(g_maat_instance, "SEQUENCE_GROUP", 1);
    sprintf(table_line_add, "%lld\t%lld\t1\t0\tnull\t1", group_id, compile_id);
    line_rule.rule_id = group_id;
    line_rule.table_line = table_line_add;
    line_rule.table_name = g2c_table_name;
    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    /* item table add line */
    memset(&line_rule, 0, sizeof(line_rule));
    memset(table_line_add, 0, sizeof(table_line_add));

    long long item_id = maat_cmd_incrby(g_maat_instance, "SEQUENCE_REGION", 1);
    sprintf(table_line_add, "%lld\t%lld\t%s\t%s\t", item_id, group_id, "URL", "graph_theory");
}
#endif
#if 0
TEST_F(MaatCmdTest, SetIP) {
	long long version_before = 0;
	const char *ip_table_name = "IP_CONFIG";
	const char *compile_table_name = "COMPILE";
    char compile_table_line_add[128] = {0};
    long long compile_id = 0;
   
    compile_id = maat_cmd_incrby(g_maat_instance, "TEST_SEQ", 1);
    sprintf(compile_table_line_add, "%lld\t0\t0\t0\t0\t0\tanything\t1\t1\t0.0", compile_id);
    struct maat_cmd_line line_rule;
    line_rule.rule_id = compile_id;
    line_rule.table_line = compile_table_line_add;
    line_rule.table_name = compile_table_name;
    int ret = maat_cmd_set_line(g_maat_instance, &line_rule);
    EXPECT_EQ(ret, 1);

    long long group_id = maat_cmd_incrby(g_maat_instance, "SEQUENCE_GROUP", 1);
	memset(&line_rule, 0, sizeof(line_rule));
	

	struct Maat_cmd_region region;
	memset(&region, 0, sizeof(region));
	region.region_type=REGION_IP;
	region.table_name=region_table;
	region.ip_rule.addr_type=ADDR_TYPE_IPv4;
	region.ip_rule.direction=ADDR_DIR_DOUBLE;
	region.ip_rule.src_ip="172.0.0.1";
	region.ip_rule.mask_src_ip="255.255.255.255";
	region.ip_rule.src_port=53331;
	region.ip_rule.mask_src_port=0;//means any port should hit.
	
	region.ip_rule.dst_ip="172.0.0.2";
	region.ip_rule.mask_dst_ip="255.255.255.255";
	region.ip_rule.dst_port=80;
	region.ip_rule.mask_dst_port=65535;
	region.ip_rule.protocol=0;//means any protocol should hit.
	ret=Maat_command_batch_set_region(batch, MAAT_OP_ADD, &region, g2c.group_id);
	EXPECT_GE(ret, 0);


	ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version_before, sizeof(version_before));
	EXPECT_EQ(ret, 0);
	Maat_command_batch_commit(batch);

	wait_for_cmd_effective(feather, version_before);
	
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr.addrtype=ADDR_TYPE_IPV4;
	inet_pton(AF_INET,region.ip_rule.src_ip,&(v4_addr.saddr));
	v4_addr.source=htons(region.ip_rule.src_port+1);//Not use the exactly port for testing port mask.
	inet_pton(AF_INET,region.ip_rule.dst_ip,&(v4_addr.daddr));
	v4_addr.dest=htons(region.ip_rule.dst_port);
	ipv4_addr.v4=&v4_addr;
	
	int table_id=0;
	struct Maat_rule_t result;
	memset(&result, 0, sizeof(result));
	scan_status_t mid=NULL;
	table_id=Maat_table_register(feather,region_table);
	ASSERT_GE(table_id, 0);

	ret=Maat_scan_proto_addr(feather,table_id,&ipv4_addr,6,&result,1, &mid,0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result.config_id, config_id);

	Maat_clean_status(&mid);
	
	ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version_before, sizeof(version_before));

	Maat_command_raw_set_compile(feather, MAAT_OP_RENEW_TIMEOUT, &compile, "COMPILE", NULL, 1, 0, timeout);
	
	sleep(timeout-1);
	ret=Maat_scan_proto_addr(feather,table_id,&ipv4_addr,6,&result,1, &mid,0);
	EXPECT_EQ(ret, 1);

	Maat_clean_status(&mid);
}
#endif
struct user_info {
	char name[256];
	char ip_addr[32];
	int id;
	int ref_cnt;
};
void plugin_ex_new_cb(int table_id, const char *key, const char *table_line, 
                      void **ad, long argl, void *argp)
{
	int *counter = (int *)argp;
	struct user_info *u = ALLOC(struct user_info, 1);
	int valid = 0, tag = 0;
	int ret = sscanf(table_line, "%d\t%s\t%s%d\t%d", &(u->id), u->ip_addr, u->name, &valid, &tag);
	EXPECT_EQ(ret, 5);
	u->ref_cnt = 1;
	*ad = u;
	(*counter)++;
}

void plugin_ex_free_cb(int table_id, void **ad, long argl, void *argp)
{
	struct user_info *u = (struct user_info *)(*ad);
	if ((__sync_sub_and_fetch(&u->ref_cnt, 1) == 0)) {
		free(u);
		*ad = NULL;
	}
}

void plugin_ex_dup_cb(int table_id,	void **to, void **from, long argl, void *argp)
{
	struct user_info *u = (struct user_info *)(*from);
	__sync_add_and_fetch(&(u->ref_cnt), 1);
	*to = u;
}

#if 0
TEST_F(MaatCmdTest, PluginEXData) {
    const char *table_name = "TEST_PLUGIN_EXDATA_TABLE";
    const int TEST_CMD_LINE_NUM = 4;
	struct maat_cmd_line line_rule;
	const char *table_line[TEST_CMD_LINE_NUM] = {"1\t192.168.0.1\tmahuateng\t1\t0",
							                     "2\t192.168.0.2\tliuqiangdong\t1\t0",
							                     "3\t192.168.0.3\tmayun\t1\t0",
							                     "4\t192.168.0.4\tliyanhong\t1\t0"};
	int table_id = maat_get_table_id(g_maat_instance, table_name);
	ASSERT_GT(table_id, 0);
    
    /* 1st line */
	memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = maat_cmd_incrby(g_maat_instance, "TEST_PLUG_SEQ", 1);
    line_rule.table_name = table_name;
    line_rule.table_line = table_line[0];
    line_rule.expire_after = 0;

    int ret = maat_cmd_set_line(g_maat_instance, &line_rule);
	EXPECT_GT(ret, 0);

    /* 2nd line */
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = maat_cmd_incrby(g_maat_instance, "TEST_PLUG_SEQ", 1);
    line_rule.table_name = table_name;
    line_rule.table_line = table_line[1];
    line_rule.expire_after = 0;

    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
	EXPECT_GT(ret, 0);

    /* 3rd line */
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = maat_cmd_incrby(g_maat_instance, "TEST_PLUG_SEQ", 1);
    line_rule.table_name = table_name;
    line_rule.table_line = table_line[2];
    line_rule.expire_after = 0;

    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
	EXPECT_GT(ret, 0);

    /* 4th line */
    memset(&line_rule, 0, sizeof(line_rule));
    line_rule.rule_id = maat_cmd_incrby(g_maat_instance, "TEST_PLUG_SEQ", 1);
    line_rule.table_name = table_name;
    line_rule.table_line = table_line[3];
    line_rule.expire_after = 0;

    ret = maat_cmd_set_line(g_maat_instance, &line_rule);
	EXPECT_GT(ret, 0);
	
    sleep(1);
    int ex_data_counter = 0;
	ret = maat_plugin_table_ex_schema_register(g_maat_instance, table_id,
								               plugin_ex_new_cb,
								               plugin_ex_free_cb,
								               plugin_ex_dup_cb,
								               0, &ex_data_counter);
	ASSERT_TRUE(ret >= 0);
	EXPECT_EQ(ex_data_counter, TEST_CMD_LINE_NUM);
	
	struct user_info *uinfo = NULL;
    const char *key1 = "192.168.0.4";
	uinfo = (struct user_info *)maat_plugin_table_get_ex_data(g_maat_instance, table_id, 
                                                              key1, strlen(key1));
	ASSERT_TRUE(uinfo != NULL);
	EXPECT_EQ(0, strcmp(uinfo->name, "liuqiangdong"));
	EXPECT_EQ(uinfo->id, 2);
	plugin_ex_free_cb(table_id, (void**)&uinfo, 0, NULL);
	
	ret = maat_cmd_set_line(g_maat_instance, &line_rule + 1);
	EXPECT_GT(ret, 0);
	
	sleep(1);
    const char *key2 = "192.168.0.2";
	uinfo = (struct user_info *)maat_plugin_table_get_ex_data(g_maat_instance, table_id,
                                                              key2, strlen(key2));
	ASSERT_TRUE(uinfo == NULL);
}
#endif

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
    char json_iris_path[512] = {0};

    snprintf(json_iris_path, sizeof(json_iris_path), "./%s_iris_tmp", json_filename);

    redisContext *c = maat_cmd_connect_redis(redis_ip, redis_port, redis_db, logger);
    if (NULL == c) {
        return -1;
    }

    redisReply *reply = maat_cmd_wrap_redis_command(c, "flushdb");
    if (NULL == reply) {
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
    char tmp_iris_full_idx_path[PATH_MAX] = {0};
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

    g_logger = log_handle_create("./maat_framework_gtest.log", 0);
    if (NULL == g_logger) {
        printf("create log handle failed.\n");
        return -1;
    }

   const char* accept_tags="{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
    char redis_ip[64] = "127.0.0.1";
    int redis_port = 6379;
    int redis_db = 0;

    ret = write_config_to_redis(redis_ip, redis_port, redis_db, g_logger);
    if (ret < 0) {
        log_error(g_logger, MODULE_FRAMEWORK_GTEST, 
                  "[%s:%d] write config to redis failed.", __FUNCTION__, __LINE__);
        log_handle_destroy(g_logger);
        g_logger = NULL;
        return -1;
    }
    
    struct maat_options *opts = maat_options_new();
    maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
    maat_options_set_logger(opts, g_logger);
    maat_options_set_accept_tags(opts, accept_tags);

    g_maat_instance = maat_new(opts, table_info_path);
    maat_options_free(opts);
    if (NULL == g_maat_instance) {
        log_error(g_logger, MODULE_FRAMEWORK_GTEST, 
                  "[%s:%d] create maat instance in MaatStringScan failed.", 
                  __FUNCTION__, __LINE__);
        log_handle_destroy(g_logger);
        return -1;
    }

    ret=RUN_ALL_TESTS();

    maat_free(g_maat_instance);
    log_handle_destroy(g_logger);
    g_logger = NULL;

	return ret;
}
