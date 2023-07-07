#include <gtest/gtest.h>
#include <dirent.h>
#include <openssl/md5.h>

#include "include/maat.h"
#include "include/maat_command.h"

#define MODULE_FRAMEWORK_GTEST	 module_name_str("maat.framework_gtest")

#define ARRAY_SIZE              10
#define HIT_PATH_SIZE           128
#define	WAIT_FOR_EFFECTIVE_S	2

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))

const char *table_info_path = "./demo_table_info.conf";
const char *maat_json_file = "./maat_demo.json";

int compile_table_set_line(struct maat *maat_inst, const char *table_name,
                           enum maat_operation op, long long compile_id,
                           const char *user_region, int clause_num,
                           int expire_after)
{
    char table_line[1024 * 16] = {0};
    sprintf(table_line, "%lld\t0\t0\t0\t0\t0\t%s\t%d\t%d\t0.0", 
            compile_id, user_region, op, clause_num);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = compile_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule);
}

#define TO_GROUP2X_KEY(group_id, parent_id, clause_index)	(((unsigned long)group_id<<32|parent_id) + clause_index)
int group2compile_table_set_line(struct maat *maat_inst, const char *table_name,
                                 enum maat_operation op, long long group_id,
                                 long long compile_id, int not_flag, 
                                 const char *vtable_name, int clause_index,
                                 int expire_after)
{
    char table_line[128] = {0};
    sprintf(table_line, "%lld\t%lld\t%d\t%d\t%s\t%d", 
            group_id, compile_id, op, not_flag, vtable_name, clause_index);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = TO_GROUP2X_KEY(group_id, compile_id, clause_index);
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule);
}

int expr_table_set_line(struct maat *maat_inst, const char *table_name,
                        enum maat_operation op, long long item_id, 
                        long long group_id, const char *keywords,
                        int expr_type, int match_method, int is_hexbin, 
                        int expire_after)
{
    char table_line[1024] = {0};
    int table_id = maat_get_table_id(maat_inst, table_name);
    if (table_id < 0) {
        return 0;
    }
    
    sprintf(table_line, "%lld\t%lld\t%s\t%d\t%d\t%d\t%d", item_id, group_id,
            keywords, expr_type, match_method, is_hexbin, op);

    struct maat_cmd_line line_rule;
    line_rule.rule_id = item_id;
    line_rule.table_line = table_line;
    line_rule.table_name = table_name;
    line_rule.expire_after = expire_after;

    return maat_cmd_set_line(maat_inst, &line_rule);
}

class JsonMode : public testing::Test
{
protected:
    static void SetUpTestCase() {
        struct maat_options *opts = maat_options_new();
        maat_options_set_json_file(opts, maat_json_file);
        maat_options_set_logger(opts, "./maat_sample_gtest.log", LOG_LEVEL_INFO);
       
        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            assert(0);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
    }

    static struct maat *_shared_maat_inst;
};

struct maat *JsonMode::_shared_maat_inst;

TEST_F(JsonMode, ScanDataOnlyOneByte) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = JsonMode::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char scan_data = 0x20;

    int ret = maat_scan_string(maat_inst, table_id, &scan_data, sizeof(scan_data),
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    EXPECT_EQ(n_hit_result, 0);
    maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, literal) {
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = JsonMode::_shared_maat_inst;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *scan_data = "http://www.cyberessays.com/search_results.php?action=search&query=username,abckkk,1234567";

    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 125);
    maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, Regex) {
    int ret = 0;
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    const char *cookie = "Cookie: Txa123aheadBCAxd";
    const char *table_name = "HTTP_URL";
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ret = maat_scan_string(maat_inst, table_id, cookie, strlen(cookie),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 146);
    maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, ExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
	const char *region_name1 ="HTTP URL";
	const char *region_name2 ="我的diStricT";
	const char *scan_data1 = "http://www.cyberessays.com/search_results.php?action=search&query=abckkk,1234567";
	const char *scan_data2 = "Addis Sapphire Hotel";
    const char *table_name = "HTTP_SIGNATURE";
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
	int ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
						        results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_ERR);//Should return error for district not setting.

	ret = maat_state_set_scan_district(state, table_id, region_name1, strlen(region_name1));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 128);
	maat_state_reset(state);

	ret = maat_state_set_scan_district(state, table_id, region_name2, strlen(region_name2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 190);
	maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, ExprPlusWithOffset)
{
	long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
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
							0x34, 0x22, 0x87, 0x4c, 0x2d, 0x00, 0x00, 0x46, //15-16:2d34
							0x2d, 0x34, 0xab, 0x39, 0xbb, 0x97, 0xe5, 0x01, //20-20:2d
							0x03, 0x46, 0x1c, 0x28, 0x5b, 0xab, 0xfa, 0x9a, //24-24:2d
							0xab, 0x2e, 0x71, 0x39, 0x66, 0xa0, 0xd7, 0xb9, 
							0xd8, 0x41, 0xa7, 0xa0, 0x84, 0xa9, 0xf3, 0x1b, 
							0x03, 0x7f, 0xa8, 0x28, 0xa2, 0xd3, 0x64, 0xc2, 
							0x3d, 0x20, 0xe0, 0xb1, 0x41, 0x12, 0x6c, 0x2f, 
							0xc5, 0xbb, 0xc3, 0xba, 0x69, 0x73, 0x52, 0x64, 
							0xf6, 0x30, 0x81, 0xf4, 0x3f, 0xc2, 0x19, 0x6a, 
							0x68, 0x61, 0x93, 0x08, 0xc0, 0x0a };

	int table_id = maat_get_table_id(maat_inst, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, region_name, strlen(region_name));
	EXPECT_EQ(ret, 0);

	ret = maat_scan_string(maat_inst, table_id, (char*)udp_payload_not_hit, sizeof(udp_payload_not_hit), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_scan_string(maat_inst, table_id, (char*)udp_payload_hit, sizeof(udp_payload_hit), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 148);
	
	maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, ExprPlusWithHex) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
	const char *scan_data1 = "text/html; charset=UTF-8";
	const char *scan_data2 = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *region_name1 = "Content-Type";
	const char *region_name2 = "User-Agent";

	int table_id = maat_get_table_id(maat_inst, "HTTP_SIGNATURE");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, region_name1, strlen(region_name1));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 156);

    ret = maat_state_set_scan_district(state, table_id, region_name2, strlen(region_name2));
	ASSERT_EQ(ret, 0);
	ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK); //maat-v3 consider as half hit, it's unreasonable
    
    table_id = maat_get_table_id(maat_inst, "KEYWORDS_TABLE");
    ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 132);                    
	maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, ExprAndExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    const char *expr_table_name = "HTTP_URL";
    const char *expr_plus_table_name = "HTTP_SIGNATURE";
    const char *region_name = "I love China";
    const char *scan_data = "today is Monday and yesterday is Tuesday";

    int expr_table_id = maat_get_table_id(maat_inst, expr_table_name);
    int expr_plus_table_id = maat_get_table_id(maat_inst, expr_plus_table_name);

    int ret = maat_scan_string(maat_inst, expr_plus_table_id, scan_data, strlen(scan_data),
                                results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_ERR);

    ret = maat_state_set_scan_district(state, expr_plus_table_id, region_name, strlen(region_name));
    ASSERT_EQ(ret, 0);
    ret = maat_scan_string(maat_inst, expr_plus_table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HALF_HIT);

    ret = maat_scan_string(maat_inst, expr_table_id, scan_data, strlen(scan_data),
                            results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(results[0], 195);
    maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, ShouldNotHitExprPlus) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
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

	int table_id = maat_get_table_id(maat_inst, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);

	int ret = maat_state_set_scan_district(state, table_id, region_name, strlen(region_name));
	ASSERT_EQ(ret, 0);
    
	ret = maat_scan_string(maat_inst, table_id, (char *)udp_payload_not_hit, sizeof(udp_payload_not_hit), 
						   results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK); //maat-v3 consider as half hit, it's unreasonable
	maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, Expr8) {
    const char *table_name = "KEYWORDS_TABLE";
    int thread_id = 0;
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int table_id = maat_get_table_id(maat_inst, table_name);
    char scan_data[128] = "string1, string2, string3, string4, string5, string6, string7, string8";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;

    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 182);

    struct maat_hit_path hit_path[HIT_PATH_SIZE] = {0};
    int n_read = 0;
    n_read = maat_state_get_hit_paths(state, hit_path, HIT_PATH_SIZE);
    EXPECT_NE(n_read, 0);
    maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, HexBinCaseSensitive) {
    const char *table_name = "KEYWORDS_TABLE";
	const char *scan_data1 = "String TeST should not hit.";
	const char *scan_data2 = "String TEST should hit";
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_string(maat_inst, table_id, scan_data1, strlen(scan_data1), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_reset(state);

    ret = maat_scan_string(maat_inst, table_id, scan_data2, strlen(scan_data2), 
                           results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 2);
    EXPECT_EQ(results[0], 206);
    EXPECT_EQ(results[1], 191);
    maat_state_free(state);
}

TEST_F(JsonMode, BugReport20190325) {
    unsigned char scan_data[] = {/* Packet 1 */
                                 0x01, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00,
                                 0x00, 0xf4, 0x01, 0x00, 0x00, 0x32, 0x00, 0x00,
                                 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x2d, 0x3d, 0x3d, 0x20, 0x48, 0x3d, 0x48, 0x20,
                                 0x3d, 0x3d, 0x2d, 0x3a, 0x00, 0x02, 0x00, 0x00,
                                 0x00, 0x07, 0x0e, 0x00, 0x00, 0xe8, 0x03, 0x00,
                                 0x00, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x33,
                                 0x2e, 0x31, 0x39, 0x2e, 0x30, 0x2d, 0x31, 0x35,
                                 0x2d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63,
                                 0x00, 0x31, 0x3a, 0x47, 0x32, 0x2e, 0x34, 0x30,
                                 0x00};
    const char *table_name = "TROJAN_PAYLOAD";
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_string(maat_inst, table_id, (char *)scan_data, sizeof(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 150);
    maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, MaatUnescape) {
    const char *scan_data = "Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char *table_name = "KEYWORDS_TABLE";
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    int thread_id = 0;

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
    int ret = maat_scan_string(maat_inst, table_id, scan_data, strlen(scan_data), 
                               results, ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], 132);
    maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, OffsetChunk64) {
    const char *table_name = "IMAGE_FP";
	const char *file_name = "./testdata/mesa_logo.jpg";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp==NULL);

    char scan_data[64];
    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
	ASSERT_TRUE(sp != NULL);

    int ret = 0;
    int read_size = 0;
    int pass_flag = 0;
    while (0 == feof(fp)) {
        read_size = fread(scan_data, 1, sizeof(scan_data), fp);
        ret = maat_stream_scan(sp, scan_data, read_size,
                                results, ARRAY_SIZE, &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break;
        }
    }
    EXPECT_EQ(pass_flag, 1);
    EXPECT_EQ(results[0], 136);
    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, OffsetChunk1460) {
    const char *table_name = "IMAGE_FP";
	const char *file_name = "./testdata/mesa_logo.jpg";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp==NULL);

    char scan_data[1460];
    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
	ASSERT_TRUE(sp != NULL);

    int ret = 0;
    int read_size = 0;
    int pass_flag = 0;
    while (0 == feof(fp)) {
        read_size = fread(scan_data, 1, sizeof(scan_data), fp);
        ret = maat_stream_scan(sp, scan_data, read_size,
                                results, ARRAY_SIZE, &n_hit_result, state);
        if (ret > 0) {
            pass_flag = 1;
            break;
        }
    }
    EXPECT_EQ(pass_flag, 1);
    EXPECT_EQ(results[0], 136);
    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, StreamScanUTF8) {
    const char *table_name = "TROJAN_PAYLOAD";
	const char* file_name = "./testdata/jd.com.html";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    char scan_data[2048];
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

	FILE *fp = fopen(file_name, "r");
	ASSERT_FALSE(fp == NULL);

    int table_id = maat_get_table_id(maat_inst, table_name);
    ASSERT_GT(table_id, 0);

    struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
    ASSERT_FALSE(sp == NULL);

    int pass_flag = 0;
    while (0 == feof(fp)) {
		size_t read_size = fread(scan_data, 1, sizeof(scan_data), fp);
		int ret = maat_stream_scan(sp, scan_data, read_size, results, ARRAY_SIZE,
                                    &n_hit_result, state);
		if (ret == MAAT_SCAN_HIT) {
			pass_flag = 1;
			break;
		}
	}

    EXPECT_EQ(pass_flag, 1);
	EXPECT_EQ(results[0], 157);
    maat_stream_free(sp);
    fclose(fp);
    maat_state_free(state);
    state = NULL;
}

TEST_F(JsonMode, StreamInput) {
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = JsonMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);
	const char *scan_data = "http://www.cyberessays.com/search_results.php?action=search&query=yulingjing,abckkk,1234567";
	const char *table_name = "HTTP_URL";

	int table_id = maat_get_table_id(maat_inst, table_name);
	ASSERT_GT(table_id, 0);

	struct maat_stream *sp = maat_stream_new(maat_inst, table_id, state);
	ASSERT_TRUE(sp != NULL);

	int ret = maat_stream_scan(sp, "www.cyberessays.com", strlen("www.cyberessays.com"),
                                results, ARRAY_SIZE, &n_hit_result, state);
	EXPECT_EQ(ret, MAAT_SCAN_OK);

	ret = maat_stream_scan(sp, scan_data, strlen(scan_data), results, ARRAY_SIZE,
                            &n_hit_result, state);
	maat_stream_free(sp);

	EXPECT_EQ(ret, MAAT_SCAN_HIT);
	EXPECT_EQ(results[0], 125);
	maat_state_free(state);
    state = NULL;
}

class RedisMode : public testing::Test
{
protected:
    static void SetUpTestCase() {
        const char *redis_ip = "127.0.0.1";
        uint16_t redis_port = 6379;
        int redis_db = 0;

        struct maat_options *opts = maat_options_new();
        maat_options_set_redis(opts, redis_ip, redis_port, redis_db);
        maat_options_set_logger(opts, "./maat_sample_gtest.log", LOG_LEVEL_INFO);
       
        _shared_maat_inst = maat_new(opts, table_info_path);
        maat_options_free(opts);
        if (NULL == _shared_maat_inst) {
            assert(0);
        }
    }

    static void TearDownTestCase() {
        maat_free(_shared_maat_inst);
    }

    static struct maat *_shared_maat_inst;
};

struct maat *RedisMode::_shared_maat_inst;

TEST_F(RedisMode, dynamic_config) {
    const char *table_name = "HTTP_URL";
    char data[128] = "welcome to maat version4, it's funny.";
    long long results[ARRAY_SIZE] = {0};
    size_t n_hit_result = 0;
    int thread_id = 0;
    struct maat *maat_inst = RedisMode::_shared_maat_inst;
    struct maat_state *state = maat_state_new(maat_inst, thread_id);

    int table_id = maat_get_table_id(maat_inst, table_name);
    int ret = maat_scan_string(maat_inst, table_id, data, strlen(data), results, 
                               ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    maat_state_reset(state);

    const char *compile_table_name = "COMPILE";
    const char *g2c_table_name = "GROUP2COMPILE";

    /* compile table add line */
    long long compile_id = maat_cmd_incrby(maat_inst, "TEST_SEQ", 1);
    ret = compile_table_set_line(maat_inst, compile_table_name, MAAT_OP_ADD, compile_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* group2compile table add line */
    long long group_id = maat_cmd_incrby(maat_inst, "SEQUENCE_GROUP", 1);
    ret = group2compile_table_set_line(maat_inst, g2c_table_name, MAAT_OP_ADD, group_id,
                                       compile_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* expr table add line */
    long long item_id = maat_cmd_incrby(maat_inst, "SEQUENCE_REGION", 1);
    const char *keywords = "welcome to maat";
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_ADD, item_id, group_id,
                              keywords, 1, 0, 0, 0); /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_id, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_HIT);
    EXPECT_EQ(n_hit_result, 1);
    EXPECT_EQ(results[0], compile_id);
    maat_state_reset(state);

    /* expr table del line */
    ret = expr_table_set_line(maat_inst, table_name, MAAT_OP_DEL, item_id, group_id,
                              keywords, 1, 0, 0, 0); /* EXPR_TYPE_AND MATCH_METHOD_SUB */
    EXPECT_EQ(ret, 1);

    /* group2compile table del line */
    ret = group2compile_table_set_line(maat_inst, g2c_table_name, MAAT_OP_DEL, group_id,
                                       compile_id, 0, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    /* compile table del line */
    ret = compile_table_set_line(maat_inst, compile_table_name, MAAT_OP_DEL, compile_id, "null", 1, 0);
    EXPECT_EQ(ret, 1);

    sleep(WAIT_FOR_EFFECTIVE_S);

    ret = maat_scan_string(maat_inst, table_id, data, strlen(data), results, 
                           ARRAY_SIZE, &n_hit_result, state);
    EXPECT_EQ(ret, MAAT_SCAN_OK);
    
    maat_state_free(state);
    state = NULL;
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

    ret=RUN_ALL_TESTS();

	return ret;
}