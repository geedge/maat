#include "Maat_rule.h"
#include "stream_fuzzy_hash.h"
#include "Maat_command.h"
#include <MESA/MESA_handle_logger.h>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <arpa/inet.h>

void ipv4_addr_set_copy(struct ipaddr *ipv4_addr, struct stream_tuple4_v4* v4_addr,
						const char* src_ip, unsigned short sport, const char* dest_ip, unsigned short dport)
{
	ipv4_addr->addrtype=ADDR_TYPE_IPV4;
	inet_pton(AF_INET, src_ip, &(v4_addr->saddr));
	v4_addr->source=htons(sport);
	inet_pton(AF_INET, dest_ip, &(v4_addr->daddr));
	v4_addr->dest=htons(dport);
	ipv4_addr->v4=v4_addr;
	return;
}


void random_keyword_generate(char* keyword_buf, size_t sz)
{
#define MIN_KEYWORD_LEN	4
	size_t i=0, len=0;
	len=random()%(sz-1-MIN_KEYWORD_LEN)+MIN_KEYWORD_LEN;
	for(i=0; i<len; i++)
	{
		keyword_buf[i]='0'+random()%('~' - '0');
	}
	keyword_buf[i]='\0';
	return;
}
void random_ipv4_addr_generate(char* ip_buff, size_t sz)
{
	unsigned int ip=random();
	inet_ntop(AF_INET, &ip, ip_buff, sz);
	return;
}
int test_add_ip_command(struct Maat_command_batch* batch, const char* region_table, const char* src_ip, const char* dst_ip, int config_id)
{
	struct Maat_cmd_group2compile g2c;
	struct Maat_rule_t rule;
	memset(&rule,0,sizeof(rule));
	rule.config_id=config_id;
	strcpy(rule.service_defined,"maat_command");

	Maat_command_batch_set_compile(batch, MAAT_OP_ADD, &rule, "COMPILE", NULL, 1, 0, 0);
	memset(&g2c, 0, sizeof(g2c));
	g2c.group_id=config_id;
	g2c.compile_id=config_id;
	g2c.table_name="GROUP2COMPILE";
	Maat_command_batch_set_group2compile(batch, MAAT_OP_ADD, &g2c);


	struct Maat_cmd_region region;
	memset(&region, 0, sizeof(region));
	region.region_id=config_id;
	region.region_type=REGION_IP;
	region.table_name=region_table;
	region.ip_rule.addr_type=ADDR_TYPE_IPv4;
	region.ip_rule.direction=ADDR_DIR_DOUBLE;
	region.ip_rule.src_ip=src_ip;
	region.ip_rule.mask_src_ip="255.255.255.255";
	region.ip_rule.src_port=0;
	region.ip_rule.mask_src_port=0;//means any port should hit.
	
	region.ip_rule.dst_ip=dst_ip;
	region.ip_rule.mask_dst_ip="255.255.255.255";
	region.ip_rule.dst_port=0;
	region.ip_rule.mask_dst_port=65535;
	region.ip_rule.protocol=0;//means any protocol should hit.
	Maat_command_batch_set_region(batch, MAAT_OP_ADD, &region, g2c.group_id);
	return 0;

}
int test_add_expr_command_copy(struct Maat_command_batch* batch, const char* region_table,int config_id, const char* keywords)
{
	struct Maat_cmd_group2compile g2c;
	struct Maat_rule_t rule;
	struct Maat_cmd_region region;
	memset(&rule,0,sizeof(rule));
	rule.config_id=config_id;
	strcpy(rule.service_defined,"maat_command");

	Maat_command_batch_set_compile(batch, MAAT_OP_ADD, &rule, "COMPILE", NULL, 1, 0, 0);
	memset(&g2c, 0, sizeof(g2c));
	g2c.group_id=config_id;
	g2c.compile_id=config_id;
	g2c.table_name="GROUP2COMPILE";
	Maat_command_batch_set_group2compile(batch, MAAT_OP_ADD, &g2c);
	memset(&region,0,sizeof(region));
	region.region_id=config_id;
	region.region_type=REGION_EXPR;
	region.table_name=region_table;
	region.expr_rule.district=NULL;
	region.expr_rule.keywords=keywords;
	region.expr_rule.expr_type=EXPR_TYPE_AND;
	region.expr_rule.match_method=MATCH_METHOD_SUB;
	region.expr_rule.hex_bin=UNCASE_PLAIN;
	Maat_command_batch_set_region(batch, MAAT_OP_ADD, &region, g2c.group_id);
	return 0;
}
void wait_for_cmd_effective_copy(Maat_feather_t feather, long long version_before)
{
	long long	version_after=version_before;
	int is_updating=1;
	long long wating_us=0, sleep_us=1000*100;
	while(is_updating||version_before==version_after)
	{
		Maat_read_state(feather,MAAT_STATE_IN_UPDATING, &is_updating, sizeof(is_updating));
		Maat_read_state(feather,MAAT_STATE_VERSION, &version_after, sizeof(version_after));

		usleep(sleep_us);//waiting for commands go into effect
		wating_us+=sleep_us;
	}
//	printf("wait for %lld ms\n", wating_us/1000);
}

class MaatCMDPerfTest : public testing::Test 
{

protected:


	static void SetUpTestCase()
	{
		const char* test_maat_redis_ip="127.0.0.1";
		unsigned short test_maat_redis_port=6379;
		int g_iThreadNum=4;
		const char* table_info_path="./table_info.conf";
		int scan_interval_ms=500;
		int effective_interval_ms=0;

	  	logger=MESA_create_runtime_log_handle("maat_perf_test.log",0);

		_shared_feather=Maat_feather(g_iThreadNum, table_info_path, logger);
		Maat_set_feather_opt(_shared_feather,MAAT_OPT_INSTANCE_NAME,"perf", strlen("perf")+1);
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_REDIS_IP, test_maat_redis_ip, strlen(test_maat_redis_ip)+1);
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_REDIS_PORT, &test_maat_redis_port, sizeof(test_maat_redis_port));
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_SCANDIR_INTERVAL_MS,&scan_interval_ms, sizeof(scan_interval_ms));
		//Set a short intevral for testing.
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_EFFECT_INVERVAL_MS,&effective_interval_ms, sizeof(effective_interval_ms));
		
		const char* foregin_dir="./foreign_files/";	
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_FOREIGN_CONT_DIR, foregin_dir, strlen(foregin_dir)+1);
	
		Maat_cmd_flushDB(_shared_feather);
		Maat_initiate_feather(_shared_feather);
	}
	static void TearDownTestCase()
	{
		Maat_burn_feather(_shared_feather);
		MESA_destroy_runtime_log_handle(logger);

	}	
 	// Some expensive resource shared by all tests.
	static Maat_feather_t _shared_feather;
	static void *logger;
};
Maat_feather_t MaatCMDPerfTest::_shared_feather;

void* MaatCMDPerfTest::logger;

//Following tests must be coded/tested at last, for they stalled the maat update thread and interrupt other tests.
TEST_F(MaatCMDPerfTest, SetExpr200K)
{
	const int CMD_EXPR_NUM=2*1000*1000;
	const int CMD_IP_NUM=13*1000*1000;
	const char* expr_table_name="HTTP_URL";
	const char* ip_table_name="IP_CONFIG";

	int srand_keyword=171, srand_ip=73;
	char keyword_buf[128];
	char src_ip_buff[32], dst_ip_buff[32];
	
	int config_id=0, ret=0;
	Maat_feather_t feather=MaatCMDPerfTest::_shared_feather;
	long long version_before=0;
	ret=Maat_read_state(feather, MAAT_STATE_VERSION, &version_before, sizeof(version_before));

	config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", CMD_EXPR_NUM+CMD_IP_NUM);
	config_id-=CMD_EXPR_NUM+CMD_IP_NUM;
	int i=0;
	
	struct Maat_command_batch* batch=NULL;
	batch=Maat_command_batch_new(feather);
	srand(srand_keyword);
	for(i=0; i<CMD_EXPR_NUM;i++)
	{
		random_keyword_generate(keyword_buf, sizeof(keyword_buf));
		test_add_expr_command_copy(batch, expr_table_name, config_id+i, keyword_buf);
	}
	srand(srand_ip);
	for(i=0; i<CMD_IP_NUM; i++)
	{
		random_ipv4_addr_generate(src_ip_buff, sizeof(src_ip_buff));
		random_ipv4_addr_generate(dst_ip_buff, sizeof(dst_ip_buff));
		test_add_ip_command(batch, ip_table_name, src_ip_buff, dst_ip_buff, config_id+CMD_EXPR_NUM+i);
	}
	Maat_command_batch_commit(batch);
	wait_for_cmd_effective_copy(feather, version_before);

	struct Maat_rule_t result;
	scan_status_t mid=NULL;

	int table_id=0;
	table_id=Maat_table_register(feather, expr_table_name);
	ASSERT_GT(table_id, 0);
	memset(&result, 0, sizeof(result));
	
	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, keyword_buf, strlen(keyword_buf), 
						&result, NULL, 1,
						&mid, 0);	
	EXPECT_EQ(ret, 1);

	Maat_clean_status(&mid);

	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr_set_copy(&ipv4_addr, &v4_addr, src_ip_buff, 50001, dst_ip_buff, 80);

	table_id=Maat_table_register(feather, ip_table_name);
	ASSERT_GT(table_id, 0);
	memset(&result, 0, sizeof(result));
	ret=Maat_scan_proto_addr(feather, table_id, &ipv4_addr, 6, &result, 1, &mid, 0);
	
	EXPECT_EQ(ret, 1);
	Maat_clean_status(&mid);
	return;
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

	ret=RUN_ALL_TESTS();
	return ret;
}


