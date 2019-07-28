#include "Maat_rule.h"
#include "stream_fuzzy_hash.h"
#include "Maat_command.h"
#include <MESA/MESA_handle_logger.h>
#include <gtest/gtest.h>
int test_add_expr_command_copy(Maat_feather_t feather,const char* region_table,int config_id, int timeout,int label_id, const char* keywords)
{
	struct Maat_cmd_t* cmd=NULL;
	struct Maat_rule_t rule;
	char huge_serv_def[1024*2];
	memset(huge_serv_def,'s',sizeof(huge_serv_def));
	struct Maat_region_t region;
	int group_num=1,ret=0;
	memset(&rule,0,sizeof(rule));
	rule.config_id=config_id;
	strcpy(rule.service_defined,"maat_command");
	//MUST acqire by function, because Maat_cmd_t has some hidden members.
	cmd=Maat_create_cmd(&rule, group_num);
	cmd->expire_after=timeout;
	cmd->label_id=label_id;
	memset(&region,0,sizeof(region));
	region.region_type=REGION_EXPR;
	region.table_name=region_table;
	region.expr_rule.district=NULL;
	region.expr_rule.keywords=keywords;
	region.expr_rule.expr_type=EXPR_TYPE_AND;
	region.expr_rule.match_method=MATCH_METHOD_SUB;
	region.expr_rule.hex_bin=UNCASE_PLAIN;
	Maat_cmd_set_opt(cmd, MAAT_RULE_SERV_DEFINE, huge_serv_def, sizeof(huge_serv_def));
	Maat_add_region2cmd(cmd, 0, &region);
	//use pipeline model.
	ret=Maat_cmd_append(feather, cmd, MAAT_OP_ADD);
	if(ret<0)
	{
		printf("Add Maat command %d failed.\n",rule.config_id);
		Maat_free_cmd(cmd);
		return 0;
	}
	//cmd has been saved in feather, so free cmd before commit is allowed.
	Maat_free_cmd(cmd);
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

	  	logger=MESA_create_runtime_log_handle("test_maat_redis.log",0);

		_shared_feather=Maat_feather(g_iThreadNum, table_info_path, logger);
		Maat_set_feather_opt(_shared_feather,MAAT_OPT_INSTANCE_NAME,"perf", strlen("perf")+1);
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_REDIS_IP, test_maat_redis_ip, strlen(test_maat_redis_ip)+1);
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_REDIS_PORT, &test_maat_redis_port, sizeof(test_maat_redis_port));
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_SCANDIR_INTERVAL_MS,&scan_interval_ms, sizeof(scan_interval_ms));
		//Set a short intevral for testing.
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_EFFECT_INVERVAL_MS,&effective_interval_ms, sizeof(effective_interval_ms));
		
		const char* foregin_dir="./foreign_files/";	
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_FOREIGN_CONT_DIR, foregin_dir, strlen(foregin_dir)+1);
		int linger_timeout=2;
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_FOREIGN_CONT_LINGER, &linger_timeout, sizeof(linger_timeout));

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
	const int CMD_EXPR_NUM=200*1000;
	const char* table_name="HTTP_URL";
	
	const char* keywords1="Hiredis";
	const char* keywords2="C Client";
	char escape_buff1[256],escape_buff2[256];
	char keywords[256];

	int label_id=5210, config_id=0,ret=0, output_id_cnt=0;
	Maat_feather_t feather=MaatCMDPerfTest::_shared_feather;
	long long version_before=0;
	ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version_before, sizeof(version_before));
	
	Maat_str_escape(escape_buff1, sizeof(escape_buff1),keywords1);
	Maat_str_escape(escape_buff2, sizeof(escape_buff2),keywords2);
	snprintf(keywords,sizeof(keywords),"%s&%s",escape_buff1,escape_buff2);
	
	config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", CMD_EXPR_NUM);
	int i=0;
	for(i=0; i<CMD_EXPR_NUM;i++)
	{
		test_add_expr_command_copy(feather,table_name,config_id-i, 0, label_id, keywords);
	}
	ret=Maat_cmd_commit(feather);
	EXPECT_TRUE(ret>=0);
	wait_for_cmd_effective_copy(feather, version_before);
	struct Maat_cmd_t* cmd=NULL;
	struct Maat_rule_t rule;
	memset(&rule,0,sizeof(rule));
	int *output_ids=(int*)malloc(sizeof(int)*CMD_EXPR_NUM);
	output_id_cnt=Maat_cmd_select(feather,label_id, output_ids, CMD_EXPR_NUM);
	EXPECT_EQ(output_id_cnt, CMD_EXPR_NUM);
	for(i=0; i<CMD_EXPR_NUM;i++)
	{
		memset(&rule,0,sizeof(rule));
		rule.config_id=output_ids[i];
		cmd=Maat_create_cmd(&rule, 0);
		ret=Maat_cmd_append(feather, cmd, MAAT_OP_DEL);
		EXPECT_EQ(ret, 0);
		Maat_free_cmd(cmd);
	}
	ret=Maat_cmd_commit(feather);
	
	EXPECT_EQ(ret, CMD_EXPR_NUM);
	free(output_ids);
}

TEST_F(MaatCMDPerfTest, SetLinesOneMillion)
{
	const int TEST_CMD_LINE_NUM=1000*1000;
	Maat_feather_t feather=MaatCMDPerfTest::_shared_feather;

	struct Maat_line_t **p_line=(struct Maat_line_t **)calloc(sizeof(struct Maat_line_t *), TEST_CMD_LINE_NUM);
	struct Maat_line_t *line_rule=(struct Maat_line_t *)calloc(sizeof(struct Maat_line_t), TEST_CMD_LINE_NUM);
	int i=0;
	const char* line="1\t192.168.0.1\t4444444444\t1";
	int seq=(int)Maat_cmd_incrby(feather,"TEST_PLUG_SEQ", TEST_CMD_LINE_NUM);
	for(i=0;i<TEST_CMD_LINE_NUM;i++)
	{
		line_rule[i].label_id=0;
		line_rule[i].rule_id=seq-i;
		line_rule[i].table_name="QD_ENTRY_INFO";
		line_rule[i].table_line=line;
//		asprintf(&(line_rule[i].table_line),"1\t192.168.0.1\t%d\t1",100+i);
		line_rule[i].expire_after=0;
		p_line[i]=line_rule+i;
	}
	
	long long version_before=0;
	Maat_read_state(feather,MAAT_STATE_VERSION, &version_before, sizeof(version_before));

	Maat_cmd_set_lines(feather,(const struct Maat_line_t **)p_line,TEST_CMD_LINE_NUM, MAAT_OP_ADD);
	
	wait_for_cmd_effective_copy(feather, version_before);
	
	for(i=0;i<TEST_CMD_LINE_NUM;i++)
	{
		line_rule[i].table_line=NULL;
	}
	Maat_cmd_set_lines(feather, (const struct Maat_line_t **)p_line,TEST_CMD_LINE_NUM, MAAT_OP_DEL);
	free(p_line);
	free(line_rule);

	return;
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

	ret=RUN_ALL_TESTS();
	return ret;
}


