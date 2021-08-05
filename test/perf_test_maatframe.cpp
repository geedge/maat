#include "Maat_rule.h"
#include "bool_matcher.h"
#include "stream_fuzzy_hash.h"
#include "Maat_command.h"
#include <MESA/MESA_handle_logger.h>
using namespace std;
#include <gtest/gtest.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/queue.h>

int global_thread_num=4;

struct bool_expr_wrapper
{
	struct bool_expr expr;
	TAILQ_ENTRY(bool_expr_wrapper) entries;
};
TAILQ_HEAD(bool_expr_q,    bool_expr_wrapper);

TEST(BoolMatcher, Match)
{
	struct bool_matcher * bm=NULL;
	struct bool_expr *expr_array=NULL;
	struct bool_expr_wrapper *p=NULL;
	bool_expr_q expr_queue;
	unsigned long long i=0;
	TAILQ_INIT(&expr_queue);
	const char* bool_expr_filename="./testdata/bool-matcher-test-exprs.txt";
	char line[512]={0};
	int ret=0, expr_num=0;
	FILE* fp=fopen(bool_expr_filename, "r");
	memset(line, 0, sizeof(line));
	while(NULL!=fgets(line,sizeof(line),fp))
	{
		if(line[0]=='#'||line[0]==' '||line[0]=='\t'||strlen(line)<4)
		{
			continue;
		}
		p=(struct bool_expr_wrapper*)calloc(sizeof(struct bool_expr_wrapper), 1);
		ret=sscanf(line, "%lld %lld %lld %lld %lld %lld %lld %lld %lld", 
			&p->expr.expr_id,
			&p->expr.items[0].item_id,
			&p->expr.items[1].item_id,
			&p->expr.items[2].item_id,
			&p->expr.items[3].item_id,
			&p->expr.items[4].item_id,
			&p->expr.items[5].item_id,
			&p->expr.items[6].item_id,
			&p->expr.items[7].item_id);
		if(ret<2)
		{
			free(p);
			continue;
		}
		p->expr.item_num=ret-1;
		p->expr.user_tag=NULL;
		TAILQ_INSERT_TAIL(&expr_queue, p, entries);
		expr_num++;	
		memset(line, 0, sizeof(line));
	}	
	fclose(fp);
	expr_array=(struct bool_expr*)malloc(sizeof(struct bool_expr)*expr_num);
	p=TAILQ_FIRST(&expr_queue);
	while(p != NULL)
	{
		TAILQ_REMOVE(&expr_queue, p, entries);
		memcpy(expr_array+i, &(p->expr), sizeof(p->expr));
		free(p);
		p = TAILQ_FIRST(&expr_queue);
		i++;
	}
	size_t mem_size=0;
	bm=bool_matcher_new(expr_array, expr_num, 4, &mem_size);
	unsigned long long test_count=2*1000*1000, match_count=0, unmatch_count=0;
	long int j=0;
	size_t k=0;
	unsigned long long input_item_ids[256], time_elapse_ms=0, scan_per_second=0;
	size_t input_item_num=0;
	struct bool_expr_match result_array[1024];
	srand(19);
	struct timespec start,end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for(i=0; i<test_count;i++)
	{
		input_item_num=0;
		j=random()%expr_num;
		for(k=0; k<expr_array[j].item_num; k++)
		{
			input_item_ids[k]=expr_array[j].items[k].item_id;
			input_item_num++;
		}
		for(k=0; k<8; k++)
		{
			input_item_ids[input_item_num]=random();
			input_item_num++;
		}
		sort(input_item_ids, input_item_ids+input_item_num);
		ret=bool_matcher_match(bm, 1, input_item_ids, input_item_num, result_array, 1024);
		if(ret>0)
		{
			match_count++;
		}
	}
	EXPECT_EQ(match_count, test_count);
	input_item_ids[0]=123;
	input_item_ids[1]=124;
	input_item_ids[2]=125;
	input_item_ids[3]=7;
	input_item_ids[4]=3;
	input_item_ids[5]=128;
	input_item_ids[6]=129;
	input_item_ids[7]=130;
	input_item_ids[8]=131;
	input_item_ids[9]=132;
	input_item_ids[10]=133;
	input_item_ids[11]=777;
	input_item_ids[12]=999;
	input_item_ids[13]=788;
	input_item_ids[14]=222;
	input_item_ids[15]=333;
	input_item_num=8;
	sort(input_item_ids, input_item_ids+input_item_num);
	for(i=0; i<test_count; i++)
	{
		ret=bool_matcher_match(bm, 1, input_item_ids, input_item_num, result_array, 1024);
		if(ret==0)
		{
			unmatch_count++;
		}
	}
	EXPECT_EQ(unmatch_count, test_count);	
	clock_gettime(CLOCK_MONOTONIC, &end);
	time_elapse_ms=(end.tv_sec-start.tv_sec)*1000+(end.tv_nsec-start.tv_nsec)/1000000;
	scan_per_second=test_count*2*1000/time_elapse_ms;
	//At least 1 million scan per second
	EXPECT_GT(scan_per_second, 1000000);
	printf("Bool matcher memsize %zu, speed %lld lookups/s\n", mem_size, scan_per_second);
	free(expr_array);
	expr_array=NULL;
	bool_matcher_free(bm);
}

#define WAIT_FOR_EFFECTIVE_SECOND 4

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
void random_fqdn_generate(char* fqdn_buff, size_t sz)
{
	size_t min_fqdn_len=6, max_fqdn_len=32;
	size_t i=0, j=0, len=0;
	len=random()%(max_fqdn_len-min_fqdn_len)+min_fqdn_len;
	if(len>=sz)
	{
		len=sz-1;
	}
	for(i=0; i<len-4; i++)
	{
		fqdn_buff[i]='a'+random()%('z' - 'a');
		if(j>5)
		{
			if(random()%3==0)
			{
				fqdn_buff[i]='.';
				j=0;
			}
		}
		j++;
	}
	fqdn_buff[i]='\0';
}
void random_keyword_generate(char* keyword_buf, size_t sz)
{
#define MIN_KEYWORD_LEN	4
	size_t i=0, len=0;
	len=random()%(sz-1-MIN_KEYWORD_LEN)+MIN_KEYWORD_LEN;
	for(i=0; i<len; i++)
	{
		//keyword_buf[i]='0'+random()%('~' - '0');
		keyword_buf[i]='a'+random()%('z' - 'a');
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
int test_add_expr_command_copy(struct Maat_command_batch* batch, const char* region_table,int config_id, const char* keywords, int clause_num)
{
	struct Maat_cmd_group2compile g2c;
	struct Maat_rule_t rule;
	struct Maat_cmd_region region;
	memset(&rule,0,sizeof(rule));
	rule.config_id=config_id;
	strcpy(rule.service_defined,"maat_command");

	Maat_command_batch_set_compile(batch, MAAT_OP_ADD, &rule, "COMPILE", NULL, clause_num, 0, 0);
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
		const char* table_info_path="./table_info.conf";
		const char* stat_file="./perf_cmd_test.fs2";
		int scan_interval_ms=500;
		int effective_interval_ms=0;

	  	logger=MESA_create_runtime_log_handle("maat_perf_test.log",0);

		_shared_feather=Maat_feather(global_thread_num, table_info_path, logger);
		Maat_set_feather_opt(_shared_feather,MAAT_OPT_INSTANCE_NAME, "cmdperf", strlen("cmdperf")+1);
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_REDIS_IP, test_maat_redis_ip, strlen(test_maat_redis_ip)+1);
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_REDIS_PORT, &test_maat_redis_port, sizeof(test_maat_redis_port));
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_SCANDIR_INTERVAL_MS, &scan_interval_ms, sizeof(scan_interval_ms));
		//Set a short intevral for testing.
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_EFFECT_INVERVAL_MS, &effective_interval_ms, sizeof(effective_interval_ms));
		
		const char* foregin_dir="./foreign_files/";	
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_FOREIGN_CONT_DIR, foregin_dir, strlen(foregin_dir)+1);
		
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_STAT_FILE_PATH, stat_file, strlen(stat_file)+1);
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_STAT_ON, NULL, 0);
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_PERF_ON, NULL, 0);
	
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
TEST_F(MaatCMDPerfTest, SetExpr50K)
{
//	const int CMD_EXPR_NUM=2*100*1000;
	const int CMD_EXPR_NUM=50*1000;
	const int CMD_IP_NUM=3*1000;
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
		test_add_expr_command_copy(batch, expr_table_name, config_id+i, keyword_buf, 1);
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
const char* high_match_string="maatframe!";
struct thread_para
{
	int thread_id;
	int test_count;
	Maat_feather_t feather;
	const char* table_name;
	unsigned long long time_elapse_ms;
};
void* high_match_rate_scan_thread(void *arg)
{

	struct thread_para* para=(struct thread_para*)arg;
	Maat_feather_t feather=para->feather;
	const char* expr_table_name=para->table_name;

	struct Maat_rule_t result;
	scan_status_t mid=NULL;

	int table_id=0, i=0, ret=0, hit_times=0;
	table_id=Maat_table_register(feather, expr_table_name);
	memset(&result, 0, sizeof(result));
	struct timespec start, end;
	
	clock_gettime(CLOCK_MONOTONIC, &start);
	for(i=0; i<para->test_count; i++)
	{
		ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, high_match_string, strlen(high_match_string), 
							&result, NULL, 1,
							&mid, para->thread_id);
		if(ret==-2)
		{
			hit_times++;
		}
		Maat_clean_status(&mid);
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	para->time_elapse_ms=(end.tv_sec-start.tv_sec)*1000+(end.tv_nsec-start.tv_nsec)/1000000;
	int* is_all_hit=(int*)malloc(sizeof(int));
	*is_all_hit=(hit_times==para->test_count)?1:0;
	return is_all_hit;
}
void* high_match_rate_update_thread(void *arg)
{
	struct thread_para* para=(struct thread_para*)arg;
	Maat_feather_t feather=para->feather;
	const int CMD_EXPR_NUM=10;
	int config_id=0;
	config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", CMD_EXPR_NUM);
	config_id-=CMD_EXPR_NUM;
	int i=0;
	char keyword_buf[128];
	struct Maat_command_batch* batch=NULL;
	batch=Maat_command_batch_new(feather);

	for(i=0; i<CMD_EXPR_NUM;i++)
	{
		random_keyword_generate(keyword_buf, sizeof(keyword_buf));
		test_add_expr_command_copy(batch, para->table_name, config_id+i, keyword_buf, 1);
		sleep(1);
	}
	int* is_all_hit=(int*)malloc(sizeof(int));
	*is_all_hit=1;
	return is_all_hit;
}

TEST_F(MaatCMDPerfTest, HighMatchRateOnMultiThread)
{
	const char* expr_table_name="HTTP_URL";
	const int CMD_EXPR_NUM=2*1000;
	int srand_keyword=717;
	int config_id=0;
	int* is_all_hit=NULL;
	
	Maat_feather_t feather=MaatCMDPerfTest::_shared_feather;
	config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", CMD_EXPR_NUM);
	config_id-=CMD_EXPR_NUM;
	int i=0;
	char keyword_buf[128];
	struct Maat_command_batch* batch=NULL;
	batch=Maat_command_batch_new(feather);
	srand(srand_keyword);
	for(i=0; i<CMD_EXPR_NUM-1;i++)
	{
		random_keyword_generate(keyword_buf, sizeof(keyword_buf));
		test_add_expr_command_copy(batch, expr_table_name, config_id+i, keyword_buf, 2);
	}
	test_add_expr_command_copy(batch, expr_table_name, config_id+CMD_EXPR_NUM-1, high_match_string, 2);
	Maat_command_batch_commit(batch);
	sleep(4);
	int global_thread_num=4;
	unsigned long long time_elapse_ms=0, scan_count=0, scan_per_second=0;
	pthread_t threads[global_thread_num+1];	
	struct thread_para thread_para[global_thread_num+1];
	for(i=0; i<global_thread_num+1; i++)
	{
		thread_para[i].feather=feather;
		thread_para[i].thread_id=i;
		thread_para[i].table_name=expr_table_name;
		thread_para[i].test_count=10*1000*1000;
		thread_para[i].time_elapse_ms=0;
		if(i<global_thread_num)
		{
			pthread_create(&(threads[i]), NULL, high_match_rate_scan_thread, thread_para+i);
		}
		else
		{
			thread_para[i].test_count=0;
			pthread_create(&(threads[i]), NULL, high_match_rate_update_thread, thread_para+i);
		}
	}

	for(i=0; i<global_thread_num+1; i++)
	{
		pthread_join(threads[i], (void**)&is_all_hit);	
		time_elapse_ms+=thread_para[i].time_elapse_ms;
		scan_count+=thread_para[i].test_count;
		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit=0;
		free(is_all_hit);
	}
	scan_per_second=scan_count*1000/time_elapse_ms;
	EXPECT_GT(scan_per_second, 800*1000);
	printf("High match rate on %d-threads speed %lld lookups/s/thread\n", global_thread_num, scan_per_second);
}

#define IP_PLUGIN_EX_DATA
struct ip_plugin_ud
{
	int rule_id;
	char* buffer;
	int ref_cnt;
};
void ip_plugin_EX_new_cb(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	int *counter=(int *)argp, ret=0;
	size_t column_offset=0, column_len=0;
	struct ip_plugin_ud* ud=(struct ip_plugin_ud*)calloc(sizeof(struct ip_plugin_ud), 1);
	ret=Maat_helper_read_column(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);
	ud->rule_id=atoi(table_line+column_offset);
	ret=Maat_helper_read_column(table_line, 5, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);
	ud->buffer=(char*)calloc(sizeof(char), column_len+1);
	strncpy(ud->buffer, table_line+column_offset, column_len);
	ud->ref_cnt=1;
	*ad=ud;
	(*counter)++;
	return;
}
void ip_plugin_EX_free_cb(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	struct ip_plugin_ud* u=(struct ip_plugin_ud*)(*ad);
	
	if ((__sync_sub_and_fetch(&u->ref_cnt, 1) == 0))
	{
		free(u->buffer);
		free(u);
		*ad=NULL;
	}
}
void ip_plugin_EX_dup_cb(int table_id,	MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void *argp)
{
	struct ip_plugin_ud* u=(struct ip_plugin_ud*)(*from);
	__sync_add_and_fetch(&(u->ref_cnt), 1);
	*to=u;
}

TEST_F(MaatCMDPerfTest, UpdateIPPlugin)
{
#define IP_Plugin_EX_data
	Maat_feather_t feather=MaatCMDPerfTest::_shared_feather;

	int ret=0, i=0;
	int table_id=0, ip_plugin_ex_data_counter=0;
	const char* table_name="TEST_IP_PLUGIN_WITH_EXDATA";


	const int TEST_CMD_LINE_NUM=4;
	const struct Maat_cmd_line *p_line[TEST_CMD_LINE_NUM];
	struct Maat_cmd_line line_rule[TEST_CMD_LINE_NUM];
	const char* table_line[TEST_CMD_LINE_NUM]={
                "101\t4\t192.168.30.99\t192.168.30.101\tSomething-like-json\t1",
				"102\t4\t192.168.30.90\t192.168.30.128\tBigger-range-should-in-the-back\t1",
                "103\t6\t2001:db8:1234::\t2001:db8:1235::\tBigger-range-should-in-the-back\t1",
				"104\t6\t2001:db8:1234::1\t2001:db8:1234::5210\tSomething-like-json\t1"
		};
	table_id=Maat_table_register(feather, table_name);
	ASSERT_GT(table_id, 0);
	memset(&line_rule,0,sizeof(line_rule));
	for(i=0;i<TEST_CMD_LINE_NUM;i++)
	{
		line_rule[i].label_id=0;
		line_rule[i].rule_id=(int)Maat_cmd_incrby(feather,"TEST_PLUG_SEQ", 1);
		line_rule[i].table_name=table_name;
		line_rule[i].table_line=table_line[i];
		line_rule[i].expire_after=0;
		p_line[i]=line_rule+i;
	}
	ret=Maat_cmd_set_lines(feather, p_line,TEST_CMD_LINE_NUM, MAAT_OP_ADD);
	EXPECT_GT(ret, 0);

	sleep(WAIT_FOR_EFFECTIVE_SECOND);

	ret=Maat_ip_plugin_EX_register(feather, table_id,
								ip_plugin_EX_new_cb,
								ip_plugin_EX_free_cb,
								ip_plugin_EX_dup_cb,
								0, &ip_plugin_ex_data_counter);
	ASSERT_TRUE(ret>=0);
	EXPECT_EQ(ip_plugin_ex_data_counter, 4);
	struct ip_address ipv4, ipv6;
	struct ip_plugin_ud* result[4];
	ipv4.ip_type=4;
	inet_pton(AF_INET, "192.168.30.100", &(ipv4.ipv4));	
	memset(&result, 0, sizeof(result));
	ret=Maat_ip_plugin_get_EX_data(feather, table_id, &ipv4, (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_EQ(result[0]->rule_id, 101);
	EXPECT_EQ(result[1]->rule_id, 102);
	for(i=0; i<ret; i++)
	{
		ip_plugin_EX_free_cb(0, (void**)&(result[i]), 0, NULL);
	}
	ipv6.ip_type=6;
	inet_pton(AF_INET6,"2001:db8:1234::5210",&(ipv6.ipv6));
	memset(&result, 0, sizeof(result));
	ret=Maat_ip_plugin_get_EX_data(feather, table_id, &ipv6, (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_EQ(result[0]->rule_id, 104);
	EXPECT_EQ(result[1]->rule_id, 103);
	for(i=0; i<ret; i++)
	{
		ip_plugin_EX_free_cb(0, (void**)&(result[i]), 0, NULL);
	}
	
	return;
}

#define FQDN_PLUGIN_EX_DATA
struct perf_fqdn_plugin_ud
{
	int rule_id;
	int catid;
	int ref_cnt;
};
void perf_fqdn_plugin_EX_new_cb(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	int *counter=(int *)argp, ret=0;
	size_t column_offset=0, column_len=0;
	struct perf_fqdn_plugin_ud* ud=(struct perf_fqdn_plugin_ud*)calloc(sizeof(struct perf_fqdn_plugin_ud), 1);
	ret=Maat_helper_read_column(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);
	ud->rule_id=atoi(table_line+column_offset);
	ret=Maat_helper_read_column(table_line, 4, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);
	sscanf(table_line+column_offset, "catid=%d",&ud->catid);
	ud->ref_cnt=1;
	*ad=ud;
	(*counter)++;
	return;
}
void perf_fqdn_plugin_EX_free_cb(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	struct perf_fqdn_plugin_ud* u=(struct perf_fqdn_plugin_ud*)(*ad);
	if ((__sync_sub_and_fetch(&u->ref_cnt, 1) == 0))
	{
		free(u);
		*ad=NULL;
	}
}
void perf_fqdn_plugin_EX_dup_cb(int table_id,	MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void *argp)
{
	struct perf_fqdn_plugin_ud* u=(struct perf_fqdn_plugin_ud*)(*from);
	__sync_add_and_fetch(&(u->ref_cnt), 1);
	*to=u;
}
void* fqdn_plugin_scan_thread(void *arg)
{

	struct thread_para* para=(struct thread_para*)arg;
	Maat_feather_t feather=para->feather;

	struct perf_fqdn_plugin_ud* result[4];

	int table_id=0, i=0, j=0, ret=0, hit_times=0;
	table_id=Maat_table_register(feather, para->table_name);
	memset(&result, 0, sizeof(result));
	struct timespec start, end;
	
	clock_gettime(CLOCK_MONOTONIC, &start);
	for(i=0; i<para->test_count; i++)
	{
	
		ret=Maat_fqdn_plugin_get_EX_data(feather, table_id, "r3---sn-i3belne6.example2.com", (void**)result, 4);
		if(ret==2)
		{
			hit_times++;
		}
		for(j=0; j<ret; j++)
		{
			perf_fqdn_plugin_EX_free_cb(0, (void**)&(result[j]), 0, NULL);
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	para->time_elapse_ms=(end.tv_sec-start.tv_sec)*1000+(end.tv_nsec-start.tv_nsec)/1000000;
	int* is_all_hit=(int*)malloc(sizeof(int));
	*is_all_hit=(hit_times==para->test_count)?1:0;
	return is_all_hit;
}
void* fqdn_plugin_update_thread(void *arg)
{
	struct thread_para* para=(struct thread_para*)arg;
	Maat_feather_t feather=para->feather;
	const int CMD_EXPR_NUM=20;
	int i=0;
	struct Maat_cmd_line line_rule;
	char line_buff[1024], fqdn_buff[256];
	for(i=0; i<CMD_EXPR_NUM; i++)
	{
		line_rule.label_id=0;
		line_rule.rule_id=(int)Maat_cmd_incrby(feather,"TEST_PLUG_SEQ", 1);
		line_rule.table_name=para->table_name;
		random_fqdn_generate(fqdn_buff, sizeof(fqdn_buff));
		snprintf(line_buff, 1024, "%d\t1\t%s\tcatid=4\t1", line_rule.rule_id, fqdn_buff);
		line_rule.table_line=line_buff;
		line_rule.expire_after=0;
		Maat_cmd_set_line(feather, &line_rule, MAAT_OP_ADD);
		sleep(1);
	}
	int* is_all_hit=(int*)malloc(sizeof(int));
	*is_all_hit=1;
	return is_all_hit;
}

TEST_F(MaatCMDPerfTest, FQDNPluginOnMultiThread)
{
#define FQDN_Plugin_EX_data
	Maat_feather_t feather=MaatCMDPerfTest::_shared_feather;
	int* is_all_hit=NULL;
	int ret=0;
	int i=0, j=0;
	int table_id=0, fqdn_plugin_ex_data_counter=0;
	const char* table_name="TEST_FQDN_PLUGIN_WITH_EXDATA";

#define FIXED_LINE_CNT 5
	int randomed_line_cnt=100*1000;
	int total_line_cnt=FIXED_LINE_CNT+randomed_line_cnt;
	const struct Maat_cmd_line **p_line=(const struct Maat_cmd_line**)calloc(sizeof(struct Maat_cmd_line*), total_line_cnt);
	struct Maat_cmd_line *line_rule=(struct Maat_cmd_line*)calloc(sizeof(struct Maat_cmd_line), total_line_cnt);
	const char* fixed_table_line[FIXED_LINE_CNT]={
				"201\t0\twww.example1.com\tcatid=1\t1",
				"202\t1\t.example1.com\tcatid=1\t1",
				"203\t0\tnews.example1.com\tcatid=2\t1",
				"204\t0\tr3---sn-i3belne6.example2.com\tcatid=3\t1",
				"205\t0\tr3---sn-i3belne6.example2.com\tcatid=3\t1"
		};
	char fqdn_buff[256];
	char** random_lines=(char**)calloc(sizeof(char*), randomed_line_cnt);
	table_id=Maat_table_register(feather, table_name);
	ASSERT_GT(table_id, 0);
	srand(521);
	Maat_cmd_incrby(feather,"TEST_PLUG_SEQ", 1000);//jump over IDs of fixed table line.
	for(i=0, j=0; i<total_line_cnt; i++)
	{
		line_rule[i].label_id=0;
		line_rule[i].rule_id=(int)Maat_cmd_incrby(feather,"TEST_PLUG_SEQ", 1);
		line_rule[i].table_name=table_name;
		if(i<FIXED_LINE_CNT)
		{
			line_rule[i].table_line=fixed_table_line[i];
		}
		else
		{
			random_lines[j]=(char*)calloc(sizeof(char), 1024);
			random_fqdn_generate(fqdn_buff, sizeof(fqdn_buff));
			snprintf(random_lines[j], 1024, "%d\t1\t%s\tcatid=4\t1", line_rule[i].rule_id, fqdn_buff);
			line_rule[i].table_line=random_lines[j];
			j++;
		}
		line_rule[i].expire_after=0;
		p_line[i]=line_rule+i;
	}
	ret=Maat_cmd_set_lines(feather, p_line, total_line_cnt, MAAT_OP_ADD);
	EXPECT_GT(ret, 0);
	free(p_line);
	p_line=NULL;
	free(line_rule);
	line_rule=NULL;
	for(i=0; i<randomed_line_cnt; i++)
	{
		free(random_lines[i]);
		random_lines[i]=NULL;
	}
	free(random_lines);
	random_lines=NULL;
	
	sleep(WAIT_FOR_EFFECTIVE_SECOND);

	ret=Maat_fqdn_plugin_EX_register(feather, table_id,
								perf_fqdn_plugin_EX_new_cb,
								perf_fqdn_plugin_EX_free_cb,
								perf_fqdn_plugin_EX_dup_cb,
								0, &fqdn_plugin_ex_data_counter);

	ASSERT_TRUE(ret>=0);
	EXPECT_EQ(fqdn_plugin_ex_data_counter, total_line_cnt);


	struct perf_fqdn_plugin_ud* result[4];

	ret=Maat_fqdn_plugin_get_EX_data(feather, table_id, "r3---sn-i3belne6.example2.com", (void**)result, 4);
	EXPECT_EQ(ret, 2);
	for(i=0; (int)i<ret; i++)
	{
		perf_fqdn_plugin_EX_free_cb(0, (void**)&(result[i]), 0, NULL);
	}
	int global_thread_num=4;
	unsigned long long time_elapse_ms=0, scan_count=0, scan_per_second_per_thread=0;
	pthread_t threads[global_thread_num+1]; 
	struct thread_para thread_para[global_thread_num+1];
	for(i=0; i<global_thread_num+1; i++)
	{
		thread_para[i].feather=feather;
		thread_para[i].thread_id=i;
		thread_para[i].table_name=table_name;
		thread_para[i].test_count=20*1000*1000;
		thread_para[i].time_elapse_ms=0;
		if(i<global_thread_num)
		{
			pthread_create(&(threads[i]), NULL, fqdn_plugin_scan_thread, thread_para+i);
		}
		else
		{
			thread_para[i].test_count=0;
			pthread_create(&(threads[i]), NULL, fqdn_plugin_update_thread, thread_para+i);
		}
	}

	for(i=0; i<global_thread_num+1; i++)
	{
		pthread_join(threads[i], (void**)&is_all_hit);	
		time_elapse_ms+=thread_para[i].time_elapse_ms;
		scan_count+=thread_para[i].test_count;
		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit=0;
		free(is_all_hit);
	}
	scan_per_second_per_thread=scan_count*1000/time_elapse_ms;
	EXPECT_GT(scan_per_second_per_thread, 800*1000);
	printf("FQDN Plugin on %d-threads speed %lld lookups/s/thread.\n", global_thread_num, scan_per_second_per_thread);	

	return;
}
class MaatFilePerfTest : public testing::Test 
{

protected:
	static void SetUpTestCase()
	{
	
		int scan_interval_ms=500;
		int effective_interval_ms=0;
		const char* rule_folder="./tsgrule/full/index";
	  	logger=MESA_create_runtime_log_handle("file_perf_test.log",0);
		const char* table_info="./tsg_tableinfo.conf";
		_shared_feather_f=Maat_feather(global_thread_num, table_info, logger);
		Maat_set_feather_opt(_shared_feather_f, MAAT_OPT_INSTANCE_NAME, "files", strlen("files")+1);
		Maat_set_feather_opt(_shared_feather_f, MAAT_OPT_FULL_CFG_DIR, rule_folder, strlen(rule_folder)+1);
		Maat_set_feather_opt(_shared_feather_f, MAAT_OPT_INC_CFG_DIR, rule_folder, strlen(rule_folder)+1);


		Maat_set_feather_opt(_shared_feather_f, MAAT_OPT_SCANDIR_INTERVAL_MS, &scan_interval_ms, sizeof(scan_interval_ms));
		//Set a short intevral for testing.
		Maat_set_feather_opt(_shared_feather_f, MAAT_OPT_EFFECT_INVERVAL_MS, &effective_interval_ms, sizeof(effective_interval_ms));

		Maat_initiate_feather(_shared_feather_f);

	}
	static void TearDownTestCase()
	{
		Maat_burn_feather(_shared_feather_f);
		MESA_destroy_runtime_log_handle(logger);

	}	
 	// Some expensive resource shared by all tests.
	static Maat_feather_t _shared_feather_f;
	static void *logger;
};
Maat_feather_t MaatFilePerfTest::_shared_feather_f;
void* MaatFilePerfTest::logger;

struct perf_ip_plugin_ud
{
	int rule_id;
	int ref_cnt;
};

void perf_ip_plugin_EX_new_cb(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	int *counter=(int *)argp, ret=0;
	size_t column_offset=0, column_len=0;
	struct perf_ip_plugin_ud* ud=(struct perf_ip_plugin_ud*)calloc(sizeof(struct perf_ip_plugin_ud), 1);
	ret=Maat_helper_read_column(table_line, 1, &column_offset, &column_len);
	EXPECT_EQ(ret, 0);
	ud->rule_id=atoi(table_line+column_offset);
	ret=Maat_helper_read_column(table_line, 5, &column_offset, &column_len);	
	EXPECT_EQ(ret, 0);
	ud->ref_cnt=1;
	*ad=ud;
	(*counter)++;
	return;
}
void perf_ip_plugin_EX_free_cb(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	struct perf_ip_plugin_ud* u=(struct perf_ip_plugin_ud*)(*ad);
	if ((__sync_sub_and_fetch(&u->ref_cnt, 1) == 0))
	{
		free(u);
		*ad=NULL;
	}
}
void perf_ip_plugin_EX_dup_cb(int table_id,	MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void *argp)
{
	struct perf_ip_plugin_ud* u=(struct perf_ip_plugin_ud*)(*from);
	__sync_add_and_fetch(&(u->ref_cnt), 1);
	*to=u;
}
static void* ip_plugin_get_thread(void* arg)
{
	const char* table_name="TSG_IP_LOCATION_BUILT_IN";
	int test_times=1000*1000, hit_times=0;
	int table_id=0;
	int ret=0, i=0, j=0;
	Maat_feather_t feather=(Maat_feather_t)arg;

	table_id=Maat_table_register(feather, table_name);

	struct perf_ip_plugin_ud* result[4];
	struct ip_address ip;
	ip.ip_type=4;
	inet_pton(AF_INET, "191.70.72.1", &(ip.ipv4));	

	for(i=0; i<test_times; i++)
	{
		ret=Maat_ip_plugin_get_EX_data(feather, table_id, &ip, (void**)result, 4);
		if(ret>0)
		{
			hit_times++;
		}
		for(j=0; j<ret; j++)
		{
			perf_ip_plugin_EX_free_cb(table_id, (void**)&(result[j]), 0, NULL);
		}
	}
	int* is_all_hit=(int*)malloc(sizeof(int));
	*is_all_hit=(hit_times==test_times)?1:0;
	return is_all_hit;
}
TEST_F(MaatFilePerfTest, IPPlugin)
{
	Maat_feather_t feather=MaatFilePerfTest::_shared_feather_f;
	int ret=0, i=0;
	int* is_all_hit=NULL;
	int table_id=0, ip_plugin_ex_data_counter=0;
	const char* table_name="TSG_IP_LOCATION_BUILT_IN";


	table_id=Maat_table_register(feather, table_name);
	ASSERT_GT(table_id, 0);


	ret=Maat_ip_plugin_EX_register(feather, table_id,
								perf_ip_plugin_EX_new_cb,
								perf_ip_plugin_EX_free_cb,
								perf_ip_plugin_EX_dup_cb,
								0, &ip_plugin_ex_data_counter);

	ASSERT_TRUE(ret>=0);

	pthread_t threads[global_thread_num];
	for(i=0; i<global_thread_num; i++)
	{
		pthread_create(&(threads[i]), NULL, ip_plugin_get_thread, feather);
	}

	for(i=0; i<global_thread_num; i++)
	{
		pthread_join(threads[i], (void**)&is_all_hit);
		EXPECT_EQ(*is_all_hit, 1);
		*is_all_hit=0;
		free(is_all_hit);
	}

	return;
}


int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);

	ret=RUN_ALL_TESTS();
	return ret;
}


