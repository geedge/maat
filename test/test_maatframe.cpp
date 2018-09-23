#include "Maat_rule.h"
#include "stream_fuzzy_hash.h"
#include "Maat_command.h"
#include <MESA/MESA_handle_logger.h>
#include <dlfcn.h>
#include <assert.h>
#include <sys/socket.h>//inet_addr
#include <netinet/in.h>//inet_addr
#include <arpa/inet.h>//inet_addr
#include <net/if.h>
#include <sys/types.h>//fstat
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <MESA/stream.h>
#include <sys/types.h>//fstat
#include <sys/stat.h>//fstat
#include <unistd.h>
#include <dirent.h>

#include <gtest/gtest.h>
const char* test_maat_redis_ip="127.0.0.1";
unsigned short test_maat_redis_port=6379;
const char* json_path="./maat_json.json";
const char* ful_cfg_dir="./rule/full/index/";
const char* inc_cfg_dir="./rule/inc/index/";
#define	WAIT_FOR_EFFECTIVE_US	1000*1000
extern int my_scandir(const char *dir, struct dirent ***namelist,
              int(*filter)(const struct dirent *),
              int(*compar)(const void *, const void *));


Maat_feather_t feather=NULL;
void *logger=NULL;

void Maat_read_entry_start_cb(int update_type,void* u_para)
{
	return;
}
void Maat_read_entry_cb(int table_id,const char* table_line,void* u_para)
{
	char ip_str[16]={0};
	int entry_id=-1,seq=-1;
	unsigned int ip_uint=0;
	int is_valid=0;
	unsigned int local_ip_nr=16820416;//192.168.0.1
	sscanf(table_line,"%d\t%s\t%d\t%d",&seq,ip_str,&entry_id,&is_valid);
	inet_pton(AF_INET,ip_str,&ip_uint);
	if(local_ip_nr==ip_uint)
	{
		if(is_valid==1)
		{
			//printf("Load entry id %d success.\n",entry_id);
			EXPECT_EQ(entry_id, 101);
		}
		else
		{
			//printf("Offload entry id %d success.\n",entry_id);
		}
	}
	return;
}
void Maat_read_entry_finish_cb(void* u_para)
{
	Maat_feather_t feather=u_para;
	long long version=0;
	int ret=0,is_last_updating_table=0;
	ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version, sizeof(version));
	EXPECT_EQ(ret, 0);
	ret=Maat_read_state(feather,MAAT_STATE_LAST_UPDATING_TABLE, &is_last_updating_table, sizeof(is_last_updating_table));
	EXPECT_EQ(ret, 0);
	//printf("Maat Version %lld at plugin finish callback, is_last_update=%d.\n",version,is_last_updating_table);

	return;
}
void test_plugin_table(Maat_feather_t feather,const char* table_name,
							Maat_start_callback_t *start,Maat_update_callback_t *update,Maat_finish_callback_t *finish,
							void *u_para,
							void* logger)
{
	int table_id=0,ret=0;
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);

	ret=Maat_table_callback_register(feather, table_id,
							start,
							update, 
							finish,
							u_para);
	
	ASSERT_GT(ret, 0);

}

TEST(PluginTable, Callback)
{
	test_plugin_table(feather, "QD_ENTRY_INFO",	
								Maat_read_entry_start_cb,
								Maat_read_entry_cb, 
								Maat_read_entry_finish_cb,
								feather,
								logger);

}
TEST(StringScan, Full)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* table_name="HTTP_URL";
	scan_status_t mid=NULL;
	const char* scan_data="http://www.cyberessays.com/search_results.php?action=search&query=yulingjing,abckkk,1234567";
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result,found_pos, 4, &mid, 0);
						
	EXPECT_GE(ret, 1);
	Maat_clean_status(&mid);
}

TEST(IPScan, IPv4)
{
	int table_id=0,ret=0;
	const char* table_name="IP_CONFIG";
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr.addrtype=ADDR_TYPE_IPV4;
	inet_pton(AF_INET,"10.0.6.205",&(v4_addr.saddr));
	v4_addr.source=htons(50001);
	inet_pton(AF_INET,"10.0.6.201",&(v4_addr.daddr));
	v4_addr.dest=htons(80);
	ipv4_addr.v4=&v4_addr;

	const char* scan_data="http://www.cyberessays.com/search_results.php?action=search&query=yulingjing,abckkk,1234567";
	table_id=Maat_table_register(feather,"HTTP_URL");
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result,NULL, 4, &mid, 0);
	EXPECT_GE(ret, 1);
	
	table_id=Maat_table_register(feather,table_name);
	
	EXPECT_GT(table_id, 0);

	ret=Maat_scan_proto_addr(feather,table_id,&ipv4_addr,6,result,4, &mid,0);
	
	EXPECT_GT(ret, 0);
	Maat_clean_status(&mid);
	return;
}
TEST(IPScan, IPv6)

{
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	struct ipaddr ipv6_addr;
	struct stream_tuple4_v6 v6_addr;
	scan_status_t mid=NULL;
	
	ipv6_addr.addrtype=ADDR_TYPE_IPV6;
	inet_pton(AF_INET6,"2001:da8:205:1::101",&(v6_addr.saddr));
	v6_addr.source=htons(50001);
	inet_pton(AF_INET6,"2001:da8:205:1::102",&(v6_addr.daddr));
	v6_addr.dest=htons(80);
	ipv6_addr.v6=&v6_addr;
	const char* table_name="IP_CONFIG";
	table_id=Maat_table_register(feather,table_name);
	EXPECT_GT(table_id, 0);

	//for improving performance.
	Maat_set_scan_status(feather, &mid, MAAT_SET_SCAN_LAST_REGION,NULL, 0);
	ret=Maat_scan_proto_addr(feather,table_id,&ipv6_addr,6,result,4, &mid,0);
	EXPECT_EQ(ret, -2);
	Maat_clean_status(&mid);
	return;
}

TEST(IntervalScan, Pure)
{
	int table_id=0,ret=0;
	int scan_val=2015;
	struct Maat_rule_t result[4];
	const char* table_name="CONTENT_SIZE";
	scan_status_t mid=NULL;
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);

	ret=Maat_scan_intval(feather, table_id, scan_val, result,4, &mid, 0);
	EXPECT_EQ(ret, -2);
	Maat_clean_status(&mid);
	return;
}
TEST(DigestScan, Pure)
{
	int table_id=0,ret=0,hit_cnt=0;
	struct stat digest_fstat;
	unsigned long long read_size=0,scan_offset=0;
	char digest_test_buff[4096]={0};
	const char* file_name="./testdata/digest_test.data";
	const char* table_name="FILE_DIGEST";
	struct Maat_rule_t result[4];
	stream_para_t sp=NULL;
	scan_status_t mid=NULL;
	table_id=Maat_table_register(feather, table_name);
	ASSERT_GT(table_id, 0);

	ret=stat(file_name,&digest_fstat);
	ASSERT_EQ(ret, 0);

	FILE* fp=fopen(file_name,"r");
	ASSERT_FALSE(fp==NULL);
	
	sp=Maat_stream_scan_digest_start(feather, table_id, digest_fstat.st_size, 0);
	while(0==feof(fp))
	{
		read_size=fread(digest_test_buff,1,sizeof(digest_test_buff),fp);
		ret=Maat_stream_scan_digest(&sp, digest_test_buff, read_size, scan_offset, result,4, &mid);
		scan_offset+=read_size;
		if(ret>0)
		{
				hit_cnt++;

		}
	}
	fclose(fp);
	Maat_stream_scan_string_end(&sp);
	EXPECT_GE(hit_cnt, 1);
	Maat_clean_status(&mid);
	return;
}
TEST(StringScan, EncodedURL)
{
	const char* url_utf8="www.google.com/?q=C%23%E4%B8%AD%E5%9B%BD";
	const char* url_gb2312="www.baidu.com/?wd=C%23%D6%D0%B9%FA";
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	
	const char* table_name="HTTP_URL";	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, url_utf8, strlen(url_utf8), 
						result,found_pos, 4,
						&mid, 0);
	EXPECT_GE(ret, 1);
	Maat_clean_status(&mid);
	
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, url_gb2312, strlen(url_gb2312), 
						result,found_pos, 4,
						&mid, 0);
	EXPECT_GE(ret, 1);
	Maat_clean_status(&mid);
	return;
}
TEST(StringScan, UnicodeEscape)
{
	const char* test_data_dir="./testdata_uni2ascii";
	struct dirent **namelist;
	FILE* fp=NULL;
	char file_path[256]={0};
	char buff[4096];
	size_t read_len=0;
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	stream_para_t sp=NULL;
	int n=0,i=0, hit_cnt=0;
	const char* table_name="KEYWORDS_TABLE";	
	scan_status_t mid=NULL;
	
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);

	n = my_scandir(test_data_dir, &namelist, NULL, (int (*)(const void*, const void*))alphasort);
	ASSERT_GT(n, 0);

	for(i=0;i<n;i++)
	{
		if((strcmp(namelist[i]->d_name, ".") == 0) || (strcmp(namelist[i]->d_name, "..") == 0))
		{
			continue;
		}
		snprintf(file_path,sizeof(file_path),"%s/%s",test_data_dir,namelist[i]->d_name);
		fp=fopen(file_path,"rb");
		
		if(fp==NULL)
		{
			printf("fopen %s error.\n",file_path);;
			continue;
		}
		sp=Maat_stream_scan_string_start(feather,table_id,0);
		ASSERT_FALSE(sp==NULL);

		read_len=fread(buff,1,sizeof(buff),fp);
		while(read_len>0)
		{

			ret=Maat_stream_scan_string(&sp,CHARSET_NONE,buff,read_len
								,result, NULL, 4, &mid);
			read_len=fread(buff,1,sizeof(buff),fp);
			if(ret>0)
			{
				hit_cnt++;
			}
		}
		Maat_stream_scan_string_end(&sp);
		fclose(fp);
		EXPECT_GT(hit_cnt, 0);
		EXPECT_GE(result[0].config_id, 130);//130, 131
		Maat_clean_status(&mid);
	}
	for(i=0;i<n;i++)
	{
		free(namelist[i]);
	}
	free(namelist);
	return;
}
TEST(StringScan, MaatUnescape)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	const char* scan_data="Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char* table_name="KEYWORDS_TABLE";	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 132);
	Maat_clean_status(&mid);

	return;
}
TEST(StringScan, StreamInput)
{
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	const char* scan_data="http://www.cyberessays.com/search_results.php?action=search&query=yulingjing,abckkk,1234567";
	const char* table_name="HTTP_URL";	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);

	struct Maat_hit_detail_t *hit_detail=(struct Maat_hit_detail_t *)malloc(sizeof(struct Maat_hit_detail_t)*10);
	stream_para_t sp=Maat_stream_scan_string_start(feather,table_id,0);
	ASSERT_FALSE(sp==NULL);
	int detail_ret=0;

	ret=Maat_stream_scan_string_detail(&sp,CHARSET_NONE,"www.cyberessays.com", strlen("www.cyberessays.com")
						,result,4,hit_detail,10
						,&detail_ret, &mid);
	EXPECT_EQ(ret, 0);
	ret=Maat_stream_scan_string_detail(&sp,CHARSET_NONE,scan_data, strlen(scan_data)
						,result,4,hit_detail,10
						,&detail_ret, &mid);
	Maat_stream_scan_string_end(&sp);
	free(hit_detail);	
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 125);
	Maat_clean_status(&mid);
	return;
}
TEST(SimilarScan, Pure)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	const char* scan_data="mwss.xiu.youku.com/live/hls/v1/0000000000000000000000001526a0a8/714.ts?&token=98765";
	const char* table_name="SIM_URL";	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);

	
	ret=Maat_similar_scan_string(feather, table_id, scan_data, strlen(scan_data), 
						result, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 135);
	Maat_clean_status(&mid);
	return;
}
TEST(TableInfo, Conjunction)
{
	int ret=0;
	int table_id=0,conj_table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* scan_data="soq is using table conjunction function.http://www.3300av.com/novel/27122.txt";
	const char* table_name="HTTP_URL", *conj_table_name="HTTP_HOST";
	scan_status_t mid=NULL;
	
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);

	conj_table_id=Maat_table_register(feather,conj_table_name);	
	ASSERT_EQ(conj_table_id, table_id);

	ret=Maat_full_scan_string(feather, conj_table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result,found_pos, 4,
						&mid, 0);
	EXPECT_EQ(ret, 2);
	EXPECT_EQ(result[0].config_id, 134);
	EXPECT_EQ(result[1].config_id, 133);
	
	Maat_clean_status(&mid);
	return;
}
void test_offset_str_scan_with_chunk(int chunk_size)
{
	int table_id=0,ret=0;
	int read_size=0,pass_flag=0;
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	//const char* fn="./testdata/mesa_logo.jpg";
	const char* table_name="IMAGE_FP";
	const char* fn="./testdata/mesa_logo.jpg";
	FILE* fp=fopen(fn,"r");
	ASSERT_FALSE(fp==NULL);

	char scan_data[chunk_size];
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);
	

	struct Maat_hit_detail_t *hit_detail=(struct Maat_hit_detail_t *)malloc(sizeof(struct Maat_hit_detail_t)*10);
	stream_para_t sp=Maat_stream_scan_string_start(feather,table_id,0);
	int detail_ret=0;
	
	ASSERT_FALSE(sp==NULL);

	while(0==feof(fp))
	{
		read_size=fread(scan_data,1,sizeof(scan_data),fp);
		ret=Maat_stream_scan_string_detail(&sp,CHARSET_NONE,scan_data,read_size
							,result,4,hit_detail,10
							,&detail_ret,&mid);
		if(ret>0)
		{
			pass_flag=1;
			break;
		}
	}
	EXPECT_EQ(pass_flag, 1);
	EXPECT_EQ(result[0].config_id, 136);
	
	Maat_stream_scan_string_end(&sp);
	free(hit_detail);
	fclose(fp);
	Maat_clean_status(&mid);
	return;
}

TEST(StringScan, OffsetChunk64)
{
	test_offset_str_scan_with_chunk(64);
	return;
}
TEST(StringScan, OffsetChunk1460)
{

	test_offset_str_scan_with_chunk(1460);
	return;
}
void accept_tags_entry_cb(int table_id,const char* table_line,void* u_para)
{
	char status[32]={0};
	int entry_id=-1,seq=-1;
	int is_valid=0;
	sscanf(table_line,"%d\t%s\t%d\t%d",&seq,status,&entry_id,&is_valid);
	EXPECT_STREQ(status ,"SUCCESS");

	return;
}


TEST(RuleTags, Plugin)
{
	int table_id=0,ret=0;
	const char* table_name="TEST_EFFECTIVE_RANGE_TABLE";
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);

	ret=Maat_table_callback_register(feather, table_id,
							NULL,
							accept_tags_entry_cb, 
							NULL,
							NULL);
	
	ASSERT_GE(ret, 0);
	return;
}

TEST(RuleTags, Compile)
{
	int ret=0;
	int table_id=0;
	scan_status_t mid=NULL;
	struct Maat_rule_t result[4];
	const char* should_hit="string bbb should hit";
	const char* should_not_hit="string aaa should not hit";
	const char* table_name="HTTP_URL";
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);

	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, should_not_hit, strlen(should_not_hit), 
						result,NULL, 4,
						&mid, 0);
	
	EXPECT_LE(ret, 0);
	
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, should_hit, strlen(should_hit), 
						result,NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	Maat_clean_status(&mid);
	return;
}


TEST(StreamFuzzyHash, Pure)
{
	const size_t FILE_CHUNK_SIZE=4096;
	char * file_buff=NULL,*sfh_ordered=NULL,*sfh_unorder=NULL;
	int read_size=0,ret=0,chunk_num=0,i=0,idx=0;
	unsigned long long *offset=NULL;
	unsigned long long file_size=0,tmp=0,hash_length=0;
	const char* filename="./testdata/digest_test.data";

	FILE* fp=fopen(filename,"r");
	sfh_instance_t * fhandle = NULL;
	struct stat file_info;
	ret=stat(filename, &file_info);
	ASSERT_TRUE(ret==0);

	file_size=file_info.st_size;
	file_buff=(char*)malloc(file_size);
	ret=fread(file_buff,1,file_size,fp);
	ASSERT_TRUE((unsigned long long)ret==file_size);

	chunk_num=file_size/FILE_CHUNK_SIZE;
	if(file_size%FILE_CHUNK_SIZE==0)
	{
		chunk_num=file_size/FILE_CHUNK_SIZE;
	}
	else
	{
		chunk_num=file_size/FILE_CHUNK_SIZE+1;
	}
	offset=(unsigned long long*)malloc(sizeof(unsigned long long)*chunk_num);
	for(i=0;i<chunk_num;i++)
	{
		offset[i]=FILE_CHUNK_SIZE*i;
	}
	fhandle=SFH_instance(0);
	SFH_feed(fhandle,file_buff,file_size,0);
	hash_length = SFH_status(fhandle, HASH_LENGTH);
	sfh_ordered=(char*)malloc(hash_length);
	SFH_digest(fhandle, sfh_ordered, hash_length);
	SFH_release(fhandle);
	fhandle=NULL;
	
	//shuffle file offsets
	srand(5210);
	for(i=0;i<chunk_num;i++)
	{
		idx=rand()%chunk_num;
		tmp=offset[i];
		offset[i]=offset[idx];
		offset[idx]=tmp;		
	}
	fhandle=SFH_instance(0);
	for(i=0;i<chunk_num;i++)
	{
		if(offset[i]+FILE_CHUNK_SIZE>file_size)
		{
			read_size=file_size-offset[i];
		}
		else
		{
			read_size=FILE_CHUNK_SIZE;
		}
		SFH_feed(fhandle,file_buff+offset[i],read_size,offset[i]);
	}
	hash_length = SFH_status(fhandle, HASH_LENGTH);
	sfh_unorder=(char*)malloc(hash_length);
	SFH_digest(fhandle, sfh_unorder, hash_length);
	//printf("%s %u %lf %s\n",path,digest_fstat.st_size,file_entropy,digest_result_buff);
	SFH_release(fhandle);
	EXPECT_STREQ(sfh_ordered, sfh_unorder);

error_out:
	fclose(fp);
	free(file_buff);
	free(sfh_ordered);
	free(sfh_unorder);
	free(offset);
	return;
}
TEST(ScanResult, LongerServiceDefine)
{
	int ret=0;
	int table_id=0;	
	scan_status_t mid=NULL;
	
	struct Maat_rule_t result[4];
	const char* scan_data="soq is using table conjunction function.http://www.3300av.com/novel/27122.txt";
	const char* table_name="HTTP_URL";
	
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);

	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 2);
	EXPECT_EQ(result[1].config_id, 133);
	EXPECT_GT(result[1].serv_def_len, 128);
	
	char* buff=(char*)malloc(sizeof(char)*result[1].serv_def_len);
	ret=Maat_read_rule(feather, result+1, MAAT_RULE_SERV_DEFINE, buff, result[1].serv_def_len);	
	EXPECT_EQ(ret, result[1].serv_def_len);
	Maat_clean_status(&mid);
	free(buff);
	return;
}

void maat_test_print_usage(void)
{
	printf("Maat Test Usage:\n");
	printf("\tSource:\n");
	printf("\t\t-j Test updating from %s. https://www.sojson.com/yasuo.html\n",json_path);
	printf("\t\t-u Load config from %s, and monitor %s. Need manually move inc index.\n",ful_cfg_dir,inc_cfg_dir);
	printf("\t\t-r Read config redis %s:%u db0.\n",test_maat_redis_ip,test_maat_redis_port);
	printf("\tOption:\n");
	printf("\t\t-d Deferred Loading config.\n");
	printf("example: ./maat_test -j -d\n");
	
	return;
}

int main(int argc, char ** argv)
{
	int g_iThreadNum=4;
	const char*	table_info_path="./table_info.conf";

	const char* log_file="./test.log";
	const char* stat_file="./scan_staus.log";
	const char* decrypt_key="mesa2017wy";
	const char* accept_tags="{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"}]}";
	int scan_interval_ms=1;
	int effective_interval_ms=0;

	int scan_detail=0,deferred_load_on=0;
	int using_redis=0;
	int rest_second=400;

	if(argc<2||argv[1][0]!='-')
	{
		maat_test_print_usage();
		return 0;
	}
	::testing::InitGoogleTest(&argc, argv);
	logger=MESA_create_runtime_log_handle(log_file,0);

	feather=Maat_feather(g_iThreadNum, table_info_path, logger);
	Maat_set_feather_opt(feather,MAAT_OPT_INSTANCE_NAME,"demo", strlen("demo")+1);
	Maat_set_feather_opt(feather,MAAT_OPT_DECRYPT_KEY,decrypt_key, strlen(decrypt_key)+1);
	int oc=0;
	while((oc=getopt(argc,argv,"ujrd"))!=-1)
	{
		switch(oc)
		{
			case 'u'://update
				Maat_set_feather_opt(feather, MAAT_OPT_FULL_CFG_DIR, ful_cfg_dir, strlen(ful_cfg_dir)+1);
				Maat_set_feather_opt(feather, MAAT_OPT_INC_CFG_DIR, inc_cfg_dir, strlen(inc_cfg_dir)+1);
				rest_second=14;
				break;
			case 'r'://redis
				Maat_set_feather_opt(feather, MAAT_OPT_REDIS_IP, test_maat_redis_ip, strlen(test_maat_redis_ip)+1);
				Maat_set_feather_opt(feather, MAAT_OPT_REDIS_PORT, &test_maat_redis_port, sizeof(test_maat_redis_port));
				using_redis=1;
				break;
			case 'd'://deferred
				Maat_set_feather_opt(feather, MAAT_OPT_DEFERRED_LOAD, NULL,0);
				deferred_load_on=1;
				break;
			case 'j'://json
				Maat_set_feather_opt(feather, MAAT_OPT_JSON_FILE_PATH, json_path, strlen(json_path)+1);
				break;
			case '?':
			default:
				maat_test_print_usage();
				return 0;
				break;
		}
	}

	Maat_set_feather_opt(feather, MAAT_OPT_SCANDIR_INTERVAL_MS,&scan_interval_ms, sizeof(scan_interval_ms));
	//Set a short intevral for testing.
	Maat_set_feather_opt(feather, MAAT_OPT_EFFECT_INVERVAL_MS,&effective_interval_ms, sizeof(effective_interval_ms));

	Maat_set_feather_opt(feather, MAAT_OPT_STAT_FILE_PATH, stat_file, strlen(stat_file)+1);
	Maat_set_feather_opt(feather, MAAT_OPT_STAT_ON, NULL, 0);
	Maat_set_feather_opt(feather, MAAT_OPT_PERF_ON, NULL, 0);
	Maat_set_feather_opt(feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
	Maat_set_feather_opt(feather, MAAT_OPT_ACCEPT_TAGS, accept_tags, strlen(accept_tags)+1);
	Maat_initiate_feather(feather);
	printf("Maat initiating, see %s\n",log_file);


	if(deferred_load_on==1)
	{
		printf("Deferred Load ON, Waiting...\n");
		usleep(WAIT_FOR_EFFECTIVE_US);
	}
	return RUN_ALL_TESTS();
}

