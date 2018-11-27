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
#include <openssl/md5.h>
#include <pthread.h>

#include <gtest/gtest.h>
const char* test_maat_redis_ip="127.0.0.1";
unsigned short test_maat_redis_port=6379;
const char* json_path="./maat_json.json";
const char* ful_cfg_dir="./rule/full/index/";
const char* inc_cfg_dir="./rule/inc/index/";
#define	WAIT_FOR_EFFECTIVE_US	1*1000*1000
extern int my_scandir(const char *dir, struct dirent ***namelist,
              int(*filter)(const struct dirent *),
              int(*compar)(const void *, const void *));


Maat_feather_t g_feather=NULL;
void *g_logger=NULL;
int g_iThreadNum=4;
const char* table_info_path="./table_info.conf";
int scan_interval_ms=1;
int effective_interval_ms=0;

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
	test_plugin_table(g_feather, "QD_ENTRY_INFO",	
								Maat_read_entry_start_cb,
								Maat_read_entry_cb, 
								Maat_read_entry_finish_cb,
								g_feather,
								g_logger);

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
	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
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
	table_id=Maat_table_register(g_feather,"HTTP_URL");
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result,NULL, 4, &mid, 0);
	EXPECT_GE(ret, 1);
	
	table_id=Maat_table_register(g_feather,table_name);
	
	EXPECT_GT(table_id, 0);

	ret=Maat_scan_proto_addr(g_feather,table_id,&ipv4_addr,6,result,4, &mid,0);
	
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
	table_id=Maat_table_register(g_feather,table_name);
	EXPECT_GT(table_id, 0);

	//for improving performance.
	Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_LAST_REGION,NULL, 0);
	ret=Maat_scan_proto_addr(g_feather,table_id,&ipv6_addr,6,result,4, &mid,0);
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
	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);

	ret=Maat_scan_intval(g_feather, table_id, scan_val, result,4, &mid, 0);
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
	table_id=Maat_table_register(g_feather, table_name);
	ASSERT_GT(table_id, 0);

	ret=stat(file_name,&digest_fstat);
	ASSERT_EQ(ret, 0);

	FILE* fp=fopen(file_name,"r");
	ASSERT_FALSE(fp==NULL);
	
	sp=Maat_stream_scan_digest_start(g_feather, table_id, digest_fstat.st_size, 0);
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

	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, url_utf8, strlen(url_utf8), 
						result,found_pos, 4,
						&mid, 0);
	EXPECT_GE(ret, 1);
	Maat_clean_status(&mid);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, url_gb2312, strlen(url_gb2312), 
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
	
	table_id=Maat_table_register(g_feather,table_name);
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
		sp=Maat_stream_scan_string_start(g_feather,table_id,0);
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

	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
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

	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);

	struct Maat_hit_detail_t *hit_detail=(struct Maat_hit_detail_t *)malloc(sizeof(struct Maat_hit_detail_t)*10);
	stream_para_t sp=Maat_stream_scan_string_start(g_feather,table_id,0);
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

	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);

	
	ret=Maat_similar_scan_string(g_feather, table_id, scan_data, strlen(scan_data), 
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
	
	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);

	conj_table_id=Maat_table_register(g_feather,conj_table_name);	
	ASSERT_EQ(conj_table_id, table_id);

	ret=Maat_full_scan_string(g_feather, conj_table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
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
	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	

	struct Maat_hit_detail_t *hit_detail=(struct Maat_hit_detail_t *)malloc(sizeof(struct Maat_hit_detail_t)*10);
	stream_para_t sp=Maat_stream_scan_string_start(g_feather,table_id,0);
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
#define RuleTags_Plugin
	int table_id=0,ret=0;
	const char* table_name="TEST_EFFECTIVE_RANGE_TABLE";
	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);

	ret=Maat_table_callback_register(g_feather, table_id,
							NULL,
							accept_tags_entry_cb, 
							NULL,
							NULL);
	
	ASSERT_GE(ret, 0);
	return;
}

TEST(RuleTags, Compile)
{
#define RuleTags_Compile
	int ret=0;
	int table_id=0;
	scan_status_t mid=NULL;
	struct Maat_rule_t result[4];
	const char* should_hit="string bbb should hit";
	const char* should_not_hit="string aaa should not hit";
	const char* table_name="HTTP_URL";
	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);

	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, should_not_hit, strlen(should_not_hit), 
						result,NULL, 4,
						&mid, 0);
	
	EXPECT_EQ(ret, -2);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, should_hit, strlen(should_hit), 
						result,NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	Maat_clean_status(&mid);
	return;
}

struct rule_ex_param
{
	int ref_cnt;
	char name[128];
	int id;
	pthread_mutex_t lock;
};

void ex_param_new(int idx, const struct Maat_rule_t* rule, const char* srv_def_large, 
												MAAT_RULE_EX_DATA* ad, long argl, void *argp)
{
	int *counter=(int*)argp;
	*ad=NULL;
	ASSERT_GT(rule->serv_def_len, 4);

	struct rule_ex_param* param=(struct rule_ex_param*)calloc(sizeof(struct rule_ex_param), 1);
	
	param->ref_cnt=1;
	pthread_mutex_init(&(param->lock), NULL);
	
	sscanf(srv_def_large,"%*[^:]:%[^,],%d",param->name,&(param->id));
	(*counter)++;
	*ad=param;
	return;
}
void ex_param_free(int idx, const struct Maat_rule_t* rule, const char* srv_def_large, MAAT_RULE_EX_DATA* ad, long argl, void *argp)
{
	if(*ad==NULL)
	{
		return;
	}
	struct rule_ex_param* param=(struct rule_ex_param*)*ad;
	pthread_mutex_lock(&(param->lock));
	param->ref_cnt--;
	if(param->ref_cnt>0)
	{	
		pthread_mutex_unlock(&(param->lock));
		return;
	}
	free(param);
	return;
}
void ex_param_dup(int idx,	MAAT_RULE_EX_DATA *to, MAAT_RULE_EX_DATA *from, long argl, void *argp)
{
	struct rule_ex_param* from_param=*((struct rule_ex_param**)from);
	pthread_mutex_lock(&(from_param->lock));
	from_param->ref_cnt++;
	pthread_mutex_unlock(&(from_param->lock));
	*((struct rule_ex_param**)to)=from_param;
	return;
}



TEST(EX_DATA_INDEX, all)
{
#define EX_data_index

	int ret=0;
	int table_id=0, ex_data_counter=0;
	scan_status_t mid=NULL;
	struct Maat_rule_t result[4];
	const char* url="i.ytimg.com/vi/OtCNcustg_I/hqdefault.jpg?sqp=-oaymwEZCNACELwBSFXyq4qpAwsIARUAAIhCGAFwAQ==&rs=AOn4CLDOp_5fHMaCA9XZuJdCRv4DNDorMg";
	const char* table_name="HTTP_URL";
	const char* expect_name="I have a name";
	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	
	int ex_param_idx=Maat_rule_get_ex_new_index(g_feather, "COMPILE_ALIAS", 
													ex_param_new, ex_param_free, ex_param_dup,
													0, &ex_data_counter);
	ASSERT_TRUE(ex_param_idx>=0);
	EXPECT_EQ(ex_data_counter, 1);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, url, strlen(url), 
						result,NULL, 4,
						&mid, 0);
	
	EXPECT_EQ(ret, 1);
	void *ex_data=Maat_rule_get_ex_data(g_feather, result, ex_param_idx);
	ASSERT_TRUE(ex_data!=NULL);
	struct rule_ex_param* param=(struct rule_ex_param*)ex_data;
	EXPECT_EQ(param->id, 7799);
	EXPECT_EQ(strcmp(param->name, expect_name),0);
	ex_param_free(0, NULL, NULL, &ex_data, 0, NULL);
	Maat_clean_status(&mid);
	return;
}


TEST(StreamFuzzyHash, Pure)
{
	
#define	StreamFuzzyHash_Pure
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
	
	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);

	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 2);
	EXPECT_EQ(result[1].config_id, 133);
	EXPECT_GT(result[1].serv_def_len, 128);
	
	char* buff=(char*)malloc(sizeof(char)*result[1].serv_def_len);
	ret=Maat_read_rule(g_feather, result+1, MAAT_RULE_SERV_DEFINE, buff, result[1].serv_def_len);	
	EXPECT_EQ(ret, result[1].serv_def_len);
	Maat_clean_status(&mid);
	free(buff);
	return;
}

class MaatFileTest : public testing::Test 
{

protected:
	static void SetUpTestCase()
	{
		const char* rule_folder="./ntcrule/full/index";
	  	logger=MESA_create_runtime_log_handle("test_maat_file.log",0);
		const char* table_info="./t2_tableinfo.conf";
		_shared_feather_f=Maat_feather(g_iThreadNum, table_info, logger);
		Maat_set_feather_opt(_shared_feather_f,MAAT_OPT_INSTANCE_NAME,"files", strlen("files")+1);
		Maat_set_feather_opt(_shared_feather_f, MAAT_OPT_FULL_CFG_DIR, rule_folder, strlen(rule_folder)+1);
		Maat_set_feather_opt(_shared_feather_f, MAAT_OPT_INC_CFG_DIR, rule_folder, strlen(rule_folder)+1);


		Maat_set_feather_opt(_shared_feather_f, MAAT_OPT_SCANDIR_INTERVAL_MS,&scan_interval_ms, sizeof(scan_interval_ms));
		//Set a short intevral for testing.
		Maat_set_feather_opt(_shared_feather_f, MAAT_OPT_EFFECT_INVERVAL_MS,&effective_interval_ms, sizeof(effective_interval_ms));

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
Maat_feather_t MaatFileTest::_shared_feather_f;
Maat_feather_t MaatFileTest::logger;

TEST_F(MaatFileTest, StreamFiles)
{
#define StreamScan_StreamFiles
	Maat_feather_t feather=MaatFileTest::_shared_feather_f;
	const char* test_data_dir="./test_streamfiles";
	struct dirent **namelist;
	FILE* fp=NULL;
	char file_path[256]={0};
	char *buff;
	size_t read_len=0;
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	stream_para_t sp=NULL;
	int n=0,i=0, hit_cnt=0;
	const char* table_name="NTC_HTTP_REQ_BODY";	
	scan_status_t mid=NULL;
	
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);

	n = my_scandir(test_data_dir, &namelist, NULL, (int (*)(const void*, const void*))alphasort);
	ASSERT_GT(n, 0);
	sp=Maat_stream_scan_string_start(feather,table_id,0);
	ASSERT_FALSE(sp==NULL);
	
	struct stat file_info;
	size_t file_size=0;
	for(i=0;i<n;i++)
	{
		if((strcmp(namelist[i]->d_name, ".") == 0) || (strcmp(namelist[i]->d_name, "..") == 0))
		{
			continue;
		}
		snprintf(file_path,sizeof(file_path),"%s/%s",test_data_dir,namelist[i]->d_name);
		
		ret=stat(file_path, &file_info);
		ASSERT_TRUE(ret==0);
		
		file_size=file_info.st_size;
		buff=(char*)malloc(file_size);
		fp=fopen(file_path,"rb");
		
		if(fp==NULL)
		{
			printf("fopen %s error.\n",file_path);
			continue;
		}
		read_len=fread(buff,1,file_size,fp);
		ret=Maat_stream_scan_string(&sp,CHARSET_NONE,buff,read_len
							,result, NULL, 4, &mid);
		read_len=fread(buff,1,sizeof(buff),fp);
		if(ret>0)
		{
			hit_cnt++;
		}
		fclose(fp);
		free(buff);
		buff=NULL;
	}
	Maat_clean_status(&mid);
	Maat_stream_scan_string_end(&sp);
	EXPECT_GT(hit_cnt, 0);

	for(i=0;i<n;i++)
	{
		free(namelist[i]);
	}
	free(namelist);

	return;
}

class MaatCmdTest : public testing::Test 
{

protected:
	
	static void SetUpTestCase()
	{
		void *logger=NULL;
	  	logger=MESA_create_runtime_log_handle("test_maat_redis.log",0);

		_shared_feather=Maat_feather(g_iThreadNum, table_info_path, logger);
		Maat_set_feather_opt(_shared_feather,MAAT_OPT_INSTANCE_NAME,"redis", strlen("redis")+1);
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_REDIS_IP, test_maat_redis_ip, strlen(test_maat_redis_ip)+1);
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_REDIS_PORT, &test_maat_redis_port, sizeof(test_maat_redis_port));
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_SCANDIR_INTERVAL_MS,&scan_interval_ms, sizeof(scan_interval_ms));
		//Set a short intevral for testing.
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_EFFECT_INVERVAL_MS,&effective_interval_ms, sizeof(effective_interval_ms));
		
		const char* foregin_dir="./foreign_files/";	
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_FOREIGN_CONT_DIR,foregin_dir, strlen(foregin_dir)+1);
		linger_timeout=2;
		Maat_set_feather_opt(_shared_feather, MAAT_OPT_FOREIGN_CONT_LINGER,&linger_timeout, sizeof(linger_timeout));

		Maat_cmd_flushDB(_shared_feather);
		Maat_initiate_feather(_shared_feather);

	}
	static void TearDownTestCase()
	{
		Maat_burn_feather(_shared_feather);

	}	
 	// Some expensive resource shared by all tests.
	static Maat_feather_t _shared_feather;	
	static int linger_timeout;
};
Maat_feather_t MaatCmdTest::_shared_feather;
int MaatCmdTest::linger_timeout;
int test_add_expr_command(Maat_feather_t feather,const char* region_table,int config_id, int timeout,int label_id, const char* keywords)
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
int del_command(Maat_feather_t feather,int config_id)
{
	struct Maat_cmd_t* cmd=NULL;
	struct Maat_rule_t rule;
	int ret=0;
	memset(&rule,0,sizeof(rule));
	rule.config_id=config_id;
	cmd=Maat_create_cmd(&rule, 0);
	ret=Maat_cmd(feather, cmd, MAAT_OP_DEL);
	if(ret<0)
	{
		printf("Delete Maat command %d failed.\n",rule.config_id);
	}
	Maat_free_cmd(cmd);
	return 0;
}

TEST_F(MaatCmdTest, SetExpr)
{
	const char* scan_data="Hiredis is a minimalistic C client library for the Redis database.\r\n";
	const char* table_name="HTTP_URL";
	
	const char* keywords1="Hiredis";
	const char* keywords2="C Client";
	char escape_buff1[256],escape_buff2[256];
	char keywords[256];
	scan_status_t mid=NULL;
	int config_id=-1, table_id=0, ret=0;
	int output_ids[4];
	int output_id_cnt=0;
	struct Maat_rule_t result;
	int timeout=0;//seconds
	int label_id=5210;
	long long version_before=0,version_after=0;
	Maat_feather_t feather=MaatCmdTest::_shared_feather;
	
	Maat_str_escape(escape_buff1, sizeof(escape_buff1),keywords1);
	Maat_str_escape(escape_buff2, sizeof(escape_buff2),keywords2);
	snprintf(keywords,sizeof(keywords),"%s&%s",escape_buff1,escape_buff2);
	config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 2);
	
	ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version_before, sizeof(version_before));
	test_add_expr_command(feather,table_name,config_id-1, 0, label_id, keywords);
	test_add_expr_command(feather,table_name,config_id, 0, label_id, keywords);
	
	ret=Maat_cmd_commit(feather);
	EXPECT_TRUE(ret>=0);
	usleep(WAIT_FOR_EFFECTIVE_US);//waiting for commands go into effect
	
	ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version_after, sizeof(version_after));
	EXPECT_EQ(ret, 0);
	EXPECT_GT(version_after, version_before);
	
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);
	memset(&result, 0, sizeof(result));
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result,NULL, 1,
						&mid, 0);
	EXPECT_GT(ret, 0);
	EXPECT_TRUE(result.config_id==config_id||result.config_id==config_id-1);

	Maat_clean_status(&mid);
	output_id_cnt=Maat_cmd_select(feather,label_id, output_ids, 4);
	EXPECT_EQ(output_id_cnt, 2);
	EXPECT_TRUE(output_ids[0]==config_id||output_ids[0]==config_id-1);

	usleep(WAIT_FOR_EFFECTIVE_US);//waiting for commands go into effect	
	del_command(feather, config_id-1);
	del_command(feather, config_id);

	usleep(WAIT_FOR_EFFECTIVE_US);//waiting for commands go into effect
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result,NULL, 1,
						&mid, 0);
	EXPECT_EQ(ret, 0);
	Maat_clean_status(&mid);
	
	timeout=1;
	config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	test_add_expr_command(feather,table_name,config_id, timeout, label_id, keywords);
	ret=Maat_cmd_commit(feather);
	EXPECT_TRUE(ret>=0);

	usleep(timeout*1000*1000+WAIT_FOR_EFFECTIVE_US);
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result,NULL, 1,
						&mid, 0);
	EXPECT_EQ(ret, 0);
}
TEST_F(MaatCmdTest, SetLines)
{
	const int TEST_CMD_LINE_NUM=4;
	const struct Maat_line_t *p_line[TEST_CMD_LINE_NUM];
	struct Maat_line_t line_rule[TEST_CMD_LINE_NUM];
	char table_line[TEST_CMD_LINE_NUM][128];
	int ret=0,i=0;
	Maat_feather_t feather=MaatCmdTest::_shared_feather;
	memset(&line_rule,0,sizeof(line_rule));
	for(i=0;i<TEST_CMD_LINE_NUM;i++)
	{
		line_rule[i].label_id=0;
		line_rule[i].rule_id=(int)Maat_cmd_incrby(feather,"TEST_PLUG_SEQ", 1);
		line_rule[i].table_name="QD_ENTRY_INFO";
		snprintf(table_line[i],sizeof(table_line[i]),"1\t192.168.0.1\t%d\t1",100+i);
		line_rule[i].table_line=table_line[i];
		line_rule[i].expire_after=0;
		p_line[i]=line_rule+i;
	}
	

	ret=Maat_cmd_set_lines(feather, p_line,TEST_CMD_LINE_NUM, MAAT_OP_ADD);
	EXPECT_GT(ret, 0);

	usleep(WAIT_FOR_EFFECTIVE_US);
	
	for(i=0;i<TEST_CMD_LINE_NUM;i++)
	{
		line_rule[i].table_line=NULL;
	}
	ret=Maat_cmd_set_lines(feather, p_line,TEST_CMD_LINE_NUM, MAAT_OP_DEL);
	EXPECT_GT(ret, 0);

	return;
}
TEST_F(MaatCmdTest, SetIP)
{
	struct Maat_cmd_t* cmd=NULL;
	struct Maat_rule_t rule;
	int config_id=0,timeout=4;
	long long version_before=0,version_after=0;
	const char* region_table="IP_CONFIG";
	struct Maat_region_t region;
	int group_num=1,ret=0;
	memset(&rule,0,sizeof(rule));
	Maat_feather_t feather=MaatCmdTest::_shared_feather;
	
	//MUST acquire by Maat_cmd_incrby to guarantee a unique compile ID.
	config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	rule.config_id=config_id;
	
	strcpy(rule.service_defined,"maat_command");
	//MUST acqire by function, because Maat_cmd_t has some hidden members.
	cmd=Maat_create_cmd(&rule, group_num);
	cmd->expire_after=timeout;
	cmd->label_id=0;	//no lable
	memset(&region,0,sizeof(region));
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
	Maat_add_region2cmd(cmd, 0, &region);

	ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version_before, sizeof(version_before));
	EXPECT_EQ(ret, 0);
	ret=Maat_cmd(feather, cmd, MAAT_OP_ADD);
	EXPECT_GE(ret, 0);
	Maat_free_cmd(cmd);
	cmd=NULL;

	//TEST if the command go into effective.
	usleep(WAIT_FOR_EFFECTIVE_US);	//waiting for commands go into effect
	
	ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version_after, sizeof(version_after));

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
	//reset timeout.
	cmd=Maat_create_cmd(&rule, 0);
	cmd->expire_after=10;
	ret=Maat_cmd(feather, cmd, MAAT_OP_RENEW_TIMEOUT);
	EXPECT_EQ(ret ,1);
	
	usleep(2*1000*1000+WAIT_FOR_EFFECTIVE_US);//wait for commands expired.
	Maat_free_cmd(cmd);
	cmd=NULL;

	ret=Maat_scan_proto_addr(feather,table_id,&ipv4_addr,6,&result,1, &mid,0);
	EXPECT_EQ(ret, 1);

	Maat_clean_status(&mid);

	return;

}
int g_test_update_paused=0;
void pause_update_test_entry_cb(int table_id,const char* table_line,void* u_para)
{
	char status[32]={0};
	int entry_id=-1,seq=-1;
	int is_valid=0;
	sscanf(table_line,"%d\t%s\t%d\t%d",&seq,status,&entry_id,&is_valid);
	EXPECT_EQ(g_test_update_paused, 0);

	return;
}

TEST_F(MaatCmdTest, PauseUpdate)
{
	Maat_feather_t feather=MaatCmdTest::_shared_feather;
	int value=0, ret=0, table_id=0;
	struct Maat_line_t line_rule;
	char* line=NULL;
	const char* table_name="QD_ENTRY_INFO";
	table_id=Maat_table_register(feather, table_name);
	ASSERT_GT(table_id, 0);
	ret=Maat_table_callback_register(g_feather, table_id,
							NULL,
							pause_update_test_entry_cb, 
							NULL,
							NULL);	
	Maat_set_feather_opt(feather, MAAT_OPT_ENABLE_UPDATE, &value, sizeof(value));
	g_test_update_paused=1;
	line_rule.label_id=0;
	line_rule.rule_id=(int)Maat_cmd_incrby(feather,"TEST_PLUG_SEQ", 1);
	line_rule.table_name=table_name;
	asprintf(&line,"1\t192.168.0.1\t101\t1");
	line_rule.table_line=line;
	line_rule.expire_after=0;
	ret=Maat_cmd_set_line(feather, &line_rule, MAAT_OP_ADD);
	EXPECT_EQ(ret, 1);
	free(line);
	value=1;
	g_test_update_paused=0;
	Maat_set_feather_opt(feather, MAAT_OPT_ENABLE_UPDATE, &value, sizeof(value));

}

void prepare_file_to_set(const char* filename, char** file_buff, size_t* file_size, char* file_key, size_t key_size)
{
	int ret=0, i=0;
	FILE* fp=NULL;
	struct stat file_info;
	unsigned char md5[MD5_DIGEST_LENGTH];
	char md5string[MD5_DIGEST_LENGTH+1];
	memset(md5, 0, sizeof(md5));
	memset(md5string, 0, sizeof(md5string));

	ret=stat(filename, &file_info);
	ASSERT_TRUE(ret==0);

	fp=fopen(filename,"r");
	ASSERT_FALSE(fp==NULL);

	*file_size=file_info.st_size;
	*file_buff=(char*)malloc(*file_size);
	ret=fread(*file_buff,1,*file_size,fp);
	fclose(fp);
	
	MD5((const unsigned char *)(*file_buff), (unsigned long)(*file_size), md5);
	for(i = 0; i < MD5_DIGEST_LENGTH; ++i)
	{
		sprintf(&md5string[i*2], "%02x", (unsigned int)md5[i]);
	}
	snprintf(file_key, key_size, "__FILE_%s", md5string);
	return;
}
char* md5_file(const char* filename, char* md5string)
{
	FILE* fp=NULL;
	int i=0;
	unsigned char md5[MD5_DIGEST_LENGTH];
	struct stat file_info;	
	stat(filename, &file_info);
	size_t file_size=file_info.st_size;

	fp=fopen(filename,"r");
	if(fp==NULL)
	{
		return NULL;
	}
	char* file_buff=(char*)malloc(file_size);
	fread(file_buff,1,file_size,fp);
	fclose(fp);
	
	MD5((const unsigned char *)(file_buff), (unsigned long)(file_size), md5);
	for(i = 0; i < MD5_DIGEST_LENGTH; ++i)
	{
		sprintf(&md5string[i*2], "%02x", (unsigned int)md5[i]);
	}
	free(file_buff);
	return md5string;
}
int is_same_file(const char* filename1, const char* filename2)
{
	char md5string[2][MD5_DIGEST_LENGTH*2+1];
	memset(md5string, 0, sizeof(md5string));
	md5_file(filename1, md5string[0]);
	md5_file(filename2, md5string[1]);
	if(0==strcmp(md5string[0], md5string[1]))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
int g_test_foregin_read_OK=0, g_test_foreign_del_OK=0;
char file1_to_del[256], file2_to_del[256];

void foreign_key_test_entry_cb(int table_id,const char* table_line,void* u_para)
{
	int rule_id=-1, not_care=0, tag=0;
	int is_valid=0;
	char file1_origin_name[256], file2_origin_name[256];
	char file1_localname[256], file2_localname[256];
	char end[16];

	memset(file1_localname, 0, sizeof(file1_localname));
	memset(file2_localname, 0, sizeof(file2_localname));
	
	sscanf(table_line, "%d\t%d\t%d\t%d\t%s\t%s\t\%s\t%s\t%s",&rule_id, &not_care, &tag, &is_valid
												, file1_origin_name, file1_localname
												, file2_origin_name, file2_localname
												, end);
	EXPECT_STREQ(end, "End");
	if(is_valid==1)
	{
		EXPECT_TRUE(is_same_file(file1_origin_name, file1_localname));
		EXPECT_TRUE(is_same_file(file2_origin_name, file2_localname));

		g_test_foregin_read_OK=1;
	}
	else
	{
		strcpy(file1_to_del, file1_localname);
		strcpy(file2_to_del, file2_localname);
		g_test_foreign_del_OK=1;
	}
	return;
}

TEST_F(MaatCmdTest, SetFile)
{
	Maat_feather_t feather=MaatCmdTest::_shared_feather;
	int ret=0, table_id=0;
	const char* table_name="TEST_FOREIGN_KEY";
	table_id=Maat_table_register(feather, table_name);
	ASSERT_GT(table_id, 0);
	ret=Maat_table_callback_register(feather, table_id,
							NULL,
							foreign_key_test_entry_cb, 
							NULL,
							NULL);	
	ASSERT_EQ(ret, 1);
	const char* file1_name="./testdata/digest_test.data", *file2_name="./testdata/mesa_logo.jpg";	
	char* file_buff=NULL, file1_key[256], file2_key[256];
	size_t file_size=0;
	
	prepare_file_to_set(file1_name, &file_buff, &file_size, file1_key, sizeof(file1_key));
	ret=Maat_cmd_set_file(feather, file1_key, file_buff, file_size, MAAT_OP_ADD);
	EXPECT_EQ(ret, 1);
	free(file_buff);
	file_buff=NULL;
	
	prepare_file_to_set(file2_name, &file_buff, &file_size, file2_key, sizeof(file2_key));
	ret=Maat_cmd_set_file(feather, file2_key, file_buff, file_size, MAAT_OP_ADD);
	EXPECT_EQ(ret, 1);
	free(file_buff);
	file_buff=NULL;
	g_test_foregin_read_OK=0;

	char line[1024];
	int tag=0;
	struct Maat_line_t line_rule;
	line_rule.label_id=0;
	line_rule.rule_id=(int)Maat_cmd_incrby(feather,"TEST_PLUG_SEQ", 1);
	line_rule.table_name=table_name;
	snprintf(line, sizeof(line),"%d\t2\t%d\t1\t%s\tredis://%s\t%s\tredis://%s\tEnd",line_rule.rule_id, tag
																			,file1_name, file1_key
																			,file2_name, file2_key);
	line_rule.table_line=line;
	line_rule.expire_after=0;
	ret=Maat_cmd_set_line(feather, &line_rule, MAAT_OP_ADD);
	EXPECT_EQ(ret, 1);
	usleep(WAIT_FOR_EFFECTIVE_US);//wait for callback triggered.
	EXPECT_EQ(g_test_foregin_read_OK, 1);

	g_test_foreign_del_OK=0;
	ret=Maat_cmd_set_file(feather, file1_key, NULL, 0, MAAT_OP_DEL);
	EXPECT_EQ(ret, 1);
	ret=Maat_cmd_set_file(feather, file2_key, NULL, 0, MAAT_OP_DEL);
	EXPECT_EQ(ret, 1);
	
	ret=Maat_cmd_set_line(feather, &line_rule, MAAT_OP_DEL);	
	EXPECT_EQ(ret, 1);
	sleep(MaatCmdTest::linger_timeout+1);
	
	struct stat file_info;	
	ret=stat(file1_to_del, &file_info);
	EXPECT_EQ(ret, -1);
	ret=stat(file2_to_del, &file_info);
	EXPECT_EQ(ret, -1);

	return;
}

int main(int argc, char ** argv)
{

	const char* log_file="./test.log";
	const char* stat_file="./scan_staus.log";
	const char* decrypt_key="mesa2017wy";
	const char* accept_tags="{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"}]}";

	int scan_detail=0;

	::testing::InitGoogleTest(&argc, argv);
	g_logger=MESA_create_runtime_log_handle(log_file,0);

	g_feather=Maat_feather(g_iThreadNum, table_info_path, g_logger);
	Maat_set_feather_opt(g_feather,MAAT_OPT_INSTANCE_NAME,"demo", strlen("demo")+1);
	Maat_set_feather_opt(g_feather,MAAT_OPT_DECRYPT_KEY,decrypt_key, strlen(decrypt_key)+1);
	Maat_set_feather_opt(g_feather, MAAT_OPT_JSON_FILE_PATH, json_path, strlen(json_path)+1);

	Maat_set_feather_opt(g_feather, MAAT_OPT_SCANDIR_INTERVAL_MS,&scan_interval_ms, sizeof(scan_interval_ms));
	//Set a short intevral for testing.
	Maat_set_feather_opt(g_feather, MAAT_OPT_EFFECT_INVERVAL_MS,&effective_interval_ms, sizeof(effective_interval_ms));

	Maat_set_feather_opt(g_feather, MAAT_OPT_STAT_FILE_PATH, stat_file, strlen(stat_file)+1);
	Maat_set_feather_opt(g_feather, MAAT_OPT_STAT_ON, NULL, 0);
	Maat_set_feather_opt(g_feather, MAAT_OPT_PERF_ON, NULL, 0);
	Maat_set_feather_opt(g_feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
	Maat_set_feather_opt(g_feather, MAAT_OPT_ACCEPT_TAGS, accept_tags, strlen(accept_tags)+1);
	Maat_initiate_feather(g_feather);
	printf("Maat initiating, see %s\n",log_file);

	int ret=RUN_ALL_TESTS();
	Maat_burn_feather(g_feather);
	MESA_destroy_runtime_log_handle(g_logger);
	return ret;
}

