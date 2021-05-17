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
extern char* md5_file(const char* filename, char* md5string);
extern int system_cmd_cp(const char* src_file,const char*dst_file);
extern int system_cmd_encrypt(const char* src_file, const char* dst_file, const char* password);
int system_cmd_gzip(const char* src_file, const char* dst_file);

Maat_feather_t g_feather=NULL;
void *g_logger=NULL;
int g_iThreadNum=4;
const char* table_info_path="./table_info.conf";
int scan_interval_ms=500;
int effective_interval_ms=0;
void wait_for_cmd_effective(Maat_feather_t feather, long long version_before)
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
void ipv4_addr_set(struct ipaddr *ipv4_addr, struct stream_tuple4_v4* v4_addr,
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
void scan_with_old_or_new_cfg(Maat_feather_t feather, int is_old)
{
	const char* hit_old_data="Hello world! I'm eve.";
	const char* hit_new_data="Maat was borned in MESA.";

	const char* table_name="HTTP_URL";
	
	scan_status_t mid=NULL;
	int table_id=0, ret=0;

	struct Maat_rule_t result;
	
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);
	memset(&result, 0, sizeof(result));
	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, hit_old_data, strlen(hit_old_data), 
						&result,NULL, 1,
						&mid, 0);
	if(is_old)
	{
		EXPECT_EQ(ret, 1);
		EXPECT_TRUE(result.config_id==1);
	}
	else
	{
		EXPECT_EQ(ret, 0);
	}
	Maat_clean_status(&mid);
	
	memset(&result, 0, sizeof(result));
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, hit_new_data, strlen(hit_new_data), 
						&result,NULL, 1,
						&mid, 0);
	if(!is_old)
	{
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(result.config_id, 2);
	}
	else
	{
		EXPECT_EQ(ret, 0);
	}

	Maat_clean_status(&mid);

}

const char* watched_json="./json_update/maat.json";
const char* old_json="./json_update/old.json";
const char* new_json="./json_update/new.json";
const char* corrupted_json="./json_update/corrupted.json";
const char* json_decrypt_key="himaat!";
const char* tmp_gzipped_file_name="./json_update/tmp_gzipped_json.gz";

class JSONUpdate : public testing::Test 
{

protected:
	static void SetUpTestCase()
	{	
		int tmp=0;
		system_cmd_gzip(old_json, tmp_gzipped_file_name);
		system_cmd_encrypt(tmp_gzipped_file_name, watched_json, json_decrypt_key);
		
		_shared_feather_j=Maat_feather(g_iThreadNum, table_info_path, g_logger);	
		tmp=1;
		Maat_set_feather_opt(_shared_feather_j, MAAT_OPT_JSON_IS_GZIPPED, &tmp, sizeof(tmp));
		Maat_set_feather_opt(_shared_feather_j, MAAT_OPT_DECRYPT_KEY, json_decrypt_key, strlen(json_decrypt_key)+1);
		Maat_set_feather_opt(_shared_feather_j, MAAT_OPT_JSON_FILE_PATH, watched_json, strlen(watched_json)+1);		
		Maat_set_feather_opt(_shared_feather_j, MAAT_OPT_SCANDIR_INTERVAL_MS, &scan_interval_ms, sizeof(scan_interval_ms));

		Maat_initiate_feather(_shared_feather_j);

	}
	static void TearDownTestCase()
	{
		Maat_burn_feather(_shared_feather_j);
	}	
 	// Some expensive resource shared by all tests.
	static Maat_feather_t _shared_feather_j;
	static void *logger;
};
Maat_feather_t JSONUpdate::_shared_feather_j;


TEST_F(JSONUpdate, OldCfg)
{
	scan_with_old_or_new_cfg(JSONUpdate::_shared_feather_j, 1);
}
TEST_F(JSONUpdate, NewCfg)
{
	system_cmd_gzip(corrupted_json, tmp_gzipped_file_name);
	system_cmd_encrypt(tmp_gzipped_file_name, watched_json, json_decrypt_key);
	sleep(2);
	scan_with_old_or_new_cfg(JSONUpdate::_shared_feather_j, 1);

	system_cmd_gzip(new_json, tmp_gzipped_file_name);
	system_cmd_encrypt(tmp_gzipped_file_name, watched_json, json_decrypt_key);
	sleep(5);
	scan_with_old_or_new_cfg(JSONUpdate::_shared_feather_j, 0);
}

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
#define Plugin_callback
TEST(PluginTable, Callback)
{
	test_plugin_table(g_feather, "QD_ENTRY_INFO",	
								Maat_read_entry_start_cb,
								Maat_read_entry_cb, 
								Maat_read_entry_finish_cb,
								g_feather,
								g_logger);

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
	u->ref_cnt--;
	if(u->ref_cnt>0) return;
	free(u->buffer);
	free(u);
	*ad=NULL;
}
void ip_plugin_EX_dup_cb(int table_id,	MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void *argp)
{
	struct ip_plugin_ud* u=(struct ip_plugin_ud*)(*from);
	u->ref_cnt++;
	*to=u;
}

TEST(IP_Plugin_Table, EX_DATA)
{
	
	int ip_plugin_ex_data_counter=0, i=0;
	const char* table_name="TEST_IP_PLUGIN_WITH_EXDATA";
	int table_id=0, ret=0;
	table_id=Maat_table_register(g_feather, table_name);
	ASSERT_GT(table_id, 0);
	ret=Maat_ip_plugin_EX_register(g_feather, table_id,
								ip_plugin_EX_new_cb,
								ip_plugin_EX_free_cb,
								ip_plugin_EX_dup_cb,
								0, &ip_plugin_ex_data_counter);
	ASSERT_TRUE(ret>=0);
	EXPECT_EQ(ip_plugin_ex_data_counter, 5);
	struct ip_address ipv4, ipv6;
	struct ip_plugin_ud* result[4];
	ipv4.ip_type=4;
	inet_pton(AF_INET, "192.168.30.100", &(ipv4.ipv4));
	ret=Maat_ip_plugin_get_EX_data(g_feather, table_id, &ipv4, (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_EQ(result[0]->rule_id, 101);
	EXPECT_EQ(result[1]->rule_id, 102);
	for(i=0; i<ret; i++)
	{
		ip_plugin_EX_free_cb(0, (void**)&(result[i]), 0, NULL);
	}
	ipv6.ip_type=6;
	inet_pton(AF_INET6,"2001:db8:1234::5210",&(ipv6.ipv6));
	ret=Maat_ip_plugin_get_EX_data(g_feather, table_id, &ipv6, (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_EQ(result[0]->rule_id, 104);
	EXPECT_EQ(result[1]->rule_id, 103);
	for(i=0; i<ret; i++)
	{
		ip_plugin_EX_free_cb(0, (void**)&(result[i]), 0, NULL);
	}
	//Reproduce BugReport-Liumengyan-20210515
	inet_pton(AF_INET6,"240e:97c:4010:104::17",&(ipv6.ipv6));
	ret=Maat_ip_plugin_get_EX_data(g_feather, table_id, &ipv6, (void**)result, 4);
	ASSERT_EQ(ret, 0);

}

#define FQDN_PLUGIN_EX_DATA
struct fqdn_plugin_ud
{
	int rule_id;
	int catid;
	int ref_cnt;
};
void fqdn_plugin_EX_new_cb(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	int *counter=(int *)argp, ret=0;
	size_t column_offset=0, column_len=0;
	struct fqdn_plugin_ud* ud=(struct fqdn_plugin_ud*)calloc(sizeof(struct fqdn_plugin_ud), 1);
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
void fqdn_plugin_EX_free_cb(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	struct fqdn_plugin_ud* u=(struct fqdn_plugin_ud*)(*ad);
	u->ref_cnt--;
	if(u->ref_cnt>0) return;
	free(u);
	*ad=NULL;
}
void fqdn_plugin_EX_dup_cb(int table_id,	MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void *argp)
{
	struct fqdn_plugin_ud* u=(struct fqdn_plugin_ud*)(*from);
	u->ref_cnt++;
	*to=u;
}
TEST(FQDN_Plugin_Table, EX_DATA)
{
	
	int fqdn_plugin_ex_data_counter=0, i=0;
	const char* table_name="TEST_FQDN_PLUGIN_WITH_EXDATA";
	int table_id=0, ret=0;
	table_id=Maat_table_register(g_feather, table_name);
	ASSERT_GT(table_id, 0);
	ret=Maat_fqdn_plugin_EX_register(g_feather, table_id,
								fqdn_plugin_EX_new_cb,
								fqdn_plugin_EX_free_cb,
								fqdn_plugin_EX_dup_cb,
								0, &fqdn_plugin_ex_data_counter);
	ASSERT_TRUE(ret>=0);
	EXPECT_EQ(fqdn_plugin_ex_data_counter, 5);

	struct fqdn_plugin_ud* result[4];

	ret=Maat_fqdn_plugin_get_EX_data(g_feather, table_id, "www.example1.com", (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_EQ(result[0]->rule_id, 201);
	EXPECT_EQ(result[1]->rule_id, 202);

	for(i=0; i<ret; i++)
	{
		fqdn_plugin_EX_free_cb(0, (void**)&(result[i]), 0, NULL);
	}

	ret=Maat_fqdn_plugin_get_EX_data(g_feather, table_id, "www.example3.com", (void**)result, 4);
	EXPECT_EQ(ret, 0);

	ret=Maat_fqdn_plugin_get_EX_data(g_feather, table_id, "r3---sn-i3belne6.example2.com", (void**)result, 4);
	ASSERT_EQ(ret, 2);
	EXPECT_EQ(result[0]->rule_id, 205);
	EXPECT_EQ(result[1]->rule_id, 204);
	for(i=0; i<ret; i++)
	{
		fqdn_plugin_EX_free_cb(0, (void**)&(result[i]), 0, NULL);
	}

}


TEST(StringScan, Full)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* table_name="HTTP_URL";
	scan_status_t mid=NULL;
	const char* scan_data="http://www.cyberessays.com/search_results.php?action=search&query=username,abckkk,1234567";
	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result,found_pos, 4, &mid, 0);
						
	EXPECT_GE(ret, 1);
	EXPECT_EQ(result[0].config_id, 125);
	Maat_clean_status(&mid);
}

TEST(StringScan, Regex)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* table_name="HTTP_URL";
	scan_status_t mid=NULL;
	const char* cookie="Cookie: Txa123aheadBCAxd";
	const char* sni_should_not_hit[]={"instagram.fbcdn.net","a.instagram.fbcdn.net"};
	const char* sni_should_hit[]={"xx.fbcdn.net","ainstagram.fbcdn.net"};
	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, cookie, strlen(cookie), 
						result,found_pos, 4, &mid, 0);
						
	EXPECT_GE(ret, 1);
	EXPECT_EQ(result[0].config_id, 146);
	Maat_clean_status(&mid);
	

	size_t i=0;
	for(i=0; i< sizeof(sni_should_not_hit)/sizeof(const char*); i++)
	{
		ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, sni_should_not_hit[i], strlen(sni_should_not_hit[i]), 
							result,found_pos, 4, &mid, 0);
		EXPECT_EQ(ret, 0);		
		Maat_clean_status(&mid);
	}
	for(i=0; i<sizeof(sni_should_hit)/sizeof(const char*); i++)
	{
		ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, sni_should_hit[i], strlen(sni_should_hit[i]), 
							result,found_pos, 4, &mid, 0);
		EXPECT_GE(ret, 1);	
		EXPECT_EQ(result[0].config_id, 149);
		Maat_clean_status(&mid);
	}	
}
TEST(StringScan, BugReport20190325)
{
	struct Maat_rule_t result[4];
	int found_pos[4];

	unsigned char scan_data[] = { /* Packet 1 */
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
	0x00 };

	int table_id=Maat_table_register(g_feather, "TROJAN_PAYLOAD");
	ASSERT_GT(table_id, 0);
	scan_status_t mid=NULL;
	int ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, (char*)scan_data, sizeof(scan_data), 
						result, found_pos, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 150);
	Maat_clean_status(&mid);
}
#define PrefixAndSuffixTest
TEST(StringScan, PrefixAndSuffix)
{
	int ret=0;
	int mail_addr_table=0, cont_sz_table=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	scan_status_t mid=NULL;
	const char* hit_twice="ceshi3@mailhost.cn";
	const char* hit_suffix="11111111111ceshi3@mailhost.cn";
	const char* hit_prefix="ceshi3@mailhost.cn11111111111";

	
	cont_sz_table=Maat_table_register(g_feather, "CONTENT_SIZE");
	ret=Maat_scan_intval(g_feather, cont_sz_table, 2015, 
					result, 4, &mid, 0);
	mail_addr_table=Maat_table_register(g_feather, "MAIL_ADDR");
	ASSERT_GT(mail_addr_table, 0);
	ret=Maat_full_scan_string(g_feather, mail_addr_table,CHARSET_GBK, hit_twice, strlen(hit_twice), 
						result,found_pos, 4, &mid, 0);
	EXPECT_EQ(ret, 2);
	EXPECT_EQ(result[0].config_id, 151);//compile has more groups is priority
	EXPECT_EQ(result[1].config_id, 152);
	Maat_clean_status(&mid);
	
	ret=Maat_full_scan_string(g_feather, mail_addr_table,CHARSET_GBK, hit_suffix, strlen(hit_suffix), 
						result,found_pos, 4, &mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 151);
	Maat_clean_status(&mid);

	ret=Maat_scan_intval(g_feather, cont_sz_table, 2015, 
					result, 4, &mid, 0);

	ret=Maat_full_scan_string(g_feather, mail_addr_table,CHARSET_GBK, hit_prefix, strlen(hit_prefix), 
						result,found_pos, 4, &mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 152);
	Maat_clean_status(&mid);

}

#define IntvalPlusTest	1
TEST(IntvalScan,   IntvalPlusPlus)
{
	int table_id=0,ret=0;
	int scan_val=2020;
	scan_status_t mid=NULL;
	struct Maat_rule_t result[4];
	
	table_id=Maat_table_register(g_feather, "INTERGER_PLUS");
	ASSERT_GT(table_id, 0);

	ret=Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_DISTRICT, "intval.plus", strlen("intval.plus"));
	ASSERT_EQ(ret, 0);
	
	ret=Maat_scan_intval(g_feather, table_id, scan_val, result,4, &mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 179);
	
	Maat_clean_status(&mid);
	
	return ;
}

#define ExprPlusTest	1
TEST(StringScan,   ExprPlus)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* region_name="HTTP URL";
	const char* scan_data="http://www.cyberessays.com/search_results.php?action=search&query=abckkk,1234567";
	table_id=Maat_table_register(g_feather, "HTTP_SIGNATURE");
	ASSERT_GT(table_id, 0);
	scan_status_t mid=NULL;
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, scan_data, strlen(scan_data), 
						result, found_pos, 4,
						&mid, 0);
	EXPECT_EQ(ret, -1);//Should return error for district not setting.

	ret=Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_DISTRICT, region_name, strlen(region_name));
	ASSERT_EQ(ret, 0);
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result, found_pos, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 128);
	
	Maat_clean_status(&mid);
	return;
}


TEST(StringScan, ExprPlusWithOffset)
{
	int ret=0, table_id=0;
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	const char* region_name="Payload";
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

	memset(&result, 0, sizeof(result));
	table_id=Maat_table_register(g_feather, "APP_PAYLOAD");
	ASSERT_GT(table_id, 0);
	ret=Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_DISTRICT, region_name, strlen(region_name));
	EXPECT_EQ(ret, 0);

	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, (char*)udp_payload_not_hit, sizeof(udp_payload_not_hit), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 0);
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, (char*)udp_payload_hit, sizeof(udp_payload_hit), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 148);
	
	Maat_clean_status(&mid);
	return;
}

TEST(StringScan, ExprPlusWithHex)
{
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	const char* scan_data="text/html; charset=UTF-8";	
	const char* region_name="Content-Type";
	int found_pos[4];
	table_id=Maat_table_register(g_feather, "HTTP_SIGNATURE");
	ASSERT_GT(table_id, 0);
	scan_status_t mid=NULL;
	ret=Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_DISTRICT, region_name, strlen(region_name));
	ASSERT_EQ(ret, 0);
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result, found_pos, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 156);
	Maat_clean_status(&mid);

	return;

}

TEST(StringScan,   CharsetWindows1251)
{
	int table_id=0,ret=0;
	int read_size=0,pass_flag=0;
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	//const char* fn="./testdata/mesa_logo.jpg";
	const char* table_name="KEYWORDS_TABLE";
	const char* fn="./testdata/charsetWindows1251.txt";
	FILE* fp=fopen(fn,"r");
	ASSERT_FALSE(fp==NULL);

	char scan_data[4096]={0};
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
	EXPECT_EQ(result[0].config_id, 164);
	
	Maat_stream_scan_string_end(&sp);
	free(hit_detail);
	fclose(fp);
	Maat_clean_status(&mid);
	return;

}

#define	TEST_IPSCAN
TEST(IPScan, IPv4_mask)
{
	int table_id=0,ret=0;
	const char* table_name="IP_CONFIG";
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr_set(&ipv4_addr, &v4_addr, "10.0.6.205", 50001, "10.0.6.201", 80);

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
TEST(IPScan, IPv6_mask)
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
TEST(IPScan, IPv4_range)
{
	int table_id=0,ret=0;
	const char* table_name="IP_PLUS_CONFIG";
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr.addrtype=ADDR_TYPE_IPV4;
	inet_pton(AF_INET, "10.0.7.106", &(v4_addr.saddr));
	v4_addr.source=htons(5000);
	inet_pton(AF_INET, "123.56.104.254", &(v4_addr.daddr));
	v4_addr.dest=htons(7400);
	ipv4_addr.v4=&v4_addr;


	table_id=Maat_table_register(g_feather, table_name);
	
	EXPECT_GT(table_id, 0);

	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result, 4, &mid, 0);
	
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 154);

	Maat_clean_status(&mid);
	return;
}

TEST(IPScan, IPv6_range)
{
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	struct ipaddr ipv6_addr;
	struct stream_tuple4_v6 v6_addr;
	scan_status_t mid=NULL;
	
	ipv6_addr.addrtype=ADDR_TYPE_IPV6;
	inet_pton(AF_INET6,"1001:da8:205:1::151",&(v6_addr.saddr));
	v6_addr.source=htons(5204);//5200~5299?
	inet_pton(AF_INET6,"3001:da8:205:1::901",&(v6_addr.daddr));
	v6_addr.dest=htons(80);//any
	ipv6_addr.v6=&v6_addr;
	const char* table_name="IP_PLUS_CONFIG";
	table_id=Maat_table_register(g_feather,table_name);
	EXPECT_GT(table_id, 0);

	//for improving performance.
	Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_LAST_REGION,NULL, 0);
	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv6_addr, 6, result,4, &mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 155);
	Maat_clean_status(&mid);
	return;

}
TEST(IPScan, IPv4_CIDR)
{
	int table_id=0,ret=0;
	const char* table_name="IP_PLUS_CONFIG";
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr.addrtype=ADDR_TYPE_IPV4;
	inet_pton(AF_INET, "192.168.0.1", &(v4_addr.saddr));
	v4_addr.source=htons(5210);
	inet_pton(AF_INET, "10.0.6.210", &(v4_addr.daddr));
	v4_addr.dest=htons(7400);
	ipv4_addr.v4=&v4_addr;


	table_id=Maat_table_register(g_feather, table_name);
	
	EXPECT_GT(table_id, 0);

	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result, 4, &mid, 0);
	
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 158);

	Maat_clean_status(&mid);
	return;
}
TEST(IPScan, IPv6_CIDR)
{
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	struct ipaddr ipv6_addr;
	struct stream_tuple4_v6 v6_addr;
	scan_status_t mid=NULL;
	
	ipv6_addr.addrtype=ADDR_TYPE_IPV6;
	inet_pton(AF_INET6,"2001:db8::00fe",&(v6_addr.saddr));
	v6_addr.source=htons(5204);//5200~5299?
	inet_pton(AF_INET6,"2001:4860:4860::8888",&(v6_addr.daddr));
	v6_addr.dest=htons(80);//any
	ipv6_addr.v6=&v6_addr;
	const char* table_name="IP_PLUS_CONFIG";
	table_id=Maat_table_register(g_feather,table_name);
	EXPECT_GT(table_id, 0);

	//for improving performance.
	Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_LAST_REGION,NULL, 0);
	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv6_addr, 6, result,4, &mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 159);
	Maat_clean_status(&mid);
	return;

}
TEST(IPScan, IPv4_Port)
{
	int table_id=0,ret=0;
	const char* table_name="IP_PLUS_CONFIG";
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr_set(&ipv4_addr, &v4_addr, "192.168.244.1", 20304, "0.0.0.0", 0);

	table_id=Maat_table_register(g_feather, table_name);
	
	EXPECT_GT(table_id, 0);

	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result, 4, &mid, 0);
	
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 169);

	Maat_clean_status(&mid);
	return;
}
TEST(IPScan, IPv4_virtual)
{
	int table_id=0,ret=0;
	const char* table_name="VIRTUAL_IP_PLUS_TABLE";
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr_set(&ipv4_addr, &v4_addr, "192.168.40.10", 443, "192.168.231.46", 25705);

	table_id=Maat_table_register(g_feather, table_name);
	
	EXPECT_GT(table_id, 0);

	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result, 4, &mid, 0);
	
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 172);

	Maat_clean_status(&mid);
	return;
}
TEST(IPScan, IPv4_composition)
{
	int table_id=0,ret=0;
	const char* table_name="COMPOSITION_IP";
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr_set(&ipv4_addr, &v4_addr, "192.168.40.11", 443, "192.168.231.47", 25715);

	table_id=Maat_table_register(g_feather, table_name);
	
	EXPECT_GT(table_id, 0);

	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result, 4, &mid, 0);
	
	EXPECT_EQ(ret, 2);
	EXPECT_EQ(result[0].config_id, 177);
	EXPECT_EQ(result[1].config_id, 175);


	struct Maat_hit_path_t hit_path[128];
	int n_read=0;
	n_read=Maat_get_scan_status(g_feather, &mid, MAAT_GET_SCAN_HIT_PATH, hit_path, sizeof(hit_path));
	int i=0, c175=0, c177=0;
	for(i=0; i<n_read; i++)
	{
		if(hit_path[i].compile_id==177) c177++;
		if(hit_path[i].compile_id==175) c175++;
	}
	EXPECT_EQ(c177, 1);
	EXPECT_EQ(c175, 2);//two paths for source IP hit and destination IP hit
	Maat_clean_status(&mid);

	//rule source IP 192.168.50.24, source port 1-40000
	ipv4_addr_set(&ipv4_addr, &v4_addr, "192.168.50.24", 30000, "23.78.217.119", 443);
	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result, 4, &mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 181);
	Maat_clean_status(&mid);

	ipv4_addr_set(&ipv4_addr, &v4_addr, "192.168.50.25", 30000, "23.78.217.119", 443);
	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result, 4, &mid, 0);
	EXPECT_EQ(ret, 0);//Rule source ip is 192.168.50.24, should not match
	Maat_clean_status(&mid);


	ipv4_addr_set(&ipv4_addr, &v4_addr, "192.168.50.24", 56486, "23.78.217.119", 443);
	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result, 4, &mid, 0);
	EXPECT_EQ(ret, 0);//Rule source port is 0-40000, should not match
	Maat_clean_status(&mid);
	return;
}
TEST(IPScan, BugReport20210515)
{
	//By Liu Mengyan 2021-5-15
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	struct ipaddr ipv6_addr;
	struct stream_tuple4_v6 v6_addr;
	scan_status_t mid=NULL;
	
	ipv6_addr.addrtype=ADDR_TYPE_IPV6;
	inet_pton(AF_INET6,"2409:8915:3430:7e7:8c9b:ff2a:7aa1:e74",&(v6_addr.saddr));
	v6_addr.source=htons(41159);
	inet_pton(AF_INET6,"240e:97c:4010:104::17",&(v6_addr.daddr));
	v6_addr.dest=htons(7706);
	ipv6_addr.v6=&v6_addr;
	const char* table_name="IP_CONFIG";
	table_id=Maat_table_register(g_feather, table_name);
	EXPECT_GT(table_id, 0);

	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv6_addr, 6, result, 4, &mid, 0);
	EXPECT_EQ(ret, 0);
	Maat_clean_status(&mid);
	return;
}

#define	TEST_NOTLogic	1

TEST(NOTLogic, OneRegion)
{
	const char* string_should_hit="This string ONLY contains must-contained-string-of-rule-143.";
	const char* string_should_not_hit="This string contains both must-contained-string-of-rule-143 and must-not-contained-string-of-rule-143.";

	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* table_name="HTTP_URL";
	scan_status_t mid=NULL;
	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	
	Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_LAST_REGION,  NULL, 0);
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, string_should_hit, strlen(string_should_hit), 
						result, found_pos, 4, &mid, 0);
						
	EXPECT_GE(ret, 1);
	Maat_clean_status(&mid);

	Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_LAST_REGION,  NULL, 0);
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, string_should_not_hit, strlen(string_should_not_hit), 
						result, found_pos, 4, &mid, 0);
						
	EXPECT_EQ(ret, -2);
	Maat_clean_status(&mid);

}

TEST(NOTLogic, ScanNotAtLast)
{
	const char* string_should_hit="This string ONLY contains must-contained-string-of-rule-144.";
	const char* string_should_not_hit="This string contains both must-contained-string-of-rule-144 and must-not-contained-string-of-rule-144.";
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* hit_table_name="HTTP_URL", *not_hit_table_name="KEYWORDS_TABLE";
	scan_status_t mid=NULL;
	table_id=Maat_table_register(g_feather,hit_table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, string_should_hit, strlen(string_should_hit), 
						result,found_pos, 4, &mid, 0);
						
	EXPECT_GE(ret, -2);
	
	table_id=Maat_table_register(g_feather,not_hit_table_name);
	ASSERT_GT(table_id, 0);
	Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_LAST_REGION,  NULL, 0);
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, string_should_not_hit, strlen(string_should_not_hit), 
						result,found_pos, 4, &mid, 0);
	EXPECT_EQ(ret, -2);
	Maat_clean_status(&mid);

}

TEST(NOTLogic, ScanIrrelavantAtLast)
{
	const char* string_should_hit="This string ONLY contains must-contained-string-of-rule-144.";
	const char* string_irrelevant="This string contiains nothing to hit.";
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* hit_table_name="HTTP_URL", *not_hit_table_name="KEYWORDS_TABLE";
	scan_status_t mid=NULL;
	table_id=Maat_table_register(g_feather,hit_table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, string_should_hit, strlen(string_should_hit), 
						result,found_pos, 4, &mid, 0);						
	EXPECT_GE(ret, -2);

	table_id=Maat_table_register(g_feather, not_hit_table_name);
	ASSERT_GT(table_id, 0);
	
	Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_LAST_REGION,  NULL, 0);
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, string_irrelevant, strlen(string_irrelevant), 
					result,found_pos, 4, &mid, 0);
	
	EXPECT_EQ(ret, 1);
	Maat_clean_status(&mid);

}
TEST(NOTLogic, ScanNotIP)
{
	const char* string_should_hit="This string ONLY contains must-contained-string-of-rule-145.";
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* hit_table_name="HTTP_URL", *not_hit_table_name="IP_CONFIG";
	scan_status_t mid=NULL;
	table_id=Maat_table_register(g_feather,hit_table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, string_should_hit, strlen(string_should_hit), 
						result,found_pos, 4, &mid, 0);						
	EXPECT_GE(ret, -2);
	
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr.addrtype=ADDR_TYPE_IPV4;
	inet_pton(AF_INET,"10.0.6.205",&(v4_addr.saddr));
	v4_addr.source=htons(50001);
	inet_pton(AF_INET,"10.0.6.201",&(v4_addr.daddr));
	v4_addr.dest=htons(80);
	ipv4_addr.v4=&v4_addr;

	table_id=Maat_table_register(g_feather, not_hit_table_name);
	ASSERT_GT(table_id, 0);
	
	Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_LAST_REGION,  NULL, 0);	
	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result, 4, &mid,0);
	
	
	EXPECT_EQ(ret, -2);
	Maat_clean_status(&mid);

}

TEST(Helper, ReadColumn)
{
	const char* ip="192.168.0.1";
	const char* tmp="something";
	char line[256];
	snprintf(line, sizeof(line), "1\t%s\t%s",ip, tmp);
	size_t offset=0, len=0;
	int ret=0;
	ret=Maat_helper_read_column(line, 2, &offset, &len);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(0, strncmp(ip, line+offset, len));
	
	ret=Maat_helper_read_column(line, 3, &offset, &len);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(0, strncmp(tmp, line+offset, len));

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
	Maat_stream_scan_digest_end(&sp);
	EXPECT_GE(hit_cnt, 1);
	Maat_clean_status(&mid);
	return;
}
TEST(StringScan, GBKEncodedURL)
{
	const char* url_gb2312="www.baidu.com/?wd=C%23%D6%D0%B9%FA";
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	
	const char* table_name="HTTP_URL";	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, url_gb2312, strlen(url_gb2312), 
						result,found_pos, 4,
						&mid, 0);
	EXPECT_GE(ret, 1);
	Maat_clean_status(&mid);
	return;
}
TEST(StringScan, UTF8EncodedURL)
{
	const char* url_utf8="www.google.com/?q=C%23%E4%B8%AD%E5%9B%BD";
	const char* url_utf8_qs="googlevideo.com/qs?nh=%2CIgpwcjA0LnN2bzAzKgkxMjcuMC4wLjE";
	const char* url_utf8_long="https://r1---sn-35153iuxa-5a56.googlevideo.com/videoplayback?clen=14143675&sparams=clen%2Cdur%2Cei%2Cgir%2Cid%2Cinitcwndbps%2Cip%2Cipbits%2Citag%2Ckeepalive%2Clmt%2Cmime%2Cmm%2Cmn%2Cms%2Cmv%2Cpl%2Crequiressl%2Csource%2Cexpire&initcwndbps=11060000&ipbits=0&c=WEB&lmt=1545866423716040&source=youtube&dur=995.221&requiressl=yes&txp=5511222&mime=audio%2Fwebm&gir=yes&signature=D1BAE8D85C01B7761609D5143FEC67B33EA35A3E.BDBFB0F6E657EC8D5E9D42015378B885CA87364E&key=yt6&itag=251&expire=1548352912&fvip=1&ei=MKlJXJjUMY6p7QSx2p3gDA&ms=au%2Crdu&mt=1548331263&mv=m&pl=24&ip=178.89.4.220&keepalive=yes&id=o-AMlnrhwQnnM19Tz8lVnzpUT7bbAsrbPPZBl9M1Sx2sw2&mm=31%2C29&mn=sn-35153iuxa-5a56%2Csn-n8v7znz7&alr=yes&cpn=nCaBFGicSajzXMjH&cver=2.20190119&range=266995-528469&rn=17&rbuf=16106";
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	
	const char* table_name="HTTP_URL";	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	memset(result, 0, sizeof(result));
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, url_utf8, strlen(url_utf8), 
						result,found_pos, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 129);
	Maat_clean_status(&mid);
	
	memset(result, 0, sizeof(result));
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, url_utf8_qs, strlen(url_utf8_qs), 
						result,found_pos, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 142);
	Maat_clean_status(&mid);

	
	memset(result, 0, sizeof(result));
	ret=Maat_full_scan_string(g_feather, table_id,CHARSET_GBK, url_utf8_long, strlen(url_utf8_long), 
						result,found_pos, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 147);
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
TEST(StringScan, Expr8)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	const char* scan_data="string1, string2, string3, string4, string5, string6, string7, string8";
	const char* table_name="KEYWORDS_TABLE";	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, scan_data, strlen(scan_data), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 182);
	Maat_clean_status(&mid);

	return;
}
TEST(StringScan, RegexWithNotContains)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	//The rule is contains
	const char* should_NOT_hit_scan_data="new.qq.com/rain/a/TWF2021042600418000";
	const char* should_hit_scan_data="fakesina.com/rain/a/TWF2021042600418000";
	const char* table_name="HTTP_URL";	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(g_feather,table_name);
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, should_NOT_hit_scan_data, strlen(should_NOT_hit_scan_data), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 0);
	Maat_clean_status(&mid);

	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, should_hit_scan_data, strlen(should_hit_scan_data), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 183);
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
	memset(result, 0 , sizeof(result));
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
#define StringScan_StreamScanUTF8 1
TEST(StringScan, StreamScanUTF8)
{
	//Bug report: https://mantis.mesalab.cn/view.php?id=712
	int table_id=0,ret=0;
	int read_size=0,pass_flag=0;
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	const char* table_name="TROJAN_PAYLOAD";
	const char* fn="./testdata/jd.com.html";
	FILE* fp=fopen(fn,"r");
	ASSERT_FALSE(fp==NULL);

	char scan_data[2048];
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
	EXPECT_EQ(result[0].config_id, 157);
	
	Maat_stream_scan_string_end(&sp);
	free(hit_detail);
	fclose(fp);
	Maat_clean_status(&mid);
	return;
}

void accept_tags_entry_cb(int table_id,const char* table_line,void* u_para)
{
	int* callback_times=(int*)u_para;
	char status[32]={0};
	int entry_id=-1,seq=-1;
	int is_valid=0;
	sscanf(table_line,"%d\t%s\t%d\t%d",&seq,status,&entry_id,&is_valid);
	EXPECT_STREQ(status ,"SUCCESS");
	(*callback_times)++;
	return;
}

TEST(Policy, PluginRuleTags1)
{
#define RuleTags_Plugin
	int ret=0;

	int table_id=Maat_table_register(g_feather,"TEST_EFFECTIVE_RANGE_TABLE");
	ASSERT_GT(table_id, 0);

	int callback_times=0;
	ret=Maat_table_callback_register(g_feather, table_id,
							NULL,
							accept_tags_entry_cb, 
							NULL,
							&callback_times);
	
	ASSERT_GE(ret, 0);
	EXPECT_EQ(callback_times, 5);
	return;
}
void accept_tags_entry2_cb(int table_id,const char* table_line,void* u_para)
{
	int* callback_times=(int*)u_para;
	(*callback_times)++;
	return;
}

TEST(Policy, PluginRuleTags2)
{
#define RuleTags_Plugin2
	int ret=0;

	int table_id=Maat_table_register(g_feather,"IR_INTERCEPT_IP");
	ASSERT_GT(table_id, 0);

	int callback_times=0;
	ret=Maat_table_callback_register(g_feather, table_id,
							NULL,
							accept_tags_entry2_cb, 
							NULL,
							&callback_times);
	
	ASSERT_GE(ret, 0);
	EXPECT_EQ(callback_times, 2);
	return;
}

TEST(Policy, CompileRuleTags)
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

void compile_ex_param_new(int idx, const struct Maat_rule_t* rule, const char* srv_def_large, 
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
void compile_ex_param_free(int idx, const struct Maat_rule_t* rule, const char* srv_def_large, MAAT_RULE_EX_DATA* ad, long argl, void *argp)
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
void compile_ex_param_dup(int idx,	MAAT_RULE_EX_DATA *to, MAAT_RULE_EX_DATA *from, long argl, void *argp)
{
	struct rule_ex_param* from_param=*((struct rule_ex_param**)from);
	pthread_mutex_lock(&(from_param->lock));
	from_param->ref_cnt++;
	pthread_mutex_unlock(&(from_param->lock));
	*((struct rule_ex_param**)to)=from_param;
	return;
}



TEST(Policy, CompileEXData)
{
#define rule_EX_data_index

	int ret=0;
	int table_id=0, ex_data_counter=0;
	scan_status_t mid=NULL;
	struct Maat_rule_t result[4];
	const char* url="i.ytimg.com/vi/OtCNcustg_I/hqdefault.jpg?sqp=-oaymwEZCNACELwBSFXyq4qpAwsIARUAAIhCGAFwAQ==&rs=AOn4CLDOp_5fHMaCA9XZuJdCRv4DNDorMg";
	const char* table_name="HTTP_URL";
	const char* expect_name="I have a name";
	table_id=Maat_table_register(g_feather, table_name);
	ASSERT_GT(table_id, 0);
	
	int ex_param_idx=Maat_rule_get_ex_new_index(g_feather, "COMPILE_ALIAS", 
													compile_ex_param_new, compile_ex_param_free, compile_ex_param_dup,
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
	compile_ex_param_free(0, NULL, NULL, &ex_data, 0, NULL);
	Maat_clean_status(&mid);
	return;
}
TEST(Policy, SubGroup)
{
#define TestSubGroup
	int ret=0, table_id=0;
	const char* scan_string="ceshi6@mailhost.cn";
	struct Maat_rule_t result[4];
	memset(result, 0, sizeof(result));
	
	scan_status_t mid=NULL;
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr.addrtype=ADDR_TYPE_IPV4;
	inet_pton(AF_INET,"10.0.6.205",&(v4_addr.saddr));
	v4_addr.source=htons(50001);
	inet_pton(AF_INET,"10.0.6.201",&(v4_addr.daddr));
	v4_addr.dest=htons(80);
	ipv4_addr.v4=&v4_addr;

	table_id=Maat_table_register(g_feather,"MAIL_ADDR");
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, scan_string, strlen(scan_string), 
						result,NULL, 4, &mid, 0);
	EXPECT_EQ(ret, -2);
	
	table_id=Maat_table_register(g_feather, "IP_CONFIG");	
	ASSERT_GT(table_id, 0);
	
	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result, 4, &mid,0);	
	
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 153);
	
	Maat_clean_status(&mid);
	return;
}

TEST(Policy, EvaluationOrder)
{
#define EvaluationOrder
	int ret=0, table_id=0;
	size_t i=0;
	const char* url="cavemancircus.com/2019/12/27/pretty-girls-6/";
	struct Maat_rule_t result[4];
	memset(result, 0, sizeof(result));
	scan_status_t mid=NULL;
	
	table_id=Maat_table_register(g_feather, "HTTP_URL");
	ASSERT_GT(table_id, 0);

	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, url, strlen(url), 
						result+i, NULL, 4-i,
						&mid, 0);
	EXPECT_EQ(ret, 3);
	EXPECT_EQ(result[i].config_id, 166);
	EXPECT_EQ(result[i+1].config_id, 167);
	EXPECT_EQ(result[i+2].config_id, 168);
	i+=ret;

	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr.addrtype=ADDR_TYPE_IPV4;
	inet_pton(AF_INET,"192.168.23.23",&(v4_addr.saddr));
	v4_addr.source=htons(50001);
	inet_pton(AF_INET,"172.0.6.233",&(v4_addr.daddr));
	v4_addr.dest=htons(80);
	ipv4_addr.v4=&v4_addr;

	table_id=Maat_table_register(g_feather, "IP_PLUS_CONFIG");	
	ASSERT_GT(table_id, 0);
	
	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result+i, 4-i, &mid,0);	
	
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[i].config_id, 165);
	i+=ret;
	
	ret=Maat_rule_sort_by_evaluation_order(g_feather, result, i);
	EXPECT_EQ(ret, i);
	EXPECT_EQ(result[0].config_id, 165);
	EXPECT_EQ(result[1].config_id, 166);
	EXPECT_EQ(result[2].config_id, 167);
	EXPECT_EQ(result[3].config_id, 168);
	Maat_clean_status(&mid);

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
TEST(Hierarchy, VirtualOfOnePhysical)
{
#define  Hierarchy_VirtualOfOnePhysical
	int ret=0, table_id=0;
	const char* http_content="Batman\\:Take me Home.Superman/:Fine,stay with me.";
	const char* http_url="https://blog.csdn.net/littlefang/article/details/8213058";
	
	struct Maat_rule_t result[4];
	memset(result, 0, sizeof(result));
	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(g_feather, "HTTP_URL");	
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, http_url, strlen(http_url), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, -2);
	

	table_id=Maat_table_register(g_feather, "HTTP_RESPONSE_KEYWORDS");
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, http_content, strlen(http_content), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 160);	
	Maat_clean_status(&mid);

	const char* should_not_hit="2018-10-05 is a keywords of table KEYWORDS_TABLE. Should not hit.";

	mid=NULL;
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, should_not_hit, strlen(should_not_hit), 
						result, NULL, 4, &mid, 0);
	EXPECT_EQ(ret, -2);
	Maat_clean_status(&mid);

	return;
}
TEST(Hierarchy, VirtualOfTwoPhysical)
{
#define  Hierarchy_VirtualWithTwoPhysical
	int ret=0, table_id=0;
	const char* sni="sports.example.com";
	int cat_id=1724;
	
	
	struct Maat_rule_t result[4];
	memset(result, 0, sizeof(result));
	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(g_feather, "VIRTUAL_SSL_SNI");	
	ASSERT_GT(table_id, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_UTF8, sni, strlen(sni), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 180);
	Maat_clean_status(&mid);
	
	memset(result, 0, sizeof(result));
	ret=Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_DISTRICT, "fqdn_cat_id", strlen("fqdn_cat_id"));
	ASSERT_EQ(ret, 0);
	
	ret=Maat_scan_intval(g_feather, table_id, cat_id, result,4, &mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 180);
	
	Maat_clean_status(&mid);

	return;
}

TEST(Hierarchy, VirtualWithVirtual)
{
#define  Hierarchy_VirtualWithVirtual
	int ret=0, table_id=0;
	const char* http_req_hdr_ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36";
	const char* http_resp_hdr_cookie="uid=12345678;BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; sugstore=1;";
	
	struct Maat_rule_t result[4];
	memset(result, 0, sizeof(result));
	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(g_feather, "HTTP_REQUEST_HEADER");	
	ASSERT_GT(table_id, 0);
	
	ret=Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_DISTRICT, "User-Agent", strlen("User-Agent"));
	ASSERT_EQ(ret, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, http_req_hdr_ua, strlen(http_req_hdr_ua), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, -2);
	

	table_id=Maat_table_register(g_feather, "HTTP_RESPONSE_HEADER");
	ASSERT_GT(table_id, 0);

	ret=Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_DISTRICT, "Cookie", strlen("Cookie"));
	ASSERT_EQ(ret, 0);

	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 162);	

	Maat_clean_status(&mid);

	return;
}

TEST(Hierarchy, OneGroupInTwoVirtual)
{
#define Hierarchy_OneGroupInTwoVirtual
	int ret=0, table_id=0;
	const char* http_resp_hdr_cookie="sessionid=888888;BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; sugstore=1;";
	
	struct Maat_rule_t result[4];
	memset(result, 0, sizeof(result));
	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(g_feather, "HTTP_REQUEST_HEADER");	
	ASSERT_GT(table_id, 0);
	
	ret=Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_DISTRICT, "Cookie", strlen("Cookie"));
	ASSERT_EQ(ret, 0);
	
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, -2);
	

	table_id=Maat_table_register(g_feather, "HTTP_RESPONSE_HEADER");
	ASSERT_GT(table_id, 0);

	ret=Maat_set_scan_status(g_feather, &mid, MAAT_SET_SCAN_DISTRICT, "Cookie", strlen("Cookie"));
	ASSERT_EQ(ret, 0);

	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_GBK, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 163);	

	Maat_clean_status(&mid);

	return;
}
TEST(Hierarchy, TwoVirtualInOneClause)
{
#define Hierarchy_TwoVirtualInOneClause
	int ret=0, table_id=0;
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;

	const char* src_asn="AS1234", *dst_asn="AS2345";
	const char* my_county="Greece.Sparta";
	
	struct Maat_rule_t result[4];
	memset(result, 0, sizeof(result));
	
	scan_status_t mid=NULL;


	//--------------------------------------
	//			Source ASN & Dest ASN
	//--------------------------------------

	table_id=Maat_table_register(g_feather, "SOURCE_IP_ASN");	
	ASSERT_GT(table_id, 0);
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_UTF8, src_asn, strlen(src_asn), 
						result, NULL, 4, &mid, 0);
	EXPECT_EQ(ret, -2);

	table_id=Maat_table_register(g_feather, "DESTINATION_IP_ASN");	
	ASSERT_GT(table_id, 0);
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_UTF8, dst_asn, strlen(dst_asn), 
						result, NULL, 4, &mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 178);

	Maat_clean_status(&mid);

	
	//--------------------------------------
	//			Source IP & Dest ASN
	//--------------------------------------
	ipv4_addr_set(&ipv4_addr, &v4_addr, "192.168.40.88", 8888, "47.92.55.81", 443);
	
	table_id=Maat_table_register(g_feather, "IP_CONFIG");	
	ASSERT_GT(table_id, 0);
	ret=Maat_scan_proto_addr(g_feather, table_id, &ipv4_addr, 6, result, 4, &mid, 0);

	EXPECT_EQ(ret, -2);

	table_id=Maat_table_register(g_feather, "DESTINATION_IP_ASN");	
	ASSERT_GT(table_id, 0);
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_UTF8, dst_asn, strlen(dst_asn), 
						result, NULL, 4, &mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 178);
	
	Maat_clean_status(&mid);	

	//--------------------------------------
	//			Source Geo & Dest ASN
	//--------------------------------------

	table_id=Maat_table_register(g_feather, "SOURCE_IP_GEO");	
	ASSERT_GT(table_id, 0);
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_UTF8, my_county, strlen(my_county), 
						result, NULL, 4, &mid, 0);
	EXPECT_EQ(ret, -2);

	table_id=Maat_table_register(g_feather, "DESTINATION_IP_ASN");	
	ASSERT_GT(table_id, 0);
	ret=Maat_full_scan_string(g_feather, table_id, CHARSET_UTF8, dst_asn, strlen(dst_asn), 
						result, NULL, 4, &mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, 178);

	Maat_clean_status(&mid);

	return;
}


class MaatFileTest : public testing::Test 
{

protected:
	static void SetUpTestCase()
	{
		const char* rule_folder="./ntcrule/full/index";
	  	logger=MESA_create_runtime_log_handle("test_maat_file.log",0);
		const char* table_info="./file_test_tableinfo.conf";
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
void* MaatFileTest::logger;

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
	static int linger_timeout;
};
Maat_feather_t MaatCmdTest::_shared_feather;

void* MaatCmdTest::logger;

int MaatCmdTest::linger_timeout;
int test_add_expr_command(struct Maat_command_batch* batch, Maat_feather_t feather, const char* region_table, int config_id, int timeout, int label_id, const char* keywords)
{
	char huge_serv_def[1024*2];
	memset(huge_serv_def,'s',sizeof(huge_serv_def)-1);
	huge_serv_def[sizeof(huge_serv_def)-1]='\0';
	struct Maat_rule_t compile;
	memset(&compile, 0, sizeof(compile));
	compile.config_id=config_id;
	strcpy(compile.service_defined, "maat_command");
	Maat_command_batch_set_compile(batch, MAAT_OP_ADD, &compile, "COMPILE", huge_serv_def, 1, label_id, timeout);

	struct Maat_cmd_region region;
	memset(&region,0,sizeof(region));
	region.region_id=Maat_command_get_new_region_id(feather);
	region.region_type=REGION_EXPR;
	region.table_name=region_table;
	region.expr_rule.district=NULL;
	region.expr_rule.keywords=keywords;
	region.expr_rule.expr_type=EXPR_TYPE_AND;
	region.expr_rule.match_method=MATCH_METHOD_SUB;
	region.expr_rule.hex_bin=UNCASE_PLAIN;

	struct Maat_cmd_group2compile g2c;
	memset(&g2c, 0, sizeof(g2c));
	g2c.group_id=Maat_command_get_new_group_id(feather);;
	g2c.table_name="GROUP2COMPILE";
	g2c.compile_id=config_id;
	g2c.clause_index=1;
	Maat_command_batch_set_group2compile(batch, MAAT_OP_ADD, &g2c);
	Maat_command_batch_set_region(batch, MAAT_OP_ADD, &region, g2c.group_id);
	return 0;

}
int test_add_expr_command_simple(Maat_feather_t feather, const char* region_table, int config_id, int timeout, int label_id, const char* keywords)
{
	struct Maat_command_batch* batch=NULL;
	batch=Maat_command_batch_new(feather);
	test_add_expr_command(batch, feather, region_table, config_id, timeout, label_id, keywords);
	Maat_command_batch_commit(batch);
	return 0;
}

int del_command(Maat_feather_t feather, int config_id)
{
	int ret=0;
	struct Maat_rule_t compile;
	memset(&compile,0,sizeof(compile));
	compile.config_id=config_id;
	ret=Maat_command_raw_set_compile(feather, MAAT_OP_DEL, &compile, "COMPILE", NULL, 1, 0, 0);
	return ret;
}
TEST_F(MaatCmdTest, SetIP)
{
	struct Maat_rule_t compile;
	int config_id=0, timeout=4;
	long long version_before=0;
	const char* region_table="IP_CONFIG";
	int ret=0;
	memset(&compile, 0, sizeof(compile));
	Maat_feather_t feather=MaatCmdTest::_shared_feather;

	//MUST acquire by Maat_cmd_incrby to guarantee a unique compile ID.
	config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	compile.config_id=config_id;
	
	strcpy(compile.service_defined, "maat_command");
	struct Maat_command_batch* batch=NULL;
	batch=Maat_command_batch_new(feather);
	//MUST acqire by function, because Maat_cmd_t has some hidden members.
	Maat_command_batch_set_compile(batch, MAAT_OP_ADD, &compile, "COMPILE", NULL, 1, 0, timeout);

	struct Maat_cmd_group2compile g2c;
	memset(&g2c, 0, sizeof(g2c));
	g2c.group_id=Maat_command_get_new_group_id(feather);
	g2c.compile_id=compile.config_id;
	g2c.clause_index=1;
	g2c.table_name="GROUP2COMPILE";
	Maat_command_batch_set_group2compile(batch, MAAT_OP_ADD, &g2c);



	

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

	return;

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
	int output_id_cnt=0;
	struct Maat_rule_t result;
	int timeout=0;//seconds
	int label_id=5210;
	long long version_before=0;
	Maat_feather_t feather=MaatCmdTest::_shared_feather;
	
	Maat_str_escape(escape_buff1, sizeof(escape_buff1),keywords1);
	Maat_str_escape(escape_buff2, sizeof(escape_buff2),keywords2);
	snprintf(keywords,sizeof(keywords),"%s&%s",escape_buff1,escape_buff2);
	config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 2);
	
	ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version_before, sizeof(version_before));
	struct Maat_command_batch* batch=NULL;
	batch=Maat_command_batch_new(feather);
	
	test_add_expr_command(batch, feather, table_name, config_id-1, 0, label_id, keywords);
	test_add_expr_command(batch, feather, table_name, config_id, 0, label_id, keywords);
	ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version_before, sizeof(version_before));
	Maat_command_batch_commit(batch);
	
	wait_for_cmd_effective(feather, version_before);
	
	table_id=Maat_table_register(feather, table_name);
	ASSERT_GT(table_id, 0);
	memset(&result, 0, sizeof(result));
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result,NULL, 1,
						&mid, 0);
	EXPECT_GT(ret, 0);
	EXPECT_TRUE(result.config_id==config_id||result.config_id==config_id-1);

	Maat_clean_status(&mid);

	struct Maat_cmd_key* keys=NULL;
	output_id_cnt=Maat_cmd_key_select(feather,label_id, &keys);
	EXPECT_TRUE(keys[0].rule_id==config_id||keys[0].rule_id==config_id-1);
	
	Maat_cmd_key_free(&keys, output_id_cnt);
	usleep(WAIT_FOR_EFFECTIVE_US);//waiting for commands go into effect	
	del_command(feather, config_id-1);
	del_command(feather, config_id);

	usleep(WAIT_FOR_EFFECTIVE_US);//waiting for commands go into effect
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result,NULL, 1,
						&mid, 0);
	EXPECT_EQ(ret, -2); //compile is deleted, but region and groups are still there.
	Maat_clean_status(&mid);
	
	timeout=1;
	config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	batch=Maat_command_batch_new(feather);
	test_add_expr_command(batch, feather, table_name, config_id, timeout, label_id, keywords);
	Maat_command_batch_commit(batch);

	usleep(timeout*1000*1000+WAIT_FOR_EFFECTIVE_US);
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result,NULL, 1,
						&mid, 0);
	EXPECT_EQ(ret, -2);	
	Maat_clean_status(&mid);
}
TEST_F(MaatCmdTest, SetExpr8)
{
	const char* scan_data8="string1, string2, string3, string4, string5, string6, string7, string8";
	const char* scan_data7="string1, string2, string3, string4, string5, string6, string7";
	
	const char* compile_table_name="COMPILE";
	const char* table_name="KEYWORDS_TABLE";
	const char* g2c_tn="GROUP2COMPILE";
	
	const char* keywords8="string1&string2&string3&string4&string5&string6&string7&string8";
	const char* keywords7="string1&string2&string3&string4&string5&string6&string7";

	struct Maat_rule_t compile1;
	struct Maat_cmd_group2compile group1;
	struct Maat_cmd_region region1;

	Maat_feather_t feather=MaatCmdTest::_shared_feather;


	memset(&compile1, 0, sizeof(compile1));
	compile1.config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile1, compile_table_name, NULL, 1, 0, 0);

	
	//group1->compile1
	memset(&group1, 0, sizeof(group1));
	group1.group_id=Maat_command_get_new_group_id(feather);
	group1.table_name=g2c_tn;
	group1.virtual_table_name="null";
	group1.compile_id=compile1.config_id;
	group1.clause_index=1;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group1);


	//region1->group1->compile1
	
	memset(&region1, 0, sizeof(region1));
	region1.region_id=Maat_command_get_new_region_id(feather);
	region1.region_type=REGION_EXPR;
	region1.table_name=table_name;
	region1.expr_rule.keywords=keywords8;
	region1.expr_rule.expr_type=EXPR_TYPE_AND;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region1, group1.group_id);

	usleep(WAIT_FOR_EFFECTIVE_US);//waiting for commands go into effect

	struct Maat_rule_t result;
	scan_status_t mid=NULL;
	int table_id=0, ret=0;
	table_id=Maat_table_register(feather, table_name);
	ASSERT_GT(table_id, 0);
	memset(&result, 0, sizeof(result));

	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, scan_data8, strlen(scan_data8), 
						&result, NULL, 1,
						&mid, 0);	
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result.config_id, compile1.config_id);
	Maat_clean_status(&mid);


	Maat_command_raw_set_region(feather, MAAT_OP_DEL, &region1, group1.group_id);
	region1.expr_rule.keywords=keywords7;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region1, group1.group_id);

	usleep(WAIT_FOR_EFFECTIVE_US);//waiting for commands go into effect

	memset(&result, 0, sizeof(result));
	mid=NULL;
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data7, strlen(scan_data7), 
						&result, NULL, 1,
						&mid, 0);	
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result.config_id, compile1.config_id);
	Maat_clean_status(&mid);
}

TEST_F(MaatCmdTest,   RuleIDRecycle)
{
	const char* table_name="HTTP_URL";
	const char* scan_data="Reuse rule ID is allowed.";
	const char* keywords="Reuse&rule";
	Maat_feather_t feather=MaatCmdTest::_shared_feather;

	struct Maat_rule_t result;
	scan_status_t mid=NULL;
	memset(&result, 0, sizeof(result));
	int table_id=0;
	table_id=Maat_table_register(feather,table_name);
	ASSERT_GT(table_id, 0);

	int rule_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	int label_id=5211, ret=0;
	
	test_add_expr_command_simple(feather,table_name,rule_id, 0, label_id, keywords);
	

	usleep(WAIT_FOR_EFFECTIVE_US);//waiting for commands go into effect
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result, NULL, 1,
						&mid, 0);
	Maat_clean_status(&mid);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result.config_id, rule_id);

	del_command(feather, rule_id);
	usleep(WAIT_FOR_EFFECTIVE_US);//waiting for commands go into effect
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result, NULL, 1,
						&mid, 0);
	Maat_clean_status(&mid);
	EXPECT_EQ(ret, -2);

	test_add_expr_command_simple(feather,table_name,rule_id, 0, label_id, keywords);

	usleep(WAIT_FOR_EFFECTIVE_US);//waiting for commands go into effect
	memset(&result, 0, sizeof(result));
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result, NULL, 1,
						&mid, 0);
	Maat_clean_status(&mid);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result.config_id, rule_id);
	return;
}
TEST_F(MaatCmdTest,   ReturnRuleIDWithDescendingOrder)
{
	const char* table_name="HTTP_URL";
	const char* scan_data="This string will hit mulptiple rules.";
	const char* keywords="string\\bwill\\bhit";
	Maat_feather_t feather=MaatCmdTest::_shared_feather;


	int table_id=0;
	table_id=Maat_table_register(feather, table_name);
	ASSERT_GT(table_id, 0);

	int i=0, repeat_times=4;
	struct Maat_rule_t result[8];
	int expect_ruleid[8];
	scan_status_t mid=NULL;

	int rule_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", repeat_times);
	int label_id=5211, ret=0;
	struct Maat_command_batch* batch=NULL;
	batch=Maat_command_batch_new(feather);
	for(i=0; i<repeat_times; i++)
	{
		//add in ascending order
		expect_ruleid[i]=rule_id+1-repeat_times+i;
		test_add_expr_command(batch, feather, table_name,rule_id+1-repeat_times+i, 0, label_id, keywords);
	}
	Maat_command_batch_commit(batch);
	
	usleep(WAIT_FOR_EFFECTIVE_US);//waiting for commands go into effect
	memset(&result, 0, sizeof(result));
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result, NULL, 8,
						&mid, 0);
	Maat_clean_status(&mid);
	EXPECT_EQ(ret, repeat_times);
	for(i=0;i<repeat_times;i++)
	{
		//return in ascending order
		EXPECT_EQ(result[i].config_id, expect_ruleid[repeat_times-i-1]);
	}
	return;
}
#define MaatCmdTest_SubGroup	0
TEST_F(MaatCmdTest,    SubGroup)
{

	const char* table_name="HTTP_URL";
	const char* g2c_tn="GROUP2COMPILE";
	const char* g2g_tn="GROUP2GROUP";
	const char* compile_table_name="COMPILE";
	const char* scan_data1="www.v2ex.com/t/573028#程序员的核心竞争力是什么";
	const char* keyword1="程序员&核心竞争力";

	const char* scan_data2="https://ask.leju.com/bj/detail/12189672562229248/?bi=tg&type=sina-pc&pos=index-dbtlwzl&wt_campaign=M_5CE750003F393&wt_source=PDPS_514ACACFD9E770";
//	const char* keyword2="ask.leju.com/bj/detail/12189672562229248/?bi=tg&type=sina-pc&pos=index-dbtlwzl&wt_campaign=M_5CE750003F393&wt_source=PDPS_514ACACFD9E770";
	const char* keyword2="ask.leju.com/b&/detail/12189672562229248/?&?bi=tg\\&type=sina-pc\\&&\\&pos=index-dbtlwzl\\&&\\&type=sina-pc\\&pos=index-dbtlwzl\\&";
	Maat_feather_t feather=MaatCmdTest::_shared_feather;
	int table_id=0;
	table_id=Maat_table_register(feather, table_name);
	struct Maat_rule_t compile1, compile2;
//	struct Maat_group_t group1, group2, group3;
	struct Maat_cmd_group2compile group1, group2_g2c;
	struct Maat_cmd_group2group group2, group3;
	struct Maat_cmd_region region1, region2;
	memset(&compile1, 0, sizeof(compile1));
	compile1.config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile1, compile_table_name, NULL, 1, 0, 0);

	memset(&compile2, 0, sizeof(compile2));
	compile2.config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile2, compile_table_name, NULL, 1, 0, 0);

	//group1->compile1
	memset(&group1, 0, sizeof(group1));
	group1.group_id=Maat_command_get_new_group_id(feather);
	group1.table_name=g2c_tn;
	group1.compile_id=compile1.config_id;
	group1.clause_index=1;
	group1.not_flag=0;
	group1.virtual_table_name="null";
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group1);

	//group1->compile2
	group1.compile_id=compile2.config_id;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group1);

	/*group2->group1->compile1
	              \
	               \__compile2
	*/
	memset(&group2, 0, sizeof(group2));
	group2.group_id=Maat_command_get_new_group_id(feather);
	group2.table_name=g2g_tn;
	group2.superior_group_id=group1.group_id;

	Maat_command_raw_set_group2group(feather, MAAT_OP_ADD, &group2);


	/*region1->group2->group1->compile1
	                        \
	                         \_compile2
	*/
	memset(&region1, 0, sizeof(region1));
	region1.region_id=Maat_command_get_new_region_id(feather);
	region1.region_type=REGION_EXPR;
	region1.table_name=table_name;
	region1.expr_rule.keywords=keyword1;
	region1.expr_rule.expr_type=EXPR_TYPE_AND;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region1, group2.group_id);
	sleep(4);
	struct Maat_rule_t result[4];
	memset(&result, 0, sizeof(result));
	
	scan_status_t mid=NULL;
	int ret=0;
	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, scan_data1, strlen(scan_data1), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 2);
	EXPECT_EQ(result[0].config_id, compile2.config_id);
	EXPECT_EQ(result[1].config_id, compile1.config_id);
	Maat_clean_status(&mid);


	/*region1->group2->group1->compile1
						\
	                     \--X--compile2
	*/
	Maat_command_raw_set_group2compile(feather, MAAT_OP_DEL, &group1);
	sleep(1);
	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, scan_data1, strlen(scan_data1), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, compile1.config_id);
	Maat_clean_status(&mid);


	/*region1->group2->group1--X--
				 \
	              \->compile2
	*/
	group1.compile_id=compile1.config_id;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_DEL, &group1);
	Maat_command_raw_set_compile(feather, MAAT_OP_DEL, &compile1, compile_table_name, NULL, 1, 0, 0);

	memset(&group2_g2c, 0, sizeof(group2_g2c));
	group2_g2c.group_id=group2.group_id;
	group2_g2c.table_name=g2c_tn;
	group2_g2c.compile_id=compile2.config_id;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group2_g2c);


	sleep(1);
	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, scan_data1, strlen(scan_data1), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, compile2.config_id);
	Maat_clean_status(&mid);


	/*region1->group2->group1--X--
				 \
	              \->compile2
	              
	  region2->group3
	*/

	memset(&group3, 0, sizeof(group3));
	group3.group_id=Maat_command_get_new_group_id(feather);
	group3.superior_group_id=group1.group_id;
	group3.table_name=g2g_tn;
	Maat_command_raw_set_group2group(feather, MAAT_OP_ADD, &group3);

	memset(&region2, 0, sizeof(region2));
	region2.region_id=Maat_command_get_new_region_id(feather);
	region2.region_type=REGION_EXPR;
	region2.table_name=table_name;
	region2.expr_rule.keywords=keyword2;
	region2.expr_rule.expr_type=EXPR_TYPE_AND;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region2, group3.group_id);

	sleep(1);
	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, scan_data2, strlen(scan_data2), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, -2);
	Maat_clean_status(&mid);

	/*region1->group2->group1--X--
				 \
	              \->compile2
	  region2->group3
	*/
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile1, compile_table_name, NULL, 1, 0, 0);
	group1.compile_id=compile1.config_id;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group1);

	Maat_command_raw_set_compile(feather, MAAT_OP_DEL, &compile1, compile_table_name, NULL, 1, 0, 0);
	group1.compile_id=compile1.config_id;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_DEL, &group1);

	sleep(1);
	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, scan_data1, strlen(scan_data1), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, compile2.config_id);

	Maat_clean_status(&mid);

}
#define MaatCmdTest_RefGroup	0
TEST_F(MaatCmdTest,    RefGroup)
{

	const char* table_name="HTTP_URL";
	const char* g2c_tn="GROUP2COMPILE";
	const char* compile_table_name="COMPILE";
	const char* scan_data1="m.facebook.com/help/2297503110373101?helpref=hc_nav&refid=69";
	const char* keyword1="something-should-not-hit";
	const char* keyword2="facebook.com/help/2297503110373101";

	Maat_feather_t feather=MaatCmdTest::_shared_feather;
	int table_id=0;
	table_id=Maat_table_register(feather, table_name);
	struct Maat_rule_t compile1;
	struct Maat_cmd_group2compile group1, group2;

	struct Maat_cmd_region region1, region2;
	
	int value=0;
	Maat_set_feather_opt(feather, MAAT_OPT_ENABLE_UPDATE, &value, sizeof(value));

	memset(&compile1, 0, sizeof(compile1));
	compile1.config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile1, compile_table_name, NULL, 1, 0, 0);

	//group1->compile1
	memset(&group1, 0, sizeof(group1));
	group1.group_id=Maat_command_get_new_group_id(feather);
	group1.table_name=g2c_tn;
	group1.compile_id=compile1.config_id;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group1);


	//region1->group1->compile1

	memset(&region1, 0, sizeof(region1));
	region1.region_id=Maat_command_get_new_region_id(feather);
	region1.region_type=REGION_EXPR;
	region1.table_name=table_name;
	region1.expr_rule.keywords=keyword1;
	region1.expr_rule.expr_type=EXPR_TYPE_AND;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region1, group1.group_id);
	value=1;
	Maat_set_feather_opt(feather, MAAT_OPT_ENABLE_UPDATE, &value, sizeof(value));

	sleep(1);
	
	value=0;
	Maat_set_feather_opt(feather, MAAT_OPT_ENABLE_UPDATE, &value, sizeof(value));
	//region1->group1-X-compile1
	//                   /
	//                  / 
	//    region2->group2
	memset(&group2, 0, sizeof(group2));
	group2.group_id=Maat_command_get_new_group_id(feather);
	group2.table_name=g2c_tn;
	group2.compile_id=compile1.config_id;

	memset(&region2, 0, sizeof(region2));
	region2.region_id=Maat_command_get_new_region_id(feather);
	region2.region_type=REGION_EXPR;
	region2.table_name=table_name;
	region2.expr_rule.keywords=keyword2;
	region2.expr_rule.expr_type=EXPR_TYPE_AND;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region2, group2.group_id);


	Maat_command_raw_set_compile(feather, MAAT_OP_DEL, &compile1, compile_table_name, NULL, 1, 0, 0);	
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile1, compile_table_name, NULL, 1, 0, 0);	
	Maat_command_raw_set_group2compile(feather, MAAT_OP_DEL, &group1);
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group2);
	value=1;
	Maat_set_feather_opt(feather, MAAT_OPT_ENABLE_UPDATE, &value, sizeof(value));
	
	sleep(1);

	struct Maat_rule_t result[4];
	memset(&result, 0, sizeof(result));
	
	scan_status_t mid=NULL;
	int ret=0;
	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, scan_data1, strlen(scan_data1), 
						result, NULL, 4,
						&mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, compile1.config_id);
	Maat_clean_status(&mid);

}

#define MaatCmdTest_VirtualTable
TEST_F(MaatCmdTest,   VirtualTable)
{
	Maat_feather_t feather=MaatCmdTest::_shared_feather;
	const char* g2c_tn="GROUP2COMPILE";
	const char* compile_table_name="COMPILE";
	const char* region_table_name="HTTP_SIGNATURE";

	struct Maat_rule_t compile1;
	struct Maat_cmd_group2compile group1, group2;
	struct Maat_cmd_region region1, region2;

	memset(&compile1, 0, sizeof(compile1));
	compile1.config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile1, compile_table_name, NULL, 2, 0, 0);

	
	//group1->compile1
	memset(&group1, 0, sizeof(group1));
	group1.group_id=Maat_command_get_new_group_id(feather);
	group1.table_name=g2c_tn;
	group1.virtual_table_name="HTTP_REQUEST_HEADER";
	group1.compile_id=compile1.config_id;
	group1.clause_index=1;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group1);


	//region1->group1->compile1
	memset(&region1, 0, sizeof(region1));
	region1.region_id=Maat_command_get_new_region_id(feather);
	region1.region_type=REGION_EXPR;
	region1.table_name=region_table_name;
	region1.expr_rule.district="User-Agent";
	region1.expr_rule.keywords="AppleWebKit";
	region1.expr_rule.expr_type=EXPR_TYPE_STRING;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region1, group1.group_id);

	//	region1->group1->compile1
	//						/
	//				group2-/
	memset(&group2, 0, sizeof(group2));
	group2.group_id=Maat_command_get_new_group_id(feather);
	group2.table_name=g2c_tn;
	group2.virtual_table_name="HTTP_RESPONSE_HEADER";
	group2.compile_id=compile1.config_id;
	group2.clause_index=2;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group2);


	//region1->group1->compile1
	//					  /
	//   region2->group2-/

	memset(&region2, 0, sizeof(region2));
	region2.region_id=Maat_command_get_new_region_id(feather);
	region2.region_type=REGION_EXPR;
	region2.table_name=region_table_name;
	region2.expr_rule.district="Cookie";
	region2.expr_rule.keywords="uid=12345678;";
	region2.expr_rule.expr_type=EXPR_TYPE_STRING;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region2, group2.group_id);

	sleep(1);

	int ret=0, table_id=0;
	const char* http_req_hdr_ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36";
	const char* http_resp_hdr_cookie="uid=12345678;BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; sugstore=1;";
	
	struct Maat_rule_t result[4];
	memset(result, 0, sizeof(result));
	
	scan_status_t mid=NULL;

	table_id=Maat_table_register(feather, "HTTP_REQUEST_HEADER");	
	ASSERT_GT(table_id, 0);
	
	ret=Maat_set_scan_status(feather, &mid, MAAT_SET_SCAN_DISTRICT, "User-Agent", strlen("User-Agent"));
	ASSERT_EQ(ret, 0);
	
	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, http_req_hdr_ua, strlen(http_req_hdr_ua), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, -2);
	

	table_id=Maat_table_register(feather, "HTTP_RESPONSE_HEADER");
	ASSERT_GT(table_id, 0);

	ret=Maat_set_scan_status(feather, &mid, MAAT_SET_SCAN_DISTRICT, "Cookie", strlen("Cookie"));
	ASSERT_EQ(ret, 0);

	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, compile1.config_id);	

	Maat_clean_status(&mid);

	//Delete group1
	Maat_command_raw_set_group2compile(feather, MAAT_OP_DEL, &group1);
	Maat_command_raw_set_compile(feather, MAAT_OP_DEL, &compile1, compile_table_name, NULL, 2, 0, 0);	
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile1, compile_table_name, NULL, 1, 0, 0);	

	sleep(1);

	table_id=Maat_table_register(feather, "HTTP_RESPONSE_HEADER");
	ASSERT_GT(table_id, 0);

	ret=Maat_set_scan_status(feather, &mid, MAAT_SET_SCAN_DISTRICT, "Cookie", strlen("Cookie"));
	ASSERT_EQ(ret, 0);

	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, compile1.config_id);	
	Maat_clean_status(&mid);
	return;

}


TEST_F(MaatCmdTest, SetLines)
{
	const int TEST_CMD_LINE_NUM=4;
	const struct Maat_cmd_line *p_line[TEST_CMD_LINE_NUM];
	struct Maat_cmd_line line_rule[TEST_CMD_LINE_NUM];
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
	struct Maat_cmd_line line_rule;
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
const char* empty_file_name="An_empty_file";
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
		if(0==strncmp(file2_origin_name, empty_file_name, strlen(empty_file_name)))
		{
			EXPECT_TRUE(0==strncasecmp(file2_localname, "null", strlen("null")));
		}
		else
		{
			EXPECT_TRUE(is_same_file(file2_origin_name, file2_localname));
		}
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
	struct Maat_cmd_line line_rule;
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


// Test empty file, file key is a string "null".
	line_rule.label_id=0;
	line_rule.rule_id=(int)Maat_cmd_incrby(feather,"TEST_PLUG_SEQ", 1);
	line_rule.table_name=table_name;
	snprintf(line, sizeof(line),"%d\t2\t%d\t1\t%s\tredis://%s\t%s\t%s\tEnd",line_rule.rule_id, tag
																			,file1_name, file1_key
																			,empty_file_name, "null");
	line_rule.table_line=line;
	line_rule.expire_after=0;

	g_test_foregin_read_OK=0;
	
	ret=Maat_cmd_set_line(feather, &line_rule, MAAT_OP_ADD);
	EXPECT_EQ(ret, 1);
	usleep(WAIT_FOR_EFFECTIVE_US);//wait for callback triggered.


	EXPECT_EQ(g_test_foregin_read_OK, 1);

	return;
}
struct user_info
{
	char name[256];
	char ip_addr[32];
	int id;
	int ref_cnt;
};
void plugin_EX_new_cb(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	int *counter=(int *)argp;
	struct user_info* u=(struct user_info*)calloc(sizeof(struct user_info), 1);
	int valid=0, tag=0, ret;
	ret=sscanf(table_line, "%d\t%s\t%s%d\t%d", &(u->id), u->ip_addr, u->name, &valid, &tag);
	EXPECT_EQ(ret, 5);
	u->ref_cnt=1;
	*ad=u;
	(*counter)++;
	return;
}
void plugin_EX_free_cb(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	struct user_info* u=(struct user_info*)(*ad);
	u->ref_cnt--;
	if(u->ref_cnt>0) return;
	free(u);
	*ad=NULL;
}
void plugin_EX_dup_cb(int table_id,	MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void *argp)
{
	struct user_info* u=(struct user_info*)(*from);
	u->ref_cnt++;
	*to=u;
}

TEST_F(MaatCmdTest, PluginEXData)
{
#define plugin_EX_data
	Maat_feather_t feather=MaatCmdTest::_shared_feather;

	int ret=0, i=0;
	int table_id=0, ex_data_counter=0;
	const char* table_name="TEST_PLUGIN_EXDATA_TABLE";


	const int TEST_CMD_LINE_NUM=4;
	const struct Maat_cmd_line *p_line[TEST_CMD_LINE_NUM];
	struct Maat_cmd_line line_rule[TEST_CMD_LINE_NUM];
	const char* table_line[TEST_CMD_LINE_NUM]={"1\t192.168.0.1\tmahuateng\t1\t0",
							"2\t192.168.0.2\tliuqiangdong\t1\t0",
							"3\t192.168.0.3\tmayun\t1\t0",
							"4\t192.168.0.4\tliyanhong\t1\t0"};
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

	usleep(WAIT_FOR_EFFECTIVE_US);
	ret=Maat_plugin_EX_register(feather, table_id,
								plugin_EX_new_cb,
								plugin_EX_free_cb,
								plugin_EX_dup_cb,
								NULL,
								0, &ex_data_counter);
	ASSERT_TRUE(ret>=0);
	EXPECT_EQ(ex_data_counter, TEST_CMD_LINE_NUM);
	
	struct user_info* uinfo=NULL;
	uinfo=(struct user_info*)Maat_plugin_get_EX_data(feather, table_id, "192.168.0.2");
	ASSERT_TRUE(uinfo!=NULL);
	EXPECT_EQ(0, strcmp(uinfo->name, "liuqiangdong"));
	EXPECT_EQ(uinfo->id, 2);
	plugin_EX_free_cb(table_id, (void**)&uinfo, 0, NULL);
	
	ret=Maat_cmd_set_lines(feather, p_line+1,1, MAAT_OP_DEL);
	EXPECT_GT(ret, 0);
	
	usleep(WAIT_FOR_EFFECTIVE_US);
	uinfo=(struct user_info*)Maat_plugin_get_EX_data(feather, table_id, "192.168.0.2");
	ASSERT_TRUE(uinfo==NULL);

	return;
}
TEST_F(MaatCmdTest, UpdateIPPlugin)
{
#define IP_Plugin_EX_data
	Maat_feather_t feather=MaatCmdTest::_shared_feather;

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

	usleep(WAIT_FOR_EFFECTIVE_US);

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
	
	ret=Maat_cmd_set_lines(feather, p_line, TEST_CMD_LINE_NUM, MAAT_OP_DEL);
	EXPECT_GT(ret, 0);
	
	usleep(WAIT_FOR_EFFECTIVE_US);
	ret=Maat_ip_plugin_get_EX_data(feather, table_id, &ipv4, (void**)result, 4);
	ASSERT_EQ(ret, 0);

	return;
}


TEST_F(MaatCmdTest, UpdateFQDNPlugin)
{
#define FQDN_Plugin_EX_data
	Maat_feather_t feather=MaatCmdTest::_shared_feather;

	int ret=0, i=0;
	int table_id=0, fqdn_plugin_ex_data_counter=0;
	const char* table_name="TEST_FQDN_PLUGIN_WITH_EXDATA";


	const int TEST_CMD_LINE_NUM=5;
	const struct Maat_cmd_line *p_line[TEST_CMD_LINE_NUM];
	struct Maat_cmd_line line_rule[TEST_CMD_LINE_NUM];
	const char* table_line[TEST_CMD_LINE_NUM]={
				"201\t0\twww.example1.com\tcatid=1\t1",
				"202\t1\t.example1.com\tcatid=1\t1",
				"203\t0\tnews.example1.com\tcatid=2\t1",
				"204\t0\tr3---sn-i3belne6.example2.com\tcatid=3\t1",
				"205\t0\tr3---sn-i3belne6.example2.com\tcatid=3\t1"
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

	usleep(WAIT_FOR_EFFECTIVE_US);

	ret=Maat_fqdn_plugin_EX_register(feather, table_id,
								fqdn_plugin_EX_new_cb,
								fqdn_plugin_EX_free_cb,
								fqdn_plugin_EX_dup_cb,
								0, &fqdn_plugin_ex_data_counter);

	ASSERT_TRUE(ret>=0);
	EXPECT_EQ(fqdn_plugin_ex_data_counter, 5);


	struct fqdn_plugin_ud* result[4];

	ret=Maat_fqdn_plugin_get_EX_data(feather, table_id, "r3---sn-i3belne6.example2.com", (void**)result, 4);
	ASSERT_EQ(ret, 2);
	for(i=0; i<ret; i++)
	{
		fqdn_plugin_EX_free_cb(0, (void**)&(result[i]), 0, NULL);
	}
	
	ret=Maat_cmd_set_lines(feather, p_line+3, TEST_CMD_LINE_NUM-3, MAAT_OP_DEL);
	EXPECT_GT(ret, 0);
	
	usleep(WAIT_FOR_EFFECTIVE_US*5);
	ret=Maat_fqdn_plugin_get_EX_data(feather, table_id, "r3---sn-i3belne6.example2.com", (void**)result, 4);
	ASSERT_EQ(ret, 0);

	return;
}
#define TEST_GROUP_IN_MASS_COMPILES
TEST_F(MaatCmdTest, GroupInMassCompiles)
{
	Maat_feather_t feather=MaatCmdTest::_shared_feather;

	const char* g2c_tn="GROUP2COMPILE";
	const char* compile_table_name="COMPILE";
	const char* table_url="HTTP_URL";
	const char* table_appid="APP_ID";
	int compile_cnt=1000, i=0;
	struct Maat_cmd_group2compile group1, group2, group3;
	struct Maat_rule_t compile[compile_cnt], target_compile;
	struct Maat_cmd_region region_url1, region_url2, region_appid;

	memset(&group1, 0, sizeof(group1));
	group1.group_id=Maat_command_get_new_group_id(feather);
	group1.table_name=g2c_tn;
	group1.clause_index=0;

	memset(&group2, 0, sizeof(group2));
	group2.group_id=Maat_command_get_new_group_id(feather);
	group2.table_name=g2c_tn;
	group2.clause_index=1;

	memset(&group3, 0, sizeof(group3));
	group3.group_id=Maat_command_get_new_group_id(feather);
	group3.table_name=g2c_tn;
	group3.clause_index=2;


	//region_url1->group1
	memset(&region_url1, 0, sizeof(region_url1));
	region_url1.region_id=Maat_command_get_new_region_id(feather);
	region_url1.region_type=REGION_EXPR;
	region_url1.table_name=table_url;
	region_url1.expr_rule.district=NULL;
	region_url1.expr_rule.keywords="baidu.com&tsg";
	region_url1.expr_rule.expr_type=EXPR_TYPE_AND;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region_url1, group1.group_id);


	//region_url2->group2
	memset(&region_url1, 0, sizeof(region_url1));
	region_url2.region_id=Maat_command_get_new_region_id(feather);
	region_url2.region_type=REGION_EXPR;
	region_url2.table_name=table_url;
	region_url2.expr_rule.district=NULL;
	region_url2.expr_rule.keywords="baidu.com&zhengzhou";
	region_url2.expr_rule.expr_type=EXPR_TYPE_AND;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region_url2, group2.group_id);


	//region_appid->group3
	memset(&region_appid, 0, sizeof(region_appid));
	region_appid.region_id=Maat_command_get_new_region_id(feather);
	region_appid.region_type=REGION_INTERVAL;
	region_appid.table_name=table_appid;
	region_appid.interval_rule.low_boundary=100;
	region_appid.interval_rule.up_boundary=100;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region_appid, group3.group_id);

	
	//region_url1->group1->compile[0~compile_cnt]
	//						/
	//region_appid->group3-/
	memset(&compile, 0, sizeof(compile));
	for(i=0; i<compile_cnt; i++)
	{
		compile[i].config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
		Maat_command_raw_set_compile(feather, MAAT_OP_ADD, compile+i, compile_table_name, NULL, 2, 0, 0);
	}
	for(i=0; i<compile_cnt; i++)
	{
		group1.compile_id=compile[i].config_id;
		group3.compile_id=compile[i].config_id;
		Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group1);
		Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group3);
	}

	//region_url2->group2->target_compile
	//						/
	//region_appid->group3-/
	memset(&target_compile, 0, sizeof(target_compile));
	target_compile.config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &target_compile, compile_table_name, NULL, 2, 0, 0);
	group2.compile_id=target_compile.config_id;
	group3.compile_id=target_compile.config_id;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group2);
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group3);

	
	sleep(1);
	
	int ret=0, url_table_id=0, appid_table_id=0;
	
	const char* http_url1="https://www.baidu.com/s?wd=tsg";
	const char* http_url2="https://www.baidu.com/s?wd=zhengzhou&rsv_spt=1&rsv_iqid=0x8b4cae8100000560&issp=1&f=8&rsv_bp=1";

	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;


	url_table_id=Maat_table_register(feather, table_url);	
	ASSERT_GT(url_table_id, 0);

	appid_table_id=Maat_table_register(feather, table_appid);	
	ASSERT_GT(appid_table_id, 0);

	
	ret=Maat_full_scan_string(feather, url_table_id, CHARSET_GBK, http_url2, strlen(http_url2), 
						result, NULL, 4, &mid, 0);
	EXPECT_EQ(ret, -2);

	ret=Maat_scan_intval(feather, appid_table_id, 100, result, 4, &mid, 0);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, target_compile.config_id);
	
	Maat_clean_status(&mid);


	ret=Maat_full_scan_string(feather, url_table_id, CHARSET_GBK, http_url1, strlen(http_url1), 
						result, NULL, 4, &mid, 0);
	EXPECT_EQ(ret, -2);

	ret=Maat_scan_intval(feather, appid_table_id, 100, result, 4, &mid, 0);
	EXPECT_EQ(ret, 4);
	
	Maat_clean_status(&mid);
	
}


#define TEST_HIT_PATH
TEST_F(MaatCmdTest,    HitPath)
{
	Maat_feather_t feather=MaatCmdTest::_shared_feather;

	const char* g2g_tn="GROUP2GROUP";
	const char* g2c_tn="GROUP2COMPILE";
	const char* compile_table_name="COMPILE";
	const char* table_http_sig="HTTP_SIGNATURE";
	const char* table_ip="IP_CONFIG";
	const char* table_keywords="KEYWORDS_TABLE";

	struct Maat_rule_t compile1;
	struct Maat_cmd_group2compile group1, group21, group3, group4;
	struct Maat_cmd_group2group group2;
	struct Maat_cmd_region region1, region2, region3, region4;

	memset(&compile1, 0, sizeof(compile1));
	compile1.config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile1, compile_table_name, NULL, 2, 0, 0);

	
	//group1->compile1
	memset(&group1, 0, sizeof(group1));
	group1.group_id=Maat_command_get_new_group_id(feather);
	group1.table_name=g2c_tn;
	group1.virtual_table_name="HTTP_REQUEST_HEADER";
	group1.compile_id=compile1.config_id;
	group1.clause_index=1;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group1);


	//region1->group1->compile1
	
	memset(&region1, 0, sizeof(region1));
	region1.region_id=Maat_command_get_new_region_id(feather);
	region1.region_type=REGION_EXPR;
	region1.table_name=table_http_sig;
	region1.expr_rule.district="URL";
	region1.expr_rule.keywords="graph_theory";
	region1.expr_rule.expr_type=EXPR_TYPE_STRING;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region1, group1.group_id);

	
	//	region1->group1->compile1
	//                   /
	//			 group21/
	
	memset(&group21, 0, sizeof(group21));
	group21.group_id=Maat_command_get_new_group_id(feather);
	group21.table_name=g2c_tn;
	group21.virtual_table_name="HTTP_RESPONSE_HEADER";
	group21.compile_id=compile1.config_id;
	group21.clause_index=2;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group21);

	
	//	region1->group1->compile1
	//					/
	//	group2->group21/	

	memset(&group2, 0, sizeof(group2));
	group2.group_id=Maat_command_get_new_group_id(feather);
	group2.table_name=g2g_tn;
	group2.superior_group_id=group21.group_id;
	Maat_command_raw_set_group2group(feather, MAAT_OP_ADD, &group2);



	//	region1->group1->compile1
	//						   /
	//region2->group2->group21/

	memset(&region2, 0, sizeof(region2));
	region2.region_id=Maat_command_get_new_region_id(feather);
	region2.region_type=REGION_EXPR;
	region2.table_name=table_http_sig;
	region2.expr_rule.district="Cookie";
	region2.expr_rule.keywords="time=2020-02-11";
	region2.expr_rule.expr_type=EXPR_TYPE_STRING;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region2, group2.group_id);

	//region3->group3, group3 is not referenced by any compile.
	memset(&region3, 0, sizeof(region3));
	region3.region_id=Maat_command_get_new_region_id(feather);
	region3.region_type=REGION_IP;
	region3.table_name=table_ip;
	region3.ip_rule.addr_type=ADDR_TYPE_IPv4;
	region3.ip_rule.direction=ADDR_DIR_DOUBLE;
	region3.ip_rule.src_ip="220.181.38.148";
	region3.ip_rule.mask_src_ip="255.255.255.254";
	region3.ip_rule.src_port=53331;
	region3.ip_rule.mask_src_port=0;//means any port should hit.
	
	region3.ip_rule.dst_ip="47.93.59.84";
	region3.ip_rule.mask_dst_ip="255.255.255.255";
	region3.ip_rule.dst_port=80;
	region3.ip_rule.mask_dst_port=65535;
	region3.ip_rule.protocol=0;//means any protocol should hit.

	group3.group_id=Maat_command_get_new_group_id(feather);
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region3, group3.group_id);

	char temp[1024]={0};
	//region4->group4, group4 is not referenced by any compile.
	memset(&region4, 0, sizeof(region4));
	region4.region_id=Maat_command_get_new_region_id(feather);
	region4.region_type=REGION_EXPR;
	region4.table_name=table_keywords;
	region4.expr_rule.district=NULL;
	region4.expr_rule.keywords= Maat_str_escape(temp, sizeof(temp), "a finite or infinite");
	region4.expr_rule.expr_type=EXPR_TYPE_STRING;
	
	group4.group_id=Maat_command_get_new_group_id(feather);
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region4, group4.group_id);


	sleep(1);

	int ret=0, table_id=0;
	const char* http_url="en.wikipedia.org/wiki/Path_(graph_theory)";
	const char* http_resp_hdr_cookie="laptop=thinkpad X1 extrem;time=2020-02-11T15:34:00;main[XWJOKE]=hoho; Hm_lvt_bbac0322e6ee13093f98d5c4b5a10912=1578874808;";

	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr_set(&ipv4_addr, &v4_addr, "220.181.38.148", 17272, "47.93.59.84", 80);
	

	struct Maat_rule_t result[4];
	memset(result, 0, sizeof(result));

	scan_status_t mid=NULL;
	int path_idx=0, Nth_scan=0;

	table_id=Maat_table_register(feather, "HTTP_REQUEST_HEADER");	
	ASSERT_GT(table_id, 0);
	
	ret=Maat_set_scan_status(feather, &mid, MAAT_SET_SCAN_DISTRICT, "URL", strlen("URL"));
	ASSERT_EQ(ret, 0);

	Nth_scan++;
	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, http_url, strlen(http_url), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, -2);
	
	struct Maat_hit_path_t hit_path[128];
	memset(hit_path, 0, sizeof(hit_path));
	int n_read=0;
	n_read=Maat_get_scan_status(feather, &mid, MAAT_GET_SCAN_HIT_PATH, hit_path, sizeof(hit_path));
	EXPECT_EQ(n_read, 1);
	ASSERT_EQ(path_idx, 0);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].region_id, region1.region_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group1.group_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, group1.group_id);
	EXPECT_EQ(hit_path[path_idx].virtual_table_id, table_id);
	EXPECT_EQ(hit_path[path_idx].compile_id, -1);
	

	table_id=Maat_table_register(feather, "HTTP_RESPONSE_HEADER");
	ASSERT_GT(table_id, 0);

	ret=Maat_set_scan_status(feather, &mid, MAAT_SET_SCAN_DISTRICT, "Cookie", strlen("Cookie"));
	ASSERT_EQ(ret, 0);

	Nth_scan++;
	ret=Maat_full_scan_string(feather, table_id, CHARSET_UTF8, http_resp_hdr_cookie, strlen(http_resp_hdr_cookie), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, compile1.config_id);	

	n_read=Maat_get_scan_status(feather, &mid, MAAT_GET_SCAN_HIT_PATH, hit_path, sizeof(hit_path));
	EXPECT_EQ(n_read, 2);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan-1);
	EXPECT_EQ(hit_path[path_idx].region_id, region1.region_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group1.group_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, group1.group_id);
	//virtual_table_id was compared in previous.
	EXPECT_EQ(hit_path[path_idx].compile_id, compile1.config_id);

	path_idx++;
	ASSERT_EQ(path_idx, 1);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].region_id, region2.region_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group2.group_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, group21.group_id);
	EXPECT_EQ(hit_path[path_idx].virtual_table_id, table_id);
	EXPECT_EQ(hit_path[path_idx].compile_id, compile1.config_id);

	const char* keywords1="In graph theory, a path in a graph is a finite or infinite \
sequence of edges which joins a sequence of vertices which, by most definitions,\
are all distinct (and since the vertices are distinct, so are the edges). ";
	const char* keywords2="A directed path in a directed graph is a finite or infinite\
sequence of edges which joins a sequence of distinct vertices, but with the added restriction\
that the edges be all directed in the same direction.";
	table_id=Maat_table_register(feather, table_keywords);
	ASSERT_GT(table_id, 0);
	stream_para_t stream_para;
	stream_para=Maat_stream_scan_string_start(feather, table_id, 0);
	Nth_scan++;
	ret=Maat_stream_scan_string(&stream_para, CHARSET_UTF8, keywords1, strlen(keywords1), result, NULL, 4, &mid);
	EXPECT_EQ(ret, -2);
	n_read=Maat_get_scan_status(feather, &mid, MAAT_GET_SCAN_HIT_PATH, hit_path, sizeof(hit_path));
	EXPECT_EQ(n_read, 3);
	path_idx++;
	ASSERT_EQ(path_idx, 2);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].region_id, region4.region_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group4.group_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, -1);
	EXPECT_EQ(hit_path[path_idx].virtual_table_id, 0);
	EXPECT_EQ(hit_path[path_idx].compile_id, -1);	
	
	table_id=Maat_table_register(feather, table_ip);
	ASSERT_GT(table_id, 0);

	Nth_scan++;
	ret=Maat_scan_proto_addr(feather, table_id, &ipv4_addr, 6, result, 4, &mid, 0);
	EXPECT_EQ(ret, -2);

	n_read=Maat_get_scan_status(feather, &mid, MAAT_GET_SCAN_HIT_PATH, hit_path, sizeof(hit_path));
	EXPECT_EQ(n_read, 4);
	path_idx++;
	ASSERT_EQ(path_idx, 3);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].region_id, region3.region_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group3.group_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, -1);
	EXPECT_EQ(hit_path[path_idx].virtual_table_id, 0);
	EXPECT_EQ(hit_path[path_idx].compile_id, -1);

	Nth_scan++;
	ret=Maat_stream_scan_string(&stream_para, CHARSET_UTF8, keywords2, strlen(keywords2), result, NULL, 4, &mid);
	EXPECT_EQ(ret, -2);
	n_read=Maat_get_scan_status(feather, &mid, MAAT_GET_SCAN_HIT_PATH, hit_path, sizeof(hit_path));
	EXPECT_EQ(n_read, 5);
	path_idx++;
	ASSERT_EQ(path_idx, 4);
	EXPECT_EQ(hit_path[path_idx].Nth_scan, Nth_scan);
	EXPECT_EQ(hit_path[path_idx].region_id, region4.region_id);
	EXPECT_EQ(hit_path[path_idx].sub_group_id, group4.group_id);
	EXPECT_EQ(hit_path[path_idx].top_group_id, -1);
	EXPECT_EQ(hit_path[path_idx].virtual_table_id, 0);
	EXPECT_EQ(hit_path[path_idx].compile_id, -1);
	Maat_stream_scan_string_end(&stream_para);

	Maat_clean_status(&mid);

	return;

}
#define Update_DeadLock_Detection
TEST_F(MaatCmdTest,    UpdateDeadLockDetection)
{
	Maat_feather_t feather=MaatCmdTest::_shared_feather;

	const char* g2c_tn="GROUP2COMPILE";
	const char* compile_table_name="COMPILE";
	const char* table_http_url="HTTP_URL";

	struct Maat_rule_t compile1, compile2;
	struct Maat_cmd_group2compile group1, group2;
	struct Maat_cmd_region region1, region2;

	memset(&compile1, 0, sizeof(compile1));
	compile1.config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile1, compile_table_name, NULL, 1, 0, 0);

	
	//group1->compile1
	memset(&group1, 0, sizeof(group1));
	group1.group_id=Maat_command_get_new_group_id(feather);
	group1.table_name=g2c_tn;
	group1.compile_id=compile1.config_id;
	group1.clause_index=0;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group1);


	//region1->group1->compile1
	
	memset(&region1, 0, sizeof(region1));
	region1.region_id=Maat_command_get_new_region_id(feather);
	region1.region_type=REGION_EXPR;
	region1.table_name=table_http_url;
	region1.expr_rule.keywords="part-1";
	region1.expr_rule.expr_type=EXPR_TYPE_STRING;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region1, group1.group_id);

	sleep(1);

	const char* scan_data1="scan string part-1.";
	const char* scan_data2="scan string part-2.";
	struct Maat_rule_t result[4];
	memset(result, 0, sizeof(result));

	scan_status_t mid=NULL;
	int ret=0, table_id=0;

	table_id=Maat_table_register(feather, table_http_url);
	ASSERT_GT(table_id, 0);

	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, scan_data1, strlen(scan_data1), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, compile1.config_id);


	memset(&compile2, 0, sizeof(compile2));
	compile2.config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile2, compile_table_name, NULL, 1, 0, 0);

	
	//group2->compile2
	memset(&group2, 0, sizeof(group2));
	group2.group_id=Maat_command_get_new_group_id(feather);
	group2.table_name=g2c_tn;
	group2.compile_id=compile2.config_id;
	group2.clause_index=0;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group2);


	//region2->group2->compile2
	
	memset(&region2, 0, sizeof(region2));
	region2.region_id=Maat_command_get_new_region_id(feather);
	region2.region_type=REGION_EXPR;
	region2.table_name=table_http_url;
	region2.expr_rule.keywords="part-2";
	region2.expr_rule.expr_type=EXPR_TYPE_STRING;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region2, group2.group_id);

	//DON'T DO THIS!!!
	//Roll back version, trigger full udpate.
	Maat_cmd_incrby(feather, "MAAT_VERSION", -100);

	//Wating for scanner garbage collect expiration.
	sleep(10);

	ret=Maat_full_scan_string(feather, table_id, CHARSET_GBK, scan_data2, strlen(scan_data2), 
						result, NULL, 4, &mid, 0);

	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, compile2.config_id);
	
	Maat_clean_status(&mid);


	return;
}
#define VersionRollBack_SegFault
TEST_F(MaatCmdTest, StreamScanSegfaultWhenVersionRollBack_TSG_6324)
{
	Maat_feather_t feather=MaatCmdTest::_shared_feather;

	const char* g2c_tn="GROUP2COMPILE";
	const char* compile_table_name="COMPILE";
	const char* scan_table_name="KEYWORDS_TABLE";

	struct Maat_rule_t compile1;
	struct Maat_cmd_group2compile group1;
	struct Maat_cmd_region region1;

	memset(&compile1, 0, sizeof(compile1));
	compile1.config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	Maat_command_raw_set_compile(feather, MAAT_OP_ADD, &compile1, compile_table_name, NULL, 1, 0, 0);

	
	//group1->compile1
	memset(&group1, 0, sizeof(group1));
	group1.group_id=Maat_command_get_new_group_id(feather);
	group1.table_name=g2c_tn;
	group1.compile_id=compile1.config_id;
	group1.clause_index=0;
	Maat_command_raw_set_group2compile(feather, MAAT_OP_ADD, &group1);


	//region1->group1->compile1
	
	memset(&region1, 0, sizeof(region1));
	region1.region_id=Maat_command_get_new_region_id(feather);
	region1.region_type=REGION_EXPR;
	region1.table_name=scan_table_name;
	region1.expr_rule.keywords="stream-keywords-001";
	region1.expr_rule.expr_type=EXPR_TYPE_STRING;
	Maat_command_raw_set_region(feather, MAAT_OP_ADD, &region1, group1.group_id);

	sleep(1);

	const char* scan_data="Here is a stream-keywords-001, this should hit.";
	stream_para_t sp=NULL;
	scan_status_t mid=NULL;
	int ret=0, table_id=0;
	struct Maat_rule_t result[4];
	memset(result, 0, sizeof(result));
	
	table_id=Maat_table_register(feather, scan_table_name);
	ASSERT_GT(table_id, 0);

	
	sp=Maat_stream_scan_string_start(feather, table_id, 0);
	ret=Maat_stream_scan_string(&sp, CHARSET_NONE, scan_data, strlen(scan_data),
						result, NULL, 4, &mid);
	EXPECT_EQ(ret, 1);
	EXPECT_EQ(result[0].config_id, compile1.config_id);

	//DON'T DO THIS!!!
	//Roll back version, trigger full udpate.
	Maat_cmd_incrby(feather, "MAAT_VERSION", -100);

	//Wating for scanner garbage collect expiration.
	sleep(10);

	ret=Maat_stream_scan_string(&sp, CHARSET_NONE, scan_data, strlen(scan_data),
						result, NULL, 4, &mid);
	EXPECT_EQ(ret, 0); //Scan was interupted after full update.

	Maat_stream_scan_string_end(&sp);

	Maat_clean_status(&mid);

}

int main(int argc, char ** argv)
{

	const char* log_file="./test.log";
	const char* stat_file="./scan_staus.log";
	const char* decrypt_key="mesa2017wy";
	const char* accept_tags="{\"tags\":[{\"tag\":\"location\",\"value\":\"北京/朝阳/华严北里/甲22号\"},{\"tag\":\"isp\",\"value\":\"移动\"},{\"tag\":\"location\",\"value\":\"Astana\"}]}";
//	const char* subsitute_acc_tags="{\"tags\":[{\"tag\":\"location\",\"value\":\"Astana\"}]}";
	int scan_detail=0, ret=0;

	::testing::InitGoogleTest(&argc, argv);
	g_logger=MESA_create_runtime_log_handle(log_file, 0);

	g_feather=Maat_feather(g_iThreadNum, table_info_path, g_logger);
	Maat_set_feather_opt(g_feather, MAAT_OPT_INSTANCE_NAME, "demo", strlen("demo")+1);
//	Maat_set_feather_opt(g_feather, MAAT_OPT_DECRYPT_KEY, decrypt_key, strlen(decrypt_key)+1);
	ret=Maat_set_feather_opt(g_feather, MAAT_OPT_JSON_FILE_PATH, json_path, strlen(json_path)+1);
	assert(ret==0);
	Maat_set_feather_opt(g_feather, MAAT_OPT_SCANDIR_INTERVAL_MS, &scan_interval_ms, sizeof(scan_interval_ms));
	//Set a short intevral for testing.
	Maat_set_feather_opt(g_feather, MAAT_OPT_EFFECT_INVERVAL_MS, &effective_interval_ms, sizeof(effective_interval_ms));

	//Set a short intevral for testing.
	int tmp=0;
	Maat_set_feather_opt(g_feather, MAAT_OPT_GARBAGE_COLLECTION_TIMEOUT_MS, &tmp, sizeof(tmp));


	Maat_set_feather_opt(g_feather, MAAT_OPT_STAT_FILE_PATH, stat_file, strlen(stat_file)+1);
	Maat_set_feather_opt(g_feather, MAAT_OPT_STAT_ON, NULL, 0);
	Maat_set_feather_opt(g_feather, MAAT_OPT_PERF_ON, NULL, 0);
	Maat_set_feather_opt(g_feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
	Maat_set_feather_opt(g_feather, MAAT_OPT_ACCEPT_TAGS, accept_tags, strlen(accept_tags)+1);
	Maat_initiate_feather(g_feather);
	printf("Maat initiating, see %s\n",log_file);

	ret=RUN_ALL_TESTS();
	Maat_burn_feather(g_feather);
	MESA_destroy_runtime_log_handle(g_logger);
	return ret;
}

