#include "Maat_rule.h"
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
extern int my_scandir(const char *dir, struct dirent ***namelist,
              int(*filter)(const struct dirent *),
              int(*compar)(const void *, const void *));
void Maat_read_entry_start_cb(int update_type,void* u_para)
{
	return;
}
void Maat_read_entry_cb(int table_id,const char* table_line,void* u_para)
{
	char ip_str[16]={0};
	int entry_id=-1,seq=-1;
	unsigned int ip_uint=0;
	unsigned int local_ip_nr=16820416;//192.168.0.1
	sscanf(table_line,"%d\t%s\t%d",&seq,ip_str,&entry_id);
	inet_pton(AF_INET,ip_str,&ip_uint);
	if(local_ip_nr==ip_uint)
	{
		printf("Load entry id %d SUCCESS.\n",entry_id);
	}
	return;
}
void Maat_read_entry_finish_cb(void* u_para)
{
	return;
}
void print_maat_ret(int ret)
{
	switch(ret)
	{
		case -1:
			printf("scan error.\n");
			break;
		case -2:
			printf("hit current region,but not hit compile rule.\n");
			break;
		case 0:
			printf("nothing hit\n");
			break;
		default://>0
			printf("hit %d rules\n",ret);
			break;
	}
	return;
}
const char* print_maat_result(struct Maat_rule_t* result,int ret)
{
	static char buff[1024]={0};
	int i=0,j=0;
	switch(ret)
	{
		case -1:
			snprintf(buff,sizeof(buff),"ret=%d,scan error.",ret);
			break;
		case -2:
			snprintf(buff,sizeof(buff),"ret=%d,hit current region,but not hit compile rule.",ret);
			break;
		case 0:
			snprintf(buff,sizeof(buff),"ret=0,nothing hit.");
			break;
		default://>0
			j=snprintf(buff,sizeof(buff),"hit %d rules, hit ruleid=",ret);
			for(i=0;i<ret;i++)
			{
				j+=snprintf(buff+j,sizeof(buff)-j,"%d ",result[i].config_id);
			}
			break;
	}
	return buff;
}
int test_string_full_scan(Maat_feather_t feather,const char* table_name,scan_status_t* mid)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* scan_data="http://www.cyberessays.com/search_results.php?action=search&query=yulingjing,abckkk,1234567";
	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.\n",table_name);
		return -1;
	}
	
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result,found_pos, 4,
						mid, 0);
	printf("Full String Scan:%s\n",print_maat_result(result,ret));
	return ret;
}
int test_unescape_string_scan(Maat_feather_t feather,const char* table_name,scan_status_t* mid)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* scan_data="Batman\\:Take me Home.Superman/:Fine,stay with me.";
	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.\n",table_name);
		return -1;
	}
	
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result,found_pos, 4,
						mid, 0);
	printf("Unescape String Scan:%s\n",print_maat_result(result,ret));

	return ret;
}
int test_intval_scan(Maat_feather_t feather,const char* table_name,scan_status_t* mid)
{
	int table_id=0,ret=0;
	int scan_val=2015;
	struct Maat_rule_t result[4];
	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.",table_name);
		
	}
	else
	{
		ret=Maat_scan_intval(feather, table_id, scan_val, result,4,mid, 0);
		printf("Intval Scan:%s\n",print_maat_result(result,ret));
	}
	return ret;
}
int test_str_stream_scan(Maat_feather_t feather,const char* table_name,scan_status_t* mid)
{
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	const char* scan_data="http://www.cyberessays.com/search_results.php?action=search&query=yulingjing,abckkk,1234567";
	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.\n",table_name);
		return -1;
	}
	struct Maat_hit_detail_t *hit_detail=(struct Maat_hit_detail_t *)malloc(sizeof(struct Maat_hit_detail_t)*10);
	stream_para_t sp=Maat_stream_scan_string_start(feather,table_id,0);
	int detail_ret=0;
	if(sp==NULL)
	{
		printf("stream scan start failed.\n");
		return -1;
	}
	ret=Maat_stream_scan_string_detail(&sp,CHARSET_NONE,"www.cyberessays.com", strlen("www.cyberessays.com")
						,result,4,hit_detail,10
						,&detail_ret,mid);
	ret=Maat_stream_scan_string_detail(&sp,CHARSET_NONE,scan_data, strlen(scan_data)
						,result,4,hit_detail,10
						,&detail_ret,mid);
	Maat_stream_scan_string_end(&sp);
	free(hit_detail);
	printf("Stream String Scan:%s\n",print_maat_result(result,ret));
	return ret;
}
int test_ipv4_scan(Maat_feather_t feather,const char* table_name,scan_status_t* mid)
{
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	struct ipaddr ipv4_addr;
	struct stream_tuple4_v4 v4_addr;
	ipv4_addr.addrtype=ADDR_TYPE_IPV4;
	inet_pton(AF_INET,"10.0.6.205",&(v4_addr.saddr));
	v4_addr.source=htons(50001);
	inet_pton(AF_INET,"10.0.6.201",&(v4_addr.daddr));
	v4_addr.dest=htons(80);
	ipv4_addr.v4=&v4_addr;

	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.\n",table_name);
		
	}
	else
	{
		ret=Maat_scan_proto_addr(feather,table_id,&ipv4_addr,6,result,4, mid,0);
		printf("IPv4 addr Scan:%s\n",print_maat_result(result,ret));
	}
	return ret;
}
int test_ipv6_scan(Maat_feather_t feather,const char* table_name,scan_status_t* mid)
{
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	struct ipaddr ipv6_addr;
	struct stream_tuple4_v6 v6_addr;
	
	ipv6_addr.addrtype=ADDR_TYPE_IPV6;
	inet_pton(AF_INET6,"2001:da8:205:1::101",&(v6_addr.saddr));
	v6_addr.source=htons(50001);
	inet_pton(AF_INET6,"2001:da8:205:1::102",&(v6_addr.daddr));
	v6_addr.dest=htons(80);
	ipv6_addr.v6=&v6_addr;

	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.\n",table_name);
		
	}
	else
	{
		ret=Maat_scan_proto_addr(feather,table_id,&ipv6_addr,6,result,4, mid,0);
		printf("IPv6 addr Scan:%s\n",print_maat_result(result,ret));

		if(ret!=-2)
		{
			printf("ipv6 scan result:%d ,shoulde be -2.\n",ret);

		}
	}
	return ret;
}
int test_digest_scan(Maat_feather_t feather,const char* table_name,scan_status_t* mid)
{
	int table_id=0,ret=0;
	const char* digest_test_file="./digest_test.data";
	struct stat digest_fstat;
	unsigned long long read_size=0,scan_offset=0;
	char digest_test_buff[4096]={0};

	struct Maat_rule_t result[4];
	stream_para_t sp=NULL;
	table_id=Maat_table_register(feather, table_name);
	if(table_id<0)
	{
		printf("registe table %s error.\n",table_name);
		return 0;
	}
	ret=stat(digest_test_file,&digest_fstat);
	if(ret!=0)
	{
		printf("fstat %s error.\n",digest_test_file);
		return 0;
	}
	FILE* fp=fopen(digest_test_file,"r");
	if(fp!=NULL)
	{
		sp=Maat_stream_scan_digest_start(feather, table_id, digest_fstat.st_size, 0);
		while(0==feof(fp))
		{
			read_size=fread(digest_test_buff,1,sizeof(digest_test_buff),fp);
			ret=Maat_stream_scan_digest(&sp, digest_test_buff, read_size, scan_offset, result,4,mid);
			scan_offset+=read_size;
			if(ret>0)
			{
					printf("Digest Scan:%s\n",print_maat_result(result,ret));

			}
		}
		fclose(fp);
	}
	else
	{
		printf("fopen %s error.\n",digest_test_file);		
	}
	Maat_stream_scan_string_end(&sp);
	return ret;
}
int test_plugin_table(Maat_feather_t feather,const char* table_name,void* logger)
{
	int table_id=0,ret=0;
	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.\n",table_name);
	}
	else
	{
		ret=Maat_table_callback_register(feather, table_id,
								Maat_read_entry_start_cb,
								Maat_read_entry_cb, 
								Maat_read_entry_finish_cb,
								logger);
		if(ret<0)
		{
			printf("Maat callback register table %s error.\n",table_name);
		}
	}
	return ret;
}
int test_url_encode(Maat_feather_t feather,const char* table_name,scan_status_t* mid)
{
	const char* url_utf8="www.google.com/?q=C%23%E4%B8%AD%E5%9B%BD";
	const char* url_gb2312="www.baidu.com/?wd=C%23%D6%D0%B9%FA";
	int table_id=0,ret=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.",table_name);
		return -1;
	}
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, url_utf8, strlen(url_utf8), 
						result,found_pos, 4,
						mid, 0);
	printf("URL encode scan utf8 url: %s\n",print_maat_result(result,ret));

	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, url_gb2312, strlen(url_gb2312), 
						result,found_pos, 4,
						mid, 0);
	printf("URL encode scan gb2312 url: %s\n",print_maat_result(result,ret));
	
	return 0;
}
int test_unicode_esc(Maat_feather_t feather,const char* table_name,scan_status_t* mid)
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
	int found_pos[4];
	int n=0,i=0;
	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed in function %s.\n",table_name,__FUNCTION__);
		return -1;
	}
	n = my_scandir(test_data_dir, &namelist, NULL, (int (*)(const void*, const void*))alphasort);
	if(n<0)
	{
		printf("%s open dir %s error.\n",__FUNCTION__,test_data_dir);
		return -1;
	}
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
		printf("%s processing %s\n",__FUNCTION__,file_path);
		sp=Maat_stream_scan_string_start(feather,table_id,0);
		if(sp==NULL)
		{
			printf("stream scan start failed.\n");
			continue;
		}
		read_len=fread(buff,1,sizeof(buff),fp);
		while(read_len>0)
		{

			ret=Maat_stream_scan_string(&sp,CHARSET_NONE,buff,read_len
								,result,found_pos,4,mid);
			read_len=fread(buff,1,sizeof(buff),fp);
			if(ret>0)
			{
				printf("UNI2ASCII file %s,%s\n",file_path,print_maat_result(result,ret));
			}
		}
		Maat_stream_scan_string_end(&sp);		
		fclose(fp);

	}
	for(i=0;i<n;i++)
	{
		free(namelist[i]);
	}
	free(namelist);
	return 0;
}
int test_expr_plus(Maat_feather_t feather,const char* table_name,scan_status_t* mid)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* region_name="URL";
	const char* scan_data="http://www.cyberessays.com/search_results.php?action=search&query=yulingjing,abckkk,1234567";
	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.\n",table_name);
		return -1;
	}
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result,found_pos, 4,
						mid, 0);
	if(ret>0)
	{
		printf("Should not hit without setting district.\n");
		return -1;
	}
	ret=Maat_set_scan_status(feather, mid, MAAT_SET_SCAN_DISTRICT,region_name,strlen(region_name)+1);
	if(ret<0)
	{
		printf("set MAAT_SET_SCAN_DISTRICT failed.\n");
		return -1;
	}
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result,found_pos, 4,
						mid, 0);
	if(ret>0)
	{
		printf("Hit expr_plus rule %d.\n",result[0].config_id);
	}
	return ret;

}
int test_table_conjunction(Maat_feather_t feather,const char* table_name,const char* conj_table_name,scan_status_t* mid)
{
	int ret=0;
	int table_id=0,conj_table_id=0;
	struct Maat_rule_t result[4];
	int found_pos[4];
	const char* scan_data="soq is using table conjunction function.http://www.3300av.com/novel/27122.txt";

	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.\n",table_name);
		return -1;
	}
	conj_table_id=Maat_table_register(feather,conj_table_name);
	assert(conj_table_id==table_id);
	ret=Maat_full_scan_string(feather, conj_table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						result,found_pos, 4,
						mid, 0);
	if(ret>=2)
	{
		printf("Table conjunction success %s\n",print_maat_result(result,ret));
	}
	return 0;
}
int main(int argc,char* argv[])
{
	Maat_feather_t feather=NULL;
	int g_iThreadNum=4;
	const char*	table_info_path="./table_info.conf";
	const char* json_path="./maat_json.json";
//	const char* ful_cfg_dir="./maat_json.json_iris_tmp/index";
//	const char* inc_cfg_dir="./rules/inc/index";
	const char* log_file="./test.log";
	const char* stat_file="./scan_staus.log";
	int scan_detail=0;
	scan_status_t mid=NULL;
	void *logger=MESA_create_runtime_log_handle(log_file,0);

	feather=Maat_feather(g_iThreadNum, table_info_path, logger);
	Maat_set_feather_opt(feather, MAAT_OPT_JSON_FILE_PATH, json_path, strlen(json_path)+1);
	Maat_set_feather_opt(feather, MAAT_OPT_STAT_FILE_PATH, stat_file, strlen(stat_file)+1);
	Maat_set_feather_opt(feather, MAAT_OPT_STAT_ON, NULL, 0);
	Maat_set_feather_opt(feather, MAAT_OPT_PERF_ON, NULL, 0);
	Maat_set_feather_opt(feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
	Maat_initiate_feather(feather);

	if(feather==NULL)
	{
		printf("Maat initial error, see %s\n",log_file);
		return -1;
	}
	test_plugin_table(feather, "QD_ENTRY_INFO",logger);
	
	test_string_full_scan(feather, "HTTP_URL", &mid);
	//not  clean status here, to test_ipv4_scan make  hit compile rule.
	test_ipv4_scan(feather, "IP_CONFIG", &mid);
	Maat_clean_status(&mid);


	test_intval_scan(feather,"CONTENT_SIZE" , &mid);
	Maat_clean_status(&mid);


	test_ipv6_scan(feather, "IP_CONFIG", &mid);
	Maat_clean_status(&mid);

	test_digest_scan(feather,"FILE_DIGEST", &mid);
	Maat_clean_status(&mid);

	test_expr_plus(feather, "HTTP_REGION", &mid);
	Maat_clean_status(&mid);

	test_url_encode(feather, "HTTP_URL", &mid);
	Maat_clean_status(&mid);

	test_unicode_esc(feather,"KEYWORDS_TABLE",&mid);
	Maat_clean_status(&mid);

	test_unescape_string_scan(feather,"KEYWORDS_TABLE",&mid);
	Maat_clean_status(&mid);

	test_table_conjunction(feather, "HTTP_URL", "HTTP_HOST", &mid);
	Maat_clean_status(&mid);

	sleep(4);
	
	Maat_burn_feather(feather);
	
	return 0;
}
