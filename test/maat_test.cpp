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
	print_maat_ret(ret);
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
		print_maat_ret(ret);
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
	print_maat_ret(ret);
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
		if(ret>0)
		{
			printf("ipv4 scan hit compile rule id %d.\n",result[0].config_id);
		}
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
		if(ret==-2)
		{
			printf("ipv6 scan hit region.\n");
		}
		else
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
				printf("digest scan hit %d.\n",result[0].config_id);

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

/*	feather=Maat_summon_feather_json(g_iThreadNum, 
									table_info_path, 
									json_path, 
									logger);
*/							
//	feather=Maat_summon_feather(g_iThreadNum,table_info_path,ful_cfg_dir,inc_cfg_dir,logger);
	feather=Maat_feather(g_iThreadNum, table_info_path, logger);
	Maat_set_feather_opt(feather, MAAT_OPT_JSON_FILE_PATH, json_path, sizeof(json_path)+1);
	Maat_set_feather_opt(feather, MAAT_OPT_STAT_FILE_PATH, stat_file, strlen(stat_file));
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

	sleep(4);
	
	Maat_burn_feather(feather);
	
	return 0;
}
