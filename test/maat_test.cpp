#include "Maat_rule.h"
#include <MESA/MESA_handle_logger.h>
#include <dlfcn.h>
#include <assert.h>
#include <sys/socket.h>//inet_addr
#include <netinet/in.h>//inet_addr
#include <arpa/inet.h>//inet_addr
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <MESA/stream.h>

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
int main()
{
	Maat_feather_t feather=NULL;
	int cb_table_id=-1,url_scan_table_id=-1,size_scan_table_id=-1,ip_scan_table_id=-1;
	int ret=-1;
	int g_iThreadNum=4;
	const char*	table_info_path="./table_info.conf";
	const char* json_path="./maat_json.json";
//	const char* ful_cfg_dir="./maat_json.json_iris_tmp/index";
//	const char* inc_cfg_dir="./rules/inc/index";
	const char* log_file="./test.log";
	const char* scan_data="http://www.cyberessays.com/search_results.php?action=search&query=yulingjing,abckkk,1234567";
	int scan_val=2015;
	struct Maat_rule_t result[4];
	int found_pos[4];
	scan_status_t mid=NULL;
	
	void *logger=MESA_create_runtime_log_handle(log_file,0);
	feather=Maat_summon_feather_json(g_iThreadNum, 
									table_info_path, 
									json_path, 
									logger);
//	feather=Maat_summon_feather(g_iThreadNum,table_info_path,ful_cfg_dir,inc_cfg_dir,logger);
	if(feather==NULL)
	{
		printf("Maat initial error, see %s\n",log_file);
		return -1;
	}
	
	cb_table_id=Maat_table_register(feather,"QD_ENTRY_INFO");
	if(cb_table_id==-1)
	{
		printf("Database table QD_ENTRY_INFO register failed.");
	}
	else
	{
		ret=Maat_table_callback_register(feather, cb_table_id,
								Maat_read_entry_start_cb,
								Maat_read_entry_cb, 
								Maat_read_entry_finish_cb,
								logger);
		if(ret<0)
		{
			printf("Maat callback register table QD_ENTRY_INFO error.");
		}
	}

	url_scan_table_id=Maat_table_register(feather,"HTTP_URL");
	if(url_scan_table_id==-1)
	{
		printf("Database table HTTP_URL register failed.");
		
	}
	else
	{
		ret=Maat_full_scan_string(feather, url_scan_table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
							result,found_pos, 4,
							&mid, 0);
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
	}
	Maat_clean_status(&mid);
	size_scan_table_id=Maat_table_register(feather,"CONTENT_SIZE");
	if(size_scan_table_id==-1)
	{
		printf("Database table CONTENT_SIZE register failed.");
		
	}
	else
	{
		ret=Maat_scan_intval(feather, size_scan_table_id, scan_val, result,4,&mid, 0);
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
	}
	Maat_clean_status(&mid);
	struct Maat_hit_detail_t *hit_detail=(struct Maat_hit_detail_t *)malloc(sizeof(struct Maat_hit_detail_t)*10);
	stream_para_t sp=Maat_stream_scan_string_start(feather,url_scan_table_id,0);
	int detail_ret=0;
	if(sp==NULL)
	{
		printf("stream scan start failed.\n");
		return -1;
	}
	ret=Maat_stream_scan_string_detail(&sp,CHARSET_NONE,"www.cyberessays.com", strlen("www.cyberessays.com")
						,result,4,hit_detail,10
						,&detail_ret,&mid);
	ret=Maat_stream_scan_string_detail(&sp,CHARSET_NONE,scan_data, strlen(scan_data)
						,result,4,hit_detail,10
						,&detail_ret,&mid);
	Maat_stream_scan_string_end(&sp);

	struct ipaddr ipv4_addr,ipv6_addr;
	struct stream_tuple4_v4 v4_addr;
	struct stream_tuple4_v6 v6_addr;
	ipv4_addr.addrtype=ADDR_TYPE_IPV4;
	inet_pton(AF_INET,"10.0.6.205",&(v4_addr.saddr));
	v4_addr.source=htons(50001);
	inet_pton(AF_INET,"10.0.6.201",&(v4_addr.daddr));
	v4_addr.dest=htons(80);
	ipv4_addr.v4=&v4_addr;

	ip_scan_table_id=Maat_table_register(feather,"IP_CONFIG");
	if(ip_scan_table_id==-1)
	{
		printf("Database table IP_CONFIG register failed.");
		
	}
	else
	{
		ret=Maat_scan_proto_addr(feather,ip_scan_table_id,&ipv4_addr,6,result,4, &mid,0);
		if(ret>0)
		{
			printf("ipv4 scan hit compile rule id %d.\n",result[0].config_id);
		}
	}
	Maat_clean_status(&mid);
	ipv6_addr.addrtype=ADDR_TYPE_IPV6;
	inet_pton(AF_INET6,"2001:da8:205:1::101",&(v6_addr.saddr));
	v6_addr.source=htons(50001);
	inet_pton(AF_INET6,"2001:da8:205:1::102",&(v6_addr.daddr));
	v6_addr.dest=htons(80);
	ipv6_addr.v6=&v6_addr;
	if(ip_scan_table_id>=0)
	{
		ret=Maat_scan_proto_addr(feather,ip_scan_table_id,&ipv6_addr,6,result,4, &mid,0);
		if(ret==-2)
		{
			printf("ipv6 scan hit region.\n");
		}
		else
		{
			printf("ipv6 scan result:%d ,shoulde be -2.\n",ret);

		}
	}
	Maat_burn_feather(feather);
	free(hit_detail);
	return 0;
}
