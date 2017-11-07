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
const char* test_maat_redis_ip="127.0.0.1";
unsigned short test_maat_redis_port=6379;
const char* json_path="./maat_json.json";
const char* ful_cfg_dir="./rule/full/index/";
const char* inc_cfg_dir="./rule/inc/index/";
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
	int is_valid=0;
	unsigned int local_ip_nr=16820416;//192.168.0.1
	sscanf(table_line,"%d\t%s\t%d\t%d",&seq,ip_str,&entry_id,&is_valid);
	inet_pton(AF_INET,ip_str,&ip_uint);
	if(local_ip_nr==ip_uint)
	{
		if(is_valid==1)
		{
			printf("Load entry id %d success.\n",entry_id);
		}
		else
		{
			printf("Offload entry id %d success.\n",entry_id);
		}
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
		//for improving performance.
		Maat_set_scan_status(feather, mid, MAAT_SET_SCAN_LAST_REGION,NULL, 0);
		ret=Maat_scan_proto_addr(feather,table_id,&ipv6_addr,6,result,4, mid,0);
		printf("IPv6 addr Scan:%s\n",print_maat_result(result,ret));

		if(ret!=-2)
		{
			printf("ipv6 scan result:%d ,shoulde be -2.\n",ret);

		}
	}
	return ret;
}
int test_digest_scan(Maat_feather_t feather,const char* table_name,const char* file_name,scan_status_t* mid)
{
	int table_id=0,ret=0;
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
	ret=stat(file_name,&digest_fstat);
	if(ret!=0)
	{
		printf("fstat %s error.\n",file_name);
		return 0;
	}
	FILE* fp=fopen(file_name,"r");
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
		printf("fopen %s error.\n",file_name);		
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
	ret=Maat_set_scan_status(feather, mid, MAAT_SET_SCAN_DISTRICT,region_name,strlen(region_name));
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
int test_string_similar_scan(Maat_feather_t feather,const char* table_name,scan_status_t* mid)
{
	int ret=0;
	int table_id=0;
	struct Maat_rule_t result[4];
	const char* scan_data="mwss.xiu.youku.com/live/hls/v1/0000000000000000000000001526a0a8/714.ts?&token=98765";
	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.\n",table_name);
		return -1;
	}
	
	ret=Maat_similar_scan_string(feather, table_id, scan_data, strlen(scan_data), 
						result, 4,
						mid, 0);
	printf("Similar String Scan:%s\n",print_maat_result(result,ret));
	return ret;
}

int test_offset_str_scan_with_chunk(Maat_feather_t feather,const char* table_name,int chunk_size)
{
	int table_id=0,ret=0;
	int read_size=0,pass_flag=0;
	struct Maat_rule_t result[4];
	scan_status_t mid=NULL;
	//const char* fn="./testdata/mesa_logo.jpg";
	const char* fn="./testdata/mesa_logo.jpg";
	FILE*fp=fopen(fn,"r");
	if(fp==NULL)
	{
		printf("%s open %s failed.\n",__FUNCTION__, fn);
		return -1;
	}
	char scan_data[chunk_size];
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
	while(0==feof(fp))
	{
		read_size=fread(scan_data,1,sizeof(scan_data),fp);
		ret=Maat_stream_scan_string_detail(&sp,CHARSET_NONE,scan_data,read_size
							,result,4,hit_detail,10
							,&detail_ret,&mid);
		if(ret>0)
		{
			printf("Test offset string Scan chunk=%d Success. String Scan:%s\n",chunk_size,print_maat_result(result,ret));
			pass_flag=1;
			break;
		}
	}
	Maat_stream_scan_string_end(&sp);
	free(hit_detail);
	fclose(fp);
	if(!pass_flag)
	{
		printf("Test offset string Scan Failed.\n");
	}
	Maat_clean_status(&mid);
	return ret;
}

void test_offset_str_scan(Maat_feather_t feather,const char* table_name)
{
	test_offset_str_scan_with_chunk(feather,table_name,64);
	test_offset_str_scan_with_chunk(feather,table_name,1460);
	return;
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
#define	TEST_CMD_LINE_NUM	4
void test_set_cmd_line(Maat_feather_t feather)
{
	const struct Maat_line_t *p_line[TEST_CMD_LINE_NUM];
	struct Maat_line_t line_rule[TEST_CMD_LINE_NUM];
	char table_line[TEST_CMD_LINE_NUM][128];
	int ret=0,i=0;
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
	assert(ret==0);
	sleep(1);
	ret=Maat_cmd_set_lines(feather, p_line,TEST_CMD_LINE_NUM, MAAT_OP_DEL);
	assert(ret==0);
	return;
}
int test_add_expr_command(Maat_feather_t feather,const char* region_table,int config_id, int timeout,int label_id, const char* keywords)
{
	struct Maat_cmd_t* cmd=NULL;
	struct Maat_rule_t rule;

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
	ret=Maat_cmd_commit(feather);
	if(ret<0)
	{
		printf("Commit Maat command %d failed.\n",rule.config_id);
	}
	return 0;

}
int test_add_ip_command(Maat_feather_t feather,const char* region_table)
{
	struct Maat_cmd_t* cmd=NULL;
	struct Maat_rule_t rule;
	int config_id=0,timeout=2;
	

	

	struct Maat_region_t region;
	int group_num=1,ret=0;
	memset(&rule,0,sizeof(rule));

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

	ret=Maat_cmd(feather, cmd, MAAT_OP_ADD);
	if(ret<0)
	{
		printf("Add Maat command %d failed.\n",rule.config_id);
		Maat_free_cmd(cmd);
		return 0;
	}
	Maat_free_cmd(cmd);

	//TEST if the command go into effective.
	sleep(1);	//waiting for commands go into effect
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
	scan_status_t mid=NULL;
	table_id=Maat_table_register(feather,region_table);
	if(table_id<0)
	{
		printf("Database table %s register failed.\n",region_table);
		
	}
	else
	{
		ret=Maat_scan_proto_addr(feather,table_id,&ipv4_addr,6,&result,1, &mid,0);
		if(ret==1&&result.config_id==config_id)
		{
			printf("Test Maat add IP rule Success.\n");
		}
		else
		{
			printf("Test Maat add IP rule Failed.\n");
		}
	}
	Maat_clean_status(&mid);

	sleep(timeout+1);//wait for commands expired.
	ret=Maat_scan_proto_addr(feather,table_id,&ipv4_addr,6,&result,1, &mid,0);
	if(ret==0)
	{
		printf("Test Maat expired IP rule Success.\n");
	}
	else
	{
		printf("Test Maat expired IP rule Failed.\n");
	}
	Maat_clean_status(&mid);

	return 0;

}
int test_del_command(Maat_feather_t feather,int config_id)
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
void test_command(Maat_feather_t feather)
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
	Maat_str_escape(escape_buff1, sizeof(escape_buff1),keywords1);
	Maat_str_escape(escape_buff2, sizeof(escape_buff2),keywords2);
	snprintf(keywords,sizeof(keywords),"%s&%s",escape_buff1,escape_buff2);
	config_id=(int)Maat_cmd_incrby(feather, "TEST_SEQ", 1);
	test_add_expr_command(feather,table_name,config_id, 0, label_id, keywords);
	sleep(1);//waiting for commands go into effect
	table_id=Maat_table_register(feather,table_name);
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result,NULL, 1,
						&mid, 0);

	if(ret>0&&result.config_id==config_id)
	{
		printf("Test Maat add EXPR rule success %s\n",print_maat_result(&result,ret));
	}
	else
	{
		printf("Test Maat add EXPR rule failed.\n");
	}
	Maat_clean_status(&mid);
	output_id_cnt=Maat_cmd_select(feather,label_id, output_ids, 4);
	if(output_id_cnt==1&&output_ids[0]==config_id)
	{
		printf("Test Maat select command success.\n");
	}
	else
	{
		printf("Test Maat select command label %d failed.\n",label_id);
	}
	test_del_command(feather, config_id);
	sleep(1);//waiting for commands go into effect
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result,NULL, 1,
						&mid, 0);
	if(ret>0)
	{
		printf("Test Maat delete EXPR command failed\n");
	}
	else
	{
		printf("Test Maat delete EXPR command success.\n");
	}
	Maat_clean_status(&mid);
	timeout=1;
	test_add_expr_command(feather,table_name,config_id, timeout, label_id, keywords);
	sleep(timeout+1);
	ret=Maat_full_scan_string(feather, table_id,CHARSET_GBK, scan_data, strlen(scan_data), 
						&result,NULL, 1,
						&mid, 0);

	if(ret>0&&result.config_id==config_id)//should not hit
	{
		printf("Test Maat command expire EXPR failed.");
	}
	else
	{
		printf("Test Maat command expire success.\n");
	}
	Maat_clean_status(&mid);
}
#define	FILE_CHUNK_SIZE	4096
void test_sfh_digest(const char* filename)
{
	char * file_buff=NULL,*sfh_ordered=NULL,*sfh_unorder=NULL;
	int read_size=0,ret=0,chunk_num=0,i=0,idx=0;
	unsigned long long *offset=NULL;
	unsigned long long file_size=0,tmp=0,hash_length=0;
	FILE* fp=fopen(filename,"r");
	sfh_instance_t * fhandle = NULL;
	struct stat file_info;
	ret=stat(filename, &file_info);
	if(ret!=0)
	{
		printf("%s stat file %s error.\n",__FUNCTION__,filename);
		goto error_out;
	}
	file_size=file_info.st_size;
	file_buff=(char*)malloc(file_size);
	ret=fread(file_buff,1,file_size,fp);
	if((unsigned long long)ret!=file_size)
	{
		printf("%s read file %s error.\n",__FUNCTION__,filename);
		free(file_buff);
		goto error_out;
	}
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
	if(0==strcmp(sfh_ordered,sfh_unorder))
	{
		printf("Test SFH success.\n");
	}
	else
	{
		printf("Test SFH failed.\n");
	}
error_out:
	fclose(fp);
	free(file_buff);
	free(sfh_ordered);
	free(sfh_unorder);
	free(offset);
}
void maat_test_print_usage(void)
{
	printf("Maat Test Usage:\n");
	printf("\tSource:\n");
	printf("\t\t-j Test updating from %s.\n",json_path);
	printf("\t\t-u Load config from %s, and monitor %s. Need manually move inc index.\n",ful_cfg_dir,inc_cfg_dir);
	printf("\t\t-r Read config redis %s:%u db0.\n",test_maat_redis_ip,test_maat_redis_port);
	printf("\tOption:\n");
	printf("\t\t-d Deferred Loading config.\n");
	printf("example: ./maat_test -j -d\n");
	
	return;
}
int main(int argc,char* argv[])
{
	Maat_feather_t feather=NULL;
	int g_iThreadNum=4;
	const char*	table_info_path="./table_info.conf";

	const char* log_file="./test.log";
	const char* stat_file="./scan_staus.log";
	const char* decrypt_key="mesa2017wy";
	const char* test_digest_file="./testdata/digest_test.data";
	int scan_interval_ms=10;
	int effective_interval_ms=10;

	int scan_detail=0,deferred_load_on=0;
	int using_redis=0;
	scan_status_t mid=NULL;
	int wait_second=400;

	if(argc<2||argv[1][0]!='-')
	{
		maat_test_print_usage();
		return 0;
	}
	void *logger=MESA_create_runtime_log_handle(log_file,0);

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
				wait_second=14;
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
	Maat_set_feather_opt(feather, MAAT_OPT_EFFECT_INVERVAL_MS,&effective_interval_ms, sizeof(scan_interval_ms));

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
	if(deferred_load_on==1)
	{
		printf("Deferred Load ON, Waiting...\n");
		sleep(1);
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

	test_digest_scan(feather,"FILE_DIGEST",test_digest_file,&mid);
	Maat_clean_status(&mid);

	test_expr_plus(feather, "HTTP_REGION", &mid);
	Maat_clean_status(&mid);

	test_url_encode(feather, "HTTP_URL", &mid);
	Maat_clean_status(&mid);

	test_unicode_esc(feather,"KEYWORDS_TABLE",&mid);
	Maat_clean_status(&mid);

	test_unescape_string_scan(feather,"KEYWORDS_TABLE",&mid);
	Maat_clean_status(&mid);

	test_str_stream_scan(feather,"HTTP_URL", &mid);
	Maat_clean_status(&mid);

	test_string_similar_scan(feather,"SIM_URL",&mid);
	Maat_clean_status(&mid);

	test_table_conjunction(feather, "HTTP_URL", "HTTP_HOST", &mid);
	Maat_clean_status(&mid);
	
	test_offset_str_scan(feather,"IMAGE_FP");
	
	if(1==using_redis)
	{
		test_command(feather);
		test_set_cmd_line(feather);
		test_add_ip_command(feather,"IP_CONFIG");
	}
	test_sfh_digest(test_digest_file);
	sleep(wait_second);
	
	Maat_burn_feather(feather);
	
	return 0;
}
