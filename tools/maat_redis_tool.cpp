#include "Maat_rule.h"
#include "Maat_command.h"
#include "Maat_rule_internal.h"
#include "json2iris.h"
#include "config_monitor.h"
#include "hiredis.h"
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
const char* redis_dump_dir="./redis_dump";
void maat_tool_print_usage(void)
{
	printf("maat_redis_tool manipulate rules from redis.\n");
	printf("Usage:\n");
	printf("\t-h [host], redis IP, 127.0.0.1 as default.\n");
	printf("\t-p [port], redis port, 6379 as default.\n");
	printf("\t-d [dir], dump rules from redis to [dir], %s as default.\n",redis_dump_dir);
	printf("example: ./maat_redis_tool -h 127.0.0.1 -p 6379 -d %s\n",redis_dump_dir);
	
	return;
}
static int compare_serial_rule(const void *a, const void *b)
{
	struct serial_rule_t *ra=(struct serial_rule_t *)a;
	struct serial_rule_t *rb=(struct serial_rule_t *)b;

	char p_str[256],q_str[256];
	snprintf(p_str,sizeof(p_str),"%s.%d",ra->table_name,ra->rule_id);
	snprintf(q_str,sizeof(q_str),"%s.%d",rb->table_name,rb->rule_id);
	return strcmp(p_str,q_str);
}
void read_rule_from_redis(const char*redis_ip, int redis_port, int redis_db,const char* output_path ,void*logger)
{
	struct serial_rule_t* rule_list;
	int rule_num=0,line_count=0;
	int i=0,ret=0;
	int update_type=CM_UPDATE_TYPE_INC;
	unsigned int version=0;
	const char* cur_table=NULL;

	char table_path[256],index_path[256];
	FILE *table_fp=NULL, *index_fp=NULL;

	struct timeval connect_timeout;
	connect_timeout.tv_sec=0;
	connect_timeout.tv_usec=100*1000; // 100 ms

	redisContext * ctx;
	ctx=redisConnectWithTimeout(redis_ip, redis_port,connect_timeout);
	if(ctx==NULL)
	{
		printf("Unable to connect %s:%d db%d\n",redis_ip,redis_port,redis_db);
		return;
	}

	printf("Reading key list from %s:%d db%d.\n",redis_ip,redis_port,redis_db);
	rule_num=get_rm_key_list(0, ctx, &rule_list, logger,&version, &update_type);
	if(rule_num==0)
	{
		printf("No Effective Rules.\n");
		return;
	}
	if(rule_num<0)
	{
		printf("Read Redis Error.\n");
		return;
	}

	assert(update_type==CM_UPDATE_TYPE_FULL);
	printf("MAAT Version: %d, key number: %d\n", version, rule_num);
	printf("Reading value: ");
	ret=get_maat_redis_value(ctx,rule_list,rule_num,logger,1);
	if(ret<0)
	{
		goto clean_up;
	}
	printf("Sorting.\n");
	qsort(rule_list,rule_num, sizeof(struct serial_rule_t),
                  compare_serial_rule);
	if((access(output_path,F_OK)) <0)

	{	if((mkdir(output_path,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) < 0)
		printf("mkdir %s error\n",output_path);

	}
	snprintf(index_path,sizeof(index_path),"%s/full_config_index.%010d",output_path,version);
	index_fp=fopen(index_path,"w");
	if(index_fp==NULL)
	{
		printf("Open %s failed.\n",index_path);
		goto clean_up;
	}

	for(i=0;i<rule_num;i++)
	{
		if(cur_table==NULL||0!=strcmp(cur_table,rule_list[i].table_name))
		{
			if(table_fp!=NULL)
			{
				fprintf(index_fp,"%s\t%d\t%s\n",cur_table,line_count,table_path);
				fclose(table_fp);
				table_fp=NULL;
				set_file_rulenum(table_path,line_count, logger);
				line_count=0;
			}
			snprintf(table_path,sizeof(table_path),"%s/%s.%010d",output_path,rule_list[i].table_name,version);
			set_file_rulenum(table_path, 0, logger);
			table_fp=fopen(table_path,"a");
			if(table_fp==NULL)
			{
				printf("Open %s failed.\n",table_path);
				goto clean_up;
			}
			printf("Writing %s\n",table_path);
			cur_table=rule_list[i].table_name;
		}
		fprintf(table_fp,"%s\tkey=%d\n",rule_list[i].table_line,rule_list[i].rule_id);
		line_count++;
	}
	fclose(table_fp);
	table_fp=NULL;
	fprintf(index_fp,"%s\t%d\t%s\n",cur_table,line_count,table_path);
	set_file_rulenum(table_path,line_count, logger);
	
	printf("Writing complete: %s\n",index_path);
clean_up:
	for(i=0;i<rule_num;i++)
	{
		empty_serial_rules(rule_list+i);
	}
	free(rule_list);
	rule_list=NULL;
	if(ctx!=NULL)
	{
		redisFree(ctx);
	}
	if(index_fp!=NULL)
	{
		fclose(index_fp);
	}
	if(table_fp!=NULL)
	{
		fclose(table_fp);
	}
	return;
}
int main(int argc, char * argv[])
{
	int oc=0;
	//char model='?';
	char redis_ip[64];
	int redis_port=6379;
	int redis_db=0;
	strncpy(redis_ip,"127.0.0.1",sizeof(redis_ip));
	char table_info[128];
	strncpy(table_info,"./table_info.conf",sizeof(table_info));
	char dump_dir[128];
	strncpy(dump_dir,redis_dump_dir,sizeof(dump_dir));
	while((oc=getopt(argc,argv,"mh:p:t:d:f:"))!=-1)
	{
		switch(oc)
		{
			case 'm':
				//model=oc;
				break;
			case 'h':
				strncpy(redis_ip,optarg,sizeof(redis_ip));
				break;
			case 'p':
				sscanf(optarg,"%d",&redis_port);
				break;
			case 't':
				strncpy(table_info,optarg,sizeof(table_info));
				break;
			case 'd':
				strncpy(dump_dir,optarg,sizeof(dump_dir));
				if(dump_dir[strlen(dump_dir)-1]=='/')
				{
					dump_dir[strlen(dump_dir)-1]='\0';
				}
				break;
			case '?':
			default:
				maat_tool_print_usage();
				return 0;
				break;
		}
	}
	read_rule_from_redis(redis_ip,redis_port, redis_db,dump_dir, NULL);
}
