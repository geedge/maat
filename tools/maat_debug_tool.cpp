#include "Maat_rule.h"
#include "Maat_command.h"
#include <MESA/MESA_handle_logger.h>

#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <getopt.h>
#include <sys/stat.h>


int debug_maat_str_scan(Maat_feather_t feather, const char* table_name, const char* district, char* data, size_t sz)
{
	int table_id=0,ret=0;
	int i=0;
	int scan_result_max=64;
	struct Maat_rule_t result[scan_result_max];
	scan_status_t mid=NULL;


	table_id=Maat_table_register(feather, table_name);
	if(table_id<0)
	{
		printf("Unkown table %s\n", table_name);
	}
	
	struct Maat_hit_detail_t *hit_detail=(struct Maat_hit_detail_t *)malloc(sizeof(struct Maat_hit_detail_t)*10);

	enum MAAT_CHARSET maat_charset=CHARSET_UTF8;

	if(strlen(district)>0)
	{	
		ret=Maat_set_scan_status(feather, &mid, MAAT_SET_SCAN_DISTRICT, district, strlen(district));
	}
	
	ret=Maat_full_scan_string(feather, table_id, maat_charset, data, sz, 
						result, NULL, scan_result_max,
						&mid, 0);
	printf("Scan table %s ", table_name);
	if(ret==-1)
	{
		printf("error.\n");
	}
	else if(ret==-2)
	{
		printf("hits group, but not compile.\n");
	}
	else if(ret==0)
	{
		printf("not hit.");
	}
	else
	{
		printf("hits ");
		for(i=0; i<ret; i++)
		{
			printf("%d, ", result[i].config_id);
		}
	}
	printf("\n");

	free(hit_detail);
	Maat_clean_status(&mid);
	return 0;
}
enum tool_arg_type{
	ARG_TABLE_INFO=0,
	ARG_TABLE_NAME,
	ARG_SCAN_FILE,
	ARG_SCAN_STRING,
	ARG_SCAN_DISTRICT,
	ARG_SCAN_CHARSET,
	ARG_INPUT_JSON,
	ARG_DECRYPT_KEY,
	ARG_ACCEPT_TAGS,
	__ARG_MAX
};

int main(int argc, char ** argv)
{
	FILE* fp=NULL;
	char* file_buff=NULL;
	size_t file_size=0;
	struct stat file_info;	
	char arg_value[__ARG_MAX][1024];
	memset(arg_value, 0, sizeof(arg_value));
	if(argc<2)
	{
		return 0;
	}
	int c=0;
	while (1) {
		int option_index = 0;
		static struct option long_options[]={
			{"table-info",		required_argument, 0, 0},
			{"table-name",		required_argument, 0, 0},
			{"scan-file",		optional_argument, 0, 0},
			{"scan-string",	optional_argument, 0, 0},
			{"scan-district", optional_argument, 0, 0},
			{"scan-charset",	optional_argument, 0, 0},
			{"maat-json",		required_argument, 0, 0},
			{"decrypt-key",	optional_argument, 0, 0},
			{"accept-tags",	optional_argument, 0, 0},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "ab", long_options, &option_index);
		if (c == -1)
			break;
		if(c!=0)
		{
			printf("Invalid parameter, long options only.\n");
		}
		else
		{
			strcpy(arg_value[option_index], optarg);
		}
	}

	const char* log_file="./test.log";
	int scan_detail=0, ret=0;
	Maat_feather_t feather=NULL;
	void *g_logger=NULL;

	g_logger=MESA_create_runtime_log_handle(log_file, 0);

	feather=Maat_feather(4, arg_value[ARG_TABLE_INFO], g_logger);
	Maat_set_feather_opt(feather, MAAT_OPT_INSTANCE_NAME, "debugtool", strlen("debugtool")+1);
	if(strlen(arg_value[ARG_DECRYPT_KEY])>0)
	{
		Maat_set_feather_opt(feather, MAAT_OPT_DECRYPT_KEY, arg_value[ARG_DECRYPT_KEY], strlen(arg_value[ARG_DECRYPT_KEY])+1);
	}
	if(strlen(arg_value[ARG_ACCEPT_TAGS])>0)
	{
		Maat_set_feather_opt(feather, MAAT_OPT_ACCEPT_TAGS, arg_value[ARG_ACCEPT_TAGS], strlen(arg_value[ARG_ACCEPT_TAGS])+1);
	}
	ret=Maat_set_feather_opt(feather, MAAT_OPT_JSON_FILE_PATH, arg_value[ARG_INPUT_JSON], strlen(arg_value[ARG_INPUT_JSON])+1);
	if(ret!=0)
	{
		printf("Read %s failed, invalid maat json.\n", arg_value[ARG_INPUT_JSON]);
		ret=-1;
		goto clean_up;
	}
	Maat_set_feather_opt(feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
	Maat_initiate_feather(feather);

	if(strlen(arg_value[ARG_SCAN_FILE])>0)
	{
	
		if(stat(arg_value[ARG_SCAN_FILE], &file_info)<0)
		{		
			printf("Stat %s failed.\n", arg_value[ARG_SCAN_FILE]);
			goto clean_up;
		}
		file_size=file_info.st_size;
		fp=fopen(arg_value[ARG_SCAN_FILE], "r");
		if(fp==NULL)
		{
			printf("Open %s failed.\n", arg_value[ARG_SCAN_FILE]);
			goto clean_up;
		}
		file_buff=(char*)malloc(file_size);
		fread(file_buff,1,file_size,fp);
		fclose(fp);
		
		debug_maat_str_scan(feather, arg_value[ARG_TABLE_NAME], arg_value[ARG_SCAN_DISTRICT], file_buff, file_size);
		free(file_buff);
	}
clean_up:
	Maat_burn_feather(feather);
	MESA_destroy_runtime_log_handle(g_logger);
	return ret;
}


