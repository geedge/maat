
#include <MESA/MESA_handle_logger.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <MESA/MESA_htable.h>
#include "cJSON.h"
#include "map_str2int.h"
#include "Maat_rule_internal.h"
#define maat_json (module_name_str("MAAT_JSON"))

const char* untitled_group_name="Untitled";
const int json_version=1;
#define	MAX_PATH_LINE	256
#define	MAX_COLUMN_NUM	32
struct group_info_t
{
	int group_id;
};
struct iris_table_t
{
	char table_name[MAX_PATH_LINE];
	char table_path[MAX_PATH_LINE];
	int line_count;
};
struct iris_description_t
{
	int group_cnt;
	int region_cnt;
	
	char tmp_iris_dir[MAX_PATH_LINE];
	char tmp_iris_index_dir[MAX_PATH_LINE];
	char index_path[MAX_PATH_LINE];

	struct iris_table_t group_table;
	struct iris_table_t compile_table;
	MESA_htable_handle group_name_map;
	MESA_htable_handle iris_table_map;
	MESA_htable_handle str2int_map;
	
};
struct traslate_command_t
{
	const char* json_string;
	char* json_value;
	int json_type;
	int str2int_flag;
	int empty_allowed;
	const char* default_string;
	int default_int;
};
int set_iris_descriptor(const char* json_file,cJSON *json,const char*compile_tn,const char* group_tn,struct iris_description_t *iris_cfg,void * logger)
{
	memset(iris_cfg,0,sizeof(struct iris_description_t));
	snprintf(iris_cfg->tmp_iris_dir,sizeof(iris_cfg->tmp_iris_dir),"%s_iris_tmp",json_file);
	snprintf(iris_cfg->tmp_iris_index_dir,sizeof(iris_cfg->tmp_iris_index_dir),"%s_iris_tmp/index",json_file);
	snprintf(iris_cfg->index_path,sizeof(iris_cfg->index_path),"%s/full_config_index.%010d",iris_cfg->tmp_iris_index_dir,json_version);


	memcpy(iris_cfg->compile_table.table_name,compile_tn,strlen(compile_tn));
	snprintf(iris_cfg->compile_table.table_path,sizeof(iris_cfg->compile_table.table_path),
			"%s/%s.local",iris_cfg->tmp_iris_dir,iris_cfg->compile_table.table_name);

	memcpy(iris_cfg->group_table.table_name,group_tn,strlen(group_tn));
	snprintf(iris_cfg->group_table.table_path,sizeof(iris_cfg->group_table.table_name),
			"%s/%s.local",iris_cfg->tmp_iris_dir,iris_cfg->group_table.table_name);
	
	MESA_htable_create_args_t hargs;
	memset(&hargs,0,sizeof(hargs));
	hargs.thread_safe=1;
	hargs.hash_slot_size = 1024;
	hargs.max_elem_num = 0;
	hargs.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	hargs.expire_time = 0;
	hargs.key_comp = NULL;
	hargs.key2index = NULL;
	hargs.recursive = 0;
	hargs.data_free = free;
	hargs.data_expire_with_condition = NULL;
	
	iris_cfg->group_name_map=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(iris_cfg->group_name_map, 0);
	
	iris_cfg->iris_table_map=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(iris_cfg->iris_table_map, 0);

	iris_cfg->str2int_map=map_create();
	
	map_register(iris_cfg->str2int_map, "yes",1);
	map_register(iris_cfg->str2int_map, "no",0);
	
	map_register(iris_cfg->str2int_map, "ip",TABLE_TYPE_IP);
	map_register(iris_cfg->str2int_map, "string",TABLE_TYPE_EXPR);
	map_register(iris_cfg->str2int_map, "expr",TABLE_TYPE_EXPR);
	map_register(iris_cfg->str2int_map, "expr_plus",TABLE_TYPE_EXPR_PLUS);
	map_register(iris_cfg->str2int_map, "intval",TABLE_TYPE_INTERVAL);
	map_register(iris_cfg->str2int_map, "digest",TABLE_TYPE_DIGEST);
	map_register(iris_cfg->str2int_map, "similar",TABLE_TYPE_SIMILARITY);

	
	map_register(iris_cfg->str2int_map, "ipv4",4);
	map_register(iris_cfg->str2int_map, "ipv6",6);

	map_register(iris_cfg->str2int_map, "double",0);
	map_register(iris_cfg->str2int_map, "single",1);

	map_register(iris_cfg->str2int_map, "none",0);
	map_register(iris_cfg->str2int_map, "and",1);
	map_register(iris_cfg->str2int_map, "regex",2);
	map_register(iris_cfg->str2int_map, "offset",3);

	map_register(iris_cfg->str2int_map, "sub",0);
	map_register(iris_cfg->str2int_map, "right",1);
	map_register(iris_cfg->str2int_map, "left",2);
	map_register(iris_cfg->str2int_map, "complete",3);

	map_register(iris_cfg->str2int_map, "uncase plain",0);
	map_register(iris_cfg->str2int_map, "hexbin",1);
	map_register(iris_cfg->str2int_map, "case plain",2);

	return 0;
}
void clear_iris_descriptor(struct iris_description_t *iris_cfg)
{
	if(iris_cfg->group_name_map!=NULL)
	{
		MESA_htable_destroy(iris_cfg->group_name_map, NULL);
	}
	if(iris_cfg->iris_table_map!=NULL)
	{
		MESA_htable_destroy(iris_cfg->iris_table_map, NULL);
	}
	return;
}
int create_tmp_dir(struct iris_description_t *p)
{

	
	if((access(p->tmp_iris_dir,F_OK))<0)
	{
		if((mkdir(p->tmp_iris_dir, 0777)) < 0)
		{
			return -1;
		}
	}
	if((access(p->tmp_iris_index_dir,F_OK))<0)
	{
		if((mkdir(p->tmp_iris_index_dir, 0777)) < 0)
		{
			return -1;
		}
	}
	return 0;
}
int set_file_rulenum(const char* path,int rulenum,void* logger)
{
	FILE* fp=NULL;
	if(rulenum==0)
	{
		fp=fopen(path,"w");
	}
	else
	{
		fp=fopen(path,"r+");
	}
	if(fp==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
							"fopen %s failed %s at set rule num.",path,strerror(errno));
		return -1;
	}
	fprintf(fp,"%010d\n",rulenum);
	fclose(fp);
	return 0;
}
int direct_write_rule(cJSON* json,MESA_htable_handle str2int,struct traslate_command_t*cmd,int cmd_cnt,const char* path,void* logger)
{
	int i=0,ret=-1;
	cJSON* item=NULL;
	cJSON dummy;
	char *p=NULL;
	int int_value=0;
	FILE* fp=NULL;
	for(i=0;i<cmd_cnt;i++)
	{
		item=cJSON_GetObjectItem(json,cmd[i].json_string);
		if(item==NULL&&cmd[i].empty_allowed==1)
		{
			dummy.valuestring=(char*)cmd[i].default_string;
			dummy.valueint=cmd[i].default_int;
			dummy.valuedouble=cmd[i].default_int;
			dummy.type=cmd[i].json_type;
			
			item=&dummy;
		}
		if(item==NULL||item->type!=cmd[i].json_type)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
									"%s not defined or wrong format.",cmd[i].json_string);
			goto error_out;
		}
		if(cmd[i].str2int_flag==1)
		{
			p=item->valuestring;
			ret=map_str2int(str2int, p, &int_value);			
			if(ret<0)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
										"%s's value %s is not valid format.",cmd[i].json_string,p);
				free(p);
				goto error_out;
			}
			cmd[i].json_value=(char*)malloc(21);/* 2^64+1 can be represented in 21 chars. */
			snprintf(cmd[i].json_value,21,"%d",int_value);

		}
		else
		{
			switch(item->type)
			{
				case cJSON_Number:
					cmd[i].json_value=cJSON_Print(item);
					break;
				case cJSON_String:
					cmd[i].json_value=(char*)calloc(strlen(item->valuestring)+1,1);
					memcpy(cmd[i].json_value,item->valuestring,strlen(item->valuestring));
					break;
				default://impossible ,already checked
					assert(0);
					break;
			}
		}
	}
	fp=fopen(path,"a");
	if(fp==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
										"fopen %s error %s.",path,strerror(errno));
		goto error_out;
	}
	for(i=0;i<cmd_cnt;i++)
	{
		fprintf(fp,"%s\t",cmd[i].json_value);
	}
	fprintf(fp,"\n");
	fclose(fp);

	for(i=0;i<cmd_cnt;i++)
	{
		if(cmd[i].json_value!=NULL)
		{
			free(cmd[i].json_value);
		}
	}
	return 0;
	
error_out:
	for(i=0;i<cmd_cnt;i++)
	{
		if(cmd[i].json_value!=NULL)
		{
			free(cmd[i].json_value);
		}
	}
	return -1;
}
int write_ip_rule(cJSON *region_json,struct iris_description_t *p_iris,const char* path,void * logger)
{
	struct traslate_command_t json_cmd[MAX_COLUMN_NUM];
	int cmd_cnt=0;
	memset(json_cmd,0,sizeof(json_cmd));

	json_cmd[cmd_cnt].json_string="region_id";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="group_id";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	json_cmd[cmd_cnt].json_string="addr_type";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].str2int_flag=1;
	cmd_cnt++;
	
	json_cmd[cmd_cnt].json_string="src_ip";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="0.0.0.0";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="mask_src_ip";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="255.255.255.255";
	cmd_cnt++;	

	json_cmd[cmd_cnt].json_string="src_port";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="0";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="mask_src_port";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="65535";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="dst_ip";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="0.0.0.0";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="mask_dst_ip";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="255.255.255.255";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="dst_port";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="0";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="mask_dst_port";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="65535";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="protocol";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_int=0;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="direction";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].str2int_flag=1;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="double";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="is_valid";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	return direct_write_rule(region_json, p_iris->str2int_map,json_cmd, cmd_cnt,path,logger);
}
int write_expr_rule(cJSON *region_json,struct iris_description_t *p_iris,const char* path,enum MAAT_TABLE_TYPE table_type,void * logger)
{
	struct traslate_command_t json_cmd[MAX_COLUMN_NUM];
	int cmd_cnt=0;
	memset(json_cmd,0,sizeof(json_cmd));

	json_cmd[cmd_cnt].json_string="region_id";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="group_id";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	if(table_type==TABLE_TYPE_EXPR_PLUS)
	{
		json_cmd[cmd_cnt].json_string="district";
		json_cmd[cmd_cnt].json_type=cJSON_String;
		cmd_cnt++;
	}

	json_cmd[cmd_cnt].json_string="keywords";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="expr_type";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].str2int_flag=1;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="match_method";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].str2int_flag=1;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="format";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].str2int_flag=1;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="is_valid";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	return direct_write_rule(region_json, p_iris->str2int_map,json_cmd, cmd_cnt,path,logger);

}
int write_intval_rule(cJSON *region_json,struct iris_description_t *p_iris,const char* path,void * logger)
{
	struct traslate_command_t json_cmd[MAX_COLUMN_NUM];
	int cmd_cnt=0;
	memset(json_cmd,0,sizeof(json_cmd));
	
	json_cmd[cmd_cnt].json_string="region_id";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="group_id";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	json_cmd[cmd_cnt].json_string="low_boundary";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="up_boundary";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="is_valid";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	return direct_write_rule(region_json, p_iris->str2int_map,json_cmd, cmd_cnt,path,logger);

}
int write_digest_rule(cJSON *region_json,struct iris_description_t *p_iris,const char* path,void * logger)
{
	struct traslate_command_t json_cmd[MAX_COLUMN_NUM];
	int cmd_cnt=0;
	memset(json_cmd,0,sizeof(json_cmd));
	
	json_cmd[cmd_cnt].json_string="region_id";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="group_id";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	json_cmd[cmd_cnt].json_string="raw_len";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="digest";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="cfds_level";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="is_valid";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	return direct_write_rule(region_json, p_iris->str2int_map,json_cmd, cmd_cnt,path,logger);

}
int write_similar_rule(cJSON *region_json,struct iris_description_t *p_iris,const char* path,void * logger)
{
	struct traslate_command_t json_cmd[MAX_COLUMN_NUM];
	int cmd_cnt=0;
	memset(json_cmd,0,sizeof(json_cmd));
	
	json_cmd[cmd_cnt].json_string="region_id";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="group_id";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	json_cmd[cmd_cnt].json_string="target";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="threshold";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="is_valid";
	json_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	return direct_write_rule(region_json, p_iris->str2int_map,json_cmd, cmd_cnt,path,logger);

}
struct iris_table_t* query_table_info(iris_description_t* p_iris,const char* table_name)
{
	struct iris_table_t* table_info=NULL;
	table_info=(struct iris_table_t*)MESA_htable_search(p_iris->iris_table_map, (const unsigned char*)table_name,strlen(table_name));
	if(table_info==NULL)
	{
		table_info=(struct iris_table_t*)calloc(sizeof(struct iris_table_t),1);
		table_info->line_count=0;
		memcpy(table_info->table_name,table_name,MIN(sizeof(table_info->table_name)-1, strlen(table_name)));
		snprintf(table_info->table_path,sizeof(table_info->table_path),"%s/%s.local",p_iris->tmp_iris_dir,table_info->table_name);
		MESA_htable_add(p_iris->iris_table_map,(const unsigned char*)table_info->table_name,strlen(table_info->table_name),table_info);
	}
	return table_info;
}
int write_plugin_table(cJSON* plug_table_json,int sequence,iris_description_t* p_iris,void* logger)
{
	cJSON* item=NULL,*table_content=NULL,*each_line=NULL;
	struct iris_table_t* table_info=NULL;
	const char* table_name=NULL,*line_content=NULL;
	int ret=0,i=0,line_cnt=0;
	FILE*fp=NULL;
	
	item=cJSON_GetObjectItem(plug_table_json,"table_name");
	if(item==NULL||item->type!=cJSON_String)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"The %d plugin_table's table_name not defined or format error.",sequence);
		return -1;
	}
	table_name= item->valuestring;
	table_info=query_table_info(p_iris, table_name);
	table_content=cJSON_GetObjectItem(plug_table_json,"table_content");
	if(table_content==NULL||table_content->type!=cJSON_Array)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"%d plugin_table's table_content not defined or format error."
								,sequence);
		return -1;
	}
	line_cnt=cJSON_GetArraySize(table_content);
	if(table_info->line_count==0)
	{
		ret=set_file_rulenum(table_info->table_path,0,logger);
		if(ret<0)
		{
			return -1;
		}
	}
	fp=fopen(table_info->table_path,"a");
	if(fp==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
										"fopen %s error %s.",table_info->table_path,strerror(errno));
		return -1;
	}

	for(i=0;i<line_cnt;i++)
	{
		each_line=cJSON_GetArrayItem(table_content,i);
		if(each_line==NULL||each_line->type!=cJSON_String)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
									"plugin_table %s's line %d format error.",table_info->table_name,i+1);
			continue;
		}
		line_content=each_line->valuestring;
		fprintf(fp,"%s\n",line_content);
		table_info->line_count++;
	}
	fclose(fp);
	set_file_rulenum(table_info->table_path,table_info->line_count,logger);
	return 0;
}
int write_region_rule(cJSON* region_json,int compile_id,int group_id,iris_description_t* p_iris,void* logger)
{
	cJSON* item=NULL,*table_content=NULL;
	int ret=0;
	int region_id=0;
	const char* table_name=NULL,*table_type_str=NULL;
	enum MAAT_TABLE_TYPE table_type=TABLE_TYPE_EXPR;
	struct iris_table_t* table_info=NULL;
	
	item=cJSON_GetObjectItem(region_json,"table_name");
	if(item==NULL||item->type!=cJSON_String)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"compile rule %d's region table_name not defined or format error.",compile_id);
		return -1;
	}
	table_name=item->valuestring;
	table_info=query_table_info( p_iris, table_name);
	item=cJSON_GetObjectItem(region_json,"table_type");
	if(item==NULL||item->type!=cJSON_String)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"compile rule %d table name %s's table_type not defined or format error."
								,compile_id,table_name);
		return -1;
	}
	table_type_str=item->valuestring;
	ret=map_str2int(p_iris->str2int_map,table_type_str,(int*)&(table_type));
	if(ret!=1)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"compile rule %d table name %s's table_type %s invalid."
								,compile_id,table_name,table_type_str);
		return -1;
	}
	table_content=cJSON_GetObjectItem(region_json,"table_content");
	if(table_content==NULL||table_content->type!=cJSON_Object)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"compile rule %d table name %s's table_content not defined or format error."
								,compile_id,table_name);
		return -1;
	}
	if(table_info->line_count==0)
	{
		ret=set_file_rulenum(table_info->table_path,0,logger);
		if(ret<0)
		{
			return -1;
		}
	}
	region_id=p_iris->region_cnt++;
	cJSON_AddNumberToObject(table_content, "region_id", region_id);
	cJSON_AddNumberToObject(table_content, "group_id", group_id);
	cJSON_AddNumberToObject(table_content, "is_valid", 1);

	switch(table_type)
	{
		case TABLE_TYPE_EXPR:
		case TABLE_TYPE_EXPR_PLUS:
			ret=write_expr_rule(table_content, p_iris, table_info->table_path,table_type, logger);
			break;
		case TABLE_TYPE_IP:
			ret=write_ip_rule(table_content, p_iris, table_info->table_path, logger);
			break;
		case TABLE_TYPE_INTERVAL:
			ret=write_intval_rule(table_content, p_iris, table_info->table_path, logger);
			break;
		case TABLE_TYPE_DIGEST:
			ret=write_digest_rule(table_content, p_iris, table_info->table_path, logger);
			break;
		case TABLE_TYPE_SIMILARITY:
			write_similar_rule(table_content, p_iris,table_info->table_path, logger);
			break;
		default:
			assert(0);
			break;
	}
	if(ret>=0)
	{
		table_info->line_count++;
		set_file_rulenum(table_info->table_path,table_info->line_count,logger);
	}
	return ret;
}

int write_compile_rule(cJSON *compile,struct iris_description_t *p_iris,void * logger)
{
	int compile_id=-1,cmd_cnt=0,ret=-1;
	cJSON* item=NULL;
	struct traslate_command_t compile_cmd[MAX_COLUMN_NUM];
	memset(compile_cmd,0,sizeof(compile_cmd));
	compile_cmd[cmd_cnt].json_string="compile_id";
	compile_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	compile_cmd[cmd_cnt].json_string="service";
	compile_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	compile_cmd[cmd_cnt].json_string="action";
	compile_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;
	
	compile_cmd[cmd_cnt].json_string="do_blacklist";
	compile_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	compile_cmd[cmd_cnt].json_string="do_log";
	compile_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	compile_cmd[cmd_cnt].json_string="effective_range";
	compile_cmd[cmd_cnt].json_type=cJSON_Number;
	compile_cmd[cmd_cnt].empty_allowed=1;
	compile_cmd[cmd_cnt].default_int=0;
	cmd_cnt++;
	
	compile_cmd[cmd_cnt].json_string="user_region";
	compile_cmd[cmd_cnt].json_type=cJSON_String;
	cmd_cnt++;
	
	compile_cmd[cmd_cnt].json_string="is_valid";
	compile_cmd[cmd_cnt].json_type=cJSON_String;
	compile_cmd[cmd_cnt].str2int_flag=1;
	cmd_cnt++;

	
	if(p_iris->compile_table.line_count==0)
	{
		ret=set_file_rulenum(p_iris->compile_table.table_path, 0,logger);
		if(ret<0)
		{
			return -1;
		}
	}
	ret=direct_write_rule(compile, p_iris->str2int_map,compile_cmd,cmd_cnt, p_iris->compile_table.table_path,logger);
	if(ret<0)
	{
		return -1;
	}
	item=cJSON_GetObjectItem(compile,"compile_id");
	if(item->type!=cJSON_Number)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"compile_id format not number.");
		return -1;
	}
	compile_id=item->valueint;
	p_iris->compile_table.line_count++;
	set_file_rulenum(p_iris->compile_table.table_path,p_iris->compile_table.line_count,logger);
	return compile_id;
}
int write_group_rule(int compile_id ,int group_id,struct iris_description_t *p_iris,void * logger)
{
	FILE*fp=NULL;
	int ret=0;

	if(p_iris->group_table.line_count==0)
	{
		ret=set_file_rulenum(p_iris->group_table.table_path,0,logger);
		if(ret<0)
		{
			return -1;
		}
	}
	fp=fopen(p_iris->group_table.table_path,"a");
	if(fp==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
										"fopen %s error %s.",p_iris->group_table.table_path,strerror(errno));
		return -1;
	}
	fprintf(fp,"%d\t%d\t1\n",group_id,compile_id);
	fclose(fp);
	p_iris->group_table.line_count++;
	ret=set_file_rulenum(p_iris->group_table.table_path,p_iris->group_table.line_count,logger);
	return 0;
}
void table_idx_write_cb(const uchar * key, uint size, void * data, void * user)
{
	struct iris_table_t* p_table=(struct iris_table_t*)data;
	FILE* fp=(FILE*)user;
	fprintf(fp,"%s\t%d\t%s\n",p_table->table_name,p_table->line_count,p_table->table_path);
}
int write_index_file(struct iris_description_t *p_iris,void* logger)
{
	FILE*fp=NULL;
	fp=fopen(p_iris->index_path,"w");
	if(fp==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
									"index file %s fopen error %s.",p_iris->index_path,strerror(errno));
		return -1;
	}
	fprintf(fp,"%s\t%d\t%s\n",p_iris->compile_table.table_name
						,p_iris->compile_table.line_count
						,p_iris->compile_table.table_path);
	fprintf(fp,"%s\t%d\t%s\n",p_iris->group_table.table_name
						,p_iris->group_table.line_count
						,p_iris->group_table.table_path);
	MESA_htable_iterate(p_iris->iris_table_map, table_idx_write_cb, fp);
	fclose(fp);
	return 0;
}
int write_iris(cJSON *json,struct iris_description_t *p_iris,void* logger)
{
	int i=0,j=0,k=0;
	int compile_id=-1,compile_cnt=0,group_cnt=0,region_cnt=0,plug_table_cnt=0;
	int ret=0;
	cJSON *c_rules=NULL,*g_rules=NULL,*r_rules=NULL,*item=NULL,*plug_tables=NULL;
	cJSON *compile_rule=NULL,*group_rule=NULL,*region_rule=NULL,*each_plug_table=NULL;
	const char* group_name=NULL;
	struct group_info_t *group_info=NULL;
	struct group_info_t untitled_group;
	plug_tables=cJSON_GetObjectItem(json,"plugin_table");
	if(NULL!=plug_tables)
	{
		plug_table_cnt=cJSON_GetArraySize(plug_tables);
		for(i=0;i<plug_table_cnt;i++)
		{
			each_plug_table=cJSON_GetArrayItem(plug_tables,i);
			write_plugin_table(each_plug_table, i, p_iris, logger);
		}
	}
	c_rules=cJSON_GetObjectItem(json,"rules");
	if(c_rules==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
									"have no rules.");
		return -1;
		
	}
	compile_cnt=cJSON_GetArraySize(c_rules);
	if(compile_cnt<=0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
									"have no rules.");
		return -1;
	}
	for(i=0;i<compile_cnt;i++)
	{
		compile_rule=cJSON_GetArrayItem(c_rules,i);
		compile_id=write_compile_rule(compile_rule,p_iris, logger);
		if(compile_id<0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
									"In %d compile rule.",i);
			return -1;
		}
		g_rules=cJSON_GetObjectItem(compile_rule,"groups");
		if(g_rules==NULL)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
									"compile rule %d have no group.",compile_id);
			return -1;
		}
		group_cnt=cJSON_GetArraySize(g_rules);
		if(group_cnt<=0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
										"compile rule %d have no groups.",compile_id);
			return -1;
		}
		for(j=0;j<group_cnt;j++)
		{
			group_rule=cJSON_GetArrayItem(g_rules,j);
			item=cJSON_GetObjectItem(group_rule,"group_name");
			if(item==NULL||item->type!=cJSON_String)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_json,
											"compile rule %d's group has no name,regard as Untitled.",compile_id);
				group_name=untitled_group_name;
			}
			else
			{
				group_name=item->valuestring;
			}
			group_info=(struct group_info_t*)MESA_htable_search(p_iris->group_name_map, (const unsigned char*)group_name, strlen(group_name));
			if(group_info!=NULL)//exist group name ,region already read
			{
				ret=write_group_rule(compile_id, group_info->group_id, p_iris,  logger);
				if(ret<0)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
												"compile rule %d write group error.",compile_id);
					return -1;
				}
				r_rules=cJSON_GetObjectItem(group_rule,"regions");
				if(r_rules!=NULL)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_INFO,maat_json,
											"compile rule %d's %s declared in previous compile rule, regions NOT take effect."
											,compile_id,group_name);
				}
				continue;
			}
			if(0==strncasecmp(group_name,untitled_group_name,strlen(untitled_group_name)))
			{
				group_info=&untitled_group;
				group_info->group_id=p_iris->group_cnt++;
			}
			else
			{
				group_info=(struct group_info_t*)malloc(sizeof(struct group_info_t));
				group_info->group_id=p_iris->group_cnt++;
				MESA_htable_add(p_iris->group_name_map,(const unsigned char*)group_name, strlen(group_name),group_info);
			}
			r_rules=cJSON_GetObjectItem(group_rule,"regions");
			if(r_rules==NULL)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
											"compile rule %d's %s has no region.",compile_id,group_name);
				return -1;
			}
			region_cnt=cJSON_GetArraySize(r_rules);
			if(region_cnt<=0)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
											"compile rule %d's %s has no region.",compile_id,group_name);
				return -1;
			}
			for(k=0;k<region_cnt;k++)
			{
				region_rule=cJSON_GetArrayItem(r_rules,k);
				ret=write_region_rule(region_rule, compile_id,  group_info->group_id, p_iris, logger);
				if(ret<0)
				{
					MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
												"compile rule %d write region error.",compile_id);
					return -1;
				}
			}
			ret=write_group_rule(compile_id, group_info->group_id, p_iris,  logger);
			if(ret<0)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
											"compile rule %d write group error.",compile_id);
				return -1;
			}

		}
	}
	ret=write_index_file(p_iris,logger);
	if(ret<0)
	{
		return -1;
	}
	return 0;
}
int json2iris(const char* json_file,const char*compile_tn,const char* group_tn,char* iris_dir_buf,int buf_len,void* logger)
{
	FILE* json_fp=NULL;
	cJSON *json=NULL;
	struct stat fstat_buf;
	int ret=-1;
	char* json_buff=NULL;
	unsigned long json_file_size=0,read_size=0;
	struct iris_description_t iris_cfg;
	memset(&iris_cfg,0,sizeof(iris_cfg));
	ret=stat(json_file, &fstat_buf);
	if(ret!=0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"fstat file %s error.",json_file);
		goto error_out;
	}

	json_fp=fopen(json_file,"r");
	if(json_fp==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"fopen file %s error %s.",json_file,strerror(errno));
		goto error_out;
	}
	

	json_file_size=fstat_buf.st_size;
	json_buff=(char*)calloc(1,json_file_size);
	read_size=fread(json_buff,1,json_file_size,json_fp);
	if(read_size!=json_file_size)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"fread file %s error.",json_file);
		goto error_out;
	}

	
	json=cJSON_Parse(json_buff);
	if (!json)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,"Error before: %-200.200s",cJSON_GetErrorPtr());
		goto error_out;
	}
	ret=set_iris_descriptor(json_file,json,compile_tn,group_tn,&iris_cfg,logger);
	if(ret<0)
	{
		goto error_out;
	}
	ret=create_tmp_dir(&iris_cfg);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"create tmp folder %s error",iris_cfg.tmp_iris_dir);
		goto error_out;
	}
	ret=write_iris(json,&iris_cfg,logger);
	if(ret<0)
	{
		goto error_out;
	}
	memcpy(iris_dir_buf,iris_cfg.tmp_iris_index_dir,MIN(strlen(iris_cfg.tmp_iris_index_dir)+1,(unsigned int)buf_len));

	cJSON_Delete(json);
	fclose(json_fp);
	free(json_buff);
	clear_iris_descriptor(&iris_cfg);
	return 0;	

	
error_out:
	cJSON_Delete(json);
	if(json_fp!=NULL)
	{
		fclose(json_fp);
	}
	free(json_buff);
	clear_iris_descriptor(&iris_cfg);
	return -1;
}

