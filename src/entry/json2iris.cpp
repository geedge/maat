
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
#include "hiredis.h"
#include "map_str2int.h"
#include "Maat_table.h"
#include "Maat_rule_internal.h"
#include "Maat_utils.h"

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
	enum MAAT_TABLE_TYPE table_type;
	void* buff;
	size_t write_pos;
	size_t buff_sz;
};
struct iris_description_t
{
	int group_cnt;
	int region_cnt;
	
	char tmp_iris_dir[MAX_PATH_LINE];
	char tmp_iris_index_dir[MAX_PATH_LINE];
	char index_path[MAX_PATH_LINE];

	struct iris_table_t* group_table;
	struct iris_table_t* compile_table;
	MESA_htable_handle group_name_map;
	MESA_htable_handle iris_table_map;
	MESA_htable_handle str2int_map;
	redisContext *redis_write_ctx;
	char* encrypt_key;
	char* encrypt_algo;
	FILE* idx_fp;
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
struct iris_table_t* query_table_info(iris_description_t* p_iris, const char* table_name, enum MAAT_TABLE_TYPE table_type)
{
	struct iris_table_t* table_info=NULL;
	table_info=(struct iris_table_t*)MESA_htable_search(p_iris->iris_table_map, (const unsigned char*)table_name,strlen(table_name));
	if(table_info==NULL)
	{
		table_info=ALLOC(struct iris_table_t, 1);
		table_info->line_count=0;
		table_info->table_type=table_type;
		memcpy(table_info->table_name, table_name, MIN(sizeof(table_info->table_name)-1, strlen(table_name)));
		snprintf(table_info->table_path,sizeof(table_info->table_path), "%s/%s.local", p_iris->tmp_iris_dir, table_info->table_name);
		MESA_htable_add(p_iris->iris_table_map, (const unsigned char*)table_info->table_name, strlen(table_info->table_name), table_info);
	}
	return table_info;
}
void free_iris_table_info(void* p)
{
	struct iris_table_t* table=(struct iris_table_t*)p;
	free(table->buff);
	table->buff=NULL;
	free(table);
}
static int get_group_seq(struct iris_description_t* iris_cfg)
{
	redisReply* data_reply=NULL;
	int sequence=0;
	if(iris_cfg->redis_write_ctx==NULL)
	{
		sequence=iris_cfg->group_cnt;
	}
	else
	{
		data_reply=_wrap_redisCommand(iris_cfg->redis_write_ctx,"INCRBY %s 1", mr_group_id_var);
		sequence=(int)data_reply->integer-1;
		freeReplyObject(data_reply);
	}
	iris_cfg->group_cnt++;
	return sequence;
}
static int get_region_seq(struct iris_description_t* iris_cfg)
{
	redisReply* data_reply=NULL;
	int sequence=0;
	if(iris_cfg->redis_write_ctx==NULL)
	{
		sequence=iris_cfg->region_cnt;
	}
	else
	{
		data_reply=_wrap_redisCommand(iris_cfg->redis_write_ctx,"INCRBY %s 1", mr_region_id_var);
		sequence=(int)data_reply->integer-1;
		freeReplyObject(data_reply);
	}
	iris_cfg->region_cnt++;
	return sequence;
}

int set_iris_descriptor(const char* json_file,cJSON *json, const char* encrypt_key, const char* encrypt_algo, const char*compile_tn,const char* group_tn, redisContext *redis_write_ctx, struct iris_description_t *iris_cfg, void * logger)
{
	memset(iris_cfg,0,sizeof(struct iris_description_t));
	snprintf(iris_cfg->tmp_iris_dir,sizeof(iris_cfg->tmp_iris_dir),"%s_iris_tmp",json_file);
	snprintf(iris_cfg->tmp_iris_index_dir,sizeof(iris_cfg->tmp_iris_index_dir),"%s_iris_tmp/index",json_file);
	snprintf(iris_cfg->index_path,sizeof(iris_cfg->index_path),"%s/full_config_index.%010d",iris_cfg->tmp_iris_index_dir,json_version);

	iris_cfg->redis_write_ctx=redis_write_ctx;
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

	hargs.data_free = free_iris_table_info;
	iris_cfg->iris_table_map=MESA_htable_create(&hargs, sizeof(hargs));
	MESA_htable_print_crtl(iris_cfg->iris_table_map, 0);

	iris_cfg->str2int_map=map_create();
	
	map_register(iris_cfg->str2int_map, "yes",1);
	map_register(iris_cfg->str2int_map, "no",0);
	
	map_register(iris_cfg->str2int_map, "ip",TABLE_TYPE_IP);
	map_register(iris_cfg->str2int_map, "ip_plus",TABLE_TYPE_IP_PLUS);
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
	map_register(iris_cfg->str2int_map, "suffix",1);
	map_register(iris_cfg->str2int_map, "left",2);
	map_register(iris_cfg->str2int_map, "prefix",2);
	map_register(iris_cfg->str2int_map, "complete",3);

	map_register(iris_cfg->str2int_map, "uncase plain",0);
	map_register(iris_cfg->str2int_map, "hexbin",1);
	map_register(iris_cfg->str2int_map, "case plain",2);

	iris_cfg->compile_table=query_table_info(iris_cfg, compile_tn, TABLE_TYPE_COMPILE);
	iris_cfg->group_table=query_table_info(iris_cfg, group_tn, TABLE_TYPE_GROUP);
	
	if(encrypt_key && encrypt_algo)
	{
		iris_cfg->encrypt_key=_maat_strdup(encrypt_key);
		iris_cfg->encrypt_algo=_maat_strdup(encrypt_algo);
	}

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
	map_destroy(iris_cfg->str2int_map);
	free(iris_cfg->encrypt_algo);
	free(iris_cfg->encrypt_key);
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
int direct_write_rule(cJSON* json, MESA_htable_handle str2int, struct traslate_command_t*cmd, int cmd_cnt, struct iris_table_t* table, void* logger)
{
	int i=0,ret=-1;
	cJSON* item=NULL;
	cJSON dummy;
	char *p=NULL;
	int int_value=0;
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
			ret=-1;
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
				ret=-1;
				goto error_out;
			}
			cmd[i].json_value=(char*)malloc(21);/* 2^64+1 can be represented in 21 chars. */
			snprintf(cmd[i].json_value,21, "%d", int_value);

		}
		else
		{
			switch(item->type)
			{
				case cJSON_Number:
					cmd[i].json_value=cJSON_Print(item);
					break;
				case cJSON_String:
					cmd[i].json_value=ALLOC(char, strlen(item->valuestring)+1);
					memcpy(cmd[i].json_value, item->valuestring, strlen(item->valuestring));
					break;
				default://impossible ,already checked
					assert(0);
					break;
			}
		}
	}
	for(i=0;i<cmd_cnt;i++)
	{
		table->write_pos+=memcat(&(table->buff), table->write_pos, &table->buff_sz, cmd[i].json_value, strlen(cmd[i].json_value));
		table->write_pos+=memcat(&(table->buff), table->write_pos, &table->buff_sz, "\t", 1);
	}
	table->write_pos+=memcat(&(table->buff), table->write_pos, &table->buff_sz, "\n", 1);
	table->line_count++;
	ret=0;
	
error_out:	
	for(i=0;i<cmd_cnt;i++)
	{
		if(cmd[i].json_value!=NULL)
		{
			free(cmd[i].json_value);
		}
	}
	return ret;

}
int write_ip_line(cJSON *region_json, struct iris_description_t *p_iris, struct iris_table_t* table, void * logger)
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
	
	return direct_write_rule(region_json, p_iris->str2int_map,json_cmd, cmd_cnt, table, logger);
}
int write_ip_plus_line(cJSON *region_json, struct iris_description_t *p_iris, struct iris_table_t* table, void * logger)
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

	json_cmd[cmd_cnt].json_string="saddr_format";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="mask";	
	cmd_cnt++;	

	json_cmd[cmd_cnt].json_string="src_ip1";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="0.0.0.0";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="src_ip2";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="255.255.255.255";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="sport_format";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="mask";	
	cmd_cnt++;	

	json_cmd[cmd_cnt].json_string="src_port1";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="0";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="src_port2";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="65535";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="daddr_format";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="mask";	
	cmd_cnt++;	

	json_cmd[cmd_cnt].json_string="dst_ip1";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="0.0.0.0";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="dst_ip2";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="255.255.255.255";
	cmd_cnt++;
	
	json_cmd[cmd_cnt].json_string="dport_format";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="mask";	
	cmd_cnt++;	

	json_cmd[cmd_cnt].json_string="dst_port1";
	json_cmd[cmd_cnt].json_type=cJSON_String;
	json_cmd[cmd_cnt].empty_allowed=1;
	json_cmd[cmd_cnt].default_string="0";
	cmd_cnt++;

	json_cmd[cmd_cnt].json_string="dst_port2";
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

	return direct_write_rule(region_json, p_iris->str2int_map,json_cmd, cmd_cnt, table, logger);

}

int write_expr_line(cJSON *region_json, struct iris_description_t *p_iris, struct iris_table_t* table, void * logger)
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
	
	if(table->table_type==TABLE_TYPE_EXPR_PLUS)
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
	
	return direct_write_rule(region_json, p_iris->str2int_map,json_cmd, cmd_cnt, table, logger);

}
int write_intval_line(cJSON *region_json, struct iris_description_t *p_iris, struct iris_table_t* table, void * logger)
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
	
	return direct_write_rule(region_json, p_iris->str2int_map, json_cmd, cmd_cnt, table, logger);

}
int write_digest_line(cJSON *region_json, struct iris_description_t *p_iris, struct iris_table_t* table, void * logger)
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
	
	return direct_write_rule(region_json, p_iris->str2int_map,json_cmd, cmd_cnt, table, logger);

}
int write_similar_line(cJSON *region_json, struct iris_description_t *p_iris, struct iris_table_t* table, void * logger)
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
	
	return direct_write_rule(region_json, p_iris->str2int_map,json_cmd, cmd_cnt, table, logger);

}

int write_plugin_line(cJSON* plug_table_json, int sequence, iris_description_t* p_iris, void* logger)
{
	cJSON* item=NULL,*table_content=NULL, *each_line=NULL;
	struct iris_table_t* table_info=NULL;
	const char* table_name=NULL, *line_content=NULL;
	int i=0, line_cnt=0;
	
	item=cJSON_GetObjectItem(plug_table_json, "table_name");
	if(item==NULL||item->type!=cJSON_String)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_json,
								"The %d plugin_table's table_name not defined or format error.", sequence);
		return -1;
	}
	table_name=item->valuestring;
	table_info=query_table_info(p_iris, table_name, TABLE_TYPE_PLUGIN);
	table_content=cJSON_GetObjectItem(plug_table_json, "table_content");
	if(table_content==NULL||table_content->type!=cJSON_Array)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"%d plugin_table's table_content not defined or format error."
								,sequence);
		return -1;
	}
	line_cnt=cJSON_GetArraySize(table_content);

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
		table_info->write_pos+=memcat(&(table_info->buff), table_info->write_pos, &(table_info->buff_sz), line_content, strlen(line_content));
		table_info->write_pos+=memcat(&(table_info->buff), table_info->write_pos, &(table_info->buff_sz), "\n", 1);
		table_info->line_count++;
	}
	return 0;
}
int write_region_rule(cJSON* region_json, int compile_id, int group_id, iris_description_t* p_iris, void* logger)
{
	cJSON* item=NULL,*table_content=NULL;
	int ret=0;
	int region_id=0;
	const char* table_name=NULL,*table_type_str=NULL;
	enum MAAT_TABLE_TYPE table_type=TABLE_TYPE_EXPR;
	struct iris_table_t* table_info=NULL;
	

	item=cJSON_GetObjectItem(region_json,"table_type");
	if(item==NULL||item->type!=cJSON_String)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"compile rule %d table name %s's table_type not defined or format error."
								,compile_id,table_name);
		return -1;
	}
	table_type_str=item->valuestring;
	ret=map_str2int(p_iris->str2int_map, table_type_str, (int*)&(table_type));
	if(ret!=1)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"compile rule %d table name %s's table_type %s invalid."
								,compile_id,table_name,table_type_str);
		return -1;
	}
	item=cJSON_GetObjectItem(region_json,"table_name");
	if(item==NULL||item->type!=cJSON_String)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"compile rule %d's region table_name not defined or format error.",compile_id);
		return -1;
	}
	table_name=item->valuestring;
	table_info=query_table_info(p_iris, table_name, table_type);

	table_content=cJSON_GetObjectItem(region_json,"table_content");
	if(table_content==NULL||table_content->type!=cJSON_Object)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
								"compile rule %d table name %s's table_content not defined or format error."
								,compile_id,table_name);
		return -1;
	}

	region_id=get_region_seq(p_iris);
	cJSON_AddNumberToObject(table_content, "region_id", region_id);
	cJSON_AddNumberToObject(table_content, "group_id", group_id);
	cJSON_AddNumberToObject(table_content, "is_valid", 1);

	switch(table_type)
	{
		case TABLE_TYPE_EXPR:
		case TABLE_TYPE_EXPR_PLUS:
			ret=write_expr_line(table_content, p_iris, table_info, logger);
			break;
		case TABLE_TYPE_IP:
			ret=write_ip_line(table_content, p_iris, table_info, logger);
			break;
		case TABLE_TYPE_IP_PLUS:
			write_ip_plus_line(table_content, p_iris, table_info, logger);
			break;
		case TABLE_TYPE_INTERVAL:
			ret=write_intval_line(table_content, p_iris, table_info, logger);
			break;
		case TABLE_TYPE_DIGEST:
			ret=write_digest_line(table_content, p_iris, table_info, logger);
			break;
		case TABLE_TYPE_SIMILARITY:
			ret=write_similar_line(table_content, p_iris, table_info, logger);
			break;
		default:
			assert(0);
			break;
	}
	return ret;
}

int write_compile_line(cJSON *compile, struct iris_description_t *p_iris, void * logger)
{
	int compile_id=-1,cmd_cnt=0,ret=-1;
	cJSON* item=NULL;
	struct iris_table_t* table_info=NULL;
	cJSON* g_rules=cJSON_GetObjectItem(compile, "groups");
	int	group_cnt=cJSON_GetArraySize(g_rules);
	cJSON_AddNumberToObject(compile, "group_num", group_cnt);

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


	compile_cmd[cmd_cnt].json_string="tags";
	compile_cmd[cmd_cnt].json_type=cJSON_String;
	compile_cmd[cmd_cnt].empty_allowed=1;
	compile_cmd[cmd_cnt].default_string="0";
	cmd_cnt++;
	
	compile_cmd[cmd_cnt].json_string="user_region";
	compile_cmd[cmd_cnt].json_type=cJSON_String;
	cmd_cnt++;
	
	compile_cmd[cmd_cnt].json_string="is_valid";
	compile_cmd[cmd_cnt].json_type=cJSON_String;
	compile_cmd[cmd_cnt].str2int_flag=1;
	cmd_cnt++;
	
	compile_cmd[cmd_cnt].json_string="group_num";
	compile_cmd[cmd_cnt].json_type=cJSON_Number;
	cmd_cnt++;

	compile_cmd[cmd_cnt].json_string="exec_seq";
	compile_cmd[cmd_cnt].json_type=cJSON_String;
	compile_cmd[cmd_cnt].empty_allowed=1;
	compile_cmd[cmd_cnt].default_string="0.0";
	cmd_cnt++;


	item=cJSON_GetObjectItem(compile,"table_name");
	if(item==NULL||item->type!=cJSON_String)
	{
		table_info=p_iris->compile_table;
	}
	else
	{
		table_info=query_table_info(p_iris, item->valuestring, TABLE_TYPE_COMPILE);
	}
	
	ret=direct_write_rule(compile, p_iris->str2int_map, compile_cmd, cmd_cnt, table_info, logger);
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
	return compile_id;
}
int write_group_line(int group_id, int parent_id, int group_not_flag, int parent_type, const char* virtual_table, struct iris_description_t *p_iris, void * logger)
{
	char buff[1024*4];
	struct iris_table_t* table=p_iris->group_table;
	snprintf(buff, sizeof(buff), "%d\t%d\t1\t%d\t%d\t%s\n", group_id, parent_id, group_not_flag, parent_type, virtual_table);
	table->write_pos+=memcat(&(table->buff), table->write_pos, &(table->buff_sz), buff, strlen(buff));
	table->line_count++;
	return 0;
}
void table_idx_write_cb(const uchar * key, uint size, void * data, void * user)
{
	struct iris_description_t *p_iris=(struct iris_description_t *)user;
	struct iris_table_t* table=(struct iris_table_t*)data;
	FILE* table_fp=NULL;
	char line_cnt_str[32], err_str[256];
	snprintf(line_cnt_str, sizeof(line_cnt_str), "%010d\n", table->line_count);

	int ret=0;
	size_t table_file_sz=strlen(line_cnt_str)+table->write_pos;
	unsigned char* buff=ALLOC(unsigned char, table_file_sz);
	unsigned char* encrypt_buff=NULL;
	size_t encrypt_buff_sz=0;
	memcpy(buff, line_cnt_str, strlen(line_cnt_str));
	memcpy(buff+strlen(line_cnt_str), table->buff, table->write_pos);
	table_fp=fopen(table->table_path, "w");
	if(p_iris->encrypt_key)
	{
		ret=crypt_memory(buff, table_file_sz, &encrypt_buff, &encrypt_buff_sz, p_iris->encrypt_key, p_iris->encrypt_algo, 1, err_str, sizeof(err_str));
		assert(ret==0);
		fwrite(encrypt_buff, encrypt_buff_sz, 1, table_fp);
		fprintf(p_iris->idx_fp,"%s\t%d\t%s\t%s\n", table->table_name, table->line_count, table->table_path, p_iris->encrypt_algo);
	}
	else
	{
		fwrite(buff, table_file_sz, 1, table_fp);		
		fprintf(p_iris->idx_fp,"%s\t%d\t%s\n", table->table_name, table->line_count, table->table_path);
	}
	fclose(table_fp);
	free(buff);
	buff=NULL;
	
	
}
int write_index_file(struct iris_description_t *p_iris,void* logger)
{
	p_iris->idx_fp=fopen(p_iris->index_path,"w");
	if(p_iris->idx_fp==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
									"index file %s fopen error %s.",p_iris->index_path, strerror(errno));
		return -1;
	}
	MESA_htable_iterate(p_iris->iris_table_map, table_idx_write_cb, p_iris);
	fclose(p_iris->idx_fp);
	p_iris->idx_fp=NULL;
	return 0;
}
int write_group_rule(cJSON *group_json, int parent_id, int parent_type, int tracking_compile_id, struct iris_description_t *p_iris, void* logger)
{
	const char* _str_parent_type[2]={"compile", "group"};
	int ret=0;
	int group_not_flag=0;
	cJSON *region_json=NULL, *item=NULL;
	cJSON *sub_groups=NULL, *region_rule=NULL;
	const char* group_name=NULL, *virtual_table=NULL;
	struct group_info_t *group_info=NULL;
	struct group_info_t untitled_group;

	item=cJSON_GetObjectItem(group_json, "group_name");
	if(item==NULL||item->type!=cJSON_String)
	{
		group_name=untitled_group_name;
	}
	else
	{
		group_name=item->valuestring;
	}

	item=cJSON_GetObjectItem(group_json, "virtual_table");
	if(item==NULL||item->type!=cJSON_String)
	{
		virtual_table="null";
	}
	else
	{
		virtual_table=item->valuestring;
	}
	item=cJSON_GetObjectItem(group_json,"not_flag");
	if(item==NULL||item->type!=cJSON_Number)
	{
		group_not_flag=0;
	}
	else
	{
		group_not_flag=item->valueint;
	}
	if(parent_type==PARENT_TYPE_GROUP)
	{
		group_not_flag=0;
	}

	group_info=(struct group_info_t*)MESA_htable_search(p_iris->group_name_map, (const unsigned char*)group_name, strlen(group_name));
	if(group_info==NULL)//exist group name, region already read
	{
		if(0==strncasecmp(group_name, untitled_group_name, strlen(untitled_group_name)))
		{
			group_info=&untitled_group;
			group_info->group_id=get_group_seq(p_iris);
		}
		else
		{
			group_info=ALLOC(struct group_info_t, 1);
			group_info->group_id=get_group_seq(p_iris);
			MESA_htable_add(p_iris->group_name_map, (const unsigned char*)group_name, strlen(group_name), group_info);
		}
	}	
	ret=write_group_line(group_info->group_id, parent_id, group_not_flag, parent_type, virtual_table, p_iris, logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
									"%s rule %d write group error.", _str_parent_type[parent_type], parent_id);
		return -1;
	}
	region_json=cJSON_GetObjectItem(group_json,"regions");
	if(region_json!=NULL)
	{
		cJSON_ArrayForEach(region_rule, region_json)
		{
			ret=write_region_rule(region_rule, tracking_compile_id,	group_info->group_id, p_iris, logger);
			if(ret<0)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,
											"compile rule %d write region error.", tracking_compile_id);
				return -1;
			}
		}
	}	
	sub_groups=cJSON_GetObjectItem(group_json,"sub_groups");
	if(sub_groups!=NULL)
	{
		//recursively
		
		cJSON_ArrayForEach(item, sub_groups)
		{
			ret=write_group_rule(item, group_info->group_id, PARENT_TYPE_GROUP, tracking_compile_id, p_iris, logger);
			if(ret<0)
			{
				return -1;
			}
		}
	}
	return 0;
}
int write_iris(cJSON *json, struct iris_description_t *p_iris, void* logger)
{
	int i=0;
	int compile_id=-1, compile_cnt=0, group_cnt=0;
	int ret=0;
	cJSON *c_rules=NULL, *g_rules=NULL, *plug_tables=NULL;
	cJSON *compile_rule=NULL,*group_rule=NULL, *each_plug_table=NULL;
	plug_tables=cJSON_GetObjectItem(json,"plugin_table");
	if(NULL!=plug_tables)
	{
		cJSON_ArrayForEach(each_plug_table, plug_tables)
		{
			write_plugin_line(each_plug_table, i, p_iris, logger);
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
	cJSON_ArrayForEach(compile_rule, c_rules)
	{
		compile_id=write_compile_line(compile_rule,p_iris, logger);
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
		cJSON_ArrayForEach(group_rule, g_rules)
		{
			ret=write_group_rule(group_rule, compile_id, PARENT_TYPE_COMPILE, compile_id, p_iris, logger);
			if(ret<0)
			{
				return -1;
			}
		}
	}
	ret=write_index_file(p_iris, logger);
	if(ret<0)
	{
		return -1;
	}
	return 0;
}
// redis_write_ctx is used by maat_redis_tool to write json to redis.
int json2iris(const char* json_buff, const char* json_filename, const char*compile_tn, const char* group_tn, redisContext *redis_write_ctx, char* iris_dir_buf, int buf_len, char* encrypt_key, char* encrypt_algo, void* logger)
{
	cJSON *json=NULL, *tmp_obj=NULL;
	int ret=-1;
	struct iris_description_t iris_cfg;
	memset(&iris_cfg, 0, sizeof(iris_cfg));
	json=cJSON_Parse(json_buff);
	if (!json)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,maat_json,"Error before: %-200.200s",cJSON_GetErrorPtr());
		goto error_out;
	}
	tmp_obj=cJSON_GetObjectItem(json, "compile_table");
	if(tmp_obj)
	{
		compile_tn=tmp_obj->valuestring;
	}

	tmp_obj=cJSON_GetObjectItem(json, "group_table");
	if(tmp_obj)
	{
		group_tn=tmp_obj->valuestring;
	}
	ret=set_iris_descriptor(json_filename, json, encrypt_key, encrypt_algo, compile_tn, group_tn, redis_write_ctx, &iris_cfg, logger);
	if(ret<0)
	{
		goto error_out;
	}
	ret=create_tmp_dir(&iris_cfg);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_json,
								"create tmp folder %s error", iris_cfg.tmp_iris_dir);
		goto error_out;
	}
	ret=write_iris(json, &iris_cfg, logger);
	if(ret<0)
	{
		goto error_out;
	}
	memcpy(iris_dir_buf, iris_cfg.tmp_iris_index_dir, MIN(strlen(iris_cfg.tmp_iris_index_dir)+1, (unsigned int)buf_len));

	cJSON_Delete(json);
	clear_iris_descriptor(&iris_cfg);
	return 0;	

	
error_out:
	cJSON_Delete(json);
	clear_iris_descriptor(&iris_cfg);
	return -1;
}

