#include "Maat_table_schema.h"
#include "map_str2int.h"
#include "Maat_utils.h"
#include "cJSON.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <MESA/MESA_handle_logger.h>

#define	MAX_TABLE_NUM			256

struct Maat_table_manager
{
	struct Maat_table_schema* p_table_info[MAX_TABLE_NUM];
	size_t table_cnt;
	struct maat_kv_store* map_tablename2id;
	int active_plugin_table_num;
	int is_last_plugin_table_updating;
	void* logger;
};
enum MAAT_SCAN_TYPE Maat_table_get_scan_type(enum MAAT_TABLE_TYPE table_type)
{
	enum MAAT_SCAN_TYPE ret=SCAN_TYPE_INVALID;
	switch(table_type)
	{
		case TABLE_TYPE_EXPR:
		case TABLE_TYPE_EXPR_PLUS:
		case TABLE_TYPE_SIMILARITY:
		case TABLE_TYPE_DIGEST:
			ret=SCAN_TYPE_STRING;
			break;
		case TABLE_TYPE_INTERVAL:
		case TABLE_TYPE_INTERVAL_PLUS:
			ret=SCAN_TYPE_INTERVAL;
			break;
		case TABLE_TYPE_IP:
		case TABLE_TYPE_IP_PLUS:
		case TABLE_TYPE_COMPOSITION:
			ret=SCAN_TYPE_IP;
			break;
		case TABLE_TYPE_PLUGIN:
			ret=SCAN_TYPE_PLUGIN;
			break;
		case TABLE_TYPE_IP_PLUGIN:
			ret=SCAN_TYPE_IP;
			break;
		case TABLE_TYPE_FQDN_PLUGIN:
			ret=SCAN_TYPE_FQDN_PLUGIN;
			break;
		case TABLE_TYPE_BOOL_PLUGIN:
			ret=SCAN_TYPE_BOOL_PLUGIN;
			break;
		case TABLE_TYPE_COMPILE:			
			ret=SCAN_TYPE_NONE;
			break;
		default:
			break;
	}
	return ret;
}

int read_expr_table_info(const char* line, struct Maat_table_schema* table, struct maat_kv_store* string2int_map)
{
	int j=0, ret[4]={0};
	char table_type[16], src_charset[256], dst_charset[256], merge[4], quick_str_scan[32]={0};
	char *token=NULL, *sub_token=NULL, *saveptr;
	struct expr_table_schema* p=&(table->expr);
	sscanf(line, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%s",&(table->table_id),
											table->table_name[0],
											table_type,
											src_charset,
											dst_charset,
											merge,
											&(p->cross_cache_size),
											quick_str_scan);
	memset(ret, 0, sizeof(ret));

	ret[0]=maat_kv_read(string2int_map, table_type, (int*)&(table->table_type));
	ret[1]=maat_kv_read(string2int_map, src_charset, (int*)&(p->src_charset));
	ret[2]=maat_kv_read(string2int_map, merge, &(p->do_charset_merge));
	if(strlen(quick_str_scan)>0)
	{
		ret[3]=maat_kv_read(string2int_map, quick_str_scan, &(p->quick_expr_switch));
	}
	memset(quick_str_scan, 0, sizeof(quick_str_scan));

	for(j=0; j<4; j++)
	{
		if(ret[j]<0)
		{
			return -1;
		}
	}
	j=0;
	for (token = dst_charset; ; token= NULL)
	{
		sub_token= strtok_r(token, "/", &saveptr);
		if (sub_token == NULL)
			break;
		ret[3]=maat_kv_read(string2int_map, sub_token, (int*)&(p->dst_charset[j]));
		if(ret[3]>0)
		{
			if(p->dst_charset[j]==p->src_charset)
			{
				p->src_charset_in_dst=TRUE;
			}
			j++;
		}
		else
		{
			return -1;
		}
		
	}
	return 0;
}

Maat_table_schema* table_info_new(void)
{
	struct Maat_table_schema*p=ALLOC(struct Maat_table_schema, 1);
	p->conj_cnt=1;
	return p;
}
void table_info_free(struct Maat_table_schema*p)
{
	free(p);
	return;
}
int _read_integer_arrary(char* string, int *array, int size)
{
	char *token=NULL,*sub_token=NULL,*saveptr;
	int i=0;
	for (token = string, i=0; i<size ; token= NULL, i++)
	{
		sub_token= strtok_r(token,",", &saveptr);
		if (sub_token == NULL)
			break;
		sscanf(sub_token, "%d", array+i);
	}
	return i;
}
#define COLUMN_PLUGIN_SCHEMA_JSON	4
#define COLUMN_IP_PLUGIN_SCHEMA_JSON	4
#define COLUMN_FQDN_PLUGIN_SCHEMA_JSON	4
#define	COLUMN_BOOL_PLUGIN_SCHEMA_JSON	4
#define COLUMN_COMPOSITION_SCHEMA_JSON	4
#define	COLUMN_VIRUTAL_SCHEMA_JSON	4
int read_virtual_table_schema(struct Maat_table_manager* table_mgr, const char* line, struct Maat_table_schema* table, MESA_htable_handle reserved_word_map)
{
	int ret=0, tmp_table_id=0;
	enum MAAT_TABLE_TYPE physical_table_type=TABLE_TYPE_INVALID;
	enum MAAT_SCAN_TYPE physical_table_scan_type=SCAN_TYPE_INVALID;
	cJSON* json=NULL, *tmp=NULL;
	char *json_str;

	
	size_t offset=0, len=0;
	char* copy_line=NULL;
	copy_line=_maat_strdup(line);
	ret=get_column_pos(copy_line, COLUMN_VIRUTAL_SCHEMA_JSON, &offset, &len);
	if(ret<0)
	{
		goto error_out;
	}
	if(offset+len<strlen(copy_line))
	{
		copy_line[offset+len]='\0';
	}
	json_str=copy_line+offset;
	if(strchr(json_str,'{')||strchr(json_str,'['))//This is a json, mostly.
	{
		json=cJSON_Parse(json_str);
		if(!json)
		{
			goto error_out;
		}
		if(json->type!=cJSON_Array)
		{
			goto error_out;
		}
		cJSON_ArrayForEach(tmp, json)
		{
			if(tmp->type!=cJSON_String)
			{
				goto error_out;
			}
			ret=maat_kv_read(table_mgr->map_tablename2id, tmp->valuestring, &tmp_table_id);
			if(ret<0)
			{
				goto error_out;		
			}
			physical_table_type=table_mgr->p_table_info[tmp_table_id]->table_type;
			physical_table_scan_type=Maat_table_get_scan_type(physical_table_type);
			if(physical_table_scan_type<SCAN_TYPE_IP)
			{
				goto error_out;
			}
			table->virtual_table.physical_table_id[physical_table_scan_type]=tmp_table_id;
		}		
	}
	else	//For compatible non-json physical description
	{
		ret=maat_kv_read(table_mgr->map_tablename2id, json_str, &tmp_table_id);
		if(ret<0)
		{
			goto error_out;
		}
		physical_table_type=table_mgr->p_table_info[tmp_table_id]->table_type;
		physical_table_scan_type=Maat_table_get_scan_type(physical_table_type);
		table->virtual_table.physical_table_id[physical_table_scan_type]=tmp_table_id;
	}
	cJSON_Delete(json);
	free(copy_line);
	return 0;

error_out:
	if(json) cJSON_Delete(json);	
	free(copy_line);
	return -1;

}

int read_plugin_table_schema(const char* line, struct Maat_table_schema* p)
{
	int i=0,ret=0;
	size_t offset=0, len=0;
	cJSON* json=NULL, *tmp=NULL, *array_item=NULL;
	char* copy_line=NULL, *plug_info=NULL;
	struct plugin_table_schema* plugin_desc=&(p->plugin);
	copy_line=_maat_strdup(line);
	ret=get_column_pos(copy_line, COLUMN_PLUGIN_SCHEMA_JSON, &offset, &len);
	if(ret<0)
	{
		goto error_out;
	}
	if(offset+len<strlen(copy_line))
	{
		copy_line[offset+len]='\0';
	}
	plug_info=copy_line+offset;

	if(NULL==strchr(plug_info,'{'))//For old version compatible.
	{
		ret=sscanf(plug_info, "%d", &(plugin_desc->valid_flag_column));
		if(ret==0||ret==EOF)
		{
			plugin_desc->valid_flag_column=-1;
		}
		free(copy_line);
		return 0;
	}
	json=cJSON_Parse(plug_info);
	if(!json)
	{
		goto error_out;
	}
	tmp=cJSON_GetObjectItem(json, "key");
	if(tmp!=NULL)
	{
		assert(tmp->type==cJSON_Number);
		plugin_desc->key_column=tmp->valueint;
	}
	tmp=cJSON_GetObjectItem(json, "valid");
	if(tmp!=NULL)
	{
		assert(tmp->type==cJSON_Number);
		plugin_desc->valid_flag_column=tmp->valueint;
	}
	tmp=cJSON_GetObjectItem(json, "tag");
	if(tmp!=NULL)
	{
		assert(tmp->type==cJSON_Number);
		plugin_desc->rule_tag_column=tmp->valueint;
	}
	tmp=cJSON_GetObjectItem(json, "foreign");
	if(tmp!=NULL)
	{
		if(tmp->type==cJSON_String)
		{
			plugin_desc->n_foreign=_read_integer_arrary(tmp->valuestring, plugin_desc->foreign_columns, MAX_FOREIGN_CLMN_NUM);
		}
		else if(tmp->type==cJSON_Array)
		{
			plugin_desc->n_foreign= cJSON_GetArraySize(tmp);
			for(i=0;i<plugin_desc->n_foreign; i++)
			{
				array_item=cJSON_GetArrayItem(tmp, i);
				assert(array_item->type==cJSON_Number);
				plugin_desc->foreign_columns[i]=array_item->valueint;
			}
		}
	}
	cJSON_Delete(json);

	free(copy_line);
	return 0;
error_out:
	free(copy_line);
	return -1;
}
int read_ip_plugin_table_schema(const char* line, struct Maat_table_schema* p)
{
	int ret=0, read_cnt=0;
	size_t offset=0, len=0;
	cJSON* json=NULL, *tmp=NULL;
	char* copy_line=NULL, *ip_plugin_info=NULL;
	struct ip_plugin_table_schema* ip_plugin_schema=&(p->ip_plugin);
	copy_line=_maat_strdup(line);
	ret=get_column_pos(copy_line, COLUMN_IP_PLUGIN_SCHEMA_JSON, &offset, &len);
	if(ret<0)
	{
		goto error_out;
	}
	if(offset+len<strlen(copy_line))
	{
		copy_line[offset+len]='\0';
	}
	ip_plugin_info=copy_line+offset;

	json=cJSON_Parse(ip_plugin_info);
	if(!json)
	{
		goto error_out;
	}
	tmp=cJSON_GetObjectItem(json, "row_id");
	if(tmp!=NULL && tmp->type==cJSON_Number)
	{
		ip_plugin_schema->row_id_column=tmp->valueint;
		read_cnt++;
	}

	tmp=cJSON_GetObjectItem(json, "ip_type");
	if(tmp!=NULL && tmp->type==cJSON_Number)
	{
		ip_plugin_schema->ip_type_column=tmp->valueint;
		read_cnt++;
	}
	tmp=cJSON_GetObjectItem(json, "start_ip");
	if(tmp!=NULL && tmp->type==cJSON_Number)
	{
		ip_plugin_schema->start_ip_column=tmp->valueint;
		read_cnt++;
	}
	tmp=cJSON_GetObjectItem(json, "end_ip");
	if(tmp!=NULL && tmp->type==cJSON_Number)
	{
		ip_plugin_schema->end_ip_column=tmp->valueint;
		read_cnt++;
	}

	tmp=cJSON_GetObjectItem(json, "valid");
	if(tmp!=NULL)
	{
		assert(tmp->type==cJSON_Number);
		ip_plugin_schema->valid_flag_column=tmp->valueint;
		read_cnt++;
	}
	ip_plugin_schema->rule_tag_column=-1;
	tmp=cJSON_GetObjectItem(json, "tag");
	if(tmp!=NULL)
	{
		assert(tmp->type==cJSON_Number);
		ip_plugin_schema->rule_tag_column=tmp->valueint;
		//read_cnt++; Tag is optional, so NOT ++ intentionally.
	}

	cJSON_Delete(json);

	free(copy_line);
	if(read_cnt<5)
	{
		return -1;
	}
	else
	{
		return 0;
	}
error_out:
	free(copy_line);
	return -1;

}
int read_fqdn_plugin_table_schema(const char* line, struct Maat_table_schema* p)
{
	int ret=0, read_cnt=0;
	size_t offset=0, len=0;
	cJSON* json=NULL, *tmp=NULL;
	char* copy_line=NULL, *fqnd_plugin_schema_json=NULL;
	struct fqdn_plugin_table_schema* fqdn_plugin_schema=&(p->fqdn_plugin);

	copy_line=_maat_strdup(line);
	ret=get_column_pos(copy_line, COLUMN_FQDN_PLUGIN_SCHEMA_JSON, &offset, &len);
	if(ret<0)
	{
		goto error_out;
	}
	if(offset+len<strlen(copy_line))
	{
		copy_line[offset+len]='\0';
	}
	fqnd_plugin_schema_json=copy_line+offset;

	json=cJSON_Parse(fqnd_plugin_schema_json);
	if(!json)
	{
		goto error_out;
	}
	tmp=cJSON_GetObjectItem(json, "row_id");
	if(tmp!=NULL && tmp->type==cJSON_Number)
	{
		fqdn_plugin_schema->row_id_column=tmp->valueint;
		read_cnt++;
	}

	tmp=cJSON_GetObjectItem(json, "is_suffix_match");
	if(tmp!=NULL && tmp->type==cJSON_Number)
	{
		fqdn_plugin_schema->is_suffix_flag_column=tmp->valueint;
		read_cnt++;
	}
	tmp=cJSON_GetObjectItem(json, "fqdn");
	if(tmp!=NULL && tmp->type==cJSON_Number)
	{
		fqdn_plugin_schema->fqdn_column=tmp->valueint;
		read_cnt++;
	}

	tmp=cJSON_GetObjectItem(json, "valid");
	if(tmp!=NULL)
	{
		assert(tmp->type==cJSON_Number);
		fqdn_plugin_schema->valid_flag_column=tmp->valueint;
		read_cnt++;
	}
	fqdn_plugin_schema->rule_tag_column=-1;
	tmp=cJSON_GetObjectItem(json, "tag");
	if(tmp!=NULL)
	{
		assert(tmp->type==cJSON_Number);
		fqdn_plugin_schema->rule_tag_column=tmp->valueint;
		//read_cnt++; Tag is optional, so NOT ++ intentionally.
	}

	cJSON_Delete(json);

	free(copy_line);
	if(read_cnt<4)
	{
		return -1;
	}
	else
	{
		return 0;
	}
error_out:
	free(copy_line);
	return -1;

}
int read_bool_plugin_table_schema(const char* line, struct Maat_table_schema* p)
{
	int ret=0, read_cnt=0;
	size_t offset=0, len=0;
	cJSON* json=NULL, *tmp=NULL;
	char* copy_line=NULL, *schema_json=NULL;
	struct bool_plugin_table_schema* bool_plugin_schema=&(p->bool_plugin);

	copy_line=_maat_strdup(line);
	ret=get_column_pos(copy_line, COLUMN_BOOL_PLUGIN_SCHEMA_JSON, &offset, &len);
	if(ret<0)
	{
		goto error_out;
	}
	if(offset+len<strlen(copy_line))
	{
		copy_line[offset+len]='\0';
	}
	schema_json=copy_line+offset;

	json=cJSON_Parse(schema_json);
	if(!json)
	{
		goto error_out;
	}
	tmp=cJSON_GetObjectItem(json, "row_id");
	if(tmp!=NULL && tmp->type==cJSON_Number)
	{
		bool_plugin_schema->row_id_column=tmp->valueint;
		read_cnt++;
	}
	tmp=cJSON_GetObjectItem(json, "bool_expr");
	if(tmp!=NULL && tmp->type==cJSON_Number)
	{
		bool_plugin_schema->bool_expr_column=tmp->valueint;
		read_cnt++;
	}

	tmp=cJSON_GetObjectItem(json, "valid");
	if(tmp!=NULL)
	{
		assert(tmp->type==cJSON_Number);
		bool_plugin_schema->valid_flag_column=tmp->valueint;
		read_cnt++;
	}
	bool_plugin_schema->rule_tag_column=-1;
	tmp=cJSON_GetObjectItem(json, "tag");
	if(tmp!=NULL)
	{
		assert(tmp->type==cJSON_Number);
		bool_plugin_schema->rule_tag_column=tmp->valueint;
		//read_cnt++; Tag is optional, so NOT ++ intentionally.
	}

	cJSON_Delete(json);

	free(copy_line);
	if(read_cnt<4)
	{
		return -1;
	}
	else
	{
		return 0;
	}
error_out:
	free(copy_line);
	return -1;

}

int read_composition_table_schema(struct Maat_table_manager* table_mgr, const char* line, struct Maat_table_schema* p, MESA_htable_handle string2int_map)
{
	int ret=0;
	size_t offset=0, len=0;
	cJSON* json=NULL, *tmp=NULL;
	char* copy_line=NULL, *composition_info=NULL;
	struct composition_table_schema* composition_schema=&(p->composition);
	copy_line=_maat_strdup(line);
	ret=get_column_pos(copy_line, COLUMN_COMPOSITION_SCHEMA_JSON, &offset, &len);
	if(ret<0)
	{
		goto error_out;
	}
	if(offset+len<strlen(copy_line))
	{
		copy_line[offset+len]='\0';
	}
	composition_info=copy_line+offset;

	json=cJSON_Parse(composition_info);
	if(!json)
	{
		goto error_out;
	}

	tmp=cJSON_GetObjectItem(json, "source");
	if(tmp!=NULL && tmp->type==cJSON_String)
	{
		ret=maat_kv_read(table_mgr->map_tablename2id, tmp->valuestring, &(composition_schema->component_table_id[COMPONENT_TABLE_TYPE_SOURCE_IP]));
		if(ret<0)
		{
			MESA_handle_runtime_log(table_mgr->logger, RLOG_LV_FATAL, maat_module,
							"Child table %s of table %s (id=%d) are not defined.",
							tmp->valuestring,
							p->table_name[0],
							p->table_id);
			goto error_out;
		}
	}
	tmp=cJSON_GetObjectItem(json, "destination");
	if(tmp!=NULL && tmp->type==cJSON_String)
	{
		ret=maat_kv_read(table_mgr->map_tablename2id, tmp->valuestring, &(composition_schema->component_table_id[COMPONENT_TABLE_TYPE_DESTINATION_IP]));
		if(ret<0)
		{
			MESA_handle_runtime_log(table_mgr->logger, RLOG_LV_FATAL, maat_module,
							"Child table %s of table %s (id=%d) are not defined.",
							tmp->valuestring,
							p->table_name[0],
							p->table_id);
			goto error_out;
		}

	}
	tmp=cJSON_GetObjectItem(json, "session");
	if(tmp!=NULL && tmp->type==cJSON_String)
	{
		ret=maat_kv_read(table_mgr->map_tablename2id, tmp->valuestring, &(composition_schema->component_table_id[COMPONENT_TABLE_TYPE_SESSION]));
		if(ret<0)
		{
			MESA_handle_runtime_log(table_mgr->logger, RLOG_LV_FATAL, maat_module,
							"Child table %s of table %s (id=%d) are not defined.",
							tmp->valuestring,
							p->table_name[0],
							p->table_id);
			goto error_out;
		}
	}
	cJSON_Delete(json);
	free(copy_line);
	return 0;
	
error_out:
	free(copy_line);
	return -1;

}
void Maat_table_manager_destroy(struct Maat_table_manager* table_mgr)
{
	size_t i=0;
	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		if(table_mgr->p_table_info[i]==NULL)
		{
			continue;
		}
		table_info_free(table_mgr->p_table_info[i]);
		table_mgr->p_table_info[i]=NULL;
	}
	maat_kv_store_free(table_mgr->map_tablename2id);
	free(table_mgr);
	return;
}

struct Maat_table_manager* Maat_table_manager_create(const char* table_info_path, void* logger)
{
	struct Maat_table_manager* table_mgr=NULL;
	FILE*fp=NULL;
	char line[MAX_TABLE_LINE_SIZE];
	int i=0, ret=0;
	char table_type_str[16]={0},not_care[1024]={0}, tmp_str[32]={0};
	struct maat_kv_store* reserved_word_map=NULL;;
	struct Maat_table_schema*p=NULL;
	struct Maat_table_schema*conj_table=NULL;
	fp=fopen(table_info_path,"r");
	if(fp==NULL)
	{
		fprintf(stderr,"Maat read table info %s error.\n",table_info_path);
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
								"Maat read table info %s failed: %s.\n", table_info_path, strerror(errno));
		return NULL;
	}
	table_mgr=ALLOC(struct Maat_table_manager, 1);
	struct Maat_table_schema** p_table_info=table_mgr->p_table_info;
	size_t n_table=MAX_TABLE_NUM;
	table_mgr->logger=logger;
	table_mgr->map_tablename2id=maat_kv_store_new();

	reserved_word_map=maat_kv_store_new();
	maat_kv_register(reserved_word_map, "expr", TABLE_TYPE_EXPR);
	maat_kv_register(reserved_word_map, "ip", TABLE_TYPE_IP);	
	maat_kv_register(reserved_word_map, "ip_plus", TABLE_TYPE_IP_PLUS);
	maat_kv_register(reserved_word_map, "compile", TABLE_TYPE_COMPILE);
	maat_kv_register(reserved_word_map, "plugin", TABLE_TYPE_PLUGIN);
	maat_kv_register(reserved_word_map, "ip_plugin", TABLE_TYPE_IP_PLUGIN);
	maat_kv_register(reserved_word_map, "fqdn_plugin", TABLE_TYPE_FQDN_PLUGIN);
	maat_kv_register(reserved_word_map, "bool_plugin", TABLE_TYPE_BOOL_PLUGIN);
	maat_kv_register(reserved_word_map, "intval", TABLE_TYPE_INTERVAL);
	maat_kv_register(reserved_word_map, "interval", TABLE_TYPE_INTERVAL);
	maat_kv_register(reserved_word_map, "intval_plus", TABLE_TYPE_INTERVAL_PLUS);
	maat_kv_register(reserved_word_map, "interval_plus", TABLE_TYPE_INTERVAL_PLUS);
	maat_kv_register(reserved_word_map, "digest", TABLE_TYPE_DIGEST);
	maat_kv_register(reserved_word_map, "expr_plus", TABLE_TYPE_EXPR_PLUS);
	maat_kv_register(reserved_word_map, "group", TABLE_TYPE_GROUP);
	maat_kv_register(reserved_word_map, "group2group", TABLE_TYPE_GROUP2GROUP);
	maat_kv_register(reserved_word_map, "group2compile", TABLE_TYPE_GROUP2COMPILE);
	maat_kv_register(reserved_word_map, "similar", TABLE_TYPE_SIMILARITY);
	maat_kv_register(reserved_word_map, "virtual", TABLE_TYPE_VIRTUAL);
	maat_kv_register(reserved_word_map, "composition", TABLE_TYPE_COMPOSITION);
	maat_kv_register(reserved_word_map, "quickoff", 0);
	maat_kv_register(reserved_word_map, "quickon", 1);
	maat_kv_register(reserved_word_map, "escape", USER_REGION_ENCODE_ESCAPE);
//	maat_kv_register(reserved_word_map,"base64",USER_REGION_ENCODE_BASE64); //NOT supported yet

	const char** charset_name_list=charset_get_all_name();
	for(i=0;i<MAX_CHARSET_NUM;i++)
	{
		if(strlen(charset_name_list[i])>0)
		{
			maat_kv_register(reserved_word_map, charset_name_list[i], i);
		}
		else
		{
			break;
		}
	}

	maat_kv_register(reserved_word_map,"yes", 1);
	maat_kv_register(reserved_word_map,"no", 0);
	

	i=0;
	while(NULL!=fgets(line,sizeof(line),fp))
	{
		i++;

		if(line[0]=='#'||line[0]==' '||line[0]=='\t'||strlen(line)<4)
		{
			continue;
		}
		p=table_info_new();

		ret=sscanf(line, "%d\t%s\t%s\t%[a-z0-9\t ]", &(p->table_id),
											p->table_name[0],
											table_type_str,
											not_care);
		if(ret<3)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"Maat read table info %s line %d error: not enough column.",table_info_path,i);
			continue;
		}
		ret=maat_kv_read(reserved_word_map, table_type_str, (int*)&(p->table_type));
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
						"Maat read table info %s line %d error:invalid table type.",table_info_path,i);
			goto invalid_table;
		}
		switch(p->table_type)
		{
			case TABLE_TYPE_EXPR:
			case TABLE_TYPE_EXPR_PLUS:
				ret=read_expr_table_info(line, p, reserved_word_map);
				if(ret<0)
				{
					fprintf(stderr, "Maat read table info %s line %d error: illegal column.\n", table_info_path, i);
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
									"Maat read table info %s line %d error:illegal column.", table_info_path, i);
					goto invalid_table;
				}
				break;
			case TABLE_TYPE_PLUGIN:
				ret=read_plugin_table_schema(line, p);
				if(ret<0)
				{
					fprintf(stderr, "Maat read table info %s line %d error: illegal plugin table schema.\n", table_info_path, i);
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
									"Maat read table info %s line %d error: illegal plugin table schema.", table_info_path, i);
					goto invalid_table;
				}
				break;
			case TABLE_TYPE_IP_PLUGIN:
				ret=read_ip_plugin_table_schema(line, p);
				if(ret<0)
				{
					fprintf(stderr, "Maat read table info %s line %d error: illegal ip_plugin table schema.\n", table_info_path, i);
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"Maat read table info %s line %d error: illegal ip_plugin table schema.", table_info_path, i);
					goto invalid_table;
				}
				break;
			case TABLE_TYPE_FQDN_PLUGIN:
				ret=read_fqdn_plugin_table_schema(line, p);
				if(ret<0)
				{
					fprintf(stderr, "Maat read table info %s line %d error: illegal fqdn_plugin table schema.\n", table_info_path, i);
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"Maat read table info %s line %d error: illegal fqdn_plugin table schema.", table_info_path, i);
					goto invalid_table;
				}
				break;
			case TABLE_TYPE_BOOL_PLUGIN:
				ret=read_bool_plugin_table_schema(line, p);
				if(ret<0)
				{
					fprintf(stderr, "Maat read table info %s line %d error: illegal bool_plugin table schema.\n", table_info_path, i);
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"Maat read table info %s line %d error: illegal bool_plugin table schema.", table_info_path, i);
					goto invalid_table;
				}
				break;
			case TABLE_TYPE_COMPOSITION:
				ret=read_composition_table_schema(table_mgr, line, p, reserved_word_map);
				if(ret<0)
				{
					fprintf(stderr, "Maat read table info %s line %d error: illegal composition table schema.\n", table_info_path, i);
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"Maat read table info %s line %d error: illegal composition table schema.", table_info_path, i);
					goto invalid_table;
				}
				break;
			case TABLE_TYPE_VIRTUAL:
				ret=read_virtual_table_schema(table_mgr, line, p, reserved_word_map);
				if(ret<0)
				{
					fprintf(stderr, "Maat read table info %s line %d error: illegal virtual table schema.\n", table_info_path, i);
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"Maat read table info %s line %d error: illegal virtual table schema.", table_info_path, i);
					goto invalid_table;
				}
				break;
			case TABLE_TYPE_COMPILE:	
				ret=sscanf(not_care,"%[a-z0-9]", tmp_str);
				if(ret>0)
				{	
					ret=maat_kv_read(reserved_word_map, tmp_str, (int*)&(p->compile.user_region_encoding));
				}
				if(ret!=1)
				{
					p->compile.user_region_encoding=USER_REGION_ENCODE_NONE;
				}
				break;
			default:
				break;
		}

		if((unsigned int)p->table_id>=n_table)
		{
			fprintf(stderr,"Maat read table info %s:%d error: table id %uh > %zu.\n",table_info_path,i,p->table_id,n_table);
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
				"Maat read table info %s line %d error: table id %uh > %d.\n",table_info_path,i,p->table_id,n_table);

			goto invalid_table;
		}
		ret=maat_kv_register(table_mgr->map_tablename2id, p->table_name[0], p->table_id);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
							"Duplicate table %s of table id %d",
							p->table_name[0],
							p->table_id);
			goto invalid_table;
		}
		if(p_table_info[p->table_id]!=NULL)//duplicate table_id,means conjunction table;
		{
			conj_table=p_table_info[p->table_id];
			if(conj_table->conj_cnt==MAX_CONJUNCTION_TABLE_NUM)
			{
				MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"Maat read table info %s line %d error: reach tableid %d conjunction upper limit."
								,table_info_path,i,p->table_id);
				goto invalid_table;
			}
			memcpy(conj_table->table_name[conj_table->conj_cnt],p->table_name[0],MAX_TABLE_NAME_LEN);
			conj_table->conj_cnt++;
			MESA_handle_runtime_log(logger, RLOG_LV_INFO, maat_module,
								"Maat read table info %s:%d:conjunction %s with %s (id=%d,total=%d)."
								,table_info_path,i,p->table_name[0]
								,conj_table->table_name[0],conj_table->table_id,conj_table->conj_cnt);
			//use goto to free the conjunctioned table_info
			goto invalid_table;
		}
		p_table_info[p->table_id]=p;
		table_mgr->table_cnt++;
		continue;
		
invalid_table:
		table_info_free(p);
		p=NULL;
	}
	fclose(fp);
	maat_kv_store_free(reserved_word_map);
	return table_mgr;
}
size_t Maat_table_manager_get_size(struct Maat_table_manager* table_mgr)
{
	return MAX_TABLE_NUM;
}
size_t Maat_table_manager_get_count(struct Maat_table_manager* table_mgr)
{
	return table_mgr->table_cnt;
}
int Maat_table_manager_get_compile_table_name(struct Maat_table_manager* table_mgr, char* buff, size_t sz)
{
	int i=0;
	for(i=0; i< MAX_TABLE_NUM; i++)
	{
		if(table_mgr->p_table_info[i] && table_mgr->p_table_info[i]->table_type==TABLE_TYPE_COMPILE)
		{
			strncpy(buff, table_mgr->p_table_info[i]->table_name[0], sz);
			return 1;
		}
	}
	return 0;
}
int Maat_table_manager_get_group2compile_table_name(struct Maat_table_manager* table_mgr, char* buff, size_t sz)
{
	int i=0;
	for(i=0; i< MAX_TABLE_NUM; i++)
	{
		if(table_mgr->p_table_info[i] && table_mgr->p_table_info[i]->table_type==TABLE_TYPE_GROUP2COMPILE)
		{
			strncpy(buff, table_mgr->p_table_info[i]->table_name[0], sz);
			return 1;
		}
	}
	return 0;
}
int Maat_table_manager_get_group2group_table_name(struct Maat_table_manager* table_mgr, char* buff, size_t sz)
{
	int i=0;
	for(i=0; i< MAX_TABLE_NUM; i++)
	{
		if(table_mgr->p_table_info[i] && table_mgr->p_table_info[i]->table_type==TABLE_TYPE_GROUP2GROUP)
		{
			strncpy(buff, table_mgr->p_table_info[i]->table_name[0], sz);
			return 1;
		}
	}
	return 0;
}
enum MAAT_TABLE_TYPE Maat_table_manager_get_type_by_id(struct Maat_table_manager* table_mgr, int table_id)
{
	if(table_id>MAX_TABLE_NUM)
	{
		return TABLE_TYPE_INVALID;
	}
	if(table_mgr->p_table_info[table_id])
	{
		return table_mgr->p_table_info[table_id]->table_type;
	}
	return TABLE_TYPE_INVALID;

}

struct Maat_table_schema * Maat_table_manager_get_scan_by_id(struct Maat_table_manager* table_mgr, int table_id, enum MAAT_SCAN_TYPE scan_type, int* virutal_table_id)
{
	enum MAAT_SCAN_TYPE tab_scan_type;
	struct Maat_table_schema **p_table_info=table_mgr->p_table_info;
	size_t n_table=MAX_TABLE_NUM;

	struct Maat_table_schema *p_table=NULL, *p_physical_table=NULL;
	if((unsigned int) table_id>n_table)
	{
		return NULL;
	}
	if(p_table_info[table_id]==NULL)
	{
		return NULL;
	}
	p_table=p_table_info[table_id];
	if(p_table==NULL)
	{
		return NULL;
	}
	if(p_table->table_type==TABLE_TYPE_VIRTUAL)
	{
		p_physical_table=p_table_info[p_table->virtual_table.physical_table_id[scan_type]];
		*virutal_table_id=table_id;
	}
	else
	{
		p_physical_table=p_table;
		if(virutal_table_id) *virutal_table_id=0;
	}
	tab_scan_type=Maat_table_get_scan_type(p_physical_table->table_type);
	if(tab_scan_type!=scan_type)
	{
			return NULL;	
	}
	return p_physical_table;
}
int Maat_table_manager_get_id_by_name(struct Maat_table_manager* table_mgr, const char* table_name)
{
	int table_id=-1,ret=0;
	ret=maat_kv_read(table_mgr->map_tablename2id, table_name, &table_id);
	if(ret>0)
	{
		return table_id;
	}
	else
	{
		return -1;
	}
}
int Maat_table_manager_add_callback_func(struct Maat_table_manager* table_mgr,
									int table_id,
									Maat_start_callback_t *start,//MAAT_RULE_UPDATE_TYPE_*,u_para
									Maat_update_callback_t *update,//table line ,u_para
									Maat_finish_callback_t *finish,//u_para
									void* u_para)
{
	int idx=0;
	struct Maat_table_schema *p_table=Maat_table_manager_get_scan_by_id(table_mgr, table_id, SCAN_TYPE_PLUGIN, NULL);
	struct plugin_table_schema *plugin_desc=&(p_table->plugin);
	if(p_table==NULL)
	{
		return -1;
	}

	idx=plugin_desc->cb_plug_cnt;
	if(idx==MAX_PLUGIN_PER_TABLE)
	{
		return -1;
	}
	plugin_desc->cb_plug_cnt++;
	plugin_desc->cb_plug[idx].start=start;
	plugin_desc->cb_plug[idx].update=update;
	plugin_desc->cb_plug[idx].finish=finish;
	plugin_desc->cb_plug[idx].u_para=u_para;
	return 1;
}

struct compile_ex_data_idx* Maat_table_manager_get_compile_rule_ex_desc(struct Maat_table_manager* table_mgr, const char* compile_table_name, int idx)
{
	int table_id=-1;
	struct Maat_table_schema *p_table=NULL;

	table_id=Maat_table_manager_get_id_by_name(table_mgr, compile_table_name);
	if(table_id<0)
	{
		return NULL;
	}
	p_table=Maat_table_manager_get_scan_by_id(table_mgr, table_id, SCAN_TYPE_NONE, NULL);
	if(!p_table)
	{
		return NULL;
	}
	if(idx<p_table->compile.ex_data_num)
	{
		return	p_table->compile.ex_desc+idx;
	}
	return NULL;

}
int Maat_table_manager_new_compile_rule_ex_index(struct Maat_table_manager* table_mgr, const char* compile_table_name,
										 Maat_rule_EX_new_func_t *new_func,
										 Maat_rule_EX_free_func_t* free_func,
										 Maat_rule_EX_dup_func_t* dup_func,
										 long argl, void *argp)
{
	int table_id=-1;
	struct Maat_table_schema *p_table=NULL;
	table_id=Maat_table_manager_get_id_by_name(table_mgr, compile_table_name);
	if(table_id<0)
	{
		return -1;
	}
	p_table=Maat_table_manager_get_scan_by_id(table_mgr, table_id, SCAN_TYPE_NONE, NULL);
	if(!p_table)
	{
		return -1;
	}
	int idx=-1;

	struct compile_table_schema* compile_desc=&(p_table->compile);
	if(compile_desc->ex_data_num==MAX_COMPILE_EX_DATA_NUM)
	{
		return -1;
	}
	idx=compile_desc->ex_data_num;
	compile_desc->ex_desc[idx].idx=idx;
	compile_desc->ex_desc[idx].table_id=table_id;
	compile_desc->ex_desc[idx].argl=argl;
	compile_desc->ex_desc[idx].argp=argp;
	compile_desc->ex_desc[idx].new_func=new_func;
	compile_desc->ex_desc[idx].free_func=free_func;
	compile_desc->ex_desc[idx].dup_func=dup_func;

	compile_desc->ex_data_num++;

	return idx;
} 
struct EX_data_schema *Maat_table_schema_get_EX_data_schema(struct Maat_table_schema *table_schema)
{
	struct EX_data_schema *ex_schema=NULL;
	switch(table_schema->table_type)
	{
		case TABLE_TYPE_PLUGIN:
			ex_schema=&table_schema->plugin.ex_schema;
			break;
		case TABLE_TYPE_IP_PLUGIN:
			ex_schema=&table_schema->ip_plugin.ex_schema;
			break;
		case TABLE_TYPE_FQDN_PLUGIN:
			ex_schema=&table_schema->fqdn_plugin.ex_schema;
			break;
		case TABLE_TYPE_BOOL_PLUGIN:
			ex_schema=&table_schema->bool_plugin.ex_schema;
			break;
		default:
			break;
	}
	return ex_schema;
}

int Maat_table_schema_set_EX_data_schema(struct Maat_table_schema *table_schema,
										Maat_plugin_EX_new_func_t* new_func,
										Maat_plugin_EX_free_func_t* free_func,
										Maat_plugin_EX_dup_func_t* dup_func,
										Maat_plugin_EX_key2index_func_t* key2index_func,
										long argl, void *argp,
										void* logger)
{
	struct EX_data_schema *ex_schema=NULL;
	if(new_func==NULL || free_func==NULL || dup_func==NULL )
	{
		assert(0);
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module, "%s failed: invalid paramter", __FUNCTION__);
		return -1;
	}
	ex_schema=Maat_table_schema_get_EX_data_schema(table_schema);
	if(ex_schema==NULL)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module, "Error: %s, target table is not a valid plugin table.", __FUNCTION__);
		return -1;
	}
	if(ex_schema->set_flag)
	{
		assert(0);
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module, "Error: %s, EX data schema already registed.", __FUNCTION__);
		return -1;
	}
	ex_schema->new_func=new_func;
	ex_schema->free_func=free_func;
	ex_schema->dup_func=dup_func;
	ex_schema->key2index_func=key2index_func;//Set but not used.
	ex_schema->argl=argl;
	ex_schema->argp=argp;
	ex_schema->set_flag=1;
	return 0;

}								
void Maat_table_manager_all_plugin_cb_start(struct Maat_table_manager* table_mgr, int update_type)
{
	table_mgr->active_plugin_table_num=0;
	int i=0, j=0;
	struct Maat_table_schema* p_table=NULL;
	struct plugin_table_schema* plugin_desc=NULL;

	for(i=0; i<MAX_TABLE_NUM; i++)
	{
		p_table=table_mgr->p_table_info[i];
		plugin_desc=&(p_table->plugin);
		if(p_table==NULL||p_table->table_type!=TABLE_TYPE_PLUGIN||plugin_desc->cb_plug_cnt==0)
		{
			continue;
		}

		table_mgr->active_plugin_table_num++;
		
		for(j=0;j<plugin_desc->cb_plug_cnt;j++)
		{
			if(plugin_desc->cb_plug[j].start!=NULL)
			{
				plugin_desc->cb_plug[j].start(update_type, plugin_desc->cb_plug[j].u_para);
			}
		}
	}

}
void Maat_table_manager_all_plugin_cb_finish(struct Maat_table_manager* table_mgr)
{
	int i=0, j=0;
	struct Maat_table_schema* p_table=NULL;
	struct plugin_table_schema* plugin_desc=NULL;

	int call_plugin_table_cnt=0;
	for(i=0;i<MAX_TABLE_NUM;i++)
	{
		p_table=table_mgr->p_table_info[i];
		if(p_table==NULL)
		{
			continue;
		}
		switch(p_table->table_type)
		{
			case TABLE_TYPE_PLUGIN:
				plugin_desc=&(p_table->plugin);				
				call_plugin_table_cnt++;
				if(call_plugin_table_cnt==table_mgr->active_plugin_table_num)
				{
					table_mgr->is_last_plugin_table_updating=1;
				}
				for(j=0;j<plugin_desc->cb_plug_cnt;j++)
				{
					if(plugin_desc->cb_plug[j].finish!=NULL)
					{
						plugin_desc->cb_plug[j].finish(plugin_desc->cb_plug[j].u_para);
					}
				}
				table_mgr->is_last_plugin_table_updating=0;
				break;
			default:
				break;
		}		
	}
	table_mgr->active_plugin_table_num=0;
	return;
}
int Maat_table_manager_is_last_plugin_table_updating(struct Maat_table_manager* table_mgr)
{
	return table_mgr->is_last_plugin_table_updating;
}
struct Maat_table_schema* Maat_table_manager_get_desc_by_name(struct Maat_table_manager* table_mgr, const char* table_name)
{
	struct Maat_table_schema * p_table=NULL;
	int table_id=0;
	table_id=Maat_table_manager_get_id_by_name(table_mgr, table_name);
	if(table_id<0)
	{
		return NULL;
	}
	p_table=table_mgr->p_table_info[table_id];
	return p_table;
}
void Maat_table_schema_set_updating_name(struct Maat_table_schema* p_table, const char* table_name)
{
	int i=0;
	for(i=0; i<p_table->conj_cnt; i++)
	{
		if(0==strcmp(p_table->table_name[i], table_name))
		{
			p_table->updating_name=i;
		}
	}
	assert(i<=p_table->conj_cnt);
}
struct Maat_table_schema * Maat_table_manager_get_by_id_raw(struct Maat_table_manager* table_mgr, int table_id)
{
	if(table_id>MAX_TABLE_NUM||table_id<0)
	{
		return NULL;
	}

	return table_mgr->p_table_info[table_id];
}

int Maat_table_manager_get_child_id(struct Maat_table_manager* table_mgr, int parent_table_id, enum MAAT_TABLE_COMPONENT_TYPE type)
{
	int ret=-1;
	struct Maat_table_schema* p_table=Maat_table_manager_get_by_id_raw(table_mgr, parent_table_id);
	if(p_table->table_type!=TABLE_TYPE_COMPOSITION)
	{
		return -1;
	}
	ret=p_table->composition.component_table_id[type];
	return ret;
}
int Maat_table_schema_get_valid_flag_column(struct Maat_table_schema* p_table)
{
	int valid_flag_column=-1;
	switch(p_table->table_type)
	{
		case TABLE_TYPE_PLUGIN:
			valid_flag_column=p_table->plugin.valid_flag_column;
			break;
		case TABLE_TYPE_IP_PLUGIN:
			valid_flag_column=p_table->ip_plugin.valid_flag_column;
			break;			
		case TABLE_TYPE_FQDN_PLUGIN:
			valid_flag_column=p_table->fqdn_plugin.valid_flag_column;
			break;
		case TABLE_TYPE_BOOL_PLUGIN:
			valid_flag_column=p_table->bool_plugin.valid_flag_column;
			break;
		default:
			valid_flag_column=-1;
			break;
	}
	return valid_flag_column;
}

