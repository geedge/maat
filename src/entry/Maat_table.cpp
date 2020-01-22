#include "Maat_table.h"
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
	struct Maat_table_desc* p_table_info[MAX_TABLE_NUM];
	size_t table_cnt;
	MESA_htable_handle map_tablename2id;
	int active_plugin_table_num;
	int is_last_plugin_table_updating;
};

int read_expr_table_info(const char* line, struct Maat_table_desc* table, MESA_htable_handle string2int_map)
{
	int j=0,ret[4]={0};
	char table_type[16],src_charset[256],dst_charset[256],merge[4],quick_str_scan[32]={0};
	char *token=NULL,*sub_token=NULL,*saveptr;
	struct expr_table_desc* p=&(table->expr);
	sscanf(line,"%d\t%s\t%s\t%s\t%s\t%s\t%d\t%s",&(table->table_id)
											,table->table_name[0]
											,table_type
											,src_charset
											,dst_charset
											,merge
											,&(p->cross_cache_size)
											,quick_str_scan);
	memset(ret,0,sizeof(ret));
	ret[0]=map_str2int(string2int_map,str_tolower(table_type),(int*)&(table->table_type));
	ret[1]=map_str2int(string2int_map,str_tolower(src_charset),(int*)&(p->src_charset));
	ret[2]=map_str2int(string2int_map,str_tolower(merge),&(p->do_charset_merge));
	if(strlen(quick_str_scan)>0)
	{
		ret[3]=map_str2int(string2int_map,str_tolower(quick_str_scan),&(p->quick_expr_switch));
	}
	memset(quick_str_scan,0,sizeof(quick_str_scan));

	for(j=0;j<4;j++)
	{
		if(ret[j]<0)
		{
			return -1;
		}
	}
	j=0;
	for (token = dst_charset; ; token= NULL)
	{
		sub_token= strtok_r(token,"/", &saveptr);
		if (sub_token == NULL)
			break;
		ret[3]=map_str2int(string2int_map,str_tolower(sub_token),(int*)&(p->dst_charset[j]));
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
int read_virtual_table_info(const char* line, struct Maat_table_desc* table, MESA_htable_handle string2int_map)
{
	int ret=0;
	char table_type[16];
	ret=sscanf(line, "%d\t%s\t%s\t%s", &(table->table_id),
									table->table_name[0],
									table_type,
									table->virtual_table.real_table_name);
	if(ret!=4)
	{
		return -1;
	}	
	ret=map_str2int(string2int_map,str_tolower(table_type),(int*)&(table->table_type));
	if(ret<0)
	{
		return -1;
	}
	return 0;
}
Maat_table_desc* table_info_new(void)
{
	struct Maat_table_desc*p=ALLOC(struct Maat_table_desc, 1);
	p->conj_cnt=1;
	return p;
}
void table_info_free(struct Maat_table_desc*p)
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
#define COLUMN_PLUGIN_DESCR_JSON	4
int read_plugin_table_description(const char* line, struct Maat_table_desc* p)
{
	int i=0,ret=0;
	size_t offset=0, len=0;
	cJSON* json=NULL, *tmp=NULL, *array_item=NULL;
	char* copy_line=NULL, *plug_info=NULL;
	struct plugin_table_desc* plugin_desc=&(p->plugin);
	copy_line=_maat_strdup(line);
	ret=get_column_pos(copy_line, COLUMN_PLUGIN_DESCR_JSON, &offset, &len);
	if(i<0)
	{
		goto error_out;
	}
	if(offset+len<strlen(copy_line))
	{
		copy_line[offset+len+1]='\0';
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
	tmp=cJSON_GetObjectItem(json, "estimate_size");
	if(tmp!=NULL)
	{
		assert(tmp->type==cJSON_Number);
		plugin_desc->estimate_size=tmp->valueint;
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

static int Maat_table_build_map(struct Maat_table_manager* table_mgr, void* logger)
{
	struct Maat_table_desc** p_table_info=table_mgr->p_table_info;
	size_t n_table=MAX_TABLE_NUM;

	MESA_htable_handle map_tablename2id=map_create();
	size_t i=0;
	int j=0, ret=0;
	for(i=0;i<n_table;i++)
	{
		if(p_table_info[i]==NULL)
		{
			continue;
		}
		
		switch(p_table_info[i]->table_type)
		{
			case TABLE_TYPE_VIRTUAL:
				ret=map_str2int(map_tablename2id, p_table_info[i]->virtual_table.real_table_name, &(p_table_info[i]->virtual_table.real_table_id));
				if(ret<0)
				{
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
									"Undefined real table %s, virtual table %s of table id %d.",
									p_table_info[i]->virtual_table.real_table_name,
									p_table_info[i]->table_name[j],
									p_table_info[i]->table_id);
					goto failed;
				}
				break;
			default:
				break;
		}

		
		for(j=0; j<p_table_info[i]->conj_cnt; j++)
		{
			ret=map_register(map_tablename2id, p_table_info[i]->table_name[j], p_table_info[i]->table_id);
			if(ret<0)
			{
				MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"Duplicate table %s of table id %d",
								p_table_info[i]->table_name[j],
								p_table_info[i]->table_id);
				continue;
			}
		}
		
	}
	table_mgr->map_tablename2id=map_tablename2id;
	return 0;
failed:
	map_destroy(map_tablename2id);
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
	MESA_htable_destroy(table_mgr->map_tablename2id, free);
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
	MESA_htable_handle string2int_map=NULL;;
	struct Maat_table_desc*p=NULL;
	struct Maat_table_desc*conj_table=NULL;
	fp=fopen(table_info_path,"r");
	if(fp==NULL)
	{
		fprintf(stderr,"Maat read table info %s error.\n",table_info_path);
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
								"Maat read table info %s failed: %s.\n", table_info_path, strerror(errno));
		return NULL;
	}
	table_mgr=ALLOC(struct Maat_table_manager, 1);
	struct Maat_table_desc** p_table_info=table_mgr->p_table_info;
	size_t n_table=MAX_TABLE_NUM;

	string2int_map=map_create();
	map_register(string2int_map,"expr", TABLE_TYPE_EXPR);
	map_register(string2int_map,"ip", TABLE_TYPE_IP);	
	map_register(string2int_map,"ip_plus", TABLE_TYPE_IP_PLUS);
	map_register(string2int_map,"compile", TABLE_TYPE_COMPILE);
	map_register(string2int_map,"plugin", TABLE_TYPE_PLUGIN);
	map_register(string2int_map,"intval", TABLE_TYPE_INTERVAL);
	map_register(string2int_map,"digest", TABLE_TYPE_DIGEST);
	map_register(string2int_map,"expr_plus", TABLE_TYPE_EXPR_PLUS);
	map_register(string2int_map,"group", TABLE_TYPE_GROUP);
	map_register(string2int_map,"similar", TABLE_TYPE_SIMILARITY);
	map_register(string2int_map,"virtual", TABLE_TYPE_VIRTUAL);
	map_register(string2int_map,"quickoff", 0);
	map_register(string2int_map,"quickon", 1);
	map_register(string2int_map,"escape", USER_REGION_ENCODE_ESCAPE);
//	map_register(string2int_map,"base64",USER_REGION_ENCODE_BASE64); //NOT supported yet

	const char** charset_name_list=charset_get_all_name();
	for(i=0;i<MAX_CHARSET_NUM;i++)
	{
		if(strlen(charset_name_list[i])>0)
		{
			map_register(string2int_map, charset_name_list[i], i);
		}
		else
		{
			break;
		}
	}

	map_register(string2int_map,"yes", 1);
	map_register(string2int_map,"no", 0);
	

	i=0;
	while(NULL!=fgets(line,sizeof(line),fp))
	{
		i++;

		if(line[0]=='#'||line[0]==' '||line[0]=='\t'||strlen(line)<4)
		{
			continue;
		}
		p=table_info_new();

		ret=sscanf(line,"%d\t%s\t%s\t%[a-z0-9\t ]",&(p->table_id)
											,p->table_name[0]
											,table_type_str
											,not_care);
		if(ret<3)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
									"Maat read table info %s line %d error: not enough column.",table_info_path,i);
			continue;
		}
		ret=map_str2int(string2int_map,str_tolower(table_type_str),(int*)&(p->table_type));
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
						"Maat read table info %s line %d error:invalid table type.",table_info_path,i);
			goto invalid_table;
		}
		switch(p->table_type)
		{
			case TABLE_TYPE_EXPR:
			case TABLE_TYPE_EXPR_PLUS:
				ret=read_expr_table_info(line, p, string2int_map);
				if(ret<0)
				{
					fprintf(stderr,"Maat read table info %s line %d error:illegal column.\n",table_info_path,i);
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
									"Maat read table info %s line %d error:illegal column.",table_info_path,i);
					goto invalid_table;
				}
				break;
			case TABLE_TYPE_PLUGIN:
				ret=read_plugin_table_description(line, p);
				if(ret<0)
				{
					fprintf(stderr,"Maat read table info %s line %d error:illegal plugin info.\n",table_info_path,i);
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
									"Maat read table info %s line %d error:illegal plugin info.",table_info_path,i);
					goto invalid_table;
				}
				break;
			case TABLE_TYPE_VIRTUAL:
				ret=read_virtual_table_info(line, p, string2int_map);
				if(ret<0)
				{
					fprintf(stderr,"Maat read table info %s line %d error:illegal virtual info.\n",table_info_path,i);
					MESA_handle_runtime_log(logger, RLOG_LV_FATAL,maat_module,
									"Maat read table info %s line %d error:illegal virtual info.",table_info_path,i);
					goto invalid_table;
				}
				break;
			case TABLE_TYPE_COMPILE:	
				ret=sscanf(not_care,"%[a-z0-9]",tmp_str);
				if(ret>0)
				{	
					ret=map_str2int(string2int_map,str_tolower(tmp_str),(int*)&(p->compile.user_region_encoding));
				}
				if(ret!=1)
				{
					p->compile.user_region_encoding=USER_REGION_ENCODE_NONE;
				}
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
		if(p_table_info[p->table_id]!=NULL)//duplicate table_id,means conjunction table;
		{
			conj_table=p_table_info[p->table_id];
			if(conj_table->conj_cnt==MAX_CONJUNCTION_TABLE_NUM)
			{
				MESA_handle_runtime_log(logger, RLOG_LV_FATAL, maat_module,
								"Maat read table info %s line %d error:reach tableid %d conjunction upper limit."
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
	ret=Maat_table_build_map(table_mgr, logger);
	if(ret<0)
	{
		return NULL;
	}
	map_destroy(string2int_map);
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
int Maat_table_get_compile_table_name(struct Maat_table_manager* table_mgr, char* buff, size_t sz)
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
int Maat_table_get_group_table_name(struct Maat_table_manager* table_mgr, char* buff, size_t sz)
{
	int i=0;
	for(i=0; i< MAX_TABLE_NUM; i++)
	{
		if(table_mgr->p_table_info[i] && table_mgr->p_table_info[i]->table_type==TABLE_TYPE_GROUP)
		{
			strncpy(buff, table_mgr->p_table_info[i]->table_name[0], sz);
			return 1;
		}
	}
	return 0;
}
const char* Maat_table_get_name_by_id(struct Maat_table_manager* table_mgr, int table_id)
{
	if(table_id>MAX_TABLE_NUM)
	{
		return NULL;
	}
	if(table_mgr->p_table_info[table_id])
	{
		return table_mgr->p_table_info[table_id]->table_name[0];
	}
	return NULL;
}
enum MAAT_TABLE_TYPE Maat_table_get_type_by_id(struct Maat_table_manager* table_mgr, int table_id)
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
struct Maat_table_desc * Maat_table_get_by_id_raw(struct Maat_table_manager* table_mgr, int table_id)
{
	if(table_id>MAX_TABLE_NUM)
	{
		return NULL;
	}

	return table_mgr->p_table_info[table_id];
}

struct Maat_table_desc * Maat_table_get_by_id(struct Maat_table_manager* table_mgr, int table_id, enum MAAT_TABLE_TYPE expect_type, int* virutal_table_id)
{

	struct Maat_table_desc **p_table_info=table_mgr->p_table_info;
	size_t n_table=MAX_TABLE_NUM;

	struct Maat_table_desc *p_table=NULL, *p_real_table=NULL;
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
		p_real_table=p_table_info[p_table->virtual_table.real_table_id];
		*virutal_table_id=table_id;
	}
	else
	{
		p_real_table=p_table;
		if(virutal_table_id) *virutal_table_id=0;
	}
	if(p_real_table->table_type!=expect_type)
	{
		if((expect_type==TABLE_TYPE_EXPR && p_real_table->table_type!=TABLE_TYPE_EXPR_PLUS)||
			(expect_type==TABLE_TYPE_IP && p_real_table->table_type!=TABLE_TYPE_IP_PLUS))
		{
			return NULL;
		}
	}
	return p_real_table;
}
int Maat_table_get_id_by_name(struct Maat_table_manager* table_mgr, const char* table_name)
{
	int table_id=-1,ret=0;
	ret=map_str2int(table_mgr->map_tablename2id, table_name, &table_id);
	if(ret>0)
	{
		return table_id;
	}
	else
	{
		return -1;
	}
}
int Maat_table_add_callback_func(struct Maat_table_manager* table_mgr,
									int table_id,
									Maat_start_callback_t *start,//MAAT_RULE_UPDATE_TYPE_*,u_para
									Maat_update_callback_t *update,//table line ,u_para
									Maat_finish_callback_t *finish,//u_para
									void* u_para)
{
	int idx=0;
	struct Maat_table_desc *p_table=Maat_table_get_by_id(table_mgr, table_id, TABLE_TYPE_PLUGIN, NULL);
	struct plugin_table_desc *plugin_desc=&(p_table->plugin);
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

struct compile_ex_data_idx* Maat_table_get_compile_rule_ex_desc(struct Maat_table_manager* table_mgr, const char* compile_table_name, int idx)
{
	int table_id=-1;
	struct Maat_table_desc *p_table=NULL;

	table_id=Maat_table_get_id_by_name(table_mgr, compile_table_name);
	if(table_id<0)
	{
		return NULL;
	}
	p_table=Maat_table_get_by_id(table_mgr, table_id, TABLE_TYPE_COMPILE, NULL);
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
int Maat_table_new_compile_rule_ex_index(struct Maat_table_manager* table_mgr, const char* compile_table_name,
										 Maat_rule_EX_new_func_t *new_func,
										 Maat_rule_EX_free_func_t* free_func,
										 Maat_rule_EX_dup_func_t* dup_func,
										 long argl, void *argp)
{
	int table_id=-1;
	struct Maat_table_desc *p_table=NULL;
	table_id=Maat_table_get_id_by_name(table_mgr, compile_table_name);
	if(table_id<0)
	{
		return -1;
	}
	p_table=Maat_table_get_by_id(table_mgr, table_id, TABLE_TYPE_COMPILE, NULL);
	if(!p_table)
	{
		return -1;
	}
	int idx=-1;

	struct compile_table_desc* compile_desc=&(p_table->compile);
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
int Maat_table_plugin_new_ex_index(struct Maat_table_manager* table_mgr, int table_id,
										Maat_plugin_EX_new_func_t* new_func,
										Maat_plugin_EX_free_func_t* free_func,
										Maat_plugin_EX_dup_func_t* dup_func,
										Maat_plugin_EX_key2index_func_t* key2index_func,
										long argl, void *argp)

{
	struct Maat_table_desc *table_desc=NULL;;
	table_desc=Maat_table_get_by_id(table_mgr, table_id, TABLE_TYPE_PLUGIN, NULL);
	struct plugin_table_desc* plugin_desc=&(table_desc->plugin);
	
	if(plugin_desc->have_exdata
		|| plugin_desc->key_column==0 || plugin_desc->valid_flag_column==0)
	{
		return -1;
	}
	plugin_desc->ex_desc.new_func=new_func;
	plugin_desc->ex_desc.free_func=free_func;
	plugin_desc->ex_desc.dup_func=dup_func;
	plugin_desc->ex_desc.key2index_func=key2index_func;//Set but not used.
	plugin_desc->ex_desc.argl=argl;
	plugin_desc->ex_desc.argp=argp;
	plugin_desc->have_exdata=1;
	return 0;
}
void Maat_table_manager_all_plugin_cb_start(struct Maat_table_manager* table_mgr, int update_type)
{
	table_mgr->active_plugin_table_num=0;
	int i=0, j=0;
	struct Maat_table_desc* p_table=NULL;
	struct plugin_table_desc* plugin_desc=NULL;

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
	struct Maat_table_desc* p_table=NULL;
	struct plugin_table_desc* plugin_desc=NULL;

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
struct Maat_table_desc* Maat_table_get_desc_by_name(struct Maat_table_manager* table_mgr, const char* table_name)
{
	struct Maat_table_desc * p_table=NULL;
	int table_id=0;
	table_id=Maat_table_get_id_by_name(table_mgr, table_name);
	if(table_id<0)
	{
		return NULL;
	}
	p_table=table_mgr->p_table_info[table_id];
	return p_table;
}
void Maat_table_set_updating_name(struct Maat_table_desc* p_table, const char* table_name)
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

