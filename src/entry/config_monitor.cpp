#include "MESA_handle_logger.h"
#include "config_monitor.h"
#include <dirent.h> 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const char*	module_config_monitor="CONFIG_MONITOR";

#define	CM_UPDATE_TYPE_ERR	-1
#define	CM_UPDATE_TYPE_NONE	0

#define	CM_MAX_TABLE_NUM	256
#define	MAX_CONFIG_FN_LEN	256
#define	MAX_CONFIG_LINE		1024*4
//#define	USING_DICTATOR	1
extern "C" void __real_free(void*p);
struct cm_table_info_t
{
	char table_name[MAX_CONFIG_FN_LEN];
	char cfg_path[MAX_CONFIG_FN_LEN];
	int cfg_num;
};
//replacement of glibc scandir, to adapt dictator malloc wrap
#define	ENLARGE_STEP	1024
int my_scandir(const char *dir, struct dirent ***namelist,
              int(*filter)(const struct dirent *),
              int(*compar)(const void *, const void *))
{
	DIR * od;
	int n = 0;
	int DIR_ENT_SIZE=ENLARGE_STEP;
	struct dirent ** list = NULL;
	struct dirent * p;
	struct dirent entry,*result;

	if((dir == NULL) || (namelist == NULL))
		return -1;

	od = opendir(dir);
	if(od == NULL)
		return -1;
    
	list = (struct dirent **)malloc(DIR_ENT_SIZE*sizeof(struct dirent *));
  
  
	while(0==readdir_r(od,&entry,&result))
	{
		if(result==NULL)
		{
			break;
		}
		if( filter && !filter(&entry))
			continue;
		
		p = (struct dirent *)malloc(sizeof(struct dirent));
		memcpy((void *)p,(void *)(&entry),sizeof(struct dirent));
		list[n] = p;

		n++;
		if(n >= DIR_ENT_SIZE)
		{
			DIR_ENT_SIZE+=ENLARGE_STEP;
			list=(struct dirent **)realloc((void*)list,DIR_ENT_SIZE*sizeof(struct dirent *));

		}
	} 

	closedir(od); 

	*namelist = list;

	if(compar)
	qsort((void *)*namelist,n,sizeof(struct dirent *),compar); 

	return n; 
   
}
 int filter_fn(const struct dirent * ent)
 {
//   files in xfs are not DT_REG.
//   if(ent->d_type != DT_REG)
//     return 0;
     
   return (strncmp(ent->d_name,"full_config_index",strlen("full_config_index")) == 0||
   	strncmp(ent->d_name,"inc_config_index",strlen("inc_config_index")) == 0);
 }
int  get_new_idx_path(unsigned int current_version,const char*file_dir,void* logger,char*** idx_path,int*idx_num)
{
	struct dirent **namelist;
	int n=0,i=0,sscanf_ret;
	
	char update_str[32]={0};
	unsigned int latest_ful_version=0,latest_inc_version=0;
	unsigned int config_seq=0;
	int *inc_file_idx;
	int full_file_idx=0,inc_idx_num=0,path_len=0;
	
	int update_type=CM_UPDATE_TYPE_NONE;

	
	n = my_scandir(file_dir, &namelist, filter_fn, (int (*)(const void*, const void*))alphasort);
	if (n < 0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor,"scan dir error");
		update_type=CM_UPDATE_TYPE_ERR;
		return update_type;
	}
	inc_file_idx=(int*)calloc(sizeof(int),n);
	inc_idx_num=0;
	for(i=0;i<n;i++)
	{
		config_seq=0;
		if((strcmp(namelist[i]->d_name, ".") == 0) || (strcmp(namelist[i]->d_name, "..") == 0))
		{
			continue;
		}
		if(strlen(namelist[i]->d_name)>32)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor 
										,"config file %s filename too long,should like full_config_index.0000000001"
										,namelist[i]->d_name);
			continue;
		}
		sscanf_ret=sscanf(namelist[i]->d_name,"%[a-zA-Z]_config_index.%u",update_str,&config_seq);
		if(sscanf_ret!=2)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor 
										,"config file %s filename error,should like full_config_index.0000000001"
										,namelist[i]->d_name);
			continue;
		}
		if(strncasecmp(update_str,"full",strlen(update_str))==0)
		{
			if(config_seq>latest_ful_version)
			{
				latest_ful_version=config_seq;
				full_file_idx=i;
			}
		}
		else if(strncasecmp(update_str,"inc",strlen(update_str))==0)
		{
			if(config_seq>current_version)
			{
				inc_file_idx[inc_idx_num]=i;
				inc_idx_num++;
				if(config_seq>latest_inc_version)
				{
					latest_inc_version=config_seq;
				}
				
			}
		}
		else
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor 
										,"config file %s,not full or inc config"
										,namelist[i]->d_name);
		}
	}
	//full update
	if(latest_ful_version>current_version)
	{
		*idx_path=(char**)malloc(sizeof(char**));
		path_len=strlen(file_dir)+strlen(namelist[full_file_idx]->d_name)+1+1;
		(*idx_path)[0]=(char*)malloc(path_len);
		snprintf((*idx_path)[0],path_len,"%s/%s",file_dir,namelist[full_file_idx]->d_name);
		*idx_num=1;
		update_type=CM_UPDATE_TYPE_FULL;
	}
	//inc update,it's possible that do inc after full update in this function,but we'll process it at next call.
	else if(latest_inc_version>current_version)
	{
		
		*idx_path=(char**)malloc(sizeof(char**)*inc_idx_num);
		for(i=0;i<inc_idx_num;i++)
		{
			path_len=strlen(file_dir)+strlen(namelist[inc_file_idx[i]]->d_name)+1+1;
			(*idx_path)[i]=(char*)malloc(path_len);
			snprintf((*idx_path)[i],path_len,"%s/%s",file_dir,namelist[inc_file_idx[i]]->d_name);
			
		}
		*idx_num=inc_idx_num;
		update_type=CM_UPDATE_TYPE_INC;
		
	}
	else
	{
		update_type=CM_UPDATE_TYPE_NONE;
	}
	free(inc_file_idx);
	for(i=0;i<n;i++)
	{
		free(namelist[i]);
	}
	free(namelist);

	return update_type;
}
int cm_read_cfg_index_file(const char* path,struct cm_table_info_t* idx,int size,void* logger)
{
	FILE* fp=NULL;
	fp=fopen(path,"r");
	int ret=0,i=0;
	while(!feof(fp))
	{
		ret=fscanf(fp,"%s\t%d\t%s",idx[i].table_name
								,&(idx[i].cfg_num)
								,idx[i].cfg_path);
		if(ret==3&&idx[i].cfg_num>=0)//jump over empty line
		{
			i++;
		}
		if(i==size)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor ,"Too much lines in %s",path);
			break;
		}
	}
	fclose(fp);
	return i;
}

int cm_read_table_file(struct cm_table_info_t* index,
							void (*update)(const char*,const char*,void*),
							void* u_para,
							void* logger)
{
	int cfg_num=0,i=0;
	char line[MAX_CONFIG_LINE]={0},*ret_str=NULL;
	FILE*fp=fopen(index->cfg_path,"r");
	if(fp==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor,"update error,open %s failed.",index->cfg_path);
		return -1;
	}
	fscanf(fp,"%d\n",&cfg_num);
	if(cfg_num!=index->cfg_num)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor ,"file %s config num not matched",index->cfg_path);
		fclose(fp);
		return -1;
	}
	for(i=0;i<cfg_num;i++)
	{
		line[sizeof(line)-1]='\0';
		ret_str=fgets(line,sizeof(line),fp);
		if(ret_str==NULL)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor ,
								"update error,file %s line_num %d less than claimed %d",
								index->cfg_path,i,cfg_num);
			break;
		}
		if(line[sizeof(line)-1]!='\0')
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor ,
								"update error,line size more than %u at of file %s:%d",
								sizeof(line),index->cfg_path,i);	
			continue;
		}
		update(index->table_name,line,u_para);
	}
	fclose(fp);
	return 0;
}
const char* path2filename(const char*path)
{
	int i=0;
	for(i=strlen(path);i>0;i--)
	{
		if(path[i]=='/')
		{
			break;
		}
	}
	return path+i+1;
}
void config_monitor_traverse(unsigned int version,const char*idx_dir,
							void (*start)(unsigned int ,int ,void*),
							void (*update)(const char* ,const char*,void* ),
							void (*finish)(void*),
							void* u_para,
							void* logger)
{

	int update_type=CM_UPDATE_TYPE_NONE;
	unsigned int new_version=0;
	char**idx_path_array=NULL;
	const char* table_filename=NULL;
	char str_not_care[256]={0};
	int idx_num=0,table_num=0,i=0,j=0;
	struct cm_table_info_t table_array[CM_MAX_TABLE_NUM];
	update_type=get_new_idx_path(version, idx_dir,logger, &idx_path_array, &idx_num);
	if(update_type==CM_UPDATE_TYPE_FULL||update_type==CM_UPDATE_TYPE_INC)
	{

		for(i=0;i<idx_num;i++)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,module_config_monitor ,
								"load %s",idx_path_array[i]);
			table_num=cm_read_cfg_index_file(idx_path_array[i],table_array, CM_MAX_TABLE_NUM,logger);
			table_filename=path2filename(idx_path_array[i]);
			sscanf(table_filename,"%[a-zA-Z]_config_index.%u",str_not_care,&new_version);
			start(new_version,update_type,u_para);
			for(j=0;j<table_num;j++)
			{
				cm_read_table_file(table_array+j,update,u_para,logger);
			}
			finish(u_para);
		}

	}
	
	for(i=0;i<idx_num;i++)
	{
		free(idx_path_array[i]);
	}
	free(idx_path_array);//free null is OK
	return;
}

