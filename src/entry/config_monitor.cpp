#include "MESA_handle_logger.h"
#include "config_monitor.h"
#include "Maat_rule_internal.h"
#include <dirent.h> 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#define module_config_monitor (module_name_str("MAAT_FILE_MONITOR"))


#define	CM_UPDATE_TYPE_ERR	-1
#define	CM_UPDATE_TYPE_NONE	0

#define	CM_MAX_TABLE_NUM	256
#define	MAX_CONFIG_FN_LEN	256
#define	MAX_CONFIG_LINE		1024*4

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif
//#define	USING_DICTATOR	1
extern "C" void __real_free(void*p);
struct cm_table_info_t
{
	char table_name[MAX_CONFIG_FN_LEN];
	char cfg_path[MAX_CONFIG_FN_LEN];
	int cfg_num;
	char encryp_algorithm[MAX_CONFIG_FN_LEN];
};
int decrypt_open(FILE* in,const unsigned char* key, const char* algorithm,unsigned char**pp_out,void *logger)
{

	unsigned char inbuf[MAX_CONFIG_LINE];
	int inlen, out_blk_len=0;
	int out_buff_len=0,buff_offset=0;
	EVP_CIPHER_CTX *ctx;

	unsigned char cipher_key[EVP_MAX_KEY_LENGTH];
	unsigned char cipher_iv[EVP_MAX_IV_LENGTH];
	memset(cipher_key,0,sizeof(cipher_key));
	memset(cipher_iv,0,sizeof(cipher_iv));

	const EVP_CIPHER *cipher;
	const EVP_MD *dgst=NULL;
	const unsigned char *salt=NULL;
	int ret=0;

	OpenSSL_add_all_algorithms();
	cipher=EVP_get_cipherbyname(algorithm);
	if(cipher==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor,"Not cipher:%s not supported.",algorithm);
		return 0;
	}
	dgst=EVP_get_digestbyname("md5");
	if(dgst==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor,"Get MD5 object failed.");
		return 0;
	}
	ret=EVP_BytesToKey(cipher,dgst,salt,key,strlen((const char*)key),1,cipher_key,cipher_iv);
	if(ret==0)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor,"Key and IV generatioin failed.");
		return 0;
	}
     /* Don't set key or IV right away; we want to check lengths */
	ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL,0);
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
	 
	/* Now we can set key and IV */
	EVP_CipherInit_ex(ctx, NULL, NULL, cipher_key, cipher_iv, 0);
	out_buff_len=16*1024;
	*pp_out=(unsigned char*)malloc(out_buff_len*sizeof(unsigned char));
	for (;;) 
	{
		inlen = fread(inbuf, 1, MAX_CONFIG_LINE, in);
		if (inlen <= 0)
			break;
		
		if(out_buff_len-buff_offset<inlen+EVP_CIPHER_block_size(cipher)-1)
		{
			out_buff_len*=2;
			*pp_out=(unsigned char*)realloc(*pp_out,out_buff_len);
		}
		out_blk_len=out_buff_len-buff_offset;
		if (!EVP_CipherUpdate(ctx, *pp_out+buff_offset, &out_blk_len, inbuf, inlen))
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor,"EVP_CipherUpdate failed.");
			EVP_CIPHER_CTX_free(ctx);
			goto error_out;
		}
		buff_offset+=out_blk_len;

	}
	if (!EVP_CipherFinal_ex(ctx, *pp_out+buff_offset, &out_blk_len))
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor,"EVP_CipherFinal_ex failed. Maybe password is wrong?");
		EVP_CIPHER_CTX_free(ctx);
		goto error_out;
	}
	buff_offset+=out_blk_len;
	EVP_CIPHER_CTX_free(ctx);
	return buff_offset;
error_out:
	free(*pp_out);
	*pp_out=NULL;
	return 0;
}
char* read_nxt_line_from_buff(const unsigned char* buff, int buff_size, int* offset, char*line ,int line_size)
{
	int this_offset=0;
	const unsigned char* p;
	//search for CRLF, aka '\r', '\n' or "\r\n"
	p=(const unsigned char*)memchr(buff+*offset,'\r',buff_size-*offset);
	if(p==NULL)
	{
		p=(const unsigned char*)memchr(buff+*offset,'\n',buff_size-*offset);
	}
	else
	{
		if(p-buff<buff_size-1&&*(p+1)=='\n')
		{
			p++;
		}
	}
	if(p!=NULL)//point to next character
	{
		p++;
	}
	else	//Treat rest buff has no CRLF as a line.
	{
		p=buff+buff_size;
	}
	this_offset=p-(buff+*offset);
	memcpy(line,buff+*offset,MIN(this_offset,line_size));
	*offset+=this_offset;
	return line;
}
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
	//inc update,it's possible that do inc after full update in this function,but we'll process it at next loop.
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
	char line[MAX_CONFIG_LINE];
	struct stat file_info;
	while(!feof(fp))
	{
		memset(line,0,sizeof(line));
		fgets(line,sizeof(line),fp);
		ret=sscanf(line,"%s\t%d\t%s\t%s",idx[i].table_name
								,&(idx[i].cfg_num)
								,idx[i].cfg_path
								,idx[i].encryp_algorithm);
		if(!(ret==3||ret==4)||idx[i].cfg_num==0)//jump over empty line
		{
			continue;
		}
		ret=stat(idx[i].cfg_path,&file_info);
		if(ret!=0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor ,"%s of %s not exisit",
									idx[i].cfg_path,
									path);
			fclose(fp);
			return -1;
		}
		i++;
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
							int (*update)(const char*,const char*,void*),
							void* u_para,
							const unsigned char* key,
							void* logger)
{
	int cfg_num=0,i=0;
	int ret=0;
	char line[MAX_CONFIG_LINE]={0},*ret_str=NULL;
	unsigned char* decrypt_buff=NULL;
	int decrypt_len=0,do_decrypt=0,decrypt_offset=0;
	FILE*fp=fopen(index->cfg_path,"r");
	if(fp==NULL)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor,"update error,open %s failed.",index->cfg_path);
		return -1;
	}
	if(strlen(index->encryp_algorithm)>0)
	{
		if(key==NULL||strlen((const char*)key)==0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor,"update error,no key to decrypt %s.",index->cfg_path);
			return -1;
		}
		decrypt_len=decrypt_open(fp, key,index->encryp_algorithm, &decrypt_buff,logger);
		if(decrypt_len==0)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor,"update error,%s decrypt failed.",index->cfg_path);
			return -1;
		}
		read_nxt_line_from_buff(decrypt_buff, decrypt_len, &decrypt_offset, line, sizeof(line));
		sscanf(line,"%d\n",&cfg_num);
		do_decrypt=1;
	}
	else
	{
		fscanf(fp,"%d\n",&cfg_num);
	}
	if(cfg_num!=index->cfg_num)
	{
		MESA_handle_runtime_log(logger,RLOG_LV_FATAL,module_config_monitor ,"file %s config num not matched",index->cfg_path);
		fclose(fp);
		return -1;
	}
	for(i=0;i<cfg_num;i++)
	{
		line[sizeof(line)-1]='\0';
		if(do_decrypt==1)
		{
			ret_str=read_nxt_line_from_buff(decrypt_buff, decrypt_len, &decrypt_offset, line, sizeof(line));
		}
		else
		{
			ret_str=fgets(line,sizeof(line),fp);
		}
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
		ret=update(index->table_name,line,u_para);
		if(ret<0)
		{
			break;
		}
	}
	fclose(fp);
	if(decrypt_buff!=NULL)
	{
		free(decrypt_buff);
	}
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
							int (*update)(const char* ,const char*,void* ),
							void (*finish)(void*),
							void* u_para,
							const unsigned char* dec_key,
							void* logger)
{

	int update_type=CM_UPDATE_TYPE_NONE;
	unsigned int new_version=0;
	char**idx_path_array=NULL;
	const char* table_filename=NULL;
	char str_not_care[256]={0};
	int idx_num=0,table_num=0,i=0,j=0;
	struct cm_table_info_t table_array[CM_MAX_TABLE_NUM];
	memset(table_array,0,sizeof(table_array));
	update_type=get_new_idx_path(version, idx_dir,logger, &idx_path_array, &idx_num);
	if(update_type==CM_UPDATE_TYPE_FULL||update_type==CM_UPDATE_TYPE_INC)
	{

		for(i=0;i<idx_num;i++)
		{
			MESA_handle_runtime_log(logger,RLOG_LV_INFO,module_config_monitor ,
								"load %s",idx_path_array[i]);
			table_num=cm_read_cfg_index_file(idx_path_array[i],table_array, CM_MAX_TABLE_NUM,logger);
			if(table_num<0)
			{
				MESA_handle_runtime_log(logger,RLOG_LV_INFO,module_config_monitor ,
									"load %s faild, abandon udpate.",idx_path_array[i]);				
				break;
			}
			table_filename=path2filename(idx_path_array[i]);
			sscanf(table_filename,"%[a-zA-Z]_config_index.%u",str_not_care,&new_version);
			start(new_version,update_type,u_para);
			for(j=0;j<table_num;j++)
			{
				cm_read_table_file(table_array+j,update,u_para,dec_key,logger);
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

