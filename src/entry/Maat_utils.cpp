#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <openssl/md5.h>

#include "Maat_utils.h"
pid_t gettid()
{
	return syscall(SYS_gettid);
}
const char*	module_name_str(const char*name)
{
	static __thread char module[64];
	snprintf(module,sizeof(module),"%s(%d)", name, gettid());
	return module;
}

int converHextoint(char srctmp)
{
	if(isdigit(srctmp))
	{
		return srctmp-'0';
	}
	else
	{
		char temp=toupper(srctmp);
		temp=temp-'A'+10;
		return temp;
	}
}
int  hex2bin(char *hex,int hex_len,char *binary,int size)
{
	int i=0;
	int resultlen=0;
	int high,low;
	for(i=0;i<hex_len&&size>resultlen; i+=2,resultlen++)
	{
		high=converHextoint(hex[i]);
		low=converHextoint(hex[i+1]);
		binary[resultlen]=high*16+low;
	}
	size=resultlen;
	binary[resultlen]='\0';
	return resultlen;
}
//functioned as strdup, for dictator compatible.
char* _maat_strdup(const char* s)
{
	char*d=NULL;
	if(s==NULL)
	{
		return NULL;
	}
	d=(char*)malloc(strlen(s)+1);
	memcpy(d,s,strlen(s)+1);
	return d;
}
char* str_tolower(char* string)
{
	int i=0;
	for(i=0;i<(int)strlen(string);i++)
	{
		string[i]=(char)tolower(string[i]);
	}
	return string;
}
char * strchr_esc(char* s,const char delim)
{
	char *token;
	if(s==NULL)
		return NULL;
	for(token=s;*token!='\0';token++)
	{
		if(*token=='\\')
		{
			token++;
			continue;
		}
		if(*token==delim)
			break;
	}
	if (*token == '\0')
	{ 
		return NULL;
	}
	else
	{
		return token;
	}
}
char *strtok_r_esc(char *s, const char delim, char **save_ptr)
{  
    char *token;  
  
    if (s == NULL) s = *save_ptr;  
  
    /* Scan leading delimiters.  */
	token=strchr_esc(s,delim);
	if(token==NULL)
	{
		*save_ptr=token;
		return s;
	}
    /* Find the end of the token.  */  
	*token='\0';
	token++;
	*save_ptr=token;

    return s;  
}   
char *str_unescape_and(char*s)
{
	int i=0,j=0;
	for(i=0,j=0;i<(int)strlen(s);i++)
	{
		if(s[i]=='\\'&&s[i+1]=='&')
		{
			s[j]='&';
			i++;
			j++;
		}
		else{
			s[j]=s[i];
			j++;
		}
	}
	s[j]='\0';
	return s;
}
char* str_unescape(char* s)
{
	int i=0,j=0;
	int len=strlen(s);
	for(i=0,j=0;i<len;i++)
	{
		if(s[i]=='\\')
		{
			switch(s[i+1])
			{
				case '&':
					s[j]='&';
					break;
				case 'b':
					s[j]=' ';//space,0x20;
					break;
				case '\\':
					s[j]='\\';
					break;
				default:
					s[j]=s[i];
					i--;	//undo the followed i++
					break;
			}
			i++;
			j++;
		}
		else
		{
			s[j]=s[i];
			j++;
		}
	}
	s[j]='\0';
	return s;
}
#define MAX_SYSTEM_CMD_LEN	512

int system_cmd_mkdir(const char* path)
{
	char cmd[MAX_SYSTEM_CMD_LEN] = { 0 };
	snprintf(cmd, sizeof(cmd),"mkdir -p %s", path);
	return  system(cmd) ;
}
int system_cmd_mv(const char* src_file,const char*dst_file)
{
	char cmd[MAX_SYSTEM_CMD_LEN] = { 0 };
	snprintf(cmd,sizeof(cmd), "mv %s %s", src_file, dst_file);
	return  system(cmd);
}
int system_cmd_cp(const char* src_file,const char*dst_file)
{
	char cmd[MAX_SYSTEM_CMD_LEN] = { 0 };
	snprintf(cmd,sizeof(cmd), "cp -f %s %s", src_file, dst_file);
	return  system(cmd);
}

int system_cmd_rm(const char* src_file)
{
	char cmd[MAX_SYSTEM_CMD_LEN] = { 0 };
	snprintf(cmd,sizeof(cmd), "rm %s -f", src_file);
	return  system(cmd);
}
char* md5_file(const char* filename, char* md5string)
{
	FILE* fp=NULL;
	int i=0;
	unsigned char md5[MD5_DIGEST_LENGTH];
	struct stat file_info;	
	stat(filename, &file_info);
	size_t file_size=file_info.st_size;

	fp=fopen(filename,"r");
	if(fp==NULL)
	{
		return NULL;
	}
	char* file_buff=(char*)malloc(file_size);
	fread(file_buff,1,file_size,fp);
	fclose(fp);
	
	MD5((const unsigned char *)(file_buff), (unsigned long)(file_size), md5);
	for(i = 0; i < MD5_DIGEST_LENGTH; ++i)
	{
		sprintf(&md5string[i*2], "%02x", (unsigned int)md5[i]);
	}
	free(file_buff);
	return md5string;
}

